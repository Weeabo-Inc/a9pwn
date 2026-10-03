//! USB transport for a9pwn — the layer the whole exploit stands on.
//!
//! Owner: transport-engineer (task-2). Frozen surface: `INTERFACE.md` §2.
//!
//! Everything above this module assumes three things of it, and each one has
//! been wrong in this project before:
//!
//! 1. **The abort primitive reports the truth.** checkm8's `stall()` submits a
//!    control transfer and deliberately cuts it off part-way; the *number of
//!    bytes that made it through* is the value the SETUP stage computes its pad
//!    request from. A primitive that returns "success" after less than a
//!    microsecond of wall time did no work at all — that is the documented
//!    defect in `readmes/a9ctl-README.md`, where a sub-millisecond wait was
//!    measured against a one-second clock and the loop body never executed.
//!    See [`Transport::control_async_abort`].
//! 2. **`reset()` does not lie.** On Windows, libusb's `winusbx_reset_device`
//!    returns `LIBUSB_SUCCESS` *unconditionally*, including on the branch where
//!    all it did was cycle the non-control pipes
//!    (`libusb1-sys-0.7.0/libusb/libusb/os/windows_winusb.c:3380-3420`; the
//!    real `ResetDevice` call at `:3413` is guarded by
//!    `sub_api != SUB_API_WINUSB`). checkm8 needs a genuine bus reset — it is
//!    the trigger that runs the overwritten `dfu_handle_bus_reset` callback —
//!    so `Ok(())` tells us nothing. [`Transport::reset`] reports what actually
//!    happened and classifies the capability from the **measured** driver.
//! 3. **The bound driver is measured, not guessed.** [`Transport::driver_class`]
//!    reads the `Service` value SetupAPI has bound to the device node. WinUSB
//!    can be opened by libusb 1.0.27 (`windows_winusb.c:2306`) — it just cannot
//!    reset — so "which driver" decides whether an attempt is worth making.
//!
//! # House rule
//!
//! Nothing in this module opens, resets or writes to a device unless a caller
//! explicitly asks for it. No test in this file touches hardware.

use std::cell::Cell;
use std::ffi::CStr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use libusb1_sys as sys;
use rusb::UsbContext;

use crate::types::{
    reset_evidence, DeviceIdentity, DriverClass, ResetCapability, ResetEvidence, SeqCounter,
    XferResult, XferStatus, LIBUSB_ERROR_OTHER, MIN_TRUSTWORTHY_MICROS,
};
use crate::{APPLE_VID, DFU_MODE_PID};

/// The setup packet is 8 bytes and `control_transfer_len` adds it to the data
/// stage. If the binding's constant ever disagreed, every transfer length would
/// be wrong at once. Caught at compile time instead.
const _: () = assert!(
    sys::constants::LIBUSB_CONTROL_SETUP_SIZE == 8,
    "USB control setup packet must be exactly 8 bytes"
);

/// How long an identification read may take. Generous on purpose: it is not
/// part of the exploit's timing and a short timeout here produces the "device
/// answered nothing" ambiguity this project keeps paying for.
const IDENT_TIMEOUT_MS: u32 = 100;

/// Beyond `abort_after_ms`, how long to keep pumping before giving up on the
/// transfer ever being reaped. A transfer not reaped by then is leaked, never
/// freed: libusb may still write through it.
const HARD_GRACE: Duration = Duration::from_millis(2_000);

/// Timeout for each `DFU_GETSTATUS` read that brackets a reset. Short on
/// purpose: the device either answers immediately or it is not answering, and
/// this runs once per stage.
const DFU_STATE_TIMEOUT_MS: u32 = 100;

/// Attempts for the post-reset `DFU_GETSTATUS`. The device has just been reset,
/// so a first read can legitimately fail; a read that never succeeds is
/// reported as unread, not as "unchanged".
const DFU_STATE_POST_ATTEMPTS: usize = 3;

/// Slice used to pump events *after* the cancel has been requested. Once the
/// window has been honoured this value no longer affects when we abort — only
/// how quickly we notice that we did.
const POST_CANCEL_SLICE: Duration = Duration::from_millis(1);

/// Apple's DFU-mode serial descriptor index, tried when the device descriptor
/// does not declare one. a9ctl read identity successfully from index 3 while
/// gaster uses `device_descriptor.i_serial_number` (4 on our hardware), so both
/// are attempted and the one that answered is reported by
/// [`Transport::ident_index`].
const FALLBACK_STRING_INDEX: u8 = 3;
const ALT_FALLBACK_STRING_INDEX: u8 = 4;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// One control request, in the terms the bootrom's DFU state machine speaks.
///
/// `length` is `wLength`, always — including for the OUT and no-data paths,
/// where it also decides how many bytes are sent. A buffer shorter than
/// `length` is a caller bug and is refused loudly rather than truncated.
#[derive(Debug, Clone, Copy)]
pub struct CtrlReq {
    pub bm: u8,
    pub b: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl CtrlReq {
    pub const fn new(bm: u8, b: u8, value: u16, index: u16, length: u16) -> CtrlReq {
        CtrlReq {
            bm,
            b,
            value,
            index,
            length,
        }
    }

    /// Device-to-host?
    fn is_in(&self) -> bool {
        self.bm & sys::constants::LIBUSB_ENDPOINT_DIR_MASK == sys::constants::LIBUSB_ENDPOINT_IN
    }
}

/// What a reset physically did.
///
/// `libusb_rc` is libusb's return value, and on Windows it is **not** evidence
/// that a bus reset happened — see the module docs. The DFU state pair is the
/// observable evidence, `evidence` is the verdict drawn from all of it, and
/// `note` is the human sentence naming what actually occurred.
#[derive(Debug, Clone)]
pub struct ResetReport {
    /// libusb's own return value. `LIBUSB_SUCCESS` here means "no error was
    /// reported", not "the port was reset": `winusbx_reset_device` returns
    /// success unconditionally (`windows_winusb.c:3419`), and it also skips the
    /// `ResetDevice` call entirely when `HANDLE_VALID(interface_handle[0])` is
    /// false (`:3414-3416`) — still returning success.
    pub libusb_rc: i32,
    /// Was interface 0 claimed on this handle at open time?
    ///
    /// Load-bearing for exactly that skip. libusb can also fill the handle in
    /// later via `auto_claim` on the first control transfer (`:612-655`,
    /// `:2985`), so `false` here means "not claimed by us", not necessarily
    /// "invalid now".
    pub interface_claimed: bool,
    /// `bState` from `DFU_GETSTATUS` (`0xA1`/`3`, byte 4 of a 6-byte reply)
    /// taken immediately **before** the reset. `None` if the device did not
    /// answer — recorded as unread, never guessed.
    pub dfu_state_before: Option<u8>,
    /// The same read taken **after** the reset, once the device answered
    /// again. `None` means it never did: issued, effect unverified.
    pub dfu_state_after: Option<u8>,
    pub capability: ResetCapability,
    /// The verdict, from [`crate::types::reset_evidence`]. Four outcomes, not
    /// two: a `bool` cannot distinguish "delivered" from "unverified", and
    /// collapsing those is how a working driver gets accused.
    pub evidence: ResetEvidence,
    /// Convenience: `evidence == Delivered`. This is the field a `resets_real`
    /// counter should use; `capability` alone answers a different question.
    pub bus_reset_delivered: bool,
    pub micros: u64,
    pub note: String,
}

/// The human sentence for a reset. Pure, so every branch is testable without a
/// device.
///
/// The state pair is rendered as measured numbers, so a reader can check the
/// verdict instead of trusting it. `bState` values: 0 appIDLE, 2 dfuIDLE,
/// 6 manifestSync, 7 manifest, 8 manifestWaitReset.
pub fn reset_note(
    capability: ResetCapability,
    interface_claimed: bool,
    driver_service: &str,
    libusb_rc: i32,
    micros: u64,
    dfu_state_before: Option<u8>,
    dfu_state_after: Option<u8>,
) -> String {
    let service = if driver_service.is_empty() {
        "(unmeasured)"
    } else {
        driver_service
    };
    let state = |s: Option<u8>| match s {
        Some(v) => format!("{v} ({})", dfu_state_name(v)),
        None => "unread".to_string(),
    };
    let states = format!("DFU state {} -> {}", state(dfu_state_before), state(dfu_state_after));
    let evidence = crate::types::reset_evidence(
        capability,
        interface_claimed,
        libusb_rc,
        dfu_state_before,
        dfu_state_after,
    );

    if libusb_rc != sys::constants::LIBUSB_SUCCESS {
        return format!(
            "libusb_reset_device FAILED after {micros} us with {} ({libusb_rc}), driver service \
             '{service}', {states}. Nothing was confirmed: no bus reset was delivered and no pipe \
             cycle was reported either.",
            libusb_error_name(libusb_rc)
        );
    }

    let head = format!(
        "libusb_reset_device returned SUCCESS after {micros} us; driver service '{service}'; \
         {states}."
    );

    match (capability, interface_claimed) {
        (ResetCapability::Real, true) => match evidence {
            ResetEvidence::Delivered => format!(
                "{head} The DFU machine was parked in manifestWaitReset and read back idle: only a \
                 genuine bus reset clears that state, and libusbK/libusb0 implement ResetDevice \
                 (windows_winusb.c:3413), so it was called. A host-initiated bus reset was \
                 DELIVERED — the trigger that runs the overwritten dfu_handle_bus_reset callback. \
                 libusbK's own status is discarded by libusb (:3419); this verdict comes from the \
                 device, not from a return code."
            ),
            ResetEvidence::Refuted => format!(
                "{head} The DFU machine is STILL parked in manifestWaitReset after the reset. That \
                 is positive evidence the reset did not take effect on the device, whatever libusb \
                 returned. checkm8's dfu_handle_bus_reset will not have run. Suspect the driver \
                 binding, the port, or a hub between host and device — not the exploit."
            ),
            _ => format!(
                "{head} A real reset was requested on a capable driver, but the DFU state read the \
                 same before and after, so the effect is UNVERIFIED: a delivered port reset does \
                 not cycle VBUS, so an already-idle machine looks unchanged, which is \
                 indistinguishable here from a pipe cycle. Not success; not failure. To settle it, \
                 drive the machine into manifestWaitReset first (that is what stage_reset does) and \
                 reset again — then the transition is decisive."
            ),
        },
        (ResetCapability::Real, false) => format!(
            "{head} Driver service '{service}' does implement ResetDevice, but interface 0 was NOT \
             claimed at open: interface_handle[0] is invalid, the HANDLE_VALID guard at \
             windows_winusb.c:3415 failed, and ResetDevice was never called. This SUCCESS describes \
             a no-op. (libusb auto-claims on the first control transfer, :2985 — if one has been \
             submitted since the claim failed, the reset may have run after all. Neither is proven \
             here.)"
        ),
        (ResetCapability::PipeCycleOnly, _) => format!(
            "{head} That SUCCESS is not a reset: driver service '{service}' is WinUSB, so libusb's \
             winusbx_reset_device only aborted, flushed and reset the non-control pipes \
             (windows_winusb.c:3389-3410) and skipped ResetDevice because of the \
             sub_api != SUB_API_WINUSB guard at :3413 (the WinUSB DLL exports no ResetDevice at \
             all, :2439-2470). No bus reset reached the device, dfu_handle_bus_reset will NOT run, \
             and checkm8 cannot fire. LIBUSB_SUCCESS here means 'no error was reported', nothing \
             more."
        ),
        (ResetCapability::Unknown, _) => format!(
            "{head} Driver service '{service}' is neither libusbK, libusb0 nor WinUSB, so whether \
             libusb issued a real device reset cannot be determined from here. Treat this as NOT a \
             proven bus reset."
        ),
    }
}

/// Human name for a `bState` value. Only the ones this project can act on are
/// named; anything else is reported as unrecognised rather than guessed at.
pub fn dfu_state_name(state: u8) -> &'static str {
    match state {
        crate::DFU_STATE_APP_IDLE => "appIDLE",
        crate::DFU_STATE_DFU_IDLE => "dfuIDLE",
        crate::DFU_STATE_MANIFEST_SYNC => "manifestSync",
        crate::DFU_STATE_MANIFEST => "manifest",
        crate::DFU_STATE_MANIFEST_WAIT_RESET => "manifestWaitReset",
        1 => "dfuDNLOAD-IDLE",
        3 => "dfuDNBUSY",
        4 => "dfuDNLOAD-SYNC",
        5 => "dfuMANIFEST-SYNC",
        9 => "dfuUPLOAD-IDLE",
        10 => "dfuERROR",
        _ => "unrecognised",
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// An open 05AC:1227 device, plus everything we measured about its host side.
pub struct Transport {
    handle: rusb::DeviceHandle<rusb::Context>,
    identity: DeviceIdentity,
    driver: DriverClass,
    driver_service: String,
    seq: SeqCounter,
    /// Descriptor index that actually answered the identification read.
    ident_index: Cell<u8>,
    /// Did `libusb_claim_interface(0)` succeed at open? Load-bearing for reset:
    /// without `interface_handle[0]` libusb skips `ResetDevice` silently
    /// (`windows_winusb.c:3414-3416`).
    interface_claimed: bool,
    /// What the open path observed: claim, configuration, driver match.
    open_note: String,
    /// Set when an asynchronous transfer was submitted and never reaped. From
    /// that point every transfer is refused, because libusb still owns memory
    /// this process handed it.
    poisoned: bool,
    bus: u8,
    address: u8,
}

impl Transport {
    // -----------------------------------------------------------------------
    // Open
    // -----------------------------------------------------------------------

    /// Find and open the first Apple DFU device.
    ///
    /// The failure messages distinguish the cases that otherwise produce one
    /// identical "could not find device in DFU mode" — the exact ambiguity
    /// documented in `readmes/a9ctl-README.md`.
    pub fn open_first_dfu() -> Result<Transport, String> {
        let ctx = rusb::Context::new().map_err(|e| format!("libusb context init failed: {e}"))?;
        let devices = ctx
            .devices()
            .map_err(|e| format!("libusb device list failed: {e}"))?;
        let enumerated = devices.len();

        let mut apple_seen = 0usize;
        let mut other_pids: Vec<u16> = Vec::new();

        for dev in devices.iter() {
            let desc = match dev.device_descriptor() {
                Ok(d) => d,
                // A node that cannot even be described is not ours to explain.
                Err(_) => continue,
            };
            if desc.vendor_id() != APPLE_VID {
                continue;
            }
            apple_seen += 1;
            if desc.product_id() != DFU_MODE_PID {
                other_pids.push(desc.product_id());
                continue;
            }
            return Self::open_this(&dev, &desc);
        }

        if apple_seen == 0 {
            Err(format!(
                "no Apple device among the {enumerated} USB device(s) libusb enumerated \
                 (VID {APPLE_VID:04X}); enumeration itself worked, the device is absent"
            ))
        } else if other_pids.is_empty() {
            Err(format!(
                "{apple_seen} Apple device(s) present but none could be described \
                 (looking for {APPLE_VID:04X}:{DFU_MODE_PID:04X})"
            ))
        } else {
            let pids: Vec<String> = other_pids.iter().map(|p| format!("{p:04X}")).collect();
            Err(format!(
                "{apple_seen} Apple device(s) present, PID(s) {}, none in DFU mode \
                 ({DFU_MODE_PID:04X}). A device in recovery or normal mode is not exploitable \
                 — it must be put back into DFU.",
                pids.join(", ")
            ))
        }
    }

    fn open_this(
        dev: &rusb::Device<rusb::Context>,
        desc: &rusb::DeviceDescriptor,
    ) -> Result<Transport, String> {
        let bus = dev.bus_number();
        let address = dev.address();

        let handle = dev.open().map_err(|e| {
            format!(
                "found {APPLE_VID:04X}:{DFU_MODE_PID:04X} at bus {bus} address {address} but \
                 libusb could not open it: {e}. This is an access or busy condition, not a \
                 driver-class one: libusb 1.0.27 opens WinUSB-bound devices \
                 (windows_winusb.c:2306); rebind to libusbK only because of the reset \
                 capability, not because opening fails."
            )
        })?;

        let mut notes: Vec<String> = Vec::new();

        // libusb needs the interface claimed before interface-recipient control
        // requests; device-recipient ones are auto-claimed by the backend. Not
        // fatal to opening — but **load-bearing for the reset**: libusb only
        // calls `ResetDevice` when `interface_handle[0].api_handle` is valid
        // (`windows_winusb.c:3414-3416`), and it does not report the skip. So
        // the outcome is recorded, reported by `ResetReport::interface_claimed`,
        // and never assumed.
        let interface_claimed = match handle.claim_interface(0) {
            Ok(()) => {
                notes.push("interface 0 claimed (required for a real reset)".to_string());
                true
            }
            Err(e) => {
                notes.push(format!(
                    "interface 0 NOT claimed ({e}); libusb will skip ResetDevice unless a later \
                     control transfer auto-claims it (:2985), and will still report SUCCESS"
                ));
                false
            }
        };

        // A device with no configuration selected still answers *standard*
        // requests, so identification succeeds and the device looks healthy
        // while every CLASS request (DFU_DNLOAD, DFU_GETSTATUS) is never
        // answered at all. That was a real, expensive symptom in a9ctl; the
        // outcome is recorded here so it can never be invisible again.
        let active = handle.active_configuration();
        match active {
            Ok(1) => notes.push("configuration 1 already active".to_string()),
            other => match handle.set_active_configuration(1) {
                Ok(()) => notes.push(format!("configuration 1 selected (was {other:?})")),
                Err(e) => notes.push(format!(
                    "configuration NOT selected: active={other:?}, set_configuration(1) failed: \
                     {e}. Standard requests will still work; class requests may never be answered"
                )),
            },
        }

        let declared_i_serial = desc.serial_number_string_index().unwrap_or(0);
        let mut transport = Transport {
            handle,
            identity: DeviceIdentity::default(),
            driver: DriverClass::Unknown,
            driver_service: String::new(),
            seq: SeqCounter::new(),
            ident_index: Cell::new(declared_i_serial),
            interface_claimed,
            open_note: String::new(),
            poisoned: false,
            bus,
            address,
        };
        transport.identity.i_serial = declared_i_serial;
        transport.identity.pid = desc.product_id();

        // Identity comes off the wire, exactly as the exploit reads it — that
        // is also how the PWND marker becomes visible after a run.
        match transport.serial_descriptor() {
            Ok(serial) => {
                let mut id = DeviceIdentity::parse(&serial);
                id.i_serial = declared_i_serial;
                id.pid = desc.product_id();
                transport.identity = id;
            }
            Err(e) => notes.push(format!("serial descriptor unreadable: {e}")),
        }

        let (service, driver_note) = measure_driver_service(&transport.identity);
        transport.driver_service = service;
        transport.driver = DriverClass::from_service(&transport.driver_service);
        notes.push(driver_note);

        transport.open_note = format!("bus {bus} addr {address}; {}", notes.join("; "));
        Ok(transport)
    }

    // -----------------------------------------------------------------------
    // Identity, driver, capability
    // -----------------------------------------------------------------------

    /// Re-read the identity from the wire.
    ///
    /// Deliberately a live read, not a cached snapshot: after PATCH the payload
    /// overwrites the bootrom's serial-number string in memory, so the *only*
    /// host-visible proof of pwn is the same GET_DESCRIPTOR returning
    /// ` PWND:[checkm8]`. A cached identity could never show it.
    ///
    /// This issues a real control transfer. Do not call it between SETUP and
    /// PATCH.
    pub fn identity(&self) -> DeviceIdentity {
        match self.serial_descriptor() {
            Ok(serial) => {
                let mut id = DeviceIdentity::parse(&serial);
                id.i_serial = self.identity.i_serial;
                id.pid = self.identity.pid;
                id
            }
            Err(_) => self.identity.clone(),
        }
    }

    /// The Apple descriptor blob, tolerantly read.
    ///
    /// Tries the index the device descriptor declares first, then index 3 and 4.
    /// The first answer that actually parses as an Apple descriptor (`CPID`,
    /// `SRTG` or `PWND`) wins; failing that, the first non-empty answer; failing
    /// that, the last error.
    pub fn serial_descriptor(&self) -> Result<String, String> {
        let declared = self.identity.i_serial;
        let mut candidates: Vec<u8> = Vec::with_capacity(4);
        if declared != 0 {
            candidates.push(declared);
        }
        for idx in [FALLBACK_STRING_INDEX, ALT_FALLBACK_STRING_INDEX] {
            if !candidates.contains(&idx) {
                candidates.push(idx);
            }
        }

        let mut first_nonempty: Option<(u8, String)> = None;
        let mut last_error = "no serial string descriptor could be read".to_string();

        for index in candidates {
            match self.read_string_descriptor(index) {
                Ok(s) => {
                    if looks_like_apple_descriptor(&s) {
                        self.ident_index.set(index);
                        return Ok(s);
                    }
                    if first_nonempty.is_none() {
                        first_nonempty = Some((index, s));
                    }
                }
                Err(e) => last_error = e,
            }
        }

        match first_nonempty {
            Some((index, s)) => {
                self.ident_index.set(index);
                Ok(s)
            }
            None => Err(last_error),
        }
    }

    fn read_string_descriptor(&self, index: u8) -> Result<String, String> {
        let req = CtrlReq::new(
            0x80,
            0x06, // GET_DESCRIPTOR
            (3u16 << 8) | index as u16,
            0x0409, // en-US
            255,
        );
        let mut buf = [0u8; 255];
        let r = self.ctrl_sync(req, &mut buf, IDENT_TIMEOUT_MS);
        if !r.ok() {
            return Err(format!(
                "GET_DESCRIPTOR(3,{index}) -> {} (libusb {})",
                r.status.as_str(),
                r.libusb_rc
            ));
        }
        if r.transferred < 2 {
            return Err(format!(
                "GET_DESCRIPTOR(3,{index}) returned {} byte(s), too short to hold a string",
                r.transferred
            ));
        }
        let body = &buf[2..r.transferred];
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    /// The driver service actually bound to this device node, as the OS reports
    /// it. Empty when the node could not be found.
    pub fn driver_service(&self) -> &str {
        &self.driver_service
    }

    /// Measured from SetupAPI's `Service` property for this device node — never
    /// guessed from PID, VID or whether an open succeeded.
    pub fn driver_class(&self) -> DriverClass {
        self.driver
    }

    /// What a reset can physically do, given the driver that is bound.
    pub fn reset_capability(&self) -> ResetCapability {
        ResetCapability::from_driver(self.driver)
    }

    /// Did interface 0 get claimed at open? A reset on an unclaimed interface
    /// is skipped by libusb while still reporting success.
    pub fn interface_claimed(&self) -> bool {
        self.interface_claimed
    }

    /// Which string-descriptor index answered the identification read. On our
    /// A9s the device descriptor says 4; a9ctl read identity from 3.
    pub fn ident_index(&self) -> u8 {
        self.ident_index.get()
    }

    /// What the open path saw: claim, configuration, driver match. Exposed
    /// because "every class request times out" had a silent cause in a9ctl and
    /// nobody could see it.
    pub fn open_note(&self) -> &str {
        &self.open_note
    }

    /// USB bus and address, for logs.
    pub fn bus_address(&self) -> (u8, u8) {
        (self.bus, self.address)
    }

    // -----------------------------------------------------------------------
    // Synchronous transfers
    // -----------------------------------------------------------------------

    /// Control transfer. `wLength` is `r.length`; the buffer must be at least
    /// that long. For an IN request up to `r.length` bytes are written back.
    pub fn control(&mut self, r: CtrlReq, data: &mut [u8], timeout_ms: u32) -> XferResult {
        if self.poisoned {
            return self.refused(r);
        }
        self.ctrl_sync(r, data, timeout_ms)
    }

    /// Control transfer, host to device. Only the first `r.length` bytes of
    /// `data` are sent.
    pub fn control_out(&mut self, r: CtrlReq, data: &[u8], timeout_ms: u32) -> XferResult {
        if self.poisoned {
            return self.refused(r);
        }
        let mut scratch = data.to_vec();
        self.ctrl_sync(r, &mut scratch, timeout_ms)
    }

    /// Control transfer with no data stage of its own.
    ///
    /// `r.length > 0` sends that many **zero** bytes, exactly as the reference
    /// does (`gaster.c:468-479`: `memset(p_data, '\0', w_len)`). Passing a null
    /// pointer with a non-zero `wLength` — the tempting "no data" shortcut — is
    /// `LIBUSB_ERROR_INVALID_PARAM` and would silently never reach the device.
    pub fn control_no_data(&mut self, r: CtrlReq, timeout_ms: u32) -> XferResult {
        if self.poisoned {
            return self.refused(r);
        }
        let mut zeros = vec![0u8; r.length as usize];
        self.ctrl_sync(r, &mut zeros, timeout_ms)
    }

    fn ctrl_sync(&self, r: CtrlReq, data: &mut [u8], timeout_ms: u32) -> XferResult {
        let seq = self.seq.next();
        let requested = r.length as usize;

        if data.len() < requested {
            return XferResult {
                seq,
                bm_request_type: r.bm,
                b_request: r.b,
                w_value: r.value,
                w_index: r.index,
                w_length: r.length,
                status: XferStatus::Error,
                transferred: 0,
                requested,
                micros: 0,
                libusb_rc: sys::constants::LIBUSB_ERROR_INVALID_PARAM,
                abort_after_ms: None,
            };
        }

        let ptr = if requested == 0 {
            std::ptr::null_mut()
        } else {
            data.as_mut_ptr() as *mut libc::c_uchar
        };

        let started = Instant::now();
        // SAFETY: the handle is open and owned by `self`; the buffer is a live
        // slice of at least `requested` bytes, or null with length 0, which is
        // the documented "no data stage" form.
        let rc = unsafe {
            sys::libusb_control_transfer(
                self.handle.as_raw(),
                r.bm,
                r.b,
                r.value,
                r.index,
                ptr,
                r.length,
                timeout_ms,
            )
        };
        let micros = started.elapsed().as_micros() as u64;

        let status = XferStatus::from_libusb_rc(rc);
        let transferred = if rc >= 0 {
            (rc as usize).min(requested)
        } else {
            0
        };

        XferResult {
            seq,
            bm_request_type: r.bm,
            b_request: r.b,
            w_value: r.value,
            w_index: r.index,
            w_length: r.length,
            status,
            transferred,
            requested,
            micros,
            libusb_rc: rc,
            abort_after_ms: None,
        }
    }

    // -----------------------------------------------------------------------
    // The abort primitive
    // -----------------------------------------------------------------------

    /// **checkm8's `stall()`** — the primitive the exploit is built on.
    ///
    /// Submits `r` asynchronously, lets it run for `cancel_after_ms`, cancels
    /// it, and reports `actual_length`: how many bytes the device actually
    /// delivered before the host cut the transfer off. The SETUP stage computes
    /// its pad request from that number, so a fabricated or lost count is not a
    /// reporting bug — it is a different exploit.
    ///
    /// Three properties this implementation guarantees, each one a defect in
    /// something we have already shipped:
    ///
    /// * **The abort window is real.** The deadline is an `Instant` computed
    ///   with microsecond arithmetic, and the slice handed to libusb is the
    ///   *remaining* time — never a fixed pump interval. a9ctl used a fixed 5 ms
    ///   pump and only checked its deadline after each slice, so windows 0..4
    ///   all aborted at >= 5 ms: one experiment wearing six labels. Here window
    ///   0 polls without blocking and cancels, and window 1 asks for 1 ms.
    /// * **The cancel happens exactly once, at the deadline**, not before. The
    ///   transfer is never cancelled in the same instant it was submitted
    ///   without libusb having looked at it at least once.
    /// * **The reported `micros` is measured**, from immediately before
    ///   `libusb_submit_transfer` to the moment the completion callback had
    ///   run, so a reader can prove from the trace whether the window was
    ///   honoured or the host overshot it.
    ///
    /// libusb's own transfer timeout is disabled (`transfer->timeout = 0`): the
    /// deadline here is the only thing that ends the transfer, so there is no
    /// race between two independently-timed mechanisms and a cancelled transfer
    /// always carries a partial `actual_length` rather than being relabelled a
    /// timeout with none (`windows_common.c:825-832`: on
    /// `ERROR_OPERATION_ABORTED`, libusb copies the kernel's partial length and
    /// only then reports `CANCELLED`).
    pub fn control_async_abort(
        &mut self,
        r: CtrlReq,
        buf: &mut [u8],
        cancel_after_ms: u32,
    ) -> XferResult {
        if self.poisoned {
            return self.refused(r);
        }
        let requested = r.length as usize;
        if buf.len() < requested {
            let seq = self.seq.next();
            return XferResult {
                seq,
                bm_request_type: r.bm,
                b_request: r.b,
                w_value: r.value,
                w_index: r.index,
                w_length: r.length,
                status: XferStatus::Error,
                transferred: 0,
                requested,
                micros: 0,
                libusb_rc: sys::constants::LIBUSB_ERROR_INVALID_PARAM,
                abort_after_ms: Some(cancel_after_ms),
            };
        }
        self.async_abort_core(r, buf, cancel_after_ms)
    }

    /// gaster's `send_usb_control_request_async_no_data`: the same aborted
    /// transfer, with a zero-filled data stage of `r.length` bytes.
    ///
    /// This is the shape the reference actually submits for the SETUP stage's
    /// 0x800-byte `DFU_DNLOAD` (`gaster.c:853`).
    pub fn control_async_abort_no_data(&mut self, r: CtrlReq, cancel_after_ms: u32) -> XferResult {
        let mut zeros = vec![0u8; r.length as usize];
        self.control_async_abort(r, &mut zeros, cancel_after_ms)
    }

    fn async_abort_core(&mut self, r: CtrlReq, buf: &mut [u8], cancel_after_ms: u32) -> XferResult {
        let seq = self.seq.next();
        let requested = r.length as usize;
        let dir_in = r.is_in();
        let window = abort_window(cancel_after_ms);
        let ctx = self.handle.context().as_raw();
        let handle = self.handle.as_raw();

        // SAFETY: every pointer below is either owned by a live allocation for
        // the whole call, or is a libusb object we allocate and hand over. The
        // rule that keeps this sound is the module's: a transfer may only be
        // freed once its completion callback has run.
        unsafe {
            let transfer = sys::libusb_alloc_transfer(0);
            if transfer.is_null() {
                return self.failed(seq, r, requested, cancel_after_ms, "libusb_alloc_transfer returned NULL", 0);
            }

            let total = control_transfer_len(requested);
            // malloc, not Vec: libusb owns this buffer and is entitled to write
            // through it after we return if the transfer is still queued.
            let raw = libc::malloc(total) as *mut u8;
            if raw.is_null() {
                sys::libusb_free_transfer(transfer);
                return self.failed(seq, r, requested, cancel_after_ms, "transfer buffer allocation failed", 0);
            }
            std::ptr::write_bytes(raw, 0, total);

            sys::libusb_fill_control_setup(
                raw,
                r.bm,
                r.b,
                r.value,
                r.index,
                r.length,
            );
            if !dir_in && requested > 0 {
                std::ptr::copy_nonoverlapping(
                    buf.as_ptr(),
                    raw.add(sys::constants::LIBUSB_CONTROL_SETUP_SIZE),
                    requested,
                );
            }

            (*transfer).dev_handle = handle;
            (*transfer).flags = 0;
            (*transfer).endpoint = 0; // control transfers always use EP0
            (*transfer).transfer_type = sys::constants::LIBUSB_TRANSFER_TYPE_CONTROL;
            // Disabled on purpose: our deadline is the only terminator. See the
            // doc comment.
            (*transfer).timeout = 0;
            // Not seeded to 0: 0 is LIBUSB_TRANSFER_COMPLETED, so a stale read
            // would look like success. libusb fills this in before the callback.
            (*transfer).status = -1;
            (*transfer).length = total as libc::c_int;
            (*transfer).actual_length = 0;
            (*transfer).callback = on_complete;
            (*transfer).user_data = std::ptr::null_mut();
            (*transfer).buffer = raw;
            (*transfer).num_iso_packets = 0;

            // The completion flag lives on the heap, not the stack: if the
            // callback ever runs after this function returns, a stack local
            // would be a write into a dead frame. Worst case here is a leak.
            let flag = Box::into_raw(Box::new(AtomicI32::new(0)));
            (*transfer).user_data = flag as *mut std::os::raw::c_void;

            let started = Instant::now();
            let submitted = sys::libusb_submit_transfer(transfer);
            if submitted != sys::constants::LIBUSB_SUCCESS {
                // A rejected submit never queues the transfer and never calls
                // the callback, so these are unambiguously ours to release.
                libc::free(raw as *mut libc::c_void);
                sys::libusb_free_transfer(transfer);
                drop(Box::from_raw(flag));
                let micros = started.elapsed().as_micros() as u64;
                let name = libusb_error_name(submitted);
                return self.failed(
                    seq,
                    r,
                    requested,
                    cancel_after_ms,
                    &format!("libusb_submit_transfer failed: {name} ({submitted})"),
                    micros,
                );
            }

            let deadline = started + window;
            let pumped = pump_until_reaped(ctx, transfer, flag, deadline, deadline + HARD_GRACE);
            let micros = started.elapsed().as_micros() as u64;

            if !pumped.reaped {
                // libusb still owns the transfer and may still write through
                // the buffer and the flag. Leaking both is the only sound
                // option, and the handle is no longer trustworthy, so it is
                // poisoned rather than driven on.
                self.poisoned = true;
                return XferResult {
                    seq,
                    bm_request_type: r.bm,
                    b_request: r.b,
                    w_value: r.value,
                    w_index: r.index,
                    w_length: r.length,
                    status: XferStatus::Error,
                    transferred: 0,
                    requested,
                    micros,
                    libusb_rc: LIBUSB_ERROR_OTHER,
                    abort_after_ms: Some(cancel_after_ms),
                };
            }

            let transfer_status = (*transfer).status;
            let raw_len = (*transfer).actual_length.max(0) as usize;
            let mut status = XferStatus::from_transfer_status(transfer_status);

            // Clamped, not trusted: libusb can report a wire count larger than
            // requested on a babble, and a caller slicing `data[..n]` would
            // panic. The raw count is what `transferred` reports whenever it
            // fits, because normalising it away is how a real partial becomes a
            // plausible zero.
            let transferred = raw_len.min(requested);
            if dir_in && transferred > 0 {
                std::ptr::copy_nonoverlapping(
                    raw.add(sys::constants::LIBUSB_CONTROL_SETUP_SIZE),
                    buf.as_mut_ptr(),
                    transferred,
                );
            }

            libc::free(raw as *mut libc::c_void);
            sys::libusb_free_transfer(transfer);
            drop(Box::from_raw(flag));

            // The floor. A transfer cannot really have happened this fast, so
            // the timing — and therefore the window this result is supposed to
            // describe — is refuted. Reported as an error, never as an answer.
            if micros < MIN_TRUSTWORTHY_MICROS {
                status = XferStatus::Error;
            }

            XferResult {
                seq,
                bm_request_type: r.bm,
                b_request: r.b,
                w_value: r.value,
                w_index: r.index,
                w_length: r.length,
                status,
                transferred,
                requested,
                micros,
                // For the asynchronous path this is libusb's
                // `libusb_transfer_status`, not a `LIBUSB_ERROR_*` code.
                libusb_rc: transfer_status,
                abort_after_ms: Some(cancel_after_ms),
            }
        }
    }

    fn failed(
        &self,
        seq: u64,
        r: CtrlReq,
        requested: usize,
        cancel_after_ms: u32,
        _why: &str,
        micros: u64,
    ) -> XferResult {
        XferResult {
            seq,
            bm_request_type: r.bm,
            b_request: r.b,
            w_value: r.value,
            w_index: r.index,
            w_length: r.length,
            status: XferStatus::Error,
            transferred: 0,
            requested,
            micros,
            libusb_rc: LIBUSB_ERROR_OTHER,
            abort_after_ms: Some(cancel_after_ms),
        }
    }

    fn refused(&self, r: CtrlReq) -> XferResult {
        XferResult {
            seq: self.seq.next(),
            bm_request_type: r.bm,
            b_request: r.b,
            w_value: r.value,
            w_index: r.index,
            w_length: r.length,
            status: XferStatus::Error,
            transferred: 0,
            requested: r.length as usize,
            micros: 0,
            libusb_rc: LIBUSB_ERROR_OTHER,
            abort_after_ms: None,
        }
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    /// `bState` from `DFU_GETSTATUS` (`0xA1`/`3`, 6-byte reply, byte 4).
    ///
    /// `None` when the device did not answer or answered short — both mean
    /// *unread*, never "unchanged". A reset verdict must not be built on a read
    /// that did not happen.
    fn dfu_status_state(&self, timeout_ms: u32) -> Option<u8> {
        if self.poisoned {
            return None;
        }
        let req = CtrlReq::new(0xA1, crate::DFU_GETSTATUS, 0, 0, 6);
        let mut buf = [0u8; 6];
        let r = self.ctrl_sync(req, &mut buf, timeout_ms);
        if r.ok() && r.transferred >= 5 {
            Some(buf[4])
        } else {
            None
        }
    }

    /// Reset the port — and say what that physically did.
    ///
    /// **`Ok` does not mean "a bus reset happened".** It means the reset call
    /// returned success, which on Windows it does unconditionally:
    /// `winusbx_reset_device` returns `LIBUSB_SUCCESS` at the end of a function
    /// whose WinUSB branch only aborts, flushes and resets pipes
    /// (`windows_winusb.c:3389-3410`) and skips `ResetDevice` entirely because
    /// of the `sub_api != SUB_API_WINUSB` guard at `:3413`. The same guard pair
    /// at `:3414-3416` skips the call when interface 0 is not claimed. Neither
    /// skip is reported by libusb.
    ///
    /// So the evidence is taken from the **device**: `DFU_GETSTATUS` is read
    /// before and after the reset, and a machine that was parked in
    /// `manifestWaitReset` and reads back idle is proof that a bus reset
    /// physically happened — because only a bus reset clears that state. A
    /// machine still parked afterwards is proof that it did not. An already
    /// idle machine is `Unverified`, which is a real outcome and is reported as
    /// one, never as success.
    ///
    /// Returns `Err` only when the call itself failed; the message says
    /// explicitly that nothing was confirmed, because the reference ignores
    /// this return value and continues.
    ///
    /// A genuine reset usually invalidates the handle — the device
    /// re-enumerates — so the caller re-opens afterwards, as gaster does.
    pub fn reset(&mut self) -> Result<ResetReport, String> {
        let dfu_state_before = self.dfu_status_state(DFU_STATE_TIMEOUT_MS);

        let started = Instant::now();
        // SAFETY: the handle is open and owned by `self`.
        let rc = unsafe { sys::libusb_reset_device(self.handle.as_raw()) };
        let micros = started.elapsed().as_micros() as u64;
        let capability = self.reset_capability();

        if rc != sys::constants::LIBUSB_SUCCESS {
            return Err(format!(
                "libusb_reset_device failed: {} ({rc}) after {micros} us with driver service \
                 '{}'. Nothing was confirmed: no bus reset was delivered and no pipe cycle was \
                 reported either. The reference ignores this return value and continues; doing \
                 the same is a choice the caller may make, but it is not evidence.",
                libusb_error_name(rc),
                self.driver_service()
            ));
        }

        // Read the device back. A real port reset does not cycle VBUS and keeps
        // the pipe handles valid, so the same handle can answer — but it may
        // take a moment, hence the retries.
        let mut dfu_state_after = None;
        for _ in 0..DFU_STATE_POST_ATTEMPTS {
            dfu_state_after = self.dfu_status_state(DFU_STATE_TIMEOUT_MS);
            if dfu_state_after.is_some() {
                break;
            }
        }

        let evidence = reset_evidence(
            capability,
            self.interface_claimed,
            rc,
            dfu_state_before,
            dfu_state_after,
        );

        Ok(ResetReport {
            libusb_rc: rc,
            interface_claimed: self.interface_claimed,
            dfu_state_before,
            dfu_state_after,
            capability,
            evidence,
            bus_reset_delivered: evidence.delivered(),
            micros,
            note: reset_note(
                capability,
                self.interface_claimed,
                self.driver_service(),
                rc,
                micros,
                dfu_state_before,
                dfu_state_after,
            ),
        })
    }

    // -----------------------------------------------------------------------
    // Diagnostics
    // -----------------------------------------------------------------------

    /// The most recently allocated transfer sequence number; 0 before the first.
    pub fn seq(&self) -> u64 {
        self.seq.last()
    }

    /// True once an asynchronous transfer was submitted and never reaped. From
    /// that point this `Transport` refuses every request: libusb still owns
    /// memory we handed it. Close it and re-open the device.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

// ---------------------------------------------------------------------------
// The abort window, in microseconds
// ---------------------------------------------------------------------------

/// `cancel_after_ms` → the wall-time window, in exact microseconds.
///
/// This is the arithmetic the old tool got wrong: it divided a millisecond
/// timeout by 1000.0 into an `int`, then compared it against `time(nullptr)`,
/// which advances in whole seconds — so a 0.0001 ms window became 0 seconds and
/// the wait loop ran zero times. Microseconds, integer, no float, no rounding
/// to a coarser unit anywhere in the path.
pub fn abort_window(cancel_after_ms: u32) -> Duration {
    Duration::from_micros(cancel_after_ms as u64 * 1_000)
}

/// Split a duration into the `(tv_sec, tv_usec)` pair `libusb` wants.
///
/// Kept separate from the `libc::timeval` construction so the split can be
/// tested without libusb types, and so that nobody is tempted to route this
/// through a coarser unit.
pub fn timeval_parts(d: Duration) -> (i64, i64) {
    (d.as_secs() as i64, d.subsec_micros() as i64)
}

/// How long to pump events for on the next iteration.
///
/// Before the cancel: exactly what is left of the window, so the requested wait
/// can never exceed the abort deadline and a 1 ms window asks for 1 ms rather
/// than a fixed 5 ms slice. After the cancel: at least [`POST_CANCEL_SLICE`],
/// because from that point the wait no longer decides *when* we abort, only how
/// fast we notice.
pub fn pump_slice(remaining: Duration, cancelled: bool) -> Duration {
    if cancelled {
        remaining.max(POST_CANCEL_SLICE)
    } else {
        remaining
    }
}

/// libusb's transfer length for a control transfer: setup packet + data stage.
pub fn control_transfer_len(data_len: usize) -> usize {
    sys::constants::LIBUSB_CONTROL_SETUP_SIZE + data_len
}

// ---------------------------------------------------------------------------
// Asynchronous plumbing
// ---------------------------------------------------------------------------

struct Pumped {
    reaped: bool,
}

/// Completion callback. libusb calls this from the thread pumping events.
///
/// `extern "system"` matches libusb's `LIBUSB_CALL`, which is `WINAPI` on
/// Windows; `extern "C"` would be an ABI mismatch there.
extern "system" fn on_complete(transfer: *mut sys::libusb_transfer) {
    // SAFETY: libusb hands back the transfer we submitted; `user_data` is the
    // leaked `AtomicI32` from `async_abort_core`.
    unsafe {
        let flag = (*transfer).user_data as *const AtomicI32;
        if !flag.is_null() {
            (*flag).store(1, Ordering::Release);
        }
    }
}

/// Pump events until the completion callback has run, or the hard deadline.
///
/// The cancel is requested exactly once, the first time the real deadline has
/// passed — never before it, and never repeatedly. `libusb_cancel_transfer`
/// does not cancel synchronously: it requests cancellation and returns, so the
/// loop keeps pumping until the callback actually fires.
///
/// # Safety
///
/// `ctx`, `transfer` and `flag` must all be valid for the duration, and the
/// transfer must have been submitted successfully.
unsafe fn pump_until_reaped(
    ctx: *mut sys::libusb_context,
    transfer: *mut sys::libusb_transfer,
    flag: *const AtomicI32,
    deadline: Instant,
    hard_deadline: Instant,
) -> Pumped {
    let mut cancelled = false;

    loop {
        if (*flag).load(Ordering::Acquire) != 0 {
            return Pumped { reaped: true };
        }
        let now = Instant::now();
        if now >= hard_deadline {
            return Pumped { reaped: false };
        }

        let slice = pump_slice(deadline.saturating_duration_since(now), cancelled);
        let (secs, usecs) = timeval_parts(slice);
        let tv = libc::timeval {
            tv_sec: secs as libc::c_long,
            tv_usec: usecs as libc::c_long,
        };

        // `flag` is an `AtomicI32`, whose layout is exactly `c_int`; libusb only
        // ever reads through this pointer (io.c:2367, 2380 — it never writes
        // it), so the cast is a plain re-typing of the same 4 bytes.
        let rc = sys::libusb_handle_events_timeout_completed(
            ctx,
            &tv,
            flag as *const AtomicI32 as *mut libc::c_int,
        );

        if rc == sys::constants::LIBUSB_ERROR_INTERRUPTED {
            // A transient interruption must not abandon a healthy in-flight
            // transfer.
            continue;
        }
        if rc != sys::constants::LIBUSB_SUCCESS {
            // We cannot keep driving libusb; report the transfer as unreaped so
            // the caller poisons the handle rather than freeing live memory.
            return Pumped { reaped: false };
        }

        if !cancelled && Instant::now() >= deadline {
            let _ = sys::libusb_cancel_transfer(transfer);
            cancelled = true;
        }
    }
}

/// Human-readable libusb error string, for messages that would otherwise be
/// bare negative integers.
fn libusb_error_name(code: libc::c_int) -> String {
    // SAFETY: `libusb_error_name` returns a static string for any input.
    unsafe {
        let p = sys::libusb_error_name(code);
        if p.is_null() {
            return format!("unknown error {code}");
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// Does this string look like Apple's DFU descriptor rather than a stray
/// product string? `PWND` counts: after a successful run the serial is replaced
/// by the pwn marker, and that is the one answer worth accepting.
fn looks_like_apple_descriptor(s: &str) -> bool {
    s.contains("CPID") || s.contains("SRTG") || s.contains("PWND")
}

// ---------------------------------------------------------------------------
// Bound-driver measurement (SetupAPI)
// ---------------------------------------------------------------------------

/// One present device node, as SetupAPI describes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsbNode {
    pub instance_id: String,
    pub hardware_id: String,
    pub service: String,
}

/// The descriptor part of a Windows device instance ID:
/// `USB\VID_05AC&PID_1227\<descriptor>` → `<descriptor>`.
fn instance_tail(instance_id: &str) -> &str {
    match instance_id.rsplit_once('\\') {
        Some((_, tail)) => tail,
        None => instance_id,
    }
}

/// Windows cannot put a space in an instance ID, so it hands back the Apple
/// descriptor with underscores where libusb uses spaces. Compare the two forms
/// as one.
fn normalise_descriptor(s: &str) -> String {
    s.replace('_', " ").trim().to_ascii_lowercase()
}

/// Pick the device node that is *our* device, preferring an exact descriptor
/// match over the VID/PID fallback. Pure, so the selection rule is testable.
pub fn select_driver_service(nodes: &[UsbNode], identity: &DeviceIdentity) -> Option<String> {
    let want_vid_pid = format!("VID_{APPLE_VID:04X}&PID_{DFU_MODE_PID:04X}");
    let mut fallback: Option<&UsbNode> = None;

    for node in nodes {
        let hw = node.hardware_id.to_ascii_uppercase();
        if !hw.contains(&want_vid_pid) {
            continue;
        }
        if fallback.is_none() {
            fallback = Some(node);
        }
        if !identity.serial.is_empty()
            && normalise_descriptor(instance_tail(&node.instance_id))
                == normalise_descriptor(&identity.serial)
        {
            return Some(node.service.clone());
        }
    }

    fallback.map(|n| n.service.clone())
}

/// Measure the driver service bound to this device.
///
/// Returns `(service, note)`. The note says why the service is empty when it
/// is, because "no service" and "enumeration broken" must not look alike.
fn measure_driver_service(identity: &DeviceIdentity) -> (String, String) {
    let nodes = enumerate_usb_nodes();
    if nodes.is_empty() {
        return (
            String::new(),
            "SetupAPI returned no device nodes: the bound driver could not be measured"
                .to_string(),
        );
    }
    match select_driver_service(&nodes, identity) {
        Some(service) if !service.is_empty() => {
            let note = format!("driver service '{service}' read from the device node");
            (service, note)
        }
        Some(_) => (
            String::new(),
            "the device node was found but its Service property is empty (driver bound but not \
             loaded, or needs re-enumeration)"
                .to_string(),
        ),
        None => (
            String::new(),
            format!(
                "no SetupAPI node matched {APPLE_VID:04X}:{DFU_MODE_PID:04X} among {} present \
                 device(s); the bound driver is unknown, not absent",
                nodes.len()
            ),
        ),
    }
}

#[cfg(windows)]
mod win {
    //! Raw SetupAPI declarations.
    //!
    //! Hand-rolled because `windows-sys` is not a permitted dependency here.
    //! Only read paths are declared: enumeration and two property reads. No
    //! device handle is opened and nothing is written.

    pub type Handle = *mut std::ffi::c_void;
    pub type Bool = i32;
    pub type Dword = u32;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    pub struct SpDevinfoData {
        cb_size: Dword,
        class_guid: Guid,
        dev_inst: Dword,
        reserved: usize,
    }

    impl Default for SpDevinfoData {
        fn default() -> Self {
            SpDevinfoData {
                cb_size: std::mem::size_of::<SpDevinfoData>() as Dword,
                class_guid: Guid::default(),
                dev_inst: 0,
                reserved: 0,
            }
        }
    }

    pub const DIGCF_PRESENT: Dword = 0x0000_0002;
    pub const DIGCF_ALLCLASSES: Dword = 0x0000_0004;
    pub const SPDRP_HARDWAREID: Dword = 0x0000_0001;
    pub const SPDRP_SERVICE: Dword = 0x0000_0004;
    pub const ERROR_NO_MORE_ITEMS: i32 = 259;
    pub const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

    #[link(name = "setupapi")]
    extern "system" {
        pub fn SetupDiGetClassDevsW(
            class_guid: *const Guid,
            enumerator: *const u16,
            hwnd_parent: Handle,
            flags: Dword,
        ) -> Handle;
        pub fn SetupDiEnumDeviceInfo(
            dev_info: Handle,
            member_index: Dword,
            dev_info_data: *mut SpDevinfoData,
        ) -> Bool;
        pub fn SetupDiGetDeviceRegistryPropertyW(
            dev_info: Handle,
            dev_info_data: *const SpDevinfoData,
            property: Dword,
            property_reg_data_type: *mut Dword,
            property_buffer: *mut u8,
            property_buffer_size: Dword,
            required_size: *mut Dword,
        ) -> Bool;
        pub fn SetupDiGetDeviceInstanceIdW(
            dev_info: Handle,
            dev_info_data: *const SpDevinfoData,
            device_instance_id: *mut u16,
            device_instance_id_size: Dword,
            required_size: *mut Dword,
        ) -> Bool;
        pub fn SetupDiDestroyDeviceInfoList(dev_info: Handle) -> Bool;
    }
}

#[cfg(windows)]
fn last_error() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(windows)]
fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Read a REG_SZ / REG_MULTI_SZ property, growing the buffer if the first
/// attempt was too small. The first string is what callers here want (a
/// multi-string hardware ID's first entry is the one that names the device).
#[cfg(windows)]
fn node_property(dev_info: win::Handle, data: &win::SpDevinfoData, property: u32) -> Option<String> {
    use win::*;
    let mut buf = vec![0u16; 512];
    let mut needed: Dword = 0;
    let mut reg_type: Dword = 0;

    // SAFETY: `dev_info` is a live set from SetupDiGetClassDevsW and `data` a
    // correctly sized member of it; `buf` is a live mutable slice.
    let ok = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            dev_info,
            data,
            property,
            &mut reg_type,
            buf.as_mut_ptr() as *mut u8,
            (buf.len() * 2) as Dword,
            &mut needed,
        )
    };
    if ok != 0 {
        return Some(wide_to_string(&buf));
    }
    if last_error() == ERROR_INSUFFICIENT_BUFFER && needed > 0 {
        let mut big = vec![0u16; (needed as usize / 2) + 2];
        // SAFETY: same call, with a buffer sized from what SetupAPI asked for.
        let ok2 = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                dev_info,
                data,
                property,
                &mut reg_type,
                big.as_mut_ptr() as *mut u8,
                (big.len() * 2) as Dword,
                &mut needed,
            )
        };
        if ok2 != 0 {
            return Some(wide_to_string(&big));
        }
    }
    None
}

#[cfg(windows)]
fn node_instance_id(dev_info: win::Handle, data: &win::SpDevinfoData) -> Option<String> {
    use win::*;
    let mut buf = vec![0u16; 512];
    let mut needed: Dword = 0;
    // SAFETY: live set, correctly sized member, live buffer.
    let ok = unsafe {
        SetupDiGetDeviceInstanceIdW(
            dev_info,
            data,
            buf.as_mut_ptr(),
            buf.len() as Dword,
            &mut needed,
        )
    };
    if ok != 0 {
        return Some(wide_to_string(&buf));
    }
    if last_error() == ERROR_INSUFFICIENT_BUFFER && needed > 0 {
        let mut big = vec![0u16; needed as usize + 2];
        // SAFETY: same call, buffer sized from the reported requirement.
        let ok2 = unsafe {
            SetupDiGetDeviceInstanceIdW(
                dev_info,
                data,
                big.as_mut_ptr(),
                big.len() as Dword,
                &mut needed,
            )
        };
        if ok2 != 0 {
            return Some(wide_to_string(&big));
        }
    }
    None
}

/// Every present device node, read-only.
///
/// This opens no device handle and writes nothing; it reads the device tree,
/// which is what makes it safe to call from a test.
#[cfg(windows)]
pub fn enumerate_usb_nodes() -> Vec<UsbNode> {
    use win::*;
    let mut out = Vec::new();

    // SAFETY: standard SetupAPI enumeration; the set is destroyed before return.
    let dev_info: Handle = unsafe {
        SetupDiGetClassDevsW(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_ALLCLASSES,
        )
    };

    // HDEVINFO is a handle, not a pointer: failure is INVALID_HANDLE_VALUE
    // (-1), and some paths return 0. `is_null()` alone would miss the first.
    if dev_info.is_null() || dev_info as isize == -1 {
        return out;
    }

    let mut index: Dword = 0;
    loop {
        let mut data = SpDevinfoData::default();
        // SAFETY: `dev_info` is live; `data` is correctly sized and initialised.
        let ok = unsafe { SetupDiEnumDeviceInfo(dev_info, index, &mut data) };
        if ok == 0 {
            if last_error() == ERROR_NO_MORE_ITEMS {
                break;
            }
            index += 1;
            if index > 10_000 {
                break;
            }
            continue;
        }
        index += 1;

        let hardware_id = node_property(dev_info, &data, SPDRP_HARDWAREID).unwrap_or_default();
        if hardware_id.is_empty() {
            continue;
        }
        out.push(UsbNode {
            instance_id: node_instance_id(dev_info, &data).unwrap_or_default(),
            hardware_id,
            service: node_property(dev_info, &data, SPDRP_SERVICE).unwrap_or_default(),
        });
    }

    // SAFETY: the set came from SetupDiGetClassDevsW and is no longer used.
    unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
    out
}

/// Non-Windows build: there is no SetupAPI, so the bound driver cannot be
/// measured and is reported as unknown rather than guessed.
#[cfg(not(windows))]
pub fn enumerate_usb_nodes() -> Vec<UsbNode> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Tests. None of these touch a device.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect in one test. A millisecond window must survive the round trip
    /// through microseconds, and the sub-millisecond ones must stay distinct —
    /// a coarse (whole-second) clock collapses every one of them to zero, which
    /// is exactly what shipped in the C++ tool this project abandoned.
    #[test]
    fn abort_windows_are_microsecond_exact_and_distinct() {
        assert_eq!(abort_window(0), Duration::ZERO);
        assert_eq!(abort_window(1), Duration::from_micros(1_000));
        assert_eq!(abort_window(4), Duration::from_micros(4_000));
        assert_eq!(abort_window(5), Duration::from_micros(5_000));
        assert_eq!(abort_window(1_000), Duration::from_millis(1_000));

        // gaster's actual sweep: usb_timeout 5 ms, windows 0..=5. Six windows,
        // six distinct durations.
        let sweep: Vec<Duration> = (0..=5u32).map(abort_window).collect();
        for i in 0..sweep.len() {
            for j in (i + 1)..sweep.len() {
                assert_ne!(sweep[i], sweep[j], "windows {i} and {j} collapsed");
            }
        }

        // The old bug, reproduced as an assertion: in whole seconds, every
        // window below one second is zero, so a `time(nullptr)`-style wait
        // cannot see them at all.
        assert_eq!(abort_window(4).as_secs(), 0);
        assert!(abort_window(4) > Duration::ZERO);
    }

    /// The floor is a real, testable predicate — and it is what the transport
    /// uses to refute a result rather than return it.
    #[test]
    fn sub_microsecond_elapsed_is_refuted() {
        assert!(MIN_TRUSTWORTHY_MICROS >= 1);
        assert!(0 < MIN_TRUSTWORTHY_MICROS);
        assert!(!(MIN_TRUSTWORTHY_MICROS as u128 > u32::MAX as u128));
    }

    #[test]
    fn timeval_parts_split_seconds_from_microseconds() {
        assert_eq!(timeval_parts(Duration::ZERO), (0, 0));
        assert_eq!(timeval_parts(Duration::from_micros(1)), (0, 1));
        assert_eq!(timeval_parts(Duration::from_micros(4_000)), (0, 4_000));
        assert_eq!(timeval_parts(Duration::from_micros(1_000_000)), (1, 0));
        assert_eq!(timeval_parts(Duration::from_millis(2_500)), (2, 500_000));
    }

    /// The pump slice is bounded by what is left of the window: that is the
    /// difference between a sweep of distinct abort windows and a9ctl's fixed
    /// 5 ms slice, where windows 0..4 all cancelled at >= 5 ms.
    #[test]
    fn pump_slices_never_exceed_the_remaining_window() {
        let remaining = abort_window(1);
        assert_eq!(pump_slice(remaining, false), remaining);
        assert!(pump_slice(Duration::ZERO, false) < abort_window(1));

        let four = abort_window(4);
        let five = abort_window(5);
        assert_ne!(
            pump_slice(four, false),
            pump_slice(five, false),
            "sub-5ms windows must ask for different waits"
        );

        // Once cancelled, the slice no longer decides when we abort, so it gets
        // a floor to avoid spinning.
        assert_eq!(pump_slice(Duration::ZERO, true), POST_CANCEL_SLICE);
        assert_eq!(pump_slice(abort_window(5), true), abort_window(5));
    }

    #[test]
    fn control_transfer_length_is_setup_plus_data() {
        assert_eq!(control_transfer_len(0), 8);
        assert_eq!(control_transfer_len(0x800), 0x808);
        assert_eq!(
            control_transfer_len(0x40),
            sys::constants::LIBUSB_CONTROL_SETUP_SIZE + 0x40
        );
    }

    /// The setup packet libusb receives must be the request the reference
    /// issues, little-endian on the wire: the SETUP stage's
    /// `DFU_DNLOAD(0, 0, 0x800)` is `21 01 00 00 00 00 00 08`.
    #[test]
    fn setup_packet_matches_the_reference_request() {
        let mut raw = [0u8; 8];
        // SAFETY: `raw` is 8 bytes, which is LIBUSB_CONTROL_SETUP_SIZE.
        unsafe {
            sys::libusb_fill_control_setup(raw.as_mut_ptr(), 0x21, 1, 0, 0, 0x800);
        }
        assert_eq!(raw, [0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08]);
    }

    #[test]
    fn direction_comes_from_the_high_bit_only() {
        assert!(CtrlReq::new(0x80, 6, 0, 0, 8).is_in());
        assert!(CtrlReq::new(0xA1, 3, 0, 0, 6).is_in());
        assert!(!CtrlReq::new(0x21, 1, 0, 0, 8).is_in());
        assert!(!CtrlReq::new(0x00, 0, 0, 0, 0).is_in());
    }

    #[test]
    fn apple_descriptors_are_recognised_and_product_strings_are_not() {
        assert!(looks_like_apple_descriptor(
            "CPID:8003 CPRV:01 BDID:02 SRTG:[IBOOT-2234.0.0.2.22]"
        ));
        assert!(looks_like_apple_descriptor(" PWND:[checkm8]"));
        assert!(!looks_like_apple_descriptor("Apple Mobile Device (DFU Mode)"));
    }

    // ---- reset evidence ----------------------------------------------------

    /// The three-way split the reset report exists for. The classification
    /// itself is tested in `types`; here the point is that **each outcome
    /// renders as a different message**, because four different problems
    /// producing one message is this project's recurring failure.
    #[test]
    fn reset_notes_name_what_happened() {
        let ok = sys::constants::LIBUSB_SUCCESS;
        let parked = Some(crate::DFU_STATE_MANIFEST_WAIT_RESET);
        let idle = Some(crate::DFU_STATE_DFU_IDLE);

        // Delivered: parked before, idle after.
        let delivered = reset_note(ResetCapability::Real, true, "libusbK", ok, 900, parked, idle);
        assert!(delivered.contains("DELIVERED"), "{delivered}");
        assert!(delivered.contains("manifestWaitReset"), "{delivered}");
        assert!(delivered.contains("8 (manifestWaitReset) -> 2 (dfuIDLE)"), "{delivered}");

        // Refuted: still parked.
        let refuted = reset_note(ResetCapability::Real, true, "libusbK", ok, 120, parked, parked);
        assert!(refuted.contains("STILL parked"), "{refuted}");
        assert!(refuted.contains("positive evidence"), "{refuted}");
        assert!(
            !refuted.contains("DELIVERED"),
            "a refuted reset must never read as delivered: {refuted}"
        );

        // Unverified: idle before and after, and unread.
        let unverified = reset_note(
            ResetCapability::Real,
            true,
            "libusbK",
            ok,
            800,
            Some(crate::DFU_STATE_APP_IDLE),
            Some(crate::DFU_STATE_APP_IDLE),
        );
        assert!(unverified.contains("UNVERIFIED"), "{unverified}");
        assert!(unverified.contains("Not success; not failure"), "{unverified}");
        assert!(
            !unverified.contains("DELIVERED"),
            "an unverified reset must not read as success: {unverified}"
        );

        let unread = reset_note(ResetCapability::Real, true, "libusbK", ok, 800, parked, None);
        assert!(unread.contains("unread"), "{unread}");
        assert!(unread.contains("UNVERIFIED"), "{unread}");

        // The three Real+claimed outcomes are mutually distinct strings.
        assert_ne!(delivered, refuted);
        assert_ne!(delivered, unverified);
        assert_ne!(refuted, unverified);

        // The silent skip: right driver, no claimed interface.
        let skipped = reset_note(ResetCapability::Real, false, "libusbK", ok, 120, parked, idle);
        assert!(skipped.contains("no-op"), "{skipped}");
        assert!(skipped.contains("3415"), "{skipped}");
        assert!(!skipped.contains("DELIVERED"), "{skipped}");

        let pipe = reset_note(ResetCapability::PipeCycleOnly, true, "WinUSB", ok, 1500, parked, idle);
        assert!(pipe.contains("not a reset"), "{pipe}");
        assert!(pipe.contains("winusbx_reset_device"), "{pipe}");
        assert!(pipe.contains("3389-3410"), "{pipe}");

        let unknown = reset_note(ResetCapability::Unknown, true, "usbhub", ok, 700, parked, idle);
        assert!(unknown.contains("NOT a proven bus reset"), "{unknown}");

        // An empty service string must render as unmeasured, never as a blank
        // that reads like a driver name.
        let unmeasured = reset_note(ResetCapability::Unknown, true, "", ok, 10, None, None);
        assert!(unmeasured.contains("(unmeasured)"), "{unmeasured}");

        // A failing call is worded as an unconfirmed attempt, not an outcome.
        let failed = reset_note(ResetCapability::Real, true, "libusbK", -4, 300, parked, idle);
        assert!(failed.contains("FAILED"), "{failed}");
        assert!(failed.contains("Nothing was confirmed"), "{failed}");
    }

    /// A report's fields must agree with its own verdict: a reader acts on
    /// `bus_reset_delivered`. The direct IOCTL status the Lead asked about is
    /// deliberately **not** a field any more — libusb offers no public path to
    /// the backend handle (`windows_common.c:893` leaves `wrap_sys_device`
    /// NULL), and a permanently-`None` member invites someone to read it as a
    /// value. The device's own state replaced it.
    #[test]
    fn report_fields_agree_with_the_delivered_judgement() {
        let ok = sys::constants::LIBUSB_SUCCESS;
        let parked = Some(crate::DFU_STATE_MANIFEST_WAIT_RESET);
        let idle = Some(crate::DFU_STATE_DFU_IDLE);

        let delivered = ResetReport {
            libusb_rc: ok,
            interface_claimed: true,
            dfu_state_before: parked,
            dfu_state_after: idle,
            capability: ResetCapability::Real,
            evidence: reset_evidence(ResetCapability::Real, true, ok, parked, idle),
            bus_reset_delivered: true,
            micros: 850,
            note: reset_note(ResetCapability::Real, true, "libusbK", ok, 850, parked, idle),
        };
        assert!(delivered.bus_reset_delivered);
        assert_eq!(delivered.evidence, ResetEvidence::Delivered);
        assert!(delivered.evidence.delivered());
        assert!(delivered.note.contains("DELIVERED"));

        // Same libusb return value, no transition: the verdict flips while
        // libusb still reports success — the whole reason this field exists.
        let unverified = ResetReport {
            dfu_state_after: parked,
            evidence: reset_evidence(ResetCapability::Real, true, ok, parked, parked),
            bus_reset_delivered: false,
            ..delivered.clone()
        };
        assert_eq!(unverified.libusb_rc, ok, "libusb still reported success");
        assert!(!unverified.bus_reset_delivered);
        assert_eq!(unverified.evidence, ResetEvidence::Refuted);
    }

    /// Unreadable post-reset state is its own outcome and must not be printed
    /// as success — the case that costs a phone session when it is.
    #[test]
    fn unread_post_reset_state_is_not_success() {
        let e = reset_evidence(
            ResetCapability::Real,
            true,
            sys::constants::LIBUSB_SUCCESS,
            Some(crate::DFU_STATE_MANIFEST_WAIT_RESET),
            None,
        );
        assert_eq!(e, ResetEvidence::Unverified);
        assert!(!e.delivered());
        assert_eq!(e.as_str(), "issued, effect unverified");
        assert_eq!(ResetEvidence::Delivered.as_str(), "delivered");
        assert_eq!(ResetEvidence::Refuted.as_str(), "REFUTED by the device");
        assert_eq!(ResetEvidence::DriverCannotReset.as_str(), "driver cannot reset");
    }

    /// State names are for humans reading a trace; an unknown value is reported
    /// as unrecognised rather than mapped onto something plausible.
    #[test]
    fn dfu_state_names_are_accurate() {
        assert_eq!(dfu_state_name(0), "appIDLE");
        assert_eq!(dfu_state_name(2), "dfuIDLE");
        assert_eq!(dfu_state_name(8), "manifestWaitReset");
        assert_eq!(dfu_state_name(0xFE), "unrecognised");
    }

    // ---- driver measurement ------------------------------------------------
    // ---- driver measurement ------------------------------------------------

    fn node(instance: &str, hw: &str, service: &str) -> UsbNode {
        UsbNode {
            instance_id: instance.to_string(),
            hardware_id: hw.to_string(),
            service: service.to_string(),
        }
    }

    const LIVE: &str = "CPID:8003 CPRV:01 CPFM:03 SCEP:01 BDID:02 ECID:00112233445566AA \
                        IBFL:1C SRTG:[IBOOT-2234.0.0.2.22]";

    /// The device node is identified by its descriptor, not by "the first Apple
    /// node" — a hub or an AULA dongle sharing Apple's VID must not decide our
    /// verdict.
    #[test]
    fn driver_service_selection_prefers_the_matching_descriptor() {
        let identity = DeviceIdentity::parse(LIVE);
        let nodes = vec![
            node(
                "USB\\VID_05AC&PID_024F\\AULA-KEYBOARD",
                "USB\\VID_05AC&PID_024F&REV_0100",
                "HidUsb",
            ),
            node(
                "USB\\VID_05AC&PID_1227\\CPID:8003_CPRV:01_CPFM:03_SCEP:01_BDID:02_\
                 ECID:00112233445566AA_IBFL:1C_SRTG:[IBOOT-2234.0.0.2.22]",
                "USB\\VID_05AC&PID_1227&REV_0100",
                "libusbK",
            ),
        ];
        assert_eq!(
            select_driver_service(&nodes, &identity).as_deref(),
            Some("libusbK")
        );
    }

    /// Underscore form and space form describe the same device.
    #[test]
    fn descriptor_comparison_ignores_windows_underscores() {
        let identity = DeviceIdentity::parse(LIVE);
        let windows_form = LIVE.replace(' ', "_");
        let nodes = vec![node(
            &format!("USB\\VID_05AC&PID_1227\\{windows_form}"),
            "USB\\VID_05AC&PID_1227&REV_0100",
            "WinUSB",
        )];
        assert_eq!(
            select_driver_service(&nodes, &identity).as_deref(),
            Some("WinUSB")
        );
        assert_eq!(
            DriverClass::from_service("WinUSB"),
            DriverClass::WinUsb,
            "and that service is the one that cannot reset"
        );
        assert_eq!(
            ResetCapability::from_driver(DriverClass::WinUsb),
            ResetCapability::PipeCycleOnly
        );
    }

    /// With no descriptor match, VID/PID still finds the node — the driver
    /// class must not come back unknown just because the serial was unreadable.
    #[test]
    fn driver_service_falls_back_to_vid_and_pid() {
        let identity = DeviceIdentity::default();
        let nodes = vec![node(
            "USB\\VID_05AC&PID_1227\\SOMETHING-ELSE",
            "USB\\VID_05AC&PID_1227&REV_0100",
            "libusb0",
        )];
        assert_eq!(
            select_driver_service(&nodes, &identity).as_deref(),
            Some("libusb0")
        );
    }

    #[test]
    fn unrelated_nodes_yield_no_service() {
        let identity = DeviceIdentity::parse(LIVE);
        let nodes = vec![
            node("USB\\VID_046D&PID_C52B\\5&1234", "USB\\VID_046D&PID_C52B", "HidUsb"),
            node("USB\\VID_8087&PID_0024\\5&5678", "USB\\VID_8087&PID_0024", "usbhub"),
        ];
        assert_eq!(select_driver_service(&nodes, &identity), None);
    }

    /// A node with an empty Service property is "driver bound but not loaded",
    /// which is a different problem from "no node at all" — both must be
    /// distinguishable in the message, which is why the note exists.
    #[test]
    fn empty_service_is_reported_as_such() {
        let identity = DeviceIdentity::default();
        let nodes = vec![node(
            "USB\\VID_05AC&PID_1227\\X",
            "USB\\VID_05AC&PID_1227&REV_0100",
            "",
        )];
        assert_eq!(select_driver_service(&nodes, &identity).as_deref(), Some(""));
        assert_eq!(DriverClass::from_service(""), DriverClass::Unknown);
    }

    #[test]
    fn instance_tails_are_split_on_the_last_backslash() {
        assert_eq!(instance_tail("USB\\VID_05AC&PID_1227\\CPID:8003"), "CPID:8003");
        assert_eq!(instance_tail("CPID:8003"), "CPID:8003");
        assert_eq!(instance_tail(""), "");
    }

    /// Read-only enumeration of the device tree: opens no device handle, writes
    /// nothing. It must never panic and must never claim a driver class it did
    /// not read.
    #[test]
    fn setupapi_enumeration_is_read_only_and_consistent() {
        let nodes = enumerate_usb_nodes();
        println!("SetupAPI reported {} present device node(s)", nodes.len());
        for n in &nodes {
            assert!(!n.hardware_id.is_empty(), "hardware id is read as a filter");
            // The classification is deterministic and total; an unknown service
            // string never becomes a confident class.
            let class = DriverClass::from_service(&n.service);
            if n.service.is_empty() {
                assert_eq!(class, DriverClass::Unknown);
            }
        }
    }
}
