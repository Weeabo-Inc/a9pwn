//! USB transport for a9pwn — the layer the whole exploit stands on.
//!
//! Owner: transport-engineer (task-2). Frozen surface: `INTERFACE.md` §2.
//!
//! Everything above this module assumes three things of it, and each one has
//! been wrong in this project before:
//!
//! 1. **The abort primitive reports the truth — both halves of it.** checkm8's
//!    `stall()` submits a control transfer and deliberately cuts it off part-way;
//!    the *number of bytes that made it through* is the value the SETUP stage
//!    computes its pad request from, and *when* the cut lands is the whole
//!    variable the sweep explores. A primitive that returns "success" after less
//!    than a microsecond of wall time did no work at all — the documented defect
//!    in `readmes/a9ctl-README.md`, where a sub-millisecond wait was measured
//!    against a one-second clock and the loop body never executed. And a
//!    primitive whose window is decided by the host rather than by the caller is
//!    the same failure one layer down: on the first hardware SETUP run, windows
//!    1..5 ms all truncated at ~11.7 ms because a Windows wait cannot honour a
//!    sub-tick timeout, so a six-window sweep explored two timings. See
//!    [`OS_WAIT_MARGIN`] and [`Transport::control_async_abort`].
//! 2. **`reset()` does not lie.** On Windows, libusb's `winusbx_reset_device`
//!    returns `LIBUSB_SUCCESS` *unconditionally*, including on the branch where
//!    all it did was cycle the non-control pipes
//!    (`libusb1-sys-0.7.0/libusb/libusb/os/windows_winusb.c:3380-3420`; the
//!    real `ResetDevice` call at `:3413` is guarded by
//!    `sub_api != SUB_API_WINUSB`). checkm8 needs a genuine bus reset — it is
//!    the trigger that runs the overwritten `dfu_handle_bus_reset` callback —
//!    so `Ok(())` tells us nothing. [`Transport::reset`] reports what actually
//!    happened and classifies the capability from the **measured** driver.
//! 3. **The bound driver is measured, not guessed.** On Windows
//!    [`Transport::driver_class`] reads the `Service` value SetupAPI has bound
//!    to the device node (WinUSB can be opened by libusb 1.0.27
//!    (`windows_winusb.c:2306`) — it just cannot reset — so "which driver"
//!    decides whether an attempt is worth making). On Linux there is no
//!    `Service`: the same question is answered from sysfs, where **no `driver`
//!    link on interface 0 is itself the measurement** — it is the usbfs path,
//!    and it is reported as `usbfs`, never as empty or unknown. See
//!    [`measure_sysfs_driver`] and [`linux_driver_reading`]. The Windows
//!    census (`enumerate_usb_nodes`) stays Windows-only on purpose: its numbers
//!    feed verdict predicates about SetupAPI device paths, and a Linux node
//!    faked into that shape would be a modelled number wearing a measured name.
//!
//! # House rule
//!
//! Nothing in this module opens, resets or writes to a device unless a caller
//! explicitly asks for it. No test in this file touches hardware.

use std::cell::Cell;
use std::ffi::CStr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
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
///
/// A prompt completion signals libusb's wait handle, and a signalled handle
/// returns immediately whatever the timeout is: MEASURED on hardware, window 0
/// aborted end to end in 437 us including the cancel, so this floor costs
/// nothing in the normal case. It exists so that a completion which never
/// arrives cannot spin for the whole [`HARD_GRACE`].
const POST_CANCEL_SLICE: Duration = Duration::from_millis(1);

/// How far short of a deadline an OS-assisted wait is allowed to stop.
///
/// **The measurement this constant exists for.** Windows' `WaitForMultipleObjects`
/// — which is what libusb waits on for *both* the async pump and every
/// synchronous transfer's timeout (`windows_winusb.c` → `io.c:2253` →
/// `os/events_windows.c:175`) — cannot honour a timeout below one system timer
/// tick. MEASURED on this host at the raw API, unsignalled event, timeout 0..16 ms:
///
/// ```text
///  0 ms ->  0.00 ms     1 ms -> ~15.5 ms    2 ms -> ~15.5 ms    3 ms -> ~15.5 ms
///  4 ms -> ~15.5 ms     5 ms -> ~15.5 ms   10 ms -> ~15.5 ms   15 ms -> ~15.5 ms
/// 16 ms -> ~30.9 ms   (two ticks)
/// ```
///
/// so *any* non-zero slice below a tick is really "one tick". (`timeBeginPeriod(1)`
/// was tried: it returned `TIMERR_NOERROR` and `NtQueryTimerResolution` reported a
/// 1 ms resolution, and the waits still came back at ~15.5 ms. Do not build on it.)
/// That is why the first hardware SETUP run showed windows 1..5 all truncating at
/// ~11.7 ms: the sweep was two experiments, not six.
///
/// The margin is therefore larger than one tick (15.625 ms worst case) so an
/// OS-assisted wait can never cross the deadline: we ask for `remaining - margin`,
/// and an overshoot of up to one tick is absorbed by the margin before the
/// deadline is reached.
const OS_WAIT_MARGIN: Duration = Duration::from_millis(20);

/// How far past the requested window an abort may land before it is reported as
/// *not honoured*. Covers the cancel-and-reap cost, which is a fraction of a
/// millisecond (measured: ~0.4 ms end to end on window 0). A tick's worth of
/// overshoot — the defect this module was fixed for — is an order of magnitude
/// above it.
const ABORT_OVERRUN_TOLERANCE_US: u64 = 1_000;

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

// ---------------------------------------------------------------------------
// Result shapes
// ---------------------------------------------------------------------------
//
// The three shapes a `XferResult` can take, built in one place each. They are
// functions rather than inline struct literals because two properties of them
// are load-bearing for other modules and both have already been wrong here:
//
// * a *submitted* transfer always carries the abort window it ran under, and
//   never reports a timing that a real transfer could not have had;
// * a transfer that was *never submitted* carries no window and no timing, so
//   it cannot be mistaken for a reaped one (`XferResult::unreaped`) nor for a
//   normal failed attempt (`stages::abort_was_refused`, `stages.rs:283`).

/// The timing floor, applied to **every** result this module returns.
///
/// A wall time below [`MIN_TRUSTWORTHY_MICROS`] cannot describe a control
/// transfer — that is at minimum two kernel round trips. The primitive this
/// module exists to make safe was defeated by exactly that arithmetic
/// (`readmes/a9ctl-README.md`: a sub-millisecond wait measured against a
/// one-second clock, so the wait loop ran zero times and the transfer was
/// cancelled the instant after submit). A number like that is not a measurement,
/// so the result is refused as an *answer*: never `Ok`, `Stall`, `Cancelled` or
/// `Timeout`, all of which the stage machine acts on.
pub fn refuse_untrustworthy_timing(status: XferStatus, micros: u64) -> XferStatus {
    if micros < MIN_TRUSTWORTHY_MICROS {
        XferStatus::Error
    } else {
        status
    }
}

/// The shape of a result for a transfer that **was submitted** to libusb.
///
/// `libusb_status` is the transfer's own `libusb_transfer_status` for a reaped
/// transfer, and [`LIBUSB_ERROR_OTHER`] for one libusb never handed back — the
/// sentinel [`XferResult::unreaped`] looks for. `abort_after_ms` is always the
/// window the transfer ran under: it is the field the whole SETUP sweep is
/// audited by (`verdict::ABORT_WINDOW_UNREPORTED` exists for its absence, and
/// `trace::Counters::setup_async_unreported` counts it), and a submitted
/// transfer always had one. `requested` comes from the request, so it can never
/// drift from `w_length`.
pub fn submitted_result(
    seq: u64,
    r: CtrlReq,
    status: XferStatus,
    transferred: usize,
    micros: u64,
    libusb_status: i32,
    abort_after_ms: u32,
) -> XferResult {
    XferResult {
        seq,
        bm_request_type: r.bm,
        b_request: r.b,
        w_value: r.value,
        w_index: r.index,
        w_length: r.length,
        status: refuse_untrustworthy_timing(status, micros),
        transferred,
        requested: r.length as usize,
        micros,
        libusb_rc: libusb_status,
        abort_after_ms: Some(abort_after_ms),
    }
}

/// The shape of a result for a transfer that was **never submitted**: refused on
/// a poisoned handle, refused for a buffer shorter than `wLength`, or lost in
/// allocate/submit.
///
/// `abort_after_ms` is `None` and `micros` is 0 — not placeholders, but the
/// absence of both things: no abort window was applied and no transfer timing
/// was taken. (A failed `libusb_submit_transfer` does have an elapsed syscall
/// time, but that is not a transfer timing, and reporting it here would invite
/// exactly the comparison against the abort window that `micros` exists for.)
///
/// Three consumers depend on this shape, so it is a contract:
///
/// * [`XferResult::unreaped`] must stay `false`: libusb owns no buffer here, so
///   the handle is **not** poisoned and must never be reported as if it were.
/// * `stages::abort_was_refused` (`stages.rs:283`) keys on *this* shape — status
///   `Error`, no abort window, zero micros — to stop the SETUP sweep instead of
///   spending its whole budget on a handle that refuses every request.
/// * `trace::Counters::setup_async_unreported` counts an async request with no
///   window, so a refusal is visible rather than silently dropped.
///
/// `libusb_rc` carries what actually happened: the failing libusb call's own
/// return code when there was one, or [`LIBUSB_ERROR_OTHER`] when the refusal was
/// ours and there is no libusb code to report.
pub fn never_submitted(seq: u64, r: CtrlReq, libusb_rc: i32) -> XferResult {
    XferResult {
        seq,
        bm_request_type: r.bm,
        b_request: r.b,
        w_value: r.value,
        w_index: r.index,
        w_length: r.length,
        status: XferStatus::Error,
        transferred: 0,
        requested: r.length as usize,
        micros: 0,
        libusb_rc,
        abort_after_ms: None,
    }
}

/// The status a **deadline** expiry is reported as.
///
/// `control_async_abort` is checkm8's `stall()`: it cuts a live transfer, and a
/// deadline expiry there is honestly `Cancelled` — a trace's `setup_abort_dnload`
/// lines must keep saying exactly that. A request sent *with a timeout* is a
/// different contract: the caller asked "no answer within N ms?", and libusb
/// itself reports that as `TIMED_OUT` on the synchronous path (`sync.c:148-149`).
/// The same underlying event is therefore reported as `Timeout` here, which is
/// what keeps `Counters::setup_pad_timeouts` and `verdict::PAD_TIMEOUT_NOT_STALL`
/// counting what they have always counted.
///
/// Only `Cancelled` is rewritten. A device answer (`Stall`, `Ok`, `NoDevice`) and
/// a transport failure (`Error`) pass through untouched: they are the device's or
/// libusb's word, not ours to reinterpret. Rewriting one of those would be the
/// silent mis-classification this mapping exists to prevent.
pub fn deadline_status(status: XferStatus) -> XferStatus {
    match status {
        XferStatus::Cancelled => XferStatus::Timeout,
        other => other,
    }
}

/// Reshape a *cut* result into the shape of a request that ran under a deadline.
///
/// The status rewrite is [`deadline_status`]. `abort_after_ms` is cleared, and
/// that is load-bearing in a second place: `trace::Tracer::account_setup`
/// classifies a transfer as a sweep attempt when `abort_after_ms.is_some()`
/// (`trace.rs:813-816`), so a pad reported *with* a window would be counted as an
/// attempt — `setup_pad_requests` and `setup_pad_timeouts` would silently stop
/// counting the pad, and `PAD_TIMEOUT_NOT_STALL` would go quiet. `None` is also the
/// truthful answer: no abort window was applied here, this transfer had a caller's
/// timeout.
///
/// Nothing else is touched. `libusb_rc` keeps libusb's own value (`3`,
/// `LIBUSB_TRANSFER_CANCELLED`), so a reader can still tell a cut from a libusb
/// timeout; `micros` keeps its measured meaning; `transferred` keeps whatever
/// libusb reported — 0 for a NAKed pad, 1280 when the device accepted it, and a
/// partial count if the OS ever produces one.
///
/// An **unreaped** transfer passes through unchanged: the sentinel pair
/// (`Error` + `OTHER` + a window) is how a poisoned handle is recognised, and that
/// matters more than the bucketing of a transfer libusb never handed back.
pub fn deadline_result(cut: XferResult) -> XferResult {
    if cut.unreaped() {
        return cut;
    }
    XferResult {
        status: deadline_status(cut.status),
        abort_after_ms: None,
        ..cut
    }
}

/// The data stage a "no data" control request actually sends: `len` **zero**
/// bytes, never a null pointer with a non-zero `wLength` (which libusb rejects as
/// `INVALID_PARAM`, so it would never reach the device). One function, so every
/// no-data path sends the same bytes — `gaster.c:468-479` zeroes the buffer it
/// sends, and a pad request's payload is part of what the bootrom sees.
pub fn zero_data_stage(len: u16) -> Vec<u8> {
    vec![0u8; len as usize]
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

/// What one `libusb_reset_device` call produced, with the two failure kinds
/// kept apart.
///
/// Three outcomes, and collapsing any two of them is how a working run gets
/// blamed on its host:
///
///   * [`ResetCall::Report`] — the call returned; the report says what it did
///     (which may be nothing, and says so).
///   * [`ResetCall::RefusedAbsent`] — the call failed because the **device was
///     not there** (`LIBUSB_ERROR_NOT_FOUND` / `LIBUSB_ERROR_NO_DEVICE`). On
///     this bootrom that is the exploit's own `DFU_CLRSTATUS` drop
///     (`gaster.c:910`), measured at 435 ms with a re-enumeration; the reference
///     absorbs it (`wait_usb_handle`, `:202-218`).
///   * [`ResetCall::RefusedPresent`] — the call failed for any other reason,
///     i.e. while the device was attached. That is a real capability problem and
///     must still stop a run.
#[derive(Debug, Clone)]
pub enum ResetCall {
    Report(ResetReport),
    RefusedAbsent { rc: i32, micros: u64, note: String },
    RefusedPresent { rc: i32, micros: u64, note: String },
}

/// Is this `LIBUSB_ERROR_*` code the device being **absent**, or the reset being
/// refused while it is present?
///
/// Pure, and pinned over the whole libusb error domain rather than the two codes
/// seen so far — the §9.3 lesson: a table tested on a sample ratifies the cells
/// nobody looked at. `LIBUSB_ERROR_NOT_FOUND` (-5) is what this host produced
/// when the spray's `DFU_CLRSTATUS` dropped the device; `LIBUSB_ERROR_NO_DEVICE`
/// (-4) is the same situation one layer out. Every other code — including
/// `LIBUSB_ERROR_IO`, `ACCESS`, `BUSY`, `TIMEOUT`, `PIPE`, `OTHER` and success
/// itself — means the call was refused with the device still on the bus.
pub fn reset_error_is_device_absent(rc: i32) -> bool {
    matches!(
        rc,
        sys::constants::LIBUSB_ERROR_NOT_FOUND | sys::constants::LIBUSB_ERROR_NO_DEVICE
    )
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

    // The claim flag is a qualifier, not a verdict: it can only ever explain a
    // reset that left no trace on the device. See `types::reset_evidence`.
    let claim_clause = if interface_claimed {
        "Interface 0 was claimed at open, so libusb's HANDLE_VALID guard \
         (windows_winusb.c:3415) cannot have skipped the call."
    } else {
        "Interface 0 was NOT claimed at open, and libusb skips ResetDevice when that handle is \
         invalid (:3414-3416) — but that flag is a snapshot from open, and libusb auto-claims on \
         the first control transfer (:2985), which this reset's own pre-reset DFU_GETSTATUS is, so \
         it does not by itself prove the call was skipped."
    };

    match (capability, evidence) {
        (ResetCapability::Real, ResetEvidence::Delivered) => format!(
            "{head} {claim_clause} The DFU machine was parked in manifestWaitReset and read back \
             idle: only a genuine bus reset clears that state, and libusbK/libusb0 implement \
             ResetDevice (windows_winusb.c:3413), so it was called. A host-initiated bus reset was \
             DELIVERED — the trigger that runs the overwritten dfu_handle_bus_reset callback. \
             libusbK's own status is discarded by libusb (:3419); this verdict comes from the \
             device, not from a return code."
        ),
        (ResetCapability::Real, ResetEvidence::Refuted) => format!(
            "{head} {claim_clause} The DFU machine is STILL parked in manifestWaitReset after the \
             reset. That is positive evidence the reset did not take effect on the device, whatever \
             libusb returned. checkm8's dfu_handle_bus_reset will not have run. Suspect the driver \
             binding, the port, or a hub between host and device — not the exploit."
        ),
        (ResetCapability::Real, ResetEvidence::Unverified) => format!(
            "{head} {claim_clause} A real reset was requested on a capable driver, but the DFU \
             state read the same before and after, so the effect is UNVERIFIED: a delivered port \
             reset does not cycle VBUS, so an already-idle machine looks unchanged, which is \
             indistinguishable here from a pipe cycle. Not success; not failure. To settle it, \
             drive the machine into manifestWaitReset first (that is what stage_reset does) and \
             reset again — then the transition is decisive."
        ),
        (ResetCapability::Real, ResetEvidence::DriverCannotReset) => format!(
            "{head} Driver service '{service}' does implement ResetDevice, but interface 0 was NOT \
             claimed at open and nothing on the device moved, so interface_handle[0] was invalid, \
             the HANDLE_VALID guard at windows_winusb.c:3415 failed, and ResetDevice was most \
             likely never called. This SUCCESS describes a no-op. (libusb auto-claims on the first \
             control transfer, :2985 — if one has been submitted since the claim failed, the reset \
             may have run after all, in which case the device would have shown it.)"
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

/// The Linux sentence for a reset: the same evidence, but naming the mechanism
/// libusb actually used.
///
/// **Why this exists.** [`reset_note`]'s clauses are written from the Windows
/// driver table, and its `Unknown` arm concludes that "whether libusb issued a
/// real device reset cannot be determined from here". On Linux that conclusion
/// is false: `libusb_reset_device` reaches `op_reset_device`
/// (`linux_usbfs.c:1578`), which issues `ioctl(IOCTL_USBFS_RESET)` (`:1596`) —
/// `_IO('U', 20)` (`linux_usbfs.h:149`), i.e. `USBDEVFS_RESET`
/// (`/usr/include/linux/usbdevice_fs.h:210`) — a genuine port reset. Printing
/// the Windows paragraph here was MEASURED on 2026-10-03: `a9pwn reset` said a
/// real reset "cannot be determined from here" about a call that had issued
/// that ioctl and taken 237.8 ms to complete.
///
/// The evidence model is unchanged and is the same one the Windows prose uses:
/// the capability is whatever [`Transport::reset_capability`] measured (and
/// `capability_evidence` says from what), the claim flag qualifies it, and the
/// verdict drawn from the DFU state pair comes from
/// [`crate::types::reset_evidence`]. What changes is that an *unverified*
/// outcome is stated as unverified — not as proof that nothing happened.
///
/// Pure, so every branch is testable without a device.
#[cfg(unix)]
pub fn reset_note_linux(
    capability: ResetCapability,
    capability_evidence: &str,
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
    let states = format!(
        "DFU state {} -> {}",
        state(dfu_state_before),
        state(dfu_state_after)
    );
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
             '{service}', {states}. Nothing was confirmed: the Linux backend's \
             ioctl(USBDEVFS_RESET) (linux_usbfs.c:1596) did not succeed, so no bus reset was \
             delivered and no pipe cycle was reported either. The reference ignores this return \
             value and continues; doing the same is a choice the caller may make, but it is not \
             evidence.",
            libusb_error_name(libusb_rc)
        );
    }

    let head = format!(
        "libusb_reset_device returned SUCCESS after {micros} us; driver service '{service}'; \
         {states}."
    );
    let capability_clause = if capability_evidence.is_empty() {
        "Capability evidence was not recorded on this transport — treat the classification as \
         unproven."
            .to_string()
    } else {
        format!("Capability evidence: {capability_evidence}")
    };
    let claim_clause = if interface_claimed {
        "Interface 0 was claimed at open, so this transport owns the interface the exploit talks \
         through."
    } else {
        "Interface 0 was NOT claimed at open; libusb's Linux backend still issues \
         ioctl(USBDEVFS_RESET) without consulting claims (linux_usbfs.c:1589-1596), but an \
         interface this transport does not own is classified UNKNOWN, not Real."
    };

    match (capability, evidence) {
        (ResetCapability::Real, ResetEvidence::Delivered) => format!(
            "{head} {capability_clause} {claim_clause} The DFU machine was parked in \
             manifestWaitReset and read back idle: only a genuine bus reset clears that state. A \
             host-initiated port reset was DELIVERED — the trigger that runs the overwritten \
             dfu_handle_bus_reset callback."
        ),
        (ResetCapability::Real, ResetEvidence::Refuted) => format!(
            "{head} {capability_clause} {claim_clause} The DFU machine is STILL parked in \
             manifestWaitReset after the reset. That is positive evidence the reset did not take \
             effect on the device, whatever libusb returned. checkm8's dfu_handle_bus_reset will \
             not have run. Suspect the port, the host controller, or a hub between host and \
             device — not the exploit."
        ),
        (ResetCapability::Real, ResetEvidence::Unverified) => format!(
            "{head} {capability_clause} {claim_clause} A real port reset was requested on a path \
             measured as capable, but the DFU state read the same before and after, so this \
             call's effect on the DFU machine is UNVERIFIED: a port reset does not cycle VBUS, so \
             an already-idle machine looks unchanged, which is indistinguishable here from a pipe \
             cycle. Not success; not failure — and NOT evidence that the reset failed. To settle \
             it, drive the machine into manifestWaitReset first (that is what stage_reset does) \
             and reset again — then the transition is decisive."
        ),
        (ResetCapability::Real, ResetEvidence::DriverCannotReset) => format!(
            "{head} {capability_clause} {claim_clause} The capability is Real but interface 0 is \
             not held by this handle, so this call is not counted as a delivered reset."
        ),
        (ResetCapability::PipeCycleOnly, _) => format!(
            "{head} {capability_clause} No Linux measurement in this crate produces 'pipe cycle \
             only' — that classification describes libusb's Windows/WinUSB backend. Seeing it \
             here is a bug report about this crate, not a device finding: do not trust this \
             line's classification until the capability evidence above explains it."
        ),
        (ResetCapability::Unknown, _) => format!(
            "{head} {capability_clause} {claim_clause} The reset capability was not established \
             on this host, so this SUCCESS is not a proven bus reset."
        ),
    }
}

/// The platform's human sentence for a reset.
///
/// Windows keeps [`reset_note`]'s exact prose, citations included. Linux uses
/// [`reset_note_linux`], because the Windows sentences name a mechanism
/// (`windows_winusb.c:3413-3419`) that is not the one libusb uses here — see
/// the measurement recorded on `reset_note_linux`.
#[allow(unused_variables)]
fn reset_note_here(
    capability: ResetCapability,
    capability_evidence: &str,
    interface_claimed: bool,
    driver_service: &str,
    libusb_rc: i32,
    micros: u64,
    dfu_state_before: Option<u8>,
    dfu_state_after: Option<u8>,
) -> String {
    #[cfg(windows)]
    {
        reset_note(
            capability,
            interface_claimed,
            driver_service,
            libusb_rc,
            micros,
            dfu_state_before,
            dfu_state_after,
        )
    }
    #[cfg(unix)]
    {
        reset_note_linux(
            capability,
            capability_evidence,
            interface_claimed,
            driver_service,
            libusb_rc,
            micros,
            dfu_state_before,
            dfu_state_after,
        )
    }
}

/// Human name for a `bState` value.
///
/// `bState` is the **index of the state in the DFU 1.1 state list**, so the
/// numbering is the list order and nothing else. The canonical table, as it
/// appears in the reference host implementation (dfu-util `src/dfu.h`,
/// `STATE_APP_IDLE 0x00` … `STATE_DFU_ERROR 0x0a`) and in the DFU 1.1
/// specification's state list (§6.1.2):
///
/// ```text
///  0 appIDLE              1 appDETACH          2 dfuIDLE
///  3 dfuDNLOAD-SYNC       4 dfuDNBUSY          5 dfuDNLOAD-IDLE
///  6 dfuMANIFEST-SYNC     7 dfuMANIFEST        8 dfuMANIFEST-WAIT-RESET
///  9 dfuUPLOAD-IDLE      10 dfuERROR
/// ```
///
/// The states this project already names elsewhere (`appIDLE`, `dfuIDLE`,
/// `manifestSync`, `manifest`, `manifestWaitReset` — the spellings this crate's
/// prose, traces and verdicts use) keep those names; the remaining six carry the
/// specification's. **An earlier version of this table had 1, 3, 4 and 5
/// wrong** — it printed `dfuDNLOAD-IDLE` for 1, `dfuDNBUSY` for 3,
/// `dfuDNLOAD-SYNC` for 4 and `dfuMANIFEST-SYNC` for 5 — so a live run showed
/// `DFU state 5 (dfuMANIFEST-SYNC)` for a bootrom that was sitting in
/// `dfuDNLOAD-IDLE`. The numeric constants were right, so no decision was
/// affected; only the label lied, which is why the numbering is now spelled out
/// above and pinned for all eleven values by `dfu_state_names_are_accurate`.
///
/// Anything outside 0..=10 is reported as unrecognised rather than guessed at.
///
/// **This function is a label.** It is called from one place, [`reset_note`],
/// to build a human sentence, and from the table test. Nothing compares its
/// output, and nothing decides anything from it: every state decision in this
/// crate matches on the numeric constants in `lib.rs` (e.g. `types.rs:445-451`).
pub fn dfu_state_name(state: u8) -> &'static str {
    match state {
        crate::DFU_STATE_APP_IDLE => "appIDLE", // 0
        1 => "appDETACH",
        crate::DFU_STATE_DFU_IDLE => "dfuIDLE", // 2
        3 => "dfuDNLOAD-SYNC",
        4 => "dfuDNBUSY",
        5 => "dfuDNLOAD-IDLE",
        crate::DFU_STATE_MANIFEST_SYNC => "manifestSync", // 6
        crate::DFU_STATE_MANIFEST => "manifest",          // 7
        crate::DFU_STATE_MANIFEST_WAIT_RESET => "manifestWaitReset", // 8
        9 => "dfuUPLOAD-IDLE",
        10 => "dfuERROR",
        _ => "unrecognised",
    }
}

/// Human name for a negotiated USB speed.
///
/// The bit rate is in the name on purpose: it is the number that decides how many
/// bytes could have crossed the wire inside an abort window, which is what makes
/// a zero `abort_xfer` readable (see [`Transport::device_speed`]).
///
/// The six variants rusb 0.9.4 defines are named explicitly. The enum is
/// `#[non_exhaustive]`, so a future libusb may report a speed this build has never
/// heard of; that is reported as unrecognised rather than guessed at — a made-up
/// bit rate would be exactly the plausible-looking wrong value this crate exists
/// to avoid.
pub fn speed_name(speed: rusb::Speed) -> &'static str {
    match speed {
        rusb::Speed::Unknown => "unknown (the OS reported no speed)",
        rusb::Speed::Low => "low (1.5 Mbit/s)",
        rusb::Speed::Full => "full (12 Mbit/s)",
        rusb::Speed::High => "high (480 Mbit/s)",
        rusb::Speed::Super => "super (5 Gbit/s)",
        rusb::Speed::SuperPlus => "super plus (10 Gbit/s)",
        _ => "unrecognised (a speed this build does not know)",
    }
}

// ---------------------------------------------------------------------------
// The DFU Functional Descriptor
// ---------------------------------------------------------------------------

/// The DFU Functional Descriptor (`GET_DESCRIPTOR` type `0x21`, 9 bytes).
///
/// These are the numbers the DFU specification says a host must obey, and the ones
/// gaster never reads: it hardcodes `DFU_MAX_TRANSFER_SZ = 0x800` (`gaster.c:44`)
/// as the SETUP abort's length. `transfer_size` is the largest DNLOAD the device
/// declares it will accept, so a value below `0x800` would mean that constant is
/// wrong for this unit — a port fix with a citation, which is why it is worth one
/// read-only transfer to know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DfuFunctionalDescriptor {
    /// `bmAttributes`. Bit 3 is `bitWillDetach`; the rest are reserved.
    pub bm_attributes: u8,
    /// `wDetachTimeOut`: milliseconds the device asks the host to wait before the
    /// USB reset that follows `DFU_DETACH`.
    pub detach_timeout_ms: u16,
    /// `wTransferSize`: the maximum transfer size the device declares. **The field
    /// this probe exists for.**
    pub transfer_size: u16,
    /// `bcdDFUVersion`, e.g. `0x0110` for DFU 1.1.
    pub bcd_dfu_version: u16,
    /// The nine bytes verbatim, so a caller prints what was actually read rather
    /// than a re-rendering of the fields — and so the two unused trailing bytes are
    /// visible instead of silently dropped.
    pub raw: [u8; 9],
}

impl DfuFunctionalDescriptor {
    /// Bytes the descriptor must have to be decoded at all.
    pub const LEN: u16 = 9;

    /// Decode the descriptor, refusing anything that is not exactly nine bytes.
    ///
    /// A short read is **not** decoded with zero filling: a zeroed `transfer_size`
    /// would read as the finding "this device declares no transfer size", and a
    /// finding must not be manufactured by a failed read.
    pub fn decode(bytes: &[u8]) -> Result<DfuFunctionalDescriptor, String> {
        if bytes.len() != Self::LEN as usize {
            return Err(format!(
                "the DFU Functional Descriptor is {} bytes, got {}: refusing to decode a partial \
                 descriptor, because a zero-filled wTransferSize would read as the finding 'no \
                 transfer size declared'",
                Self::LEN,
                bytes.len()
            ));
        }
        Ok(DfuFunctionalDescriptor {
            bm_attributes: bytes[0],
            // Bytes 7-8 are unused by the specification; the fields stop at 6.
            detach_timeout_ms: u16::from_le_bytes([bytes[1], bytes[2]]),
            transfer_size: u16::from_le_bytes([bytes[3], bytes[4]]),
            bcd_dfu_version: u16::from_le_bytes([bytes[5], bytes[6]]),
            raw: [
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8],
            ],
        })
    }

    /// One line, with the raw bytes, because the raw bytes are the measurement.
    pub fn one_line(&self) -> String {
        let raw: Vec<String> = self.raw.iter().map(|b| format!("{b:02X}")).collect();
        format!(
            "DFU functional descriptor: bmAttributes=0x{:02X} wDetachTimeOut={} ms \
             wTransferSize={} (0x{:04X}) bcdDFUVersion=0x{:04X} raw=[{}]",
            self.bm_attributes,
            self.detach_timeout_ms,
            self.transfer_size,
            self.transfer_size,
            self.bcd_dfu_version,
            raw.join(" ")
        )
    }

    /// Does this device declare a transfer size gaster's constant would exceed?
    ///
    /// `None` when the device declares `0`, which is "unlimited" in practice for
    /// the bootroms and is not a cap this crate may invent.
    pub fn caps_gaster_transfer_size(&self) -> Option<bool> {
        if self.transfer_size == 0 {
            return None;
        }
        Some(self.transfer_size < crate::DFU_MAX_TRANSFER_SZ)
    }
}

/// The request that reads the DFU Functional Descriptor: `bmRequestType = 0x81`
/// (device-to-host, standard, device), `bRequest = 6` (`GET_DESCRIPTOR`),
/// `wValue = 0x2100` (descriptor type `0x21` in the high byte), `wIndex = 0`,
/// `wLength = 9`. Pure, so the wire parameters are pinned without a device.
pub fn dfu_functional_descriptor_request() -> CtrlReq {
    CtrlReq::new(0x81, 0x06, 0x2100, 0, DfuFunctionalDescriptor::LEN)
}

// ---------------------------------------------------------------------------
// The device's EP0 rate line
// ---------------------------------------------------------------------------

/// How fast this ROM's EP0 actually moves data: a fixed startup before the first
/// packet, then whole 64-byte packets.
///
/// **MEASURED on the A9 in SecureROM DFU, three independent ways** (all latencies
/// are `XferResult::micros`, i.e. submit → completion or cut):
///
/// ```text
///   1 packet   (16 B, 64 B DNLOADs; 62 B IN read)   3.44 / 3.92 / 3.463 ms
///  20 packets  (1280 B pad, an unhandled request)  21.4 … 27.9 ms, 21.5 / 36.6, 23.02
///  32 packets  (2048 B DNLOAD completions)         34.897 / 35.027 / 37.912 ms
/// ```
///
/// Fit through the two *DNLOAD* clusters (1 and 32 packets): startup ≈ 2.57 ms,
/// 1.04 ms per packet. The pad's cluster is deliberately **not** used to fit or to
/// widen the spread: it is a request the ROM has no handler for, so its latency
/// includes whatever its refusal path costs on top of the data, which is why it
/// scatters over 15 ms while the DNLOAD completions scatter over 3 ms.
///
/// **Why this exists as a named value.** Every cancelled transfer on this host
/// reports `transferred = 0` — proven in both directions by
/// [`Transport::diagnostic_partial_count_probe`] — so the byte count that
/// checkm8's pad arithmetic needs cannot be read. The only substitute is a model,
/// and a model must live in one cited place with its error stated rather than be
/// re-derived by hand at each call site.
///
/// **The assumption, stated and not resolved by preference** (INFERRED): that the
/// time is spent packet by packet *on the wire*, because EP0 holds one
/// max-packet and therefore the device paces the host. The alternative reading —
/// the host controller delivered everything early and the ROM processed it
/// afterwards — would put the byte count at an order of magnitude more (~2048
/// rather than ~166 at a 5 ms window). Nothing we own can measure which is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ep0RateLine {
    /// Time from submit to the first packet having moved, in microseconds.
    pub startup_us: u64,
    /// Time per whole 64-byte packet after that.
    pub packet_us: u64,
    /// The observed per-attempt scatter, in packets. A window-derived byte count
    /// is a **centre** with this much error, never an answer — which is why the
    /// sweep belongs on the byte count itself, where this band is searched instead
    /// of trusted.
    pub spread_packets: u32,
}

impl Ep0RateLine {
    /// EP0's max packet size, and therefore the quantum of every byte count this
    /// crate derives. `gaster.c`'s `EP0_MAX_PACKET_SZ` is the same 0x40.
    pub const PACKET_BYTES: u32 = 64;

    /// The A9 SecureROM DFU measurement above: 2.57 ms startup, 1.04 ms per
    /// packet, ±2 packets of scatter (the 32-packet cluster's 1.66 ms standard
    /// deviation rounded up).
    pub const A9_SECUREROM_DFU: Ep0RateLine = Ep0RateLine {
        startup_us: 2_570,
        packet_us: 1_043,
        spread_packets: 2,
    };

    /// Whole packets that could have crossed by `elapsed`.
    ///
    /// `elapsed` is the time from `libusb_submit_transfer` to the cut — which is
    /// exactly what the trace publishes as `abort_micros`, so a reader can feed the
    /// *measured* truncation rather than the designed window and see whether the
    /// two agree.
    pub fn packets_in(&self, elapsed: Duration) -> u32 {
        let us = elapsed.as_micros() as u64;
        if us <= self.startup_us {
            return 0;
        }
        ((us - self.startup_us) / self.packet_us.max(1)) as u32
    }

    /// Bytes that could have crossed by `elapsed`, always a whole number of
    /// packets — the quantum cannot be fractional, so this is not "approximately".
    pub fn bytes_in(&self, elapsed: Duration) -> u32 {
        self.packets_in(elapsed) * Self::PACKET_BYTES
    }

    /// The elapsed time that should let `packets` whole packets cross.
    pub fn elapsed_for_packets(&self, packets: u32) -> Duration {
        Duration::from_micros(self.startup_us + u64::from(packets) * self.packet_us)
    }

    /// The **designed window** that should let `packets` cross, given the caller's
    /// measured cancel-and-reap overhead (`abort_micros − window`, ~340 µs on this
    /// host). Saturing, so a target the overhead swallows becomes zero rather than
    /// a negative deadline.
    pub fn window_for_packets(&self, packets: u32, cancel_overhead: Duration) -> Duration {
        self.elapsed_for_packets(packets)
            .saturating_sub(cancel_overhead)
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
    /// What a reset can physically do on this host, decided once at open from
    /// the measured host path — SetupAPI's `Service` on Windows, sysfs on Linux
    /// (see [`linux_driver_reading`]). Stored rather than recomputed so the
    /// classification and [`Transport::capability_evidence`] can never disagree.
    capability: ResetCapability,
    /// Which measurement produced `capability`, in one sentence. Never empty
    /// once the open path has run: an unknown capability that cannot say *why*
    /// it is unknown is the message this project keeps paying for.
    capability_note: String,
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
    /// Negotiated USB speed, captured once at open. See [`Transport::device_speed`]
    /// for why the transport carries it.
    speed: rusb::Speed,
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
    ///
    /// Every failure path records itself through [`fail_open`] (see
    /// [`last_open_failure`]), and a **successful** open clears that record, so
    /// `last_open_failure()` answers "did the last attempt fail?" rather than
    /// "did any attempt ever fail?". A failure inside this function is the
    /// measurement `verdict::WRONG_DRIVER_BOUND` / `DRIVER_BOUND_NOT_LOADED`
    /// need; a stale one from an earlier call would be a false accusation.
    pub fn open_first_dfu() -> Result<Transport, String> {
        let ctx = match rusb::Context::new() {
            Ok(c) => c,
            Err(e) => {
                return fail_open(
                    Some(rusb_error_code(e)),
                    format!("libusb context init failed: {e}"),
                )
            }
        };
        let devices = match ctx.devices() {
            Ok(d) => d,
            Err(e) => {
                return fail_open(
                    Some(rusb_error_code(e)),
                    format!("libusb device list failed: {e}"),
                )
            }
        };
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
            // No libusb call failed here, so there is no libusb code to report —
            // and reporting a made-up one would be worse than `None`.
            return fail_open(
                None,
                format!(
                    "no Apple device among the {enumerated} USB device(s) libusb enumerated \
                     (VID {APPLE_VID:04X}); enumeration itself worked, the device is absent"
                ),
            );
        }
        if other_pids.is_empty() {
            return fail_open(
                None,
                format!(
                    "{apple_seen} Apple device(s) present but none could be described \
                     (looking for {APPLE_VID:04X}:{DFU_MODE_PID:04X})"
                ),
            );
        }
        let pids: Vec<String> = other_pids.iter().map(|p| format!("{p:04X}")).collect();
        fail_open(
            None,
            format!(
                "{apple_seen} Apple device(s) present, PID(s) {}, none in DFU mode \
                 ({DFU_MODE_PID:04X}). A device in recovery or normal mode is not exploitable \
                 — it must be put back into DFU.",
                pids.join(", ")
            ),
        )
    }

    fn open_this(
        dev: &rusb::Device<rusb::Context>,
        desc: &rusb::DeviceDescriptor,
    ) -> Result<Transport, String> {
        let bus = dev.bus_number();
        let address = dev.address();

        let handle = match dev.open() {
            Ok(h) => h,
            Err(e) => {
                // `rusb::Error` carries a libusb code and nothing else; the
                // mapping is restated in `rusb_error_code`. `windows_winusb.c:2595-2602`
                // is where these come from for this device class.
                return fail_open(
                    Some(rusb_error_code(e)),
                    format!(
                        "found {APPLE_VID:04X}:{DFU_MODE_PID:04X} at bus {bus} address {address} but \
                         libusb could not open it: {e}. This is an access or busy condition, not a \
                         driver-class one: libusb 1.0.27 opens WinUSB-bound devices \
                         (windows_winusb.c:2306); rebind to libusbK only because of the reset \
                         capability, not because opening fails."
                    ),
                );
            }
        };

        let mut notes: Vec<String> = Vec::new();

        // Captured first: the bus speed decides how a zero `abort_xfer` must be
        // read, so it belongs next to bus and address in the open note.
        // `libusb_get_device_speed` is host-side (it returns the speed libusb
        // cached at enumeration) and cannot fail, so `Unknown` is its own honest
        // "no measurement" value rather than an `Option` nobody would ever see.
        let speed = dev.speed();
        notes.push(format!("negotiated speed {}", speed_name(speed)));

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
            capability: ResetCapability::Unknown,
            capability_note: String::new(),
            seq: SeqCounter::new(),
            ident_index: Cell::new(declared_i_serial),
            interface_claimed,
            open_note: String::new(),
            poisoned: false,
            bus,
            address,
            speed,
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

        // What the host says about the driver, and what that means for a reset.
        //
        // Windows: SetupAPI's `Service` property, exactly as before — the value
        // and the notes below are unchanged, and `DriverReading` only carries
        // them to the fields the rest of the crate already read.
        //
        // Linux: sysfs, keyed by the bus/address libusb itself took from the
        // same files (`linux_usbfs.c:624-636`, `:919-920`). No kernel driver
        // bound to interface 0 is the usbfs path, reported as `usbfs`; a
        // kernel driver bound there is reported by name and is not resettable
        // through libusb. Either way the capability carries the evidence that
        // produced it, so a reader never has to guess why it says what it says.
        #[cfg(windows)]
        let reading = {
            let (service, note) = measure_driver_service(&transport.identity);
            let driver = DriverClass::from_service(&service);
            DriverReading {
                capability: ResetCapability::from_driver(driver),
                capability_note: windows_capability_note(
                    ResetCapability::from_driver(driver),
                    &service,
                ),
                service,
                note,
            }
        };
        #[cfg(unix)]
        let reading = linux_driver_reading(
            measure_sysfs_driver(&sysfs_root(), bus, address),
            interface_claimed,
        );

        // The class travels with the reading: on Linux it is classified exactly
        // (`linux_driver_class`), not by `DriverClass::from_service`'s substring
        // rule, so the driver line and the capability line cannot disagree.
        #[cfg(unix)]
        let driver_class = linux_driver_class(&reading);
        #[cfg(windows)]
        let driver_class = DriverClass::from_service(&reading.service);

        transport.driver_service = reading.service;
        transport.driver = driver_class;
        transport.capability = reading.capability;
        transport.capability_note = reading.capability_note;
        notes.push(reading.note);

        transport.open_note = format!("bus {bus} addr {address}; {}", notes.join("; "));
        // The open succeeded, so any earlier failure is history, not a
        // measurement of *this* attempt. `last_open_failure()` must not be able
        // to accuse a device that just opened.
        clear_last_open_failure();
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
    /// it. Empty when the node could not be found. On Linux this is a kernel
    /// driver name, or `usbfs` when interface 0 has no kernel driver bound.
    pub fn driver_service(&self) -> &str {
        &self.driver_service
    }

    /// Measured from the OS for this device node — SetupAPI's `Service`
    /// property on Windows, sysfs on Linux — never guessed from PID, VID or
    /// whether an open succeeded.
    pub fn driver_class(&self) -> DriverClass {
        self.driver
    }

    /// What a reset can physically do on this host, from the **measured** host
    /// path — never from the operating system's name.
    ///
    /// Windows: the bound driver service decides, via
    /// `ResetCapability::from_driver` (libusbK/libusb0 reach `ResetDevice`,
    /// `windows_winusb.c:3413`; WinUSB does not). Linux: `Real` requires the
    /// sysfs measurement (interface 0 not held by a kernel driver) *and*
    /// interface 0 claimed at open — the reasoning and its citations are in
    /// [`linux_driver_reading`]. [`Transport::capability_evidence`] names which
    /// measurement produced this answer.
    pub fn reset_capability(&self) -> ResetCapability {
        self.capability
    }

    /// Which measurement produced [`Transport::reset_capability`], in one
    /// sentence. The same sentence is woven into the reset note, so `a9pwn
    /// reset` and a trace both show *why* the capability is what it is.
    pub fn capability_evidence(&self) -> &str {
        &self.capability_note
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

    /// The negotiated USB speed, captured at open (one host-side call to
    /// `libusb_get_device_speed`, no traffic). `Speed::Unknown` is what the OS
    /// says when it has no measurement; it is never guessed at here.
    ///
    /// **Why the transport carries the bus speed at all.** `XferResult::transferred`
    /// counts bytes that crossed the wire, and how many *could* have crossed
    /// inside a 1-5 ms abort window is a function of the speed — with gaster's own
    /// EP0 packet size (`EP0_MAX_PACKET_SZ = 0x40 = 64`, `lib.rs:28`):
    ///
    /// ```text
    /// full speed (12 Mbit/s): one 64 B packet per 1 ms frame
    ///                         -> 2048 B needs 32 frames, ~32 ms
    /// high speed (480 Mbit/s): same 64 B packet per 125 us microframe
    ///                         -> 2048 B in ~4 ms, inside a 4-5 ms window
    /// ```
    ///
    /// (INFERRED from the USB 2.0 frame/microframe and the mandated HS EP0 packet
    /// size; the speed itself is measured.) So a zero byte count inside a 4 ms
    /// window means different things at the two speeds: at full speed nothing
    /// *could* have arrived, so the count is uninformative and a cancelled URB's
    /// missing partial length explains it; at high speed the whole DNLOAD fits
    /// inside the window, so a zero count says the request never reached the wire.
    /// The first hardware SETUP run could not tell those apart, because the crate
    /// never asked for the speed.
    pub fn device_speed(&self) -> rusb::Speed {
        self.speed
    }

    // -----------------------------------------------------------------------
    // Synchronous transfers
    // -----------------------------------------------------------------------

    /// Control transfer. `wLength` is `r.length`; the buffer must be at least
    /// that long. For an IN request up to `r.length` bytes are written back.
    ///
    /// # The one libusb path that completes `Ok` without touching the wire
    ///
    /// If a caller sends a standard `SET_CONFIGURATION` (`bm = 0x00`, `b = 9`)
    /// whose `wValue` equals the configuration the Windows backend already holds,
    /// libusb does not issue anything: it calls
    /// `windows_force_sync_completion(itransfer, 0)` (`windows_winusb.c:2996-3004`),
    /// which posts a synthetic completion with `InternalHigh = 0`
    /// (`windows_common.c:295-309`). The result is therefore `Ok` with
    /// `transferred == 0` and no USB traffic — "the device answered with nothing"
    /// would be the wrong reading of it. No checkm8 stage sends
    /// `SET_CONFIGURATION`; the note is here so that a future caller who does is
    /// not surprised by a zero-byte success. Every other transfer on this API
    /// reaches the wire or reports a non-`Ok` status.
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
        let mut zeros = zero_data_stage(r.length);
        self.ctrl_sync(r, &mut zeros, timeout_ms)
    }

    fn ctrl_sync(&self, r: CtrlReq, data: &mut [u8], timeout_ms: u32) -> XferResult {
        let seq = self.seq.next();
        let requested = r.length as usize;

        if data.len() < requested {
            // A caller bug, refused before anything reaches libusb — so there is
            // no abort window and no timing to report.
            return never_submitted(seq, r, sys::constants::LIBUSB_ERROR_INVALID_PARAM);
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
    /// * **The abort window is real, and the OS is never asked to make it so.**
    ///   The deadline is an `Instant` computed with microsecond arithmetic, and
    ///   the slice handed to libusb is [`pump_slice`]'s: zero while the deadline
    ///   is within [`OS_WAIT_MARGIN`], otherwise `remaining - margin` so an
    ///   OS-assisted wait cannot cross the deadline. a9ctl used a fixed 5 ms pump
    ///   and only checked its deadline after each slice, so windows 0..4 all
    ///   aborted at >= 5 ms: one experiment wearing six labels. The *first
    ///   hardware run of this crate* had a subtler version of the same defect —
    ///   this function handed libusb the exact remaining window, which on Windows
    ///   is a `WaitForMultipleObjects` timeout that cannot return before the next
    ///   ~15.6 ms tick, so windows 1..5 all truncated at ~11.7 ms and the sweep
    ///   explored two timings instead of six. Window 0 was the only honest one
    ///   (437 us end to end) because a zero timeout *can* be honoured.
    /// * **The cancel happens exactly once, at the deadline**, not before. The
    ///   transfer is never cancelled in the same instant it was submitted
    ///   without libusb having looked at it at least once.
    /// * **The reported `micros` is measured**, from immediately before
    ///   `libusb_submit_transfer` to the moment the completion callback had
    ///   run, so a reader can prove from the trace whether the window was
    ///   honoured or the host overshot it — [`abort_truncation_note`] states that
    ///   comparison in words, and both numbers are already on every transfer
    ///   line.
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
            return never_submitted(seq, r, sys::constants::LIBUSB_ERROR_INVALID_PARAM);
        }
        self.async_abort_core(r, buf, cancel_after_ms)
    }

    /// gaster's `send_usb_control_request_async_no_data`: the same aborted
    /// transfer, with a zero-filled data stage of `r.length` bytes.
    ///
    /// This is the shape the reference actually submits for the SETUP stage's
    /// 0x800-byte `DFU_DNLOAD` (`gaster.c:853`).
    pub fn control_async_abort_no_data(&mut self, r: CtrlReq, cancel_after_ms: u32) -> XferResult {
        let mut zeros = zero_data_stage(r.length);
        self.control_async_abort(r, &mut zeros, cancel_after_ms)
    }

    /// **A control transfer with a true deadline — the pad's primitive.**
    ///
    /// The synchronous [`Self::control`] cannot honour a timeout shorter than one
    /// system timer tick (see [`OS_WAIT_MARGIN`]): a nominal 5 ms wait returns
    /// anywhere in ~8-31 ms on this host, which is how a ~21-37 ms device watchdog
    /// answered a "5 ms" pad request and got counted as a checkm8 pass. This holds
    /// the deadline on `Instant` with zero-timeout polls instead — the same
    /// machinery [`Self::control_async_abort`] uses and the same one [`pump_slice`]
    /// fixed.
    ///
    /// Status, because it is the whole point:
    ///
    /// * the device answers before the deadline -> its own status: `Stall` (the
    ///   pass condition, `gaster.c:853`), `Ok`, `NoDevice`, …
    /// * the deadline expires with no answer -> `Timeout`, **not** `Cancelled`; see
    ///   [`deadline_status`] for why that keeps a verdict alive
    /// * transport failure -> `Error`
    ///
    /// `abort_after_ms` is `None`: this transfer had a timeout, not an abort
    /// window, and [`deadline_result`] explains why the tracer depends on that.
    ///
    /// If the device answers at the same instant the deadline passes, the result
    /// races between its own status and `Timeout`. That race is gaster's too — its
    /// pad is a 5 ms poll (`gaster.c:227`, `:853`) — so it is documented rather
    /// than engineered away with a margin that would make the deadline a lie.
    pub fn control_with_deadline(
        &mut self,
        r: CtrlReq,
        buf: &mut [u8],
        deadline_ms: u32,
    ) -> XferResult {
        deadline_result(self.control_async_abort(r, buf, deadline_ms))
    }

    /// [`Self::control_with_deadline`] for a request with no caller data: the
    /// zero-filled data stage of `r.length` bytes that [`Self::control_no_data`]
    /// sends, cut off at a true deadline.
    pub fn control_with_deadline_no_data(&mut self, r: CtrlReq, deadline_ms: u32) -> XferResult {
        let mut zeros = zero_data_stage(r.length);
        self.control_with_deadline(r, &mut zeros, deadline_ms)
    }

    /// **Diagnostic only — never on the exploit path.** Aborts one IN control
    /// transfer (a `GET_DESCRIPTOR` read of the bootrom's serial string) after
    /// `deadline_ms` and reports `transferred`: the bytes libusb says arrived
    /// before the cut.
    ///
    /// WHY THIS EXISTS: every SETUP attempt reports `transferred = 0` for its
    /// aborted 0x800 `DFU_DNLOAD`, and no trace can separate "the device accepted
    /// nothing" from "WinUSB reports no partial count for a cancelled URB". For an
    /// **IN** transfer the same quantity is visible to a USBPcap capture, whose
    /// completion record carries the length the kernel reported — so running this
    /// probe under a capture and comparing this function's `transferred` against
    /// the pcap's completion `dataLength` answers it directly. A `GET_DESCRIPTOR`
    /// is used because this device provably answers that request during
    /// identification (`read_string_descriptor`), so a zero cannot be blamed on the
    /// device refusing.
    ///
    /// Deliberately bounded: one transfer, one deadline, no loop, and the caller
    /// must be a diagnostic, not a stage. The result is a *cut*, so its status is
    /// `Cancelled` and its `abort_after_ms` is the deadline — it goes through
    /// [`Self::control_async_abort`] rather than the deadline form precisely so the
    /// mechanism stays visible.
    pub fn diagnostic_partial_count_probe(&mut self, deadline_ms: u32) -> XferResult {
        let req = CtrlReq::new(
            0x80,
            0x06,
            (3u16 << 8) | FALLBACK_STRING_INDEX as u16,
            0x0409,
            255,
        );
        let mut buf = [0u8; 255];
        // One millisecond is the useful setting: identification shows this device
        // answering a string-descriptor read in ~6 ms, so a 1 ms cut lands inside
        // the transfer rather than after it.
        self.control_async_abort(req, &mut buf, deadline_ms)
    }

    /// **The DFU Functional Descriptor, read from the device.** One read-only
    /// control transfer; no reset, no `DNLOAD`, nothing state-changing.
    ///
    /// gaster never issues this (there is no `GET_DESCRIPTOR` of type `0x21`
    /// anywhere in `gaster.c`), so what it returns is new information rather than a
    /// comparison — in particular `wTransferSize`, the largest `DNLOAD` this unit
    /// declares it will accept, against gaster's hardcoded
    /// `DFU_MAX_TRANSFER_SZ = 0x800` (`gaster.c:44`).
    ///
    /// The three ways this can fail are three different facts and get three
    /// different messages, because the whole thesis of this crate is that
    /// collapsing them is how a diagnosis goes wrong:
    ///
    /// * **STALL** — the device does not serve this descriptor. A property of the
    ///   bootrom, not a fault in the request, and it means the declared size cannot
    ///   be read at all.
    /// * **TIMEOUT** — the request reached the wire and no answer came back.
    /// * **SHORT READ** — the device answered with fewer than nine bytes; refused
    ///   rather than zero-filled, so a failed read cannot manufacture the finding
    ///   "no transfer size declared".
    ///
    /// Uses the ordinary synchronous path: this is not timing-sensitive, and the
    /// tick-rounded wait that makes the *pad* unusable costs nothing here.
    pub fn dfu_functional_descriptor(&mut self) -> Result<DfuFunctionalDescriptor, String> {
        let req = dfu_functional_descriptor_request();
        let mut buf = [0u8; DfuFunctionalDescriptor::LEN as usize];
        let r = self.control(req, &mut buf, IDENT_TIMEOUT_MS);

        match r.status {
            XferStatus::Ok => DfuFunctionalDescriptor::decode(&buf[..r.transferred]).map_err(|e| {
                format!(
                    "{e}. The device answered the GET_DESCRIPTOR(type 0x21) with {} byte(s) after \
                     {} us; libusb rc {}",
                    r.transferred, r.micros, r.libusb_rc
                )
            }),
            XferStatus::Stall => Err(format!(
                "GET_DESCRIPTOR(type 0x21, wLength 9) STALLed after {} us: this device does not \
                 serve the DFU Functional Descriptor. That is a property of the bootrom, not a \
                 fault in the request — and it means the declared wTransferSize cannot be read \
                 from the device at all, so gaster's 0x800 stays an assumption rather than a \
                 measurement. libusb rc {}",
                r.micros, r.libusb_rc
            )),
            XferStatus::Timeout => Err(format!(
                "GET_DESCRIPTOR(type 0x21, wLength 9) returned TIMEOUT after {} us: the request \
                 reached the wire (the setup packet is in the capture) and no answer came back \
                 within {IDENT_TIMEOUT_MS} ms, which is what a NAKing endpoint looks like. \
                 Different from a STALL: nothing refused it, nothing answered it. libusb rc {}",
                r.micros, r.libusb_rc
            )),
            other => Err(format!(
                "GET_DESCRIPTOR(type 0x21, wLength 9) failed at the transport level: {} after \
                 {} us, libusb rc {}. Not a device answer — the request may never have been \
                 submitted.",
                other.as_str(),
                r.micros,
                r.libusb_rc
            )),
        }
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
                // Ours to report and nothing to reap: `NO_MEM` is what libusb
                // would have said, and the handle is untouched.
                return never_submitted(seq, r, sys::constants::LIBUSB_ERROR_NO_MEM);
            }

            let total = control_transfer_len(requested);
            // malloc, not Vec: libusb owns this buffer and is entitled to write
            // through it after we return if the transfer is still queued.
            let raw = libc::malloc(total) as *mut u8;
            if raw.is_null() {
                sys::libusb_free_transfer(transfer);
                return never_submitted(seq, r, sys::constants::LIBUSB_ERROR_NO_MEM);
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
                // the callback, so these are unambiguously ours to release — and
                // the handle is *not* poisoned. `libusb_rc` carries libusb's own
                // code (`NO_DEVICE`, `BUSY`, `NO_MEM`, ...) rather than the
                // `OTHER` sentinel, so this can never read as an unreaped
                // transfer for which libusb still owns memory. The elapsed time
                // here is a failed syscall's latency, not a transfer timing, so
                // it is not reported as one.
                libc::free(raw as *mut libc::c_void);
                sys::libusb_free_transfer(transfer);
                drop(Box::from_raw(flag));
                return never_submitted(seq, r, submitted);
            }

            let deadline = started + window;
            let pumped = pump_until_reaped(ctx, transfer, flag, deadline, deadline + HARD_GRACE);
            let micros = started.elapsed().as_micros() as u64;

            if !pumped.reaped {
                // libusb still owns the transfer and may still write through
                // the buffer and the flag. Leaking both is the only sound
                // option, and the handle is no longer trustworthy, so it is
                // poisoned rather than driven on. `abort_after_ms` stays
                // `Some(window)`: this transfer *was* submitted and *was*
                // cancelled at that deadline — libusb simply never said so.
                self.poisoned = true;
                return submitted_result(
                    seq,
                    r,
                    XferStatus::Error,
                    0,
                    micros,
                    LIBUSB_ERROR_OTHER,
                    cancel_after_ms,
                );
            }

            let transfer_status = (*transfer).status;
            let raw_len = (*transfer).actual_length.max(0) as usize;

            // Clamped, not trusted: libusb can report a wire count larger than
            // requested on a babble, and a caller slicing `data[..n]` would
            // panic. The raw count is what `transferred` reports whenever it
            // fits, because normalising it away is how a real partial becomes a
            // plausible zero.
            //
            // On the setup packet: for a control transfer libusb's
            // `actual_length` is the **data stage only** — the sync call returns
            // it verbatim (`sync.c:140-146`) and the Windows backend hands
            // `WinUsb_ControlTransfer` `transfer->length - LIBUSB_CONTROL_SETUP_SIZE`
            // (`windows_winusb.c:2973,3006`) — so this count is directly
            // comparable with `wLength` and with gaster's `transfer_ret->sz`.
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

            // The floor is applied inside `submitted_result`: a result below
            // `MIN_TRUSTWORTHY_MICROS` leaves as `Error`, never as an answer.
            submitted_result(
                seq,
                r,
                XferStatus::from_transfer_status(transfer_status),
                transferred,
                micros,
                transfer_status,
                cancel_after_ms,
            )
        }
    }

    fn refused(&self, r: CtrlReq) -> XferResult {
        // The handle is poisoned: libusb still owns a transfer's buffer, so no
        // request may be submitted. Nothing was submitted here, so there is no
        // window and no timing — see `never_submitted` for why that matters to
        // `stages::abort_was_refused`.
        never_submitted(self.seq.next(), r, LIBUSB_ERROR_OTHER)
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
        match self.reset_call() {
            ResetCall::Report(report) => Ok(report),
            ResetCall::RefusedAbsent { note, .. } | ResetCall::RefusedPresent { note, .. } => Err(note),
        }
    }

    /// Reset the port, with the failure **classified** rather than flattened.
    ///
    /// [`Transport::reset`] collapses every failure into one `Err`, which is
    /// right for an operator asking "did it reset?" and wrong for the run loop,
    /// which has to tell two different situations apart (MEASURED on this host,
    /// 2026-10-03 — a stock device, our own run):
    ///
    /// ```text
    ///   SPRAY: stage_pass
    ///   post-stage reset: libusb_reset_device failed: LIBUSB_ERROR_NOT_FOUND (-5)
    ///                     after 2 us with driver service 'usbfs'
    /// ```
    ///
    /// That `-5` is **not** the host refusing to reset. The A9 spray's last line
    /// is a `DFU_CLRSTATUS` (`gaster.c:910`), and a bare one drops this bootrom
    /// off the bus and it re-enumerates by itself — MEASURED as E2 on
    /// 2026-10-03: the device left the bus and returned **435 ms later at a new
    /// address**, PWND marker intact. `gaster` absorbs exactly this: it resets
    /// after every stage and discards the result (`gaster.c:197-200`, `:1268`),
    /// and `wait_usb_handle` (`:202-218`) simply loops until a handle appears
    /// again. So the drop caused by the exploit must never be attributed to the
    /// host's reset capability — that is the difference between
    /// [`ResetCall::RefusedAbsent`] and [`ResetCall::RefusedPresent`].
    ///
    /// The state pre-read is still taken first, so a report is produced whenever
    /// the call completed at all.
    pub fn reset_call(&mut self) -> ResetCall {
        let dfu_state_before = self.dfu_status_state(DFU_STATE_TIMEOUT_MS);

        let started = Instant::now();
        // SAFETY: the handle is open and owned by `self`.
        let rc = unsafe { sys::libusb_reset_device(self.handle.as_raw()) };
        let micros = started.elapsed().as_micros() as u64;
        let capability = self.reset_capability();

        if rc != sys::constants::LIBUSB_SUCCESS {
            let note = format!(
                "libusb_reset_device failed: {} ({rc}) after {micros} us with driver service \
                 '{}'. Nothing was confirmed: no bus reset was delivered and no pipe cycle was \
                 reported either. The reference ignores this return value and continues; doing \
                 the same is a choice the caller may make, but it is not evidence.",
                libusb_error_name(rc),
                self.driver_service()
            );
            return if reset_error_is_device_absent(rc) {
                ResetCall::RefusedAbsent {
                    rc,
                    micros,
                    note: format!(
                        "{note} The code says the DEVICE WAS ABSENT, not that the reset was \
                         refused: the exploit's own DFU_CLRSTATUS drops this bootrom and it \
                         re-enumerates by itself (MEASURED 435 ms, new address, 2026-10-03). \
                         Continue after waiting for it to come back."
                    ),
                }
            } else {
                ResetCall::RefusedPresent {
                    rc,
                    micros,
                    note: format!(
                        "{note} The device was present and the call was still refused, which is a \
                         capability problem, not the known drop."
                    ),
                }
            };
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

        ResetCall::Report(ResetReport {
            libusb_rc: rc,
            interface_claimed: self.interface_claimed,
            dfu_state_before,
            dfu_state_after,
            capability,
            evidence,
            bus_reset_delivered: evidence.delivered(),
            micros,
            note: reset_note_here(
                capability,
                &self.capability_note,
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
/// **Before the cancel: never ask the OS for a wait it cannot honour.** On
/// Windows that wait is `WaitForMultipleObjects` (`events_windows.c:175`), and any
/// non-zero timeout below one timer tick returns after a whole tick — so handing
/// it the remaining window (what this did) made every window from 1 to 5 ms
/// truncate at the same instant, which is exactly what the first hardware SETUP
/// run measured. See [`OS_WAIT_MARGIN`] for the numbers.
///
/// So the pre-cancel rule is *poll, or wait properly*: the OS is asked for
/// `remaining - margin` only when that is itself at least a margin — which by
/// construction is longer than one tick, so the request is one the OS can honour
/// to within a tick — and otherwise the wait is **zero** and the deadline is held
/// on `Instant`. Because every request stops a margin short, the overshoot
/// (always under one tick) cannot reach the deadline: measured, zero-timeout
/// polling hits windows of 1/2/3/4/5 ms at 1.003 / 2.002 / 3.008 / 4.007 /
/// 5.005 ms, and a long window still lets the OS do the bulk of the waiting.
///
/// After the cancel: at least [`POST_CANCEL_SLICE`], because from that point the
/// wait no longer decides *when* we abort, only how fast we notice.
pub fn pump_slice(remaining: Duration, cancelled: bool) -> Duration {
    if cancelled {
        return remaining.max(POST_CANCEL_SLICE);
    }
    let slice = remaining.saturating_sub(OS_WAIT_MARGIN);
    if slice < OS_WAIT_MARGIN {
        Duration::ZERO
    } else {
        slice
    }
}

/// libusb's transfer length for a control transfer: setup packet + data stage.
pub fn control_transfer_len(data_len: usize) -> usize {
    sys::constants::LIBUSB_CONTROL_SETUP_SIZE + data_len
}

/// **Requested window against effective truncation**, in words, for a trace.
///
/// The two numbers are already on every transfer line — `abort_after_ms` is what
/// the sweep asked for, `micros` is what the transfer actually took from
/// `libusb_submit_transfer` to the completion being reaped — but on the first
/// hardware SETUP run they were 4 ms and 11,700 us on *every* window, and a
/// reader had to notice that for themselves. This states the comparison, so the
/// next reader does not have to infer it.
///
/// The allowance for "honoured" is [`ABORT_OVERRUN_TOLERANCE_US`]: the cancel and
/// its reap cost a fraction of a millisecond, so a window that lands within 1 ms
/// of the request did what it was asked to do. A tick's worth of overshoot — the
/// defect, ~11 ms — is ten times that.
///
/// The caller owns the printing: this module measures, `stages.rs`'s per-attempt
/// line and `trace.rs`'s transfer line are where a sweep reports.
pub fn abort_truncation_note(r: &XferResult) -> String {
    let window_ms = match r.abort_after_ms {
        Some(ms) => ms,
        None => {
            return format!(
                "not an aborted transfer (no window was requested): {}",
                r.one_line()
            )
        }
    };
    let requested_us = u64::from(window_ms) * 1_000;
    let effective_us = r.micros;
    if effective_us < requested_us {
        // Cannot happen through `control_async_abort` — the cancel is only
        // requested once the deadline has passed — so say so rather than round
        // it into "honoured".
        return format!(
            "abort window requested {window_ms} ms but the transfer was reaped after only \
             {effective_us} us, BEFORE the window elapsed: the deadline was not the thing that \
             ended it. {}",
            r.one_line()
        );
    }
    let over_us = effective_us - requested_us;
    if over_us <= ABORT_OVERRUN_TOLERANCE_US {
        format!(
            "abort window requested {window_ms} ms, effective {effective_us} us \
             (+{over_us} us for the cancel and its reap): window HONOURED"
        )
    } else {
        // No attribution of the exact mechanism here: on the first hardware run
        // the overrun ranged from ~6.6 ms to ~10.7 ms across windows, because the
        // total is dominated by where in the OS wait's granularity the window
        // fell. Naming a figure the trace does not support is the defect this
        // project keeps paying for, so this states the overrun and the fact.
        format!(
            "abort window requested {window_ms} ms, effective {effective_us} us — OVER by \
             {over_us} us (a system timer tick is ~15.6 ms and the cancel costs well under 1 ms): \
             the host decided the truncation point, not the window, so this sweep cannot \
             distinguish its windows"
        )
    }
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
/// Windows only: this is the SetupAPI path, and it is gated rather than shared
/// because the Linux answer is a different measurement of a different thing
/// (sysfs, [`measure_sysfs_driver`]) — not a fallback for this one.
///
/// Returns `(service, note)`. The note says why the service is empty when it
/// is, because "no service" and "enumeration broken" must not look alike.
#[cfg(windows)]
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

// ---------------------------------------------------------------------------
// The discovery census and the open-failure record
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS. `verdict::classify` can only separate the four cases that
// `readmes/a9ctl-README.md` is built around if it is *given* the census and the
// open failure:
//
//   DEVICE_PATH_TOO_LONG     needs `Counters::device_path_len`  (verdict.rs:220-225)
//   WRONG_DRIVER_BOUND       needs `Counters::nodes_present_by_pid` + `last_open_error`
//   DRIVER_BOUND_NOT_LOADED  needs the same two                  (verdict.rs:226-232)
//   DEVICE_ABSENT            needs `discovery_recorded`          (verdict.rs:635-656)
//
// and those three `Counters` fields are written only by `Tracer::enumerated`,
// `Tracer::device_path` and `Tracer::open_failed`, which had no production
// caller — so three of the four verdicts could not fire at runtime. This section
// is the measuring half of the fix; `main.rs` owns the wiring into the `Tracer`.
//
// Everything here is read-only: SetupAPI enumeration and property reads, no
// device handle, no I/O to any USB device. Nothing here changes the behaviour of
// `open_first_dfu`, which is only instrumented to say *why* it failed.

/// The `LIBUSB_ERROR_*` code behind a `rusb::Error`.
///
/// rusb 0.9 exposes the error *variant* and no numeric code — its own mapping is
/// one-way (`rusb-0.9.4/src/error.rs:82-97`, `i32 -> Error`) — so the code is
/// restated here against `libusb1_sys::constants` and pinned by
/// [`tests::rusb_errors_map_to_their_libusb_codes`]. The match is exhaustive on
/// purpose: a future rusb variant must be classified by hand rather than
/// silently becoming `OTHER`.
pub fn rusb_error_code(e: rusb::Error) -> i32 {
    use sys::constants as c;
    match e {
        rusb::Error::Io => c::LIBUSB_ERROR_IO,
        rusb::Error::InvalidParam => c::LIBUSB_ERROR_INVALID_PARAM,
        rusb::Error::Access => c::LIBUSB_ERROR_ACCESS,
        rusb::Error::NoDevice => c::LIBUSB_ERROR_NO_DEVICE,
        rusb::Error::NotFound => c::LIBUSB_ERROR_NOT_FOUND,
        rusb::Error::Busy => c::LIBUSB_ERROR_BUSY,
        rusb::Error::Timeout => c::LIBUSB_ERROR_TIMEOUT,
        rusb::Error::Overflow => c::LIBUSB_ERROR_OVERFLOW,
        rusb::Error::Pipe => c::LIBUSB_ERROR_PIPE,
        rusb::Error::Interrupted => c::LIBUSB_ERROR_INTERRUPTED,
        rusb::Error::NoMem => c::LIBUSB_ERROR_NO_MEM,
        rusb::Error::NotSupported => c::LIBUSB_ERROR_NOT_SUPPORTED,
        // `rusb::Error::from_libusb` folds every other libusb code — including
        // `LIBUSB_ERROR_OTHER` — into `Other` (error.rs:96), and `BadDescriptor`
        // has no libusb 1.0.27 code at all. One bucket, named honestly.
        rusb::Error::BadDescriptor | rusb::Error::Other => c::LIBUSB_ERROR_OTHER,
    }
}

/// The last failure `open_first_dfu` reported, and the libusb code behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFailure {
    /// The `LIBUSB_ERROR_*` value when a libusb call produced one, or `None`
    /// when the failure was ours and no libusb call was made (for example "no
    /// Apple device among the 40 nodes enumerated"). `None` is a measurement,
    /// not a missing value: it says no libusb code exists for this failure.
    pub code: Option<i32>,
    /// The same sentence `open_first_dfu` returned. Device descriptors are
    /// already ECID-free on this path — the failure happens before any serial
    /// read — so nothing here needs redacting.
    pub note: String,
}

static LAST_OPEN_FAILURE: Mutex<Option<OpenFailure>> = Mutex::new(None);

/// Record a failed open. Poisoned-lock safe: a failure record is diagnostic, so
/// losing it (only possible if another thread panicked while holding this lock)
/// must never turn into a panic on the path that is reporting a problem.
fn record_open_failure(code: Option<i32>, note: &str) {
    if let Ok(mut slot) = LAST_OPEN_FAILURE.lock() {
        *slot = Some(OpenFailure {
            code,
            note: note.to_string(),
        });
    }
}

/// Record a failed open **and** return it, so a failure path cannot be written
/// without one. Every `Err` this module returns about opening goes through here.
fn fail_open(code: Option<i32>, message: String) -> Result<Transport, String> {
    record_open_failure(code, &message);
    Err(message)
}

/// Forget the last open failure. Called on every **successful** open, so
/// [`last_open_failure`] answers "did the last attempt fail?" — a stale record
/// from an earlier call would otherwise let `verdict.rs:226` accuse a device that
/// has just opened successfully.
pub fn clear_last_open_failure() {
    if let Ok(mut slot) = LAST_OPEN_FAILURE.lock() {
        *slot = None;
    }
}

/// The last failed open attempt, or `None` if the last attempt succeeded (or no
/// attempt has been made in this process).
///
/// Feed this to `Tracer::open_failed(errno, note)` — `errno` is `code`. Its
/// absence is **not** proof of a working open, exactly as
/// `trace::Counters::last_open_error` documents.
pub fn last_open_failure() -> Option<OpenFailure> {
    LAST_OPEN_FAILURE.lock().ok().and_then(|slot| slot.clone())
}

/// `VID_xxxx` and `PID_xxxx` out of a SetupAPI hardware ID, or `None` when the
/// ID carries neither.
///
/// Device IDs are `key_value` pairs joined by `\`, `&`, `#`, `.` or `^`; both
/// the separator and exactly four hex digits are required, which is what keeps
/// `PCI\VEN_8086&DEV_1234` (different keys entirely) and a hypothetical
/// `PROVID_1234` (no separator before `VID_`) from being read as a vendor ID.
/// USB vendor and product IDs are always four hex digits.
pub fn vid_pid_from_hardware_id(hardware_id: &str) -> Option<(u16, u16)> {
    let upper = hardware_id.to_ascii_uppercase();
    Some((
        id_field(&upper, "VID_")?,
        id_field(&upper, "PID_")?,
    ))
}

fn id_field(id_upper: &str, key: &str) -> Option<u16> {
    let bytes = id_upper.as_bytes();
    let mut from = 0usize;
    while let Some(pos) = id_upper[from..].find(key) {
        let at = from + pos;
        let boundary = at == 0 || matches!(bytes[at - 1], b'\\' | b'&' | b'#' | b'.' | b'^');
        let digits: String = id_upper[at + key.len()..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if boundary && digits.len() == 4 {
            return u16::from_str_radix(&digits, 16).ok();
        }
        from = at + key.len();
    }
    None
}

/// A read-only census of the present device tree, taken **before** any open.
///
/// Carries no device-identifying string: instance IDs contain the ECID, so only
/// their *lengths* are kept (HANDOFF §9.8), which is also all
/// `Tracer::device_path` stores.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceCensus {
    /// Present device nodes SetupAPI reported *at all*, hardware IDs included.
    /// Wider than the by-PID counts: it is the "did enumeration run" number.
    pub nodes_seen: usize,
    /// Present nodes that carry a `VID_`/`PID_`, counted per PID, in
    /// enumeration order. This is the argument `Tracer::enumerated` takes, and
    /// `Counters::nodes_total()` sums it.
    ///
    /// Keyed by PID alone (the `Tracer` interface is), so a PID shared by
    /// another vendor would be counted here; [`DeviceCensus::target_nodes`] is
    /// the VID-**and**-PID number where that distinction matters.
    pub nodes_by_pid: Vec<(u16, u32)>,
    pub target_vid: u16,
    pub target_pid: u16,
    /// Nodes matching [`DeviceCensus::target_vid`] **and**
    /// [`DeviceCensus::target_pid`]. A measured zero, not an absence of data.
    pub target_nodes: u32,
    /// Longest device instance ID among the target nodes, in bytes. `None` when
    /// there is no target node, or when its instance ID could not be read — an
    /// unreadable ID is not a measurement of length 0.
    pub longest_target_instance_id: Option<usize>,
    /// The same measurement across every node, for context. Never the number to
    /// compare against libusb's buffer: a long path on somebody else's device
    /// says nothing about ours.
    pub longest_any_instance_id: Option<usize>,
}

impl DeviceCensus {
    /// Where these numbers come from, said once so a reader can judge whether
    /// they are comparable with libusb's own buffer.
    pub const SOURCE: &'static str = "device instance ID read by our own SetupAPI pass \
         (SetupDiGetDeviceInstanceIdW, byte length; the IDs are ASCII so this is the same length \
         libusb sees through SetupDiGetDeviceInstanceIdA), which libusb reads into char[256] \
         (windows_winusb.h:37, windows_winusb.c:1599,1719) and silently skips when it does not fit";

    /// What `Tracer::device_path` should record: the length, and the note naming
    /// the source. `None` when no target node was present, in which case **do not
    /// call `device_path`** — no path was measured, and `Some(0)` would be a
    /// fabricated measurement rather than an absent one.
    ///
    /// The wiring, runnable (this is the call `main.rs` makes):
    ///
    /// ```
    /// use a9pwn::trace::Tracer;
    /// use a9pwn::usb::census_from_nodes;
    ///
    /// // No 05AC:1227 node was present, so no length was measured and the API
    /// // says so instead of reporting a `0` that a comparison could act on.
    /// let census = census_from_nodes(&[]);
    /// let (len, note) = census.device_path_arg();
    /// assert_eq!(len, None);
    ///
    /// let mut tracer = Tracer::new(None, false).expect("no trace file requested");
    /// match len {
    ///     Some(len) => tracer.device_path(len, &note),
    ///     None => tracer.event("device_path", None, &note),
    /// }
    /// ```
    pub fn device_path_arg(&self) -> (Option<usize>, String) {
        match self.longest_target_instance_id {
            Some(len) => (
                Some(len),
                format!(
                    "longest instance ID among {} node(s) {:#06X}:{:#06X}; {}. Compare against \
                     {} — at or beyond it libusb never opens this node.",
                    self.target_nodes,
                    self.target_vid,
                    self.target_pid,
                    Self::SOURCE,
                    crate::trace::LIBUSB_DEV_ID_CAPACITY
                ),
            ),
            None => (
                None,
                format!(
                    "no {:#06X}:{:#06X} node was present in the census ({} node(s) seen), so no \
                     instance ID was measured; {}",
                    self.target_vid,
                    self.target_pid,
                    self.nodes_seen,
                    Self::SOURCE
                ),
            ),
        }
    }

    /// Total nodes counted by PID — the value `Counters::nodes_total()` will
    /// report, and the "enumeration works" denominator.
    pub fn nodes_counted(&self) -> u32 {
        self.nodes_by_pid.iter().map(|(_, n)| *n).sum()
    }
}

/// Build the census from an already-taken node list. Pure, so the measurement
/// rule is testable without a device tree — the same reason
/// [`select_driver_service`] is pure.
pub fn census_from_nodes(nodes: &[UsbNode]) -> DeviceCensus {
    let mut out = DeviceCensus {
        nodes_seen: nodes.len(),
        target_vid: APPLE_VID,
        target_pid: DFU_MODE_PID,
        ..DeviceCensus::default()
    };

    for node in nodes {
        let len = node.instance_id.len();
        if len > 0 {
            // Only a non-empty ID is a length measurement.
            out.longest_any_instance_id = Some(out.longest_any_instance_id.unwrap_or(0).max(len));
        }

        let (vid, pid) = match vid_pid_from_hardware_id(&node.hardware_id) {
            Some(v) => v,
            None => continue,
        };
        match out.nodes_by_pid.iter_mut().find(|(p, _)| *p == pid) {
            Some((_, count)) => *count += 1,
            None => out.nodes_by_pid.push((pid, 1)),
        }
        if vid == APPLE_VID && pid == DFU_MODE_PID {
            out.target_nodes += 1;
            if len > 0 {
                out.longest_target_instance_id =
                    Some(out.longest_target_instance_id.unwrap_or(0).max(len));
            }
        }
    }

    out
}

/// Take the census now. Read-only; safe to call before an open, and safe to call
/// when no device is attached (that is the case it exists for).
pub fn census() -> DeviceCensus {
    census_from_nodes(&enumerate_usb_nodes())
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

/// Non-Windows build: there is no SetupAPI, so a Windows-shaped device census
/// cannot be taken — and one is deliberately **not** faked here.
///
/// The census feeds verdict predicates that are Windows measurements: the
/// longest *instance ID* is compared against libusb's 256-byte device-path
/// buffer (`verdict.rs:220-225`, `trace::LIBUSB_DEV_ID_CAPACITY`), and the
/// bound driver is SetupAPI's `SPDRP_SERVICE` string. A Linux node has neither
/// — its sysfs name is `1-4`, not a device path, and its "service" is a kernel
/// `driver` symlink — so returning Linux nodes in that shape would hand
/// `verdict.rs` a modelled number wearing a measured name. That is the exact
/// injury this crate exists to prevent.
///
/// What Linux needs instead is the *driver* answer, measured properly, and that
/// lives in [`measure_sysfs_driver`] / [`linux_driver_reading`]: the kernel
/// driver bound to **interface 0** of the node libusb opened, keyed by the bus
/// and address libusb itself read from the same sysfs `busnum`/`devnum` files
/// (`linux_usbfs.c:624-636`, stored at `:919-920`).
#[cfg(not(windows))]
pub fn enumerate_usb_nodes() -> Vec<UsbNode> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// The Linux host path: driver binding and reset capability, from sysfs
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS. `a9pwn` was written on Windows, where "can this host deliver
// the bus reset checkm8's trigger needs?" is answered by the *driver service*
// libusb is talking through: libusbK/libusb0 reach `ResetDevice`, WinUSB cannot
// (`windows_winusb.c:3389-3420`). On Linux the question has a different answer
// with a different mechanism, and the first hardware run printed the Windows
// answer on Linux — MEASURED 2026-10-03:
//
// ```text
//   capability    : unknown
//   what happened : ... driver service '(unmeasured)' is neither libusbK, libusb0
//                   nor WinUSB, so whether libusb issued a real device reset
//                   cannot be determined from here. Treat this as NOT a proven
//                   bus reset.
// ```
//
// while `libusb_reset_device` on that host had in fact gone to
// `op_reset_device` (`linux_usbfs.c:1578`), which issues
// `ioctl(IOCTL_USBFS_RESET)` (`:1596`) — `_IO('U', 20)` (`linux_usbfs.h:149`),
// i.e. `USBDEVFS_RESET` (`/usr/include/linux/usbdevice_fs.h:210`), a genuine
// port reset — and took 237.8 ms doing it. The Windows paragraph was not
// merely unhelpful there, it was FALSE, which is why the Linux capability is
// measured from sysfs and the Linux reset prose names the Linux mechanism.
//
// Nothing here opens a device, writes anything, or resets anything. It reads
// sysfs, which is read-only by construction, and it is pure over a `root` so
// the whole domain is pinned by fixture tests (no phone, no `/sys`).
//
// THE TRAP THIS CODE IS BUILT AROUND, MEASURED on this host 2026-10-03: every
// USB device node has a *device-level* `driver` link — for our DFU device
// `1-4/driver -> .../drivers/apple-mfi-fastcharge`, for an unrelated Bluetooth
// radio `1-10/driver -> .../drivers/usb`, the generic driver bound to every USB
// device. Reading *that* link as "the bound driver" would report a confident,
// plausible-looking wrong value for a device whose interface 0 is unbound.
// The classification input is therefore **interface 0's** link and nothing else
// (the device-level link is still measured and printed, as context).

/// Environment variable that overrides the sysfs root. `/sys` when unset or
/// empty. It exists so a fixture tree (or a captured tree) can be measured
/// without hardware — and so the evidence strings can say loudly that the root
/// was **not** `/sys`, because a fixture that masquerades as the real device
/// would be the same class of error as a guessed driver name.
#[cfg(unix)]
pub const SYSFS_ROOT_ENV: &str = "A9PWN_SYSFS_ROOT";

/// The real sysfs root. A `/sys` that is a symlink somewhere else is still the
/// real tree; this constant is what [`root_provenance`] compares against.
#[cfg(unix)]
pub const REAL_SYSFS_ROOT: &str = "/sys";

/// Resolve the sysfs root from an override value. **Pure**, so the rule is
/// testable without `set_var`, which would race every other test in the binary
/// (cargo runs tests in threads; one environment, many readers).
///
/// An override that is unset, empty or all whitespace means "no override", not
/// "the root is the empty path" — the second reading would silently measure
/// nothing and report it as absent.
#[cfg(unix)]
pub fn sysfs_root_from(override_value: Option<&str>) -> std::path::PathBuf {
    let trimmed = override_value.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return std::path::PathBuf::from(REAL_SYSFS_ROOT);
    }
    // `/tmp/fixture/` and `/tmp/fixture` must produce identical evidence
    // strings, or two runs of the same fixture would read as two roots.
    let stripped = trimmed.trim_end_matches('/');
    std::path::PathBuf::from(if stripped.is_empty() { "/" } else { stripped })
}

/// The sysfs root in use. Thin shell over [`sysfs_root_from`], which is where
/// the rule and its tests live.
#[cfg(unix)]
pub fn sysfs_root() -> std::path::PathBuf {
    sysfs_root_from(std::env::var(SYSFS_ROOT_ENV).ok().as_deref())
}

/// One sentence naming which root was measured, so an override can never be
/// mistaken for the real device in a trace or a report.
#[cfg(unix)]
pub fn root_provenance(root: &std::path::Path) -> String {
    if root == std::path::Path::new(REAL_SYSFS_ROOT) {
        format!("sysfs root {REAL_SYSFS_ROOT}")
    } else {
        format!(
            "sysfs root '{}' taken from {SYSFS_ROOT_ENV} — this is NOT {REAL_SYSFS_ROOT}",
            root.display()
        )
    }
}

/// One USB device node as `<root>/bus/usb/devices` describes it.
///
/// Interface bindings are resolved separately by [`resolve_interface0`], and the
/// device-level driver link by [`measure_sysfs_driver`], so one unrelated device
/// that is mid-enumeration cannot fail or pollute the measurement of ours.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysfsUsbNode {
    /// Directory name under `<root>/bus/usb/devices`, e.g. `1-4`.
    pub name: String,
    /// `busnum`, decimal. This is the number libusb reports as
    /// `bus_number` — libusb reads the same file (`linux_usbfs.c:624-629`).
    pub bus: u8,
    /// `devnum`, decimal. libusb's `device_address` (`:631-636`).
    pub address: u8,
    pub id_vendor: u16,
    pub id_product: u16,
}

/// The result of scanning a sysfs tree.
///
/// `skipped` is not decoration: a device tree where the node we want could not
/// be parsed must not read as "the device is absent", so the reason travels
/// with the scan and is quoted by the not-found message.
#[cfg(unix)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SysfsScan {
    pub nodes: Vec<SysfsUsbNode>,
    /// Entries that look like device nodes but could not be read or parsed,
    /// each with its reason.
    pub skipped: Vec<String>,
}

/// The driver binding of interface 0 on one device node.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysfsInterfaceBinding {
    /// Directory name, e.g. `1-4:1.0`.
    pub dir: String,
    /// The `driver` link's basename. **`None` is a measurement**: sysfs has no
    /// `driver` link on interface 0, so no kernel driver is bound to it.
    pub driver: Option<String>,
}

/// What the Linux host path measured about one device.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysfsDriverMeasurement {
    /// The root that was measured, verbatim, so the evidence carries it.
    pub root: String,
    pub device: SysfsUsbNode,
    pub interface0: SysfsInterfaceBinding,
    /// The **device-level** `driver` link, as context (see the trap above).
    /// `Err` means the link exists but could not be read: stated in the note and
    /// deliberately not fatal, because the classification input is interface 0.
    pub device_driver: Result<Option<String>, String>,
    /// The `Service`-equivalent string the rest of the crate classifies: a
    /// kernel driver name, or `usbfs` when no kernel driver is bound to
    /// interface 0 (which is what libusb is talking through).
    pub service: String,
    /// Human sentence naming exactly what was read, with the root provenance.
    pub note: String,
}

/// Read a sysfs attribute, trimmed.
///
/// Three outcomes, deliberately distinct, because collapsing them is how "not
/// there" becomes "nothing to see":
///   * `Ok(Some(v))`  — read;
///   * `Ok(None)`     — the attribute does not exist, so this directory is not
///     the kind of node being looked for (a USB *interface* has no `idVendor`);
///   * `Err(reason)`  — it exists and could not be read. Never silently treated
///     as absent: EACCES is a failed measurement, not a finding.
#[cfg(unix)]
fn read_attr(path: &std::path::Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("'{}' could not be read: {e}", path.display())),
    }
}

/// Parse a sysfs hexadecimal USB ID attribute.
///
/// sysfs prints exactly four lowercase hex digits with no `0x` (`05ac`). A
/// value of any other shape is refused rather than interpreted: a misread
/// `idVendor` would silently match — or fail to match — the wrong device, which
/// is the plausible-looking wrong value this module exists to prevent. Strict
/// on purpose, like `vid_pid_from_hardware_id` on the Windows side.
#[cfg(unix)]
fn parse_hex16(attr: &str, value: &str) -> Result<u16, String> {
    if value.len() != 4 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "'{attr}' reads '{value}', which is not the four hex digits sysfs prints for a USB ID"
        ));
    }
    u16::from_str_radix(value, 16).map_err(|e| format!("'{attr}' reads '{value}': {e}"))
}

/// Parse a sysfs decimal byte attribute (`busnum`, `devnum`).
#[cfg(unix)]
fn parse_dec_u8(attr: &str, value: &str) -> Result<u8, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "'{attr}' reads '{value}', which is not the decimal number sysfs prints"
        ));
    }
    value
        .parse::<u8>()
        .map_err(|e| format!("'{attr}' reads '{value}', which is not a byte value: {e}"))
}

/// Read and parse an attribute, keeping "absent" (`Ok(None)`) separate from
/// "present and unreadable or malformed" (`Err`).
#[cfg(unix)]
fn read_parsed<T>(
    path: &std::path::Path,
    parse: impl Fn(&str, &str) -> Result<T, String>,
) -> Result<Option<T>, String> {
    match read_attr(path)? {
        Some(v) => parse(&path.display().to_string(), &v).map(Some),
        None => Ok(None),
    }
}

/// The basename of `<dir>/driver`, or `None` when sysfs has no such link.
///
/// Four outcomes, and the difference between them is the whole point:
///   * no link at all — `Ok(None)`: **no kernel driver is bound** (a real
///     answer, reported as `usbfs` by the caller, never as unknown);
///   * a link into `<root>/bus/usb/drivers/<name>` — `Ok(Some(name))`;
///   * a link that cannot be resolved (dangling) — `Err`;
///   * a link that resolves *outside* the USB bus driver tree — `Err`. A
///     non-USB node's driver is not this device's driver, and accepting it
///     would put a confident wrong name in the `ident` line.
#[cfg(unix)]
fn driver_link(dir: &std::path::Path, root: &std::path::Path) -> Result<Option<String>, String> {
    let link = dir.join("driver");
    let meta = match std::fs::symlink_metadata(&link) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("'{}' could not be examined: {e}", link.display())),
    };
    if !meta.file_type().is_symlink() {
        return Err(format!(
            "'{}' exists but is not a symlink; refusing to read a driver name out of it",
            link.display()
        ));
    }
    let resolved = std::fs::canonicalize(&link).map_err(|e| {
        format!(
            "'{}' could not be resolved ({e}); a dangling driver link is not a measured driver",
            link.display()
        )
    })?;
    let drivers_root = root.join("bus/usb/drivers");
    let drivers_root = std::fs::canonicalize(&drivers_root).map_err(|e| {
        format!(
            "'{}' could not be resolved ({e}); without it a driver link cannot be checked",
            drivers_root.display()
        )
    })?;
    if !resolved.starts_with(&drivers_root) {
        return Err(format!(
            "'{}' resolves to '{}', which is not under '{}' — that is not a USB interface \
             driver, so it is not accepted as this device's binding",
            link.display(),
            resolved.display(),
            drivers_root.display()
        ));
    }
    match resolved.file_name().and_then(|n| n.to_str()) {
        Some(n) if !n.is_empty() => Ok(Some(n.to_string())),
        _ => Err(format!(
            "'{}' resolves to '{}', whose last component is not a driver name",
            link.display(),
            resolved.display()
        )),
    }
}

/// Every USB device node under `<root>/bus/usb/devices`, read-only.
///
/// Directory entries that are not device nodes (interfaces, whose names contain
/// `:`) are skipped deliberately; entries missing the four identifying
/// attributes are skipped as "not a USB device node"; but an attribute that is
/// *present and unreadable or malformed* is an error, never a skip — that is
/// how a permission problem becomes "no device" and then "device absent". Such
/// entries are returned in [`SysfsScan::skipped`] with their reason rather than
/// failing the whole scan, so a broken unrelated device cannot take our
/// measurement down with it.
#[cfg(unix)]
pub fn scan_sysfs_usb_devices(root: &std::path::Path) -> Result<SysfsScan, String> {
    let devices_dir = root.join("bus/usb/devices");
    let entries = std::fs::read_dir(&devices_dir).map_err(|e| {
        format!(
            "the sysfs device tree '{}' could not be listed ({e}); no kernel driver was \
             measured, which is UNKNOWN, not absent",
            devices_dir.display()
        )
    })?;

    let mut scan = SysfsScan::default();
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "a directory entry under '{}' could not be read: {e}",
                devices_dir.display()
            )
        })?;
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            // A non-UTF-8 name cannot be our device node; it is nevertheless
            // recorded rather than silently dropped.
            Err(raw) => {
                scan.skipped
                    .push(format!("<non-UTF-8 name {raw:?}>: not a nameable device node"));
                continue;
            }
        };
        if name.contains(':') {
            // `1-4:1.0` — an interface, not a device.
            continue;
        }
        let dir = entry.path();
        let parsed = (|| -> Result<Option<SysfsUsbNode>, String> {
            let id_vendor = match read_parsed(&dir.join("idVendor"), parse_hex16)? {
                Some(v) => v,
                None => return Ok(None),
            };
            let id_product = match read_parsed(&dir.join("idProduct"), parse_hex16)? {
                Some(v) => v,
                None => return Ok(None),
            };
            let bus = match read_parsed(&dir.join("busnum"), parse_dec_u8)? {
                Some(v) => v,
                None => return Ok(None),
            };
            let address = match read_parsed(&dir.join("devnum"), parse_dec_u8)? {
                Some(v) => v,
                None => return Ok(None),
            };
            Ok(Some(SysfsUsbNode {
                name: name.clone(),
                bus,
                address,
                id_vendor,
                id_product,
            }))
        })();
        match parsed {
            Ok(Some(node)) => scan.nodes.push(node),
            Ok(None) => {}
            Err(reason) => scan.skipped.push(format!("'{name}': {reason}")),
        }
    }
    Ok(scan)
}

/// Resolve **interface 0** of one device node: which directory is it, and what
/// driver is bound to it.
///
/// The name carries `(configuration, interface)` — `1-4:1.0` — but the name is
/// confirmed against `bInterfaceNumber` rather than trusted. More than one
/// configuration can carry an interface 0, so when that happens the device's
/// active `bConfigurationValue` decides; if it cannot, this refuses to guess
/// rather than pick one. A device with no interface-0 directory is an error,
/// **not** "no kernel driver bound": those are different measurements and only
/// one of them was taken.
#[cfg(unix)]
pub fn resolve_interface0(
    root: &std::path::Path,
    node: &SysfsUsbNode,
) -> Result<SysfsInterfaceBinding, String> {
    let dev_dir = root.join("bus/usb/devices").join(&node.name);
    let prefix = format!("{}:", node.name);
    let entries = std::fs::read_dir(&dev_dir).map_err(|e| {
        format!(
            "the device directory '{}' could not be listed ({e}); its interface drivers could \
             not be measured",
            dev_dir.display()
        )
    })?;

    // (directory name, configuration number from the name, bInterfaceNumber)
    let mut candidates: Vec<(String, u8)> = Vec::new();
    let mut interface_dirs = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "a directory entry under '{}' could not be read: {e}",
                dev_dir.display()
            )
        })?;
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        // `<device>:<cfg>.<iface>`
        let Some((cfg, iface)) = rest.split_once('.') else {
            continue;
        };
        interface_dirs += 1;
        if iface != "0" {
            continue;
        }
        let number = match read_parsed(&entry.path().join("bInterfaceNumber"), parse_dec_u8)? {
            Some(v) => v,
            // A directory shaped like `:1.0` with no `bInterfaceNumber` is not
            // something to interpret; it cannot be confirmed as interface 0.
            None => continue,
        };
        if number != 0 {
            continue;
        }
        let Ok(cfg_number) = cfg.parse::<u8>() else {
            continue;
        };
        candidates.push((name, cfg_number));
    }

    let chosen = match candidates.as_slice() {
        [] => {
            return Err(format!(
                "sysfs has no interface 0 directory under '{}' ({} interface directory/\
                 directories seen); refusing to report 'no kernel driver bound' for an \
                 interface that was not found",
                dev_dir.display(),
                interface_dirs
            ));
        }
        [one] => one.0.clone(),
        many => {
            // Several configurations carry an interface 0. The active one
            // decides — and only if the active configuration is readable.
            let active = read_parsed(&dev_dir.join("bConfigurationValue"), parse_dec_u8)?;
            match active {
                Some(active) => match many.iter().find(|(_, cfg)| *cfg == active) {
                    Some((name, _)) => name.clone(),
                    None => {
                        return Err(format!(
                            "'{}' has {} interface-0 directories but the active \
                             bConfigurationValue {} names none of them ({}); refusing to pick one",
                            dev_dir.display(),
                            many.len(),
                            active,
                            many.iter()
                                .map(|(n, c)| format!("{n} (cfg {c})"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                    }
                },
                None => {
                    return Err(format!(
                        "'{}' has {} interface-0 directories ({}) and no readable \
                         bConfigurationValue to say which is active; refusing to pick one",
                        dev_dir.display(),
                        many.len(),
                        many.iter()
                            .map(|(n, c)| format!("{n} (cfg {c})"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                }
            }
        }
    };

    let driver = driver_link(&dev_dir.join(&chosen), root)?;
    Ok(SysfsInterfaceBinding { dir: chosen, driver })
}

/// Measure the kernel driver binding of the device libusb opened.
///
/// `bus` and `address` are libusb's numbers, which on Linux **are** sysfs
/// `busnum`/`devnum`: libusb reads those two files and stores them as
/// `dev->bus_number` / `dev->device_address` (`linux_usbfs.c:624-636`,
/// `:919-920`). That correspondence is what makes this a measurement of the
/// same node rather than of a lookalike, and the ids are cross-checked anyway:
/// a node whose `idVendor`/`idProduct` are not `05AC:1227` is refused, so a
/// stale or recycled bus/address can never attribute another device's driver to
/// ours.
///
/// `Ok` means the node and its interface-0 binding were measured. `Err` is a
/// failed measurement whose reason is returned verbatim — the caller reports
/// `Unknown` with that reason, never a guess.
#[cfg(unix)]
pub fn measure_sysfs_driver(
    root: &std::path::Path,
    bus: u8,
    address: u8,
) -> Result<SysfsDriverMeasurement, String> {
    let scan = scan_sysfs_usb_devices(root)?;
    let matches: Vec<&SysfsUsbNode> = scan
        .nodes
        .iter()
        .filter(|d| d.bus == bus && d.address == address)
        .collect();
    let device = match matches.as_slice() {
        [] => {
            let skipped = if scan.skipped.is_empty() {
                String::new()
            } else {
                format!(
                    " ({} entr(y/ies) could not be read: {})",
                    scan.skipped.len(),
                    scan.skipped.join("; ")
                )
            };
            return Err(format!(
                "no sysfs device node reports busnum {bus} devnum {address} among {} readable \
                 USB device node(s) under '{}'{skipped}; the kernel driver bound to the device \
                 libusb opened could not be measured",
                scan.nodes.len(),
                root.display()
            ))
        }
        [one] => (*one).clone(),
        many => {
            return Err(format!(
                "{} sysfs device nodes report busnum {bus} devnum {address} ({}); refusing to \
                 pick one",
                many.len(),
                many.iter()
                    .map(|d| d.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    };

    if device.id_vendor != APPLE_VID || device.id_product != DFU_MODE_PID {
        return Err(format!(
            "sysfs node '{}' is busnum {bus} devnum {address} but reports {:04X}:{:04X}, not \
             {APPLE_VID:04X}:{DFU_MODE_PID:04X}; refusing to attribute another device's driver \
             to this one",
            device.name, device.id_vendor, device.id_product
        ));
    }

    // Context only, and explicitly non-fatal: the classification input is
    // interface 0. An unreadable device-level link is *stated*, not guessed at.
    let device_driver = driver_link(&root.join("bus/usb/devices").join(&device.name), root);
    let interface0 = resolve_interface0(root, &device)?;
    let (service, binding_note) = match &interface0.driver {
        Some(name) if name == "usbfs" => (
            name.clone(),
            format!(
                "sysfs '{}' reports interface 0 ({}) bound to usbfs: a userspace claim is \
                 holding it",
                device.name, interface0.dir
            ),
        ),
        Some(name) => (
            name.clone(),
            format!(
                "sysfs '{}' reports interface 0 ({}) bound to kernel driver '{}'",
                device.name, interface0.dir, name
            ),
        ),
        None => (
            "usbfs".to_string(),
            format!(
                "sysfs '{}' has NO driver link on interface 0 ({}), so no kernel driver is \
                 bound to it — that is the usbfs path libusb uses, not an unknown",
                device.name, interface0.dir
            ),
        ),
    };
    let device_note = match &device_driver {
        Ok(Some(name)) => format!(
            "the device node itself is bound to '{name}' (device-level, not interface 0 — every \
             USB device has such a link, so it is context, not the classification input)"
        ),
        Ok(None) => "the device node itself has no driver link".to_string(),
        Err(reason) => format!(
            "the device-level driver link could not be read ({reason}) — context only, not the \
             classification input"
        ),
    };
    let note = format!("{binding_note}; {device_note}; {}", root_provenance(root));

    Ok(SysfsDriverMeasurement {
        root: root.display().to_string(),
        device,
        interface0,
        device_driver,
        service,
        note,
    })
}

/// The host-side driver reading: the service string, the note, and the reset
/// capability with the evidence that produced it.
///
/// Fields are private to this module; `Transport` copies them out. The driver
/// *class* is derived from `service` at the call site — `DriverClass::from_service`
/// on Windows, [`linux_driver_class`] on Linux — so the driver line and the
/// capability line are always classified from the same measurement.
struct DriverReading {
    service: String,
    note: String,
    capability: ResetCapability,
    capability_note: String,
}

/// Classify the Linux driver answer, exactly.
///
/// **Why not [`DriverClass::from_service`].** That function matches on substring
/// (`s.contains("usbfs")`, `types.rs:383-384`), while the capability path here
/// compares the measured name exactly. A kernel driver literally named
/// `usbfs-kernel` bound to interface 0 would therefore print `driver service:
/// usbfs` in the same `ident` block whose next line says `reset: unknown` — two
/// answers to one question, and the reassuring one is the wrong one. On Linux
/// the measurement is exact, so the classification is too: only the literal
/// `usbfs` is the usbfs path (MEASURED: the reviewer's `usbfs-something-kernel`
/// fixture reproduced the contradiction this prevents), and any other bound
/// kernel driver is `Other` — a readable, non-libusb binding, which is what
/// `DriverClass::Other` means.
#[cfg(unix)]
fn linux_driver_class(reading: &DriverReading) -> DriverClass {
    match reading.service.as_str() {
        "usbfs" => DriverClass::Usbfs,
        "" => DriverClass::Unknown,
        _ => DriverClass::Other,
    }
}

/// Classify the Linux reset capability from the *measured* host path.
///
/// **Pure**, so the whole domain is pinned by a table test: every combination
/// of (measurement outcome, interface claimed) has exactly one classification
/// and one evidence sentence, and no combination is left to a default arm.
///
/// `Real` requires all three of these, in this order:
///   1. the sysfs measurement succeeded — the node was found by the same
///      bus/address libusb uses and its ids are ours;
///   2. interface 0 is not held by a kernel driver (its `driver` link is absent
///      or is `usbfs`), so the interface is the user-space path libusb talks
///      through;
///   3. interface 0 was **claimed** at open (`Transport::interface_claimed`).
///
/// Point 3 is a deliberate conservatism, not a Windows leftover: the Linux
/// backend issues the reset ioctl without consulting claims — `op_reset_device`
/// releases the interfaces *it* holds (`linux_usbfs.c:1589-1592`) and then
/// calls `ioctl(IOCTL_USBFS_RESET)` unconditionally (`:1596`) — so a reset can
/// physically work on an unclaimed handle. But an interface this transport does
/// not own is not an interface it can drive the exploit through, and the
/// Windows-side truth table (`types::reset_evidence`) reads a `Real` capability
/// with `claimed == false` as `DriverCannotReset`, which would make a working
/// run look broken. So an unclaimed interface is `Unknown` **with the reason**,
/// never `Real` on a hope.
///
/// Nothing here reads the OS *name*: a service string that is not `usbfs` is
/// evidence that a kernel driver holds the interface, and is classified
/// `Unknown` (it is never "Linux, therefore Real").
#[cfg(unix)]
fn linux_driver_reading(
    measured: Result<SysfsDriverMeasurement, String>,
    interface_claimed: bool,
) -> DriverReading {
    let measured = match measured {
        Ok(m) => m,
        Err(reason) => {
            return DriverReading {
                service: String::new(),
                note: format!(
                    "the Linux driver measurement failed: {reason}. This is a failed \
                     measurement, which is UNKNOWN — not evidence that no driver is bound"
                ),
                capability: ResetCapability::Unknown,
                capability_note: format!(
                    "reset capability UNKNOWN: {reason}. Nothing is assumed from the operating \
                     system's name, and nothing is assumed from a failed read"
                ),
            }
        }
    };

    let kernel_driver_bound = measured.service != "usbfs";
    if kernel_driver_bound {
        return DriverReading {
            service: measured.service.clone(),
            note: measured.note.clone(),
            capability: ResetCapability::Unknown,
            capability_note: format!(
                "reset capability UNKNOWN: {}. A kernel driver holding interface 0 means libusb \
                 cannot own it, so this transport is not classified as able to reset — and \
                 `usbfs` was not measured, so nothing here claims the user-space reset path",
                measured.note
            ),
        };
    }

    if !interface_claimed {
        return DriverReading {
            service: measured.service.clone(),
            note: measured.note.clone(),
            capability: ResetCapability::Unknown,
            capability_note: format!(
                "reset capability UNKNOWN: {}. The usbfs path is what libusb would use, but \
                 interface 0 was NOT claimed at open, so this transport does not own the \
                 interface. (The Linux backend still issues ioctl(USBDEVFS_RESET) without \
                 consulting claims — linux_usbfs.c:1589-1596 — but an interface we do not own is \
                 not classified Real.)",
                measured.note
            ),
        };
    }

    DriverReading {
        service: measured.service.clone(),
        note: measured.note.clone(),
        capability: ResetCapability::Real,
        capability_note: format!(
            "reset capability REAL, from two measurements plus one source inspection: \
             (a) MEASURED — {}. (b) MEASURED — interface 0 was claimed at open, so the interface \
             is this transport's. (c) INSPECTED, not measured here (no reset has been attempted \
             at this point, and none can be from a pure function) — libusb's Linux backend maps \
             libusb_reset_device to ioctl(USBDEVFS_RESET): op_reset_device at linux_usbfs.c:1578, \
             the ioctl at :1596, _IO('U', 20) at linux_usbfs.h:149. The kernel performs that \
             ioctl as a genuine port reset on the host controller, not a pipe cycle; the \
             reference implementation pwned this device through this host path \
             (MEASURED 2026-10-03). Capability is Real because (a) and (b) held; (c) is what \
             makes a per-call reset reportable as a bus reset rather than a pipe cycle.",
            measured.note
        ),
    }
}

/// The Windows capability evidence, in one sentence: which measured driver
/// service produced the classification. Pure; the classification itself stays
/// `ResetCapability::from_driver`, unchanged. Windows-only because it names the
/// Windows backends; Linux has its own evidence in [`linux_driver_reading`].
#[cfg(windows)]
fn windows_capability_note(capability: ResetCapability, service: &str) -> String {
    let service = if service.is_empty() { "(unmeasured)" } else { service };
    match capability {
        ResetCapability::Real => format!(
            "reset capability REAL from the measured driver service '{service}': libusb's \
             winusbx_reset_device reaches ResetDevice for libusbK/libusb0 (windows_winusb.c:3413)"
        ),
        ResetCapability::PipeCycleOnly => format!(
            "reset capability PIPE-CYCLE-ONLY from the measured driver service '{service}': the \
             WinUSB branch only aborts, flushes and resets the non-control pipes \
             (windows_winusb.c:3389-3410) and the sub_api guard at :3413 skips ResetDevice"
        ),
        ResetCapability::Unknown => format!(
            "reset capability UNKNOWN: the measured driver service '{service}' is not one of the \
             backends whose reset behaviour is known here (libusbK, libusb0, WinUSB)"
        ),
    }
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

    /// **The pre-cancel slice must never be a wait the OS cannot honour.**
    ///
    /// The old version of this test asserted that windows 0..5 produce
    /// *different* slices — which they did, and the OS then turned every
    /// non-zero one into the same ~15.6 ms tick. That is the third time this
    /// session a green test has ratified a wrong value: it tested the arithmetic
    /// we control, not the truncation we get. The property is therefore stated in
    /// terms of what the OS will do with the number, and the end-to-end behaviour
    /// is measured separately by
    /// [`effective_truncation_tracks_the_requested_window`].
    #[test]
    fn pre_cancel_slices_are_never_sub_tick_and_never_cross_the_deadline() {
        // The margin has to absorb a whole tick of overshoot, or an OS-assisted
        // wait could cross the deadline it is supposed to stop short of.
        assert!(
            OS_WAIT_MARGIN > Duration::from_micros(15_625),
            "the margin must exceed one system timer tick (15.625 ms)"
        );

        // gaster's A9 sweep — usb_timeout 5 ms, windows 0..=5 — is entirely
        // polled on this host, which is the case the hardware run needed.
        for ms in [0u32, 1, 2, 3, 4, 5] {
            assert_eq!(
                pump_slice(abort_window(ms), false),
                Duration::ZERO,
                "a {ms} ms window must be polled, never handed to the OS"
            );
        }

        // Invariants over a range that spans both branches, including the
        // boundary: zero, or long enough for the OS to honour, and always a
        // margin short of the deadline.
        for micros in [
            0u64, 1, 500, 1_000, 4_000, 5_000, 10_000, 19_999, 20_000, 39_999, 40_000, 40_001,
            100_000, 1_000_000, 2_000_000_000,
        ] {
            let remaining = Duration::from_micros(micros);
            let slice = pump_slice(remaining, false);
            assert!(
                slice == Duration::ZERO || slice >= OS_WAIT_MARGIN,
                "{micros} us remaining produced a {slice:?} slice: a sub-tick request is rounded \
                 up to a tick by the OS, so asking for one is asking for something else"
            );
            if slice > Duration::ZERO {
                assert!(
                    remaining - slice >= OS_WAIT_MARGIN,
                    "{micros} us remaining: the slice leaves only {:?} before the deadline, less \
                     than a tick of overshoot",
                    remaining - slice
                );
            }
        }

        // Exactly the documented rule, at the boundary and past it.
        assert_eq!(pump_slice(abort_window(40), false), abort_window(20));
        assert_eq!(pump_slice(abort_window(39), false), Duration::ZERO);
        assert_eq!(
            pump_slice(abort_window(1_000), false),
            abort_window(1_000) - OS_WAIT_MARGIN
        );

        // After the cancel the slice no longer decides when we abort, so it keeps
        // its floor: a signalled completion returns immediately whatever it is.
        assert_eq!(pump_slice(Duration::ZERO, true), POST_CANCEL_SLICE);
        assert_eq!(pump_slice(abort_window(5), true), abort_window(5));
    }

    /// **The property the sweep lives on, measured end to end.** Runs the real
    /// pump decision against the real libusb event loop and times how long it
    /// takes to reach a window-sized deadline.
    ///
    /// No device, no transfers: a libusb context with nothing queued is host-side
    /// only, which is why this is allowed in this file. What it proves is the
    /// thing that was *not* true on hardware: with `pump_slice` deciding the
    /// slices, a 4 ms window is reached in ~4 ms. Handing `remaining` straight to
    /// libusb (the pre-fix code) reaches it in ~15.6 ms on this host, because
    /// `WaitForMultipleObjects(4)` cannot return before the next tick.
    ///
    /// Three trials, best-of: a scheduling blip can only make a trial slower, so
    /// the minimum is the honest measurement of the mechanism — and a regression
    /// to a tick-granular wait is uniform, so it still fails the bound.
    #[test]
    fn effective_truncation_tracks_the_requested_window() {
        let ctx = match rusb::Context::new() {
            Ok(c) => c,
            Err(e) => {
                // No libusb on this machine is not a failure of this logic.
                println!("skipping: could not create a libusb context: {e}");
                return;
            }
        };
        let raw = ctx.as_raw();

        // Windows: 0, 1, 2, 4, 5 ms — gaster's sweep — each window retried until
        // it is **proven** honoured, up to a bounded number of attempts.
        //
        // WHY THIS ASSERTION HAS THE SHAPE IT HAS. The defect this test exists
        // for is the Windows tick: a sub-tick wait was rounded up, so windows
        // 1..5 all truncated at ~11.7 ms absolute — 6.7 ms or more OVER their
        // deadlines — and *every* window did. Two facts follow:
        //
        //   * load can only ever ADD time to a trial, so a single trial is a
        //     measurement of the machine's load, not of the mechanism. The
        //     pre-fix form of this test asserted `best-of-3 < window + 5 ms` for
        //     every window and flaked: MEASURED 2026-10-03 under a 40-way CPU
        //     load it failed 2 of 6 runs (`18.985 ms >= 9 ms`, window 4 ms),
        //     while the same load on the retry form below was 6/6 green.
        //   * the tick defect cannot produce a *single* clean sample on any
        //     host, however idle: no trial can land closer to the deadline than
        //     the tick it is quantised to. So retrying cannot rescue a real
        //     defect — it only stops machine load from failing an honest one.
        //
        // The assertion stays **per window** on purpose: a global minimum would
        // let window 0's instantly-returning sample mask a regression affecting
        // windows 1..5, which is exactly the regression this test is for.
        const MAX_TRIALS: u32 = 20;
        const CLEAN: Duration = Duration::from_millis(5);
        let mut samples: Vec<(u32, Duration)> = Vec::new();

        for window_ms in [0u32, 1, 2, 4, 5] {
            let window = abort_window(window_ms);
            let mut best = Duration::MAX;
            let mut trials = String::new();
            let mut attempts = 0u32;
            let mut proven = false;

            while attempts < MAX_TRIALS && !proven {
                attempts += 1;
                let started = Instant::now();
                let deadline = started + window;
                let mut polls = 0u32;
                loop {
                    let slice = pump_slice(deadline.saturating_duration_since(Instant::now()), false);
                    let (secs, usecs) = timeval_parts(slice);
                    let tv = libc::timeval {
                        tv_sec: secs as libc::c_long,
                        tv_usec: usecs as libc::c_long,
                    };
                    // SAFETY: `raw` is a live context owned by `ctx` for the whole
                    // test, and no transfer is ever submitted, so libusb cannot
                    // dispatch a callback into a dead frame.
                    let rc = unsafe {
                        sys::libusb_handle_events_timeout_completed(
                            raw,
                            &tv,
                            std::ptr::null_mut(),
                        )
                    };
                    polls += 1;
                    if rc == sys::constants::LIBUSB_ERROR_INTERRUPTED {
                        continue;
                    }
                    assert!(
                        rc == sys::constants::LIBUSB_SUCCESS
                            || rc == sys::constants::LIBUSB_ERROR_TIMEOUT,
                        "event pump failed: {rc}"
                    );
                    if Instant::now() >= deadline {
                        break;
                    }
                    assert!(polls < 1_000_000, "the pump never reached its deadline");
                }
                let effective = started.elapsed();
                if effective < best {
                    best = effective;
                }
                samples.push((window_ms, effective));
                if attempts > 1 {
                    trials.push_str(", ");
                }
                trials.push_str(&format!("{:.3}ms/{polls}p", effective.as_secs_f64() * 1000.0));
                if effective < window + CLEAN {
                    proven = true;
                }
            }

            println!(
                "abort window {window_ms} ms -> best effective {:.3} ms in {attempts}/\
                 {MAX_TRIALS} trial(s) ({trials})",
                best.as_secs_f64() * 1000.0
            );

            assert!(
                proven,
                "window {window_ms} ms was NOT honoured in {MAX_TRIALS} trials: best {best:?}, \
                 which is {:?} over the deadline. Every trial overshooting by more than {CLEAN:?} \
                 is what a tick-granular wait does — on the Windows host windows 1..5 all landed \
                 at ~11.7 ms — so the truncation point is coming from the host, not the window",
                best.saturating_sub(window)
            );

            // Never early: this half is a hard invariant of the loop and needs
            // no load tolerance — the cancel is only requested once the
            // deadline has passed, so no amount of load can make a sample short.
            for (ms, effective) in samples.iter().filter(|(ms, _)| *ms == window_ms) {
                assert!(
                    *effective >= abort_window(*ms),
                    "window {ms} ms was cut short: {effective:?} < {:?}",
                    abort_window(*ms)
                );
            }
        }
    }

    /// The requested-vs-effective line a sweep reports. Both verdicts matter: a
    /// window that was honoured must read as honoured, and the ~11 ms overrun
    /// that made the first hardware sweep unauditable must read as a defect —
    /// loudly, because that is the number nobody could see.
    #[test]
    fn abort_truncation_note_names_the_overrun() {
        let honoured = XferResult {
            abort_after_ms: Some(4),
            micros: 4_113,
            ..never_submitted(1, req(), LIBUSB_ERROR_OTHER)
        };
        let note = abort_truncation_note(&honoured);
        assert!(note.contains("requested 4 ms"), "{note}");
        assert!(note.contains("effective 4113 us"), "{note}");
        assert!(note.contains("HONOURED"), "{note}");
        assert!(!note.contains("OVER by"), "{note}");

        // Window 0 is honoured too: the 437 us is the cancel and its reap.
        let immediate = XferResult {
            abort_after_ms: Some(0),
            micros: 437,
            ..honoured.clone()
        };
        assert!(abort_truncation_note(&immediate).contains("HONOURED"));

        // The measured defect: every window landing at ~11.7 ms. Two of the real
        // pairs from the hardware run, because the overrun is not a constant.
        for (window_ms, micros, expected_over) in
            [(4u32, 11_700u64, 7_700u64), (1, 11_700, 10_700), (5, 11_600, 6_600)]
        {
            let overrun = XferResult {
                abort_after_ms: Some(window_ms),
                micros,
                ..honoured.clone()
            };
            let note = abort_truncation_note(&overrun);
            assert!(
                note.contains(&format!("OVER by {expected_over} us")),
                "{note}"
            );
            assert!(note.contains("host decided the truncation point"), "{note}");
            assert!(
                !note.contains("HONOURED"),
                "a tick-sized overrun must never read as honoured: {note}"
            );
        }

        // A transfer that was reaped before its window cannot happen through
        // `control_async_abort`; if it ever does, it must not be rounded up to
        // "honoured".
        let early = XferResult {
            abort_after_ms: Some(5),
            micros: 800,
            ..honoured.clone()
        };
        let note = abort_truncation_note(&early);
        assert!(note.contains("BEFORE the window elapsed"), "{note}");
        assert!(!note.contains("HONOURED"), "{note}");

        // Not an aborted transfer at all.
        let sync = never_submitted(2, req(), LIBUSB_ERROR_OTHER);
        assert!(abort_truncation_note(&sync).contains("no window was requested"));
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

        // The silent skip: right driver, no claimed interface, and nothing
        // moved on the device — so the skip is the explanation.
        let skipped = reset_note(ResetCapability::Real, false, "libusbK", ok, 120, parked, parked);
        assert!(skipped.contains("no-op"), "{skipped}");
        assert!(skipped.contains("3415"), "{skipped}");
        assert!(!skipped.contains("DELIVERED"), "{skipped}");

        // …but when the device DID move, the claim flag must not be allowed to
        // turn a delivered reset into a "no-op" sentence: the flag is a snapshot
        // from open and libusb auto-claims (`windows_winusb.c:2985`), which is
        // exactly what the pre-reset `DFU_GETSTATUS` does. This note used to say
        // "ResetDevice was never called" here, contradicting the state pair
        // printed in its own first sentence.
        let moved_unclaimed =
            reset_note(ResetCapability::Real, false, "libusbK", ok, 120, parked, idle);
        assert!(moved_unclaimed.contains("DELIVERED"), "{moved_unclaimed}");
        assert!(
            !moved_unclaimed.contains("no-op"),
            "a reset the device confirmed must not be called a no-op: {moved_unclaimed}"
        );
        assert!(
            moved_unclaimed.contains("NOT claimed at open"),
            "…and the claim flag must still be stated, not hidden: {moved_unclaimed}"
        );
        assert!(
            moved_unclaimed.contains("8 (manifestWaitReset) -> 2 (dfuIDLE)"),
            "{moved_unclaimed}"
        );
        // The two wordings for an unclaimed interface are different sentences
        // for different measurements.
        assert_ne!(skipped, moved_unclaimed);

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

    // ---- result shapes -----------------------------------------------------
    //
    // The three builders are the only place a `XferResult` is constructed for a
    // transfer, so these tests are what keeps the shapes from drifting back into
    // per-call-site literals. None of them touches a device.

    fn req() -> CtrlReq {
        CtrlReq::new(0x21, 1, 0, 0, 0x800)
    }

    /// A transfer that was never submitted must not look like one libusb still
    /// owes us. That distinction is not cosmetic: `XferResult::unreaped` says
    /// "libusb may still write through the buffer", and `stages::abort_was_refused`
    /// reads the same shape to stop sweeping a handle that refuses everything.
    ///
    /// This pinned a real defect: a failed `libusb_submit_transfer` used to be
    /// reported with `libusb_rc = LIBUSB_ERROR_OTHER` **and** an abort window and
    /// a measured micros, which satisfies `unreaped()` — so a submit that never
    /// queued anything printed `UNREAPED` and poisoned nothing.
    #[test]
    fn never_submitted_transfers_report_no_window_and_are_not_unreaped() {
        // Every code a never-submitted path can carry, including the sentinel
        // itself: the sentinel alone must not be enough to look unreaped.
        for code in [
            LIBUSB_ERROR_OTHER,
            sys::constants::LIBUSB_ERROR_NO_DEVICE,
            sys::constants::LIBUSB_ERROR_BUSY,
            sys::constants::LIBUSB_ERROR_NO_MEM,
            sys::constants::LIBUSB_ERROR_INVALID_PARAM,
            sys::constants::LIBUSB_SUCCESS,
        ] {
            let r = never_submitted(7, req(), code);
            assert_eq!(r.seq, 7);
            assert_eq!(r.status, XferStatus::Error, "code {code}");
            assert_eq!(r.transferred, 0, "nothing crossed the wire");
            assert_eq!(r.requested, 0x800);
            assert_eq!(r.libusb_rc, code, "the real code must survive");
            assert_eq!(r.abort_after_ms, None, "no window was applied");
            assert_eq!(r.micros, 0, "no transfer timing was taken");
            assert!(r.timing_refuted(), "0 us is not a measurement");
            assert!(
                !r.unreaped(),
                "code {code}: nothing was submitted, libusb owns nothing"
            );
            assert!(!r.one_line().contains("UNREAPED"), "{}", r.one_line());
            assert!(r.one_line().ends_with("SUBMICRO"), "{}", r.one_line());
        }
    }

    /// Every result for a transfer that *was* submitted carries the abort window
    /// it ran under — the field `verdict::ABORT_WINDOW_UNREPORTED` and
    /// `Counters::setup_async_unreported` exist to detect the absence of — and
    /// the timing floor is applied here, where it cannot be forgotten.
    #[test]
    fn submitted_transfers_always_report_a_window_and_apply_the_floor() {
        for window in [0u32, 1, 4, 5, 1_000] {
            let ok = submitted_result(
                3,
                req(),
                XferStatus::Ok,
                0x800,
                900,
                sys::constants::LIBUSB_TRANSFER_COMPLETED,
                window,
            );
            assert_eq!(ok.abort_after_ms, Some(window), "window {window} went missing");
            assert_eq!(ok.status, XferStatus::Ok, "a real 900 us result is kept");
            assert_eq!(ok.requested, 0x800, "requested comes from wLength");
            assert!(ok.ok() && !ok.stalled());
        }

        // Sub-microsecond: the transfer cannot have happened, so the *answer* is
        // refused even though a callback ran and libusb said COMPLETED. This is
        // the a9ctl defect, applied to the shape rather than to a promise.
        let refuted = submitted_result(
            4,
            req(),
            XferStatus::Ok,
            0x800,
            0,
            sys::constants::LIBUSB_TRANSFER_COMPLETED,
            4,
        );
        assert_eq!(refuted.status, XferStatus::Error);
        assert!(!refuted.ok(), "a sub-microsecond Ok must never leave");
        assert!(refuted.timing_refuted());
        assert_eq!(refuted.abort_after_ms, Some(4), "the window is still reported");

        // The floor is total: no status survives it below the floor.
        for status in [
            XferStatus::Ok,
            XferStatus::Stall,
            XferStatus::Timeout,
            XferStatus::Cancelled,
            XferStatus::NoDevice,
            XferStatus::Error,
        ] {
            assert_eq!(
                refuse_untrustworthy_timing(status, 0),
                XferStatus::Error,
                "{status:?} must not survive a 0 us timing"
            );
            assert_eq!(
                refuse_untrustworthy_timing(status, MIN_TRUSTWORTHY_MICROS),
                status,
                "{status:?} at the floor is kept"
            );
        }

        // An unreaped transfer is the one shape allowed to satisfy `unreaped()`:
        // submitted, cancelled at its deadline, never handed back, with a real
        // elapsed time — and the handle poisoned by the caller.
        let lost = submitted_result(
            5,
            req(),
            XferStatus::Error,
            0,
            2_004_000,
            LIBUSB_ERROR_OTHER,
            4,
        );
        assert!(lost.unreaped(), "{}", lost.one_line());
        assert!(lost.one_line().ends_with("UNREAPED"), "{}", lost.one_line());
        assert_eq!(lost.abort_after_ms, Some(4));
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

    /// State names are for humans reading a trace, and a wrong one is worse than
    /// none: it reads as a measurement. **This test previously checked three
    /// states (0, 2, 8) and the sentinel — and those three were exactly the three
    /// the table had right**, so it ratified a scramble of 1/3/4/5 and passed
    /// while a live run printed `5 (dfuMANIFEST-SYNC)` for a device in
    /// `dfuDNLOAD-IDLE`. A subset check cannot catch a table error, so this now
    /// pins all eleven states, in both directions.
    #[test]
    fn dfu_state_names_are_accurate() {
        // (bState, expected name) for the whole DFU 1.1 list, in order.
        let table: [(u8, &str); 11] = [
            (0, "appIDLE"),
            (1, "appDETACH"),
            (2, "dfuIDLE"),
            (3, "dfuDNLOAD-SYNC"),
            (4, "dfuDNBUSY"),
            (5, "dfuDNLOAD-IDLE"),
            (6, "manifestSync"),
            (7, "manifest"),
            (8, "manifestWaitReset"),
            (9, "dfuUPLOAD-IDLE"),
            (10, "dfuERROR"),
        ];
        for (state, name) in table {
            assert_eq!(dfu_state_name(state), name, "bState {state}");
        }

        // The four that were scrambled, called out by number so a future edit
        // that "tidies" them back cannot pass by accident.
        assert_eq!(dfu_state_name(1), "appDETACH");
        assert_eq!(dfu_state_name(3), "dfuDNLOAD-SYNC");
        assert_eq!(dfu_state_name(4), "dfuDNBUSY");
        assert_eq!(dfu_state_name(5), "dfuDNLOAD-IDLE");

        // The numeric constants this crate decides on must agree with the names
        // the table gives those numbers: if a constant in `lib.rs` ever moved,
        // the name would move with it and that collision shows up here.
        assert_eq!(
            dfu_state_name(crate::DFU_STATE_MANIFEST_WAIT_RESET),
            "manifestWaitReset"
        );
        assert_eq!(crate::DFU_STATE_MANIFEST_WAIT_RESET, 8);

        // 11 is one past the end of the list, not a state.
        assert_eq!(dfu_state_name(11), "unrecognised");
        assert_eq!(dfu_state_name(0xFE), "unrecognised");

        // Distinct names: two states sharing one label is an ambiguous trace at
        // exactly the point where it has to be unambiguous.
        for (i, (_, a)) in table.iter().enumerate() {
            for (_, b) in table.iter().skip(i + 1) {
                assert_ne!(a, b, "two DFU states share the name {a}");
            }
        }
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
                        IBFL:<redacted> SRTG:[IBOOT-2234.0.0.2.22]";

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
                 ECID:00112233445566AA_IBFL:<redacted>_SRTG:[IBOOT-2234.0.0.2.22]",
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

    /// Every speed has a distinct, honest name, and the two that decide how a
    /// zero `abort_xfer` must be read carry their bit rate — the whole reason the
    /// transport measures the speed at all.
    #[test]
    fn speed_names_are_distinct_and_carry_the_bit_rate() {
        let table = [
            (rusb::Speed::Unknown, "unknown"),
            (rusb::Speed::Low, "1.5 Mbit/s"),
            (rusb::Speed::Full, "12 Mbit/s"),
            (rusb::Speed::High, "480 Mbit/s"),
            (rusb::Speed::Super, "5 Gbit/s"),
            (rusb::Speed::SuperPlus, "10 Gbit/s"),
        ];
        for (speed, expected) in table {
            let name = speed_name(speed);
            assert!(name.contains(expected), "{speed:?} -> {name}");
        }
        // Distinct: two speeds sharing one name would make the trace ambiguous at
        // exactly the point that decides how a 0-byte abort is read.
        for (i, (a, _)) in table.iter().enumerate() {
            for (b, _) in table.iter().skip(i + 1) {
                assert_ne!(speed_name(*a), speed_name(*b), "{a:?} and {b:?} share a name");
            }
        }
        // The discriminator this test exists for: full and high must not be
        // confusable, because they give opposite readings of the same 0 bytes.
        assert!(speed_name(rusb::Speed::Full).contains("12"));
        assert!(speed_name(rusb::Speed::High).contains("480"));
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

    // ---- the discovery census and the open-failure record -------------------
    //
    // `verdict.rs` can only separate DEVICE_PATH_TOO_LONG, WRONG_DRIVER_BOUND,
    // DRIVER_BOUND_NOT_LOADED and DEVICE_ABSENT if it is handed these
    // measurements, so what they measure is pinned here rather than assumed.

    /// `rusb` names its errors but does not number them
    /// (`rusb-0.9.4/src/error.rs:82-97` maps `i32 -> Error` only), so our
    /// restatement has to be checked against the binding, not trusted.
    #[test]
    fn rusb_errors_map_to_their_libusb_codes() {
        use sys::constants as c;
        let table: [(rusb::Error, i32); 14] = [
            (rusb::Error::Io, -1),
            (rusb::Error::InvalidParam, -2),
            (rusb::Error::Access, -3),
            (rusb::Error::NoDevice, -4),
            (rusb::Error::NotFound, -5),
            (rusb::Error::Busy, -6),
            (rusb::Error::Timeout, -7),
            (rusb::Error::Overflow, -8),
            (rusb::Error::Pipe, -9),
            (rusb::Error::Interrupted, -10),
            (rusb::Error::NoMem, -11),
            (rusb::Error::NotSupported, -12),
            (rusb::Error::BadDescriptor, -99),
            (rusb::Error::Other, -99),
        ];
        for (err, code) in table {
            assert_eq!(rusb_error_code(err), code, "{err:?}");
        }
        // …and the literals above are the binding's own values.
        assert_eq!(c::LIBUSB_ERROR_IO, -1);
        assert_eq!(c::LIBUSB_ERROR_INVALID_PARAM, -2);
        assert_eq!(c::LIBUSB_ERROR_ACCESS, -3);
        assert_eq!(c::LIBUSB_ERROR_NO_DEVICE, -4);
        assert_eq!(c::LIBUSB_ERROR_NOT_FOUND, -5);
        assert_eq!(c::LIBUSB_ERROR_BUSY, -6);
        assert_eq!(c::LIBUSB_ERROR_TIMEOUT, -7);
        assert_eq!(c::LIBUSB_ERROR_OVERFLOW, -8);
        assert_eq!(c::LIBUSB_ERROR_PIPE, -9);
        assert_eq!(c::LIBUSB_ERROR_INTERRUPTED, -10);
        assert_eq!(c::LIBUSB_ERROR_NO_MEM, -11);
        assert_eq!(c::LIBUSB_ERROR_NOT_SUPPORTED, -12);
        assert_eq!(c::LIBUSB_ERROR_OTHER, LIBUSB_ERROR_OTHER);
    }

    /// Hardware-ID parsing is what the census counts on, so it is pinned against
    /// the shapes Windows actually produces — and the ones that must not match.
    #[test]
    fn hardware_ids_are_parsed_by_separator_and_exactly_four_digits() {
        assert_eq!(
            vid_pid_from_hardware_id("USB\\VID_05AC&PID_1227&REV_0100"),
            Some((0x05AC, 0x1227))
        );
        // The same ID reaches us in either case, depending on the source.
        assert_eq!(
            vid_pid_from_hardware_id("usb\\vid_05ac&pid_1227&rev_0100"),
            Some((0x05AC, 0x1227))
        );
        assert_eq!(
            vid_pid_from_hardware_id("HID\\VID_05AC&PID_0220"),
            Some((0x05AC, 0x0220))
        );

        // Not USB IDs at all: a PCI ID uses different keys, and a root hub has
        // no IDs, so neither may be counted as a device with a PID.
        assert_eq!(vid_pid_from_hardware_id("PCI\\VEN_8086&DEV_1234"), None);
        assert_eq!(vid_pid_from_hardware_id("USB\\ROOT_HUB30\\5&4087d53&0&0"), None);
        assert_eq!(vid_pid_from_hardware_id(""), None);

        // The separator and the width are enforced, not hoped for.
        assert_eq!(vid_pid_from_hardware_id("USB\\PROVID_05AC&PID_1227"), None);
        assert_eq!(vid_pid_from_hardware_id("USB\\VID_05AC1&PID_1227"), None);
        assert_eq!(vid_pid_from_hardware_id("USB\\VID_05A&PID_1227"), None);
        // Half an ID is not an ID.
        assert_eq!(vid_pid_from_hardware_id("USB\\VID_05AC&REV_0100"), None);
    }

    /// The census measurement, on synthetic nodes. The number that decides
    /// `DEVICE_PATH_TOO_LONG` is the longest instance ID among the **target**
    /// nodes — a 400-byte path on somebody else's device must not accuse ours.
    #[test]
    fn census_measures_the_target_path_not_the_longest_path_on_the_bus() {
        let short = format!("USB\\VID_05AC&PID_1227\\{}", "A".repeat(100));
        let long = format!("USB\\VID_05AC&PID_1227\\{}", "B".repeat(270));
        let other = format!("USB\\VID_046D&PID_C52B\\{}", "C".repeat(400));
        let nodes = vec![
            node(&short, "USB\\VID_05AC&PID_1227&REV_0100", "libusbK"),
            node(&other, "USB\\VID_046D&PID_C52B&REV_0100", "HidUsb"),
            node(&long, "USB\\VID_05AC&PID_1227&REV_0100", "libusbK"),
            node("USB\\ROOT_HUB30\\5&4087d53&0&0", "USB\\ROOT_HUB30", "usbhub"),
        ];
        let c = census_from_nodes(&nodes);

        assert_eq!(c.nodes_seen, 4, "every node SetupAPI reported is counted");
        assert_eq!(c.target_vid, APPLE_VID);
        assert_eq!(c.target_pid, DFU_MODE_PID);
        assert_eq!(c.target_nodes, 2);
        assert_eq!(c.longest_target_instance_id, Some(long.len()));
        assert!(
            c.longest_target_instance_id.unwrap() >= crate::trace::LIBUSB_DEV_ID_CAPACITY,
            "the fixture has to be over libusb's buffer for this to test anything"
        );
        assert_eq!(
            c.longest_any_instance_id,
            Some(other.len()),
            "context only — and it is longer, which is exactly why it is not the number used"
        );

        // Counted by PID, in enumeration order. The root hub has no VID/PID, so
        // it appears in `nodes_seen` and in no by-PID count.
        assert_eq!(c.nodes_by_pid, vec![(0x1227, 2), (0xC52B, 1)]);
        assert_eq!(c.nodes_counted(), 3);
        assert!(c.nodes_counted() as usize <= c.nodes_seen);

        let (len, note) = c.device_path_arg();
        assert_eq!(len, Some(long.len()), "the target length, not the bus maximum");
        assert!(note.contains("256"), "{note}");
        assert!(note.contains("SetupDiGetDeviceInstanceIdW"), "{note}");
    }

    /// No target node means **nothing was measured**: `None`, never a plausible
    /// zero that some later comparison would treat as a number somebody took.
    #[test]
    fn a_census_without_the_target_measures_no_path() {
        let c = census_from_nodes(&[
            node(
                "USB\\VID_046D&PID_C52B\\5&1234",
                "USB\\VID_046D&PID_C52B&REV_0100",
                "HidUsb",
            ),
            node("USB\\ROOT_HUB30\\5&4087d53&0&0", "USB\\ROOT_HUB30", "usbhub"),
        ]);
        assert_eq!(c.target_nodes, 0);
        assert_eq!(c.longest_target_instance_id, None);
        assert!(!c.nodes_by_pid.is_empty(), "the rest of the bus was still counted");

        let (len, note) = c.device_path_arg();
        assert_eq!(len, None, "no target node — do not call Tracer::device_path");
        assert!(note.contains("no 0x05AC:0x1227 node"), "{note}");
        assert!(note.contains("2 node(s) seen"), "{note}");

        // A recorded empty census is the only thing that makes
        // `Counters::nodes_total() == 0` mean "nothing enumerated".
        let empty = census_from_nodes(&[]);
        assert_eq!(empty.nodes_seen, 0);
        assert_eq!(empty.nodes_counted(), 0);
        assert_eq!(empty.longest_any_instance_id, None);
        assert!(empty.device_path_arg().0.is_none());
    }

    /// An unreadable instance ID is not a length of zero. It is the difference
    /// between "libusb can hold this path" and "nobody looked".
    #[test]
    fn an_unreadable_instance_id_is_not_a_zero_length_path() {
        let c = census_from_nodes(&[node("", "USB\\VID_05AC&PID_1227&REV_0100", "libusbK")]);
        assert_eq!(c.target_nodes, 1, "the node is present");
        assert_eq!(
            c.longest_target_instance_id, None,
            "SetupAPI returned no ID, so no length was measured"
        );
        assert_eq!(c.device_path_arg().0, None);
    }

    /// The census must never carry a device-identifying string: instance IDs
    /// contain the ECID (HANDOFF §9.8), and `Tracer::device_path`'s contract is
    /// that only the length is stored.
    #[test]
    fn the_census_keeps_lengths_not_instance_ids() {
        let ecid = "00112233445566AA";
        let instance = format!(
            "USB\\VID_05AC&PID_1227\\CPID:8003_CPRV:01_BDID:02_ECID:{ecid}_SRTG:[IBOOT-2234.0.0.2.22]"
        );
        let c = census_from_nodes(&[node(
            &instance,
            "USB\\VID_05AC&PID_1227&REV_0100",
            "libusbK",
        )]);
        let (len, note) = c.device_path_arg();
        assert_eq!(len, Some(instance.len()));

        let rendered = format!("{c:?} {note}");
        assert!(!rendered.contains(ecid), "the ECID leaked: {rendered}");
        assert!(!rendered.contains("SRTG"), "the descriptor leaked: {rendered}");
        assert!(!rendered.contains("CPID"), "the descriptor leaked: {rendered}");
    }

    /// The open-failure record is what tells "driver bound but not loaded" from
    /// "device absent", and it must describe the **last** attempt: a failure that
    /// outlived a successful open would accuse a device that is working.
    ///
    /// One test, not three, because this state is process-global and the test
    /// harness runs tests in parallel — separate tests would race each other.
    #[test]
    fn the_open_failure_record_describes_the_last_attempt() {
        clear_last_open_failure();
        assert_eq!(last_open_failure(), None, "nothing has failed yet");

        record_open_failure(Some(-4), "libusb_open: NO_DEVICE");
        let f = last_open_failure().expect("recorded");
        assert_eq!(f.code, Some(-4));
        assert_eq!(f.note, "libusb_open: NO_DEVICE");

        // Replaced, not accumulated.
        record_open_failure(None, "no Apple device among the 40 nodes enumerated");
        let f = last_open_failure().expect("recorded");
        assert_eq!(f.code, None, "our own failure has no libusb code to report");
        assert!(f.note.contains("40 nodes"), "{}", f.note);

        // `fail_open` records and returns the same sentence, so a failure path
        // cannot be written that forgets the record.
        clear_last_open_failure();
        let message = match fail_open(Some(-6), "device busy".to_string()) {
            Ok(_) => panic!("fail_open must never succeed"),
            Err(e) => e,
        };
        assert_eq!(message, "device busy");
        assert_eq!(last_open_failure().unwrap().code, Some(-6));

        // A successful open clears it; `None` then means "the last attempt
        // worked" rather than "a failure from an earlier call".
        clear_last_open_failure();
        assert_eq!(last_open_failure(), None);
    }

    // ---- the pad's true deadline -------------------------------------------
    //
    // The pad is the pass condition's instrument (`gaster.c:853`), so these pin
    // both halves: what the device's answer looks like, and what the *host* giving
    // up looks like. A fix that quietly disarms a verdict is worse than the bug it
    // fixes, which is why the third test below reads the real counters.

    /// The mapping that keeps a pad timeout meaning a timeout. Both directions,
    /// because the risk is asymmetric: rewriting `Cancelled` is deliberate, and
    /// rewriting anything else would be a lie about the device.
    #[test]
    fn a_deadline_expiry_is_a_timeout_and_nothing_else_is_rewritten() {
        assert_eq!(deadline_status(XferStatus::Cancelled), XferStatus::Timeout);
        for status in [
            XferStatus::Ok,
            XferStatus::Stall,
            XferStatus::Timeout,
            XferStatus::NoDevice,
            XferStatus::Error,
        ] {
            assert_eq!(
                deadline_status(status),
                status,
                "{status:?} is not ours to reinterpret"
            );
        }
    }

    /// What a pad result looks like after the reshape — every branch the SETUP
    /// stage acts on, plus the unreaped sentinel that must survive untouched.
    #[test]
    fn a_pad_result_keeps_the_device_answer_and_loses_the_abort_window() {
        let pad = CtrlReq::new(0x00, 0x00, 0, 0, 1280);

        // NAKed until the deadline: the host gave up, so it is a TIMEOUT — and it
        // must not carry a window, or the tracer buckets it as a sweep attempt.
        let cut = submitted_result(
            1,
            pad,
            XferStatus::Cancelled,
            0,
            5_337,
            sys::constants::LIBUSB_TRANSFER_CANCELLED,
            5,
        );
        let r = deadline_result(cut);
        assert_eq!(r.status, XferStatus::Timeout);
        assert_eq!(r.abort_after_ms, None, "a timeout is not an abort window");
        assert_eq!(r.micros, 5_337, "the measured wall time survives");
        assert_eq!(
            r.libusb_rc,
            sys::constants::LIBUSB_TRANSFER_CANCELLED,
            "libusb's own word survives, so a cut is still visible as a cut"
        );
        assert_eq!(r.requested, 1280);
        assert!(!r.unreaped() && !r.timing_refuted());

        // The device refused before the deadline: the pass condition, unchanged.
        let r = deadline_result(submitted_result(
            2,
            pad,
            XferStatus::Stall,
            0,
            2_100,
            sys::constants::LIBUSB_TRANSFER_STALL,
            5,
        ));
        assert_eq!(r.status, XferStatus::Stall);
        assert!(r.stalled(), "the pass condition must survive the reshape");
        assert_eq!(r.abort_after_ms, None);

        // The device accepted the 1280 bytes: `pad_ok`, with its count.
        let r = deadline_result(submitted_result(
            3,
            pad,
            XferStatus::Ok,
            1280,
            24_000,
            sys::constants::LIBUSB_TRANSFER_COMPLETED,
            5,
        ));
        assert!(r.ok());
        assert_eq!(r.transferred, 1280, "pad_ok must stay distinguishable");

        // Unreaped is passed through untouched: `unreaped()` is how a poisoned
        // handle is recognised, and the sentinel pair needs the window.
        let lost = submitted_result(
            4,
            pad,
            XferStatus::Error,
            0,
            2_004_000,
            LIBUSB_ERROR_OTHER,
            5,
        );
        assert!(lost.unreaped());
        let passed = deadline_result(lost);
        assert!(passed.unreaped(), "the poison sentinel must survive");
        assert_eq!(passed.abort_after_ms, Some(5));
    }

    /// **The counters that consume the status.** A pad shaped by `deadline_result`
    /// must still be counted as a pad request, and a timed-out pad must still land
    /// in `setup_pad_timeouts` — the field `verdict::PAD_TIMEOUT_NOT_STALL` reads.
    /// A sweep DNLOAD must still be counted as an attempt with its window.
    ///
    /// This is the trap the change was shaped around: had the pad kept an
    /// `abort_after_ms`, `Tracer::account_setup` would have bucketed it as an
    /// attempt and both pad counters would have gone to zero in silence.
    #[test]
    fn pad_and_sweep_results_land_in_the_counters_they_always_did() {
        use crate::trace::Tracer;
        use crate::types::Stage;

        let mut tracer = Tracer::new(None, false).expect("no trace file requested");
        let pad = CtrlReq::new(0x00, 0x00, 0, 0, 1280);

        // A pad that NAKed until its 5 ms deadline.
        let timed_out = deadline_result(submitted_result(
            1,
            pad,
            XferStatus::Cancelled,
            0,
            5_337,
            sys::constants::LIBUSB_TRANSFER_CANCELLED,
            5,
        ));
        tracer.xfer(Stage::Setup, "setup_pad_request", &timed_out);

        // A pad the device refused within the deadline — the pass condition.
        let stalled = deadline_result(submitted_result(
            2,
            pad,
            XferStatus::Stall,
            0,
            2_100,
            sys::constants::LIBUSB_TRANSFER_STALL,
            5,
        ));
        tracer.xfer(Stage::Setup, "setup_pad_request", &stalled);

        // A sweep DNLOAD, the shape that must keep its window.
        let sweep = submitted_result(
            3,
            req(),
            XferStatus::Cancelled,
            0,
            4_337,
            sys::constants::LIBUSB_TRANSFER_CANCELLED,
            4,
        );
        tracer.xfer(Stage::Setup, "setup_abort_dnload", &sweep);

        let c = tracer.counters();
        assert_eq!(c.setup_pad_requests, 2, "both pads are pad requests");
        assert_eq!(
            c.setup_pad_timeouts, 1,
            "the deadline expiry is a pad TIMEOUT, which is what PAD_TIMEOUT_NOT_STALL reads"
        );
        assert_eq!(c.setup_stall_seen, 1, "and a STALL is still the pass condition");
        assert_eq!(
            c.setup_attempts, 1,
            "only the DNLOAD is a sweep attempt — the pad must not be bucketed as one"
        );
        assert_eq!(c.setup_async_unreported, 0, "the DNLOAD reports its window");
        assert_eq!(c.abort_sweep, vec![4], "and the window reaches the sweep");
    }

    /// The no-data data stage is `w_len` **zero** bytes, not a null pointer with a
    /// non-zero length: one function, so every no-data path sends the same bytes.
    #[test]
    fn a_no_data_stage_is_zero_filled_and_the_right_length() {
        assert!(zero_data_stage(0).is_empty());
        let zeros = zero_data_stage(1280);
        assert_eq!(zeros.len(), 1280, "the pad's wLength, exactly");
        assert!(zeros.iter().all(|b| *b == 0), "the pad's payload is zeros");
        assert_eq!(zero_data_stage(0x800).len(), 0x800, "and the sweep's DNLOAD");
    }

    // ---- the DFU Functional Descriptor -------------------------------------

    /// The wire parameters, pinned without a device: `bmRequestType = 0x81`,
    /// `bRequest = 6`, `wValue = 0x2100`, `wIndex = 0`, `wLength = 9`. A wrong
    /// `wValue` would read the wrong descriptor and still look successful, so this
    /// is asserted rather than trusted.
    #[test]
    fn the_functional_descriptor_request_is_the_specified_one() {
        let r = dfu_functional_descriptor_request();
        assert_eq!(r.bm, 0x81, "device-to-host, standard, device recipient");
        assert_eq!(r.b, 0x06, "GET_DESCRIPTOR");
        assert_eq!(r.value, 0x2100, "descriptor type 0x21 in the high byte");
        assert_eq!(r.index, 0);
        assert_eq!(r.length, 9);
        assert_eq!(r.length, DfuFunctionalDescriptor::LEN);
        assert!(r.is_in(), "a descriptor read is device-to-host");
    }

    /// The decode, little-endian, field by field — including the case this probe
    /// exists for: a declared size below gaster's 0x800.
    #[test]
    fn the_functional_descriptor_decodes_little_endian() {
        // bmAttributes 0x0B, wDetachTimeOut 100, wTransferSize 0x0800, bcdDFU 0x0110.
        let bytes = [0x0B, 0x64, 0x00, 0x00, 0x08, 0x10, 0x01, 0x00, 0x00];
        let d = DfuFunctionalDescriptor::decode(&bytes).expect("nine bytes");
        assert_eq!(d.bm_attributes, 0x0B);
        assert_eq!(d.detach_timeout_ms, 100);
        assert_eq!(d.transfer_size, 0x0800);
        assert_eq!(d.bcd_dfu_version, 0x0110);
        assert_eq!(d.raw, bytes, "the raw bytes are kept, not re-rendered");
        assert_eq!(d.caps_gaster_transfer_size(), Some(false), "0x800 == gaster's constant");

        // A unit that declares less than gaster's constant: the finding that would
        // make the SETUP abort's length wrong for this device.
        let small = [0x0B, 0x64, 0x00, 0x00, 0x02, 0x10, 0x01, 0x00, 0x00];
        let small_d = DfuFunctionalDescriptor::decode(&small).expect("nine bytes");
        assert_eq!(small_d.transfer_size, 0x0200);
        assert_eq!(small_d.caps_gaster_transfer_size(), Some(true), "0x200 < 0x800");

        // Zero means "no declared cap"; this crate does not invent one.
        let zero = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            DfuFunctionalDescriptor::decode(&zero)
                .expect("nine bytes")
                .caps_gaster_transfer_size(),
            None
        );

        // The two unused trailing bytes do not reach the fields, but they are kept.
        let mut altered = bytes;
        altered[7] = 0xAA;
        altered[8] = 0xBB;
        let d2 = DfuFunctionalDescriptor::decode(&altered).expect("nine bytes");
        assert_eq!(d2.transfer_size, d.transfer_size);
        assert_eq!(d2.bm_attributes, d.bm_attributes);
        assert_ne!(d2.raw, d.raw, "…and a difference in them is still visible");
    }

    // ---- the EP0 rate line ------------------------------------------------

    /// **The model is pinned to the measurements it was fitted from.** Every
    /// recorded latency is fed back through `packets_in` and must come back within
    /// `spread_packets` of the packet count it really moved — so a mistyped
    /// constant, or a "tidied" one, fails here rather than silently re-centring the
    /// sweep.
    #[test]
    fn the_rate_line_round_trips_its_own_measurements() {
        let line = Ep0RateLine::A9_SECUREROM_DFU;
        let spread = line.spread_packets as i64;
        assert!(spread > 0, "a model with no stated error is not a model");

        // The clusters the line IS fitted through — 1 packet and 32 packets — must
        // sit inside the stated spread. A mistyped constant fails here.
        let fitted: [(u64, i64); 6] = [
            (3_440, 1),
            (3_920, 1),
            (3_463, 1),
            (34_897, 32),
            (35_027, 32),
            (37_912, 32),
        ];
        for (micros, packets) in fitted {
            let got = line.packets_in(Duration::from_micros(micros)) as i64;
            assert!(
                (got - packets).abs() <= spread,
                "the fitted clusters must sit inside the stated spread: {micros} us -> {got}, \
                 expected {packets} +/- {spread}"
            );
        }

        // The pad cluster is deliberately **not** fitted and its numbers are not a
        // tolerance: it is the measurement that justifies the exclusion. Same packet
        // count (20), nine answers, and it scatters far wider than the DNLOAD
        // completions — because a request the ROM has no handler for pays for its
        // refusal path on top of the data.
        let dnload = [34_897u64, 35_027, 37_912];
        let pad = [
            21_400u64, 22_900, 24_500, 24_500, 25_300, 27_900, 21_500, 36_600, 23_020,
        ];
        let dnload_spread = dnload.iter().max().unwrap() - dnload.iter().min().unwrap();
        let pad_spread = pad.iter().max().unwrap() - pad.iter().min().unwrap();
        assert!(
            pad_spread > dnload_spread,
            "the pad cluster must be the noisier one: {pad_spread} us vs {dnload_spread} us"
        );
        assert!(
            pad_spread > 10_000,
            "…and noisier by more than a tick, or it would not need excluding: {pad_spread} us"
        );
        // …and the pad's own best case is *faster* than the DNLOAD line predicts at
        // 20 packets, which is the same fact from the other side: two different
        // paths, so one line cannot describe both.
        assert!(
            pad.iter().min().unwrap() < &line.elapsed_for_packets(20).as_micros().try_into().unwrap(),
            "the pad's fastest answer should beat the DNLOAD line at 20 packets"
        );
    }

    /// The quantum: byte counts are whole packets, and the sweep therefore steps in
    /// packets. `p_error` is expressed in the same unit for the same reason.
    #[test]
    fn derived_byte_counts_are_whole_packets() {
        let line = Ep0RateLine::A9_SECUREROM_DFU;
        assert_eq!(Ep0RateLine::PACKET_BYTES, 64, "EP0's max packet, as gaster uses it");

        for packets in 0..40u32 {
            let elapsed = line.elapsed_for_packets(packets);
            assert_eq!(
                line.packets_in(elapsed),
                packets,
                "{packets} packets must round-trip through the elapsed time"
            );
            assert_eq!(line.bytes_in(elapsed), packets * 64);
            assert_eq!(line.bytes_in(elapsed) % 64, 0, "never a fractional packet");
        }

        // Quantisation is a step function, and it never invents a packet: the
        // startup is dead time by construction.
        assert_eq!(line.packets_in(Duration::ZERO), 0);
        assert_eq!(line.packets_in(Duration::from_micros(line.startup_us)), 0);
        assert_eq!(
            line.packets_in(Duration::from_micros(line.startup_us + line.packet_us - 1)),
            0,
            "one microsecond short of a whole packet is no packet"
        );
        assert_eq!(
            line.packets_in(Duration::from_micros(line.startup_us + line.packet_us)),
            1
        );

        // A designed window is the elapsed time minus the caller's own measured
        // cancel-and-reap cost, and it saturates rather than going negative.
        let overhead = Duration::from_micros(340);
        assert_eq!(
            line.window_for_packets(0, overhead),
            line.elapsed_for_packets(0).saturating_sub(overhead)
        );
        assert_eq!(
            line.window_for_packets(4, Duration::from_secs(1)),
            Duration::ZERO,
            "a target the overhead swallows becomes zero, not a negative deadline"
        );
        // The set gaster's windows can actually reach on this device — the finding
        // this model exists to make visible. With the fitted startup (2.57 ms) the
        // 0-5 ms range reaches only 0, 1 and 2 packets: **four of gaster's six
        // windows are the same experiment**, and the sweep's three distinct cut
        // positions here are the reference's six. That is the number that says a
        // *byte-count* sweep is the faithful one on this host.
        let reachable: Vec<u32> = [0u32, 1, 2, 3, 4, 5]
            .iter()
            .map(|ms| line.packets_in(abort_window(*ms) + overhead))
            .collect();
        assert_eq!(
            reachable,
            vec![0, 0, 0, 0, 1, 2],
            "gaster's six windows collapse to three distinct packet counts here"
        );
        let distinct: std::collections::BTreeSet<u32> = reachable.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            3,
            "three distinct cut positions, not six — measured, not assumed"
        );
    }

    /// A failed read must never become a finding. Every length that is not nine
    /// bytes is refused, with the two numbers in the message.
    #[test]
    fn a_partial_functional_descriptor_is_refused_not_zero_filled() {
        for bad in [
            &[][..],
            &[0x0B][..],
            &[0x0B, 0x64, 0x00, 0x00, 0x08, 0x10, 0x01, 0x00][..], // 8: one short
            &[0x0B, 0x64, 0x00, 0x00, 0x08, 0x10, 0x01, 0x00, 0x00, 0x00][..], // 10
        ] {
            let e = DfuFunctionalDescriptor::decode(bad).unwrap_err();
            assert!(e.contains("is 9 bytes"), "{e}");
            assert!(e.contains(&format!("got {}", bad.len())), "{e}");
            assert!(
                e.contains("refusing to decode a partial descriptor"),
                "the refusal must say why: {e}"
            );
        }
    }

    // ==== the Linux host path: sysfs driver + reset capability ==============
    //
    // None of these tests touches a device or the real /sys. Each builds a
    // fixture tree in a fresh temp directory, removes it on drop, and drives the
    // pure functions directly. The fixture shape is the one MEASURED on this
    // host 2026-10-03 — `/sys/bus/usb/devices/1-4` = 05AC:1227 with
    // `1-4:1.0` unbound (no `driver` link, class FE/01/00) and a device-level
    // link to `apple-mfi-fastcharge` — with no device-unique data in it.
    //
    // WHY EVERY PREDICATE BELOW HAS A FAILING CASE: this project has produced
    // five confident-wrong answers from checks that were only ever shown to
    // pass. A "no driver link means usbfs" rule that also fires on an absent
    // root, a wrong device or a dangling link would read exactly like the
    // correct measurement on the one machine that matters, so each of those is
    // a test here.

    #[cfg(unix)]
    struct Fixture {
        root: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl Fixture {
        fn new(name: &str) -> Fixture {
            let root =
                std::env::temp_dir().join(format!("a9pwn-sysfs-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("bus/usb/devices")).expect("fixture devices dir");
            std::fs::create_dir_all(root.join("bus/usb/drivers")).expect("fixture drivers dir");
            Fixture { root }
        }

        fn root(&self) -> &std::path::Path {
            &self.root
        }

        fn write(&self, rel: &str, contents: &str) {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("fixture parent");
            }
            std::fs::write(&path, contents).expect("fixture write");
        }

        fn mkdir(&self, rel: &str) {
            std::fs::create_dir_all(self.root.join(rel)).expect("fixture mkdir");
        }

        /// A driver link exactly as sysfs presents it: a symlink into
        /// `<root>/bus/usb/drivers/<name>`, so the "is this a USB interface
        /// driver?" check has something real to resolve.
        fn driver_link(&self, from_rel: &str, name: &str) {
            self.mkdir(&format!("bus/usb/drivers/{name}"));
            let link = self.root.join(from_rel);
            if let Some(parent) = link.parent() {
                std::fs::create_dir_all(parent).expect("fixture link parent");
            }
            std::os::unix::fs::symlink(self.root.join(format!("bus/usb/drivers/{name}")), &link)
                .expect("fixture driver symlink");
        }

        /// One USB device node with interface 0, shaped like real sysfs.
        fn device(
            &self,
            name: &str,
            vid: &str,
            pid: &str,
            bus: u8,
            address: u8,
            interface0_driver: Option<&str>,
            device_driver: Option<&str>,
        ) {
            let dev = format!("bus/usb/devices/{name}");
            self.mkdir(&dev);
            self.write(&format!("{dev}/idVendor"), &format!("{vid}\n"));
            self.write(&format!("{dev}/idProduct"), &format!("{pid}\n"));
            self.write(&format!("{dev}/busnum"), &format!("{bus}\n"));
            self.write(&format!("{dev}/devnum"), &format!("{address}\n"));
            self.write(&format!("{dev}/bConfigurationValue"), "1\n");
            let iface = format!("{dev}/{name}:1.0");
            self.mkdir(&iface);
            self.write(&format!("{iface}/bInterfaceNumber"), "00\n");
            if let Some(d) = device_driver {
                self.driver_link(&format!("{dev}/driver"), d);
            }
            if let Some(d) = interface0_driver {
                self.driver_link(&format!("{iface}/driver"), d);
            }
        }

        /// The unbound-interface device this task exists for: 05AC:1227 at bus
        /// 1 address 7, interface 0 with no `driver` link, a device-level
        /// driver as context.
        fn dfu_device(&self) {
            self.device("1-4", "05ac", "1227", 1, 7, None, Some("apple-mfi-fastcharge"));
        }
    }

    #[cfg(unix)]
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// The single device node a one-device fixture holds.
    #[cfg(unix)]
    fn only_node(root: &std::path::Path) -> SysfsUsbNode {
        let scan = scan_sysfs_usb_devices(root).expect("scan must succeed");
        assert_eq!(scan.nodes.len(), 1, "fixture should hold one device node");
        assert!(scan.skipped.is_empty(), "nothing should be skipped: {:?}", scan.skipped);
        scan.nodes.into_iter().next().unwrap()
    }

    /// A device offering two interface-0 directories (two configurations), with
    /// an optional active `bConfigurationValue`.
    #[cfg(unix)]
    fn two_config_device(f: &Fixture, active: Option<&str>) {
        let dev = "bus/usb/devices/1-4";
        f.mkdir(dev);
        f.write(&format!("{dev}/idVendor"), "05ac\n");
        f.write(&format!("{dev}/idProduct"), "1227\n");
        f.write(&format!("{dev}/busnum"), "1\n");
        f.write(&format!("{dev}/devnum"), "7\n");
        if let Some(a) = active {
            f.write(&format!("{dev}/bConfigurationValue"), &format!("{a}\n"));
        }
        for cfg in [1u8, 2u8] {
            let iface = format!("{dev}/1-4:{cfg}.0");
            f.mkdir(&iface);
            f.write(&format!("{iface}/bInterfaceNumber"), "00\n");
        }
    }

    /// The device node is found by the **same key libusb uses** — sysfs
    /// `busnum`/`devnum`, which libusb reads into `bus_number` /
    /// `device_address` (`linux_usbfs.c:624-636`, `:919-920`) — never by
    /// enumeration order, name, or "the first Apple-looking node". Ambiguity is
    /// refused, not resolved by taking the first match.
    #[test]
    #[cfg(unix)]
    fn sysfs_lookup_is_keyed_by_bus_devnum_not_position() {
        let f = Fixture::new("lookup");
        // Deliberately out of order: another vendor's node listed first, and
        // an Apple-PID node on a different address.
        f.device("1-10", "8087", "0026", 1, 2, Some("btusb"), Some("usb"));
        f.device("1-9", "05ac", "1227", 1, 9, None, None);
        f.device("1-4", "05ac", "1227", 1, 7, None, Some("apple-mfi-fastcharge"));

        let m = measure_sysfs_driver(f.root(), 1, 7).expect("the target node must be found");
        assert_eq!(m.device.name, "1-4", "found by bus/address, not by order");
        assert_eq!((m.device.bus, m.device.address), (1, 7));
        assert_eq!((m.device.id_vendor, m.device.id_product), (APPLE_VID, DFU_MODE_PID));
        assert_eq!(m.interface0.dir, "1-4:1.0");
        assert_eq!(m.interface0.driver, None, "no driver link is a measurement");
        assert_eq!(m.service, "usbfs");
        assert_eq!(m.device_driver, Ok(Some("apple-mfi-fastcharge".to_string())));

        // The *other* 05AC:1227 device is measured too, and is not confused
        // with ours.
        let other = measure_sysfs_driver(f.root(), 1, 9).expect("the second target node");
        assert_eq!(other.device.name, "1-9");
        assert_eq!(other.interface0.dir, "1-9:1.0");

        // Wrong bus/address: a failed measurement with a reason, never the
        // nearest node.
        let e = measure_sysfs_driver(f.root(), 2, 7).unwrap_err();
        assert!(e.contains("no sysfs device node"), "{e}");
        assert!(e.contains("busnum 2 devnum 7"), "{e}");

        // Two nodes claiming one bus/address cannot be told apart: refuse
        // rather than take the first.
        let dup = Fixture::new("dupaddr");
        dup.device("1-4", "05ac", "1227", 1, 7, None, None);
        dup.device("1-9", "05ac", "1227", 1, 7, None, None);
        let e = measure_sysfs_driver(dup.root(), 1, 7).unwrap_err();
        assert!(e.contains("refusing to pick one"), "{e}");
        assert!(e.contains("1-4") && e.contains("1-9"), "{e}");
    }

    /// **The measurement this task exists for.** Interface 0 with no `driver`
    /// link is `usbfs` — a real answer — and with interface 0 claimed the
    /// capability is `Real`, with the evidence naming the two measurements and
    /// the one source inspection that produced it.
    #[test]
    #[cfg(unix)]
    fn sysfs_no_driver_link_reports_usbfs_and_real_with_its_evidence() {
        let f = Fixture::new("nolnk");
        f.dfu_device();

        let reading = linux_driver_reading(measure_sysfs_driver(f.root(), 1, 7), true);
        assert_eq!(
            reading.service, "usbfs",
            "no kernel driver bound is the usbfs path — never empty, never unknown"
        );
        assert_eq!(reading.capability, ResetCapability::Real);
        assert!(
            reading.note.contains("NO driver link on interface 0"),
            "the note must name the measurement: {}",
            reading.note
        );
        assert!(reading.note.contains("1-4:1.0"), "{}", reading.note);
        assert!(
            reading.note.contains("apple-mfi-fastcharge"),
            "the device-level link is measured as context: {}",
            reading.note
        );
        assert!(reading.capability_note.contains("REAL"), "{}", reading.capability_note);
        assert!(
            reading.capability_note.contains("USBDEVFS_RESET"),
            "Real must cite the mechanism that makes it real: {}",
            reading.capability_note
        );
        assert!(
            reading.capability_note.contains("claimed at open"),
            "Real must name the claim evidence: {}",
            reading.capability_note
        );
        assert!(
            reading.capability_note.contains("NOT /sys"),
            "a fixture root must never masquerade as /sys: {}",
            reading.capability_note
        );
        // The exact string `main.rs:179` prints, through the classifier
        // `open_this` actually uses on Linux. "other" would be a class that
        // names nothing; "unknown" is the defect this task removes.
        assert_eq!(linux_driver_class(&reading).as_str(), "usbfs");
        assert_eq!(DriverClass::from_service(&reading.service).as_str(), "usbfs");
        // And Real's sentence labels its cited source INSPECTED, never as a
        // fourth measurement (LINUX-HANDOFF rule 3).
        assert!(
            reading.capability_note.contains("INSPECTED"),
            "{}",
            reading.capability_note
        );
        assert!(
            !reading.capability_note.contains("from three measurements"),
            "{}",
            reading.capability_note
        );
    }

    /// A `usbfs` driver link is the same answer by the other route: a userspace
    /// claim is visible on interface 0, and it is still the Real path.
    #[test]
    #[cfg(unix)]
    fn sysfs_usbfs_driver_link_is_reported_as_usbfs() {
        let f = Fixture::new("usbfslnk");
        f.device("1-4", "05ac", "1227", 1, 7, Some("usbfs"), None);

        let m = measure_sysfs_driver(f.root(), 1, 7).expect("measured");
        assert_eq!(m.interface0.driver.as_deref(), Some("usbfs"));
        assert_eq!(m.service, "usbfs");
        assert!(m.note.contains("userspace claim"), "{}", m.note);

        let reading = linux_driver_reading(Ok(m), true);
        assert_eq!(reading.capability, ResetCapability::Real);
        assert!(reading.capability_note.contains("REAL"), "{}", reading.capability_note);
    }

    /// A real kernel driver holding interface 0 is *not* our path: libusb
    /// cannot claim it, so the capability must not be `Real` however healthy
    /// the device looks.
    #[test]
    #[cfg(unix)]
    fn sysfs_kernel_driver_on_interface_zero_is_never_real() {
        let f = Fixture::new("usbhid");
        f.device("1-4", "05ac", "1227", 1, 7, Some("usbhid"), None);

        let reading = linux_driver_reading(measure_sysfs_driver(f.root(), 1, 7), true);
        assert_eq!(reading.service, "usbhid", "the driver is reported by its measured name");
        assert_eq!(reading.capability, ResetCapability::Unknown);
        assert_ne!(reading.capability, ResetCapability::Real);
        assert!(reading.capability_note.contains("usbhid"), "{}", reading.capability_note);
        assert!(reading.capability_note.contains("UNKNOWN"), "{}", reading.capability_note);
        assert!(
            !reading.capability_note.contains("REAL"),
            "a claimed interface held by a kernel driver must not read as Real: {}",
            reading.capability_note
        );
    }

    /// The negative control for the whole rule: an absent root — and a second
    /// failure, a *file* where the device tree should be — is `Unknown` **with
    /// the reason**, never a guess in either direction. A real EACCES on an
    /// attribute is a third failure and has its own test,
    /// `sysfs_unreadable_attributes_are_not_reported_as_absent`; before that
    /// test existed, a mutation folding "cannot read" into "not there" left the
    /// whole suite green.
    #[test]
    #[cfg(unix)]
    fn sysfs_absent_or_not_a_directory_root_is_unknown_with_the_reason() {
        let f = Fixture::new("badroot");
        let missing = f.root().join("no-such-tree");
        let e_missing = measure_sysfs_driver(&missing, 1, 7).unwrap_err();
        assert!(e_missing.contains("could not be listed"), "{e_missing}");
        assert!(e_missing.contains("UNKNOWN, not absent"), "{e_missing}");

        // A *different* failure — the tree exists but is not a directory — must
        // not produce the same sentence. Four problems, four messages.
        let f2 = Fixture::new("fileroot");
        std::fs::remove_dir_all(f2.root().join("bus/usb/devices")).unwrap();
        std::fs::write(f2.root().join("bus/usb/devices"), "not a directory").unwrap();
        let e_file = measure_sysfs_driver(f2.root(), 1, 7).unwrap_err();
        assert!(e_file.contains("could not be listed"), "{e_file}");
        assert_ne!(e_missing, e_file, "two different failures, two different messages");

        for reason in [e_missing, e_file] {
            let reading = linux_driver_reading(Err(reason.clone()), true);
            assert_eq!(reading.service, "", "a failed measurement measures no service");
            assert_eq!(DriverClass::from_service(&reading.service), DriverClass::Unknown);
            assert_eq!(reading.capability, ResetCapability::Unknown);
            assert!(
                reading.capability_note.contains(&reason),
                "the reason must travel verbatim: {}",
                reading.capability_note
            );
            assert!(!reading.capability_note.contains("REAL"), "{}", reading.capability_note);
            assert!(reading.note.contains("failed measurement"), "{}", reading.note);
            assert_ne!(reading.service, "usbfs", "no guess, in either direction");
        }
    }

    /// A node at the right bus/address but with the wrong USB IDs is a
    /// *different device* — addresses are recycled, the IDs are the device.
    #[test]
    #[cfg(unix)]
    fn sysfs_wrong_device_at_our_address_is_refused() {
        for (vid, pid) in [("046d", "c52b"), ("05ac", "1338"), ("0000", "0000")] {
            let f = Fixture::new(&format!("wrong-{vid}-{pid}"));
            f.device("1-4", vid, pid, 1, 7, None, None);

            let e = measure_sysfs_driver(f.root(), 1, 7).unwrap_err();
            assert!(
                e.contains("refusing to attribute another device's driver"),
                "{e}"
            );
            assert!(e.contains(&format!("{vid}:{pid}").to_uppercase()), "{e}");

            let reading = linux_driver_reading(Err(e), true);
            assert_eq!(reading.service, "");
            assert_eq!(reading.capability, ResetCapability::Unknown);
            assert_ne!(reading.capability, ResetCapability::Real);
        }
    }

    /// A driver link that is not a USB interface driver — or that is dangling —
    /// is refused. This is the "non-USB or wrong-device node" control: a PCI
    /// driver name must never become this device's `driver service`.
    #[test]
    #[cfg(unix)]
    fn sysfs_non_usb_or_dangling_driver_link_is_refused() {
        let f = Fixture::new("nondriver");
        f.device("1-4", "05ac", "1227", 1, 7, None, None);
        f.mkdir("bus/pci/drivers/fake-pci");
        std::os::unix::fs::symlink(
            f.root().join("bus/pci/drivers/fake-pci"),
            f.root().join("bus/usb/devices/1-4/1-4:1.0/driver"),
        )
        .unwrap();
        let e_non_usb = measure_sysfs_driver(f.root(), 1, 7).unwrap_err();
        assert!(e_non_usb.contains("not a USB interface driver"), "{e_non_usb}");

        let f2 = Fixture::new("dangling");
        f2.device("1-4", "05ac", "1227", 1, 7, None, None);
        std::os::unix::fs::symlink(
            f2.root().join("bus/usb/drivers/vanished"),
            f2.root().join("bus/usb/devices/1-4/1-4:1.0/driver"),
        )
        .unwrap();
        let e_dangling = measure_sysfs_driver(f2.root(), 1, 7).unwrap_err();
        assert!(e_dangling.contains("could not be resolved"), "{e_dangling}");
        assert!(e_dangling.contains("dangling driver link"), "{e_dangling}");
        assert_ne!(e_non_usb, e_dangling, "four problems, four messages");

        // A regular file named `driver` is not a driver binding either: sysfs
        // creates a symlink or nothing at all.
        let f3 = Fixture::new("filelink");
        f3.device("1-4", "05ac", "1227", 1, 7, None, None);
        f3.write("bus/usb/devices/1-4/1-4:1.0/driver", "usbfs\n");
        let e_file = measure_sysfs_driver(f3.root(), 1, 7).unwrap_err();
        assert!(e_file.contains("not a symlink"), "{e_file}");

        // None of the three may be read as "no kernel driver bound".
        for e in [e_non_usb, e_dangling, e_file] {
            let reading = linux_driver_reading(Err(e), true);
            assert_ne!(reading.service, "usbfs");
            assert_eq!(reading.service, "");
            assert_eq!(reading.capability, ResetCapability::Unknown);
        }
    }

    /// No interface-0 directory is *not* "no kernel driver bound": only one of
    /// those was measured, and it is the unhelpful one.
    #[test]
    #[cfg(unix)]
    fn sysfs_missing_interface_zero_is_not_no_kernel_driver() {
        let f = Fixture::new("noiface");
        let dev = "bus/usb/devices/1-4";
        f.mkdir(dev);
        f.write(&format!("{dev}/idVendor"), "05ac\n");
        f.write(&format!("{dev}/idProduct"), "1227\n");
        f.write(&format!("{dev}/busnum"), "1\n");
        f.write(&format!("{dev}/devnum"), "7\n");

        let e = measure_sysfs_driver(f.root(), 1, 7).unwrap_err();
        assert!(e.contains("no interface 0 directory"), "{e}");
        assert!(
            e.contains("refusing to report 'no kernel driver bound'"),
            "the refusal must say what it refuses to conclude: {e}"
        );

        let reading = linux_driver_reading(Err(e), true);
        assert_eq!(reading.service, "");
        assert_eq!(reading.capability, ResetCapability::Unknown);
    }

    /// Interface-0 selection, whole domain: which directory is interface 0 is
    /// decided by `bInterfaceNumber` and, when several configurations offer
    /// one, by the active configuration — and never by picking the first.
    #[test]
    #[cfg(unix)]
    fn sysfs_interface_zero_selection_pins_the_whole_domain() {
        // (a) one configuration, one interface 0.
        let a = Fixture::new("iface-a");
        a.dfu_device();
        assert_eq!(
            resolve_interface0(a.root(), &only_node(a.root())).unwrap().dir,
            "1-4:1.0"
        );

        // (b) two configurations offer interface 0; the active one decides.
        let b = Fixture::new("iface-b");
        two_config_device(&b, Some("2"));
        assert_eq!(
            resolve_interface0(b.root(), &only_node(b.root())).unwrap().dir,
            "1-4:2.0"
        );
        let b1 = Fixture::new("iface-b1");
        two_config_device(&b1, Some("1"));
        assert_eq!(
            resolve_interface0(b1.root(), &only_node(b1.root())).unwrap().dir,
            "1-4:1.0"
        );

        // (c) two candidates and no active configuration: refuse, do not pick.
        let c = Fixture::new("iface-c");
        two_config_device(&c, None);
        let e_c = resolve_interface0(c.root(), &only_node(c.root())).unwrap_err();
        assert!(e_c.contains("refusing to pick one"), "{e_c}");
        assert!(e_c.contains("no readable bConfigurationValue"), "{e_c}");

        // (d) the active configuration names neither candidate.
        let d = Fixture::new("iface-d");
        two_config_device(&d, Some("3"));
        let e_d = resolve_interface0(d.root(), &only_node(d.root())).unwrap_err();
        assert!(e_d.contains("names none of them"), "{e_d}");
        assert_ne!(e_c, e_d, "four problems, four messages");

        // (e) only interface 1 exists: no interface 0 was found, and the count
        // says so rather than reporting zero interface directories.
        let e = Fixture::new("iface-e");
        let dev = "bus/usb/devices/1-4";
        e.mkdir(dev);
        e.write(&format!("{dev}/idVendor"), "05ac\n");
        e.write(&format!("{dev}/idProduct"), "1227\n");
        e.write(&format!("{dev}/busnum"), "1\n");
        e.write(&format!("{dev}/devnum"), "7\n");
        e.mkdir(&format!("{dev}/1-4:1.1"));
        e.write(&format!("{dev}/1-4:1.1/bInterfaceNumber"), "01\n");
        let err_e = resolve_interface0(e.root(), &only_node(e.root())).unwrap_err();
        assert!(err_e.contains("no interface 0 directory"), "{err_e}");
        assert!(err_e.contains("1 interface directory"), "{err_e}");

        // (f) a directory NAMED `:1.0` whose bInterfaceNumber says 1 is not
        //     interface 0: the name is confirmed, never trusted.
        let g = Fixture::new("iface-lying");
        g.dfu_device();
        g.write("bus/usb/devices/1-4/1-4:1.0/bInterfaceNumber", "01\n");
        let err_g = resolve_interface0(g.root(), &only_node(g.root())).unwrap_err();
        assert!(err_g.contains("no interface 0 directory"), "{err_g}");
    }

    /// Attribute parsing, whole domain: sysfs's exact formats accepted, every
    /// near-miss refused. A misread `idVendor` is how the wrong device gets
    /// credited with our driver.
    #[test]
    #[cfg(unix)]
    fn sysfs_attribute_parsing_pins_the_whole_domain() {
        for (text, want) in [
            ("05ac", 0x05ACu16),
            ("1227", 0x1227),
            ("0000", 0x0000),
            ("FFFF", 0xFFFF),
            ("0a0b", 0x0A0B),
        ] {
            assert_eq!(parse_hex16("idVendor", text).unwrap(), want, "{text}");
        }
        for bad in ["", "5ac", "05ac0", "0x05ac", "zzzz", "05 c", "05AC ", "０５ａｃ"] {
            let e = parse_hex16("idVendor", bad).unwrap_err();
            assert!(e.contains("not the four hex digits"), "{bad}: {e}");
        }

        for (text, want) in [("1", 1u8), ("007", 7), ("255", 255), ("0", 0)] {
            assert_eq!(parse_dec_u8("busnum", text).unwrap(), want, "{text}");
        }
        for bad in ["", "256", "-1", "1x", "1 ", "0x1", "999999999999999999999"] {
            let e = parse_dec_u8("devnum", bad).unwrap_err();
            assert!(
                e.contains("not the decimal number") || e.contains("not a byte value"),
                "{bad}: {e}"
            );
        }
    }

    /// The capability table, pinned for every cell — the §9.3 lesson: a test
    /// that checks a sample ratifies the cells it did not look at.
    #[test]
    #[cfg(unix)]
    fn linux_capability_pins_the_whole_domain() {
        // (what, service the fixture measures or the reason it fails, claimed,
        // expected capability) — every outcome with BOTH claim states, so no
        // cell of the domain is untested.
        #[allow(clippy::type_complexity)]
        let cases: [(&str, Result<&str, &str>, bool, ResetCapability); 10] = [
            ("usbfs link, claimed", Ok("usbfs"), true, ResetCapability::Real),
            ("no driver link, claimed", Ok("none"), true, ResetCapability::Real),
            ("usbfs link, unclaimed", Ok("usbfs"), false, ResetCapability::Unknown),
            ("no driver link, unclaimed", Ok("none"), false, ResetCapability::Unknown),
            ("kernel driver, claimed", Ok("usbhid"), true, ResetCapability::Unknown),
            ("kernel driver, unclaimed", Ok("usbhid"), false, ResetCapability::Unknown),
            (
                "root absent, claimed",
                Err("the sysfs device tree '/nope' could not be listed (os error 2)"),
                true,
                ResetCapability::Unknown,
            ),
            (
                "root absent, unclaimed",
                Err("the sysfs device tree '/nope' could not be listed (os error 2)"),
                false,
                ResetCapability::Unknown,
            ),
            (
                "interface 0 missing, claimed",
                Err("sysfs has no interface 0 directory under '/nope/1-4'"),
                true,
                ResetCapability::Unknown,
            ),
            (
                "interface 0 missing, unclaimed",
                Err("sysfs has no interface 0 directory under '/nope/1-4'"),
                false,
                ResetCapability::Unknown,
            ),
        ];

        for (what, outcome, claimed, want) in cases {
            let measured = match outcome {
                Ok(kind) => {
                    let f = Fixture::new(&format!("cap-{kind}-{claimed}"));
                    let driver = match kind {
                        "usbfs" => Some("usbfs"),
                        "none" => None,
                        other => Some(other),
                    };
                    f.device("1-4", "05ac", "1227", 1, 7, driver, None);
                    measure_sysfs_driver(f.root(), 1, 7)
                }
                Err(reason) => Err(reason.to_string()),
            };
            let reading = linux_driver_reading(measured, claimed);

            assert_eq!(reading.capability, want, "{what}");
            assert!(!reading.capability_note.is_empty(), "{what}: evidence must never be blank");
            if want == ResetCapability::Real {
                assert!(claimed, "{what}: no Real cell may exist with an unclaimed interface");
                assert!(reading.capability_note.contains("REAL"), "{what}");
                assert!(reading.capability_note.contains("USBDEVFS_RESET"), "{what}");
                assert!(
                    reading.capability_note.contains("INSPECTED"),
                    "{what}: the cited backend property must be labelled INSPECTED, not \
                     measured: {}",
                    reading.capability_note
                );
                assert!(
                    reading.capability_note.contains("claimed at open"),
                    "{what}: Real must record the claim evidence: {}",
                    reading.capability_note
                );
                assert_eq!(reading.service, "usbfs", "{what}");
            } else {
                assert!(
                    reading.capability_note.contains("UNKNOWN"),
                    "{what}: an Unknown capability must say so: {}",
                    reading.capability_note
                );
                assert!(!reading.capability_note.contains("REAL"), "{what}");
            }
            if !claimed && reading.service == "usbfs" {
                assert!(
                    reading.capability_note.contains("NOT claimed"),
                    "{what}: the unclaimed path must say so: {}",
                    reading.capability_note
                );
            }
        }

        // The table must pin the WHOLE domain: every measurement outcome with
        // both claim states. A table that samples is how a green suite once
        // ratified three of eleven DFU states (HANDOFF §9.3).
        let mut domain: Vec<(String, bool)> = cases
            .iter()
            .map(|(_, outcome, claimed, _)| (format!("{outcome:?}"), *claimed))
            .collect();
        domain.sort();
        domain.dedup();
        assert_eq!(domain.len(), 10, "5 outcomes x 2 claim states: {domain:?}");
    }

    /// The Linux reset prose must never draw the Windows conclusion. The
    /// measured defect (2026-10-03) was `a9pwn reset` saying a real reset
    /// "cannot be determined from here" 237.8 ms after `USBDEVFS_RESET` had
    /// been issued. Every branch is checked, so no branch can pass by being
    /// unreachable.
    #[test]
    #[cfg(unix)]
    fn linux_reset_note_never_prints_the_windows_conclusion() {
        // The shape `linux_driver_reading` actually records for the Real case,
        // so the assertion below tests the real input, not a stub.
        let evidence = "reset capability REAL, from two measurements plus one source inspection: (a) sysfs reports no \
                        kernel driver bound to interface 0; (b) interface 0 was claimed at open; \
                        (c) libusb_reset_device maps to ioctl(USBDEVFS_RESET) \
                        (linux_usbfs.c:1596)";
        let states: [(Option<u8>, Option<u8>); 5] = [
            (Some(8), Some(2)), // the delivered transition
            (Some(8), Some(8)), // still parked: refuted
            (Some(2), Some(2)), // idle both ends
            (None, Some(2)),    // unread -> idle: the measured `a9pwn reset` case
            (None, None),       // nothing readable at all
        ];
        for capability in [
            ResetCapability::Real,
            ResetCapability::PipeCycleOnly,
            ResetCapability::Unknown,
        ] {
            for claimed in [true, false] {
                for (before, after) in states {
                    for rc in [sys::constants::LIBUSB_SUCCESS, -4] {
                        let note = reset_note_linux(
                            capability,
                            evidence,
                            claimed,
                            "usbfs",
                            rc,
                            237_818,
                            before,
                            after,
                        );
                        assert!(!note.is_empty());
                        assert!(
                            !note.contains("windows_winusb.c"),
                            "the Windows table must not speak for Linux: {note}"
                        );
                        assert!(
                            !note.contains("cannot be determined from here"),
                            "the Linux reset path IS determinable: {note}"
                        );
                        assert!(
                            note.contains("usbfs"),
                            "the measured service must appear: {note}"
                        );
                        if rc == sys::constants::LIBUSB_SUCCESS {
                            assert!(
                                note.contains("USBDEVFS_RESET"),
                                "a successful reset must name the mechanism: {note}"
                            );
                        }
                    }
                }
            }
        }

        // The named outcomes, so each branch is pinned by name and not merely
        // by "did not panic".
        let ok = sys::constants::LIBUSB_SUCCESS;
        let delivered =
            reset_note_linux(ResetCapability::Real, evidence, true, "usbfs", ok, 237_000, Some(8), Some(2));
        assert!(delivered.contains("DELIVERED"), "{delivered}");
        let refuted =
            reset_note_linux(ResetCapability::Real, evidence, true, "usbfs", ok, 237_000, Some(8), Some(8));
        assert!(refuted.contains("STILL parked"), "{refuted}");
        assert!(refuted.contains("positive evidence"), "{refuted}");
        let unread_then_idle =
            reset_note_linux(ResetCapability::Real, evidence, true, "usbfs", ok, 237_818, None, Some(2));
        assert!(unread_then_idle.contains("UNVERIFIED"), "{unread_then_idle}");
        assert!(
            unread_then_idle.contains("NOT evidence that the reset failed"),
            "unverified must not be read as failure: {unread_then_idle}"
        );
        let failed =
            reset_note_linux(ResetCapability::Real, evidence, true, "usbfs", -4, 300, Some(2), Some(2));
        assert!(failed.contains("FAILED"), "{failed}");
        assert!(failed.contains("ioctl(USBDEVFS_RESET)"), "{failed}");
        let unknown = reset_note_linux(
            ResetCapability::Unknown,
            "reset capability UNKNOWN: root absent",
            true,
            "",
            ok,
            1_000,
            Some(2),
            Some(2),
        );
        assert!(unknown.contains("(unmeasured)"), "{unknown}");
        assert!(unknown.contains("not a proven bus reset"), "{unknown}");
        // A transport that recorded no evidence must say so rather than invent
        // a mechanism.
        let no_evidence =
            reset_note_linux(ResetCapability::Real, "", true, "usbfs", ok, 237_000, Some(2), Some(2));
        assert!(
            no_evidence.contains("Capability evidence was not recorded"),
            "{no_evidence}"
        );
    }

    /// The root override rule, whole domain — including the two ways an empty
    /// override could silently measure nothing ("the empty path" and "a root
    /// with a trailing slash two names for one tree").
    #[test]
    #[cfg(unix)]
    fn sysfs_root_override_domain() {
        use std::path::Path;
        assert_eq!(sysfs_root_from(None), Path::new("/sys"));
        assert_eq!(sysfs_root_from(Some("")), Path::new("/sys"));
        assert_eq!(sysfs_root_from(Some("   ")), Path::new("/sys"));
        assert_eq!(sysfs_root_from(Some("\t\n")), Path::new("/sys"));
        assert_eq!(sysfs_root_from(Some("/tmp/a9pwn-fixture")), Path::new("/tmp/a9pwn-fixture"));
        assert_eq!(sysfs_root_from(Some("/tmp/a9pwn-fixture/")), Path::new("/tmp/a9pwn-fixture"));
        assert_eq!(sysfs_root_from(Some("/tmp/a9pwn-fixture///")), Path::new("/tmp/a9pwn-fixture"));
        assert_eq!(
            sysfs_root_from(Some("  /tmp/a9pwn-fixture  ")),
            Path::new("/tmp/a9pwn-fixture")
        );
        // "/" survives as "/": stripping the slash would make the root empty.
        assert_eq!(sysfs_root_from(Some("/")), Path::new("/"));
    }

    /// An override must be visible in the evidence, so a fixture run can never
    /// be mistaken for a hardware measurement.
    #[test]
    #[cfg(unix)]
    fn root_provenance_marks_an_override_and_not_the_real_sysfs() {
        use std::path::Path;
        let real = root_provenance(Path::new("/sys"));
        assert!(real.contains("sysfs root /sys"), "{real}");
        assert!(!real.contains("NOT"), "the real root needs no warning: {real}");

        let over = root_provenance(Path::new("/tmp/fixture"));
        assert!(over.contains("NOT /sys"), "{over}");
        assert!(over.contains(SYSFS_ROOT_ENV), "{over}");
        assert!(over.contains("/tmp/fixture"), "{over}");
    }

    /// A failing scan must not hide behind "no device": the reason for a
    /// malformed entry travels in the not-found message. (This test is about a
    /// *malformed* attribute; real EACCES has its own test,
    /// `sysfs_unreadable_attributes_are_not_reported_as_absent`.)
    #[test]
    #[cfg(unix)]
    fn sysfs_malformed_node_is_reported_in_the_not_found_reason() {
        let f = Fixture::new("badattr");
        f.dfu_device();
        // `1-9` looks like a device node but its idVendor is malformed.
        let other = "bus/usb/devices/1-9";
        f.mkdir(other);
        f.write(&format!("{other}/idVendor"), "0x05ac\n");
        f.write(&format!("{other}/idProduct"), "1227\n");
        f.write(&format!("{other}/busnum"), "1\n");
        f.write(&format!("{other}/devnum"), "9\n");

        let scan = scan_sysfs_usb_devices(f.root()).unwrap();
        assert_eq!(scan.nodes.len(), 1, "the good node is still measured");
        assert_eq!(scan.skipped.len(), 1, "the bad node is not silently dropped");
        assert!(scan.skipped[0].contains("not the four hex digits"), "{:?}", scan.skipped);

        // A device tree where *our* node is the unreadable one must say so
        // rather than report the device absent.
        let e = measure_sysfs_driver(f.root(), 1, 9).unwrap_err();
        assert!(e.contains("no sysfs device node"), "{e}");
        assert!(e.contains("1-9"), "{e}");
        assert!(e.contains("could not be read"), "{e}");
    }

    /// The `ident` line, pinned end to end. `main.rs:179` prints
    /// `DriverClass::as_str()`, so the measured service string only reaches the
    /// operator through this mapping — and it must not hand out a capability:
    /// the capability is measured in this file, never inferred from the name.
    #[test]
    fn usbfs_is_a_named_driver_class_that_never_grants_capability() {
        let class = DriverClass::from_service("usbfs");
        assert_eq!(class.as_str(), "usbfs");
        assert_ne!(class, DriverClass::Unknown);
        assert_ne!(class, DriverClass::LibusbK);
        assert_eq!(
            ResetCapability::from_driver(class),
            ResetCapability::Unknown,
            "Usbfs must not be aliased to Real: that would bypass the measured evidence"
        );
    }

    /// **"Unreadable" is not "absent", pinned under a real EACCES.**
    ///
    /// The reviewer's mutation M7 — `read_attr` folding every error into
    /// `Ok(None)`, i.e. "cannot read" becoming "not there" — left the whole
    /// suite green before this test existed. That is the difference between
    /// `Unknown` and a confident answer, on the one host that matters.
    ///
    /// If the test runs as a user that mode 000 cannot stop (root), it says so
    /// loudly and returns rather than passing without having measured anything.
    #[test]
    #[cfg(unix)]
    fn sysfs_unreadable_attributes_are_not_reported_as_absent() {
        use std::os::unix::fs::PermissionsExt;

        let f = Fixture::new("eacces-vid");
        f.dfu_device();
        let vid = f.root().join("bus/usb/devices/1-4/idVendor");
        std::fs::set_permissions(&vid, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_to_string(&vid).is_ok() {
            eprintln!(
                "SKIP sysfs_unreadable_attributes_are_not_reported_as_absent: mode 000 is \
                 readable by this user (root?); no EACCES to measure"
            );
            return;
        }
        let e_vid = measure_sysfs_driver(f.root(), 1, 7).unwrap_err();
        assert!(e_vid.contains("could not be read"), "{e_vid}");
        assert!(
            e_vid.contains("Permission denied") || e_vid.contains("os error 13"),
            "the reason must be the real one: {e_vid}"
        );
        assert!(e_vid.contains("idVendor"), "{e_vid}");
        let reading = linux_driver_reading(Err(e_vid.clone()), true);
        assert_eq!(reading.service, "", "an unreadable id must not yield a service");
        assert_eq!(DriverClass::from_service(&reading.service), DriverClass::Unknown);
        assert_eq!(reading.capability, ResetCapability::Unknown);
        assert_ne!(reading.service, "usbfs", "no guess in either direction");

        // The same rule one layer in: interface 0 exists, but its
        // bInterfaceNumber cannot be read, so nothing may be reported as
        // "no kernel driver bound" — and the message is a different one.
        let f2 = Fixture::new("eacces-iface");
        f2.dfu_device();
        let bnum = f2
            .root()
            .join("bus/usb/devices/1-4/1-4:1.0/bInterfaceNumber");
        std::fs::set_permissions(&bnum, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_to_string(&bnum).is_ok() {
            eprintln!(
                "SKIP sysfs_unreadable_attributes_are_not_reported_as_absent: mode 000 is \
                 readable by this user (root?); no EACCES to measure"
            );
            return;
        }
        let e_iface = measure_sysfs_driver(f2.root(), 1, 7).unwrap_err();
        assert!(e_iface.contains("could not be read"), "{e_iface}");
        assert!(
            e_iface.contains("Permission denied") || e_iface.contains("os error 13"),
            "the reason must be the real one: {e_iface}"
        );
        assert!(e_iface.contains("bInterfaceNumber"), "{e_iface}");
        assert_ne!(
            e_iface, e_vid,
            "two different unreadable attributes, two different messages"
        );
        let reading2 = linux_driver_reading(Err(e_iface), true);
        assert_eq!(reading2.service, "");
        assert_eq!(reading2.capability, ResetCapability::Unknown);
        assert_ne!(reading2.service, "usbfs");
    }

    /// The platform dispatch itself, pinned. Both reviewers found that
    /// `reset_note_here`'s `#[cfg(unix)]` arm could be reverted to the Windows
    /// `reset_note` with the whole suite still green — the measured defect (a
    /// real Linux reset reported as "cannot be determined from here") could
    /// come back silently. This calls the dispatcher, not the Linux function.
    #[test]
    #[cfg(unix)]
    fn reset_note_dispatch_uses_the_linux_sentence_on_this_host() {
        let note = reset_note_here(
            ResetCapability::Real,
            "reset capability REAL, from two measurements plus one source inspection: (c) \
             INSPECTED — ioctl(USBDEVFS_RESET) (linux_usbfs.c:1596)",
            true,
            "usbfs",
            sys::constants::LIBUSB_SUCCESS,
            237_000,
            Some(5),
            Some(5),
        );
        assert!(note.contains("linux_usbfs.c"), "{note}");
        assert!(!note.contains("windows_winusb.c"), "{note}");
        assert!(!note.contains("cannot be determined from here"), "{note}");
        assert!(note.contains("UNVERIFIED"), "{note}");
    }

    /// The driver line and the capability line are classified from one **exact**
    /// measurement. The reviewer's `usbfs-something-kernel` fixture produced
    /// `driver service: usbfs` next to `reset: unknown` under the substring rule
    /// `DriverClass::from_service` uses; on Linux the classification is exact,
    /// so the two lines cannot disagree.
    #[test]
    #[cfg(unix)]
    fn linux_driver_class_is_exact_about_usbfs() {
        let cases = [
            ("usbfs", "usbfs", ResetCapability::Real),
            ("usbfs-kernel", "other", ResetCapability::Unknown),
            ("usbfsfoo", "other", ResetCapability::Unknown),
            ("usbhid", "other", ResetCapability::Unknown),
        ];
        for (service, want_class, want_cap) in cases {
            let f = Fixture::new(&format!("class-{service}"));
            f.device("1-4", "05ac", "1227", 1, 7, Some(service), None);
            let reading = linux_driver_reading(measure_sysfs_driver(f.root(), 1, 7), true);
            assert_eq!(linux_driver_class(&reading).as_str(), want_class, "{service}");
            assert_eq!(reading.capability, want_cap, "{service}");
            assert_eq!(
                linux_driver_class(&reading).as_str() == "usbfs",
                reading.capability == ResetCapability::Real,
                "{service}: the ident driver line and the ident reset line must agree"
            );
        }
    }
}
