//! Shared vocabulary for a9pwn. FROZEN SURFACE — see `INTERFACE.md` §1.
//!
//! Written by the Lead as the common language every module speaks. The owner of
//! this file (transport-engineer) may extend it and must add the parsing tests,
//! but must not change these signatures: five other modules are written against
//! them.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// `LIBUSB_ERROR_OTHER` (-99): libusb's "something else went wrong" code.
///
/// Re-declared rather than imported so this vocabulary module needs no libusb
/// binding, and pinned against `libusb1_sys` by a test at the bottom of this
/// file. It is also the sentinel [`XferResult::unreaped`] looks for: an
/// asynchronous transfer that libusb never handed back has no libusb code of
/// its own, and inventing a positive one would be worse than saying "other".
pub const LIBUSB_ERROR_OTHER: i32 = -99;

/// `LIBUSB_SUCCESS` (0). Named so the one place that must check it reads as a
/// statement rather than as a bare zero.
pub const LIBUSB_SUCCESS: i32 = 0;

/// The shortest wall time in which a real USB control transfer can plausibly
/// have happened at all.
///
/// A control transfer is at minimum two kernel round trips. Anything that
/// claims to have completed in under a microsecond did not do the work — that
/// is the exact defect this crate exists to make impossible (see
/// `readmes/a9ctl-README.md`: a sub-millisecond wait measured against a
/// one-second clock, so the loop body never ran).
pub const MIN_TRUSTWORTHY_MICROS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferStatus {
    Ok,
    Stall,
    Timeout,
    Cancelled,
    NoDevice,
    Error,
}

impl XferStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            XferStatus::Ok => "OK",
            XferStatus::Stall => "STALL",
            XferStatus::Timeout => "TIMEOUT",
            XferStatus::Cancelled => "CANCELLED",
            XferStatus::NoDevice => "NO_DEVICE",
            XferStatus::Error => "ERROR",
        }
    }

    /// `libusb_transfer_status` → `XferStatus`.
    ///
    /// This mapping is FROZEN (INTERFACE.md §2) and every arm is tested,
    /// including the unknown one. The numbering is not guessable: `STALL` is 4
    /// and `NO_DEVICE` is 5, while the enum lists them in the other order.
    pub fn from_transfer_status(code: i32) -> XferStatus {
        match code {
            0 => XferStatus::Ok,          // LIBUSB_TRANSFER_COMPLETED
            4 => XferStatus::Stall,       // LIBUSB_TRANSFER_STALL
            2 => XferStatus::Timeout,     // LIBUSB_TRANSFER_TIMED_OUT
            3 => XferStatus::Cancelled,   // LIBUSB_TRANSFER_CANCELLED
            5 => XferStatus::NoDevice,    // LIBUSB_TRANSFER_NO_DEVICE
            _ => XferStatus::Error,       // ERROR(1), OVERFLOW(6), anything new
        }
    }

    /// `LIBUSB_ERROR_*` (the return value of a *synchronous* call) → `XferStatus`.
    ///
    /// A synchronous call cannot be cancelled, so `Cancelled` is only ever
    /// produced by the asynchronous path. `LIBUSB_ERROR_INTERRUPTED` is a
    /// retryable environment condition, not a device answer, and is reported
    /// as `Error` rather than dressed up as "we stopped it".
    pub fn from_libusb_rc(rc: i32) -> XferStatus {
        match rc {
            r if r >= 0 => XferStatus::Ok,
            -9 => XferStatus::Stall,     // LIBUSB_ERROR_PIPE
            -7 => XferStatus::Timeout,   // LIBUSB_ERROR_TIMEOUT
            -4 => XferStatus::NoDevice,  // LIBUSB_ERROR_NO_DEVICE
            _ => XferStatus::Error,      // IO, ACCESS, BUSY, NO_MEM, OVERFLOW, ...
        }
    }
}

impl fmt::Display for XferStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct XferResult {
    pub seq: u64,
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
    pub status: XferStatus,
    pub transferred: usize,
    pub requested: usize,
    pub micros: u64,
    pub libusb_rc: i32,
    pub abort_after_ms: Option<u32>,
}

impl XferResult {
    pub fn ok(&self) -> bool {
        self.status == XferStatus::Ok
    }

    pub fn stalled(&self) -> bool {
        self.status == XferStatus::Stall
    }

    /// Did the device actually answer?
    ///
    /// A stall is an answer: several checkm8 stages treat `STALL` as the pass
    /// condition, so folding it into "error" would invert the exploit.
    pub fn completed(&self) -> bool {
        matches!(self.status, XferStatus::Ok | XferStatus::Stall)
    }

    /// Was this transfer cut off (by us, by libusb's timeout) rather than
    /// answered?
    pub fn aborted(&self) -> bool {
        matches!(self.status, XferStatus::Cancelled | XferStatus::Timeout)
    }

    /// The reported wall time is below [`MIN_TRUSTWORTHY_MICROS`], so it cannot
    /// describe a transfer that really ran. The transport refutes the result
    /// rather than returning it as a plausible success.
    pub fn timing_refuted(&self) -> bool {
        self.micros < MIN_TRUSTWORTHY_MICROS
    }

    /// The asynchronous transfer was submitted but libusb never handed it back
    /// before the hard deadline.
    ///
    /// When this is true, `transferred` is 0 **by construction and is not a
    /// measurement** — nothing may be inferred from it, and the `Transport`
    /// that produced it is poisoned. Identified by the sentinel pair
    /// (`Error` + [`LIBUSB_ERROR_OTHER`] + an abort window) and never by
    /// `micros < 1`, so it cannot be confused with [`Self::timing_refuted`].
    ///
    /// **A transfer that was never submitted must never satisfy this.** libusb
    /// owns no buffer in that case, so nothing is poisoned and claiming
    /// otherwise would make a dead handle out of a live one. A failed
    /// `libusb_submit_transfer` in particular keeps libusb's own
    /// `LIBUSB_ERROR_*` code (not the `OTHER` sentinel) and carries no abort
    /// window, so it is neither `unreaped` nor a timing claim — see
    /// `usb::never_submitted`, which is the single construction site for every
    /// such result, and `usb::submitted_result` for the one shape that may
    /// legitimately set this.
    pub fn unreaped(&self) -> bool {
        self.status == XferStatus::Error
            && self.libusb_rc == LIBUSB_ERROR_OTHER
            && self.abort_after_ms.is_some()
            && !self.timing_refuted()
    }

    /// Is `transferred` a wire MEASUREMENT?
    ///
    /// True only for a completed transfer (`Ok`): the synchronous control API
    /// (`libusb_control_transfer`, libusb "Synchronous device I/O") returns the
    /// byte count on success and a bare negative `LIBUSB_ERROR_*` on failure —
    /// there is no `transferred` out-parameter, unlike bulk/interrupt. So the
    /// construction site's `transferred = if rc >= 0 { … } else { 0 }`
    /// (`usb.rs`) FABRICATES the 0 on every failure: the true partial length is
    /// not recoverable from this API. Nothing may read `transferred` as data
    /// unless this returns true — the read path reports the buffer's prefix as
    /// unverified instead, and `one_line` marks such rows `XFER-UNMEASURED`.
    pub fn transferred_measured(&self) -> bool {
        self.status == XferStatus::Ok
    }

    /// Stable, greppable, colourless. Designed to be pasted into a report.
    ///
    /// The trailing markers are derived from the fields, never stored:
    /// `SUBMICRO` from [`Self::timing_refuted`] and `UNREAPED` from
    /// [`Self::unreaped`]. They are mutually exclusive by construction;
    /// `XFER-UNMEASURED` from [`Self::transferred_measured`] is orthogonal and
    /// marks a substituted (fabricated) transfer count.
    pub fn one_line(&self) -> String {
        let abort = match self.abort_after_ms {
            Some(ms) => format!(" abort={ms}ms"),
            None => String::new(),
        };
        let mut flags = match (self.timing_refuted(), self.unreaped()) {
            (true, _) => " SUBMICRO".to_string(),
            (_, true) => " UNREAPED".to_string(),
            _ => String::new(),
        };
        if !self.transferred_measured() {
            flags.push_str(" XFER-UNMEASURED");
        }
        format!(
            "seq={:<6} {:<9} bm=0x{:02X} b=0x{:02X} wV=0x{:04X} wI=0x{:04X} wL={:<5} \
             xfer={}/{} {:>9}us rc={}{}{}",
            self.seq,
            self.status.as_str(),
            self.bm_request_type,
            self.b_request,
            self.w_value,
            self.w_index,
            self.w_length,
            self.transferred,
            self.requested,
            self.micros,
            self.libusb_rc,
            abort,
            flags
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Reset,
    Setup,
    Spray,
    Patch,
    Pwned,
}

impl Stage {
    pub fn name(&self) -> &'static str {
        match self {
            Stage::Reset => "RESET",
            Stage::Setup => "SETUP",
            Stage::Spray => "SPRAY",
            Stage::Patch => "PATCH",
            Stage::Pwned => "PWNED",
        }
    }

    pub fn parse(s: &str) -> Option<Stage> {
        match s.to_ascii_lowercase().as_str() {
            "reset" => Some(Stage::Reset),
            "setup" => Some(Stage::Setup),
            "spray" => Some(Stage::Spray),
            "patch" => Some(Stage::Patch),
            "pwned" => Some(Stage::Pwned),
            _ => None,
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Pwned,
    NoDevice,
    Exhausted { rounds: u32 },
    Unsupported(String),
    Aborted(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub serial: String,
    pub pid: u16,
    pub cpid: Option<u32>,
    pub cprv: Option<u32>,
    pub cpfm: Option<u32>,
    pub scep: Option<u32>,
    pub bdid: Option<u32>,
    pub ecid: Option<u64>,
    pub ibfl: Option<u32>,
    pub srtg: Option<String>,
    pub pwnd: Option<String>,
    pub i_serial: u8,
}

impl DeviceIdentity {
    /// Tolerant parse of the DFU serial descriptor.
    ///
    /// Windows cannot put spaces in a device instance ID, so SetupAPI hands back
    /// the same string with `_` where libusb hands it back with a space. Splitting
    /// on whitespace alone therefore produced one unparseable token on the only
    /// platform this tool runs on — see `readmes/a9ctl-README.md`. Normalise both.
    pub fn parse(serial: &str) -> DeviceIdentity {
        let mut id = DeviceIdentity {
            serial: serial.to_string(),
            ..Default::default()
        };

        let normalised = serial.replace('_', " ");
        for token in normalised.split_whitespace() {
            let (key, value) = match token.split_once(':') {
                Some(kv) => kv,
                None => continue,
            };
            let value = value.trim();
            let trimmed = value.trim_matches(|c| c == '[' || c == ']');
            let hex32 = |v: &str| u32::from_str_radix(v, 16).ok();

            match key.to_ascii_uppercase().as_str() {
                "CPID" => id.cpid = hex32(trimmed),
                "CPRV" => id.cprv = hex32(trimmed),
                "CPFM" => id.cpfm = hex32(trimmed),
                "SCEP" => id.scep = hex32(trimmed),
                "BDID" => id.bdid = hex32(trimmed),
                "ECID" => id.ecid = u64::from_str_radix(trimmed, 16).ok(),
                "IBFL" => id.ibfl = hex32(trimmed),
                "SRTG" => id.srtg = Some(trimmed.to_string()),
                "PWND" => id.pwnd = Some(trimmed.to_string()),
                _ => {}
            }
        }
        id
    }

    /// Success marker. The payload writes ` PWND:[checkm8]` into the bootrom's
    /// serial-number string, and it is the only host-visible proof of pwn.
    pub fn is_pwned(&self) -> bool {
        self.pwnd
            .as_deref()
            .map(|p| p.to_ascii_lowercase().contains("checkm8"))
            .unwrap_or(false)
    }

    pub fn is_a9(&self) -> bool {
        matches!(self.cpid, Some(0x8000) | Some(0x8003))
    }

    pub fn cpid_hex(&self) -> String {
        match self.cpid {
            Some(c) => format!("0x{c:04X}"),
            None => "unknown".to_string(),
        }
    }

    /// Parse a Windows **device instance ID**, whose Apple descriptor is only
    /// the component after the last backslash:
    ///
    /// ```text
    /// USB\VID_05AC&PID_1227\CPID:8003_CPRV:01_..._SRTG:[iBoot-2234.0.0.2.22]
    /// ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this prefix swallows the first key
    /// ```
    ///
    /// Fed straight to [`DeviceIdentity::parse`], that prefix turns the first
    /// token's key into `USB\VID_05AC&PID_1227\CPID`, which matches nothing —
    /// so `CPID` silently read as absent. Same failure class as the underscore
    /// bug, one layer out. Kept as a separate function so `parse` keeps its
    /// exact behaviour on the strings the rest of the crate already passes it.
    pub fn parse_instance_id(instance_id: &str) -> DeviceIdentity {
        match instance_id.rsplit_once('\\') {
            Some((_, descriptor)) => DeviceIdentity::parse(descriptor),
            None => DeviceIdentity::parse(instance_id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverClass {
    LibusbK,
    Libusb0,
    WinUsb,
    /// Linux: no kernel driver is bound to the device (or its interface 0), so
    /// libusb talks to it through `usbfs` on `/dev/bus/usb/<bus>/<addr>`.
    ///
    /// This is a *positive* measurement, not a fallback: it is read from the
    /// absence of a `driver` symlink on the device/interface node in sysfs, which
    /// is the state a DFU device is normally in on Linux, and it is what makes
    /// `USBDEVFS_RESET` reachable. The variant exists so `ident` can say
    /// `usbfs` instead of the uninformative `other`.
    Usbfs,
    Other,
    Unknown,
}

impl DriverClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DriverClass::LibusbK => "libusbK",
            DriverClass::Libusb0 => "libusb0",
            DriverClass::WinUsb => "WinUSB",
            DriverClass::Usbfs => "usbfs",
            DriverClass::Other => "other",
            DriverClass::Unknown => "unknown",
        }
    }

    /// Classify from the bound driver service name, as reported by the OS.
    pub fn from_service(service: &str) -> DriverClass {
        let s = service.to_ascii_lowercase();
        if s.contains("libusbk") {
            DriverClass::LibusbK
        } else if s.contains("libusb0") {
            DriverClass::Libusb0
        } else if s.contains("winusb") {
            DriverClass::WinUsb
        } else if s.contains("usbfs") {
            DriverClass::Usbfs
        } else if s.is_empty() {
            DriverClass::Unknown
        } else {
            DriverClass::Other
        }
    }
}

/// What the evidence says about whether a bus reset was **actually delivered**.
///
/// A `bool` cannot express this, and forcing it to is how four different
/// problems collapse into one message. "The call succeeded on a capable driver
/// but nothing observable changed" is genuinely different from "the device told
/// us it did not reset", and the difference decides whether an operator should
/// distrust the driver or distrust the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetEvidence {
    /// Positive evidence. The DFU state machine was parked in
    /// `MANIFEST_WAIT_RESET` and read back idle afterwards — a transition only
    /// a genuine bus reset causes.
    Delivered,
    /// Positive evidence it did **not** reset: the device was parked in
    /// `MANIFEST_WAIT_RESET` and still is.
    Refuted,
    /// The call returned success on a driver that can reset, but no state
    /// change could be observed or the state was idle both before and after.
    /// Consistent with a real reset; not proof of one. Never to be printed as
    /// success.
    Unverified,
    /// The bound driver cannot deliver a bus reset at all (WinUSB), or the
    /// interface the reset needs was never claimed.
    DriverCannotReset,
}

impl ResetEvidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResetEvidence::Delivered => "delivered",
            ResetEvidence::Refuted => "REFUTED by the device",
            ResetEvidence::Unverified => "issued, effect unverified",
            ResetEvidence::DriverCannotReset => "driver cannot reset",
        }
    }

    /// Is there positive evidence a bus reset happened?
    pub fn delivered(&self) -> bool {
        matches!(self, ResetEvidence::Delivered)
    }
}

/// Classify a reset from everything measured about it. Pure, so every branch is
/// testable without hardware.
///
/// The order matters: capability first, because libusb's return value is
/// fabricated on Windows (`windows_winusb.c:3419` returns `LIBUSB_SUCCESS`
/// unconditionally) and must never be the thing that decides. Then the DFU
/// state transition, which is real evidence *when* the device was parked in
/// [`crate::DFU_STATE_MANIFEST_WAIT_RESET`] before the reset.
///
/// **Device evidence outranks the claim flag.** Leaving
/// `MANIFEST_WAIT_RESET` for an idle state is the project's definition of
/// positive evidence, and it cannot happen without a bus reset reaching the
/// device; `interface_claimed` is only a snapshot taken at open. libusb
/// auto-claims on the first control transfer (`windows_winusb.c:2985`), and
/// `Transport::reset` issues one — the pre-reset `DFU_GETSTATUS` — before it
/// resets, so `false` there does **not** prove the call was skipped. The flag
/// still decides every case where the machine did *not* move, which is where a
/// skip is a real explanation.
///
/// Note what is deliberately **not** claimed: idle before and idle after is
/// exactly what a delivered host-initiated port reset looks like — libusbK's
/// reset does not cycle VBUS, so the device keeps its address and its DFU
/// machine has nothing to leave — and it is equally what a pipe cycle looks
/// like. The two are indistinguishable from the state machine alone, so the
/// answer is [`ResetEvidence::Unverified`], not success and not failure. To
/// turn that case into evidence, park the device in `MANIFEST_WAIT_RESET`
/// first (`stage_reset` does exactly that) and then reset.
pub fn reset_evidence(
    capability: ResetCapability,
    interface_claimed: bool,
    libusb_rc: i32,
    dfu_state_before: Option<u8>,
    dfu_state_after: Option<u8>,
) -> ResetEvidence {
    // The one cell that must not be gated on the claim snapshot: the device
    // itself says a reset arrived. Returning `DriverCannotReset` here (which is
    // what this did) makes `stages::reset_gate` STOP a run in which the reset
    // was delivered — the exact false accusation this type exists to prevent.
    if capability == ResetCapability::Real
        && libusb_rc == LIBUSB_SUCCESS
        && matches!(
            (dfu_state_before, dfu_state_after),
            (Some(crate::DFU_STATE_MANIFEST_WAIT_RESET), Some(after))
                if after == crate::DFU_STATE_APP_IDLE || after == crate::DFU_STATE_DFU_IDLE
        )
    {
        return ResetEvidence::Delivered;
    }

    if capability != ResetCapability::Real || !interface_claimed {
        return ResetEvidence::DriverCannotReset;
    }
    if libusb_rc != LIBUSB_SUCCESS {
        // The call itself failed; nothing about the port was confirmed.
        return ResetEvidence::Unverified;
    }

    match (dfu_state_before, dfu_state_after) {
        (Some(crate::DFU_STATE_MANIFEST_WAIT_RESET), Some(crate::DFU_STATE_MANIFEST_WAIT_RESET)) => {
            ResetEvidence::Refuted
        }
        // Includes idle-before/idle-after and every unreadable or
        // uninterpretable combination. `Unverified` is the honest name for all
        // of them; inventing a verdict here is the defect this crate exists to
        // prevent.
        _ => ResetEvidence::Unverified,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetCapability {
    /// The host can deliver a genuine USB bus reset.
    Real,
    /// The call returns success but only cycles pipes. checkm8 cannot fire.
    PipeCycleOnly,
    Unknown,
}

impl ResetCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResetCapability::Real => "real bus reset",
            ResetCapability::PipeCycleOnly => "pipe cycle only (silent no-op)",
            ResetCapability::Unknown => "unknown",
        }
    }

    /// Classify what a reset can physically do, from the driver that is
    /// **actually bound**.
    ///
    /// This is a statement about the driver, not about any particular call, and
    /// it has to be, because the call cannot tell us: libusb's
    /// `winusbx_reset_device` returns `LIBUSB_SUCCESS` unconditionally —
    /// including on the branch where all it did was abort, flush and reset the
    /// non-control pipes (`libusb1-sys-0.7.0/libusb/libusb/os/windows_winusb.c`
    /// :3380-3420; the real `ResetDevice` call at :3413 is skipped when
    /// `sub_api == SUB_API_WINUSB`). Only libusbK and libusb0 reach it.
    ///
    /// checkm8 needs a genuine bus reset — it is what runs the overwritten
    /// `dfu_handle_bus_reset` callback — so `WinUsb` here means the exploit
    /// cannot fire, whatever libusb returned.
    ///
    /// **Linux is deliberately NOT decided here.** `Usbfs` means "no kernel driver
    /// is bound", which says nothing by itself about what a reset does — on Linux
    /// the capability must be established from the *measured* evidence in `usb.rs`
    /// (the interface claim plus what `libusb_reset_device`/`USBDEVFS_RESET`
    /// actually did), never from the driver name. Do not "fix" this arm to
    /// `Real`: doing so would let a name stand in for a measurement, which is the
    /// one failure this project keeps paying for.
    pub fn from_driver(driver: DriverClass) -> ResetCapability {
        match driver {
            DriverClass::LibusbK | DriverClass::Libusb0 => ResetCapability::Real,
            DriverClass::WinUsb => ResetCapability::PipeCycleOnly,
            DriverClass::Usbfs | DriverClass::Other | DriverClass::Unknown => {
                ResetCapability::Unknown
            }
        }
    }
}

/// Monotonic transfer counter, shared by every `XferResult`.
///
/// One counter per `Transport`, so a trace is totally ordered even when two
/// modules interleave their logging, and a gap in the sequence is proof that
/// something was dropped rather than merely not printed.
///
/// Starts empty: `next()` hands out 1, 2, 3, ... and `last()` is 0 before any
/// transfer has been issued.
pub struct SeqCounter {
    issued: AtomicU64,
}

impl SeqCounter {
    pub const fn new() -> SeqCounter {
        SeqCounter {
            issued: AtomicU64::new(0),
        }
    }

    /// Allocate the next sequence number. Never returns 0.
    pub fn next(&self) -> u64 {
        self.issued.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// The most recently allocated number, or 0 if none has been.
    pub fn last(&self) -> u64 {
        self.issued.load(Ordering::Relaxed)
    }
}

impl Default for SeqCounter {
    fn default() -> Self {
        SeqCounter::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: &str = "CPID:8003 CPRV:01 CPFM:03 SCEP:01 BDID:02 \
                        ECID:00112233445566AA IBFL:1C SRTG:[IBOOT-2234.0.0.2.22]";
    const LIVE_WINDOWS: &str = "CPID:8003_CPRV:01_CPFM:03_SCEP:01_BDID:02_\
                                ECID:00112233445566AA_IBFL:1C_SRTG:[IBOOT-2234.0.0.2.22]";

    #[test]
    fn parses_space_form() {
        let id = DeviceIdentity::parse(LIVE);
        assert_eq!(id.cpid, Some(0x8003));
        assert_eq!(id.cprv, Some(0x01));
        assert_eq!(id.bdid, Some(0x02));
        assert_eq!(id.ibfl, Some(0x1C));
        assert_eq!(id.ecid, Some(0x0011_2233_4455_66AA));
        assert_eq!(id.srtg.as_deref(), Some("IBOOT-2234.0.0.2.22"));
        assert!(id.is_a9());
        assert!(!id.is_pwned());
    }

    #[test]
    fn parses_windows_underscore_form_identically() {
        let a = DeviceIdentity::parse(LIVE);
        let b = DeviceIdentity::parse(LIVE_WINDOWS);
        assert_eq!(a.cpid, b.cpid);
        assert_eq!(a.bdid, b.bdid);
        assert_eq!(a.srtg, b.srtg);
        assert_eq!(a.ecid, b.ecid);
    }

    #[test]
    fn detects_pwned() {
        let pwned = DeviceIdentity::parse(&format!("{LIVE} PWND:[checkm8]"));
        assert!(pwned.is_pwned());
        assert_eq!(pwned.pwnd.as_deref(), Some("checkm8"));
        assert!(pwned.is_a9());
    }

    #[test]
    fn unknown_chip_is_not_a9() {
        let other = DeviceIdentity::parse("CPID:8010 CPRV:11 BDID:0C SRTG:[iBoot-1]");
        assert!(!other.is_a9());
        assert_eq!(other.cpid_hex(), "0x8010");
    }

    #[test]
    fn empty_and_garbage_are_survivable() {
        let empty = DeviceIdentity::parse("");
        assert_eq!(empty.cpid, None);
        assert!(!empty.is_a9());
        assert!(!empty.is_pwned());
        let junk = DeviceIdentity::parse("not a descriptor at all");
        assert_eq!(junk.cpid, None);
        assert_eq!(junk.srtg, None);
    }

    #[test]
    fn driver_classification() {
        assert_eq!(DriverClass::from_service("libusbK"), DriverClass::LibusbK);
        assert_eq!(DriverClass::from_service("LIBUSBK"), DriverClass::LibusbK);
        assert_eq!(DriverClass::from_service("WinUSB"), DriverClass::WinUsb);
        assert_eq!(DriverClass::from_service("libusb0"), DriverClass::Libusb0);
        assert_eq!(DriverClass::from_service(""), DriverClass::Unknown);
        assert_eq!(DriverClass::from_service("usbhub"), DriverClass::Other);
    }

    #[test]
    fn one_line_is_stable() {
        let r = XferResult {
            seq: 7,
            bm_request_type: 0x21,
            b_request: 1,
            w_value: 0,
            w_index: 0,
            w_length: 16,
            status: XferStatus::Ok,
            transferred: 16,
            requested: 16,
            micros: 823,
            libusb_rc: 16,
            abort_after_ms: None,
        };
        let s = r.one_line();
        assert!(s.starts_with("seq=7 "), "{s}");
        assert!(s.contains("OK"), "{s}");
        assert!(s.contains("bm=0x21"), "{s}");
        assert!(s.contains("xfer=16/16"), "{s}");
        assert!(!s.contains("abort="), "{s}");
    }

    #[test]
    fn abort_window_is_reported() {
        let r = XferResult {
            abort_after_ms: Some(3),
            ..XferResult {
                seq: 1,
                bm_request_type: 0x21,
                b_request: 1,
                w_value: 0,
                w_index: 0,
                w_length: 0x800,
                status: XferStatus::Cancelled,
                transferred: 0,
                requested: 2048,
                micros: 3001,
                libusb_rc: -2,
                abort_after_ms: None,
            }
        };
        assert!(r.one_line().contains("abort=3ms"));
    }

    // ---------------------------------------------------------------------
    // Added by the transport owner (task-2). The frozen surface above is
    // untouched; everything below pins behaviour the exploit depends on.
    // ---------------------------------------------------------------------

    /// Every `libusb_transfer_status` value, including the two whose numbering
    /// is least guessable. `STALL` is 4 and `NO_DEVICE` is 5; the enum lists
    /// them the other way round, so a careless edit here is silent and fatal
    /// (a stall is the PASS condition for several checkm8 stages).
    #[test]
    fn transfer_status_mapping_is_total_and_frozen() {
        assert_eq!(XferStatus::from_transfer_status(0), XferStatus::Ok);
        assert_eq!(XferStatus::from_transfer_status(1), XferStatus::Error);
        assert_eq!(XferStatus::from_transfer_status(2), XferStatus::Timeout);
        assert_eq!(XferStatus::from_transfer_status(3), XferStatus::Cancelled);
        assert_eq!(XferStatus::from_transfer_status(4), XferStatus::Stall);
        assert_eq!(XferStatus::from_transfer_status(5), XferStatus::NoDevice);
        // OVERFLOW is 6 and has no variant of its own: "everything else -> Error".
        assert_eq!(XferStatus::from_transfer_status(6), XferStatus::Error);
        assert_eq!(XferStatus::from_transfer_status(99), XferStatus::Error);
        assert_eq!(XferStatus::from_transfer_status(-1), XferStatus::Error);
    }

    /// The numbers above are libusb's, not ours. If the binding ever disagreed,
    /// the mapping would be silently wrong, so it is checked against the crate
    /// rather than trusted.
    #[test]
    fn mapping_numbers_agree_with_the_libusb_binding() {
        use libusb1_sys::constants as c;
        let pairs: [(i32, i32); 7] = [
            (0, c::LIBUSB_TRANSFER_COMPLETED),
            (1, c::LIBUSB_TRANSFER_ERROR),
            (2, c::LIBUSB_TRANSFER_TIMED_OUT),
            (3, c::LIBUSB_TRANSFER_CANCELLED),
            (4, c::LIBUSB_TRANSFER_STALL),
            (5, c::LIBUSB_TRANSFER_NO_DEVICE),
            (6, c::LIBUSB_TRANSFER_OVERFLOW),
        ];
        for (ours, theirs) in pairs {
            assert_eq!(ours, theirs, "transfer status numbering drifted");
        }
        assert_eq!(c::LIBUSB_ERROR_PIPE, -9);
        assert_eq!(c::LIBUSB_ERROR_TIMEOUT, -7);
        assert_eq!(c::LIBUSB_ERROR_NO_DEVICE, -4);
        assert_eq!(c::LIBUSB_ERROR_OTHER, LIBUSB_ERROR_OTHER);
    }

    /// Synchronous calls hand back a negative `LIBUSB_ERROR_*`, not a transfer
    /// status. A non-negative return is a byte count and therefore success.
    #[test]
    fn error_code_mapping_for_synchronous_calls() {
        assert_eq!(XferStatus::from_libusb_rc(64), XferStatus::Ok);
        assert_eq!(XferStatus::from_libusb_rc(0), XferStatus::Ok);
        assert_eq!(XferStatus::from_libusb_rc(-9), XferStatus::Stall);
        assert_eq!(XferStatus::from_libusb_rc(-7), XferStatus::Timeout);
        assert_eq!(XferStatus::from_libusb_rc(-4), XferStatus::NoDevice);
        assert_eq!(XferStatus::from_libusb_rc(-1), XferStatus::Error);
        assert_eq!(XferStatus::from_libusb_rc(-3), XferStatus::Error);
        assert_eq!(XferStatus::from_libusb_rc(-6), XferStatus::Error);
        assert_eq!(XferStatus::from_libusb_rc(-10), XferStatus::Error);
        assert_eq!(XferStatus::from_libusb_rc(-99), XferStatus::Error);
    }

    fn sample(status: XferStatus) -> XferResult {
        XferResult {
            seq: 1,
            bm_request_type: 0x80,
            b_request: 6,
            w_value: 0x0304,
            w_index: 0x0A,
            w_length: 0x40,
            status,
            transferred: 0,
            requested: 0x40,
            micros: 1200,
            libusb_rc: 0,
            abort_after_ms: None,
        }
    }

    /// `STALL` is an answer, not an error. If it ever stopped counting as one,
    /// the PAD request — whose pass condition IS a stall — would never pass.
    #[test]
    fn stall_completes_and_is_not_ok() {
        let s = sample(XferStatus::Stall);
        assert!(s.stalled());
        assert!(!s.ok());
        assert!(s.completed());
        assert!(!s.aborted());
    }

    /// `completed` and `aborted` are mutually exclusive but deliberately do
    /// **not** cover every status: a vanished device and a transfer-level error
    /// are neither an answer nor something we ended. Squeezing them into one of
    /// the two is how a dead device gets read as a quiet timeout.
    #[test]
    fn answers_aborts_and_neither_are_kept_apart() {
        let table = [
            (XferStatus::Ok, true, false),
            (XferStatus::Stall, true, false),
            (XferStatus::Timeout, false, true),
            (XferStatus::Cancelled, false, true),
            (XferStatus::NoDevice, false, false),
            (XferStatus::Error, false, false),
        ];
        for (status, completed, aborted) in table {
            let r = sample(status);
            assert_eq!(r.completed(), completed, "{status:?} completed");
            assert_eq!(r.aborted(), aborted, "{status:?} aborted");
            assert!(
                !(r.completed() && r.aborted()),
                "{status:?} cannot be both an answer and an abort"
            );
        }
    }

    /// The floor. Zero elapsed time is the signature of the documented defect —
    /// a wait that never executed — and must be refuted, not reported.
    #[test]
    fn sub_microsecond_timings_are_refuted() {
        assert!(!sample(XferStatus::Cancelled).timing_refuted());
        let mut r = sample(XferStatus::Cancelled);
        r.micros = 0;
        assert!(r.timing_refuted(), "0 us cannot describe a real transfer");
        r.micros = MIN_TRUSTWORTHY_MICROS;
        assert!(!r.timing_refuted(), "1 us is the floor, and is accepted");
    }

    /// Two different bad outcomes, two different names — and they must never be
    /// confused, because one is a timing lie and the other is a lost transfer
    /// whose byte count means nothing.
    #[test]
    fn unreaped_is_distinct_from_a_refuted_timing() {
        let mut lost = sample(XferStatus::Error);
        lost.libusb_rc = LIBUSB_ERROR_OTHER;
        lost.abort_after_ms = Some(4);
        lost.micros = 2_004_000;
        assert!(lost.unreaped());
        assert!(!lost.timing_refuted());

        let mut fast = sample(XferStatus::Error);
        fast.libusb_rc = LIBUSB_ERROR_OTHER;
        fast.abort_after_ms = Some(4);
        fast.micros = 0;
        assert!(fast.timing_refuted());
        assert!(!fast.unreaped(), "a sub-microsecond result is not 'unreaped'");

        // The sentinel needs the abort window: a synchronous call that failed
        // with OTHER is an ordinary error, not a lost transfer.
        let mut sync = sample(XferStatus::Error);
        sync.libusb_rc = LIBUSB_ERROR_OTHER;
        assert!(!sync.unreaped());
    }

    #[test]
    fn one_line_marks_refuted_timings_and_lost_transfers() {
        let clean = sample(XferStatus::Ok);
        assert!(!clean.one_line().contains("SUBMICRO"));
        assert!(!clean.one_line().contains("UNREAPED"));
        assert!(!clean.one_line().contains("XFER-UNMEASURED"), "{}", clean.one_line());

        let mut fast = sample(XferStatus::Error);
        fast.micros = 0;
        assert!(fast.one_line().contains("SUBMICRO"), "{}", fast.one_line());
        // Instrument fix 2's marker: a failed transfer's `transferred` is the sync API's
        // substitution, never a measurement — and the row says so in greppable form.
        assert!(fast.one_line().contains("XFER-UNMEASURED"), "{}", fast.one_line());

        let mut lost = sample(XferStatus::Error);
        lost.libusb_rc = LIBUSB_ERROR_OTHER;
        lost.abort_after_ms = Some(2);
        lost.micros = 2_001_000;
        assert!(lost.one_line().contains("UNREAPED"), "{}", lost.one_line());
        assert!(lost.one_line().contains("abort=2ms"), "{}", lost.one_line());
    }

    /// The Windows instance ID has a prefix that swallows the first key if it
    /// is not stripped. `parse` itself is deliberately left alone.
    #[test]
    fn instance_id_prefix_is_stripped() {
        let inst = "USB\\VID_05AC&PID_1227\\CPID:8003_CPRV:01_CPFM:03_SCEP:01_BDID:02_\
                    ECID:00112233445566AA_IBFL:1C_SRTG:[IBOOT-2234.0.0.2.22]";
        let id = DeviceIdentity::parse_instance_id(inst);
        assert_eq!(id.cpid, Some(0x8003));
        assert_eq!(id.bdid, Some(0x02));
        assert_eq!(id.cprv, Some(0x01));
        assert_eq!(id.srtg.as_deref(), Some("IBOOT-2234.0.0.2.22"));
        assert!(id.is_a9());

        // A bare descriptor (no prefix) goes through unchanged.
        let bare = DeviceIdentity::parse_instance_id(
            "CPID:8003_CPRV:01_BDID:02_SRTG:[IBOOT-2234.0.0.2.22]",
        );
        assert_eq!(bare, DeviceIdentity::parse("CPID:8003_CPRV:01_BDID:02_SRTG:[IBOOT-2234.0.0.2.22]"));
    }

    /// Windows' underscore form of the pwn marker is the only place a *success*
    /// is visible on the platform this tool runs on.
    #[test]
    fn underscore_form_still_reports_pwned() {
        let pwned = DeviceIdentity::parse("CPID:8003_CPRV:01_BDID:02_PWND:[checkm8]");
        assert!(pwned.is_pwned());
        assert_eq!(pwned.pwnd.as_deref(), Some("checkm8"));
        assert_eq!(pwned.cpid, Some(0x8003));
    }

    /// The reset classification is the one decision that decides whether an
    /// attempt is worth making, and it must follow the driver — not the
    /// (always successful) return value of the reset call.
    #[test]
    fn reset_capability_follows_the_bound_driver() {
        assert_eq!(
            ResetCapability::from_driver(DriverClass::LibusbK),
            ResetCapability::Real
        );
        assert_eq!(
            ResetCapability::from_driver(DriverClass::Libusb0),
            ResetCapability::Real
        );
        assert_eq!(
            ResetCapability::from_driver(DriverClass::WinUsb),
            ResetCapability::PipeCycleOnly
        );
        assert_eq!(
            ResetCapability::from_driver(DriverClass::Other),
            ResetCapability::Unknown
        );
        assert_eq!(
            ResetCapability::from_driver(DriverClass::Unknown),
            ResetCapability::Unknown
        );
        // And it agrees with the service-name classification it is fed from.
        assert_eq!(
            ResetCapability::from_driver(DriverClass::from_service("WinUSB")),
            ResetCapability::PipeCycleOnly
        );
    }

    #[test]
    fn sequence_numbers_are_monotonic_and_start_at_one() {
        let c = SeqCounter::new();
        assert_eq!(c.last(), 0, "nothing issued yet");
        assert_eq!(c.next(), 1);
        assert_eq!(c.next(), 2);
        assert_eq!(c.last(), 2);
        assert_eq!(c.next(), 3);
        assert_eq!(c.last(), 3);
    }

    // ---- reset evidence ----------------------------------------------------

    /// The DFU state numbers are the bootrom's, not ours.
    #[test]
    fn dfu_state_constants_match_the_dfu_spec() {
        assert_eq!(crate::DFU_STATE_APP_IDLE, 0, "appIDLE");
        assert_eq!(crate::DFU_STATE_DFU_IDLE, 2, "dfuIDLE");
        assert_eq!(crate::DFU_STATE_MANIFEST_SYNC, 6, "manifestSync");
        assert_eq!(crate::DFU_STATE_MANIFEST, 7, "manifest");
        assert_eq!(crate::DFU_STATE_MANIFEST_WAIT_RESET, 8, "manifestWaitReset");
        assert_eq!(LIBUSB_SUCCESS, 0);
    }

    /// The one unambiguous case: parked in MANIFEST_WAIT_RESET and unparked
    /// afterwards. Only a bus reset clears that state.
    #[test]
    fn leaving_wait_reset_is_positive_evidence() {
        for after in [crate::DFU_STATE_APP_IDLE, crate::DFU_STATE_DFU_IDLE] {
            let e = reset_evidence(
                ResetCapability::Real,
                true,
                LIBUSB_SUCCESS,
                Some(crate::DFU_STATE_MANIFEST_WAIT_RESET),
                Some(after),
            );
            assert_eq!(e, ResetEvidence::Delivered, "after={after}");
            assert!(e.delivered());
        }
    }

    /// Still parked: the reset did not take effect, whatever libusb said.
    #[test]
    fn staying_in_wait_reset_refutes_the_reset() {
        let e = reset_evidence(
            ResetCapability::Real,
            true,
            LIBUSB_SUCCESS,
            Some(crate::DFU_STATE_MANIFEST_WAIT_RESET),
            Some(crate::DFU_STATE_MANIFEST_WAIT_RESET),
        );
        assert_eq!(e, ResetEvidence::Refuted);
        assert!(!e.delivered());
        assert_ne!(
            e,
            ResetEvidence::Unverified,
            "a device that is still parked is positive evidence, not an unknown"
        );
    }

    /// Idle before, idle after. Not success — and not failure either. This is
    /// the bare `reset` case, and calling it failure would accuse a working
    /// driver.
    #[test]
    fn idle_to_idle_is_unverified_in_both_directions() {
        for (before, after) in [
            (crate::DFU_STATE_APP_IDLE, crate::DFU_STATE_APP_IDLE),
            (crate::DFU_STATE_DFU_IDLE, crate::DFU_STATE_DFU_IDLE),
            (crate::DFU_STATE_APP_IDLE, crate::DFU_STATE_DFU_IDLE),
            (crate::DFU_STATE_DFU_IDLE, crate::DFU_STATE_APP_IDLE),
        ] {
            let e = reset_evidence(
                ResetCapability::Real,
                true,
                LIBUSB_SUCCESS,
                Some(before),
                Some(after),
            );
            assert_eq!(e, ResetEvidence::Unverified, "{before}->{after}");
            assert!(!e.delivered(), "{before}->{after} must not read as success");
            assert_ne!(e, ResetEvidence::Refuted, "{before}->{after} must not accuse");
        }
    }

    /// A read that could not be taken is its own outcome, and an unread state
    /// never becomes a verdict.
    #[test]
    fn unreadable_states_are_unverified() {
        for (before, after) in [
            (None, Some(crate::DFU_STATE_DFU_IDLE)),
            (Some(crate::DFU_STATE_MANIFEST_WAIT_RESET), None),
            (None, None),
            (Some(3), Some(4)), // legal DFU states we do not interpret
        ] {
            let e = reset_evidence(
                ResetCapability::Real,
                true,
                LIBUSB_SUCCESS,
                before,
                after,
            );
            assert_eq!(e, ResetEvidence::Unverified, "{before:?}->{after:?}");
            assert!(!e.delivered());
        }
    }

    /// Capability and the claim gate the verdict, because libusb's success is
    /// fabricated: a WinUSB "reset" that reports success, and a libusbK reset
    /// that was skipped for want of a claimed interface, are both non-resets.
    ///
    /// **The one cell the gate must not decide** is pinned separately below: a
    /// device that visibly left `MANIFEST_WAIT_RESET`. The claim flag is a
    /// snapshot from open, and libusb auto-claims on the first control transfer
    /// (`windows_winusb.c:2985`) — which `Transport::reset` performs for its
    /// pre-reset `DFU_GETSTATUS` — so `false` does not prove the call was
    /// skipped. Every case where the machine did *not* move stays gated.
    #[test]
    fn capability_and_claim_gate_the_verdict() {
        let parked = Some(crate::DFU_STATE_MANIFEST_WAIT_RESET);
        let idle = Some(crate::DFU_STATE_DFU_IDLE);

        // WinUSB: reports success, cycles pipes. The capability gate is
        // absolute, transition or no transition.
        assert_eq!(
            reset_evidence(
                ResetCapability::PipeCycleOnly,
                true,
                LIBUSB_SUCCESS,
                parked,
                idle
            ),
            ResetEvidence::DriverCannotReset
        );
        assert_eq!(
            reset_evidence(ResetCapability::Unknown, true, LIBUSB_SUCCESS, parked, idle),
            ResetEvidence::DriverCannotReset
        );
        // libusbK but interface 0 never claimed: libusb skips ResetDevice and
        // still returns success — so with no movement from the parked state,
        // the skip *is* the explanation.
        assert_eq!(
            reset_evidence(ResetCapability::Real, false, LIBUSB_SUCCESS, parked, parked),
            ResetEvidence::DriverCannotReset
        );
        assert_eq!(
            reset_evidence(
                ResetCapability::Real,
                false,
                LIBUSB_SUCCESS,
                Some(crate::DFU_STATE_APP_IDLE),
                Some(crate::DFU_STATE_APP_IDLE)
            ),
            ResetEvidence::DriverCannotReset
        );
        assert_eq!(
            reset_evidence(ResetCapability::Real, false, LIBUSB_SUCCESS, None, None),
            ResetEvidence::DriverCannotReset
        );
        // A failed call is never evidence of delivery, even with a transition.
        assert_eq!(
            reset_evidence(ResetCapability::Real, true, -4, parked, idle),
            ResetEvidence::Unverified
        );
        // …and neither is it `DriverCannotReset` when the interface was not
        // claimed: the rc says this call failed, which is its own outcome.
        assert_eq!(
            reset_evidence(ResetCapability::Real, false, -4, parked, parked),
            ResetEvidence::DriverCannotReset
        );
    }

    /// Device evidence outranks the claim snapshot — the one cell that changed
    /// when this was fixed, stated on its own so the decision is visible.
    ///
    /// Before: `(Real, claimed=false, rc=0, 8 -> 2)` was `DriverCannotReset`, so
    /// `stages::reset_gate` returned `Stop` and a run in which the reset had
    /// demonstrably been delivered was aborted with "the driver cannot reset".
    /// A machine that left `MANIFEST_WAIT_RESET` was reset by something; if the
    /// claim flag is the only thing saying otherwise, the flag is wrong, because
    /// it was taken at open and libusb auto-claims on the first control transfer.
    #[test]
    fn a_transition_out_of_wait_reset_outranks_an_unclaimed_interface() {
        for after in [crate::DFU_STATE_APP_IDLE, crate::DFU_STATE_DFU_IDLE] {
            let e = reset_evidence(
                ResetCapability::Real,
                false,
                LIBUSB_SUCCESS,
                Some(crate::DFU_STATE_MANIFEST_WAIT_RESET),
                Some(after),
            );
            assert_eq!(e, ResetEvidence::Delivered, "after={after}");
            assert!(e.delivered());
        }

        // The capability gate still comes first: a WinUSB "reset" cannot have
        // delivered anything, whatever the state machine appears to show, and
        // saying otherwise would break the one verdict that protects the phone.
        assert_eq!(
            reset_evidence(
                ResetCapability::PipeCycleOnly,
                false,
                LIBUSB_SUCCESS,
                Some(crate::DFU_STATE_MANIFEST_WAIT_RESET),
                Some(crate::DFU_STATE_DFU_IDLE)
            ),
            ResetEvidence::DriverCannotReset
        );
        // And a failed call is still not a delivery.
        assert_eq!(
            reset_evidence(
                ResetCapability::Real,
                false,
                -4,
                Some(crate::DFU_STATE_MANIFEST_WAIT_RESET),
                Some(crate::DFU_STATE_DFU_IDLE)
            ),
            ResetEvidence::DriverCannotReset
        );
    }
}
