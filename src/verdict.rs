//! a9pwn — failure classification. OWNER: diagnostics-engineer. Contract: `INTERFACE.md` §6.
//!
//! ## The design rule this file implements
//!
//! > *"A tool that cannot tell four things apart is not a tool."*
//! > — `readmes/a9ctl-README.md`
//!
//! The C++ tool this project abandoned printed `Could not find device in DFU
//! mode!` for four different problems, and all four happened in one session.
//! `gaster` has the mirror-image defect: its SETUP sweep is an unbounded `for(;;)`
//! that prints nothing (`gaster.c:848-860`) and its device wait loops forever
//! without a word (`gaster.c:206-215`). One message for four causes is the failure
//! mode; this module's whole job is to refuse it.
//!
//! ## Rules this module obeys
//!
//! 1. **Every `evidence` entry names the measurement it came from** — the
//!    `Counters` field, the descriptor field, or the `file:line` in the reference
//!    — so a reader can re-derive the conclusion without re-running anything.
//! 2. **Every `next_action` is a command, not advice.** "Consider checking the
//!    driver" is not an action; ``run `a9drv bind --pid 1227` elevated`` is.
//! 3. **No fabrication.** A code fires only on an observable in
//!    [`Counters`]/[`DeviceIdentity`]/[`DriverClass`]/[`ResetCapability`]. When a
//!    measurement is missing the verdict says so and lowers its confidence rather
//!    than guessing. Codes whose counters are never wired simply never fire.
//! 4. **Precedence is causal, and documented** — see [`classify`].
//!
//! ## The one that matters most
//!
//! [`NO_RESET_CAPABILITY`]. On Windows with WinUSB bound, libusb's reset degrades
//! to a pipe cycle and still returns `LIBUSB_SUCCESS`
//! (`libusb1-sys-0.7.0/libusb/libusb/os/windows_winusb.c:3380-3420`), so the
//! mandatory reset after every stage attempt (`gaster.c:1268`) silently does
//! nothing. The observable is the endless pad-request TIMEOUT in
//! `a9ctl/stage-setup.log`, which is why [`PAD_TIMEOUT_NOT_STALL`] exists and why
//! [`classify`] checks the driver before it interprets anything else.

use crate::trace::{counters_one_line, Counters};
use crate::types::{DeviceIdentity, DriverClass, ResetCapability, RunOutcome};

// ---------------------------------------------------------------------- codes

/// The reference's own success predicate: `strstr(serial, " PWND:[checkm8]")`
/// (`gaster.c:811`).
pub const PWNED: &str = "PWNED";
/// Reported pwned, but the marker above is absent — so it is not pwned.
pub const PWNED_UNCONFIRMED: &str = "PWNED_UNCONFIRMED";
/// Driver is WinUSB (or the reset measured as a pipe cycle): resets are no-ops.
pub const NO_RESET_CAPABILITY: &str = "NO_RESET_CAPABILITY";
/// The reset capability was never established.
pub const RESET_CAPABILITY_UNKNOWN: &str = "RESET_CAPABILITY_UNKNOWN";
/// Resets were attempted and none was delivered.
pub const RESET_NOT_DELIVERED: &str = "RESET_NOT_DELIVERED";
/// `RunOutcome::NoDevice`, or a device that never answered at all.
pub const DEVICE_ABSENT: &str = "DEVICE_ABSENT";
/// A DFU node exists in the census but the open failed with a non-libusb driver bound.
pub const WRONG_DRIVER_BOUND: &str = "WRONG_DRIVER_BOUND";
/// A DFU node exists in the census but the open failed and no usable driver is bound.
pub const DRIVER_BOUND_NOT_LOADED: &str = "DRIVER_BOUND_NOT_LOADED";
/// The instance path is at or beyond libusb's `char dev_id[256]`, where libusb
/// skips the node with nothing but a warning (`windows_winusb.c:1599,1719-1723`).
pub const DEVICE_PATH_TOO_LONG: &str = "DEVICE_PATH_TOO_LONG";
/// The device was present and then went away mid-run (`XferStatus::NoDevice`).
pub const DEVICE_LOST_MID_RUN: &str = "DEVICE_LOST_MID_RUN";
/// Something answered but the serial descriptor did not yield a CPID.
pub const IDENTITY_UNREADABLE: &str = "IDENTITY_UNREADABLE";
/// CPID outside the A9 table.
pub const UNSUPPORTED_CHIP: &str = "UNSUPPORTED_CHIP";
/// SRTG absent: iBSS DFU, not SecureROM.
pub const WRONG_BOOT_STAGE: &str = "WRONG_BOOT_STAGE";
/// The config layer refused an identity the reference would have accepted.
pub const CONFIG_ROW_MISMATCH: &str = "CONFIG_ROW_MISMATCH";
/// SETUP exhausted its budget and the pad request never STALLed.
pub const SETUP_NEVER_STALLED: &str = "SETUP_NEVER_STALLED";
/// The pad request returned TIMEOUT: the device is NAKing, not STALLing.
pub const PAD_TIMEOUT_NOT_STALL: &str = "PAD_TIMEOUT_NOT_STALL";
/// The pad request failed at the host (`Error`/`NoDevice`), not on the device.
pub const PAD_ERROR_NOT_STALL: &str = "PAD_ERROR_NOT_STALL";
/// No pad request was ever sent: `sz < overwrite_pad` never held (`gaster.c:853`).
pub const PAD_NEVER_REQUESTED: &str = "PAD_NEVER_REQUESTED";
/// The abort window never advanced (`gaster.c:857`'s modulus collapsed).
pub const ABORT_WINDOW_PINNED: &str = "ABORT_WINDOW_PINNED";
/// Async transfers carried no `abort_after_ms`: the sweep cannot be audited.
pub const ABORT_WINDOW_UNREPORTED: &str = "ABORT_WINDOW_UNREPORTED";
/// Aborted transfers returned `Cancelled` before their own window elapsed.
pub const ABORT_CANCELLED_EARLY: &str = "ABORT_CANCELLED_EARLY";
/// `checkm8_usb_request_stall` (`gaster.c:890-894`) did not STALL.
pub const SPRAY_REQUEST_NOT_STALLING: &str = "SPRAY_REQUEST_NOT_STALLING";
/// The leak predicate (`gaster.c:866,886`) never returned zero bytes.
pub const SPRAY_LEAK_NOT_ZERO: &str = "SPRAY_LEAK_NOT_ZERO";
/// Rounds exhausted, nothing matched.
pub const EXHAUSTED_UNKNOWN: &str = "EXHAUSTED_UNKNOWN";
/// The run stopped deliberately; the transport's message is the only cause.
pub const RUN_ABORTED: &str = "RUN_ABORTED";

/// Every code this module can return. `a9pwn selftest` and the unit tests assert
/// that each one is reachable from some observable signature.
pub const CODES: &[&str] = &[
    PWNED,
    PWNED_UNCONFIRMED,
    NO_RESET_CAPABILITY,
    RESET_CAPABILITY_UNKNOWN,
    RESET_NOT_DELIVERED,
    DEVICE_ABSENT,
    WRONG_DRIVER_BOUND,
    DRIVER_BOUND_NOT_LOADED,
    DEVICE_PATH_TOO_LONG,
    DEVICE_LOST_MID_RUN,
    IDENTITY_UNREADABLE,
    UNSUPPORTED_CHIP,
    WRONG_BOOT_STAGE,
    CONFIG_ROW_MISMATCH,
    SETUP_NEVER_STALLED,
    PAD_TIMEOUT_NOT_STALL,
    PAD_ERROR_NOT_STALL,
    PAD_NEVER_REQUESTED,
    ABORT_WINDOW_PINNED,
    ABORT_WINDOW_UNREPORTED,
    ABORT_CANCELLED_EARLY,
    SPRAY_REQUEST_NOT_STALLING,
    SPRAY_LEAK_NOT_ZERO,
    EXHAUSTED_UNKNOWN,
    RUN_ABORTED,
];

/// The A9 members of the reference's table. `config.rs` owns the real row set;
/// this is only the membership test that tells `UNSUPPORTED_CHIP` from the rest.
const A9_CPIDS: [u32; 2] = [0x8000, 0x8003];

/// gaster's A9 rows are selected on the SRTG substring alone (`gaster.c:624,641`).
const A9_SRTG_MARKER: &str = "2234";

// ----------------------------------------------------------------- confidence

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

// -------------------------------------------------------------------- verdict

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Stable, uppercase, e.g. `NO_RESET_CAPABILITY`.
    pub code: &'static str,
    pub headline: String,
    /// Each item names the measurement it came from.
    pub evidence: Vec<String>,
    /// A concrete instruction, not advice.
    pub next_action: String,
    pub confidence: Confidence,
}

// ------------------------------------------------------------------ classify

/// Classify a finished (or refused) run into exactly one code.
///
/// Precedence, in order, each step a different measurement:
///
/// 1. reset capability — nothing else is interpretable if resets are pipe cycles;
/// 2. success, by the reference's own `PWND:[checkm8]` predicate;
/// 3. the discovery record, when no transfer happened: path length, then a node that
///    exists but will not open — the README's other three cases;
/// 4. absence, with the census that proves it (or states that none was taken);
/// 5. a device that reported `NO_DEVICE` mid-run;
/// 6. identity — CPID and SRTG decide which of three different problems this is;
/// 7. config refusal for an identity the reference would have accepted;
/// 8. resets that were attempted and not delivered;
/// 9. the SETUP sweep, by which clause of `gaster.c:853` failed;
/// 10. the SPRAY predicates (`gaster.c:890-894`, `gaster.c:866,886`);
/// 11. a capability that was never established;
/// 12. exhausted / aborted, with the recorded counters attached.
///
/// Steps 3-5 use the additive `Counters` discovery fields, so the signature stays
/// exactly as `INTERFACE.md` §6 freezes it.
pub fn classify(
    outcome: &RunOutcome,
    counters: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    reset_cap: ResetCapability,
) -> Verdict {
    // 1 ---------------------------------------------------------------- resets
    if driver == DriverClass::WinUsb
        || reset_cap == ResetCapability::PipeCycleOnly
        || counters.resets_pipe_cycle > 0
    {
        return no_reset_capability(counters, ident, driver, reset_cap);
    }

    // 2 --------------------------------------------------------------- success
    if matches!(outcome, RunOutcome::Pwned) {
        return if ident.is_pwned() {
            pwned(counters, ident)
        } else {
            pwned_unconfirmed(counters, ident)
        };
    }

    // 3 ------------------------------------------------------- discovery record
    // Taken before any transfer, so it only speaks when no transfer happened: a
    // run's own counters outrank a stale census. This is where the README's other
    // three cases earn their own messages, using the `Counters` discovery fields
    // (`nodes_present_by_pid`, `device_path_len`, `last_open_errno/error`).
    let nothing_ran = counters.total() == 0
        && !counters.setup_ran()
        && !counters.any_predicate_failed();
    if nothing_ran && counters.discovery_recorded {
        if counters.device_path_overflows_libusb()
            && (ident.cpid.is_none() || counters.last_open_error.is_some())
        {
            return device_path_too_long(counters, ident, driver, reset_cap);
        }
        if counters.node_present(crate::DFU_MODE_PID) && counters.last_open_error.is_some() {
            return if driver == DriverClass::Other {
                wrong_driver_bound(counters, ident, driver, reset_cap)
            } else {
                driver_bound_not_loaded(counters, ident, driver, reset_cap)
            };
        }
    }
    let empty_identity = ident.serial.is_empty() && ident.cpid.is_none() && ident.srtg.is_none();
    if matches!(outcome, RunOutcome::NoDevice)
        || (empty_identity
            && nothing_ran
            && driver == DriverClass::Unknown
            && reset_cap == ResetCapability::Unknown)
    {
        return device_absent(counters, ident, driver, reset_cap);
    }

    // 4 ------------------------------------------------------- lost mid-run
    // A NO_DEVICE transfer is the OS saying the device is gone. Any story told
    // about the stages after that is guesswork about hardware that is not there.
    if counters.nodevice > 0 {
        return device_lost_mid_run(counters, ident);
    }

    // 5 -------------------------------------------------------------- identity
    match ident.cpid {
        Some(cpid) => {
            if !A9_CPIDS.contains(&cpid) {
                return unsupported_chip_out(counters, ident, cpid);
            }
            if ident.srtg.is_none() {
                return wrong_boot_stage(counters, ident);
            }
        }
        None => {
            // An unreadable descriptor is only the answer when there is no run to
            // read instead. After a run the device re-enumerates, and main.rs falls
            // back to a default identity if that re-read fails — the sweep's own
            // counters are the stronger measurement, so defer to them and fall back
            // to IDENTITY_UNREADABLE in step 10.
            if counters.total() == 0 && !counters.setup_ran() && !counters.any_predicate_failed() {
                return identity_unreadable(counters, ident, driver, reset_cap);
            }
        }
    }

    // 5 ------------------------------------------------- the config layer said no
    if let (RunOutcome::Unsupported(msg), Some(_)) = (outcome, ident.cpid) {
        return config_row_mismatch(counters, ident, msg);
    }

    // 6 --------------------------------------------------------------- resets
    if counters.resets_attempted > 0
        && counters.resets_real == 0
        && counters.resets_pipe_cycle == 0
    {
        return reset_not_delivered(counters, ident, driver, reset_cap);
    }

    // 7 ----------------------------------------------------------------- SETUP
    // gaster.c:853 is `aborted_sz < overwrite_pad` AND the pad request STALLs.
    // Only classify SETUP when the pass condition was never met: once the pad
    // request has STALLed, SETUP converged and the blocker is downstream.
    if counters.setup_ran() && counters.setup_stall_seen == 0 {
        if counters.setup_attempts == 0 && counters.setup_async_unreported > 0 {
            return abort_window_unreported(counters, ident);
        }
        if counters.abort_window_pinned() {
            return abort_window_pinned(counters, ident);
        }
        if counters.setup_abort_early > 0 {
            return abort_cancelled_early(counters, ident);
        }
        if counters.setup_attempts > 0 && counters.setup_pad_requests == 0 {
            return pad_never_requested(counters, ident);
        }
        if counters.setup_pad_timeouts > 0 {
            return pad_timeout_not_stall(counters, ident, driver, reset_cap);
        }
        if counters.setup_pad_errors > 0 {
            return pad_error_not_stall(counters, ident);
        }
        if counters.setup_attempts > 0 {
            return setup_never_stalled(counters, ident);
        }
    }

    // 9 ----------------------------------------------------------------- SPRAY
    if counters.spray_stall_requests > 0 && counters.spray_stall_not_stalling > 0 {
        return spray_request_not_stalling(counters, ident);
    }
    if counters.spray_leak_requests > 0 && counters.spray_leak_not_zero > 0 {
        return spray_leak_not_zero(counters, ident);
    }

    // 10 -------------------------------------------------- capability unknown
    if reset_cap == ResetCapability::Unknown {
        return reset_capability_unknown(counters, ident, driver, reset_cap);
    }

    // 11 ---------------------------------------------------------- fallthrough
    // A run happened but the chip was never named: say that, rather than blaming
    // the round budget for a failure we cannot even attribute to a SoC.
    if ident.cpid.is_none() {
        return identity_unreadable(counters, ident, driver, reset_cap);
    }
    match outcome {
        RunOutcome::Aborted(msg) => run_aborted(counters, ident, msg),
        RunOutcome::Unsupported(msg) => config_row_mismatch(counters, ident, msg),
        RunOutcome::Exhausted { rounds } => exhausted_unknown(counters, ident, *rounds),
        RunOutcome::NoDevice => device_absent(counters, ident, driver, reset_cap),
        RunOutcome::Pwned => pwned(counters, ident),
    }
}

// ------------------------------------------------------------------- builders

fn hex_or_absent(v: Option<u32>, width: usize) -> String {
    match v {
        Some(x) => format!("0x{x:0width$X}"),
        None => "absent".to_string(),
    }
}

fn some_or_none<T: std::fmt::Display>(v: Option<T>) -> String {
    match v {
        Some(x) => format!("{x}"),
        None => "none".to_string(),
    }
}

/// The census, rendered so that "nothing enumerated" and "nobody looked" cannot
/// be confused — the distinction the README's `--all` self-test exists to make.
fn nodes_render(c: &Counters) -> String {
    if !c.discovery_recorded {
        return "no census taken".to_string();
    }
    if c.nodes_present_by_pid.is_empty() {
        return "recorded, 0 nodes".to_string();
    }
    c.nodes_present_by_pid
        .iter()
        .map(|(p, n)| format!("PID 0x{p:04X}={n}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Names every field of the discovery record, and the method that wrote it. A
/// value nobody can trace is a value we will argue about later.
fn ev_discovery(c: &Counters) -> String {
    format!(
        "trace: discovery recorded={} nodes=[{}] path_len={} open_errno={} open_error={} \
         (Counters.discovery_recorded/nodes_present_by_pid/device_path_len/last_open_errno/\
         last_open_error, written by Tracer::enumerated / Tracer::device_path / Tracer::open_failed)",
        c.discovery_recorded,
        nodes_render(c),
        some_or_none(c.device_path_len),
        some_or_none(c.last_open_errno),
        match c.last_open_error.as_deref() {
            Some(e) => format!("\"{e}\""),
            None => "none".to_string(),
        }
    )
}

/// Names every descriptor field the classification can see. The ECID is never
/// printed — it is device-unique and does not belong in a log.
fn ev_device(id: &DeviceIdentity) -> String {
    format!(
        "device: PID=0x{:04X} CPID={} CPRV={} BDID={} SRTG={} PWND={} serial_len={} (USB serial descriptor)",
        id.pid,
        id.cpid_hex(),
        hex_or_absent(id.cprv, 2),
        hex_or_absent(id.bdid, 2),
        id.srtg
            .as_deref()
            .map(|s| format!("[{s}]"))
            .unwrap_or_else(|| "absent".to_string()),
        id.pwnd.clone().unwrap_or_else(|| "absent".to_string()),
        id.serial.len(),
    )
}

fn ev_usb(driver: DriverClass, cap: ResetCapability) -> String {
    format!(
        "usb: driver_class={} reset_capability={} (Transport::driver_class / Transport::reset_capability, read from the OS)",
        driver.as_str(),
        cap.as_str()
    )
}

fn ev_counts(c: &Counters) -> String {
    format!("trace: {} (Counters, exact)", counters_one_line(c))
}

fn ev_setup(c: &Counters) -> String {
    format!(
        "trace: setup attempts={} pad_requests={} pad_stalls={} pad_timeouts={} pad_errors={} \
         abort_completed_full={} abort_cancelled_early={} unreported_windows={} (Counters.setup_*)",
        c.setup_attempts,
        c.setup_pad_requests,
        c.setup_stall_seen,
        c.setup_pad_timeouts,
        c.setup_pad_errors,
        c.setup_abort_full,
        c.setup_abort_early,
        c.setup_async_unreported
    )
}

fn ev_windows(c: &Counters) -> String {
    format!(
        "trace: abort_sweep={:?} over setup_attempts={} (Counters.abort_sweep, distinct windows in order)",
        c.abort_sweep, c.setup_attempts
    )
}

fn ev_pad_sizes(c: &Counters) -> String {
    format!(
        "trace: distinct pad-request lengths={:?} over {} pad request(s) (Counters.setup_pad_sizes; \
         length = overwrite_pad - transferred, gaster.c:853 — 1280 = 0x500 is gaster's A9 row \
         for SRTG [iBoot-2234.0.0.2.22]/[iBoot-2234.0.0.3.3])",
        c.setup_pad_sizes, c.setup_pad_requests
    )
}

fn ev_resets(c: &Counters) -> String {
    format!(
        "trace: resets_attempted={} resets_real={} resets_pipe_cycle={} (Counters.resets_*, from Tracer::reset)",
        c.resets_attempted, c.resets_real, c.resets_pipe_cycle
    )
}

fn ev_stages(c: &Counters) -> String {
    if c.stage_status.is_empty() {
        return "trace: no per-stage transfer counts were recorded (Counters.stage_status empty)".to_string();
    }
    format!(
        "trace: per-stage transfer counts {} (Counters.stage_status, kind=xfer lines)",
        c.stage_status
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn ev_predicates(c: &Counters) -> Vec<String> {
    if !c.any_predicate_failed() {
        return Vec::new();
    }
    vec![format!(
        "trace: failed reference predicates {} (Counters.predicate_failures, from Tracer::predicate)",
        c.predicate_failures
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    )]
}

fn ev_no_run(c: &Counters) -> Option<String> {
    if c.total() == 0 && !c.setup_ran() {
        Some(
            "trace: no transfers were recorded at all (Counters.total=0) — this verdict is based on \
             the device and driver state, not on a run"
                .to_string(),
        )
    } else {
        None
    }
}

/// The prior session's log, which is what this code exists to name. Cited as
/// INSPECTED because this program did not produce it.
fn ev_prior_setup_log() -> String {
    "prior session (INSPECTED, a9ctl/stage-setup.log): 384 x `SETUP abort_ms=N -> Cancelled len=0` \
     cycling windows 4,5,0,1,2,3 followed by `SETUP pad request (1280 bytes) -> Timeout len=0`"
        .to_string()
}

fn ev_reference(line: &str) -> String {
    format!("reference: {line}")
}

fn push_opt(v: &mut Vec<String>, item: Option<String>) {
    if let Some(s) = item {
        v.push(s);
    }
}

// ------------------------------------------------------------- verdict bodies

fn no_reset_capability(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    cap: ResetCapability,
) -> Verdict {
    let mut evidence = vec![
        format!(
            "usb: driver_class={} reset_capability={} — the reset is the measurement that decides this verdict",
            driver.as_str(),
            cap.as_str()
        ),
        ev_counts(c),
        ev_resets(c),
        ev_setup(c),
        ev_reference(
            "libusb1-sys-0.7.0/libusb/libusb/os/windows_winusb.c:3380-3420: winusbx_reset_device \
             cycles pipes and only calls ResetDevice when sub_api != WinUSB, then returns \
             LIBUSB_SUCCESS either way — the caller cannot tell the two apart",
        ),
        ev_reference(
            "gaster.c:1268 resets after every stage attempt, successful or not; a pipe cycle does \
             not re-arm the bootrom's DFU state, and after PATCH the overwritten dfu_handle_bus_reset \
             callback can never fire",
        ),
    ];
    if driver != DriverClass::WinUsb && cap == ResetCapability::PipeCycleOnly {
        evidence.push(
            "usb: the bound driver is not WinUSB yet the reset measured as a pipe cycle — confirm \
             the node that was opened is USB\\VID_05AC&PID_1227 and not a hub or a sibling interface"
                .to_string(),
        );
    }
    if c.setup_pad_timeouts > 0 {
        evidence.push(format!(
            "trace: setup_pad_timeouts={} of setup_pad_requests={} — the endless pad-request TIMEOUT \
             this verdict predicts",
            c.setup_pad_timeouts, c.setup_pad_requests
        ));
        evidence.push(ev_prior_setup_log());
    }
    push_opt(&mut evidence, ev_no_run(c));
    evidence.push(ev_device(ident));

    Verdict {
        code: NO_RESET_CAPABILITY,
        headline: "The bound driver cannot reset the port, so checkm8 can never fire. This is the \
                   failure that looks like an exploit bug and is not one."
            .to_string(),
        evidence,
        next_action: "Run `a9drv bind --pid 1227` from an ELEVATED prompt to rebind \
                      USB\\VID_05AC&PID_1227 to libusbK, then run `a9pwn preflight` and require it to \
                      print `reset: real bus reset`. Only then `a9pwn run`. (Fallback: \
                      zadig-2.9.exe -> Options -> List All Devices -> 05AC:1227 -> libusbK -> \
                      Install Driver.)"
            .to_string(),
        confidence: Confidence::High,
    }
}

fn pwned(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: PWNED,
        headline: "Pwned: the bootrom's serial descriptor carries the checkm8 marker."
            .to_string(),
        evidence: vec![
            format!(
                "device: PWND={} (USB serial descriptor, re-read after the run)",
                ident.pwnd.clone().unwrap_or_else(|| "absent".to_string())
            ),
            ev_reference(
                "gaster.c:811 sets its `pwned` flag to `strstr(usb_serial_num, \" PWND:[checkm8]\") \
                 != NULL` — that substring is the reference's only success predicate",
            ),
            ev_counts(c),
            ev_resets(c),
        ],
        next_action: "Nothing to do on the exploit side: run `a9pwn ident` to record the PWND marker \
                      and hand the device to your loader. Do not re-run the exploit; the payload is \
                      already resident."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn pwned_unconfirmed(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: PWNED_UNCONFIRMED,
        headline: "The run reported success but the reference's own success marker is absent: treat \
                   this as NOT pwned."
            .to_string(),
        evidence: vec![
            format!(
                "device: PWND={} serial_len={} (USB serial descriptor, re-read after the run)",
                ident.pwnd.clone().unwrap_or_else(|| "absent".to_string()),
                ident.serial.len()
            ),
            ev_reference(
                "gaster.c:811 — success IS `strstr(serial, \" PWND:[checkm8]\")`; a reported success \
                 without that substring contradicts the reference",
            ),
            ev_counts(c),
        ],
        next_action: "Run `a9pwn ident` now: if the PWND marker is absent the device is not pwned. \
                      Re-enter SecureROM DFU (Power+VolDown 8 s, release Power, keep VolDown ~10 s) \
                      and re-run `a9pwn run --rounds 64 --allow-winusb` only after `a9pwn preflight` \
                      prints `reset: real bus reset`."
            .to_string(),
        confidence: Confidence::Low,
    }
}

fn device_absent(c: &Counters, ident: &DeviceIdentity, driver: DriverClass, cap: ResetCapability) -> Verdict {
    // The census decides whether absence is proven or merely assumed, which is
    // exactly the distinction `a9ctl --all` was written to make.
    let census = if !c.discovery_recorded {
        "census: none was taken, so 'absent' here is an inference from a failed open, not a \
         measurement — this is the ambiguity the a9ctl --all self-test exists to remove"
            .to_string()
    } else if c.nodes_total() == 0 {
        "census: recorded and EMPTY — absence is proven, not assumed (the a9ctl --all self-test)"
            .to_string()
    } else if !c.node_present(crate::DFU_MODE_PID) {
        format!(
            "census: {} node(s) enumerated, none with PID 0x{:04X} — enumeration works and the DFU \
             device is simply not attached",
            c.nodes_total(),
            crate::DFU_MODE_PID
        )
    } else {
        format!(
            "census: PID 0x{:04X} IS present ({} node(s)) yet the device still could not be used — \
             this is one of the other three cases, not absence",
            crate::DFU_MODE_PID,
            c.nodes_for_pid(crate::DFU_MODE_PID).unwrap_or(0)
        )
    };
    Verdict {
        code: DEVICE_ABSENT,
        headline: "No usable DFU device: either nothing enumerated or the open never succeeded."
            .to_string(),
        evidence: vec![
            census,
            ev_discovery(c),
            ev_device(ident),
            ev_usb(driver, cap),
            ev_counts(c),
            ev_reference(
                "readmes/a9ctl-README.md: absent device, driver bound but not loaded, driver loaded \
                 but wrong, and a device path too long for libusb all collapse into one message in \
                 the tool this project replaced — this verdict covers only the first of the four",
            ),
        ],
        next_action: "Enter SecureROM DFU (hold Power+VolDown 8 s, release Power, keep VolDown ~10 s) \
                      and run `a9pwn ident`; if it still reports nothing, run \
                      `Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like '*VID_05AC&PID_1227*' }` \
                      to prove whether enumeration itself is the broken part before touching the phone again."
            .to_string(),
        confidence: if c.discovery_recorded && c.nodes_total() == 0 {
            Confidence::High
        } else {
            Confidence::Medium
        },
    }
}

/// The README's fourth case: libusb cannot even see the node. The predicate is the
/// caller's; this builder only reports the measurement.
fn device_path_too_long(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    cap: ResetCapability,
) -> Verdict {
    Verdict {
        code: DEVICE_PATH_TOO_LONG,
        headline: format!(
            "The device instance path is {} bytes, at or beyond libusb's {}-byte buffer: libusb \
             skips this node with nothing but a warning, so no open can ever succeed.",
            some_or_none(c.device_path_len),
            crate::trace::LIBUSB_DEV_ID_CAPACITY
        ),
        evidence: vec![
            format!(
                "trace: device_path_len={} measured by our own SetupAPI pass (Counters.device_path_len, \
                 Tracer::device_path) — libusb never reports it, because it skips the node instead",
                some_or_none(c.device_path_len)
            ),
            ev_discovery(c),
            ev_reference(
                "libusb/os/windows_winusb.h:37 `#define MAX_PATH_LENGTH 256`; windows_winusb.c:1599 \
                 `char dev_id[MAX_PATH_LENGTH];`; windows_winusb.c:1719 \
                 `SetupDiGetDeviceInstanceIdA(..., dev_id, sizeof(dev_id), NULL)` — that call needs \
                 room for the ID plus its terminator, and :1719-1723 answers failure with \
                 `usbi_warn(... \"skipping\")` and `continue`",
            ),
            ev_device(ident),
            ev_usb(driver, cap),
            ev_counts(c),
        ],
        next_action: "Do not chase the exploit; nothing can open this node. Run `a9pwn ident` to print \
                      the measured path length, then plug the iPhone directly into a root port (no hub, \
                      no extension cable) and re-run it. If the length stays at or above 256, the \
                      vendored libusb's `char dev_id[256]` must be raised in libusb1-sys-0.7.0 — that \
                      is a dependency decision for the Lead, not a run-time flag."
            .to_string(),
        confidence: Confidence::High,
    }
}

/// A node is present and the open failed with a non-libusb driver bound.
fn wrong_driver_bound(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    cap: ResetCapability,
) -> Verdict {
    Verdict {
        code: WRONG_DRIVER_BOUND,
        headline: format!(
            "A DFU node is present and the bound service is `{}` — not a libusb driver — so the open \
             fails because the wrong driver owns the device.",
            driver.as_str()
        ),
        evidence: vec![
            format!(
                "trace: the census proves a PID 0x{:04X} node exists ({} node(s)) and an open error was \
                 recorded (Counters.nodes_present_by_pid, Counters.last_open_error)",
                crate::DFU_MODE_PID,
                c.nodes_for_pid(crate::DFU_MODE_PID).unwrap_or(0)
            ),
            ev_discovery(c),
            format!(
                "usb: driver_class={} — a readable, non-libusb service is bound to the node \
                 (Transport::driver_class reads the bound service, it does not guess)",
                driver.as_str()
            ),
            ev_reference(
                "readmes/a9ctl-README.md: `driver loaded but wrong` is one of the four cases the C++ \
                 tool printed as `Could not find device in DFU mode!`",
            ),
            ev_device(ident),
            ev_counts(c),
        ],
        next_action: format!(
            "Run `a9drv bind --pid 1227` from an ELEVATED prompt to replace the `{}` binding on \
             USB\\VID_05AC&PID_1227 with libusbK, then `a9pwn ident` must print `driver service: \
             libusbK` and `reset: real bus reset` before `a9pwn run`.",
            driver.as_str()
        ),
        confidence: Confidence::High,
    }
}

/// A node is present, the open failed, and no *wrong* driver can be named: either
/// the service could not be read at all, or a libusb driver is bound and still
/// refused the node.
fn driver_bound_not_loaded(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    cap: ResetCapability,
) -> Verdict {
    let why = if driver == DriverClass::Unknown {
        "usb: the bound driver service could not be read at all, so `which driver` is unknown — that \
         is why this is not reported as WRONG_DRIVER_BOUND"
            .to_string()
    } else {
        format!(
            "usb: driver_class={} is already a libusb driver, yet the open still failed — the node is \
             not usable rather than mis-bound",
            driver.as_str()
        )
    };
    Verdict {
        code: DRIVER_BOUND_NOT_LOADED,
        headline: format!(
            "A DFU node is present and the open still failed: the driver is bound but the device is \
             not usable (not started, or held by another handle). Observed: {}.",
            c.last_open_error.as_deref().unwrap_or("no open error recorded")
        ),
        evidence: vec![
            format!(
                "trace: the census proves a PID 0x{:04X} node exists ({} node(s)) and an open error was \
                 recorded: errno={} {} (Counters.nodes_present_by_pid, Counters.last_open_errno, \
                 Counters.last_open_error)",
                crate::DFU_MODE_PID,
                c.nodes_for_pid(crate::DFU_MODE_PID).unwrap_or(0),
                some_or_none(c.last_open_errno),
                c.last_open_error.as_deref().unwrap_or("none")
            ),
            ev_discovery(c),
            why,
            ev_reference(
                "readmes/a9ctl-README.md: `driver bound but not loaded (needs re-enumeration)` is one \
                 of the four cases the C++ tool printed as `Could not find device in DFU mode!`",
            ),
            ev_device(ident),
            ev_counts(c),
        ],
        next_action: "Re-enumerate the node: run `pnputil /scan-devices` from an elevated prompt (or \
                      unplug and replug the cable), and close any process still holding it — a stale \
                      `a9ctl` or `king.exe` from an earlier session keeps the node unopenable. Then run \
                      `a9pwn ident` and require a non-empty `serial` line. If the open error repeats \
                      with libusbK already bound, re-run `a9drv bind --pid 1227` elevated."
            .to_string(),
        confidence: Confidence::Medium,
    }
}

/// The device was present and then reported `NO_DEVICE`: it went away mid-run.
fn device_lost_mid_run(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: DEVICE_LOST_MID_RUN,
        headline: format!(
            "The device was present and then went away mid-run: {} transfer(s) reported NO_DEVICE, so \
             nothing classified after that point describes the exploit.",
            c.nodevice
        ),
        evidence: vec![
            format!(
                "trace: nodevice={} of {} transfers; the stage/status records put it at: {} \
                 (Counters.nodevice, Counters.total, Counters.stage_status)",
                c.nodevice,
                c.total(),
                c.stages_with_status(crate::types::XferStatus::NoDevice)
            ),
            ev_counts(c),
            ev_stages(c),
            ev_reference(
                "gaster.c:206-215 reopens from scratch in `wait_usb_handle` whenever the handle is \
                 lost; a device that disappears mid-sweep is a link, port or power fault, never a \
                 protocol result",
            ),
            ev_device(ident),
        ],
        next_action: "Power-cycle the phone, plug it directly into a root port with the cable that \
                      worked for `a9pwn ident` (no hub, no extension), re-enter SecureROM DFU, then \
                      re-run `a9pwn run --stage setup --setup-budget 64 --trace run.jsonl --verbose` \
                      and read the `per stage` line of the summary to see which stage lost it."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn identity_unreadable(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    cap: ResetCapability,
) -> Verdict {
    Verdict {
        code: IDENTITY_UNREADABLE,
        headline: "A device answered but its serial descriptor yielded no CPID: we cannot name the \
                   chip, so no failure downstream of this can be trusted."
            .to_string(),
        evidence: vec![
            ev_device(ident),
            ev_usb(driver, cap),
            ev_counts(c),
            ev_reference(
                "gaster.c:498-511,519-816: every parameter is chosen by `strstr` on the serial \
                 descriptor; with an unreadable descriptor the reference sets cpid = 0 and \
                 `wait_usb_handle` (gaster.c:206-215, :1243) loops forever printing nothing",
            ),
            ev_reference(
                "readmes/a9ctl-README.md: `driver bound but not loaded` and `device path too long for \
                 an unpatched libusb` both present exactly like this — an empty or truncated serial",
            ),
        ],
        next_action: "Run `a9pwn ident --verbose` and read the `serial` line: an empty or truncated \
                      serial means the descriptor read failed, not that the phone is absent. Rebind \
                      the node with `a9drv bind --pid 1227` from an elevated prompt, re-enumerate, and \
                      retry; if the serial is still short, the device path is longer than libusb's \
                      buffer."
            .to_string(),
        confidence: Confidence::Medium,
    }
}

fn unsupported_chip_out(c: &Counters, ident: &DeviceIdentity, cpid: u32) -> Verdict {
    Verdict {
        code: UNSUPPORTED_CHIP,
        headline: format!(
            "CPID 0x{cpid:04X} is outside the A9 table: this payload is the wrong exploit for this chip."
        ),
        evidence: vec![
            ev_device(ident),
            format!(
                "config: the A9 membership test is CPID in {{0x8000, 0x8003}} (s8000 'Maui', s8003 \
                 'Malta'); the observed CPID is 0x{cpid:04X}"
            ),
            ev_reference(
                "gaster.c:1050-1064 routes any CPID outside {0x8960,0x7001,0x7000,0x8003,0x8000,...} \
                 to the generic notA9 payload, and gaster.c:624,641 give A9 its own rows",
            ),
            ev_counts(c),
        ],
        next_action: format!(
            "Do not run the A9 payload against 0x{cpid:04X}. Run `a9pwn ident` to confirm the CPID, \
             then use a checkm8 build that carries a row for it — A10/A11 need the notA9 path with \
             different gadgets and must not be ported to A9."
        ),
        confidence: Confidence::High,
    }
}

fn wrong_boot_stage(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: WRONG_BOOT_STAGE,
        headline: "SRTG is absent: this is iBSS DFU, not SecureROM DFU. checkm8's SecureROM \
                   predicates do not apply here."
            .to_string(),
        evidence: vec![
            ev_device(ident),
            format!(
                "device: CPID={} parsed, SRTG absent — PID 0x1227 alone cannot tell SecureROM DFU \
                 from iBSS DFU, so SRTG is the gate (a9lab/findings.jsonl F007)",
                ident.cpid_hex()
            ),
            ev_reference(
                "gaster.c:519-816 selects every config by `strstr(serial, \" SRTG:[...\")`; with no \
                 SRTG the match fails, cpid stays 0, and `wait_usb_handle` loops forever",
            ),
            ev_counts(c),
        ],
        next_action: "Get the phone into SecureROM DFU: hard power-off (Power+VolDown until the screen \
                      goes black), then hold Power+VolDown 8 s, release Power, keep VolDown ~10 s. Run \
                      `a9pwn ident` and require a non-empty `SRTG` line before `a9pwn run`."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn config_row_mismatch(c: &Counters, ident: &DeviceIdentity, msg: &str) -> Verdict {
    let mut evidence = vec![
        format!("outcome: RunOutcome::Unsupported(\"{msg}\")"),
        ev_device(ident),
        "deviation by design: the reference WOULD HAVE PROCEEDED here and we did not. gaster.c:624,641 \
         select the A9 row from the SRTG substring alone, so any A9 in SecureROM DFU takes that path; \
         our `config_for_identity` keys on the parsed identity and refuses a pair it has no row for. \
         The refusal is therefore stricter than the reference, and deliberate — it is not a bug in \
         our port, and a reader comparing this log with gaster's must not read it as one."
            .to_string(),
        ev_reference(
            "gaster.c:624 `SRTG:[iBoot-2234.0.0.2.22]` -> cpid 0x8003 and gaster.c:641 \
             `SRTG:[iBoot-2234.0.0.3.3]` -> cpid 0x8000: the key is the SRTG string, not CPID/CPRV",
        ),
        ev_counts(c),
    ];
    if ident
        .srtg
        .as_deref()
        .map(|s| s.contains(A9_SRTG_MARKER))
        .unwrap_or(false)
    {
        evidence.push(format!(
            "device: SRTG shares gaster's A9 marker \"{A9_SRTG_MARKER}\" while the config lookup \
             refused the identity — the refusal is a table key, not the chip"
        ));
    }
    push_opt(&mut evidence, ev_no_run(c));
    Verdict {
        code: CONFIG_ROW_MISMATCH,
        headline: "The config table refused an identity the reference would have accepted. This is a \
                   table-key mismatch, not an unsupported chip."
            .to_string(),
        evidence,
        next_action: "Run `a9pwn selftest` to print the config table and `a9pwn plan` to see which row \
                      was refused; if SRTG is [iBoot-2234.0.0.2.22] or [iBoot-2234.0.0.3.3] while \
                      CPID/CPRV is not a listed pair, add the row keyed on SRTG as the reference does \
                      (gaster.c:624,641)."
            .to_string(),
        confidence: Confidence::Medium,
    }
}

fn reset_not_delivered(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    cap: ResetCapability,
) -> Verdict {
    Verdict {
        code: RESET_NOT_DELIVERED,
        headline: "Resets were attempted and none was recorded as delivered: the bootrom's DFU state \
                   is never re-armed between stages."
            .to_string(),
        evidence: vec![
            ev_resets(c),
            ev_usb(driver, cap),
            ev_reference(
                "gaster.c:1231-1276: a reset follows every stage attempt, and after PATCH the \
                 overwritten dfu_handle_bus_reset callback is what completes the exploit",
            ),
            format!(
                "trace: resets_real=0 and resets_pipe_cycle=0 over resets_attempted={} — either the \
                 call failed outright or the run did not record which kind it was",
                c.resets_attempted
            ),
            ev_counts(c),
            ev_device(ident),
        ],
        next_action: "Run `a9pwn reset` and read its `capability` and `what happened` lines; if they \
                      report an error or a pipe cycle, rebind with `a9drv bind --pid 1227` from an \
                      elevated prompt. Do not raise --rounds: more rounds cannot help when the reset \
                      is not being delivered."
            .to_string(),
        confidence: Confidence::Medium,
    }
}

fn abort_window_unreported(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: ABORT_WINDOW_UNREPORTED,
        headline: "The async SETUP transfers carry no abort window, so the sweep cannot be audited. \
                   The exploit's timing parameter is unobservable."
            .to_string(),
        evidence: vec![
            format!(
                "trace: setup_async_unreported={} async DFU_DNLOAD transfers with abort_after_ms=None; \
                 abort_sweep={:?} (Counters.setup_async_unreported, Counters.abort_sweep)",
                c.setup_async_unreported, c.abort_sweep
            ),
            ev_setup(c),
            ev_reference(
                "gaster.c:849,857: the sweep's entire state is `usb_abort_timeout`; INTERFACE.md §2 \
                 requires Transport::control_async_abort to take cancel_after_ms and types.rs carries \
                 it as XferResult.abort_after_ms, so a missing value is a missing measurement",
            ),
            ev_device(ident),
        ],
        next_action: "Fix the transport before running again: `Transport::control_async_abort` must \
                      return `XferResult.abort_after_ms = Some(cancel_after_ms)`. Then re-run \
                      `a9pwn run --stage setup --trace setup.jsonl --verbose` and confirm the abort \
                      lines carry `\"abort_after_ms\":N` in setup.jsonl."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn abort_window_pinned(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: ABORT_WINDOW_PINNED,
        headline: "The abort window never advanced: the sweep is a single point, so checkm8's timing \
                   parameter is never explored and SETUP cannot converge."
            .to_string(),
        evidence: vec![
            format!(
                "trace: abort_sweep={:?} over setup_attempts={} — two or more attempts with one \
                 distinct window (Counters.abort_sweep, Counters.setup_attempts)",
                c.abort_sweep, c.setup_attempts
            ),
            ev_setup(c),
            ev_reference(
                "gaster.c:857 `usb_abort_timeout = (t + 1) % (usb_timeout - abort_min + 1) + abort_min` \
                 collapses to a single value when usb_timeout == abort_min; gaster.c:1635-1638 resets \
                 abort_min to 0 only when abort_min > usb_timeout, so equality survives and pins the sweep",
            ),
            ev_device(ident),
        ],
        next_action: "Re-run with distinct bounds: `a9pwn run --stage setup --abort-min-ms 0 \
                      --usb-timeout-ms 5 --trace setup.jsonl --verbose`, then check that abort_sweep \
                      in the summary walks 4,5,0,1,2,3. If it still does not advance, the window \
                      update in `stage_setup` is the defect."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn abort_cancelled_early(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: ABORT_CANCELLED_EARLY,
        headline: "The abort cancelled transfers before their own window elapsed: the primitive never \
                   waited, so the transfer never reached the wire."
            .to_string(),
        evidence: vec![
            format!(
                "trace: setup_abort_early={} CANCELLED transfers with abort_after_ms >= 1 ms and \
                 XferResult.micros < 100 us (Counters.setup_abort_early)",
                c.setup_abort_early
            ),
            ev_windows(c),
            ev_setup(c),
            ev_reference(
                "readmes/a9ctl-README.md `stall()`: the C++ primitive computed `t = timeout/1000` from \
                 a one-second clock while callers passed 0.0001 s, so the wait loop ran zero times; \
                 that same primitive is what creates checkm8's use-after-free",
            ),
            ev_device(ident),
        ],
        next_action: "Grep the trace for the evidence before changing anything: \
                      `Select-String -Path setup.jsonl -Pattern '\"status\":\"CANCELLED\"'` and compare \
                      `xfer_micros` with `abort_after_ms` on each line. Then re-run \
                      `a9pwn run --stage setup --usb-timeout-ms 5 --abort-min-ms 0 --trace setup.jsonl \
                      --verbose` and require at least one CANCELLED line whose xfer_micros is close to \
                      its abort_after_ms in milliseconds."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn pad_never_requested(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: PAD_NEVER_REQUESTED,
        headline: "No pad request was ever sent: the first clause of gaster's SETUP predicate never \
                   held, so the STALL the exploit needs was never even attempted."
            .to_string(),
        evidence: vec![
            format!(
                "trace: setup_attempts={} with setup_pad_requests=0, setup_abort_full={} \
                 (Counters.setup_attempts / setup_pad_requests / setup_abort_full)",
                c.setup_attempts, c.setup_abort_full
            ),
            ev_windows(c),
            ev_reference(
                "gaster.c:853 — the pad request is only reached when `transfer_ret.sz < \
                 config_overwrite_pad`; a full transfer (0x800 bytes, gaster.c:853's DFU_MAX_TRANSFER_SZ) \
                 means the abort did not truncate it, so the branch is never taken",
            ),
            ev_device(ident),
        ],
        next_action: "Re-run `a9pwn run --stage setup --trace setup.jsonl --verbose` and read the \
                      abort lines: `xfer=2048/2048` with `abort=Nms` means the cancel lost the race \
                      with completion. Shorten the window (`--abort-min-ms 0 --usb-timeout-ms 5`) and \
                      confirm a pad request appears in the trace before touching SPRAY or PATCH."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn pad_timeout_not_stall(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    cap: ResetCapability,
) -> Verdict {
    let mut evidence = vec![
        format!(
            "trace: setup_pad_timeouts={} of setup_pad_requests={} — every pad request TIMED_OUT, so \
             the device is NAKing EP0 (Counters.setup_pad_timeouts / setup_pad_requests)",
            c.setup_pad_timeouts, c.setup_pad_requests
        ),
        ev_pad_sizes(c),
        ev_windows(c),
        ev_setup(c),
        ev_reference(
            "gaster.c:853 requires `transfer_ret.ret == USB_TRANSFER_STALL` on the pad request; a \
             TIMEOUT is a different USB fact (the endpoint is not answering) and means SETUP never \
             converged",
        ),
        ev_prior_setup_log(),
        ev_device(ident),
    ];
    if cap != ResetCapability::Real {
        evidence.push(ev_usb(driver, cap));
        evidence.push(
            "usb: the reset capability is not established as real, and a reset that only cycles pipes \
             produces exactly this endless pad TIMEOUT — rule that out before touching the abort window"
                .to_string(),
        );
    } else {
        evidence.push(ev_usb(driver, cap));
    }

    Verdict {
        code: PAD_TIMEOUT_NOT_STALL,
        headline: "The pad request TIMED OUT instead of STALLing: the device is NAKing, so SETUP never \
                   converged and no STALL was ever available to detect."
            .to_string(),
        evidence,
        next_action: "Rule out the Windows reset trap first: `a9pwn ident` and require \
                      `reset: real bus reset`; if it does not say that, run `a9drv bind --pid 1227` \
                      elevated and retry. If the reset is real, re-run \
                      `a9pwn run --stage setup --abort-min-ms 1 --usb-timeout-ms 5 --trace setup.jsonl \
                      --verbose` (drops window 0, the zero-microsecond abort) and require at least one \
                      abort line with `xfer=0/2048` and `xfer_micros` near its window."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn pad_error_not_stall(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: PAD_ERROR_NOT_STALL,
        headline: "The pad request failed at the host, not on the device: this is a transport fault, \
                   not the bootrom refusing the request."
            .to_string(),
        evidence: vec![
            format!(
                "trace: setup_pad_errors={} of setup_pad_requests={} — pad requests returned \
                 XferStatus::Error or NoDevice (Counters.setup_pad_errors)",
                c.setup_pad_errors, c.setup_pad_requests
            ),
            ev_setup(c),
            ev_counts(c),
            ev_reference(
                "gaster.c:226-240 maps LIBUSB_ERROR_PIPE to STALL and everything else to \
                 USB_TRANSFER_ERROR, so an Error here is a pipe or node failure that the reference \
                 would also have reported as ERROR — not as the STALL it needs",
            ),
            ev_device(ident),
        ],
        next_action: "Run `a9pwn run --stage setup --trace setup.jsonl --verbose` and read the pad \
                      lines' `libusb_rc`: -1 (LIBUSB_ERROR_IO) or -4 (LIBUSB_ERROR_NO_DEVICE) means the \
                      pipe or the node died mid-sweep. Power-cycle the phone, rebind with \
                      `a9drv bind --pid 1227` elevated, confirm with `a9pwn ident`, then retry."
            .to_string(),
        confidence: Confidence::Medium,
    }
}

fn setup_never_stalled(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    Verdict {
        code: SETUP_NEVER_STALLED,
        headline: "SETUP exhausted its budget without the pad request ever STALLing. The heap \
                   corruption the rest of the exploit depends on did not happen."
            .to_string(),
        evidence: vec![
            format!(
                "trace: setup_attempts={} setup_stall_seen=0 with setup_pad_timeouts={} and \
                 setup_pad_errors={} — pad requests were sent and none of them ended in the pass \
                 condition (Counters.setup_*)",
                c.setup_attempts, c.setup_pad_timeouts, c.setup_pad_errors
            ),
            ev_windows(c),
            ev_pad_sizes(c),
            ev_setup(c),
            ev_reference(
                "gaster.c:848-860: the loop is unbounded and its only exit is the pad request STALLing; \
                 the abort window starts at usb_timeout - 1 (gaster.c:849) and advances by one on every \
                 failed attempt (gaster.c:857)",
            ),
            ev_device(ident),
        ],
        next_action: "Get a complete record of the sweep: `a9pwn run --stage setup --setup-budget 64 \
                      --trace setup.jsonl --verbose`, then check in the summary that abort_sweep walks \
                      4,5,0,1,2,3 and that pad_sizes shows the length each pad request used \
                      (1280 = 0x500 is gaster's A9 row). If the windows or lengths are wrong, the \
                      defect is in `stage_setup`, not in the timing."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn spray_request_not_stalling(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    let mut evidence = vec![
        format!(
            "trace: spray_stall_requests={} of which spray_stall_not_stalling={} — the request \
             bm=0x02 b=0x03 wIndex=0x80 did not return STALL (Counters.spray_*)",
            c.spray_stall_requests, c.spray_stall_not_stalling
        ),
        ev_stages(c),
        ev_reference(
            "gaster.c:890-894 `checkm8_usb_request_stall` returns true only when that request STALLs; \
             gaster.c:901-902 makes it the first clause of the A9 spray loop's exit condition",
        ),
        ev_device(ident),
    ];
    evidence.extend(ev_predicates(c));
    evidence.push(ev_counts(c));

    Verdict {
        code: SPRAY_REQUEST_NOT_STALLING,
        headline: "The spray loop's USB request is not returning the STALL the reference requires, so \
                   the loop spins forever."
            .to_string(),
        evidence,
        next_action: "Capture the exact status: `a9pwn run --stage spray --trace spray.jsonl --verbose` \
                      and read the lines whose `bm_request_type` is 2 and `b_request` is 3. A status of \
                      OK or TIMEOUT there means the bootrom is not diverting the request; re-check that \
                      SETUP actually reached its STALL first, because SPRAY's predicates are downstream \
                      of SETUP's heap state."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn spray_leak_not_zero(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    let mut evidence = vec![
        format!(
            "trace: spray_leak_requests={} of which spray_leak_not_zero={} — the serial-descriptor \
             reads (IN GET_DESCRIPTOR, wLength 0x40 and 0xC1) returned bytes where gaster requires \
             zero (Counters.spray_*, from `transferred`, not from status)",
            c.spray_leak_requests, c.spray_leak_not_zero
        ),
        ev_stages(c),
        ev_reference(
            "gaster.c:866 `checkm8_usb_request_leak` and gaster.c:886 `checkm8_no_leak` both require \
             `transfer_ret.sz == 0`; gaster.c:875-879 is the same predicate with a sweeping abort window",
        ),
        ev_reference(
            "INTERFACE.md §4: LEAK_WINDEX_GASTER = 0x0A, LEAK_WINDEX_IPWNDFU = 0x00 — the one \
             parameter this project has not resolved on hardware",
        ),
        ev_device(ident),
    ];
    evidence.extend(ev_predicates(c));
    evidence.push(ev_counts(c));

    Verdict {
        code: SPRAY_LEAK_NOT_ZERO,
        headline: "The leak predicate never returned zero bytes: the serial-descriptor read is being \
                   served normally instead of being cut off by the corrupted state."
            .to_string(),
        evidence,
        next_action: "Try the other leak index, which is the unresolved parameter on this device: \
                      `a9pwn run --stage spray --leak-windex-ipwndfu --trace spray.jsonl --verbose` \
                      (wIndex 0x00 instead of gaster's 0x0A). Read `spray_leak_not_zero` in the summary \
                      afterwards: zero means the index was the problem, non-zero means the corruption \
                      is not happening at all and belongs to SETUP."
            .to_string(),
        confidence: Confidence::Medium,
    }
}

fn reset_capability_unknown(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    cap: ResetCapability,
) -> Verdict {
    let mut evidence = vec![
        ev_usb(driver, cap),
        ev_reference(
            "readmes/a9ctl-README.md: on Windows a reset can silently be a pipe cycle, which decides \
             whether checkm8 can fire at all — an unknown capability means the decisive fact was not \
             measured",
        ),
        ev_counts(c),
        ev_stages(c),
        ev_device(ident),
    ];
    push_opt(&mut evidence, ev_no_run(c));
    Verdict {
        code: RESET_CAPABILITY_UNKNOWN,
        headline: "The reset capability was never established. This is not the same as 'no capability' \
                   — it is a missing measurement, and it is the one this exploit depends on."
            .to_string(),
        evidence,
        next_action: "Run `a9pwn reset` (a bare port reset) and read its `capability` line, then run \
                      `a9pwn preflight`. If either reports `pipe cycle only`, run \
                      `a9drv bind --pid 1227` from an elevated prompt and repeat until `a9pwn ident` \
                      prints `reset: real bus reset`."
            .to_string(),
        confidence: Confidence::Low,
    }
}

fn exhausted_unknown(c: &Counters, ident: &DeviceIdentity, rounds: u32) -> Verdict {
    let mut evidence = vec![format!("outcome: RunOutcome::Exhausted {{ rounds: {rounds} }}")];
    if c.rounds > 0 {
        evidence.push(format!(
            "trace: counters.rounds={} (Counters.rounds, from Tracer::round) against the outcome's \
             {rounds} — the two records of the same number",
            c.rounds
        ));
    } else {
        evidence.push(
            "trace: counters.rounds=0 — the stage machine reported no round boundaries through \
             Tracer::round, so the outcome's round count is the only record of it"
                .to_string(),
        );
    }
    evidence.extend([
        ev_counts(c),
        ev_stages(c),
        ev_setup(c),
        ev_resets(c),
        ev_device(ident),
    ]);
    if c.setup_stall_seen > 0 {
        evidence.push(format!(
            "trace: setup_stall_seen={} — SETUP DID reach its pass condition, so the blocker is \
             downstream (SPRAY/PATCH), not in the sweep",
            c.setup_stall_seen
        ));
    }
    if !c.setup_ran() {
        evidence.push(
            "trace: no SETUP activity and no SPRAY predicates were recorded — the run did not \
             exercise the stages that carry the signatures this taxonomy knows"
                .to_string(),
        );
    }
    evidence.extend(ev_predicates(c));

    Verdict {
        code: EXHAUSTED_UNKNOWN,
        headline: "Rounds exhausted with no classified signature. The counters below are the full \
                   measurement — nothing here matched a known failure."
            .to_string(),
        evidence,
        next_action: "Re-run with a trace and a bounded budget so the record is complete: \
                      `a9pwn run --rounds 8 --setup-budget 64 --trace run.jsonl --verbose`, then read \
                      the `per stage` line of the summary to see which stage produced transfers and \
                      `abort_windows=` to see whether the sweep advanced."
            .to_string(),
        confidence: Confidence::Low,
    }
}

fn run_aborted(c: &Counters, ident: &DeviceIdentity, msg: &str) -> Verdict {
    let mut evidence = vec![
        format!("outcome: RunOutcome::Aborted(\"{msg}\") — the run stopped deliberately"),
        ev_counts(c),
        ev_stages(c),
        ev_device(ident),
    ];
    push_opt(&mut evidence, ev_no_run(c));
    Verdict {
        code: RUN_ABORTED,
        headline: format!("The run was stopped before it could be classified: {msg}"),
        evidence,
        next_action: format!(
            "Re-run the stage named in the message with a trace: `a9pwn run --stage setup --trace \
             setup.jsonl --verbose`, then read the last line of setup.jsonl — \"{msg}\" is the \
             transport's own message and is the only description of the cause"
        ),
        confidence: Confidence::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::Tracer;
    use crate::types::{Stage, XferResult, XferStatus};

    fn xf(
        status: XferStatus,
        bm: u8,
        b: u8,
        w_index: u16,
        w_len: u16,
        transferred: usize,
        abort_after_ms: Option<u32>,
    ) -> XferResult {
        XferResult {
            seq: 1,
            bm_request_type: bm,
            b_request: b,
            w_value: 0,
            w_index,
            w_length: w_len,
            status,
            transferred,
            requested: w_len as usize,
            micros: 2000,
            libusb_rc: 0,
            abort_after_ms,
        }
    }

    fn ident_a9() -> DeviceIdentity {
        DeviceIdentity::parse(
            "CPID:8003 CPRV:01 CPFM:03 SCEP:01 BDID:02 ECID:00112233445566AA IBFL:1C \
             SRTG:[IBOOT-2234.0.0.2.22]",
        )
    }

    fn exhausted(rounds: u32) -> RunOutcome {
        RunOutcome::Exhausted { rounds }
    }

    /// Build a counter set in one expression: `Default::default()` followed by
    /// field assignment is a clippy lint and, more importantly, reads as if the
    /// fields were an afterthought rather than the measurement.
    fn counters(set: impl FnOnce(&mut Counters)) -> Counters {
        let mut c = Counters::default();
        set(&mut c);
        c
    }

    /// Replays `a9ctl/stage-setup.log` through the real Tracer: 384 rounds of an
    /// aborted DNLOAD cancelled after window N, followed by a pad request of 1280
    /// bytes that TIMED OUT.
    fn setup_log_counters() -> Counters {
        let mut t = Tracer::new(None, false).expect("tracer");
        let windows = [4u32, 5, 0, 1, 2, 3];
        for i in 0..384 {
            let w = windows[i % 6];
            let mut abort = xf(XferStatus::Cancelled, 0x21, 1, 0, 0x800, 0, Some(w));
            abort.micros = 3001;
            t.xfer(Stage::Setup, "async-abort", &abort);
            t.xfer(
                Stage::Setup,
                "pad-request",
                &xf(XferStatus::Timeout, 0x00, 0x00, 0, 1280, 0, None),
            );
        }
        t.counters()
    }

    #[test]
    fn required_table_codes_are_all_present() {
        for code in [
            PWNED,
            NO_RESET_CAPABILITY,
            SETUP_NEVER_STALLED,
            PAD_TIMEOUT_NOT_STALL,
            DEVICE_ABSENT,
            UNSUPPORTED_CHIP,
            WRONG_BOOT_STAGE,
            EXHAUSTED_UNKNOWN,
        ] {
            assert!(CODES.contains(&code), "{code} missing from CODES");
        }
    }

    #[test]
    fn codes_are_unique_and_uppercase() {
        let mut seen = std::collections::BTreeSet::new();
        for code in CODES {
            assert_eq!(*code, code.to_ascii_uppercase(), "{code} is not uppercase");
            assert!(seen.insert(*code), "{code} duplicated");
        }
        assert_eq!(seen.len(), CODES.len());
    }

    /// The required distinction: a pad-request TIMEOUT and a SETUP sweep that
    /// never stalled are different problems and must not share a code.
    #[test]
    fn pad_timeout_and_setup_never_stalled_get_different_codes() {
        // (a) the a9ctl/stage-setup.log signature: pad requests TIMED OUT.
        let timed_out = setup_log_counters();
        let a = classify(
            &exhausted(64),
            &timed_out,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(a.code, PAD_TIMEOUT_NOT_STALL, "{:?}", a);

        // (b) pad requests were sent and answered, the sweep walked every window,
        //     and the pass condition still never arrived.
        let mut t = Tracer::new(None, false).expect("tracer");
        let windows = [4u32, 5, 0, 1, 2, 3];
        for i in 0..384 {
            let w = windows[i % 6];
            let mut abort = xf(XferStatus::Cancelled, 0x21, 1, 0, 0x800, 0, Some(w));
            abort.micros = 3001;
            t.xfer(Stage::Setup, "async-abort", &abort);
            t.xfer(
                Stage::Setup,
                "pad-request",
                &xf(XferStatus::Ok, 0x00, 0x00, 0, 1280, 1280, None),
            );
        }
        let answered = t.counters();
        let b = classify(
            &exhausted(64),
            &answered,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(b.code, SETUP_NEVER_STALLED, "{:?}", b);

        assert_ne!(a.code, b.code);
        assert_eq!(a.code, "PAD_TIMEOUT_NOT_STALL");
        assert_eq!(b.code, "SETUP_NEVER_STALLED");
    }

    #[test]
    fn the_prior_session_signature_is_no_reset_capability_under_winusb() {
        let c = setup_log_counters();
        let v = classify(
            &exhausted(64),
            &c,
            &ident_a9(),
            DriverClass::WinUsb,
            ResetCapability::PipeCycleOnly,
        );
        assert_eq!(v.code, NO_RESET_CAPABILITY);
        assert_eq!(v.confidence, Confidence::High);
        let all = v.evidence.join("\n");
        assert!(all.contains("driver_class=WinUSB"), "{all}");
        assert!(all.contains("pipe cycle only"), "{all}");
        assert!(all.contains("windows_winusb.c:3380-3420"), "{all}");
        assert!(all.contains("setup_pad_timeouts=384"), "{all}");
        assert!(v.next_action.contains("a9drv bind --pid 1227"), "{}", v.next_action);
        assert!(v.next_action.contains("elevated") || v.next_action.contains("ELEVATED"));

        // The same counters with a driver that can reset must NOT be blamed on the
        // driver: that is the whole point of the taxonomy.
        let v2 = classify(
            &exhausted(64),
            &c,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v2.code, PAD_TIMEOUT_NOT_STALL);
        assert!(v2.evidence.join("\n").contains("a9ctl/stage-setup.log"));
    }

    #[test]
    fn measured_pipe_cycles_outrank_the_live_probe() {
        let c = counters(|c| {
            c.resets_attempted = 6;
            c.resets_pipe_cycle = 6;
        });
        let v = classify(
            &exhausted(6),
            &c,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, NO_RESET_CAPABILITY, "a measured pipe cycle must win");
        assert!(v.evidence.join("\n").contains("resets_pipe_cycle=6"));
    }

    #[test]
    fn success_requires_the_reference_marker() {
        let pwned = DeviceIdentity::parse(
            "CPID:8003 CPRV:01 BDID:02 ECID:00112233445566AA SRTG:[IBOOT-2234.0.0.2.22] \
             PWND:[checkm8]",
        );
        let v = classify(
            &RunOutcome::Pwned,
            &Counters::default(),
            &pwned,
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, PWNED);
        assert_eq!(v.confidence, Confidence::High);

        let unconfirmed = classify(
            &RunOutcome::Pwned,
            &Counters::default(),
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(unconfirmed.code, PWNED_UNCONFIRMED);
        assert!(unconfirmed.evidence.join("\n").contains("gaster.c:811"));
    }

    #[test]
    fn degenerate_inputs_are_classified_honestly() {
        // Nothing attached at all.
        let absent = classify(
            &RunOutcome::NoDevice,
            &Counters::default(),
            &DeviceIdentity::default(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        );
        assert_eq!(absent.code, DEVICE_ABSENT);

        // A device that answered but whose descriptor did not parse.
        let unreadable_ident = DeviceIdentity {
            serial: "\u{fffd}".to_string(),
            ..DeviceIdentity::default()
        };
        let unreadable = classify(
            &RunOutcome::Unsupported("no config".into()),
            &Counters::default(),
            &unreadable_ident,
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(unreadable.code, IDENTITY_UNREADABLE);
        assert_eq!(unreadable.confidence, Confidence::Medium);

        // An A10 in DFU is a different exploit, not a broken A9 run.
        let a10 = DeviceIdentity::parse("CPID:8010 CPRV:11 BDID:0C SRTG:[iBoot-2696.0.0.1.33]");
        let unsupported = classify(
            &RunOutcome::Unsupported("no A9 row".into()),
            &Counters::default(),
            &a10,
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(unsupported.code, UNSUPPORTED_CHIP);

        // A9 CPID with no SRTG is iBSS DFU, and that is a third thing.
        let ibss = DeviceIdentity::parse("CPID:8003 CPRV:01 BDID:02");
        let wrong_stage = classify(
            &exhausted(64),
            &Counters::default(),
            &ibss,
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(wrong_stage.code, WRONG_BOOT_STAGE);
        assert!(wrong_stage.evidence.join("\n").contains("F007"));
    }

    #[test]
    fn config_refusal_for_an_a9_identity_is_not_an_unsupported_chip() {
        let v = classify(
            &RunOutcome::Unsupported("no row for CPID 0x8003 CPRV 0x20".into()),
            &Counters::default(),
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, CONFIG_ROW_MISMATCH);
        assert!(v.evidence.join("\n").contains("gaster.c:624,641"));
    }

    #[test]
    fn every_code_is_reachable_from_some_observable() {
        let a9 = ident_a9();
        let mut produced: Vec<&'static str> = Vec::new();

        let mut sig = |v: Verdict| produced.push(v.code);

        sig(classify(
            &RunOutcome::Pwned,
            &Counters::default(),
            &DeviceIdentity::parse(
                "CPID:8003 CPRV:01 BDID:02 SRTG:[IBOOT-2234.0.0.2.22] PWND:[checkm8]",
            ),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        sig(classify(
            &RunOutcome::Pwned,
            &Counters::default(),
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        sig(classify(
            &exhausted(1),
            &Counters::default(),
            &a9,
            DriverClass::WinUsb,
            ResetCapability::PipeCycleOnly,
        ));

        let resets_unknown = counters(|c| {
            c.ok = 3;
        });
        sig(classify(
            &exhausted(1),
            &resets_unknown,
            &a9,
            DriverClass::Other,
            ResetCapability::Unknown,
        ));

        let resets_not_delivered = counters(|c| {
            c.resets_attempted = 6;
        });
        sig(classify(
            &exhausted(6),
            &resets_not_delivered,
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));

        sig(classify(
            &RunOutcome::NoDevice,
            &Counters::default(),
            &DeviceIdentity::default(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        ));

        // The discovery record: a node that is present in the census but will not
        // open is one of the README's other three cases, never "absent".
        let path_too_long = counters(|c| {
            c.discovery_recorded = true;
            c.nodes_present_by_pid = vec![(0x1227, 1)];
            c.device_path_len = Some(271);
            c.last_open_errno = Some(-4);
            c.last_open_error = Some("libusb_open: NOT_FOUND".into());
        });
        sig(classify(
            &RunOutcome::NoDevice,
            &path_too_long,
            &DeviceIdentity::default(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));

        let wrong_driver = counters(|c| {
            c.discovery_recorded = true;
            c.nodes_present_by_pid = vec![(0x1227, 1)];
            c.last_open_errno = Some(5);
            c.last_open_error = Some("CreateFile: ERROR_ACCESS_DENIED".into());
        });
        sig(classify(
            &RunOutcome::NoDevice,
            &wrong_driver,
            &DeviceIdentity::default(),
            DriverClass::Other,
            ResetCapability::Real,
        ));

        let not_loaded = counters(|c| {
            c.discovery_recorded = true;
            c.nodes_present_by_pid = vec![(0x1227, 1)];
            c.last_open_error = Some("libusb_open: NOT_FOUND".into());
        });
        sig(classify(
            &RunOutcome::NoDevice,
            &not_loaded,
            &DeviceIdentity::default(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        ));

        let lost_mid_run = counters(|c| {
            c.ok = 20;
            c.nodevice = 1;
        });
        sig(classify(
            &exhausted(4),
            &lost_mid_run,
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        sig(classify(
            &RunOutcome::Unsupported("no config".into()),
            &Counters::default(),
            &DeviceIdentity::default(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        sig(classify(
            &RunOutcome::Unsupported("no row".into()),
            &Counters::default(),
            &DeviceIdentity::parse("CPID:8010 CPRV:11 SRTG:[iBoot-2696.0.0.1.33]"),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        sig(classify(
            &exhausted(64),
            &Counters::default(),
            &DeviceIdentity::parse("CPID:8003 CPRV:01 BDID:02"),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        sig(classify(
            &RunOutcome::Unsupported("no row".into()),
            &Counters::default(),
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));

        sig(classify(
            &exhausted(64),
            &setup_log_counters(),
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));

        let answered = counters(|c| {
            c.setup_attempts = 384;
            c.setup_pad_requests = 384;
            c.abort_sweep = vec![4, 5, 0, 1, 2, 3];
        });
        sig(classify(&exhausted(64), &answered, &a9, DriverClass::LibusbK, ResetCapability::Real));

        let mut pad_errors = answered.clone();
        pad_errors.setup_pad_errors = 12;
        sig(classify(&exhausted(64), &pad_errors, &a9, DriverClass::LibusbK, ResetCapability::Real));

        let pad_never = counters(|c| {
            c.setup_attempts = 384;
            c.setup_abort_full = 384;
            c.abort_sweep = vec![4, 5, 0, 1, 2, 3];
        });
        sig(classify(&exhausted(64), &pad_never, &a9, DriverClass::LibusbK, ResetCapability::Real));

        let pinned = counters(|c| {
            c.setup_attempts = 64;
            c.setup_pad_requests = 64;
            c.setup_pad_timeouts = 64;
            c.abort_sweep = vec![5];
        });
        sig(classify(&exhausted(64), &pinned, &a9, DriverClass::LibusbK, ResetCapability::Real));

        let unreported = counters(|c| {
            c.setup_async_unreported = 64;
        });
        sig(classify(&exhausted(64), &unreported, &a9, DriverClass::LibusbK, ResetCapability::Real));

        let early = counters(|c| {
            c.setup_attempts = 64;
            c.setup_abort_early = 64;
            c.abort_sweep = vec![4, 5, 0, 1, 2, 3];
        });
        sig(classify(&exhausted(64), &early, &a9, DriverClass::LibusbK, ResetCapability::Real));

        let spray_stall = counters(|c| {
            c.spray_stall_requests = 40;
            c.spray_stall_not_stalling = 40;
        });
        sig(classify(&exhausted(64), &spray_stall, &a9, DriverClass::LibusbK, ResetCapability::Real));

        let spray_leak = counters(|c| {
            c.spray_leak_requests = 40;
            c.spray_leak_not_zero = 40;
        });
        sig(classify(&exhausted(64), &spray_leak, &a9, DriverClass::LibusbK, ResetCapability::Real));

        sig(classify(&exhausted(64), &Counters::default(), &a9, DriverClass::LibusbK, ResetCapability::Real));
        sig(classify(
            &RunOutcome::Aborted("transport: pipe refused".into()),
            &Counters::default(),
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));

        produced.sort_unstable();
        produced.dedup();
        let expected: Vec<&str> = {
            let mut v = CODES.to_vec();
            v.sort_unstable();
            v
        };
        assert_eq!(produced, expected, "every code must be reachable");
    }

    #[test]
    fn every_next_action_is_a_command_not_advice() {
        let v = classify(
            &exhausted(64),
            &setup_log_counters(),
            &ident_a9(),
            DriverClass::WinUsb,
            ResetCapability::PipeCycleOnly,
        );
        for verdict in reachable_verdicts(v) {
            assert!(
                verdict.next_action.contains('`'),
                "{} has no concrete command: {}",
                verdict.code,
                verdict.next_action
            );
        }
    }

    /// Collect one verdict per code, using the same signatures as the reachability
    /// test. Kept as a helper so both tests exercise the same set.
    fn reachable_verdicts(seed: Verdict) -> Vec<Verdict> {
        let a9 = ident_a9();
        let mut out = vec![seed];
        out.push(classify(
            &RunOutcome::Pwned,
            &Counters::default(),
            &DeviceIdentity::parse(
                "CPID:8003 CPRV:01 BDID:02 SRTG:[IBOOT-2234.0.0.2.22] PWND:[checkm8]",
            ),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        out.push(classify(
            &RunOutcome::Pwned,
            &Counters::default(),
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        out.push(classify(
            &RunOutcome::NoDevice,
            &Counters::default(),
            &DeviceIdentity::default(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        ));

        // The discovery record: a node present in the census that will not open is
        // one of the README's other three cases, never "absent".
        let path_too_long = counters(|c| {
            c.discovery_recorded = true;
            c.nodes_present_by_pid = vec![(0x1227, 1)];
            c.device_path_len = Some(271);
            c.last_open_errno = Some(-4);
            c.last_open_error = Some("libusb_open: NOT_FOUND".into());
        });
        out.push(classify(
            &RunOutcome::NoDevice,
            &path_too_long,
            &DeviceIdentity::default(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));

        let wrong_driver = counters(|c| {
            c.discovery_recorded = true;
            c.nodes_present_by_pid = vec![(0x1227, 1)];
            c.last_open_errno = Some(5);
            c.last_open_error = Some("CreateFile: ERROR_ACCESS_DENIED".into());
        });
        out.push(classify(
            &RunOutcome::NoDevice,
            &wrong_driver,
            &DeviceIdentity::default(),
            DriverClass::Other,
            ResetCapability::Real,
        ));

        let not_loaded = counters(|c| {
            c.discovery_recorded = true;
            c.nodes_present_by_pid = vec![(0x1227, 1)];
            c.last_open_error = Some("libusb_open: NOT_FOUND".into());
        });
        out.push(classify(
            &RunOutcome::NoDevice,
            &not_loaded,
            &DeviceIdentity::default(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        ));

        let lost_mid_run = counters(|c| {
            c.ok = 20;
            c.nodevice = 1;
        });
        out.push(classify(
            &exhausted(4),
            &lost_mid_run,
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        out.push(classify(
            &RunOutcome::Unsupported("no config".into()),
            &Counters::default(),
            &DeviceIdentity::default(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        out.push(classify(
            &RunOutcome::Unsupported("no row".into()),
            &Counters::default(),
            &DeviceIdentity::parse("CPID:8010 CPRV:11 SRTG:[iBoot-2696.0.0.1.33]"),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        out.push(classify(
            &exhausted(64),
            &Counters::default(),
            &DeviceIdentity::parse("CPID:8003 CPRV:01 BDID:02"),
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        out.push(classify(
            &RunOutcome::Unsupported("no row".into()),
            &Counters::default(),
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));

        let resets_unknown = counters(|c| {
            c.ok = 3;
        });
        out.push(classify(
            &exhausted(1),
            &resets_unknown,
            &a9,
            DriverClass::Other,
            ResetCapability::Unknown,
        ));
        let resets_not_delivered = counters(|c| {
            c.resets_attempted = 6;
        });
        out.push(classify(
            &exhausted(6),
            &resets_not_delivered,
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        out.push(classify(
            &exhausted(64),
            &setup_log_counters(),
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));

        let answered = counters(|c| {
            c.setup_attempts = 384;
            c.setup_pad_requests = 384;
            c.abort_sweep = vec![4, 5, 0, 1, 2, 3];
        });
        out.push(classify(&exhausted(64), &answered, &a9, DriverClass::LibusbK, ResetCapability::Real));
        let mut pad_errors = answered.clone();
        pad_errors.setup_pad_errors = 12;
        out.push(classify(&exhausted(64), &pad_errors, &a9, DriverClass::LibusbK, ResetCapability::Real));
        let pad_never = counters(|c| {
            c.setup_attempts = 384;
            c.setup_abort_full = 384;
            c.abort_sweep = vec![4, 5, 0, 1, 2, 3];
        });
        out.push(classify(&exhausted(64), &pad_never, &a9, DriverClass::LibusbK, ResetCapability::Real));
        let pinned = counters(|c| {
            c.setup_attempts = 64;
            c.setup_pad_requests = 64;
            c.setup_pad_timeouts = 64;
            c.abort_sweep = vec![5];
        });
        out.push(classify(&exhausted(64), &pinned, &a9, DriverClass::LibusbK, ResetCapability::Real));
        let unreported = counters(|c| {
            c.setup_async_unreported = 64;
        });
        out.push(classify(&exhausted(64), &unreported, &a9, DriverClass::LibusbK, ResetCapability::Real));
        let early = counters(|c| {
            c.setup_attempts = 64;
            c.setup_abort_early = 64;
            c.abort_sweep = vec![4, 5, 0, 1, 2, 3];
        });
        out.push(classify(&exhausted(64), &early, &a9, DriverClass::LibusbK, ResetCapability::Real));
        let spray_stall = counters(|c| {
            c.spray_stall_requests = 40;
            c.spray_stall_not_stalling = 40;
        });
        out.push(classify(&exhausted(64), &spray_stall, &a9, DriverClass::LibusbK, ResetCapability::Real));
        let spray_leak = counters(|c| {
            c.spray_leak_requests = 40;
            c.spray_leak_not_zero = 40;
        });
        out.push(classify(&exhausted(64), &spray_leak, &a9, DriverClass::LibusbK, ResetCapability::Real));
        out.push(classify(&exhausted(64), &Counters::default(), &a9, DriverClass::LibusbK, ResetCapability::Real));
        out.push(classify(
            &RunOutcome::Aborted("transport: pipe refused".into()),
            &Counters::default(),
            &a9,
            DriverClass::LibusbK,
            ResetCapability::Real,
        ));
        out
    }

    #[test]
    fn a_failed_post_run_descriptor_read_does_not_hide_the_sweep_signature() {
        // main.rs re-reads the identity after the run and falls back to a default
        // one if the re-open fails. The run's own counters are the stronger
        // measurement, so the pad TIMEOUT must still be named.
        let v = classify(
            &exhausted(64),
            &setup_log_counters(),
            &DeviceIdentity::default(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, PAD_TIMEOUT_NOT_STALL, "{:?}", v);

        // With no run at all, an unreadable descriptor IS the answer.
        let no_run = classify(
            &exhausted(4),
            &counters(|c| {
                c.ok = 3;
            }),
            &DeviceIdentity::default(),
            DriverClass::Other,
            ResetCapability::Real,
        );
        assert_eq!(no_run.code, IDENTITY_UNREADABLE, "{:?}", no_run);
    }

    #[test]
    fn evidence_always_names_a_measurement() {
        let verdicts = reachable_verdicts(classify(
            &exhausted(64),
            &setup_log_counters(),
            &ident_a9(),
            DriverClass::WinUsb,
            ResetCapability::PipeCycleOnly,
        ));
        for v in verdicts {
            assert!(!v.evidence.is_empty(), "{} has no evidence", v.code);
            for e in &v.evidence {
                assert!(
                    e.contains('=') || e.contains(':'),
                    "{} evidence names no source: {e}",
                    v.code
                );
                assert!(!e.contains("ECID:0"), "{} leaks an ECID: {e}", v.code);
            }
            assert!(!v.headline.is_empty(), "{} has no headline", v.code);
        }
    }

    #[test]
    fn preflight_verdicts_do_not_claim_a_run_happened() {
        let v = classify(
            &RunOutcome::Aborted("preflight: reset is not real".into()),
            &Counters::default(),
            &ident_a9(),
            DriverClass::WinUsb,
            ResetCapability::PipeCycleOnly,
        );
        assert_eq!(v.code, NO_RESET_CAPABILITY);
        let all = v.evidence.join("\n");
        assert!(all.contains("no transfers were recorded"), "{all}");
        assert!(all.contains("Counters.total=0"), "{all}");
    }

    #[test]
    fn setup_that_passed_is_not_blamed_for_the_failure() {
        let c = counters(|c| {
            c.setup_attempts = 6;
            c.setup_pad_requests = 6;
            c.setup_stall_seen = 1; // the pass condition was met
            c.abort_sweep = vec![4, 5, 0, 1, 2, 3];
        });
        let v = classify(&exhausted(64), &c, &ident_a9(), DriverClass::LibusbK, ResetCapability::Real);
        assert_eq!(v.code, EXHAUSTED_UNKNOWN, "{:?}", v);
        let all = v.evidence.join("\n");
        assert!(all.contains("setup_stall_seen=1"), "{all}");
        assert!(all.contains("downstream"), "{all}");
    }

    #[test]
    fn spray_leak_verdict_names_the_unresolved_windex() {
        let c = counters(|c| {
            c.spray_leak_requests = 40;
            c.spray_leak_not_zero = 40;
        });
        let v = classify(&exhausted(64), &c, &ident_a9(), DriverClass::LibusbK, ResetCapability::Real);
        assert_eq!(v.code, SPRAY_LEAK_NOT_ZERO);
        assert!(v.evidence.join("\n").contains("LEAK_WINDEX_GASTER"));
        assert!(v.next_action.contains("--leak-windex-ipwndfu"), "{}", v.next_action);
    }
}
