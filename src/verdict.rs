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
//!    driver" is not an action; ``run `a9pwn reset` `` is — and it must be a
//!    command that EXISTS on the host that printed it. Every remedy that names
//!    Windows-only tooling therefore goes through [`host_remedy`], which states
//!    both hosts' texts at every call site, so no verdict can be silently
//!    Windows-only. This rule was earned on 2026-10-03: six remedied verdicts
//!    told a Linux operator to run `a9drv bind`, `zadig-2.9.exe` and
//!    `pnputil /scan-devices` — none of which exist on that host.
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
/// Non-delivery of the port reset, **evidenced**: the device refuted it
/// (`ResetEvidence::Refuted`), or the reset call failed outright and produced no
/// evidence state at all. An unverifiable reset proves nothing — this bootrom rests at
/// bState 5 and `Delivered` needs a transition only PATCH's walk arranges (MEASURED) —
/// so it does not reach this verdict.
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
/// 1. reset capability — nothing else is interpretable when the driver cannot reset
///    at all, or when a reset was *measured* as a pipe cycle. An unverifiable reset
///    is not evidence and is never interpreted here;
/// 2. success, by the reference's own `PWND:[checkm8]` predicate;
/// 3. the discovery record, when no transfer happened: path length, then a node that
///    exists but will not open — the README's other three cases;
/// 4. absence, with the census that proves it (or states that none was taken);
/// 5. a device that reported `NO_DEVICE` mid-run;
/// 6. identity — CPID and SRTG decide which of three different problems this is;
/// 7. config refusal for an identity the reference would have accepted;
/// 8. resets whose non-delivery was measured (refuted by the device, or established
///    and undelivered) — never merely unverified;
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
    // 0 -------------------------------------------------------- demonstrated pwn
    // ORDERING IS LOAD-BEARING. This block used to sit *below* the reset block,
    // and on 2026-10-03 that produced a verdict which contradicted its own
    // evidence: `a9pwn run` pwned the device on bare-metal Linux (exit 0, and the
    // same output block printed `PWND marker present: Some("checkm8")`), while the
    // verdict read
    //     "The bound driver cannot reset the port, so checkm8 can never fire.
    //      [NO_RESET_CAPABILITY]  confidence: High"
    // because the Linux transport could not classify a driver and counted two
    // `DriverCannotReset` resets as pipe cycles.
    //
    // A PWND marker in the serial descriptor is a MEASUREMENT. The driver class and
    // the reset capability are INFERENCES about the environment. When they
    // disagree, the measurement wins — that is the whole discipline this project
    // paid five rounds to learn. A tool may not announce that the exploit cannot
    // fire on a device it just fired on.
    if matches!(outcome, RunOutcome::Pwned) {
        return if ident.is_pwned() {
            pwned(counters, ident)
        } else {
            pwned_unconfirmed(counters, ident)
        };
    }

    // The device is pwned but THIS run did not report it — the marker was already
    // there (an earlier run, or another tool). The goal state is still achieved, so
    // the verdict says so, and it says plainly which of the two situations this is
    // rather than letting a reader assume the run did it.
    if ident.is_pwned() {
        let mut v = pwned(counters, ident);
        v.evidence.insert(
            0,
            format!(
                "run: this run's own outcome was {outcome:?}, so IT did not produce the marker — the \
                 device was already pwned when the run started. The marker is a measurement and \
                 outranks the driver/reset model below"
            ),
        );
        return v;
    }

    // 1 ---------------------------------------------------------------- resets
    // Fires on a driver that *cannot* reset, or on a reset that was **measured** as
    // a pipe cycle (`ResetEvidence::DriverCannotReset`, the only thing
    // `resets_pipe_cycle` counts). It deliberately does NOT fire on
    // `resets_unverified`: this bootrom reports bState 5 at rest and a full
    // re-enumeration does not change it (MEASURED), while `Delivered` needs the
    // transition out of `MANIFEST_WAIT_RESET` that only PATCH's walk arranges — so an
    // unverifiable reset after RESET/SETUP/SPRAY says nothing about the driver.
    // Blaming the driver for it is the defect this file measured on hardware
    // (`a9pwn run --stage reset`: attempted=1 real=0 pipe_cycle=1).
    if driver == DriverClass::WinUsb
        || reset_cap == ResetCapability::PipeCycleOnly
        || counters.resets_pipe_cycle > 0
    {
        return no_reset_capability(counters, ident, driver, reset_cap);
    }

    // 2 --------------------------------------------------------------- success
    // Reached only when the marker is absent, so a `Pwned` outcome here is the
    // contradictory case `pwned_unconfirmed` exists for.
    if matches!(outcome, RunOutcome::Pwned) {
        return pwned_unconfirmed(counters, ident);
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
    // Non-delivery must be **evidenced**, never inferred from the absence of a
    // delivery. Two things evidence it: the device refuted the reset
    // (ResetEvidence::Refuted), or the reset call failed outright and produced no
    // evidence state at all (Counters::resets_unrecorded). `resets_unverified > 0`
    // does neither: this bootrom reports bState 5 at rest and a re-enumeration does
    // not change it (MEASURED), and the exploit's own sequence parks the DFU machine
    // in MANIFEST_WAIT_RESET only for the reset after PATCH, so the transition
    // `Delivered` needs cannot occur after RESET/SETUP/SPRAY. A run that continues past
    // such a reset must still be classified by what actually failed downstream — with
    // its reset evidence attached to that verdict rather than replacing it.
    if counters.reset_non_delivery_measured() {
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
        "trace: resets_attempted={} resets_real={} resets_refuted={} resets_unverified={} \
         resets_pipe_cycle={} (Counters.resets_*, from Tracer::reset; pipe_cycle = the driver \
         cannot reset, unverified = the effect was observable neither way)",
        c.resets_attempted,
        c.resets_real,
        c.resets_refuted,
        c.resets_unverified,
        c.resets_pipe_cycle
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

/// The reset story, attached to a verdict that is **not** about the reset.
///
/// An [`crate::types::ResetEvidence::Unverified`] reset decides nothing — it is the
/// crate's "not success, not failure" state and, after RESET/SETUP/SPRAY, the only
/// outcome the DFU machine can produce. So it must never choose a verdict; but it must
/// still be *visible* on the verdict that does, or a reader cannot tell "resets were
/// issued and their effect was unobservable" from "no reset was attempted". `None`
/// when there is nothing to report.
fn ev_reset_unverified(c: &Counters) -> Option<String> {
    if c.resets_unverified == 0 {
        return None;
    }
    Some(format!(
        "trace: resets_unverified={} of resets_attempted={} — this bootrom reports bState 5 \
         (dfuDNLOAD-IDLE) at rest, and a full re-enumeration does not change it (MEASURED on this \
         device: an elevated device restart, fresh handle, 5 -> 5; the Windows command and the \
         elevation requirement are recorded at HANDOFF.md:314). `Delivered` requires a \
         transition out of MANIFEST_WAIT_RESET (8), which only PATCH's walk arranges — that walk \
         parks at 8 and the reset follows with nothing in between, so `Delivered` stays reachable \
         and meaningful there, and this counter is a PATCH-only instrument rather than a broken \
         one. An absent transition after RESET/SETUP/SPRAY is therefore not evidence of \
         non-delivery and is not a driver fault. This is NOT the cause of this verdict; it is \
         recorded because it is a measurement (Counters.resets_unverified, from Tracer::reset)",
        c.resets_unverified, c.resets_attempted
    ))
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

// ------------------------------------------------------- host-aware remedies

/// Which host a remedy is written for.
///
/// Two arms only, and honestly so: `remedy_host` is Windows or *everything
/// else* (this crate targets Windows and Linux; a macOS build would get the
/// Linux text rather than a Windows tool it does not have).
///
/// A value, not a `cfg!` at each call site, so that a test on EITHER host can
/// execute BOTH selections. The Windows text is contract (`HANDOFF.md` §9.3) and
/// this project has paid five times for checks nobody could make fail; a Windows
/// branch that only Windows can execute is exactly such a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemedyHost {
    Windows,
    Linux,
}

const fn remedy_host() -> RemedyHost {
    if cfg!(target_os = "windows") {
        RemedyHost::Windows
    } else {
        RemedyHost::Linux
    }
}

/// `windows` **byte for byte** when `host` is Windows, `linux` otherwise.
/// Nothing is reflowed, trimmed or re-escaped: the Windows remedy is a contract
/// and this is its only selector.
fn remedy_for(host: RemedyHost, windows: &str, linux: &str) -> String {
    match host {
        RemedyHost::Windows => windows.to_string(),
        RemedyHost::Linux => linux.to_string(),
    }
}

/// The single host-aware remedy selector. Every `next_action` that names
/// Windows-only tooling goes through this, with BOTH texts written out at the
/// call site, so a future verdict cannot be silently Windows-only.
///
/// The failure this exists for (MEASURED 2026-10-03, bare-metal Linux): six
/// remedied verdicts told a Linux operator to run `a9drv bind`,
/// `zadig-2.9.exe` or `pnputil /scan-devices`, none of which exist on this
/// host — one of them about a device this host had just pwned. `next_action` is
/// the field a reader ACTS on, so a wrong value there is worse than a missing
/// one, and it is the same failure class as the `NO_RESET_CAPABILITY` headline
/// that accused a Windows driver on a Linux-pwned phone.
///
/// The Linux halves teach the Linux-side facts (MEASURED on this host):
/// - `a9pwn reset` prints `capability` and `what happened`; a reset that returns
///   in the ~237 ms class with the device answering afterwards is a real
///   `USBDEVFS_RESET` port reset;
/// - `a9pwn preflight` must show its `reset` line reading `real bus reset`
///   (`main.rs` prints `reset         : real bus reset`; the remedies therefore
///   say "the `reset` line reads `real bus reset`" rather than quoting a literal
///   that is not in the output — an operator told to grep for a string the tool
///   never prints concludes a PASSING preflight failed);
/// - enumeration is `udevadm trigger --subsystem-match=usb` or unplug/replug;
/// - permissions are `/dev/bus/usb` access (a udev rule for `05ac:1227`);
/// - **no kernel driver bound (`usbfs`) is the NORMAL, working Linux state.**
///
/// Two tests keep this honest: `remedy_pairs_state_both_hosts_texts` pins every
/// pair below on both hosts, and
/// `no_windows_only_invocation_escapes_the_windows_consts` audits this whole
/// file, so a remedy cannot be added without a `_WINDOWS`/`_LINUX` pair.
fn host_remedy(windows: &str, linux: &str) -> String {
    remedy_for(remedy_host(), windows, linux)
}

// ------------------------------------------------------------- verdict bodies

/// Windows remedy for [`no_reset_capability`] — CONTRACT, do not reflow: this
/// text is what a Windows host has always printed, and `HANDOFF.md` §9.3 makes
/// the Windows behaviour binding.
const REMEDY_NO_RESET_CAPABILITY_WINDOWS: &str = "Run `a9drv bind --pid 1227` from an ELEVATED prompt to rebind \
     USB\\VID_05AC&PID_1227 to libusbK, then run `a9pwn preflight` and require it to \
     print `reset: real bus reset`. Only then `a9pwn run`. (Fallback: \
     zadig-2.9.exe -> Options -> List All Devices -> 05AC:1227 -> libusbK -> \
     Install Driver.)";

/// Linux remedy for [`no_reset_capability`]. On this host there is no driver
/// table to act on, so the actionable thing is to MEASURE the reset instead of
/// inheriting a Windows model's conclusion from it.
const REMEDY_NO_RESET_CAPABILITY_LINUX: &str = "This is a missing MEASUREMENT, not a property \
     of the device. First measure the reset instead of inferring it: run `a9pwn reset` and read \
     its `capability` and `what happened` lines — a reset that returns in the ~237 ms class \
     with the device answering afterwards is a real `USBDEVFS_RESET` port reset on this host. \
     Then run `a9pwn preflight` and require its `reset` line to read `real bus reset`. On Linux \
     the driver model this verdict is built on does not apply: no kernel driver bound (`usbfs`) \
     is the NORMAL working state, and a kernel driver owning the node would be the anomaly. If \
     `a9pwn reset` itself fails, fix /dev/bus/usb access for 05ac:1227 (a udev rule for the \
     device) and the measurement in `usb.rs` before accusing the port. Do NOT run `a9drv bind` \
     or zadig: those are Windows-only and have no meaning here.";

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
    push_opt(&mut evidence, ev_reset_unverified(c));
    evidence.push(ev_device(ident));

    // The driver-class model this verdict is built on is a WINDOWS model: it
    // describes which Windows kernel driver libusb can drive a real reset through.
    // On Linux there is no such driver to name — "no kernel driver bound" is the
    // normal, working state (libusb reaches the device through usbfs) — so the
    // Windows remedy is not merely unhelpful, it is unavailable: `a9drv bind` and
    // zadig do not exist on this host.
    //
    // MEASURED 2026-10-03: on Linux this verdict fired with `driver_class=unknown`
    // after a run that PWNED THE DEVICE, and its advice was to rebind a Windows
    // driver. The TEXT is therefore selected by host through the one helper, and
    // the CONFIDENCE keeps its own condition: a missing measurement must be
    // reported as a missing measurement, never as a property of the device.
    let windows_driver = matches!(
        driver,
        DriverClass::LibusbK | DriverClass::Libusb0 | DriverClass::WinUsb
    );
    let on_linux = cfg!(target_os = "linux");
    let next_action = host_remedy(
        REMEDY_NO_RESET_CAPABILITY_WINDOWS,
        REMEDY_NO_RESET_CAPABILITY_LINUX,
    );
    let confidence = if on_linux && !windows_driver {
        evidence.push(format!(
            "host: this is a Linux host and driver_class={} is not one of the Windows classes this \
             model describes, so the Windows driver table does not apply. The honest reading of \
             reset_capability={} is 'not measured on this host', not 'the device cannot be reset' \
             — the same reset path delivered the reference pwn and our own on this machine",
            driver.as_str(),
            cap.as_str()
        ));
        Confidence::Low
    } else {
        Confidence::High
    };

    Verdict {
        code: NO_RESET_CAPABILITY,
        headline: "The bound driver cannot reset the port, so checkm8 can never fire. This is the \
                   failure that looks like an exploit bug and is not one."
            .to_string(),
        evidence,
        next_action,
        confidence,
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

/// Windows remedy for [`pwned_unconfirmed`] — CONTRACT, do not reflow.
const REMEDY_PWNED_UNCONFIRMED_WINDOWS: &str = "Run `a9pwn ident` now: if the PWND marker is absent the device is not pwned. \
     Re-enter SecureROM DFU by holding Power + Home ~8 s, then release Power and keep \
     Home held ~10 s — this iPhone SE has a MECHANICAL Home button, and \
     solid-state-Home devices (iPhone 7/8/X) use Power + VolDown instead, which does \
     nothing here. The screen stays BLACK in DFU, so the host is the only reliable \
     confirmation: `Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like \
     '*VID_05AC&PID_1227*' }` must list the node. Re-run `a9pwn run --rounds 64 \
     --allow-winusb` only after `a9pwn preflight` prints `reset: real bus reset`.";

/// Linux remedy for [`pwned_unconfirmed`]. Same device-class instruction, but the
/// host-side confirmation is `lsusb` and the re-run does not carry the
/// Windows-only `--allow-winusb` escape hatch, which has no meaning here (there
/// is no pipe-cycle reset to override on `usbfs`).
const REMEDY_PWNED_UNCONFIRMED_LINUX: &str = "Run `a9pwn ident` now: if the PWND marker is \
     absent the device is not pwned. Re-enter SecureROM DFU by holding Power + Home ~8 s, then \
     release Power and keep Home held ~10 s — this iPhone SE has a MECHANICAL Home button, and \
     solid-state-Home devices (iPhone 7/8/X) use Power + VolDown instead, which does nothing \
     here. The screen stays BLACK in DFU, so the host is the only reliable confirmation: `lsusb \
     -d 05ac:1227` must list the node (VID_05AC&PID_1227), and if it does not, re-enumerate \
     with `udevadm trigger --subsystem-match=usb` or unplug and replug the cable. Then run \
     `a9pwn preflight`: its `reset` line must read `real bus reset` (no kernel driver bound — \
     `usbfs` — is the NORMAL Linux state, and `a9pwn reset` in the ~237 ms class with the \
     device answering afterwards is a real `USBDEVFS_RESET` port reset). Only then re-run \
     `a9pwn run --rounds 64`.";

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
        next_action: host_remedy(
            REMEDY_PWNED_UNCONFIRMED_WINDOWS,
            REMEDY_PWNED_UNCONFIRMED_LINUX,
        ),
        confidence: Confidence::Low,
    }
}

/// Windows remedy for [`device_absent`] — CONTRACT, do not reflow.
const REMEDY_DEVICE_ABSENT_WINDOWS: &str = "Enter SecureROM DFU: hold Power + Home ~8 s, release Power, keep Home held ~10 s \
     (mechanical-Home devices such as this iPhone SE use Power + Home; \
     solid-state-Home devices use Power + VolDown). The screen stays BLACK in DFU, so \
     confirm from the host instead: `Get-PnpDevice -PresentOnly | Where-Object { \
     $_.InstanceId -like '*VID_05AC&PID_1227*' }` must list the node. Then run \
     `a9pwn ident`; if it still reports nothing while the node IS enumerated, \
     enumeration is not the broken part and the open is — check that before touching \
     the phone again.";

/// Linux remedy for [`device_absent`]. The host-side confirmation is `lsusb`, the
/// re-enumeration is udev (or a replug), and the open failure to check after that
/// is `/dev/bus/usb` permission — the most common cause of a DFU node that
/// enumerates and still will not open on Linux.
const REMEDY_DEVICE_ABSENT_LINUX: &str = "Enter SecureROM DFU: hold Power + Home ~8 s, release Power, keep Home held ~10 s \
     (mechanical-Home devices such as this iPhone SE use Power + Home; \
     solid-state-Home devices use Power + VolDown). The screen stays BLACK in DFU, so \
     confirm from the host instead: `lsusb -d 05ac:1227` must list the node \
     (VID_05AC&PID_1227); if nothing enumerates, try `udevadm trigger \
     --subsystem-match=usb` or unplug and replug the cable. Then run `a9pwn ident`; if \
     it still reports nothing while the node IS enumerated, the open is what failed and \
     the first thing to check is /dev/bus/usb access for 05ac:1227 (a udev rule for \
     the device) before touching the phone again.";

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
        next_action: host_remedy(REMEDY_DEVICE_ABSENT_WINDOWS, REMEDY_DEVICE_ABSENT_LINUX),
        confidence: if c.discovery_recorded && c.nodes_total() == 0 {
            Confidence::High
        } else {
            Confidence::Medium
        },
    }
}

/// Windows remedy for [`device_path_too_long`] — CONTRACT, do not reflow.
const REMEDY_DEVICE_PATH_TOO_LONG_WINDOWS: &str = "Do not chase the exploit; nothing can open this node. Run `a9pwn ident` to print \
     the measured path length, then plug the iPhone directly into a root port (no hub, \
     no extension cable) and re-run it. If the length stays at or above 256, the \
     vendored libusb's `char dev_id[256]` must be raised in libusb1-sys-0.7.0 — that \
     is a dependency decision for the Lead, not a run-time flag.";

/// Linux remedy for [`device_path_too_long`]: the 256-byte `char dev_id` this
/// verdict is defined by is libusb's Windows backend, so on this host the census
/// and the open error are the measurements worth acting on.
const REMEDY_DEVICE_PATH_TOO_LONG_LINUX: &str = "On Linux this verdict has no mechanism: the 256-byte `char dev_id` it names is \
     libusb's Windows backend, and a Linux transport does not measure `device_path_len` \
     at all. Read the census instead — `lsusb -d 05ac:1227` must list the node \
     (VID_05AC&PID_1227); if the open still fails, check /dev/bus/usb access for \
     05ac:1227 (a udev rule for the device) and re-enumerate with `udevadm trigger \
     --subsystem-match=usb` or a replug. Do not chase the exploit; nothing can open this \
     node.";

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
        next_action: host_remedy(
            REMEDY_DEVICE_PATH_TOO_LONG_WINDOWS,
            REMEDY_DEVICE_PATH_TOO_LONG_LINUX,
        ),
        confidence: Confidence::High,
    }
}

/// Windows remedy — CONTRACT, do not reflow. `{driver}` is substituted by
/// `.replace`, not by `format!`, so the text stays a plain `&str` the tests can
/// pin; the emitted bytes are identical to the `format!` this replaced.
const REMEDY_WRONG_DRIVER_BOUND_WINDOWS: &str = "Run `a9drv bind --pid 1227` from an ELEVATED prompt to replace the `{driver}` binding on \
     USB\\VID_05AC&PID_1227 with libusbK, then `a9pwn ident` must print `driver service: \
     libusbK` and `reset: real bus reset` before `a9pwn run`.";

/// Linux remedy for [`wrong_driver_bound`]. There is nothing to rebind: the
/// normal Linux state is no kernel driver at all, so a kernel driver that owns
/// the node is the anomaly to remove, and `/dev/bus/usb` access is the other
/// thing that makes an open fail with a class of `other`.
const REMEDY_WRONG_DRIVER_BOUND_LINUX: &str = "On Linux a kernel driver owning the node is the \
     exception, not the rule: `usbfs` with no kernel driver bound is the NORMAL working state, \
     and `a9drv bind` / libusbK are Windows-only tools that do not exist on this host. `a9pwn \
     ident` prints what it actually read (`driver service: {driver}`): find that driver in \
     `lsusb -t` or the `driver` symlink under /sys/bus/usb/devices, unbind or blacklist it (a \
     device in SecureROM needs no kernel driver), then re-enumerate with `udevadm trigger \
     --subsystem-match=usb` or a replug. Also confirm /dev/bus/usb access for 05ac:1227 (a udev \
     rule for the device), then require `a9pwn preflight`'s `reset` line to read `real bus \
     reset` before `a9pwn run`.";

/// A node is present and the open failed with a non-libusb driver bound.
///
/// The reset capability is carried for signature parity with the other discovery
/// builders and is deliberately unused: this verdict is decided by the census and
/// the open error alone, so wiring `cap` into a `usb: ...` evidence line here would
/// change the `evidence` of every `WRONG_DRIVER_BOUND` verdict for no measurement.
fn wrong_driver_bound(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    _cap: ResetCapability,
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
        next_action: host_remedy(
            &REMEDY_WRONG_DRIVER_BOUND_WINDOWS.replace("{driver}", driver.as_str()),
            &REMEDY_WRONG_DRIVER_BOUND_LINUX.replace("{driver}", driver.as_str()),
        ),
        confidence: Confidence::High,
    }
}

/// Windows remedy for [`driver_bound_not_loaded`] — CONTRACT, do not reflow.
const REMEDY_DRIVER_BOUND_NOT_LOADED_WINDOWS: &str = "Re-enumerate the node: run `pnputil /scan-devices` from an elevated prompt (or \
     unplug and replug the cable), and close any process still holding it — a stale \
     `a9ctl` or `king.exe` from an earlier session keeps the node unopenable. Then run \
     `a9pwn ident` and require a non-empty `serial` line. If the open error repeats \
     with libusbK already bound, re-run `a9drv bind --pid 1227` elevated.";

/// Linux remedy for [`driver_bound_not_loaded`]. Re-enumeration is udev, the
/// process holding the node is a stale `a9pwn`, and the thing that usually makes a
/// present node unopenable on this host is `/dev/bus/usb` permission — not a
/// driver binding.
const REMEDY_DRIVER_BOUND_NOT_LOADED_LINUX: &str = "Re-enumerate the node: `udevadm trigger --subsystem-match=usb`, or unplug and \
     replug the cable, and close any process still holding it — a stale `a9pwn` from \
     an earlier session keeps the node unopenable, and `fuser -v /dev/bus/usb/<bus>/<dev>` \
     names the holder. Then run `a9pwn ident` and require a non-empty `serial` line. If \
     the open error repeats with no kernel driver bound (`a9pwn ident` prints `driver \
     service: usbfs` — the NORMAL Linux state), check /dev/bus/usb access for 05ac:1227 \
     (a udev rule for the device), which is the usual cause on this host, and confirm \
     nothing else holds the node open.";

/// A node is present, the open failed, and no *wrong* driver can be named: either
/// the service could not be read at all, or a libusb driver is bound and still
/// refused the node.
///
/// As in [`wrong_driver_bound`], the reset capability is deliberately unused: the
/// node never opened, so no reset was measurable. Adding it to `evidence` would be
/// a fabricated measurement.
fn driver_bound_not_loaded(
    c: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    _cap: ResetCapability,
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
        next_action: host_remedy(
            REMEDY_DRIVER_BOUND_NOT_LOADED_WINDOWS,
            REMEDY_DRIVER_BOUND_NOT_LOADED_LINUX,
        ),
        confidence: Confidence::Medium,
    }
}

/// Windows remedy for [`device_lost_mid_run`] — CONTRACT, do not reflow.
const REMEDY_DEVICE_LOST_MID_RUN_WINDOWS: &str = "Power-cycle the phone, plug it directly into a root port with the cable that \
     worked for `a9pwn ident` (no hub, no extension), then re-enter SecureROM DFU: \
     hold Power + Home ~8 s, release Power, keep Home held ~10 s (mechanical-Home \
     devices such as this iPhone SE use Power + Home; solid-state-Home devices use \
     Power + VolDown). The screen stays BLACK in DFU, so confirm from the host with \
     `Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like \
     '*VID_05AC&PID_1227*' }`. Then re-run `a9pwn run --stage setup --setup-budget 64 \
     --trace run.jsonl --verbose` and read the `per stage` line of the summary to see \
     which stage lost it.";

/// Linux remedy for [`device_lost_mid_run`]. Same re-entry instructions, but the
/// host-side confirmation is `lsusb`, the kernel's own record of the disconnect is
/// `dmesg`, and re-enumeration is udev or a replug.
const REMEDY_DEVICE_LOST_MID_RUN_LINUX: &str = "Power-cycle the phone, plug it directly into a \
     root port with the cable that worked for `a9pwn ident` (no hub, no extension), then \
     re-enter SecureROM DFU: hold Power + Home ~8 s, release Power, keep Home held ~10 s \
     (mechanical-Home devices such as this iPhone SE use Power + Home; solid-state-Home devices \
     use Power + VolDown). The screen stays BLACK in DFU, so confirm from the host with `lsusb \
     -d 05ac:1227` (VID_05AC&PID_1227), and `sudo dmesg | tail` for the disconnect the kernel \
     logged (reading the kernel buffer needs root on this host); if the node does not come \
     back, `udevadm trigger --subsystem-match=usb` or unplug and replug re-enumerates it. Then \
     re-run `a9pwn run --stage setup --setup-budget 64 --trace run.jsonl --verbose` and read \
     the `per stage` line of the summary to see which stage lost it.";

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
        next_action: host_remedy(
            REMEDY_DEVICE_LOST_MID_RUN_WINDOWS,
            REMEDY_DEVICE_LOST_MID_RUN_LINUX,
        ),
        confidence: Confidence::High,
    }
}

/// Windows remedy for [`identity_unreadable`] — CONTRACT, do not reflow.
const REMEDY_IDENTITY_UNREADABLE_WINDOWS: &str = "Run `a9pwn ident --verbose` and read the `serial` line: an empty or truncated \
     serial means the descriptor read failed, not that the phone is absent. Rebind \
     the node with `a9drv bind --pid 1227` from an elevated prompt, re-enumerate, and \
     retry; if the serial is still short, the device path is longer than libusb's \
     buffer.";

/// Linux remedy for [`identity_unreadable`]. The 256-byte path limit the Windows
/// text can end on is libusb's Windows backend, so the Linux-side second suspect
/// is `/dev/bus/usb` permission.
const REMEDY_IDENTITY_UNREADABLE_LINUX: &str = "Run `a9pwn ident --verbose` and read the `serial` line: an empty or truncated \
     serial means the descriptor read failed, not that the phone is absent. \
     Re-enumerate with `udevadm trigger --subsystem-match=usb` (or unplug and replug) \
     and retry; the 256-byte device-path limit this message can name is libusb's \
     Windows backend and does not apply on Linux, so if the serial is still short \
     check /dev/bus/usb access for 05ac:1227 (a udev rule for the device) before \
     blaming the descriptor.";

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
        next_action: host_remedy(
            REMEDY_IDENTITY_UNREADABLE_WINDOWS,
            REMEDY_IDENTITY_UNREADABLE_LINUX,
        ),
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

/// Windows remedy for [`wrong_boot_stage`] — CONTRACT, do not reflow.
const REMEDY_WRONG_BOOT_STAGE_WINDOWS: &str = "Get the phone into SecureROM DFU, not iBSS DFU: hard power-off first (hold Power \
     + Home until the screen goes black), then hold Power + Home ~8 s, release Power, \
     keep Home held ~10 s. Mechanical-Home devices such as this iPhone SE use Power + \
     Home; solid-state-Home devices use Power + VolDown. The screen stays BLACK in \
     DFU, so confirm from the host: `Get-PnpDevice -PresentOnly | Where-Object { \
     $_.InstanceId -like '*VID_05AC&PID_1227*' }` must list the node. Then run \
     `a9pwn ident` and require a non-empty `SRTG` line before `a9pwn run`.";

/// Linux remedy for [`wrong_boot_stage`]. Same re-entry instructions; the host
/// check is `lsusb`, with udev named in case the node is not there yet.
const REMEDY_WRONG_BOOT_STAGE_LINUX: &str = "Get the phone into SecureROM DFU, not iBSS DFU: hard power-off first (hold Power \
     + Home until the screen goes black), then hold Power + Home ~8 s, release Power, \
     keep Home held ~10 s. Mechanical-Home devices such as this iPhone SE use Power + \
     Home; solid-state-Home devices use Power + VolDown. The screen stays BLACK in \
     DFU, so confirm from the host: `lsusb -d 05ac:1227` must list the node \
     (VID_05AC&PID_1227) — if it does not, `udevadm trigger --subsystem-match=usb` or a \
     replug re-enumerates it. Then run `a9pwn ident` and require a non-empty `SRTG` line \
     before `a9pwn run`.";

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
        next_action: host_remedy(REMEDY_WRONG_BOOT_STAGE_WINDOWS, REMEDY_WRONG_BOOT_STAGE_LINUX),
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

/// Windows remedy for [`reset_not_delivered`] — CONTRACT, do not reflow.
const REMEDY_RESET_NOT_DELIVERED_WINDOWS: &str = "Run `a9pwn reset` and read its `capability` and `what happened` lines; if they \
     report an error or a pipe cycle, rebind with `a9drv bind --pid 1227` from an \
     elevated prompt. Do not raise --rounds: more rounds cannot help when the reset \
     is not being delivered.";

/// Linux remedy for [`reset_not_delivered`]. There is no driver to rebind here:
/// the actionable measurement is `a9pwn reset`'s own `capability`/`what happened`
/// pair, and the actionable failure mode is `/dev/bus/usb` access.
const REMEDY_RESET_NOT_DELIVERED_LINUX: &str = "Run `a9pwn reset` and read its `capability` and \
     `what happened` lines: a reset that returns in the ~237 ms class with the device answering \
     afterwards is a real `USBDEVFS_RESET` port reset, and `a9pwn preflight`'s `reset` line \
     must read `real bus reset`. There is no driver to rebind here — no kernel driver bound \
     (`usbfs`) is the NORMAL Linux state, and `a9drv bind` is a Windows-only tool that does not \
     exist on this host. If `a9pwn reset` itself fails, check /dev/bus/usb access for 05ac:1227 \
     (a udev rule for the device) and that nothing else holds the node. Do not raise --rounds: \
     more rounds cannot help when the reset is not being delivered.";

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
                "trace: resets_attempted={} resets_real={} resets_refuted={} resets_unverified={} \
                 resets_pipe_cycle={} unrecorded={} — this verdict requires *evidence* of \
                 non-delivery, and requires that nothing was delivered: the device was parked in \
                 MANIFEST_WAIT_RESET and stayed there (ResetEvidence::Refuted), or the reset call \
                 failed outright and left no evidence state at all (the `unrecorded` count, logged \
                 as a bare `reset` event). A merely unverified reset is not counted here \
                 (Counters::reset_non_delivery_measured)",
                c.resets_attempted,
                c.resets_real,
                c.resets_refuted,
                c.resets_unverified,
                c.resets_pipe_cycle,
                c.resets_unrecorded()
            ),
            ev_counts(c),
            ev_device(ident),
        ],
        next_action: host_remedy(
            REMEDY_RESET_NOT_DELIVERED_WINDOWS,
            REMEDY_RESET_NOT_DELIVERED_LINUX,
        ),
        confidence: Confidence::Medium,
    }
}

fn abort_window_unreported(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    let mut evidence = vec![
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
    ];
    push_opt(&mut evidence, ev_reset_unverified(c));
    Verdict {
        code: ABORT_WINDOW_UNREPORTED,
        headline: "The async SETUP transfers carry no abort window, so the sweep cannot be audited. \
                   The exploit's timing parameter is unobservable."
            .to_string(),
        evidence,
        next_action: "Fix the transport before running again: `Transport::control_async_abort` must \
                      return `XferResult.abort_after_ms = Some(cancel_after_ms)`. Then re-run \
                      `a9pwn run --stage setup --trace setup.jsonl --verbose` and confirm the abort \
                      lines carry `\"abort_after_ms\":N` in setup.jsonl."
            .to_string(),
        confidence: Confidence::High,
    }
}

fn abort_window_pinned(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    let mut evidence = vec![
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
    ];
    push_opt(&mut evidence, ev_reset_unverified(c));
    Verdict {
        code: ABORT_WINDOW_PINNED,
        headline: "The abort window never advanced: the sweep is a single point, so checkm8's timing \
                   parameter is never explored and SETUP cannot converge."
            .to_string(),
        evidence,
        next_action: "Re-run with distinct bounds: `a9pwn run --stage setup --abort-min-ms 0 \
                      --usb-timeout-ms 5 --trace setup.jsonl --verbose`, then check that abort_sweep \
                      in the summary walks 4,5,0,1,2,3. If it still does not advance, the window \
                      update in `stage_setup` is the defect."
            .to_string(),
        confidence: Confidence::High,
    }
}

/// Windows remedy for [`abort_cancelled_early`] — CONTRACT, do not reflow.
const REMEDY_ABORT_CANCELLED_EARLY_WINDOWS: &str = "Grep the trace for the evidence before changing anything: \
     `Select-String -Path setup.jsonl -Pattern '\"status\":\"CANCELLED\"'` and compare \
     `xfer_micros` with `abort_after_ms` on each line. Then re-run \
     `a9pwn run --stage setup --usb-timeout-ms 5 --abort-min-ms 0 --trace setup.jsonl \
     --verbose` and require at least one CANCELLED line whose xfer_micros is close to \
     its abort_after_ms in milliseconds.";

/// Linux remedy for [`abort_cancelled_early`] — the same trace query in the tool
/// this host actually has. `next_action` is acted on literally, so a PowerShell
/// one-liner here is a remedy that does not run.
const REMEDY_ABORT_CANCELLED_EARLY_LINUX: &str = "Grep the trace for the evidence before changing anything: \
     `grep -n '\"status\":\"CANCELLED\"' setup.jsonl` and compare `xfer_micros` with \
     `abort_after_ms` on each line. Then re-run \
     `a9pwn run --stage setup --usb-timeout-ms 5 --abort-min-ms 0 --trace setup.jsonl \
     --verbose` and require at least one CANCELLED line whose xfer_micros is close to \
     its abort_after_ms in milliseconds.";

fn abort_cancelled_early(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    let mut evidence = vec![
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
    ];
    push_opt(&mut evidence, ev_reset_unverified(c));
    Verdict {
        code: ABORT_CANCELLED_EARLY,
        headline: "The abort cancelled transfers before their own window elapsed: the primitive never \
                   waited, so the transfer never reached the wire."
            .to_string(),
        evidence,
        next_action: host_remedy(
            REMEDY_ABORT_CANCELLED_EARLY_WINDOWS,
            REMEDY_ABORT_CANCELLED_EARLY_LINUX,
        ),
        confidence: Confidence::High,
    }
}

fn pad_never_requested(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    let mut evidence = vec![
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
    ];
    push_opt(&mut evidence, ev_reset_unverified(c));
    Verdict {
        code: PAD_NEVER_REQUESTED,
        headline: "No pad request was ever sent: the first clause of gaster's SETUP predicate never \
                   held, so the STALL the exploit needs was never even attempted."
            .to_string(),
        evidence,
        next_action: "Re-run `a9pwn run --stage setup --trace setup.jsonl --verbose` and read the \
                      abort lines: `xfer=2048/2048` with `abort=Nms` means the cancel lost the race \
                      with completion. Shorten the window (`--abort-min-ms 0 --usb-timeout-ms 5`) and \
                      confirm a pad request appears in the trace before touching SPRAY or PATCH."
            .to_string(),
        confidence: Confidence::High,
    }
}

/// Windows remedy for [`pad_timeout_not_stall`] — CONTRACT, do not reflow.
const REMEDY_PAD_TIMEOUT_NOT_STALL_WINDOWS: &str = "Rule out the Windows reset trap first: `a9pwn ident` and require \
     `reset: real bus reset`; if it does not say that, run `a9drv bind --pid 1227` \
     elevated and retry. If the reset is real, re-run \
     `a9pwn run --stage setup --abort-min-ms 1 --usb-timeout-ms 5 --trace setup.jsonl \
     --verbose` (drops window 0, the zero-microsecond abort) and require at least one \
     abort line with `xfer=0/2048` and `xfer_micros` near its window.";

/// Linux remedy for [`pad_timeout_not_stall`]. The reset must still be ruled out
/// FIRST — but on this host that means measuring it (the `reset` line must read
/// `real bus reset`), not rebinding a driver that does not exist.
const REMEDY_PAD_TIMEOUT_NOT_STALL_LINUX: &str = "Rule out the reset first, on this host's \
     terms: run `a9pwn preflight` and require its `reset` line to read `real bus reset` — a \
     reset that returns in the ~237 ms class with the device answering afterwards is a real \
     `USBDEVFS_RESET` port reset, and there is no Windows pipe-cycle trap to fix by rebinding. \
     If the capability is not real, check /dev/bus/usb access for 05ac:1227 (a udev rule for \
     the device) and read `a9pwn reset`'s `what happened` line for an error. If the reset is \
     real, re-run `a9pwn run --stage setup --abort-min-ms 1 --usb-timeout-ms 5 --trace \
     setup.jsonl --verbose` (drops window 0, the zero-microsecond abort) and require at least \
     one abort line with `xfer=0/2048` and `xfer_micros` near its window.";

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
    push_opt(&mut evidence, ev_reset_unverified(c));

    Verdict {
        code: PAD_TIMEOUT_NOT_STALL,
        headline: "The pad request TIMED OUT instead of STALLing: the device is NAKing, so SETUP never \
                   converged and no STALL was ever available to detect."
            .to_string(),
        evidence,
        next_action: host_remedy(
            REMEDY_PAD_TIMEOUT_NOT_STALL_WINDOWS,
            REMEDY_PAD_TIMEOUT_NOT_STALL_LINUX,
        ),
        confidence: Confidence::High,
    }
}

/// Windows remedy for [`pad_error_not_stall`] — CONTRACT, do not reflow.
const REMEDY_PAD_ERROR_NOT_STALL_WINDOWS: &str = "Run `a9pwn run --stage setup --trace setup.jsonl --verbose` and read the pad \
     lines' `libusb_rc`: -1 (LIBUSB_ERROR_IO) or -4 (LIBUSB_ERROR_NO_DEVICE) means the \
     pipe or the node died mid-sweep. Power-cycle the phone, rebind with \
     `a9drv bind --pid 1227` elevated, confirm with `a9pwn ident`, then retry.";

/// Linux remedy for [`pad_error_not_stall`]. A transport fault is fixed by
/// re-seating the link and the permissions, not by rebinding a driver that does
/// not exist on this host.
const REMEDY_PAD_ERROR_NOT_STALL_LINUX: &str = "Run `a9pwn run --stage setup --trace setup.jsonl --verbose` and read the pad \
     lines' `libusb_rc`: -1 (LIBUSB_ERROR_IO) or -4 (LIBUSB_ERROR_NO_DEVICE) means the \
     pipe or the node died mid-sweep. Power-cycle the phone, replug it directly into a \
     root port (no hub), re-enumerate with `udevadm trigger --subsystem-match=usb` if the \
     node does not come back, confirm /dev/bus/usb access for 05ac:1227 (a udev rule for \
     the device) and `a9pwn ident`, then retry — there is no driver to rebind on Linux.";

fn pad_error_not_stall(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    let mut evidence = vec![
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
    ];
    push_opt(&mut evidence, ev_reset_unverified(c));
    Verdict {
        code: PAD_ERROR_NOT_STALL,
        headline: "The pad request failed at the host, not on the device: this is a transport fault, \
                   not the bootrom refusing the request."
            .to_string(),
        evidence,
        next_action: host_remedy(
            REMEDY_PAD_ERROR_NOT_STALL_WINDOWS,
            REMEDY_PAD_ERROR_NOT_STALL_LINUX,
        ),
        confidence: Confidence::Medium,
    }
}

fn setup_never_stalled(c: &Counters, ident: &DeviceIdentity) -> Verdict {
    let mut evidence = vec![
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
    ];
    push_opt(&mut evidence, ev_reset_unverified(c));
    Verdict {
        code: SETUP_NEVER_STALLED,
        headline: "SETUP exhausted its budget without the pad request ever STALLing. The heap \
                   corruption the rest of the exploit depends on did not happen."
            .to_string(),
        evidence,
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
    push_opt(&mut evidence, ev_reset_unverified(c));

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
    push_opt(&mut evidence, ev_reset_unverified(c));

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

/// Windows remedy for [`reset_capability_unknown`] — CONTRACT, do not reflow.
const REMEDY_RESET_CAPABILITY_UNKNOWN_WINDOWS: &str = "Run `a9pwn reset` (a bare port reset) and read its `capability` line, then run \
     `a9pwn preflight`. If either reports `pipe cycle only`, run \
     `a9drv bind --pid 1227` from an elevated prompt and repeat until `a9pwn ident` \
     prints `reset: real bus reset`.";

/// Linux remedy for [`reset_capability_unknown`]. `pipe cycle only` is a Windows
/// driver-model outcome, not a driver to rebind on this host: the measurement to
/// establish is the ~237 ms `USBDEVFS_RESET`, and the failure to rule out is
/// `/dev/bus/usb` access.
const REMEDY_RESET_CAPABILITY_UNKNOWN_LINUX: &str = "Run `a9pwn reset` (a bare port reset) and \
     read its `capability` and `what happened` lines, then run `a9pwn preflight` and require \
     its `reset` line to read `real bus reset` — a reset that returns in the ~237 ms class with \
     the device answering afterwards is a real `USBDEVFS_RESET` port reset on this host. If it \
     reports `pipe cycle only`, there is no driver to rebind: no kernel driver bound (`usbfs`) \
     is the NORMAL Linux state, and the fault is a measurement defect in `usb.rs` or \
     /dev/bus/usb access for 05ac:1227 (a udev rule for the device) — fix that before running \
     the exploit.";

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
    push_opt(&mut evidence, ev_reset_unverified(c));
    Verdict {
        code: RESET_CAPABILITY_UNKNOWN,
        headline: "The reset capability was never established. This is not the same as 'no capability' \
                   — it is a missing measurement, and it is the one this exploit depends on."
            .to_string(),
        evidence,
        next_action: host_remedy(
            REMEDY_RESET_CAPABILITY_UNKNOWN_WINDOWS,
            REMEDY_RESET_CAPABILITY_UNKNOWN_LINUX,
        ),
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
    push_opt(&mut evidence, ev_reset_unverified(c));

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
    push_opt(&mut evidence, ev_reset_unverified(c));
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
    use crate::types::{ResetEvidence, Stage, XferResult, XferStatus};

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
            "CPID:8003 CPRV:01 CPFM:03 SCEP:01 BDID:02 ECID:00112233445566AA IBFL:<redacted> \
             SRTG:[IBOOT-2234.0.0.2.22]",
        )
    }

    /// The same device AFTER a successful pwn: the reference's success predicate is
    /// the ` PWND:[checkm8]` suffix in the serial descriptor (`gaster.c:811`).
    fn ident_pwned() -> DeviceIdentity {
        DeviceIdentity::parse(
            "CPID:8003 CPRV:01 CPFM:03 SCEP:01 BDID:02 ECID:00112233445566AA IBFL:<redacted> \
             SRTG:[IBOOT-2234.0.0.2.22] PWND:[checkm8]",
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
        setup_log_counters_after(None)
    }

    /// The same replay, optionally preceded by one reset recorded through the real
    /// [`Tracer::reset`]. `Some(ResetEvidence::Unverified)` reproduces the live
    /// device's MEASURED signature (`a9pwn run --stage reset`): this bootrom rests at
    /// bState 5 and a full re-enumeration does not change that, so the transition
    /// `Delivered` requires — only PATCH's walk arranges it — is absent after the
    /// RESET stage.
    fn setup_log_counters_after(reset: Option<ResetEvidence>) -> Counters {
        let mut t = Tracer::new(None, false).expect("tracer");
        if let Some(evidence) = reset {
            t.reset(
                evidence,
                "after RESET (round 1): rc=0 capability=\"real bus reset\" interface_claimed=true",
            );
        }
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
        // The remedy is HOST-SELECTED (see `host_remedy`): the Windows text is
        // contract and stays asserted on Windows, while a Linux run must never be
        // handed `a9drv bind` — it does not exist there. Both assertions stay
        // compiled in this file; only the one for the running host executes.
        #[cfg(target_os = "windows")]
        {
            assert!(v.next_action.contains("a9drv bind --pid 1227"), "{}", v.next_action);
            assert!(v.next_action.contains("elevated") || v.next_action.contains("ELEVATED"));
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(v.next_action, REMEDY_NO_RESET_CAPABILITY_LINUX);
            assert!(!v.next_action.contains("from an ELEVATED prompt"), "{}", v.next_action);
            assert!(!v.next_action.contains("zadig-2.9.exe"), "{}", v.next_action);
        }

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

    // -----------------------------------------------------------------------
    // Ordering: a measured pwn outranks the driver/reset model
    // -----------------------------------------------------------------------
    //
    // The three tests below exist because of a real, dated incident. On
    // 2026-10-03 `a9pwn run` PWNED an Apple A9 on bare-metal Linux (exit 0) while
    // the verdict printed
    //     "The bound driver cannot reset the port, so checkm8 can never fire.
    //      [NO_RESET_CAPABILITY]  confidence: High"
    // in the same output block as `PWND marker present: Some("checkm8")`. The
    // Linux transport could not name a driver, so it counted two
    // `DriverCannotReset` resets as pipe cycles, and the reset block ran before
    // the success block. Each test pins one half of the fix.

    /// The exact live case, with the counters the Linux run actually produced.
    #[test]
    fn a_measured_pwn_outranks_an_unmeasurable_driver_class() {
        let c = counters(|c| {
            c.resets_attempted = 4;
            c.resets_pipe_cycle = 2;
        });
        let v = classify(
            &RunOutcome::Pwned,
            &c,
            &ident_pwned(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        );
        assert_eq!(v.code, PWNED, "headline was: {}", v.headline);
        assert_eq!(v.confidence, Confidence::High);
        assert!(
            !v.headline.contains("never fire"),
            "a pwned device was told checkm8 can never fire: {}",
            v.headline
        );
    }

    /// The same rule against the Windows model. WinUSB genuinely cannot reset the
    /// port, but that is a statement about what a *future* attempt can achieve — it
    /// cannot make an already-pwned device un-pwned, and a verdict must not claim it.
    #[test]
    fn a_measured_pwn_outranks_winusb() {
        let v = classify(
            &RunOutcome::Pwned,
            &Counters::default(),
            &ident_pwned(),
            DriverClass::WinUsb,
            ResetCapability::PipeCycleOnly,
        );
        assert_eq!(v.code, PWNED, "headline was: {}", v.headline);
        assert!(!v.headline.contains("never fire"), "{}", v.headline);
    }

    /// **The whole ordering domain, pinned entry by entry.**
    ///
    /// The two tests above pin the case that actually happened. This one pins the
    /// rest of the matrix, because §9.3's lesson is that a test named for a property
    /// can pass while checking three of eleven cases: `dfu_state_names_are_accurate`
    /// verified exactly the states the table happened to have right. A reordering
    /// like the one under test is precisely the kind of change whose damage shows up
    /// in the rows nobody looked at.
    ///
    /// The `Unknown`/`Unknown` + `resets_pipe_cycle = 2` row is the LIVE incident,
    /// reproduced synthetically because the real device no longer reports it: after
    /// task-1 landed, this same hardware correctly reports `usbfs` / `Real`, so the
    /// broken input can only be reconstructed from the counters that run left behind
    /// (`resets_attempted=4 resets_pipe_cycle=2`, `driver_class=unknown`).
    #[test]
    fn the_pwn_outranks_the_driver_model_across_the_whole_matrix() {
        // (label, outcome, ident, driver, cap, pipe_cycle_counter, expected code)
        let cases: Vec<(&str, RunOutcome, DeviceIdentity, DriverClass, ResetCapability, u64, &str)> = vec![
            (
                "LIVE INCIDENT: pwned run, no classifiable driver, 2 pipe cycles",
                RunOutcome::Pwned,
                ident_pwned(),
                DriverClass::Unknown,
                ResetCapability::Unknown,
                2,
                PWNED,
            ),
            (
                "pwned run on a WinUSB host (a real pwn cannot be undone by a driver)",
                RunOutcome::Pwned,
                ident_pwned(),
                DriverClass::WinUsb,
                ResetCapability::PipeCycleOnly,
                0,
                PWNED,
            ),
            (
                "run claims success but the reference's marker is absent",
                RunOutcome::Pwned,
                ident_a9(),
                DriverClass::LibusbK,
                ResetCapability::Real,
                0,
                PWNED_UNCONFIRMED,
            ),
            (
                "marker already present, this run exhausted: pwned, but not by this run",
                exhausted(64),
                ident_pwned(),
                DriverClass::Unknown,
                ResetCapability::Unknown,
                0,
                PWNED,
            ),
            (
                "no marker, no driver, measured pipe cycles: the Windows diagnosis",
                exhausted(64),
                ident_a9(),
                DriverClass::Unknown,
                ResetCapability::Unknown,
                2,
                NO_RESET_CAPABILITY,
            ),
            (
                "no marker, WinUSB bound: the prior session's signature",
                exhausted(64),
                ident_a9(),
                DriverClass::WinUsb,
                ResetCapability::PipeCycleOnly,
                0,
                NO_RESET_CAPABILITY,
            ),
        ];

        for (label, outcome, ident, driver, cap, cycles, want) in cases {
            let c = counters(|c| {
                c.resets_attempted = if cycles > 0 { 4 } else { 0 };
                c.resets_pipe_cycle = cycles;
            });
            let v = classify(&outcome, &c, &ident, driver, cap);
            assert_eq!(v.code, want, "case {label:?} -> got {} ({})", v.code, v.headline);
        }
    }

    /// The boundary the reordering must NOT have moved: with no marker AND no
    /// driver, the run's own outcome still decides between the two "nothing worked"
    /// verdicts. Without this row, moving the success block to the top could have
    /// silently swallowed every failure into `PWNED_UNCONFIRMED`.
    #[test]
    fn without_a_marker_a_success_claim_is_still_refused() {
        let v = classify(
            &RunOutcome::Pwned,
            &Counters::default(),
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, PWNED_UNCONFIRMED);
        assert!(v.headline.contains("NOT pwned"), "{}", v.headline);
        assert!(v.confidence == Confidence::High || v.confidence == Confidence::Low);
    }

    /// Marker present but THIS run did not report success: the device is pwned, and
    /// the verdict must not let a reader believe this run did it.
    #[test]
    fn a_marker_present_before_the_run_is_pwned_and_says_the_run_did_not_do_it() {
        let v = classify(
            &exhausted(64),
            &Counters::default(),
            &ident_pwned(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        );
        assert_eq!(v.code, PWNED, "headline was: {}", v.headline);
        let all = v.evidence.join("\n");
        assert!(
            all.contains("already pwned when the run started"),
            "the verdict must say the run did not produce the marker: {all}"
        );
        assert!(all.contains("Exhausted"), "{all}");
    }

    /// Negative control for the pair above: with the marker ABSENT, the reset model
    /// must still be able to win, or the reordering would have silenced a real
    /// diagnosis. This is the same call as the live incident minus the pwn.
    #[test]
    fn without_the_marker_the_reset_model_still_wins() {
        let c = counters(|c| {
            c.resets_attempted = 4;
            c.resets_pipe_cycle = 2;
        });
        let v = classify(
            &exhausted(4),
            &c,
            &ident_a9(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        );
        assert_eq!(v.code, NO_RESET_CAPABILITY);
    }

    /// On Linux the Windows remedy is not merely unhelpful, it does not exist.
    /// Linux-gated because the branch it pins is host-selected.
    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_an_unmeasured_capability_is_a_missing_measurement_not_a_driver_fault() {
        // `resets_pipe_cycle > 0` is what reaches `no_reset_capability` here — the
        // live run counted 2, which is precisely how a Linux host with no
        // classifiable driver ended up inside a Windows verdict.
        let c = counters(|c| {
            c.resets_attempted = 4;
            c.resets_pipe_cycle = 2;
        });
        let v = classify(
            &exhausted(4),
            &c,
            &ident_a9(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        );
        assert_eq!(v.code, NO_RESET_CAPABILITY);
        assert_eq!(v.next_action, REMEDY_NO_RESET_CAPABILITY_LINUX);
        assert!(
            v.next_action.contains("missing MEASUREMENT"),
            "{}",
            v.next_action
        );
        // The negative control is about what the text PRESCRIBES, not about which
        // words appear: the Linux text deliberately names the Windows tools in order
        // to forbid them. So pin the Windows remedy's own invocations, which must be
        // absent — an earlier version of this test asserted on the bare substring and
        // failed against its own prose.
        assert!(
            !v.next_action.contains("from an ELEVATED prompt")
                && !v.next_action.contains("zadig-2.9.exe"),
            "a Linux host was handed the Windows remedy: {}",
            v.next_action
        );
        assert!(
            v.next_action.contains("Do NOT run `a9drv bind`"),
            "the Linux text must name the Windows remedy only to forbid it: {}",
            v.next_action
        );
        assert_eq!(
            v.confidence,
            Confidence::Low,
            "an unmeasured capability is not a High-confidence device property"
        );
        assert!(v.evidence.join("\n").contains("not measured on this host"));
    }


    /// The live device, MEASURED by the Lead (`a9pwn run --stage reset`): the reset's
    /// evidence was `Unverified` and the tracer counted it as a pipe cycle, so
    /// `classify` blamed a libusbK driver that was never at fault. It must now be
    /// classified by what actually failed in the sweep.
    #[test]
    fn an_unverified_live_reset_is_not_reported_as_a_driver_fault() {
        let c = setup_log_counters_after(Some(ResetEvidence::Unverified));
        assert_eq!(c.resets_attempted, 1, "the reset was attempted");
        assert_eq!(c.resets_real, 0);
        assert_eq!(c.resets_unverified, 1);
        assert_eq!(
            c.resets_pipe_cycle, 0,
            "an unverified reset must never be counted as a pipe cycle"
        );

        let v = classify(
            &exhausted(64),
            &c,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, PAD_TIMEOUT_NOT_STALL, "{:?}", v);
        assert_ne!(v.code, NO_RESET_CAPABILITY);
        assert_ne!(v.code, RESET_NOT_DELIVERED);
        // Nothing in it may blame the reset: no pipe-cycle claim, no WinUSB driver.
        let all = v.evidence.join("\n").to_ascii_lowercase();
        assert!(!all.contains("pipe cycle"), "{:?}", v.evidence);
        assert!(!all.contains("driver_class=winusb"), "{:?}", v.evidence);
    }

    /// …but a driver that genuinely cannot reset still has to name itself, however
    /// healthy the live capability probe looked.
    #[test]
    fn a_driver_cannot_reset_is_still_a_driver_fault() {
        let c = setup_log_counters_after(Some(ResetEvidence::DriverCannotReset));
        assert_eq!(c.resets_pipe_cycle, 1);
        assert_eq!(c.resets_unverified, 0);
        let v = classify(
            &exhausted(64),
            &c,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, NO_RESET_CAPABILITY, "{:?}", v);
        assert_eq!(v.confidence, Confidence::High);
        assert!(
            v.evidence.join("\n").contains("resets_pipe_cycle=1"),
            "{:?}",
            v.evidence
        );
    }

    /// A refuted reset is a measurement of non-delivery, and it is distinguishable
    /// from both a driver fault and an unverifiable reset.
    #[test]
    fn a_refuted_reset_is_a_measured_non_delivery() {
        let refuted = setup_log_counters_after(Some(ResetEvidence::Refuted));
        assert_eq!(refuted.resets_refuted, 1);
        assert_eq!(refuted.resets_unverified, 0);
        let v = classify(
            &exhausted(64),
            &refuted,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, RESET_NOT_DELIVERED, "{:?}", v);
        assert_ne!(v.code, NO_RESET_CAPABILITY);
        assert!(v.evidence.join("\n").contains("resets_refuted=1"), "{:?}", v.evidence);

        // The same sweep with an unverifiable reset instead is NOT non-delivery.
        let unverified = setup_log_counters_after(Some(ResetEvidence::Unverified));
        let u = classify(
            &exhausted(64),
            &unverified,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(u.code, PAD_TIMEOUT_NOT_STALL, "{:?}", u);
        assert_ne!(u.code, v.code, "refuted and unverified are different problems");
    }

    /// Absence of a delivery is not evidence of non-delivery. A run whose resets are
    /// all unverifiable and which matched no other signature must not claim the reset
    /// was never delivered — and the unverifiable resets must still be visible on
    /// whatever verdict does come out.
    #[test]
    fn unverifiable_resets_alone_never_claim_non_delivery() {
        let mut t = Tracer::new(None, false).expect("tracer");
        for _ in 0..6 {
            t.reset(ResetEvidence::Unverified, "bState 5 at rest; re-enumeration did not change it");
        }
        t.round(1, "stage=SETUP");
        let c = t.counters();
        assert_eq!(c.resets_attempted, 6);
        assert_eq!(c.resets_unverified, 6);
        assert_eq!(c.resets_refuted, 0);
        assert_eq!(c.resets_unrecorded(), 0);
        assert!(!c.reset_non_delivery_measured());

        let v = classify(
            &exhausted(6),
            &c,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_ne!(v.code, RESET_NOT_DELIVERED, "{:?}", v);
        assert_ne!(v.code, NO_RESET_CAPABILITY, "{:?}", v);
        assert_eq!(v.code, EXHAUSTED_UNKNOWN, "{:?}", v);
        let all = v.evidence.join("\n");
        assert!(all.contains("resets_unverified=6"), "{all}");
        assert!(all.contains("NOT the cause"), "{all}");
        // The evidence must carry the MEASUREMENT, not the mechanism we used to
        // assume: this bootrom rests at bState 5 and re-enumeration does not change it,
        // so an absent transition after RESET/SETUP/SPRAY proves nothing about delivery.
        assert!(all.contains("bState 5"), "{all}");
        assert!(all.contains("MEASURED"), "{all}");
        assert!(all.contains("PATCH-only instrument"), "{all}");
        assert!(
            !all.contains("mid-download"),
            "the unsupported mid-download mechanism claim must not come back: {all}"
        );
    }

    /// The one case with no `ResetEvidence` that still *is* non-delivery: the reset
    /// call itself failed, so no bus reset was delivered and nothing was observed.
    #[test]
    fn a_failed_reset_call_is_evidenced_non_delivery() {
        let mut t = Tracer::new(None, false).expect("tracer");
        for _ in 0..2 {
            t.event(
                crate::trace::kind::RESET,
                Some(Stage::Reset),
                "the reset call failed",
            );
        }
        let c = t.counters();
        assert_eq!(c.resets_attempted, 2);
        assert_eq!(c.resets_unrecorded(), 2, "two attempts, no evidence state");
        assert!(c.reset_non_delivery_measured());

        let v = classify(
            &exhausted(2),
            &c,
            &ident_a9(),
            DriverClass::LibusbK,
            ResetCapability::Real,
        );
        assert_eq!(v.code, RESET_NOT_DELIVERED, "{:?}", v);
        assert!(v.evidence.join("\n").contains("unrecorded=2"), "{:?}", v.evidence);
        assert!(
            v.evidence.join("\n").contains("failed outright"),
            "the evidence must name which of the two positive cases fired: {:?}",
            v.evidence
        );
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

    /// The DFU entry instruction has to be one the operator can actually follow on
    /// THIS device class. This is an iPhone SE 1st gen (`CPID 0x8003`, BDID 0x02,
    /// `SRTG [IBOOT-2234.0.0.2.22]`): a mechanical Home button, so Power + Home.
    /// Power + VolDown is the solid-state-Home combo (iPhone 7/8/X) and does nothing
    /// here — a next_action that cannot be followed is worse than none, because the
    /// operator concludes the device is unrecoverable.
    #[test]
    fn dfu_entry_instructions_are_followable_on_a_mechanical_home_device() {
        let verdicts = reachable_verdicts(classify(
            &exhausted(64),
            &setup_log_counters(),
            &ident_a9(),
            DriverClass::WinUsb,
            ResetCapability::PipeCycleOnly,
        ));
        let mut checked = 0;
        for v in verdicts {
            if !v.next_action.contains("DFU") {
                continue;
            }
            checked += 1;
            let a = &v.next_action;
            assert!(
                a.contains("Power + Home"),
                "{} must name this device's class combo: {a}",
                v.code
            );
            assert!(
                !a.contains("Power+VolDown") && !a.contains("keep VolDown"),
                "{} still instructs the solid-state-Home combo: {a}",
                v.code
            );
            assert!(
                a.contains("BLACK"),
                "{} must say the screen stays black in DFU: {a}",
                v.code
            );
            assert!(
                a.contains("VID_05AC&PID_1227"),
                "{} must give the operator a host-side check, since the screen cannot confirm: {a}",
                v.code
            );
        }
        assert!(
            checked >= 4,
            "expected the DFU-entry instructions to be reachable; only checked {checked}"
        );
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

    // -----------------------------------------------------------------------
    // Host-aware remedies: the Windows contract, executable on either host
    // -----------------------------------------------------------------------
    //
    // Before this section, `verdict.rs` handed Linux operators `a9drv bind`,
    // `zadig-2.9.exe` and `pnputil /scan-devices` — none of which exist on this
    // host — and `next_action` is the field a reader ACTS on. Three different
    // tests, because one cannot do all three jobs:
    //
    //   1. `remedy_pairs_state_both_hosts_texts` — the selector and the detector,
    //      every pair asserted from both hosts' side, with the detector's own
    //      sensitivity as the negative control;
    //   2. `the_windows_remedies_are_the_bytes_the_presplit_file_emitted` — the
    //      whole Windows set pinned by hash, so "unchanged" is a MEASUREMENT and
    //      not an assertion;
    //   3. `every_reachable_next_action_is_non_empty_and_host_correct` plus
    //      `no_windows_only_invocation_escapes_the_windows_consts` — the whole
    //      domain of `classify`, and the whole file, rather than the handy sample
    //      (HANDOFF §9.3: a test named for a property passed while checking three
    //      of eleven cases).
    //
    // Each of the three has a negative control that was run and shown to fail:
    // see `the_windows_only_detector_fails_on_a_doctored_linux_remedy`,
    // `the_windows_manifest_detects_a_single_doctored_byte`, and the doctored
    // source inside `no_windows_only_invocation_escapes_the_windows_consts`.

    /// Every remedy that names Windows-only tooling, as `(code, Windows, Linux)`.
    ///
    /// Order is the order the builders appear in this file. The set is pinned by
    /// `remedy_pairs_cover_the_whole_set`: a pair missing from this table is a
    /// pair whose Linux half no test ever reads.
    const REMEDY_PAIRS: &[(&str, &str, &str)] = &[
        (
            NO_RESET_CAPABILITY,
            REMEDY_NO_RESET_CAPABILITY_WINDOWS,
            REMEDY_NO_RESET_CAPABILITY_LINUX,
        ),
        (
            PWNED_UNCONFIRMED,
            REMEDY_PWNED_UNCONFIRMED_WINDOWS,
            REMEDY_PWNED_UNCONFIRMED_LINUX,
        ),
        (DEVICE_ABSENT, REMEDY_DEVICE_ABSENT_WINDOWS, REMEDY_DEVICE_ABSENT_LINUX),
        (
            DEVICE_PATH_TOO_LONG,
            REMEDY_DEVICE_PATH_TOO_LONG_WINDOWS,
            REMEDY_DEVICE_PATH_TOO_LONG_LINUX,
        ),
        (
            WRONG_DRIVER_BOUND,
            REMEDY_WRONG_DRIVER_BOUND_WINDOWS,
            REMEDY_WRONG_DRIVER_BOUND_LINUX,
        ),
        (
            DRIVER_BOUND_NOT_LOADED,
            REMEDY_DRIVER_BOUND_NOT_LOADED_WINDOWS,
            REMEDY_DRIVER_BOUND_NOT_LOADED_LINUX,
        ),
        (
            DEVICE_LOST_MID_RUN,
            REMEDY_DEVICE_LOST_MID_RUN_WINDOWS,
            REMEDY_DEVICE_LOST_MID_RUN_LINUX,
        ),
        (
            IDENTITY_UNREADABLE,
            REMEDY_IDENTITY_UNREADABLE_WINDOWS,
            REMEDY_IDENTITY_UNREADABLE_LINUX,
        ),
        (WRONG_BOOT_STAGE, REMEDY_WRONG_BOOT_STAGE_WINDOWS, REMEDY_WRONG_BOOT_STAGE_LINUX),
        (
            RESET_NOT_DELIVERED,
            REMEDY_RESET_NOT_DELIVERED_WINDOWS,
            REMEDY_RESET_NOT_DELIVERED_LINUX,
        ),
        (
            ABORT_CANCELLED_EARLY,
            REMEDY_ABORT_CANCELLED_EARLY_WINDOWS,
            REMEDY_ABORT_CANCELLED_EARLY_LINUX,
        ),
        (
            PAD_TIMEOUT_NOT_STALL,
            REMEDY_PAD_TIMEOUT_NOT_STALL_WINDOWS,
            REMEDY_PAD_TIMEOUT_NOT_STALL_LINUX,
        ),
        (
            PAD_ERROR_NOT_STALL,
            REMEDY_PAD_ERROR_NOT_STALL_WINDOWS,
            REMEDY_PAD_ERROR_NOT_STALL_LINUX,
        ),
        (
            RESET_CAPABILITY_UNKNOWN,
            REMEDY_RESET_CAPABILITY_UNKNOWN_WINDOWS,
            REMEDY_RESET_CAPABILITY_UNKNOWN_LINUX,
        ),
    ];

    /// Windows-only *content*, in two layers, because one layer is not enough —
    /// and a reviewer proved it: appending
    /// ``If that fails run `a9drv bind` or open Zadig.`` to a Linux remedy left
    /// every test green, because ``a9drv bind`` without ``--pid 1227`` and
    /// ``Zadig`` without ``.exe`` are different strings from the ones a
    /// single-layer list happens to hold.
    ///
    /// **Layer 1 — exact invocations.** A phrase that tells the reader to run a
    /// tool, or a host-side check, that only a Windows host has. A finding
    /// wherever it appears, including inside a prohibition: a Linux remedy has no
    /// reason to spell one out this precisely.
    ///
    /// **Layer 2 — a Windows tool NAME in a sentence that does not forbid it.**
    /// The Linux remedies DO name these tools — in order to forbid them — so the
    /// name is the finding only when its sentence carries no prohibition:
    /// "Do NOT run `a9drv bind`" passes, "run `a9drv bind`" does not.
    ///
    /// `libusbK` and `WinUSB` are deliberately NOT names here: they are driver
    /// *classes* a verdict must be able to REPORT (`driver service: {driver}`,
    /// "not a libusb driver"), not tools the reader is told to run. A prescription
    /// that names one of them also names `a9drv` or `install`, which layer 2 does
    /// cover. This is still a lexical bound, not a proof: it pins the markers
    /// below, and `remedy_pairs_state_both_hosts_texts` proves the bound is not
    /// vacuous by making it fire on every Windows half.
    const WINDOWS_ONLY_INVOCATIONS: &[&str] = &[
        "`a9drv bind --pid 1227`",
        "zadig-2.9.exe",
        "pnputil",
        "Get-PnpDevice",
        "Select-String",
        "king.exe",
        "from an ELEVATED prompt",
        "--allow-winusb",
        "`char dev_id[256]`",
    ];

    /// Windows-only tool names for layer 2, matched case-insensitively. These may
    /// not appear in ANY emitted field, evidence included.
    /// `powershell`, `setupapi` and `dpinst` were added after a reviewer showed
    /// "Run PowerShell to re-enumerate the node." passed the first version.
    const WINDOWS_TOOL_NAMES: &[&str] = &[
        "a9drv",
        "zadig",
        "pnputil",
        "get-pnpdevice",
        "select-string",
        "king.exe",
        "device manager",
        "allow-winusb",
        "powershell",
        "dpinst",
    ];

    /// Windows-only internals that must not appear in a REMEDY but may legitimately
    /// appear in `evidence`, whose job is to name the measurement: the
    /// `device_path_too_long` evidence says "measured by our own SetupAPI pass", and
    /// that is a citation, not an instruction. A reviewer's mutation showed that
    /// leaving evidence entirely unchecked also let a prescription through, so
    /// evidence IS checked — against layer 1 and the tool names above, not these.
    const WINDOWS_ONLY_INTERNALS: &[&str] = &["setupapi", "dev_id[256]", "elevated prompt"];

    /// A clause carrying a Windows tool name is a finding unless it also says
    /// why that tool is not usable here.
    ///
    /// `no` and `cannot` are in this list because a reviewer's false-positive
    /// probe showed correct remedies written as "There is no `zadig` on this
    /// host." and "This host cannot run `a9drv`." were rejected. A check that
    /// rejects correct text gets loosened by the next author, which is how a
    /// detector dies, so the natural phrasings must pass.
    ///
    /// Deliberately NOT position-aware: requiring the negation to precede the
    /// name would reject the equally natural "`a9drv bind` is not available on
    /// this host". Clause splitting (on `,` and `—` as well as sentence enders)
    /// is what keeps this honest — a prescription in a LATER clause cannot hide
    /// behind a negation in an earlier one.
    const PROHIBITIONS: &[&str] = &[
        "not",
        "never",
        "without",
        "cannot",
        "no",
        "isn't",
        "doesn't",
        "don't",
        "windows-only",
        "unavailable",
    ];

    /// `needle` occurs in `haystack` as a whole word. Substring matching let the
    /// prohibition `not` match inside `Notably`, which is how a reviewer got
    /// "Notably, run `a9drv bind` elevated." past the first version of layer 2.
    fn contains_word(haystack: &str, needle: &str) -> bool {
        let bytes = haystack.as_bytes();
        let mut from = 0;
        while let Some(rel) = haystack[from..].find(needle) {
            let start = from + rel;
            let end = start + needle.len();
            let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
            let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
            from = start + 1;
        }
        false
    }

    fn windows_only_marker_named(text: &str, names: &[&'static str]) -> Option<&'static str> {
        if let Some(invocation) = WINDOWS_ONLY_INVOCATIONS
            .iter()
            .copied()
            .find(|t| text.contains(t))
        {
            return Some(invocation);
        }
        let lower = text.to_ascii_lowercase();
        // CLAUSES, not just sentences: a reviewer showed that
        // "The `a9drv bind` tool is not available here, so run `a9drv bind` elevated."
        // satisfied a sentence-scoped prohibition with a negation belonging to a
        // different clause.
        for clause in lower.split(['.', ';', ':', '!', '?', ',', '—']) {
            if let Some(name) = names.iter().copied().find(|n| clause.contains(n)) {
                if !PROHIBITIONS.iter().any(|p| contains_word(clause, p)) {
                    return Some(name);
                }
            }
        }
        None
    }

    /// A finding in `next_action` and `headline`: layer 1, every tool name, and the
    /// Windows internals a remedy must not prescribe.
    fn windows_only_marker(text: &str) -> Option<&'static str> {
        windows_only_marker_named(text, WINDOWS_TOOL_NAMES)
            .or_else(|| windows_only_marker_named(text, WINDOWS_ONLY_INTERNALS))
    }

    /// A finding in `evidence`: layer 1 and the tool names, but not the internals
    /// that evidence cites as the source of a measurement.
    #[cfg(test)]
    fn windows_only_marker_in_evidence(text: &str) -> Option<&'static str> {
        windows_only_marker_named(text, WINDOWS_TOOL_NAMES)
    }

    /// The only placeholder any remedy text carries. `wrong_driver_bound` is
    /// reached exclusively with `DriverClass::Other` (see `classify`), so "other"
    /// is the substitution that site can actually emit.
    fn fill_placeholder(text: &str) -> String {
        text.replace("{driver}", "other")
    }

    /// The Windows remedy set as bytes: placeholder filled, each text followed by
    /// 0x1f. Computed over the consts, so a byte change anywhere in the set moves
    /// the hash.
    fn windows_remedy_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        for (_code, windows, _linux) in REMEDY_PAIRS {
            out.extend_from_slice(fill_placeholder(windows).as_bytes());
            out.push(0x1f);
        }
        out
    }

    fn fnv1a64(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// The selector, both ways, and the detector's sensitivity — on whichever
    /// host runs the suite, because `remedy_for` takes the host as a value.
    #[test]
    fn remedy_pairs_state_both_hosts_texts() {
        assert!(!REMEDY_PAIRS.is_empty());
        for (code, windows, linux) in REMEDY_PAIRS {
            assert_ne!(windows, linux, "{code} has one text for two hosts");
            assert_eq!(
                remedy_for(RemedyHost::Windows, windows, linux),
                *windows,
                "{code}: the Windows text must come back byte for byte"
            );
            assert_eq!(remedy_for(RemedyHost::Linux, windows, linux), *linux, "{code}");
            // Negative control for the selector: it must not leak the Windows
            // text to Linux, or every check below would be testing nothing.
            assert_ne!(
                remedy_for(RemedyHost::Linux, windows, linux),
                *windows,
                "{code}: the Linux selection returned the Windows text"
            );
            // …and each arm must genuinely IGNORE the other host's argument: a
            // poisoned argument cannot change what the selected host emits.
            assert_eq!(
                remedy_for(RemedyHost::Windows, windows, "POISONED LINUX ARM"),
                *windows,
                "{code}: the Windows selection read the Linux argument"
            );
            assert_eq!(
                remedy_for(RemedyHost::Linux, "POISONED WINDOWS ARM", linux),
                *linux,
                "{code}: the Linux selection read the Windows argument"
            );
            // Negative control for the detector: it must FIRE on every Windows
            // half. Its silence on the Linux halves only means something if it
            // can see these tokens at all.
            assert!(
                windows_only_marker(windows).is_some(),
                "{code}: no Windows-only invocation found in the Windows remedy, so the detector \
                 is blind and its verdict on the Linux remedy proves nothing: {windows}"
            );
            assert_eq!(
                windows_only_marker(linux),
                None,
                "{code}: the Linux remedy prescribes a Windows-only invocation: {linux}"
            );
        }
    }

    /// §9.3's lesson applied to this table: a table named for the whole set must
    /// pin the whole set. If a builder grows a Windows/Linux pair, this is what
    /// notices that the pair was never added here.
    #[test]
    fn remedy_pairs_cover_the_whole_set() {
        let mut codes: Vec<&str> = REMEDY_PAIRS.iter().map(|(c, _, _)| *c).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n, "a code appears twice in REMEDY_PAIRS");
        let mut expected = vec![
            NO_RESET_CAPABILITY,
            PWNED_UNCONFIRMED,
            DEVICE_ABSENT,
            DEVICE_PATH_TOO_LONG,
            WRONG_DRIVER_BOUND,
            DRIVER_BOUND_NOT_LOADED,
            DEVICE_LOST_MID_RUN,
            IDENTITY_UNREADABLE,
            WRONG_BOOT_STAGE,
            RESET_NOT_DELIVERED,
            ABORT_CANCELLED_EARLY,
            PAD_TIMEOUT_NOT_STALL,
            PAD_ERROR_NOT_STALL,
            RESET_CAPABILITY_UNKNOWN,
        ];
        expected.sort_unstable();
        assert_eq!(
            codes, expected,
            "the remedied set changed: add the new pair to REMEDY_PAIRS, or its Linux text is \
             pinned by nothing"
        );
    }

    /// The detector's negative control, with the doctoring OUTSIDE the table: a
    /// Linux remedy that grows a Windows invocation must be caught even though
    /// `REMEDY_PAIRS` still holds the clean text.
    #[test]
    fn the_windows_only_detector_fails_on_a_doctored_linux_remedy() {
        let text = REMEDY_PAD_TIMEOUT_NOT_STALL_LINUX;
        assert_eq!(windows_only_marker(text), None, "the baseline must be clean");
        let doctored = format!(
            "{text} If that fails, run `a9drv bind --pid 1227` from an ELEVATED prompt."
        );
        assert_eq!(
            windows_only_marker(&doctored),
            Some("`a9drv bind --pid 1227`"),
            "the detector must catch a Windows invocation appended to a Linux remedy"
        );
        // …and the selector would hand that doctored text to Linux unchanged,
        // which is exactly how the live incident reached an operator.
        assert_eq!(remedy_for(RemedyHost::Linux, "windows text", &doctored), doctored);
    }

    /// The other way a Windows-only instruction could reach a Linux operator:
    /// through an ARGUMENT, not through the literal. `wrong_driver_bound` is the
    /// one remedy that interpolates (`{driver}`), so the closed set of values it
    /// can interpolate is pinned here — every `DriverClass` variant, not the one
    /// the tests happen to use.
    #[test]
    fn the_interpolated_driver_name_cannot_smuggle_a_windows_marker_into_a_linux_remedy() {
        let classes = [
            DriverClass::LibusbK,
            DriverClass::Libusb0,
            DriverClass::WinUsb,
            DriverClass::Usbfs,
            DriverClass::Other,
            DriverClass::Unknown,
        ];
        for class in &classes {
            let text = REMEDY_WRONG_DRIVER_BOUND_LINUX.replace("{driver}", class.as_str());
            assert_eq!(
                windows_only_marker(&text),
                None,
                "driver_class={} puts a Windows marker into the Linux remedy: {text}",
                class.as_str()
            );
        }
        // Negative control: an interpolated value that DID carry a tool name would
        // be caught, so the loop above is not vacuous.
        let doctored = REMEDY_WRONG_DRIVER_BOUND_LINUX.replace("{driver}", "pnputil");
        assert!(windows_only_marker(&doctored).is_some());
        // …and the same check on the Windows half must FIRE on the real value, or
        // the `None`s above would only mean the detector is asleep.
        let windows_text = REMEDY_WRONG_DRIVER_BOUND_WINDOWS.replace("{driver}", "other");
        assert!(windows_only_marker(&windows_text).is_some());
    }

    /// The whole Windows *remedy* set, by hash — not every Windows-visible
    /// string: `evidence` still cites Windows internals by design and is not
    /// pinned here. Pinned from the pre-split file
    /// (`/tmp/verdict.rs.orig`, sha256 `02C85CBA1E7256C6…`) by a script that
    /// decoded each original Rust literal with the compiler's own rules and
    /// reported all 14 sites byte-identical before this constant was written;
    /// `/tmp/compare_windows.py` reproduces that comparison. FNV-1a is not a
    /// cryptographic hash — it detects ACCIDENTAL change, which is what a
    /// regression pin is for; the byte-identity proof is decode-and-compare.
    #[test]
    fn the_windows_remedies_are_the_bytes_the_presplit_file_emitted() {
        const WINDOWS_REMEDY_FNV1A64: u64 = 0xFD10_3BB1_7430_5133;
        assert_eq!(
            fnv1a64(&windows_remedy_bytes()),
            WINDOWS_REMEDY_FNV1A64,
            "a Windows remedy changed: the Windows behaviour is contract (HANDOFF §9.3)"
        );
    }

    /// Negative control for the hash above: one byte is enough to move it, so a
    /// green hash is evidence rather than a constant that never had a chance to
    /// fail.
    #[test]
    fn the_windows_manifest_detects_a_single_doctored_byte() {
        let clean = windows_remedy_bytes();
        let pin = fnv1a64(&clean);
        assert_eq!(pin, 0xFD10_3BB1_7430_5133);
        let mut doctored = clean.clone();
        // A trailing space on the last Windows remedy — the smallest edit that
        // would still be invisible to a human reading a log.
        doctored.insert(doctored.len() - 2, b' ');
        assert_ne!(
            fnv1a64(&doctored),
            pin,
            "the manifest cannot see a one-byte change"
        );
    }

    /// Every code `classify` can return, from the Windows-model seed and from the
    /// Linux-measured seed, so the property "no `next_action` hands a Linux
    /// operator a Windows-only invocation" is checked over the whole domain and
    /// not over the sample that happened to be handy (HANDOFF §9.3).
    fn every_reachable_verdict() -> Vec<Verdict> {
        let windows_model = classify(
            &exhausted(64),
            &setup_log_counters(),
            &ident_a9(),
            DriverClass::WinUsb,
            ResetCapability::PipeCycleOnly,
        );
        // The LIVE Linux incident's counters: no classifiable driver, a measured
        // pipe cycle, and a run that produced no marker.
        let linux_measured = classify(
            &exhausted(4),
            &counters(|c| {
                c.resets_attempted = 4;
                c.resets_pipe_cycle = 2;
            }),
            &ident_a9(),
            DriverClass::Unknown,
            ResetCapability::Unknown,
        );
        let mut all = reachable_verdicts(windows_model);
        all.extend(reachable_verdicts(linux_measured));
        all
    }

    #[test]
    fn every_reachable_next_action_is_non_empty_and_host_correct() {
        let verdicts = every_reachable_verdict();

        let mut codes: Vec<&str> = verdicts.iter().map(|v| v.code).collect();
        codes.sort_unstable();
        codes.dedup();
        let mut expected = CODES.to_vec();
        expected.sort_unstable();
        assert_eq!(
            codes, expected,
            "this test must cover every code `classify` can return, not a sample"
        );

        for v in &verdicts {
            assert!(
                !v.next_action.trim().is_empty(),
                "{} has an empty next_action",
                v.code
            );
            assert!(!v.headline.trim().is_empty(), "{} has an empty headline", v.code);
            // Every emitted field is checked, not just the one the operator acts
            // on: `headline` is the first line they read, and `evidence` is what
            // they check the verdict against. The exemption this used to carry
            // ("evidence cites `windows_winusb.c`") was not needed — that citation
            // carries no marker — and a reviewer put a prescription in evidence to
            // prove the gap was real.
            #[cfg(target_os = "linux")]
            {
                let fields = [
                    ("next_action", &v.next_action),
                    ("headline", &v.headline),
                ];
                for (field, text) in fields {
                    if let Some(hit) = windows_only_marker(text) {
                        panic!(
                            "{} hands a Linux operator Windows-only content in its {field} \
                             ({hit:?}): {text}",
                            v.code
                        );
                    }
                }
                for (i, evidence) in v.evidence.iter().enumerate() {
                    if let Some(hit) = windows_only_marker_in_evidence(evidence) {
                        panic!(
                            "{} hands a Linux operator Windows-only content in evidence[{i}] \
                             ({hit:?}): {evidence}",
                            v.code
                        );
                    }
                }
            }
        }

        // The Linux halves are not merely clean, they are REACHABLE: a table
        // entry no input can produce would be a pin on dead text.
        #[cfg(target_os = "linux")]
        for (code, _windows, linux) in REMEDY_PAIRS {
            let want = fill_placeholder(linux);
            assert!(
                verdicts.iter().any(|v| v.next_action == want),
                "{code}: no input reaches the Linux remedy in REMEDY_PAIRS"
            );
        }
    }

    /// The audit walk, as a function, so its negative control can run it on a
    /// doctored SOURCE instead of on a token.
    ///
    /// A line may carry a Windows invocation only while it is inside a
    /// `_WINDOWS` remedy const. Comments and doc comments are prose about the
    /// rule, not remedies, and are skipped.
    fn windows_invocations_outside_windows_consts(production: &str) -> Vec<String> {
        let mut inside_windows_const = false;
        let mut violations = Vec::new();
        for (index, raw) in production.lines().enumerate() {
            let code = raw.split_once("//").map(|(code, _)| code).unwrap_or(raw);
            // Boundary detection on the COMMENT-STRIPPED line as well, so prose
            // mentioning `_WINDOWS: &str =` can neither open nor close the region.
            let declares = code.contains("_WINDOWS: &str =");
            let closes = code.trim_end().ends_with("\";");
            if !inside_windows_const && !declares {
                // Layer 1 only. This walk sees SOURCE LINES, not sentences, so
                // layer 2 would fire on the tail of a prohibition whose `NOT`
                // sits on the previous line — it did exactly that on
                // "or zadig: those are Windows-only and have no meaning here."
                // Layer 2 is applied where it belongs: to the whole emitted
                // string, in `every_reachable_next_action_is_non_empty_and_host_correct`.
                if let Some(hit) = WINDOWS_ONLY_INVOCATIONS
                    .iter()
                    .copied()
                    .find(|t| code.contains(t))
                {
                    violations.push(format!(
                        "line {}: {hit:?} outside a _WINDOWS const: {code:?}",
                        index + 1
                    ));
                }
            }
            if declares {
                inside_windows_const = !closes;
            } else if inside_windows_const && closes {
                inside_windows_const = false;
            }
        }
        violations
    }

    /// "No site was missed" as a check instead of a grep someone ran once: in the
    /// production half of this file, every Windows-only invocation must sit
    /// inside a `_WINDOWS` remedy const, because a remedy written inline would be
    /// outside `REMEDY_PAIRS` and no other test could see it.
    #[test]
    fn no_windows_only_invocation_escapes_the_windows_consts() {
        let source = include_str!("verdict.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("verdict.rs has a production half");
        assert!(
            production.len() < source.len(),
            "the audit must stop at the test module, or it would ban its own token list"
        );

        let violations = windows_invocations_outside_windows_consts(production);
        assert!(
            violations.is_empty(),
            "a Windows-only invocation escaped the Windows remedy consts ({} found):\n{}",
            violations.len(),
            violations.join("\n")
        );

        // Negative control, on the REAL source: insert an inline Windows remedy
        // and require the walk to find exactly it. Without this, an audit that
        // silently matched nothing would look exactly like a clean file.
        let doctored = production.replace(
            "fn pwned(",
            "const SNEAKY: &str = \"run `a9drv bind --pid 1227` elevated\";\nfn pwned(",
        );
        assert_ne!(doctored, production, "the doctoring anchor moved");
        let caught = windows_invocations_outside_windows_consts(&doctored);
        assert_eq!(
            caught.len(),
            1,
            "the walk must catch an inline Windows remedy, and only it: {caught:?}"
        );
        assert!(
            caught[0].contains("a9drv bind --pid 1227"),
            "the walk caught the wrong line: {caught:?}"
        );
    }
}
