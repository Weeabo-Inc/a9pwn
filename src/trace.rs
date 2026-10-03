//! a9pwn — instrumentation. OWNER: diagnostics-engineer. Contract: `INTERFACE.md` §5.
//!
//! This module exists because the reference tool and its C port both failed
//! *silently and plausibly*: `a9ctl`'s C++ ancestor printed one message for four
//! different problems, and `gaster`'s own SETUP sweep is an unbounded `for(;;)`
//! that prints nothing between attempts (`gaster.c:848-860`). Everything here is
//! measured, counted exactly, and written down.
//!
//! ## What a reader can re-derive from the output
//!
//! Every JSONL line carries `seq`, `stage`, `kind`, `t_micros`, in that order,
//! always. The key order is the field order of [`Line`] and is asserted by test,
//! so two runs that did the same thing produce byte-identical key sequences.
//!
//! On top of the plain per-transfer record, [`Tracer::xfer`] derives a handful of
//! measurements **structurally** from the frozen [`XferResult`] fields — no
//! cooperation from the caller is required, and no label is trusted for them:
//!
//! | measurement | how it is recognised | reference |
//! |---|---|---|
//! | SETUP attempt | `abort_after_ms` is `Some(_)`, or a `0x21/DFU_DNLOAD/0x800` transfer | `gaster.c:853` |
//! | abort window | the `abort_after_ms` value, kept distinct and in order | `gaster.c:857` |
//! | pad request | label says `pad`, else an OUT transfer that is neither `DFU_DNLOAD` nor the `0x40` unstick | `gaster.c:853` |
//! | pad **STALL** | that transfer returned [`XferStatus::Stall`] — the pass condition | `gaster.c:853` |
//! | spray stall request | `bm=0x02 b=0x03 wIndex=0x80` | `gaster.c:890-894` |
//! | spray leak request | IN `GET_DESCRIPTOR`, `wLength` 0x40 or 0xC1 | `gaster.c:866,886` |
//!
//! ## Privacy
//!
//! The DFU serial descriptor contains the ECID, which is a device-unique
//! identifier and does not belong in a log that gets pasted into a bug report
//! (`readmes/a9ctl-README.md`). [`Tracer::event`] therefore scrubs any
//! `ECID:<hex>` token down to its last four digits before it is written. Pass a
//! serial through [`redact_ecid`] yourself if you log one directly.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use serde::Serialize;

use crate::types::{Stage, XferResult, XferStatus};

/// gaster's `send_usb_control_request_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, 0x40)`
/// "unstick" request (`gaster.c:856`).
const EP0_MAX_PACKET_SZ: u16 = 0x40;
/// `DFU_MAX_TRANSFER_SZ`, the length of the aborted async `DFU_DNLOAD` (`gaster.c:853`).
const DFU_MAX_TRANSFER_SZ: u16 = 0x800;
const DFU_DNLOAD: u8 = 0x01;
const GET_DESCRIPTOR: u8 = 0x06;
/// `checkm8_usb_request_leak`: `EP0_MAX_PACKET_SZ` (`gaster.c:866`).
const LEAK_LEN: u16 = EP0_MAX_PACKET_SZ;
/// `checkm8_no_leak`: `3 * EP0_MAX_PACKET_SZ + 1` (`gaster.c:886`).
const NO_LEAK_LEN: u16 = 3 * EP0_MAX_PACKET_SZ + 1;
/// A stage separator that cannot collide with a stage name.
pub const NO_STAGE: &str = "-";

/// libusb reads each device's instance ID into `char dev_id[MAX_PATH_LENGTH]`, and
/// `MAX_PATH_LENGTH` is **256** (`libusb/os/windows_winusb.h:37`, buffer declared
/// at `windows_winusb.c:1599`, filled by `SetupDiGetDeviceInstanceIdA(..., dev_id,
/// sizeof(dev_id), NULL)` at `:1719`). That call needs room for the ID **and** its
/// terminator, so an instance ID of 256 bytes or more cannot be read — and
/// `windows_winusb.c:1719-1723` only logs `usbi_warn(..."skipping")` and
/// `continue`s. That is how a long device path becomes "no device found".
pub const LIBUSB_DEV_ID_CAPACITY: usize = 256;

/// Event kind strings. Use these rather than literals: [`Tracer::event`] counts
/// resets and rounds by exact kind, and a typo would silently under-count.
pub mod kind {
    /// A port reset was attempted; delivery unknown.
    pub const RESET: &str = "reset";
    /// A port reset was attempted and genuinely delivered.
    pub const RESET_REAL: &str = "reset_real";
    /// A port reset returned success but only cycled pipes.
    pub const RESET_PIPE_CYCLE: &str = "reset_pipe_cycle";
    /// One trip round the stage machine.
    pub const ROUND: &str = "round";
    /// A per-transfer record, written by [`super::Tracer::xfer`].
    pub const XFER: &str = "xfer";
    /// A named reference predicate, written by [`super::Tracer::predicate`].
    pub const PREDICATE: &str = "predicate";
    /// Node counts per PID, written by [`super::Tracer::enumerated`].
    pub const ENUMERATED: &str = "enumerated";
    /// The resolved device instance path length, written by [`super::Tracer::device_path`].
    pub const DEVICE_PATH: &str = "device_path";
    /// A failed open, written by [`super::Tracer::open_failed`].
    pub const OPEN_FAILED: &str = "open_failed";
}

/// Exact counters. **No sampling, no estimation** — every value is incremented
/// once per observed event and read back verbatim.
///
/// The first block is frozen by `INTERFACE.md` §5 and may not be renamed or
/// re-typed. The second block is an **additive extension** requested by the
/// taxonomy: `classify` receives only this struct, and without these fields a
/// pad-request TIMEOUT (the device NAKing) is indistinguishable from the async
/// abort itself timing out, and from a pad request that was never sent. Those
/// three have different fixes, so they get different counters. All extensions
/// default to zero, so a caller that never sets them sees the conservative
/// behaviour rather than a fabricated measurement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    // ---- frozen (INTERFACE.md §5) ----
    pub ok: u64,
    pub stall: u64,
    pub timeout: u64,
    pub cancelled: u64,
    pub nodevice: u64,
    pub err: u64,
    /// distinct abort windows exercised, in order
    pub abort_sweep: Vec<u32>,
    pub setup_attempts: u64,
    /// times the pad request STALLed (the pass condition)
    pub setup_stall_seen: u64,
    pub resets_attempted: u64,
    /// resets that were genuinely delivered
    pub resets_real: u64,
    pub rounds: u64,

    // ---- additive extension: SETUP, per reference predicate ----
    /// Pad requests actually sent. Zero while `setup_attempts > 0` means the
    /// first clause of gaster's predicate (`sz < config_overwrite_pad`,
    /// `gaster.c:853`) never held, so the pad request was never reached.
    pub setup_pad_requests: u64,
    /// Pad requests that returned [`XferStatus::Timeout`] — the device NAKing.
    pub setup_pad_timeouts: u64,
    /// Pad requests that returned [`XferStatus::Error`] or `NoDevice`.
    pub setup_pad_errors: u64,
    /// Distinct pad-request lengths sent, in order. Each length is
    /// `overwrite_pad - transferred`, so a single value across the whole sweep is
    /// the closed-loop measurement that the aborted transfer never leaked.
    pub setup_pad_sizes: Vec<u16>,
    /// Async `DFU_DNLOAD`s that completed `Ok` having sent every requested byte:
    /// the abort window never cancelled them.
    pub setup_abort_full: u64,
    /// Async `DFU_DNLOAD`s that themselves returned `Timeout`.
    pub setup_abort_timeouts: u64,
    /// Async `DFU_DNLOAD`s whose `abort_after_ms` was `None`, i.e. the window was
    /// not reported and the sweep cannot be audited.
    pub setup_async_unreported: u64,
    /// Aborted transfers that came back `Cancelled` **before their own window
    /// elapsed**: a non-zero window (`>= 1 ms`) with `micros < 100`. This is the
    /// exact defect `a9ctl`'s README is built around — a cancel that never waits,
    /// so the transfer never reaches the wire and the use-after-free never
    /// happens. `micros` comes from [`XferResult::micros`], the window from
    /// [`XferResult::abort_after_ms`]; both are on the JSONL line.
    pub setup_abort_early: u64,

    // ---- additive extension: SPRAY, per reference predicate ----
    /// `checkm8_usb_request_stall` attempts (`bm=0x02 b=0x03 wIndex=0x80`).
    pub spray_stall_requests: u64,
    /// …of which did **not** STALL.
    pub spray_stall_not_stalling: u64,
    /// `checkm8_usb_request_leak` / `checkm8_no_leak` attempts.
    pub spray_leak_requests: u64,
    /// …of which returned more than zero bytes where gaster requires zero.
    pub spray_leak_not_zero: u64,

    // ---- additive extension: resets and shape ----
    /// Resets that returned success but only cycled pipes (libusb's WinUSB path
    /// returns `LIBUSB_SUCCESS` without a bus reset, `windows_winusb.c:3380-3420`).
    pub resets_pipe_cycle: u64,
    /// `"STAGE/STATUS" -> exact count`, e.g. `"SETUP/TIMEOUT"`.
    pub stage_status: BTreeMap<String, u64>,
    /// Failed reference predicates reported by the stage machine, by stable code.
    pub predicate_failures: BTreeMap<String, u64>,

    // ---- additive extension: the discovery record (taken before any transfer) ----
    /// Device nodes present per PID, in enumeration order: `(pid, count)`. Written
    /// by [`Tracer::enumerated`].
    ///
    /// Empty is **ambiguous on its own** — "nothing enumerated" and "nobody looked"
    /// are different problems that the C++ tool this project replaced printed
    /// identically. [`Counters::discovery_recorded`] is the field that tells them
    /// apart, which is why the README's `--all` self-test exists at all.
    pub nodes_present_by_pid: Vec<(u16, u32)>,
    /// True once a discovery record has been taken. See
    /// [`Counters::nodes_present_by_pid`].
    pub discovery_recorded: bool,
    /// Byte length of the device instance path that was resolved, from
    /// [`Tracer::device_path`]. Compare against [`LIBUSB_DEV_ID_CAPACITY`]: at or
    /// beyond it, libusb silently skips the node
    /// (`windows_winusb.c:1599,1719-1723`).
    pub device_path_len: Option<usize>,
    /// The last enumeration/open failure, verbatim, from [`Tracer::open_failed`].
    /// Its absence means either a successful open **or** no attempt — so no
    /// classification may treat `None` as proof of a working open.
    pub last_open_error: Option<String>,
    /// The errno or libusb return code behind [`Counters::last_open_error`].
    pub last_open_errno: Option<i32>,
}

impl Counters {
    /// Total transfers counted. Exact, by construction.
    pub fn total(&self) -> u64 {
        self.ok + self.stall + self.timeout + self.cancelled + self.nodevice + self.err
    }

    pub fn status_count(&self, status: XferStatus) -> u64 {
        match status {
            XferStatus::Ok => self.ok,
            XferStatus::Stall => self.stall,
            XferStatus::Timeout => self.timeout,
            XferStatus::Cancelled => self.cancelled,
            XferStatus::NoDevice => self.nodevice,
            XferStatus::Error => self.err,
        }
    }

    fn stage_status_key(stage: Stage, status: XferStatus) -> String {
        format!("{}/{}", stage.name(), status.as_str())
    }

    pub fn stage_status(&self, stage: Stage, status: XferStatus) -> u64 {
        self.stage_status
            .get(&Self::stage_status_key(stage, status))
            .copied()
            .unwrap_or(0)
    }

    pub fn stage_total(&self, stage: Stage) -> u64 {
        let prefix = format!("{}/", stage.name());
        self.stage_status
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| *v)
            .sum()
    }

    pub fn predicate_failed(&self, code: &str) -> u64 {
        self.predicate_failures.get(code).copied().unwrap_or(0)
    }

    pub fn any_predicate_failed(&self) -> bool {
        self.predicate_failures.values().any(|v| *v > 0)
    }

    /// Did the SETUP stage do anything at all?
    pub fn setup_ran(&self) -> bool {
        self.setup_attempts > 0
            || self.setup_pad_requests > 0
            || self.setup_async_unreported > 0
    }

    /// Node count recorded for `pid`, or `None` when **no discovery record was
    /// taken** — the distinction the README's `--all` self-test exists to make.
    pub fn nodes_for_pid(&self, pid: u16) -> Option<u32> {
        if !self.discovery_recorded {
            return None;
        }
        Some(
            self.nodes_present_by_pid
                .iter()
                .filter(|(p, _)| *p == pid)
                .map(|(_, n)| *n)
                .sum(),
        )
    }

    /// The discovery record proves a node for `pid` was present. False also when no
    /// record was taken: absence must be provable, never assumed.
    pub fn node_present(&self, pid: u16) -> bool {
        self.nodes_for_pid(pid).map(|n| n > 0).unwrap_or(false)
    }

    /// Total nodes in the discovery record. Zero means "nothing enumerated" only
    /// when [`Counters::discovery_recorded`] is true.
    pub fn nodes_total(&self) -> u32 {
        self.nodes_present_by_pid.iter().map(|(_, n)| *n).sum()
    }

    /// `"STAGE=count ..."` for every stage/status bucket ending in `status`, or
    /// `"none"`. Names *where* something happened — e.g. which stage lost the device.
    pub fn stages_with_status(&self, status: XferStatus) -> String {
        let suffix = format!("/{}", status.as_str());
        let hits: Vec<String> = self
            .stage_status
            .iter()
            .filter(|(k, _)| k.ends_with(&suffix))
            .map(|(k, v)| {
                let stage = k.trim_end_matches(&suffix);
                format!("{stage}={v}")
            })
            .collect();
        if hits.is_empty() {
            "none".to_string()
        } else {
            hits.join(" ")
        }
    }

    /// The resolved device path is at or beyond libusb's `char dev_id[256]` buffer,
    /// where the node is skipped with only a warning
    /// (`windows_winusb.c:1599,1719-1723`).
    pub fn device_path_overflows_libusb(&self) -> bool {
        matches!(self.device_path_len, Some(len) if len >= LIBUSB_DEV_ID_CAPACITY)
    }

    /// Distinct abort windows exercised, in order.
    pub fn windows(&self) -> &[u32] {
        &self.abort_sweep
    }

    /// `true` when the sweep cannot converge: gaster advances the window on every
    /// failed attempt, so two or more attempts with a single distinct window means
    /// the modulus in `gaster.c:857` has collapsed (`usb_timeout == abort_min`).
    pub fn abort_window_pinned(&self) -> bool {
        self.setup_attempts >= 2 && self.abort_sweep.len() == 1
    }
}

/// Human-readable, stable one-line rendering of an exact counter set. Used by
/// [`Tracer::summary_lines`] and by the verdict evidence.
pub fn counters_one_line(c: &Counters) -> String {
    format!(
        "transfers={} ok={} stall={} timeout={} cancelled={} nodevice={} error={}",
        c.total(),
        c.ok,
        c.stall,
        c.timeout,
        c.cancelled,
        c.nodevice,
        c.err
    )
}

/// Replace the body of an `ECID:<hex>` token with its last four digits.
///
/// The ECID is device-unique and belongs in no log that leaves the machine
/// (`readmes/a9ctl-README.md`). Everything else in the string is left byte-exact.
pub fn redact_ecid(s: &str) -> String {
    const KEY: &str = "ECID:";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find(KEY) {
        out.push_str(&rest[..pos + KEY.len()]);
        let after = &rest[pos + KEY.len()..];
        let end = after
            .find(|ch: char| !ch.is_ascii_hexdigit())
            .unwrap_or(after.len());
        let token = &after[..end];
        if token.len() > 4 {
            out.push_str("...");
            out.push_str(&token[token.len() - 4..]);
        } else {
            out.push_str(token);
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// One JSONL object. Field order **is** the byte order on the wire; do not
/// reorder. `seq`, `stage`, `kind`, `t_micros` are present on every line.
#[derive(Debug, Serialize)]
struct Line<'a> {
    seq: u64,
    stage: &'a str,
    kind: &'a str,
    t_micros: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bm_request_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b_request: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    w_value: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    w_index: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    w_length: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transferred: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    xfer_micros: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    libusb_rc: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    abort_after_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    xfer_seq: Option<u64>,
}

/// JSONL event log plus the exact counters the verdict is built from.
pub struct Tracer {
    start: Instant,
    seq: u64,
    verbose: bool,
    sink: Option<BufWriter<File>>,
    sink_path: Option<PathBuf>,
    lines: u64,
    sink_errors: u64,
    counters: Counters,
}

impl Tracer {
    /// `path` is created (truncated) when given; `verbose` mirrors per-transfer
    /// lines to stdout as well as the file.
    ///
    /// Truncation is deliberate: appending would mix two runs in one file and
    /// destroy the ability to re-derive a conclusion from it.
    pub fn new(path: Option<PathBuf>, verbose: bool) -> std::io::Result<Tracer> {
        let sink = match &path {
            Some(p) => Some(BufWriter::new(File::create(p)?)),
            None => None,
        };
        Ok(Tracer {
            start: Instant::now(),
            seq: 0,
            verbose,
            sink,
            sink_path: path,
            lines: 0,
            sink_errors: 0,
            counters: Counters::default(),
        })
    }

    /// Monotonic microseconds since the tracer was created. Every line carries it.
    pub fn t_micros(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    /// Number of JSONL lines written. Exact.
    pub fn lines_written(&self) -> u64 {
        self.lines
    }

    /// Record one control transfer and fold it into the counters.
    ///
    /// The structural accounting below is independent of `label` wherever the
    /// reference's own request signature is unambiguous, so a mislabelled transfer
    /// still counts correctly (see the module header table).
    pub fn xfer(&mut self, stage: Stage, label: &str, r: &XferResult) {
        match r.status {
            XferStatus::Ok => self.counters.ok += 1,
            XferStatus::Stall => self.counters.stall += 1,
            XferStatus::Timeout => self.counters.timeout += 1,
            XferStatus::Cancelled => self.counters.cancelled += 1,
            XferStatus::NoDevice => self.counters.nodevice += 1,
            XferStatus::Error => self.counters.err += 1,
        }
        *self
            .counters
            .stage_status
            .entry(Counters::stage_status_key(stage, r.status))
            .or_insert(0) += 1;

        match stage {
            Stage::Setup => self.account_setup(label, r),
            Stage::Spray => self.account_spray(r),
            _ => {}
        }

        let seq = self.next_seq();
        let t_micros = self.t_micros();
        self.write_line(Line {
            seq,
            stage: stage.name(),
            kind: kind::XFER,
            t_micros,
            label: Some(label),
            detail: None,
            status: Some(r.status.as_str()),
            bm_request_type: Some(r.bm_request_type),
            b_request: Some(r.b_request),
            w_value: Some(r.w_value),
            w_index: Some(r.w_index),
            w_length: Some(r.w_length),
            transferred: Some(r.transferred),
            requested: Some(r.requested),
            xfer_micros: Some(r.micros),
            libusb_rc: Some(r.libusb_rc),
            abort_after_ms: r.abort_after_ms,
            xfer_seq: Some(r.seq),
        });

        if self.verbose {
            println!("  [{}] {} | {}", stage.name(), label, r.one_line());
        }
    }

    /// Record a named event. `stage` is `None` for events that belong to no stage.
    ///
    /// Kinds [`kind::RESET`], [`kind::RESET_REAL`], [`kind::RESET_PIPE_CYCLE`] and
    /// [`kind::ROUND`] are counted exactly; anything else is recorded verbatim.
    /// `detail` is passed through [`redact_ecid`].
    pub fn event(&mut self, kind_name: &str, stage: Option<Stage>, detail: &str) {
        match kind_name {
            kind::RESET => self.counters.resets_attempted += 1,
            kind::RESET_REAL => {
                self.counters.resets_attempted += 1;
                self.counters.resets_real += 1;
            }
            kind::RESET_PIPE_CYCLE => {
                self.counters.resets_attempted += 1;
                self.counters.resets_pipe_cycle += 1;
            }
            kind::ROUND => self.counters.rounds += 1,
            _ => {}
        }

        let detail = redact_ecid(detail);
        let stage_name = stage.map(|s| s.name()).unwrap_or(NO_STAGE);
        let seq = self.next_seq();
        let t_micros = self.t_micros();
        self.write_line(Line {
            seq,
            stage: stage_name,
            kind: kind_name,
            t_micros,
            label: None,
            detail: Some(&detail),
            status: None,
            bm_request_type: None,
            b_request: None,
            w_value: None,
            w_index: None,
            w_length: None,
            transferred: None,
            requested: None,
            xfer_micros: None,
            libusb_rc: None,
            abort_after_ms: None,
            xfer_seq: None,
        });

        if self.verbose {
            println!("  [{}] {} | {}", stage_name, kind_name, detail);
        }
    }

    /// Typed shortcut for a port reset. Prefer this over a bare `event` string:
    /// `delivered == false` means the call returned but only pipes were cycled,
    /// which is a measurement, not a guess.
    pub fn reset(&mut self, delivered: bool, note: &str) {
        let k = if delivered {
            kind::RESET_REAL
        } else {
            kind::RESET_PIPE_CYCLE
        };
        self.event(k, Some(Stage::Reset), note);
    }

    /// Typed shortcut for one trip round the stage machine.
    pub fn round(&mut self, n: u32, detail: &str) {
        self.event(kind::ROUND, None, &format!("round={n} {detail}"));
    }

    /// Record the enumeration result: how many nodes exist for each PID.
    ///
    /// Call this **before** any open attempt, including when the answer is "none".
    /// It is what makes absence provable, and it is the measurement that separates
    /// "device absent" from "driver bound but not loaded" — the same reason
    /// `a9ctl --all` prints a raw node count.
    pub fn enumerated(&mut self, by_pid: &[(u16, u32)]) {
        self.counters.nodes_present_by_pid = by_pid.to_vec();
        self.counters.discovery_recorded = true;
        let detail = if by_pid.is_empty() {
            "no matching node enumerated".to_string()
        } else {
            by_pid
                .iter()
                .map(|(pid, n)| format!("PID 0x{pid:04X}={n}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        self.event(kind::ENUMERATED, None, &detail);
    }

    /// Record the resolved device instance path length. Compare against
    /// [`LIBUSB_DEV_ID_CAPACITY`]; nothing else about the path is stored, so no
    /// machine-identifying string reaches the log.
    pub fn device_path(&mut self, len: usize, note: &str) {
        self.counters.device_path_len = Some(len);
        self.event(kind::DEVICE_PATH, None, &format!("len={len} {note}"));
    }

    /// Record a failed enumeration/open, verbatim. `None` errno is allowed and is
    /// itself a measurement: the transport did not have one.
    pub fn open_failed(&mut self, errno: Option<i32>, note: &str) {
        self.counters.last_open_errno = errno;
        self.counters.last_open_error = Some(redact_ecid(note));
        self.event(kind::OPEN_FAILED, None, &format!("errno={errno:?} {note}"));
    }

    /// Record a named reference predicate and whether it held.
    ///
    /// Use this for predicates only the stage machine can evaluate — for example
    /// `checkm8_usb_request_stall` (`gaster.c:890-894`) or the
    /// `dfu_set_state_wait_reset` triple check (`gaster.c:829-834`). Failures are
    /// counted by `code` and surfaced in [`Counters::predicate_failures`]; passes
    /// are recorded in the JSONL only.
    pub fn predicate(&mut self, stage: Stage, code: &str, passed: bool, detail: &str) {
        if !passed {
            *self
                .counters
                .predicate_failures
                .entry(code.to_string())
                .or_insert(0) += 1;
        }
        let detail = redact_ecid(detail);
        let seq = self.next_seq();
        let t_micros = self.t_micros();
        self.write_line(Line {
            seq,
            stage: stage.name(),
            kind: kind::PREDICATE,
            t_micros,
            label: Some(code),
            detail: Some(&detail),
            status: Some(if passed { "PASS" } else { "FAIL" }),
            bm_request_type: None,
            b_request: None,
            w_value: None,
            w_index: None,
            w_length: None,
            transferred: None,
            requested: None,
            xfer_micros: None,
            libusb_rc: None,
            abort_after_ms: None,
            xfer_seq: None,
        });
        if self.verbose && !passed {
            println!("  [{}] predicate FAILED {} | {}", stage.name(), code, detail);
        }
    }

    /// A snapshot of the exact counters. Cloned, not sampled.
    pub fn counters(&self) -> Counters {
        self.counters.clone()
    }

    /// Exact human summary, one line per measurement. Printed to stdout by the CLI.
    pub fn summary_lines(&self) -> Vec<String> {
        let c = &self.counters;
        let mut out = Vec::new();

        out.push("  trace summary (exact counts; nothing sampled or estimated)".to_string());
        match (&self.sink_path, self.sink_errors) {
            (Some(p), 0) => out.push(format!(
                "    sink           : {} ({} JSONL line(s) written)",
                p.display(),
                self.lines
            )),
            (Some(p), e) => out.push(format!(
                "    sink           : {} ({} JSONL line(s) written, {} WRITE FAILURE(S))",
                p.display(),
                self.lines,
                e
            )),
            (None, _) => out.push(format!(
                "    sink           : none ({} JSONL line(s) not persisted; pass --trace FILE)",
                self.lines
            )),
        }
        out.push(format!("    transfers      : {}", counters_one_line(c)));
        out.push(format!(
            "    per stage      : {}",
            if c.stage_status.is_empty() {
                "(no transfers)".to_string()
            } else {
                c.stage_status
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        ));
        out.push(format!(
            "    setup          : attempts={} pad_requests={} pad_stalls={} pad_timeouts={} pad_errors={}",
            c.setup_attempts,
            c.setup_pad_requests,
            c.setup_stall_seen,
            c.setup_pad_timeouts,
            c.setup_pad_errors
        ));
        out.push(format!(
            "                     abort_windows={:?} unwindowed_attempts={}",
            c.abort_sweep, c.setup_async_unreported
        ));
        out.push(format!(
            "                     pad_sizes={:?} abort_completed_full={} abort_timeouts={} abort_cancelled_early={}",
            c.setup_pad_sizes, c.setup_abort_full, c.setup_abort_timeouts, c.setup_abort_early
        ));
        out.push(format!(
            "    spray          : stall_requests={} stall_not_stalling={} leak_requests={} leak_not_zero={}",
            c.spray_stall_requests,
            c.spray_stall_not_stalling,
            c.spray_leak_requests,
            c.spray_leak_not_zero
        ));
        out.push(format!(
            "    resets         : attempted={} real={} pipe_cycle={}",
            c.resets_attempted, c.resets_real, c.resets_pipe_cycle
        ));
        out.push(format!("    rounds         : {}", c.rounds));
        out.push(format!(
            "    discovery      : recorded={} nodes=[{}] path_len={} open_errno={} open_error={}",
            c.discovery_recorded,
            c.nodes_present_by_pid
                .iter()
                .map(|(p, n)| format!("0x{p:04X}={n}"))
                .collect::<Vec<_>>()
                .join(" "),
            match c.device_path_len {
                Some(l) => format!("{l}"),
                None => "none".to_string(),
            },
            match c.last_open_errno {
                Some(e) => format!("{e}"),
                None => "none".to_string(),
            },
            match c.last_open_error.as_deref() {
                Some(e) => format!("\"{e}\""),
                None => "none".to_string(),
            }
        ));
        if c.any_predicate_failed() {
            out.push(format!(
                "    predicate fails: {}",
                c.predicate_failures
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
        out
    }

    /// Flush the file sink and stdout. Never panics; a failed flush is counted and
    /// reported by [`Tracer::summary_lines`] rather than swallowed.
    pub fn flush(&mut self) {
        if let Some(sink) = self.sink.as_mut() {
            if sink.flush().is_err() {
                self.sink_errors += 1;
            }
        }
        let _ = std::io::stdout().flush();
    }

    // ---------------------------------------------------------------- internals

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn write_line(&mut self, line: Line<'_>) {
        let json = match serde_json::to_string(&line) {
            Ok(j) => j,
            Err(e) => {
                self.sink_errors += 1;
                format!(
                    "{{\"seq\":{},\"stage\":\"{}\",\"kind\":\"{}\",\"detail\":\"serialize error: {}\"}}",
                    line.seq, line.stage, line.kind, e
                )
            }
        };
        self.lines += 1;
        if let Some(sink) = self.sink.as_mut() {
            if writeln!(sink, "{json}").is_err() {
                self.sink_errors += 1;
            }
        }
    }

    /// `gaster.c:848-860`. One iteration is one async `DFU_DNLOAD` of
    /// `DFU_MAX_TRANSFER_SZ`, aborted after `usb_abort_timeout` ms, followed by
    /// either the pad request (when the aborted length is under `overwrite_pad`)
    /// or the `0x40` unstick.
    fn account_setup(&mut self, label: &str, r: &XferResult) {
        let is_async = r.abort_after_ms.is_some()
            || (r.bm_request_type == 0x21
                && r.b_request == DFU_DNLOAD
                && r.w_length == DFU_MAX_TRANSFER_SZ);
        if is_async {
            self.counters.setup_attempts += 1;
            match r.abort_after_ms {
                Some(t) => {
                    if !self.counters.abort_sweep.contains(&t) {
                        self.counters.abort_sweep.push(t);
                    }
                }
                None => self.counters.setup_async_unreported += 1,
            }
            if r.status == XferStatus::Ok && r.requested > 0 && r.transferred >= r.requested {
                self.counters.setup_abort_full += 1;
            }
            if r.status == XferStatus::Timeout {
                self.counters.setup_abort_timeouts += 1;
            }
            // A window of 0 ms is gaster's legitimate starting point and may
            // genuinely return in under a microsecond, so it is excluded. A
            // non-zero window that returns in under 100 us did not wait.
            if r.status == XferStatus::Cancelled
                && matches!(r.abort_after_ms, Some(t) if t >= 1)
                && r.micros < 100
            {
                self.counters.setup_abort_early += 1;
            }
            return;
        }

        // The pad request is `send_usb_control_request_no_data(handle, 0, 0, 0, 0,
        // overwrite_pad - sz, ...)` — bm=0x00, b=0x00 (gaster.c:853, :468-480).
        // An explicit `pad` label wins; otherwise the only other OUT request in the
        // loop is the 0x40 unstick (gaster.c:856), which is excluded by length.
        let labelled = label.to_ascii_lowercase().contains("pad");
        let structural = r.abort_after_ms.is_none()
            && (r.bm_request_type & 0x80) == 0
            && r.b_request != DFU_DNLOAD
            && r.w_length != EP0_MAX_PACKET_SZ;
        if !(labelled || structural) {
            return;
        }

        self.counters.setup_pad_requests += 1;
        if !self.counters.setup_pad_sizes.contains(&r.w_length) {
            self.counters.setup_pad_sizes.push(r.w_length);
        }
        match r.status {
            XferStatus::Stall => self.counters.setup_stall_seen += 1,
            XferStatus::Timeout => self.counters.setup_pad_timeouts += 1,
            XferStatus::Error | XferStatus::NoDevice => self.counters.setup_pad_errors += 1,
            _ => {}
        }
    }

    /// `gaster.c:890-894` (`bm=0x02 b=0x03 wIndex=0x80` must STALL) and
    /// `gaster.c:866,886` (the serial-descriptor reads that must return zero bytes).
    fn account_spray(&mut self, r: &XferResult) {
        if r.bm_request_type == 0x02 && r.b_request == 0x03 && r.w_index == 0x80 {
            self.counters.spray_stall_requests += 1;
            if r.status != XferStatus::Stall {
                self.counters.spray_stall_not_stalling += 1;
            }
            return;
        }
        let is_leak_read = (r.bm_request_type & 0x80) != 0
            && r.b_request == GET_DESCRIPTOR
            && (r.w_length == LEAK_LEN || r.w_length == NO_LEAK_LEN);
        if is_leak_read {
            self.counters.spray_leak_requests += 1;
            if r.transferred > 0 {
                self.counters.spray_leak_not_zero += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::XferStatus;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("a9pwn-trace-tests");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.join(name)
    }

    fn xf(
        status: XferStatus,
        bm: u8,
        b: u8,
        w_len: u16,
        transferred: usize,
        requested: usize,
        abort_after_ms: Option<u32>,
    ) -> XferResult {
        xfi(status, bm, b, 0, w_len, transferred, requested, abort_after_ms)
    }

    #[allow(clippy::too_many_arguments)]
    fn xfi(
        status: XferStatus,
        bm: u8,
        b: u8,
        w_index: u16,
        w_len: u16,
        transferred: usize,
        requested: usize,
        abort_after_ms: Option<u32>,
    ) -> XferResult {
        XferResult {
            seq: 7,
            bm_request_type: bm,
            b_request: b,
            w_value: 0,
            w_index,
            w_length: w_len,
            status,
            transferred,
            requested,
            micros: 1234,
            libusb_rc: 0,
            abort_after_ms,
        }
    }

    /// The `a9ctl/stage-setup.log` signature, replayed as counters: 384 rounds of
    /// `abort_ms=N -> Cancelled len=0` then `pad request (1280 bytes) -> Timeout`.
    fn setup_log_replay() -> Tracer {
        let mut t = Tracer::new(None, false).expect("tracer");
        let windows = [4u32, 5, 0, 1, 2, 3];
        for i in 0..384 {
            let w = windows[i % 6];
            t.xfer(
                Stage::Setup,
                "async-abort",
                &xf(XferStatus::Cancelled, 0x21, DFU_DNLOAD, 0x800, 0, 0x800, Some(w)),
            );
            t.xfer(
                Stage::Setup,
                "pad-request",
                &xf(XferStatus::Timeout, 0x00, 0x00, 1280, 0, 1280, None),
            );
        }
        t
    }

    #[test]
    fn jsonl_lines_carry_the_four_required_keys_in_stable_order() {
        let path = tmp("order.jsonl");
        let mut t = Tracer::new(Some(path.clone()), false).expect("tracer");
        // A transfer with every optional field populated, so the whole 17-key
        // order is asserted, not just the four required keys.
        t.xfer(
            Stage::Patch,
            "dnload",
            &xf(XferStatus::Ok, 0x21, 0x01, 0x40, 64, 64, Some(3)),
        );
        t.event("run_end", None, "done");
        t.flush();

        let text = std::fs::read_to_string(&path).expect("read trace");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");

        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            for key in ["seq", "stage", "kind", "t_micros"] {
                assert!(v.get(key).is_some(), "missing {key} in {line}");
            }
        }

        // Byte-stable key order: declaration order, asserted positionally.
        let order = [
            "seq",
            "stage",
            "kind",
            "t_micros",
            "label",
            "status",
            "bm_request_type",
            "b_request",
            "w_value",
            "w_index",
            "w_length",
            "transferred",
            "requested",
            "xfer_micros",
            "libusb_rc",
            "abort_after_ms",
            "xfer_seq",
        ];
        let mut last = 0usize;
        for key in order {
            let at = lines[0].find(&format!("\"{key}\":")).expect("key present");
            assert!(at > last || key == "seq", "key {key} out of order in {}", lines[0]);
            last = at;
        }
        // Stage-less events report "-", never a fabricated stage.
        assert!(lines[1].contains("\"stage\":\"-\""), "{}", lines[1]);
    }
    #[test]
    fn jsonl_round_trips_every_field_value() {
        let path = tmp("roundtrip.jsonl");
        let mut t = Tracer::new(Some(path.clone()), false).expect("tracer");
        let r = xf(XferStatus::Stall, 0x21, 0x01, 0x40, 64, 64, Some(3));
        t.xfer(Stage::Reset, "reset-dnload", &r);
        t.flush();

        let text = std::fs::read_to_string(&path).expect("read trace");
        let v: serde_json::Value = serde_json::from_str(text.trim()).expect("valid JSON");
        assert_eq!(v["seq"], 1);
        assert_eq!(v["stage"], "RESET");
        assert_eq!(v["kind"], "xfer");
        assert_eq!(v["label"], "reset-dnload");
        assert_eq!(v["status"], "STALL");
        assert_eq!(v["bm_request_type"], 0x21);
        assert_eq!(v["b_request"], 0x01);
        assert_eq!(v["w_length"], 0x40);
        assert_eq!(v["transferred"], 64);
        assert_eq!(v["requested"], 64);
        assert_eq!(v["xfer_micros"], 1234);
        assert_eq!(v["abort_after_ms"], 3);
        assert_eq!(v["xfer_seq"], 7);
        assert!(v["t_micros"].is_u64());
    }

    #[test]
    fn counters_are_exact_for_mixed_statuses() {
        let mut t = Tracer::new(None, false).expect("tracer");
        for _ in 0..3 {
            t.xfer(Stage::Reset, "a", &xf(XferStatus::Ok, 0x21, 1, 0x40, 64, 64, None));
        }
        t.xfer(Stage::Spray, "b", &xf(XferStatus::Stall, 0x02, 3, 0, 0, 0, None));
        t.xfer(Stage::Spray, "c", &xf(XferStatus::Timeout, 0x80, 6, 0x40, 0, 64, Some(1)));
        t.xfer(Stage::Patch, "d", &xf(XferStatus::Cancelled, 0x21, 1, 0x800, 0, 0x800, Some(0)));
        t.xfer(Stage::Patch, "e", &xf(XferStatus::NoDevice, 0x21, 1, 0, 0, 0, None));
        t.xfer(Stage::Patch, "f", &xf(XferStatus::Error, 0x21, 1, 0, 0, 0, None));

        let c = t.counters();
        assert_eq!(c.total(), 8);
        assert_eq!(c.ok, 3);
        assert_eq!(c.stall, 1);
        assert_eq!(c.timeout, 1);
        assert_eq!(c.cancelled, 1);
        assert_eq!(c.nodevice, 1);
        assert_eq!(c.err, 1);
        assert_eq!(c.stage_status(Stage::Reset, XferStatus::Ok), 3);
        assert_eq!(c.stage_status(Stage::Spray, XferStatus::Stall), 1);
        assert_eq!(c.stage_total(Stage::Patch), 3);
        assert_eq!(c.status_count(XferStatus::Ok), 3);
    }

    #[test]
    fn setup_signature_is_measured_exactly() {
        let c = setup_log_replay().counters();
        assert_eq!(c.setup_attempts, 384);
        assert_eq!(c.setup_pad_requests, 384);
        assert_eq!(c.setup_stall_seen, 0);
        assert_eq!(c.setup_pad_timeouts, 384);
        assert_eq!(c.setup_pad_errors, 0);
        assert_eq!(c.cancelled, 384);
        assert_eq!(c.timeout, 384);
        // The sweep starts at usb_timeout - 1 (gaster.c:849) and walks the whole
        // modulus: [4,5,0,1,2,3] — exactly what a9ctl/stage-setup.log shows.
        assert_eq!(c.abort_sweep, vec![4, 5, 0, 1, 2, 3]);
        // overwrite_pad - transferred = 1280 - 0 = 0x500, gaster's A9 row.
        assert_eq!(c.setup_pad_sizes, vec![1280]);
        assert!(!c.abort_window_pinned());
        assert!(c.setup_ran());
    }

    #[test]
    fn abort_windows_are_distinct_in_order_and_detect_a_pinned_sweep() {
        let mut t = Tracer::new(None, false).expect("tracer");
        for w in [3u32, 3, 3, 3] {
            t.xfer(Stage::Setup, "abort", &xf(XferStatus::Cancelled, 0x21, 1, 0x800, 0, 0x800, Some(w)));
        }
        let c = t.counters();
        assert_eq!(c.abort_sweep, vec![3]);
        assert_eq!(c.setup_attempts, 4);
        assert!(c.abort_window_pinned(), "4 attempts, 1 window => pinned");

        let mut t2 = Tracer::new(None, false).expect("tracer");
        t2.xfer(Stage::Setup, "abort", &xf(XferStatus::Cancelled, 0x21, 1, 0x800, 0, 0x800, Some(3)));
        assert!(!t2.counters().abort_window_pinned(), "a single attempt proves nothing");
    }

    #[test]
    fn setup_async_transfers_without_a_reported_window_are_counted_separately() {
        let mut t = Tracer::new(None, false).expect("tracer");
        t.xfer(Stage::Setup, "abort", &xf(XferStatus::Cancelled, 0x21, 1, 0x800, 0, 0x800, None));
        t.xfer(Stage::Setup, "abort", &xf(XferStatus::Ok, 0x21, 1, 0x800, 0x800, 0x800, None));
        let c = t.counters();
        assert_eq!(c.setup_attempts, 2);
        assert_eq!(c.setup_async_unreported, 2);
        assert!(c.abort_sweep.is_empty());
        assert_eq!(c.setup_abort_full, 1);
        assert_eq!(c.setup_pad_requests, 0, "the 0x800 async must never count as a pad request");
    }

    #[test]
    fn unstick_request_is_not_mistaken_for_a_pad_request() {
        let mut t = Tracer::new(None, false).expect("tracer");
        // gaster.c:856 — the 0x40 DNLOAD that advances the sweep on failure.
        t.xfer(Stage::Setup, "unstick", &xf(XferStatus::Ok, 0x21, DFU_DNLOAD, 0x40, 64, 64, None));
        let c = t.counters();
        assert_eq!(c.setup_pad_requests, 0);
        assert_eq!(c.setup_stall_seen, 0);
        assert_eq!(c.setup_pad_sizes.len(), 0);
    }

    #[test]
    fn spray_predicates_are_counted_from_the_reference_signature() {
        let mut t = Tracer::new(None, false).expect("tracer");
        // checkm8_usb_request_stall, gaster.c:890-894: bm=0x02 b=0x03 wIndex=0x80.
        t.xfer(
            Stage::Spray,
            "req-stall",
            &xfi(XferStatus::Stall, 0x02, 0x03, 0x80, 0, 0, 0, None),
        );
        t.xfer(
            Stage::Spray,
            "req-stall",
            &xfi(XferStatus::Ok, 0x02, 0x03, 0x80, 0, 0, 0, None),
        );
        // checkm8_usb_request_leak: 0x40 bytes, gaster requires transferred == 0.
        t.xfer(
            Stage::Spray,
            "leak",
            &xfi(XferStatus::Ok, 0x80, 0x06, 0x0A, 0x40, 0, 0x40, Some(1)),
        );
        // checkm8_no_leak: 3 * EP0 + 1 = 0xC1 bytes, also requires zero. Here it
        // returned 12 bytes, which is the leak-not-zero observable.
        t.xfer(
            Stage::Spray,
            "no-leak",
            &xfi(XferStatus::Ok, 0x80, 0x06, 0x0A, 0xC1, 12, 0xC1, Some(1)),
        );
        // The CLR_STATUS that follows the sweep is OUT and must not be counted.
        t.xfer(
            Stage::Spray,
            "clr",
            &xfi(XferStatus::Ok, 0x21, 0x04, 0, 0xC1, 0, 0, None),
        );

        let c = t.counters();
        assert_eq!(c.spray_stall_requests, 2);
        assert_eq!(c.spray_stall_not_stalling, 1);
        assert_eq!(c.spray_leak_requests, 2);
        assert_eq!(c.spray_leak_not_zero, 1);
    }

    #[test]
    fn event_kinds_drive_the_reset_and_round_counters() {
        let mut t = Tracer::new(None, false).expect("tracer");
        t.reset(true, "libusb rc=0, real bus reset");
        t.reset(false, "libusb rc=0, pipe cycle only");
        t.event(kind::RESET, Some(Stage::Reset), "attempted, outcome unknown");
        t.round(1, "stage=SETUP");
        t.round(2, "stage=SETUP");

        let c = t.counters();
        assert_eq!(c.resets_attempted, 3);
        assert_eq!(c.resets_real, 1);
        assert_eq!(c.resets_pipe_cycle, 1);
        assert_eq!(c.rounds, 2);
    }

    #[test]
    fn predicate_failures_are_counted_by_code() {
        let mut t = Tracer::new(None, false).expect("tracer");
        t.predicate(Stage::Setup, "setup.pad_stall", false, "TIMEOUT");
        t.predicate(Stage::Setup, "setup.pad_stall", false, "TIMEOUT");
        t.predicate(Stage::Spray, "spray.usb_request_leak", true, "sz=0");
        let c = t.counters();
        assert_eq!(c.predicate_failed("setup.pad_stall"), 2);
        assert_eq!(c.predicate_failed("spray.usb_request_leak"), 0);
        assert!(c.any_predicate_failed());
    }

    #[test]
    fn ecid_is_redacted_in_events_and_predicates() {
        let path = tmp("redact.jsonl");
        let mut t = Tracer::new(Some(path.clone()), false).expect("tracer");
        t.event(
            "ident",
            None,
            "serial=CPID:8003 ECID:00112233445566AA SRTG:[IBOOT-2234.0.0.2.22]",
        );
        t.predicate(Stage::Spray, "x", false, "ECID:00112233445566AA");
        t.flush();
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(!text.contains("00112233445566AA"), "{text}");
        assert!(text.contains("ECID:...13BA"), "{text}");
        assert!(text.contains("CPID:8003"), "{text}");
        assert!(text.contains("SRTG:[IBOOT-2234.0.0.2.22]"), "{text}");
    }

    #[test]
    fn redact_ecid_handles_degenerate_input() {
        assert_eq!(redact_ecid(""), "");
        assert_eq!(redact_ecid("no ecid here"), "no ecid here");
        assert_eq!(redact_ecid("ECID:AB"), "ECID:AB");
        assert_eq!(redact_ecid("ECID:00112233445566AA"), "ECID:...13BA");
        assert_eq!(redact_ecid("ECID:00112233445566AA."), "ECID:...13BA.");
    }

    #[test]
    fn no_sink_still_counts_and_summarises() {
        let t = Tracer::new(None, false).expect("tracer");
        let lines = t.summary_lines();
        assert!(lines[0].contains("trace summary"));
        assert!(lines.iter().any(|l| l.contains("sink           : none")));
        assert!(lines.iter().any(|l| l.contains("transfers      : transfers=0")));
        assert!(lines.iter().any(|l| l.contains("abort_windows=[]")));
    }

    #[test]
    fn summary_reports_the_exact_setup_signature() {
        let t = setup_log_replay();
        let s = t.summary_lines().join("\n");
        assert!(s.contains("attempts=384"), "{s}");
        assert!(s.contains("pad_requests=384"), "{s}");
        assert!(s.contains("pad_timeouts=384"), "{s}");
        assert!(s.contains("abort_windows=[4, 5, 0, 1, 2, 3]"), "{s}");
        assert!(s.contains("pad_sizes=[1280]"), "{s}");
        assert!(s.contains("SETUP/CANCELLED=384"), "{s}");
        assert!(s.contains("SETUP/TIMEOUT=384"), "{s}");
    }

    #[test]
    fn abort_transfers_that_do_not_wait_their_window_are_counted() {
        let mut t = Tracer::new(None, false).expect("tracer");
        // The C++ defect: a 5 ms window cancelled after 0 us.
        let mut early = xf(XferStatus::Cancelled, 0x21, DFU_DNLOAD, 0x800, 0, 0x800, Some(5));
        early.micros = 12;
        t.xfer(Stage::Setup, "abort", &early);
        // Legitimate: window 0 may return in under a microsecond.
        let mut window0 = xf(XferStatus::Cancelled, 0x21, DFU_DNLOAD, 0x800, 0, 0x800, Some(0));
        window0.micros = 0;
        t.xfer(Stage::Setup, "abort", &window0);
        // Legitimate: a real 4 ms wait, as in a9ctl/stage-setup.log.
        let mut waited = xf(XferStatus::Cancelled, 0x21, DFU_DNLOAD, 0x800, 0, 0x800, Some(4));
        waited.micros = 3001;
        t.xfer(Stage::Setup, "abort", &waited);

        let c = t.counters();
        assert_eq!(c.setup_attempts, 3);
        assert_eq!(c.setup_abort_early, 1);
        assert_eq!(c.abort_sweep, vec![5, 0, 4]);
    }

    #[test]
    fn discovery_record_separates_nothing_there_from_nobody_looked() {
        let mut t = Tracer::new(None, false).expect("tracer");
        assert!(!t.counters().discovery_recorded);
        assert_eq!(t.counters().nodes_for_pid(crate::DFU_MODE_PID), None);
        assert!(!t.counters().node_present(crate::DFU_MODE_PID));

        t.enumerated(&[(0x05AC, 3), (0x1227, 1)]);
        let c = t.counters();
        assert!(c.discovery_recorded);
        assert_eq!(c.nodes_for_pid(0x1227), Some(1));
        assert!(c.node_present(crate::DFU_MODE_PID));
        assert_eq!(c.nodes_total(), 4);
        assert_eq!(c.nodes_for_pid(0x9999), Some(0));

        // A recorded-but-empty census is provable absence, not a missing record.
        let mut empty = Tracer::new(None, false).expect("tracer");
        empty.enumerated(&[]);
        let e = empty.counters();
        assert!(e.discovery_recorded);
        assert_eq!(e.nodes_total(), 0);
        assert!(!e.node_present(crate::DFU_MODE_PID));
    }

    #[test]
    fn open_failure_and_path_length_are_recorded_with_their_source() {
        let path = tmp("discovery.jsonl");
        let mut t = Tracer::new(Some(path.clone()), false).expect("tracer");
        t.enumerated(&[(0x1227, 1)]);
        t.device_path(271, "instance id read by our own SetupAPI pass");
        t.open_failed(Some(-4), "libusb_open: NOT_FOUND for the only 1227 node");
        t.flush();

        let c = t.counters();
        assert_eq!(c.device_path_len, Some(271));
        assert_eq!(c.last_open_errno, Some(-4));
        assert!(c
            .last_open_error
            .as_deref()
            .unwrap()
            .contains("NOT_FOUND"));
        assert!(!c.device_path_overflows_libusb(), "271 < 256 is false");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("\"kind\":\"enumerated\""), "{text}");
        assert!(text.contains("PID 0x1227=1"), "{text}");
        assert!(text.contains("\"kind\":\"device_path\""), "{text}");
        assert!(text.contains("len=271"), "{text}");
        assert!(text.contains("\"kind\":\"open_failed\""), "{text}");
    }

    #[test]
    fn a_path_at_the_libusb_buffer_limit_is_flagged() {
        // windows_winusb.c:1599 `char dev_id[256]`, filled at :1719 with
        // sizeof(dev_id) — 255 bytes plus a terminator fit, 256 do not.
        let mut t = Tracer::new(None, false).expect("tracer");
        t.device_path(255, "at the edge");
        assert!(!t.counters().device_path_overflows_libusb());
        t.device_path(256, "one over");
        assert!(t.counters().device_path_overflows_libusb());
        t.device_path(4096, "far over");
        assert!(t.counters().device_path_overflows_libusb());
    }

    #[test]
    fn stage_status_helper_names_where_a_status_happened() {
        let mut t = Tracer::new(None, false).expect("tracer");
        t.xfer(Stage::Setup, "drain", &xf(XferStatus::NoDevice, 0x21, 1, 0x40, 0, 0, None));
        t.xfer(Stage::Patch, "chunk", &xf(XferStatus::NoDevice, 0x21, 1, 0x800, 0, 0, None));
        t.xfer(Stage::Patch, "chunk", &xf(XferStatus::Ok, 0x21, 1, 0x800, 64, 64, None));
        let c = t.counters();
        assert_eq!(c.stages_with_status(XferStatus::NoDevice), "SETUP=1 PATCH=1");
        assert_eq!(c.stages_with_status(XferStatus::Stall), "none");
        assert_eq!(c.stage_status(Stage::Patch, XferStatus::NoDevice), 1);
    }

    #[test]
    fn unwritable_sink_path_is_an_error_not_a_panic() {
        let bad = std::env::temp_dir()
            .join("a9pwn-no-such-dir-9f3a1c")
            .join("nested")
            .join("trace.jsonl");
        assert!(Tracer::new(Some(bad), false).is_err());
    }

    #[test]
    fn flush_is_idempotent_and_never_panics() {
        let mut t = Tracer::new(None, false).expect("tracer");
        t.event("a", None, "1");
        t.flush();
        t.flush();
        assert_eq!(t.lines_written(), 1);
        assert_eq!(t.counters().total(), 0);
    }

    #[test]
    fn counters_one_line_reports_every_status() {
        let c = Counters {
            ok: 1,
            stall: 2,
            timeout: 3,
            cancelled: 4,
            nodevice: 5,
            err: 6,
            ..Counters::default()
        };
        assert_eq!(
            counters_one_line(&c),
            "transfers=21 ok=1 stall=2 timeout=3 cancelled=4 nodevice=5 error=6"
        );
    }
}
