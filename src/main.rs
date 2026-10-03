//! a9pwn — CLI. OWNER: **Lead only.** This file is the enforcing contract for
//! every module: it calls the frozen signatures, so if it compiles, the modules
//! agree with `INTERFACE.md`.

use std::path::PathBuf;
use std::process::ExitCode;

use a9pwn::payload;
use a9pwn::stages::{self, RunOptions, SetupBudget};
use a9pwn::trace::Tracer;
use a9pwn::types::{DeviceIdentity, ResetCapability, RunOutcome, Stage};
use a9pwn::usb::Transport;
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
           --leak-windex-ipwndfu      use the ipwndfu wIndex instead of gaster's\n\
           --stop-after-setup-stall   exit as soon as SETUP passes (diagnostic)\n\
           --setup-budget N           max SETUP attempts before giving up (default 20000)\n\
           --settle-ms N              sleep between rounds (default 0)\n\
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

    let mut opts = RunOptions {
        max_rounds: number(args, "--rounds").unwrap_or(64) as u32,
        usb_timeout_ms: number(args, "--usb-timeout-ms").unwrap_or(USB_TIMEOUT_MS as u64) as u32,
        abort_timeout_min_ms: number(args, "--abort-min-ms")
            .unwrap_or(ABORT_TIMEOUT_MIN_MS as u64) as u32,
        leak_windex: if flag(args, "--leak-windex-ipwndfu") {
            a9pwn::stages::LEAK_WINDEX_IPWNDFU
        } else {
            a9pwn::stages::LEAK_WINDEX_GASTER
        },
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
    println!("  serial        : {}", id.serial);
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

            let mut tracer = match Tracer::new(opts.trace_path.clone(), opts.verbose) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("a9pwn: cannot open trace file: {e}");
                    return ExitCode::from(EXIT_BAD_ARGS);
                }
            };
            tracer.event(
                "run_start",
                None,
                &format!(
                    "rounds={} dry_run={} stage={:?} leak_windex=0x{:X} usb_timeout={}ms",
                    opts.max_rounds,
                    opts.dry_run,
                    opts.stage_filter,
                    opts.leak_windex,
                    opts.usb_timeout_ms
                ),
            );
            tracer.flush();

            let outcome = stages::run(opts.clone());
            tracer.event("run_end", None, &format!("{outcome:?}"));
            tracer.flush();

            let counters = tracer.counters();
            println!();
            for line in tracer.summary_lines() {
                println!("{line}");
            }

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

        other => {
            eprintln!("a9pwn: unknown command '{other}'");
            usage();
            ExitCode::from(EXIT_BAD_ARGS)
        }
    }
}
