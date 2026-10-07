<div align="center">
	<h2>a9pwn</h2>
</div>

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-0078D6.svg?style=flat-square)]()
[![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-PWNED%20on%20a%20real%20A9-brightgreen.svg?style=flat-square)]()

### checkm8, rewritten in Rust — with a verdict system that refuses to guess.

A native implementation of the checkm8 bootrom exploit (CVE-2019-8900) for the Apple A9 (`s8003`, board `n69ap`), driven from Linux over `usbfs` instead of through a Windows driver stack. It pwns a stock DFU iPhone SE 1st gen, and every verdict it prints carries the evidence behind it plus a remedy written for the host it is actually running on.

Written because the reference tooling fails **silently and plausibly** here — and because *"the exploit did not work"* and *"this host cannot perform the reset the exploit needs"* are different findings that were being reported as one.

---

### What does this do?

```
$ a9pwn run --rounds 12 --setup-budget 300 --pad-timeout-ms 5

  SETUP: PASSED - pad STALL after 3 attempts. attempts=3 distinct_abort_windows=3 [4ms,5ms,0ms]
  RESET: device absent (the known drop, rc=-5, 1 us) — continuing; the next re-open waits
  PWND marker present: Some("checkm8") — checkm8 landed.
  VERDICT  Pwned: the bootrom's serial descriptor carries the checkm8 marker.  [PWNED]
```

It reads the chip out of the bootrom's own USB serial descriptor, measures whether the host can really deliver the bus reset the exploit depends on, runs the four stages (RESET → SETUP → SPRAY → PATCH), and proves the result by the marker the bootrom writes into its own descriptor.

---

### The failure this exists to prevent

**The exploit's own drop was being blamed on the host.** checkm8's SPRAY ends with a `DFU_CLRSTATUS` that takes the device off the bus for 350–435 ms, so the next reset call legitimately returns `NOT_FOUND`. A gate that reads every failed call as *"this host cannot reset"* stops a run that is working — which is exactly what happened here until the drop was classified.

The drop is now its own evidence kind (`reset_after_drop`) that **no counter claims**, so it can never feed `RESET_NOT_DELIVERED` and blame the host for what the exploit did. Measured on hardware: 400.840 ms and 268.045 ms of wall-clock absence, with the pwn landing 0.25 ms after re-enumeration — and one of those drops was a **237.160 ms reset that was delivered and still returned `NOT_FOUND`**, which is why the rule judges by the *kind* of failure, not by whether the call succeeded.

The other failure it fixes: **every verdict used to name Windows tools.** On Linux, `a9pwn ident` printed `driver service: unknown`. The Linux arm now measures sysfs directly (interface-0 claim, driver binding, `usbfs` with no driver bound as the *normal* state) and returns `driver service: usbfs` / `reset: real bus reset`, with `preflight` exiting 0.

---

### Layout

| Path | What |
|---|---|
| `src/stages.rs` | The four stages, the drop classification, the bounded re-open |
| `src/usb.rs` | The transport: libusb, Linux sysfs measurement, reset-capability evidence |
| `src/verdict.rs` | The verdict system — every code, its evidence, its host-correct remedy |
| `src/trace.rs` | The JSON trace that every verdict is derived from |
| `docs/` | `GASTER-SPEC.md`, `GASTER-LINUX-RUNBOOK.md`, `LINUX-REFERENCE-NOTES.md`, live-run verification |
| `payloads/` | The checkm8 payload and its build notes |
| `INTERFACE.md` | The frozen public surface and its contracts |

---

### Status

**PWNED on hardware**, repeatedly, on a power-cycled stock device: `checkm8 landed`, verified three ways (kernel sysfs, `lsusb`, and the tool's own `ident`). The gate is green at 222 tests over 3 suites with a manifest pinned before and after the run.

One honest caveat: the Windows path is INSPECTED, not executed here — this box has no Windows target. The Windows remedies are held byte-identical to their pre-refactor form by a decoder plus an FNV pin, and both arms are unit-tested on either host, but "runs on Windows" is not a claim this repository can make from here.
