# a9pwn — FROZEN INTERFACE CONTRACT

**Owner of this file: the Lead. Nobody else edits it.**

`a9pwn` is `gaster`'s checkm8 rewritten in Rust, with instrumentation as a
first-class feature rather than an afterthought. The algorithm is **not** up for
redesign: checkm8 is a timing-sensitive bootrom heap corruption, and every
deviation from the reference is a silent new failure mode. The improvements we
make are **observability, correctness of the transport layer, and honest
failure classification**. That is the whole mandate.

Reference implementation: `P:\Reverseing\Arlo\research\refs\gaster\gaster.c`
(1667 lines) and `payload_A9.S` / `payload_handle_checkm8_request.S`.
Target: iPhone SE 1st gen, `CPID 0x8003` (s8003 "Malta"), `BDID 0x02`, in stock
SecureROM DFU (`USB 05AC:1227`).

---

## 0. HOUSE RULES FOR EVERY CONTRIBUTOR

1. **Only the Lead touches the phone.** Never open, reset, or write to a USB
   device. Never run `a9pwn run`, `a9pwn reset`, or any `--stage` path. Hardware
   access is Lead-only; concurrent agents on one DFU device is how a session is
   lost. You may run `cargo build`, `cargo test`, and offline `--dry-run` paths.
2. **Stay in your write scope.** Your task lists the exact files you own. Do not
   edit another contributor's file. If you need a change there, message the Lead.
3. **Never invent a measurement.** If you did not run it, say INSPECTED, not
   MEASURED. This tree has already been burned six times by a plausible-looking
   wrong value.
4. **No new dependencies** beyond the four in `Cargo.toml` unless the Lead agrees.
5. Write Rust that compiles on **`x86_64-pc-windows-msvc`**, Rust 2021.

---

## 1. `src/types.rs` — owner: transport-engineer

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferStatus { Ok, Stall, Timeout, Cancelled, NoDevice, Error }

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
    pub fn ok(&self) -> bool;                 // status == Ok
    pub fn stalled(&self) -> bool;            // status == Stall
    pub fn one_line(&self) -> String;         // stable, greppable, no colour
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage { Reset, Setup, Spray, Patch, Pwned }
impl Stage { pub fn name(&self) -> &'static str; }

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
    pub cpid: Option<u32>, pub cprv: Option<u32>, pub cpfm: Option<u32>, pub scep: Option<u32>,
    pub bdid: Option<u32>, pub ecid: Option<u64>, pub ibfl: Option<u32>,
    pub srtg: Option<String>, pub pwnd: Option<String>,
    pub i_serial: u8,
}
impl DeviceIdentity {
    pub fn parse(serial: &str) -> DeviceIdentity;   // tolerant: Windows replaces spaces with '_'
    pub fn is_pwned(&self) -> bool;                 // pwnd contains "checkm8"
    pub fn is_a9(&self) -> bool;                    // cpid in {0x8000, 0x8003}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverClass { LibusbK, Libusb0, WinUsb, Other, Unknown }
impl DriverClass { pub fn as_str(&self) -> &'static str; }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetCapability { Real, PipeCycleOnly, Unknown }
```

## 2. `src/usb.rs` — owner: transport-engineer

```rust
#[derive(Debug, Clone, Copy)]
pub struct CtrlReq { pub bm: u8, pub b: u8, pub value: u16, pub index: u16, pub length: u16 }

pub struct ResetReport {
    pub libusb_rc: i32,
    pub capability: ResetCapability,
    pub micros: u64,
    pub note: String,          // human sentence naming what actually happened
}

pub struct Transport { /* opaque */ }

impl Transport {
    pub fn open_first_dfu() -> Result<Transport, String>;
    pub fn identity(&self) -> DeviceIdentity;
    pub fn serial_descriptor(&self) -> Result<String, String>;
    pub fn driver_class(&self) -> DriverClass;      // from the bound driver, not guessed
    pub fn reset_capability(&self) -> ResetCapability;

    pub fn control(&mut self, r: CtrlReq, data: &mut [u8], timeout_ms: u32) -> XferResult;
    pub fn control_out(&mut self, r: CtrlReq, data: &[u8], timeout_ms: u32) -> XferResult;
    pub fn control_no_data(&mut self, r: CtrlReq, timeout_ms: u32) -> XferResult;

    /// checkm8's `stall()`: submit an async control transfer, abort it after
    /// `cancel_after_ms`, and report how many bytes made it. MUST refuse to
    /// return in under 1 µs (that is the exact defect this primitive exists to
    /// make impossible — see a9ctl's README).
    pub fn control_async_abort(&mut self, r: CtrlReq, buf: &mut [u8], cancel_after_ms: u32)
        -> XferResult;

    /// Must report WHAT IT DID, not merely whether it returned success.
    pub fn reset(&mut self) -> Result<ResetReport, String>;

    pub fn seq(&self) -> u64;   // monotonic transfer counter
}
```

### 2.1 The Linux measurement surface (added session 3, 2026-10-03)

On Linux there is no SetupAPI, so the Windows driver table cannot answer "what is
bound, and can it reset?". Before this surface existed, `ident` printed
`driver service: unknown` / `reset: unknown` on the only host that can pwn the
device, and `main.rs`'s preflight gate refused to run. The surface below is the
measurement that replaced that blindness. Everything here is `#[cfg(unix)]` except
the constants; the Windows path is unchanged.

```rust
pub const SYSFS_ROOT_ENV: &str = "A9PWN_SYSFS_ROOT";   // overrides the sysfs root
pub const REAL_SYSFS_ROOT: &str = "/sys";

/// Resolve the sysfs root. The override exists so tests can point at FIXTURE trees
/// and is the reason the whole surface is testable without a phone.
pub fn sysfs_root_from(override_value: Option<&str>) -> std::path::PathBuf;
pub fn sysfs_root() -> std::path::PathBuf;

/// A sentence naming WHERE the root came from (real /sys vs an override), so a
/// reader can never mistake a fixture result for a hardware one.
pub fn root_provenance(root: &std::path::Path) -> String;

/// Read-only scan of the device tree. Opens no device handle and writes nothing.
/// `Err` means the scan could not be trusted — it is NEVER folded into "empty".
pub fn scan_sysfs_usb_devices(root: &std::path::Path) -> Result<SysfsScan, String>;

/// Interface 0's binding for one node of the scan.
pub fn resolve_interface0(
    root: &std::path::Path,
    node: &SysfsUsbNode,
) -> Result<SysfsInterfaceBinding, String>;

/// The driver actually bound to (bus, address), and the note explaining it.
/// Refuses when the scan finds no node, or more than one node, at that address.
pub fn measure_sysfs_driver(
    root: &std::path::Path,
    bus: u8,
    address: u8,
) -> Result<SysfsDriverMeasurement, String>;
```

**Contracts a caller may rely on — and the ones it may NOT:**
1. **`cannot read` is never `not there`.** An EACCES (or any unreadable path)
   produces `Err` quoting the OS reason; it never becomes absence, and never
   becomes `usbfs`. This is a MATERIAL-reviewed property with a chmod-000
   negative control.
2. **`usbfs` is a positive measurement**, not a fallback: it is the absence of a
   `driver` symlink on interface 0, which is the normal, working state of a DFU
   device on Linux. `DriverClass::Usbfs` therefore maps to
   `ResetCapability::Unknown` in `types.rs::from_driver` — capability is decided
   by the *measured* evidence here, never by the driver name.
3. **A duplicate (bus, addr) is refused, not picked from.** Two nodes reporting
   the same address produce an error.
4. **The scan is bounded**: one `read_dir`, one pass, no recursion, no `unwrap`
   on absent files, and malformed attribute content is quoted rather than
   guessed at.

### 2.2 The reset-call classification (added session 3 after a live regression)

**Why this exists.** MEASURED 2026-10-03: the exploit's own SPRAY ends with a
`DFU_CLRSTATUS` (`gaster.c:910`) that **takes the device off the bus for ~350-435 ms**
(`RUNG1-EVIDENCE.md` §7). The next reset call therefore fails with
`LIBUSB_ERROR_NOT_FOUND`. A gate that treats every failed call as "the host cannot
reset" **stopped a run that was working** — our tool could not pwn a stock device at
all until this distinction was made. The drop is the exploit's own, and the reference
absorbs it (`gaster.c:197-200`, `:1268`; `wait_usb_handle` `:202-218`).

```rust
/// What a reset call actually did. `RefusedAbsent` and `RefusedPresent` are the
/// distinction the regression turned on: the first is the KNOWN drop and the run
/// continues; the second stops it.
pub enum ResetCall {
    Report,
    RefusedAbsent { rc: i32, micros: u64, note: String },
    RefusedPresent { rc: i32, micros: u64, note: String },
}

/// Exactly `LIBUSB_ERROR_NOT_FOUND` (-5) and `LIBUSB_ERROR_NO_DEVICE` (-4).
pub fn reset_error_is_device_absent(rc: i32) -> bool;

impl Transport { pub fn reset_call(&mut self) -> ResetCall; }   // `reset()` wraps it

// stages.rs
pub enum ResetDisposition { Continue, Stop }
pub fn reset_failure_disposition(rc: i32, allow_winusb: bool) -> ResetDisposition;
pub const KIND_RESET_AFTER_DROP: &str = "reset_after_drop";   // its own trace kind
pub const OPEN_RETRY_BUDGET: Duration;   // 3 s wall clock (was 600 attempts)
pub fn open_retry_allowed(/* … */) -> bool;
pub fn open_retry_ok_note(/* … */) -> String;
pub fn open_retry_exhausted_note(/* … */) -> String;
```

**Contracts:**
1. **A refusal while the device is PRESENT still stops the run.** That is the case the
   original gate existed for, and this change must not weaken it. Pinned by
   both-direction negative controls: "every failure continues" and "absent also stops"
   each make named tests fail.
2. **The drop is its own evidence kind.** `KIND_RESET_AFTER_DROP` is deliberately a
   kind that **no counter claims**, so it can never feed `resets_unrecorded` and
   produce `RESET_NOT_DELIVERED` — which would blame the host for the exploit's own
   drop. A test asserts `KIND_RESET_AFTER_DROP != kind::RESET`.
3. **The wait is wall-clock bounded, not attempt-counted.** "19 open attempts" was
   MEASURED to be 285-292 ms — a property of our pacing loop, not of the device
   (LINUX-HANDOFF §4.8).

`XferStatus` mapping is fixed and tested: `LIBUSB_TRANSFER_COMPLETED → Ok`,
`STALL → Stall`, `TIMED_OUT → Timeout`, `CANCELLED → Cancelled`,
`NO_DEVICE → NoDevice`, everything else → `Error`.

## 3. `src/config.rs` + `src/payload.rs` — owner: stages-engineer

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind { A9, NotA9, NotA9Armv7 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocConfig {
    pub cpid: u32, pub cprv: u32, pub name: &'static str,
    pub overwrite_pad: u32,      // gaster: config_overwrite_pad
    pub large_leak: u32,         // gaster: config_large_leak  (0 on A9)
    pub hole: u32,               // gaster: config_hole
    pub ttbr0_vrom_off: u64, pub ttbr0_sram_off: u64,
    pub insecure_memory_base: u64,
    pub dfu_handle_bus_reset: u64, pub dfu_handle_request: u64,
    pub memcpy_addr: u64, pub g_usb_serial_number: u64,
    pub usb_create_string_descriptor: u64, pub usb_serial_number_string_descriptor: u64,
    pub patch_addr: u64, pub boot_tramp_end: u64, pub ttbr0_addr: u64,
    pub pwnd_string: &'static str,
}

pub fn config_for_identity(id: &DeviceIdentity) -> Result<(SocConfig, PayloadKind), String>;
pub fn all_configs() -> &'static [SocConfig];

pub const A9_STRUCT_SIZE: usize = 104;              // 13 × u64, load-bearing
pub const HANDLE_CHECKM8_STRUCT_SIZE: usize = 56;   //  7 × u64, load-bearing

pub struct FieldTrace { pub off: usize, pub len: usize, pub label: &'static str, pub value: u64 }

pub struct BuiltPayload {
    pub blob: Vec<u8>,
    pub overwrite: Vec<u8>,
    pub fields: Vec<FieldTrace>,     // every struct field, in offset order
    pub blob_sha256: String,
}

pub fn build_payload(cfg: &SocConfig, kind: PayloadKind) -> Result<BuiltPayload, String>;
pub fn verify_blob_hashes() -> Result<(), String>;
```

`payloads/payload_A9.bin` (280 B) and `payloads/payload_handle_checkm8_request.bin`
(248 B) are vendored from gaster, Apache-2.0. Expected SHA-256:

```
A698045FAE09ACDC5BFAFC26EF3FE7848F1454B8CE8847FDC45396CC18A532B2  payload_A9.bin
C0C213047A8902186392396CB7E57C096626B4812B61E07C2CF7CF6B99A9889C  payload_handle_checkm8_request.bin
```

`verify_blob_hashes()` must **fail loudly** on mismatch. A swapped blob is a
silently different exploit.

## 4. `src/stages.rs` — owner: stages-engineer

```rust
pub struct StageFail { pub code: &'static str, pub detail: String, pub last: Option<XferResult> }
pub enum StageResult { Pass, Fail(StageFail) }

pub const LEAK_WINDEX_GASTER: u16 = 0x0A;   // gaster's USB_MAX_STRING_DESCRIPTOR_IDX
pub const LEAK_WINDEX_IPWNDFU: u16 = 0x00;  // the alternative; the one unresolved parameter

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupBudget { pub max_attempts: u64, pub max_millis: u64 }

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub max_rounds: u32,
    pub usb_timeout_ms: u32,          // gaster default 5
    pub abort_timeout_min_ms: u32,    // gaster default 0
    pub leak_windex: u16,
    pub dry_run: bool,
    pub verbose: bool,
    pub trace_path: Option<std::path::PathBuf>,
    pub allow_winusb: bool,           // refuse without it: see §0 of the verdict rules
    pub stage_filter: Option<Stage>,
    pub setup_budget: SetupBudget,
    pub stop_after_setup_stall: bool, // diagnostic: prove SETUP before spending PATCH
    pub force: bool,                  // run the exploit even if the descriptor already carries
                                      // PWND:[checkm8] (rule 14: without it a marked device sends
                                      // nothing, transfers=0, and the verdict is PWNED_UNMEASURED).
                                      // Needed to re-pwn while an image is held in the DFU buffer:
                                      // a Power+Home re-entry destroys that image.
    pub settle_ms: u32,               // sleep between rounds; 0 = gaster's behaviour
}
impl Default for RunOptions { /* gaster's defaults: rounds 64, usb_timeout 5, abort_min 0 */ }

pub struct StageIo<'a> {
    pub usb: &'a mut Transport,
    pub trace: &'a mut Tracer,
    pub cfg: &'a SocConfig,
    pub opts: &'a RunOptions,
}

pub fn stage_reset(io: &mut StageIo) -> StageResult;
pub fn stage_setup(io: &mut StageIo) -> StageResult;
pub fn stage_spray(io: &mut StageIo) -> StageResult;
pub fn stage_patch(io: &mut StageIo, built: &BuiltPayload) -> StageResult;
pub fn run(opts: RunOptions) -> RunOutcome;
pub fn run_one_stage(stage: Stage, opts: RunOptions) -> RunOutcome;
```

**The stage order is fixed** (gaster.c:1231-1276): `RESET → SETUP → SPRAY →
PATCH → reset → re-open → check PWND`, and **a reset happens after every stage
attempt**, successful or not. That reset is what both cleans the DFU state and,
after PATCH, fires the overwritten `dfu_handle_bus_reset` callback. Removing it
breaks the exploit; do not "optimise" it away.

`stage_setup` is gaster's abort/pad sweep: submit an async `DFU_DNLOAD` of
`DFU_MAX_TRANSFER_SZ` (0x800) aborted after `usb_abort_timeout` ms; if it came
back with fewer than `overwrite_pad` bytes, send a **pad request** of
`overwrite_pad - transferred` bytes and **STALL is the pass condition**. On
anything else, send `DFU_DNLOAD` of `EP0_MAX_PACKET_SZ` (0x40) and advance the
abort window `(t + 1) % (usb_timeout - abort_min + 1) + abort_min`. The sweep must
be **bounded** by `SetupBudget` and must log every attempt with its abort window
and observed outcome — that log is the entire point of this rewrite.

## 5. `src/trace.rs` — owner: diagnostics-engineer

```rust
pub struct Tracer { /* opaque */ }

impl Tracer {
    pub fn new(path: Option<std::path::PathBuf>, verbose: bool) -> std::io::Result<Tracer>;
    pub fn xfer(&mut self, stage: Stage, label: &str, r: &XferResult);
    pub fn event(&mut self, kind: &str, stage: Option<Stage>, detail: &str);
    pub fn counters(&self) -> Counters;
    pub fn summary_lines(&self) -> Vec<String>;
    pub fn flush(&mut self);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub ok: u64, pub stall: u64, pub timeout: u64, pub cancelled: u64,
    pub nodevice: u64, pub err: u64,
    pub abort_sweep: Vec<u32>,        // distinct abort windows exercised, in order
    pub setup_attempts: u64,
    pub setup_stall_seen: u64,        // times the pad request STALLed (the pass condition)
    pub resets_attempted: u64,
    pub resets_real: u64,             // resets that were genuinely delivered
    pub rounds: u64,
}
```

Output format: one JSON object per line (JSONL) to `path` when given, and a
human summary to stdout. Byte-stable field order. `serde_json` is allowed.
Every line carries `seq`, `stage`, `kind`, `t_micros`.

## 6. `src/verdict.rs` — owner: diagnostics-engineer

```rust
pub enum Confidence { High, Medium, Low }

pub struct Verdict {
    pub code: &'static str,          // stable, uppercase, e.g. NO_RESET_CAPABILITY
    pub headline: String,
    pub evidence: Vec<String>,       // each item names the measurement it came from
    pub next_action: String,
    pub confidence: Confidence,
}

pub fn classify(
    outcome: &RunOutcome,
    counters: &Counters,
    ident: &DeviceIdentity,
    driver: DriverClass,
    reset_cap: ResetCapability,
) -> Verdict;
```

Required verdict codes, at minimum, each distinguished from the others — this
project's recurring failure is four different problems producing one message:

| code | condition |
|---|---|
| `PWNED` | `RunOutcome::Pwned` |
| `NO_RESET_CAPABILITY` | driver is WinUSB → resets are pipe cycles → checkm8 cannot fire |
| `SETUP_NEVER_STALLED` | setup attempts exhausted, `setup_stall_seen == 0` |
| `PAD_TIMEOUT_NOT_STALL` | pad requests observed returning `Timeout` |
| `DEVICE_ABSENT` | `RunOutcome::NoDevice` |
| `UNSUPPORTED_CHIP` | cpid outside the A9 table |
| `WRONG_BOOT_STAGE` | `SRTG` absent → this is iBSS DFU, not SecureROM |
| `EXHAUSTED_UNKNOWN` | rounds exhausted with no signature matched |

## 7. `src/main.rs` + `Cargo.toml` + `src/lib.rs` — owner: **Lead only**

CLI (hand-rolled parsing, no clap):

```
a9pwn ident                 read-only identity + driver + reset capability
a9pwn preflight             ident, then refuse to continue if resets are not real
a9pwn reset                 bare port reset, reporting what it actually did
a9pwn plan                  build the payload, print every field, send nothing
a9pwn selftest              offline checks: blob hashes, struct sizes, config table, verdicts
a9pwn run [--rounds N] [--dry-run] [--verbose] [--trace FILE]
          [--stage reset|setup|spray|patch] [--allow-winusb] [--force]
          [--leak-windex-ipwndfu] [--stop-after-setup-stall] [--setup-budget N]
```

Exit codes: `0` pwned/success · `1` no device · `2` bad arguments ·
`3` unsupported chip · `4` preflight refused (no reset capability) ·
`5` exhausted · `6` transport error.

`--dry-run` must build every byte and print the field traces without sending
anything. It is the only path a non-Lead contributor may exercise.
