# LINUX-REFERENCE-NOTES — PATCH's pass condition, SETUP's `sz`, and the E5 log spec

**Task:** `task-3` (analysis only). **Author:** `stages-analyst`.
**Write scope honoured:** this file only. No code was edited; the phone was never opened by this
agent (no `a9pwn run/reset/ident/plan/probe-*`, no libusb, no driver work). Every hardware number
below was produced by the **Lead** and read back from the files cited; labels are `MEASURED`
(from a file/tool), `INSPECTED` (read in source), `INFERRED` (derived).

> **Revision 5** (§9 lists every correction). Revision 1 was adversarially reviewed; the reviewer
> found 6 BLOCKER/MATERIAL errors (a wrong Δt, three wrong line citations, two proposals that would
> not compile, a wrong overstatement, several wrong document section numbers) and, more importantly,
> pointed at a run this report had not seen: **`a9pwn` itself pwned the phone on Linux at 14:28**
> (`a9pwn-traces/linux/our-run1.*`). That run is now the primary evidence and it independently
> confirms every load-bearing claim. A second adversarial pass over revision 2 found no BLOCKER —
> only citation slips and one mis-signed set of residuals — all applied as revision 3. Revision 4
> carried in the measurement that resolved open question #4 (the async path **does** report graded
> 64-byte-quantised partials on Linux; `a9pwn-traces/linux/e1-ep0cut-ladder.txt`) and added the
> task-9 instrument `tools/arlo/ep0cut --mode sweep`.
>
> **Revision 5 carries the durable reviewer's T3-R findings (two rounds) and two new hardware
> datasets**, and one of them **invalidates a claim this report made in revisions 1-4**: the PWND
> marker is *not* at "index 6" as a property — the declared `iSerialNumber` moves and the marker
> follows it (archived: index 4 → 228 B; the "index 6 → 0 B" half is Lead-reported and unarchived,
> §3.3). It also replaces §7's Windows-watchdog inference with the task-9 result: the **cold** pad's
> *latency* is flat at ≤64 B with a knee at 128 B (N=1 per point), so "consumes its `wLength`" does
> not hold for a cold pad, and the post-abort pad — which is what the exploit actually sends —
> remains untested. T3-R round 2 then falsified the abort-pad mode's baseline arm and eight further
> claims (§9 items 32-38); round 3 falsified those fixes — including a BLOCKER where an empty
> ladder printed a confident negative with `incomplete:false` and exit 0 (§9 items 39-46). All were
> fixed before the mode's first hardware run. Revision 6 then carries the **stock cold pad row** —
> the measurement that settles §7 item 5's third branch and shows SETUP's STALL is a **created**
> response — plus the tool defect that row exposed (a slope fitted through libusb's 250 ms deadline
> printed "DATA CONSUMPTION SUPPORTED" at 12792.6 µs/packet) and T3-R's round-4 findings. The tool
> is at **29 tests**, and round 5 corrected one of this report's own arithmetical claims (a
> 1280-byte transfer cannot carry 25-30 packets) and named the conservative reading of the stock
> row's contrast beside the favourable one.

## 0. Revision pin — read this before checking any line number

`a9pwn/src/usb.rs` and `a9pwn/src/main.rs` were being edited by other teammates continuously while
this report was written. Every citation in those two files was re-resolved **by quoted code**, not
by line, at:

| file | sha256 (first 16) | lines | movement observed |
|---|---|---|---|
| `research/refs/gaster/gaster.c` | `9aadab9db873b3e2…` | 1667 | stable |
| `a9pwn/src/stages.rs` | `79ef56553a89559f…` | 3823 | stable (matches the LINUX-HANDOFF manifest) |
| `a9pwn/src/payload.rs` | `e3607cb89d1b2a8d…` | 755 | stable |
| `a9pwn/src/usb.rs` | `6b2bda4e…` | 5996 | 4040 → 4972 → 4979 → 5724 → 5986 → 5996 → `6b2bda4e` (hash changes, length does not) |
| `a9pwn/src/main.rs` | `f57ce965bbabb979…` | 812 | 496 → 523 → 754 → 812 |

**Consequence, stated up front:** the `usb.rs` and `main.rs` line numbers below are the ones at the
revision each edit was written against, and both files have moved since. The E5 items in §5 carry
their own revision; where a line is load-bearing the symbol or the quoted code is given so the
citation survives a move. A reader who finds a mismatch should re-resolve by symbol and treat the
line number as a hint. (T3-R's review measured five `usb.rs` revisions during one pass; line-number
pinning is a losing game on those two files, which is why the report quotes code.)
(`trace.rs` has been edited since the manifest — `4918751ad3cd3ae4…` — but no `trace.rs` line is
cited here, so nothing depends on it.)

Evidence files:

| file | sha256 (first 16) | what it is |
|---|---|---|
| `a9pwn-traces/linux/our-run1.txt` | `366e5c632c095c1c…` | MEASURED: usbmon URB capture, **`a9pwn`'s own Linux pwn** (Lead, 14:28) |
| `a9pwn-traces/linux/our-run1.jsonl` | `55cc46e0647d48f7…` | MEASURED: `a9pwn`'s JSONL trace of that run (63 lines) |
| `a9pwn-traces/linux/our-run1.txt.stdout.txt` | — | MEASURED: that run's stdout, incl. the verdict |
| `a9pwn-traces/linux/e4-gaster-1.txt` | `d66021f45cf01d9a…` | MEASURED: usbmon capture of the reference `gaster` pwn (Lead, 14:23) |
| `a9pwn-traces/linux/e1-probe-{0,1,8,50}ms.*` | `f1158776…` etc. | MEASURED: the `probe-partial-count` runs (Lead) |
| `a9pwn-traces/linux/e0-ident.txt` | — | MEASURED: `a9pwn ident` |

usbmon text format, as it appears in these files: `URBtag t_us S|C pipe status length [data]`;
a submission line carries `s <bm> <b> <wValue> <wIndex> <wLength> <dataLen> = <data>`; a completion
line carries `C <status> <actual_length>`. Status: `0` success, `-2` `-ENOENT` (URB unlinked),
`-32` `-EPIPE` (**STALL**), `-71` `-EPROTO`, `-108` `-ESHUTDOWN` (device gone). Timestamps are
microseconds; a `C` line's last number is the actual transferred length, and usbmon prints at most
32 data bytes per line.

---

## 1. TL;DR — the three answers

1. **PATCH.** On the wire PATCH's trigger **is** the 48-byte data stage: `our-run1.txt:161` and
   `e4-gaster-1.txt:157` both read `s 02 03 0000 0080 0030 48`, i.e. `wLength = 0x30 = 48`, exactly
   `gaster.c:1211` with `overwrite_sz = sizeof(checkm8_overwrite) = 48` (`gaster.c:91-96`,
   `:111-113`, A9 branch `:1192-1196`). The `wLength = 0` request (`e4-gaster-1.txt:87`,
   `our-run1.txt:91`) is **SPRAY's stall primitive** (`gaster.c:893`, driven by `:902`) — our own
   trace labels the two requests `spray_request_stall` (`our-run1.jsonl` seq 37, `w_length: 0`) and
   `patch_overflow_callback` (`seq 48`, `w_length: 48`). So LINUX-HANDOFF §4.7 describes this request
   exactly, and **the STALL is vacuous as a pass condition**: the identical request with no data
   stage produces the identical `-32 / 0` (156-158 µs vs 164-167 µs across the two runs). The
   observable that proves PATCH fired is the **PWND marker**: the serial descriptor goes 198 B →
   228 B (+30 B = `" PWND:[checkm8]"`) only after the PATCH sequence and the post-PATCH reset, in
   **both** runs (`our-run1.txt:160` vs `:226`; `e4-gaster-1.txt:156` vs `:220`).
2. **`sz`.** On Linux both runs executed `pad = overwrite_pad − sz` with **`sz = 0`** — provable
   from the wire, because the pad went out with `wLength = 0x500 = 1280` (`our-run1.txt:59`,
   `e4-gaster-1.txt:57`) and `config_overwrite_pad = 0x500` for CPID 0x8003 (`gaster.c:625-626`);
   the only value of `sz` that yields 1280 is 0. The reference's sweep **collapses on Linux, in the
   opposite direction from Windows**: windows 4 ms and 5 ms *complete* the 2048-byte DNLOAD
   (935-992 µs), only window 0 cuts it (70-117 µs, 0 bytes) — so `sz` is only ever 2048 or 0, and
   the pass arrives on the `sz = 0` attempt where the pad is the full 1280. Our port reproduces
   this exactly (`our-run1.jsonl` seq 19/22/25/26) and pwned. **The packet-quantised sweep is
   unnecessary here and would be a new variable the Linux reference never exercises** — and the
   reason is now measured, not assumed: on the async path Linux reports real, 64-byte-quantised
   partials for cancelled transfers (§4.4).
3. **E5 spec** is §5: five items, each with the exact file:line and the smallest edit.

---

## 2. Two runs, reconciled — and the Lead's decode corrected

MEASURED. `ours` = `our-run1.txt` (a9pwn, `run --rounds 12 --setup-budget 300 --pad-timeout-ms 5
--allow-winusb`); `gaster` = `e4-gaster-1.txt`. Δt = completion timestamp − submission timestamp.

| event | ours | gaster | status / `wLength` / `C length` |
|---|---|---|---|
| SETUP w=4 ms: DNLOAD 2048 **completes** | `:49-50` 935 µs | `:47-48` 992 µs | 0 / 0x800 / 2048 |
| SETUP w=5 ms: DNLOAD 2048 **completes** | `:53-54` 974 µs | `:51-52` 974 µs | 0 / 0x800 / 2048 |
| SETUP w=0 ms: DNLOAD 2048 **cut** | `:57-58` **70 µs** | `:55-56` **117 µs** | **-2** / 0x800 / 0 |
| **SETUP pad** (`bm=0,b=0`) | `:59-60` **736 µs** | `:57-58` **889 µs** | **-32** / **0x500=1280** / 0 |
| SPRAY stall (`bm=2,b=3,wIndex=0x80`) | `:91-92` **156 µs** | `:87-88` **158 µs** | **-32** / **0** / 0 |
| SPRAY leak / no-leak (abort 1 ms) | `:93-96` | `:89-92` | -2 / 0x40, 0xC1 / 0 |
| SPRAY trailing CLR_STATUS | `:97-100` | `:93,96` | **-71** / 0xC1=193 / **64** |
| **PATCH overflow** (`bm=2,b=3,wIndex=0x80`) | `:161-162` **164 µs** | `:157-158` **167 µs** | **-32** / **0x30=48** / **0** |
| PATCH payload DNLOAD 528 | `:163-164` 5078 µs | `:159,161` 5061 µs | **-2** / 0x210=528 / **528** |
| PATCH suffix / end / 3× walk / **pre-read** | `:165-177` | `:162-171` | -2 (5-5.1 ms each) — see note |
| serial descriptor **before** PATCH | `:160` **198 B** | `:156` **198 B** | at the declared index (4 at that moment) |
| serial descriptor **after** PATCH | `:226` **228 B** | `:220` **228 B** | at the **declared** index (4 at that moment) |
| device address across the drop | 1:008 → 1:009 → 1:010 | 1:005 → 1:006 → 1:007 | re-enumeration |

**Note on that row (T3-R F6).** Ours has **four** `a1 03` reads in this region, not three: the
three MANIFEST-walk reads (`:170-175`) plus a fourth at `:176-177` that took **100,053 µs** — that
is our post-PATCH **reset's DFU state pre-read** (`DFU_STATE_TIMEOUT_MS = 100`), which gaster does
not issue (its reset is a bare `libusb_reset_device`, `gaster.c:197-200`). So this is a real
wire-level deviation in the PATCH tail and a live illustration of E5-1: the extra read is 100 ms of
the run, and its own result is the one thing E5-1 says is being discarded.

**The Lead's decode attributed line 87 to PATCH; it is SPRAY's stall.** Evidence, three ways:
(a) `wLength = 0` is `checkm8_usb_request_stall` exactly (`gaster.c:889-894`), whose only A9 caller
is the spray triple (`gaster.c:901-902`) — the other caller at `:1198` is gated to
`cpid ∈ {0x8001,0x8010,0x8011,0x8015,0x8012}`; (b) in both captures that request is immediately
followed by the leak read (`wIndex=0x0A`, `wValue=0x0304`, 64 B, 1 ms abort), the no-leak read
(193 B, 1 ms) and the trailing CLR_STATUS of `3*EP0_MAX_PACKET_SZ+1 = 193` (`gaster.c:910`) —
the spray triple, in order; (c) the 48-byte request is immediately followed by the 528-byte
payload, the 16-byte suffix, the zero-length end DNLOAD and three `DFU_GET_STATUS` reads (ours has a
fourth, the reset pre-read — see the note under the table) — the
fixed PATCH order of `gaster.c:1211-1222`. The decisive disambiguation is our **own labelled
trace**: `our-run1.jsonl` seq 37 `"label": "spray_request_stall" … "w_length": 0` and seq 48
`"label": "patch_overflow_callback" … "w_length": 48`, in that order. `sz = 0` is confirmed
independently by seq 26 (`setup_pad_request`, `w_length: 1280`, `status: STALL`) and by the
printed sweep (`our-run1.txt.stdout.txt:4`: `abort_xfer=0 … pad_req=1280 pad_status=STALL
pad_xfer=0/1280 … pad_micros=745`).

**Both runs pwned.** `gaster` printed its success in the Lead's run; `a9pwn` printed
`PWND marker present: Some("checkm8") — checkm8 landed.` (`our-run1.txt.stdout.txt:11`). Our run's
PATCH also shows the two effects this report predicts: the 528-byte payload's **data stage
completed on the wire** (`our-run1.txt:164`, `-2 / 528`) while our trace recorded it as
`TIMEOUT … transferred: 0` (`our-run1.jsonl` seq 50, `libusb_rc: -7`) and raised
`PATCH_UPLOAD_SHORT` (seq 52; `stdout:9`) — i.e. **the false alarm fires on a successful pwn**
(§3.4).

---

## 3. Q1 — PATCH's pass condition (LINUX-HANDOFF §4.7)

### 3.1 Q1(a) — what in gaster's source distinguishes "STALL at setup stage" from "STALL after 48 bytes"?

**Nothing. It is unobservable by construction, for three independent reasons.**

1. **The call cannot report it.** `gaster.c:1211` is
   `send_usb_control_request(handle, 2, 3, 0, 0x80, overwrite, overwrite_sz, &transfer_ret)`,
   the synchronous path (`gaster.c:226-240`). Its only evidence is libusb's return value:
   `ret >= 0` → `sz = (uint32_t)ret`, `OK` (`:230-232`); `ret == LIBUSB_ERROR_PIPE` → `STALL`
   (`:233-234`); else `ERROR` (`:235-237`). libusb 1.0.27 (the version this host links —
   `libusb-1.0-0 2:1.0.27-1`) collapses every STALL position to one code and **discards the byte
   count**: `sync.c:144-153` returns `LIBUSB_ERROR_PIPE` for `LIBUSB_TRANSFER_STALL` and returns
   `transfer->actual_length` only for `LIBUSB_TRANSFER_COMPLETED` (`sync.c:145-147`). Consequence
   visible in gaster: on a STALL, `transfer_ret->sz` is **never written** at `gaster.c:229-237` —
   the field keeps its previous value. gaster reads only `.ret` at `:1211`, so it is harmless, but
   it proves the author never expected a count from that call.
2. **The predicate is one enum.** `transfer_ret.ret == USB_TRANSFER_STALL` (`gaster.c:1211`) is one
   bit: "the request was refused". Setup, data and status stage all land in it.
3. **The identical request without a data stage produces the identical STALL**, and gaster uses it
   that way. `checkm8_usb_request_stall` (`gaster.c:889-894`) issues
   `send_usb_control_request_no_data(handle, 2, 3, 0, 0x80, 0, &transfer_ret)` and returns
   `ret == USB_TRANSFER_STALL`; that is SPRAY's stall primitive (`gaster.c:902`). MEASURED in both
   runs: `-32 / 0` in 156 µs (ours `:91-92`) and 158 µs (gaster `:87-88`). So "STALL on
   `bm=2,b=3,wIndex=0x80`" is routinely produced by a request that **cannot** have had a data
   stage. The pass condition is therefore not evidence of an overflow.

For completeness: libusb's **asynchronous** API does expose `actual_length` alongside a STALL
(`gaster.c:262-276` fills `sz` and maps `LIBUSB_TRANSFER_STALL` from the same completion), and our
async path reads it unconditionally (`usb.rs:1830`,
`let raw_len = (*transfer).actual_length.max(0) as usize;`). The distinction is obtainable from
libusb — just not through the call gaster chose at `:1211`.

### 3.2 Q1(b) — the exact wire-level predicate that would distinguish them

**Decisive, and not available from usbmon:** the per-packet handshake of the data stage —
`SETUP/ACK, DATA0/ACK, IN/STALL` ("48 bytes consumed, then the status stage was refused") versus
`SETUP/ACK, DATA0/STALL` ("nothing consumed"). usbmon is URB-level: one submission line and one
completion line per control transfer; it cannot show a packet handshake. A hardware USB protocol
analyser (or a device-side observation) is the only direct instrument.

**Best usbmon proxy:** the `C` line of the URB whose `S` line carries `s 02 03 0000 0080 0030 48`:
`status == -32` and `length` (= `urb->actual_length`). `48` ⇒ the data packet was ACKed before the
STALL; `0` ⇒ either nothing moved **or** the HCD did not record it.

MEASURED: `length` is `0` in both runs (`our-run1.txt:162`, `e4-gaster-1.txt:158`) — **and that
zero cannot be read as "nothing was consumed", because both STALLs gaster's own sequence treats as
the pass condition show the same `-32 / 0`** (the pad, `:60` / `:58`). The capture's internal
control for "is `length` populated on an error termination?" is the 528-byte payload DNLOAD: it
ended in error and the `C` line still reported `528` (`our-run1.txt:164`, `e4-gaster-1.txt:161`).
But that is a *timeout* path; whether the HCD zeroes `actual_length` on a *STALL* path is not
settled by anything in these files (§8.2).

**Timing, the strongest host-only discriminator.** Two runs, same request shapes:

| request | `wLength` | ours (wire) | gaster (wire) | marginal per 64 B |
|---|---|---|---|---|
| DNLOAD 2048 (completes) | 0x800 | 935 / 974 µs | 992 / 974 µs | 29-31 µs (32 packets, no baseline subtracted) |
| pad STALL | 0x500 = 1280 | **736 µs** | **889 µs** | 29 µs (ours) / 36.6 µs (gaster), after subtracting the 156/158 µs baseline † |
| SET_FEATURE STALL, no data | 0 | 156 µs | 158 µs | — baseline |
| SET_FEATURE STALL, 48 B | 0x30 = 48 | 164 µs (**+8**) | 167 µs (**+9**) | 8-9 µs |

† **Disclosure (T3-R F17):** that baseline is a `bm=2,b=3` SET_FEATURE, not the `bm=0,b=0` pad, so
the subtraction mixes request shapes. Recomputed with consistent estimators the pad's per-packet
cost is 36.8 / 44.5 µs (no baseline subtracted, `wLength/64`) or 24.3 / 26.1 µs (DNLOAD-implied
baseline) — the same order of magnitude either way, so the conclusion is unchanged, but the row's
number is estimator-dependent and is labelled as such. **And revision 5's task-9 sweep now shows
the cold pad is FLAT at ≤64 B (§7 items 4-5), which is direct evidence against this bullet's
"scales with `wLength`" reading for a *cold* pad.** The bullet stands only for the post-abort pad,
which is the state the sweep did not test.

* The pad's latency **scales with its `wLength`** at the DNLOAD's per-packet order of magnitude in
  both runs — that is what "the pad's 1280-byte data stage is consumed" predicts, and it is the
  reason to doubt the Windows "watchdog" reading (§7 item 5). INFERRED (two points, different request
  shape from the DNLOAD; the marginal-cost estimator differs between rows and is stated per row).
* The PATCH 48-byte data stage costs **+8 µs (ours) and +9 µs (gaster)** over the zero-length form
  — below the 29-37 µs per-packet cost of the pad. **The two numbers are not strictly
  comparable**: the first is a single-packet delta on a `bm=2,b=3` request the ROM refuses, the
  second a 20-packet average on a `bm=0,b=0` pad it serves, so the inequality cannot by itself
  discriminate "cheap packet" from "no packet". With that caveat, two readings:
  **(A)** the packet was consumed but is cheap, because this request is *rejected by the request
  dispatcher* while the pad is *served*, so its single packet may be handled by the endpoint
  hardware/DMA path rather than the firmware loop that paces a 20-packet transfer;
  **(B)** the packet was not consumed, and the STALL preceded the data — in which case the
  48 bytes, the **only** carrier of `callback = insecure_memory_base` in the A9 path
  (`gaster.c:1192-1196`; our `payload.rs:277-279`, `OVERWRITE_CALLBACK_OFF = 32`, `payload.rs:29`),
  never reached the device and the pwn needs an undocumented mechanism. (A) is labelled INFERRED
  and requires no ROM knowledge beyond "a rejected request need not pay a served request's
  per-packet cost"; (B) is not impossible but has no mechanism in our sources. **The raw
  `-32 / 0` is identical in both cases, so no usbmon field decides this.**

**Naming the claim this refutes (T3-R F15).** `LINUX-HANDOFF.md` §6 E3(b)
(`LINUX-HANDOFF.md:228-231`) puts the test this way: watch the 48-byte overflow URB's transferred
length — "48 ⇒ the data stage was accepted ⇒ the overflow is real; 0 ⇒ **PATCH is a no-op** and
§4.7 is confirmed". That field cannot be read that way: it is 0 on PATCH's 48-byte STALL *and* on
the pad's 1280-byte STALL, which gaster's own pass condition treats as consumed. A 0 therefore
establishes neither "no-op" nor "consumed"; E3(b)'s question needs a per-packet instrument.

**What would settle it, cheapest first:**
1. **Latency vs `wLength` on one request shape.** The two runs already bracket it (0 → 156/158 µs,
   1280 → 736/889 µs for the pad; 0 → 156/158 µs, 48 → 164/167 µs for the SET_FEATURE). A flat
   curve ⇒ refusal at the arming stage; a curve growing ~29-37 µs per 64 B ⇒ the data stage is
   consumed. This also settles the wLength question (§7 items 4-5).
2. **A per-packet analyser** for one PATCH: `DATA0/ACK` then `IN/STALL` versus `DATA0/STALL`.
3. **The end-to-end oracle, which needs no new instrument:** the PWND marker after the post-PATCH
   reset.

### 3.3 The one observable that proves PATCH fired

MEASURED in both runs: after the PATCH sequence and the post-PATCH reset, the re-enumerated
device's serial descriptor is **228 bytes** where it was **198 bytes** (`our-run1.txt:160` before,
`:226` after; `e4-gaster-1.txt:156` before, `:220` after), and it is served at **the index the
device descriptor declares** — which moves. Supporting measurements: the payload's `C length == 528`
proves the payload reached the device (`our-run1.txt:164`), and the 198-byte read after the SPRAY
drop proves the device was **not** pwned before PATCH (`our-run1.txt:160`; in gaster's run the
same sequence is `:144` → `:156` → PATCH → `:220`), which removes the only competing cause.

> **Correction (revision 5, from the Lead — and it invalidates a claim this report made in
> revisions 1-4).** Earlier revisions said "the marker is at index 6 where the pre-pwn device served
> index 4". That is a snapshot, not a property. **Archived half (MEASURED):** `e3-sweep.txt:26`
> shows the post-sweep re-enumeration with the descriptor's `…02 03 04 01` (iSerial = 4) and
> `:30` `s 80 06 0304` → **228 bytes**; `e1-ep0cut-corrected.txt.stdout.txt:18-21` likewise reports
> `COMPLETED 228` at the declared index 4. **Unarchived half (Lead-reported, not in any capture):**
> "index 6 → 0 bytes" and "`lsusb` reports iSerial 4 now, 6 earlier". T3-R round 2 grepped the whole
> trace tree and found that **every** `06 0306` request on disk (e4-gaster-1.txt:219/229/235,
> our-run1.txt:225/231/233/235/237/243) returned **228**, from the era when 6 was the declared
> index; there is no archived index-6→0 read. That half is therefore recorded here as the Lead's
> report, not as a measurement, and should be archived or dropped. The rule for every tool and
> reader: **read the index the device descriptor declares**
> (`serial_number_string_index()`; `a9pwn`'s `resolve_index` does exactly this), and the negative
> control is a *non-marker* string at that index. The PATCH-causality evidence survives the
> correction when restated: **no marker-bearing descriptor read (228 B at the declared index) occurs
> before PATCH** — before `e4-gaster-1.txt:157` / `our-run1.txt:161` every serial read is 198 bytes.

The **content** of the +30 bytes is INFERRED, not measured: usbmon prints only 32 data bytes, so
the string identity comes from `gaster.c:1110` (`memcpy(A9.pwnd, pwnd_str, strlen(pwnd_str));`,
`pwnd_str = " PWND:[checkm8]"`, `gaster.c:154`, used by the checker at `:811`), and from our own
trace, which reports `PWND marker present: Some("checkm8")` (`our-run1.txt.stdout.txt:11`) and
`serial_len=113` (`:36`). 228 = 2 + 2×113 and 198 = 2 + 2×98, i.e. +15 UTF-16 units =
the 15-character marker — the arithmetic closes. (The corrected `cut` run reports the same
228 bytes at declared index 4: `e1-ep0cut-corrected.txt.stdout.txt:18-21`.)

**Recommendation.** PATCH's pass condition should be the **marker**, not the STALL: keep
`patch_overflow_stall` as a recorded predicate (it is the reference's own predicate, and it is
genuinely needed before the upload), but treat a PATCH "pass" as a precondition, not a result, and
put the pre/post serial length in the run's evidence (E5 item 2). Our own run demonstrates why:
the STALL predicate passed, the payload chunk predicate **failed**, and the pwn landed anyway.

### 3.4 Q1(c) — does our implementation share the blindness? **Yes — quoted.**

`stage_patch` sends the overflow through the synchronous path and predicates on the status alone
(`stages.rs:1691-1707`):

```rust
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
        …
```

and the transport fabricates `transferred = 0` for **every** non-`Ok` return (quoted code,
re-resolve by quote — `usb.rs:1494-1499` at `6b2bda4e…`/5996, `:1485-1490` at `c46ce084…`/5724):

```rust
        let status = XferStatus::from_libusb_rc(rc);
        let transferred = if rc >= 0 {
            (rc as usize).min(requested)
        } else {
            0
        };
```

So our trace's `patch_overflow_callback … xfer=0/48` **cannot** answer §4.7: it is 0 by
construction whenever the status is `Stall`, exactly as in gaster. The machinery to see the count
already exists — the async path reports `actual_length` regardless of terminal status
(`usb.rs:1830-1844`) — but PATCH does not use it, and re-pointing it would change which libusb
call issues the request (a transport-path deviation the Lead owns, not this report).

**Adjacent consequence, MEASURED, and it has already happened:** the *same* sync-path blindness
makes our PATCH instrumentation cry wolf on a successful Linux pwn. Both runs show the payload's
data stage completing while the transfer ends in a timeout —
`our-run1.txt:163-164` = 528 requested, `C length 528`, status `-2`, reaped at 5078 µs;
`e4-gaster-1.txt:159-161` the same. Our chunk call uses the same 5 ms window
(`stages.rs:1730-1740` → `req_out`, `stages.rs:533-536`, which calls
`io.usb.control_out(r, data, io.opts.timeout_ms())` directly — *not* through `req_ctrl`; the
timeout is `timeout_ms()` at `:313`) and our completeness test is
`status == Ok && transferred == len` (`stages.rs:1613-1615`), so the chunk that *delivers* the
payload is recorded `TIMEOUT … transferred: 0` and `PATCH_UPLOAD_SHORT` fires
(`our-run1.jsonl` seq 50/52; `our-run1.txt.stdout.txt:9`). It does not stop the stage
(deliberately, `stages.rs:1662-1677`), and the stage then reports
`acknowledged=0 bytes, short_or_failed_chunks=1` (`our-run1.jsonl` seq 58) — on the run that
pwned. A reader must not read that as failure: on this host the marker, not the chunk status, is
the evidence.

---

## 4. Q2 — SETUP's `sz` arithmetic

### 4.1 How `sz` is obtained in the reference

`gaster.c:848-860`, the whole function:

```c
	for(;;) {
		if(send_usb_control_request_async_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, DFU_MAX_TRANSFER_SZ, usb_abort_timeout, &transfer_ret) && transfer_ret.sz < config_overwrite_pad && send_usb_control_request_no_data(handle, 0, 0, 0, 0, config_overwrite_pad - transfer_ret.sz, &transfer_ret) && transfer_ret.ret == USB_TRANSFER_STALL) {
			return true;
		}
		send_usb_control_request_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, EP0_MAX_PACKET_SZ, NULL);
		usb_abort_timeout = (usb_abort_timeout + 1) % (usb_timeout - usb_abort_timeout_min + 1) + usb_abort_timeout_min;
	}
```

* `sz` is `transfer_ret.sz` from the **aborted async 2048-byte `DFU_DNLOAD`**
  (`DFU_MAX_TRANSFER_SZ = 0x800`, `gaster.c:44`; submit/cancel at `gaster.c:243-283`).
* On the libusb path it is `transfer->actual_length`, read **after the cancel completes**, for
  every terminal status (`gaster.c:262-276`): `transfer_ret->sz = (uint32_t)transfer->actual_length;`
  then `COMPLETED → OK`, `STALL → STALL`, else `ERROR`.
* `pad = config_overwrite_pad − sz` (`:853`) goes out as a `bm=0, b=0, wValue=0, wIndex=0` control
  OUT of that many zero bytes (`send_usb_control_request_no_data`, `gaster.c:467-480`), and
  **STALL on that pad is the pass condition**.
* For A9 `config_overwrite_pad = 0x500 = 1280` (`gaster.c:625-626`).
* `usb_timeout` defaults to 5 ms and `usb_abort_timeout_min` to 0 (`gaster.c:1632`, `:1636`), so
  the first window is 4 ms and the cycle is `4,5,0,1,2,3` (`:849`, `:857`) — the windows observed
  in both runs, in order.

### 4.2 What the Linux runs show — the arithmetic, and its collapse

MEASURED (ours then gaster):

* window 4 ms: DNLOAD 2048 **completes** in 935 / 992 µs. `sz = 2048 ≥ 1280` ⇒ **no pad**; the
  64-byte drain follows (`gaster.c:856`).
* window 5 ms: DNLOAD 2048 **completes** in 974 / 974 µs. No pad; drain.
* window 0 ms: DNLOAD 2048 is **cut at 70 / 117 µs, 0 bytes** (`-2 / 0`).
  `sz = 0 < 1280` ⇒ pad of `1280 − 0 = 1280` goes out and STALLs after 736 / 889 µs ⇒ **SETUP
  passes** (ours: `our-run1.jsonl` seq 25/26, `stdout:4`).

**`sz` was 0 — provable without trusting libusb.** The pad's `wLength` is `1280` and the formula is
`1280 − sz`; only `sz = 0` yields 1280. So the reference's arithmetic evaluated with `sz = 0`, and
the total offered was `0 + 1280 = overwrite_pad` exactly. **The reference's success did not depend
on a nonzero partial count**, in either run: the attempts that moved bytes moved *all* of them
(2048 ≥ 1280 ⇒ no pad), and the attempt that produced the pad moved none.

**Was the 0 truthful?** Supporting numbers: the request shape's own "refuse" latency is 156/158 µs
and the cut came at 70/117 µs — shorter than a full request round trip. INFERRED (not proof): no
complete packet-plus-turnaround could have finished inside the cut, so `sz = 0` is a true 0 rather
than a discarded partial. The inference is weak in the direction that matters (a 70 µs cut could
in principle overlap the first packet), which is why §4.4 keeps the question open.

**Is the reference arithmetic "exact" on Linux?** It is *executed* exactly, and on this device it
never has to be exact about anything but 0 or 2048: with ms-granular windows, 0 ms cancels before
the ROM starts and ≥1 ms completes the whole 2048 bytes. **The sweep is degenerate on Linux in the
opposite direction from Windows:** the Windows windows were too *short* (all cut, `sz = 0` every
time, pad frozen at 1280); the Linux windows are too *long* (all complete, no pad) except window 0,
which is the one that pads. The pass is the window-0 attempt, and it is the **pad**, not the cut
position, that carries the exploit.

**Consequences for our port.** `stage_setup` already reproduces this bit-for-bit: it reads the same
`actual_length` field through `control_async_abort` → `submitted_result` (`stages.rs:825-834`,
`:888-931`; `usb.rs:1830-1844`) and computes `pad_request_len = overwrite_pad − transferred`
(`stages.rs:446-451`). With the shipped defaults (`usb_timeout_ms = 5` at `stages.rs:81`;
`abort_timeout_min_ms = 0` at `stages.rs:297` — *not* `:296`, which is `pad_timeout_ms`) the sweep
walks `4,5,0` and passes on the third attempt — MEASURED in
`our-run1`. **Recommendation: do not land the packet-quantised sweep.** On this host it would
matter only if a cut landed mid-transfer, which the reference never does here; introducing one
changes the heap state the primitive depends on (INTERFACE.md: "every deviation from the reference
is a silent new failure mode") and replaces a reference-faithful sequence with an unreferenced one.
If the partial-count question still needs an answer, answer it with a measurement (§4.4), not by
changing the exploit.

### 4.3 What a NO-PARTIAL result would imply

If it were established that Linux reports 0 for a cancelled control transfer that *did* move bytes:

1. `pad` becomes the constant 1280 on every cut attempt and the total offered becomes
   `sz_true + 1280` — a second, unmodelled variable, exactly the Windows defect
   (LINUX-HANDOFF §4.2). The packet-quantised sweep `pad = overwrite_pad − j·64` would be the only
   way to make the total exactly `overwrite_pad` by construction.
2. **On this device it would change nothing**, because the only cut attempt has `sz_true = 0`
   (§4.2) — and that is now measured in two runs, with the pwn as the outcome. The sweep would be
   a workaround for a condition this host does not reach.
3. It would weaken E4 (the gaster control) in one specific way: gaster-on-Linux reads the same
   `transfer->actual_length` we do (`gaster.c:267`), so if Linux loses partials, gaster's
   arithmetic is equally collapsed — a gaster *failure* on Linux could not be blamed on the
   transport. Its *success* is unaffected as evidence: this run's success did not use `sz`.

### 4.4 The decisive observation, and why the E1 data does not settle it

**Decisive for "the reference arithmetic is exact" (branch A):** an attempt where the trace shows
`setup_abort_dnload … xfer = p·64`, `p > 0`, **and** the usbmon `C length` for that same URB agrees,
**and** the pad goes out with `wLength = 1280 − p·64`. The usbmon URB tag (column 1) ties the two
records together; `a9pwn`'s `seq`/`xfer_seq` fields tie it to the trace line.

**Decisive for "NO-PARTIAL" (branch B):** an attempt where usbmon's `C length` for the aborted
DNLOAD is `> 0` while `a9pwn` reports `xfer = 0` for the same URB. The divergence *is* the proof;
either instrument alone is ambiguous (a 0 can mean "nothing had arrived").

**ANSWERED (revisions 4-5, from measurements that landed after revision 3).** The question above is
settled by `tools/arlo/ep0cut` cutting control transfers at **microsecond** deadlines. In the IN
direction, `GET_DESCRIPTOR(3,4)` cut at µs deadlines reported **graded, 64-byte-quantised counts —
64 / 0 / 64 / 128 / 192 / 198** followed by `COMPLETED 198`
(`a9pwn-traces/linux/e1-ep0cut-ladder.txt:4-19`). So on Linux the **async** path — the one our SETUP
sweep uses (`control_async_abort`) — carries a real partial for a cancelled control transfer, and
branch A holds for the IN direction.

**Direction (T3-R F3, and now MEASURED rather than inferred).** The archived ladder cuts an IN
transfer; the exploit's aborted transfer is an OUT `DFU_DNLOAD`. The kernel accumulator is
direction-agnostic (`os/linux_usbfs.c:2610`, INSPECTED), but until revision 5 no OUT cut had been
observed. It has now: the task-9 sweep's `pad` row at `wLength = 128` was an **OUT** control
transfer that libusb timed out after consuming one packet, and it reported **`sz = 64`** with the
wire independently showing **`C … -2 64`** (`e3-sweep.txt:9-10`, `e3-sweep.table.txt` row
`pad 128 TIMED_OUT 64`). Partial reporting on this host is therefore measured in **both**
directions. The exploit's own aborted DNLOAD still has only ever reported 0 (`our-run1.jsonl`
seq 25) with the wire agreeing (`our-run1.txt:58`, `-2 / 0`) — that is a *truthful* 0 (the cut landed
at 70-117 µs, before the ROM had moved anything), not a discarded partial.

**Recap of the two consequences.** (i) The packet-quantised sweep is definitively unnecessary: the
reference's arithmetic reads a real number here, and the two pwn runs' passing attempt had `sz = 0`
so its `pad = 1280` was the reference's exact formula. (ii) A **separate** defect remains and is
worth its own fix: the **synchronous** path discards the count on any non-`Ok` return — partly the
libusb API's own limitation (`libusb_control_transfer` returns one `int`: `sync.c:144-153`,
INSPECTED) and partly our transport's mapping, which sets `transferred = 0` for every `rc < 0`
(`usb.rs`, the `let transferred = if rc >= 0 { … } else { 0 };` block). That is why our PATCH trace
records `TIMEOUT … transferred: 0` while the wire shows `-2 / 528`
(`our-run1.jsonl` seq 50 vs `our-run1.txt:164`); it is the source of the `PATCH_UPLOAD_SHORT` false
alarm in §3.4, and the tool that measured the async path cannot see it.

> Note on the raw file vs the tool's own verdict — corrected in revision 5 (T3-R F2). The two
> archived `ep0cut` runs failed **different** controls, and **neither** passed both:
> `e1-ep0cut.txt` had control 1 OK and control 2 FAILED (it demanded `COMPLETED / 255`, got the
> legitimate `COMPLETED / 198`); `e1-ep0cut-ladder.txt` had control 1 FAILED (it demanded
> `CANCELLED / sz = 0` where the row contained the answer, `CANCELLED / 64`) and control 2 OK. Both
> prints read `VERDICT INVALID LADDER` for different reasons. The current `cut_controls` fixes both;
> **it has since been run on hardware and both controls pass** —
> `e1-ep0cut-corrected.txt.stdout.txt:23-26`: control 1 OK, control 2 OK (`228 of 255`), and
> `VERDICT PARTIALS SURVIVE CANCELLATION: cut after 196us reported libusb sz=64 of 255`. The ladder
> also shows what a real cut looks like: 50 µs → 64 B, 75 µs → 128 B, 100 µs → 128 B, 125 µs → the
> full 228 B (`:12-18`). The same failure mode as ever, one file over: a check that cannot pass for
> the right reason.

**A 0 alone cannot conclude NO-PARTIAL**, and that is what the *old* E1 runs show. MEASURED from
the four `probe-partial-count` captures: all four report `CANCELLED xfer=0/255`, `libusb_rc=3`, with
usbmon `-2 / 0` on the aborted URB; **three of the four are uninformative** because their open-time
identity reads timed out at exactly 100 ms (`e1-probe-1ms.txt:1-4`, `-2 / 0` twice) —
`IDENT_TIMEOUT_MS = 100` (`usb.rs:74`) — so the device was answering nothing at all in those runs;
the 0 ms run's device *was* answering (198 B in 157 µs, `e1-probe-0ms.txt:1-2`), but its cut landed
at 126-148 µs, inside the spread of the device's own answer latency for index 4 (112, 112, 120,
150, 160, 167, 190 µs across seven reads in `e4-gaster-1.txt:6,38,46,78,86,144,156`), so even there
0 is ambiguous.

**The printed conclusion is also mis-worded on mechanism.** It is not that libusb discards a
partial: libusb 1.0.27 adds `urb->actual_length` to the transfer **before** the cancellation branch
(`os/linux_usbfs.c:2610`, then `:2612-2620`), and our async path reads the result (`usb.rs:1830`).
The 0 is the *kernel's* `urb->actual_length`, independently visible as usbmon's `-2 / 0`. The
honest sentence is "the kernel reported 0 bytes for this URB". (The print is at
`main.rs:502-505`, not `:481-486`.)

**How it was made decisive (kept for the method, since the answer is now in).** Window granularity
is ms and the DNLOAD takes ~0.95 ms, so gaster's windows cannot land mid-data. The answer came from
changing the *instrument*, not the exploit: `tools/arlo/ep0cut` cuts `GET_DESCRIPTOR(3,4)` at
**microsecond** deadlines on the async path, and the cancelled rows reported 64 / 0 / 64 / 128 / 192
/ 198 (`e1-ep0cut-ladder.txt:4-19`). The two older options are now moot: (ii) the 5 ms timeout path
was already calibrated to report a partial (`-2 / 528` in both runs), and (iii) both runs pwned with
`sz = 0`, so the question never gated the exploit. This report still recommends **not** building the
packet-quantised sweep — and now the reason is measured rather than inferred.

---

## 5. Q3 — the five E5 log additions, with exact edit sites

Line numbers in this section are pinned to the revisions in §0 (`usb.rs` at `c46ce084…`/5724,
which has since moved to `6b2bda4e…`/5996 — **re-resolve by symbol**; `stages.rs` is stable). Each
item is a *proposal*; no code was changed by this report. E5-3 and E5-5 have since been implemented
by the Lead and are marked SUPERSEDED below.

### E5-1 — record the DFU state pre-read's error code; say refused vs real

* **Call site:** `usb.rs:1928` — `let dfu_state_before = self.dfu_status_state(DFU_STATE_TIMEOUT_MS);`
  inside `reset()` (opens at `usb.rs:1927`).
* **Why the code is lost:** `dfu_status_state` (`usb.rs:1888-1900`) returns `Option<u8>`, discarding
  the `XferResult`: `if r.ok() && r.transferred >= 5 { Some(buf[4]) } else { None }`. "No answer" and
  "answered short" collapse into one `None`; the pre-read's `status`, `libusb_rc` and `micros` never
  reach the report. LINUX-HANDOFF §4.5's classification of the fast population (13-23 µs = "already
  dead before the reset") therefore rests on **timing alone**.
* **Smallest correct edit:** add a sibling that keeps the result —
  `fn dfu_status_read(&self, timeout_ms: u32) -> (Option<u8>, Option<XferResult>)` — with
  `dfu_status_state` delegating to it; add `pub dfu_state_before_read: Option<XferResult>` to
  `ResetReport` (`usb.rs:354-385`; `dfu_state_before` is at `:371`); populate it at `usb.rs:1928`;
  append it in `reset_facts` (`stages.rs:2492-2504`), which already prints `dfu_state_pair(r)`.
  **Compile note — BLOCKER, T3-R F1, independently reproduced.** `ResetReport` has **THREE**
  exhaustive struct literals, not two: `a9pwn/src/usb.rs` (production, `Ok(ResetReport {` — `:1974`
  at `usb.rs` `c46ce084…`), a test literal in the same file (`let delivered = ResetReport {` —
  `:4062` at the same revision), **and `a9pwn/src/stages.rs:3423`** in its own `reset_report` test
  helper. All three fail `E0063` when the field is added. The other literals are functional updates
  and inherit it: `usb.rs` `let unverified = ResetReport { … , ..delivered.clone() }` and
  `stages.rs:3558`/`:3570` (`..reset_report(…)`). T3-R applied the first draft's edit on a scratch
  copy and got `error[E0063]: missing field … --> src/stages.rs:3423` — i.e. **`cargo test`, which
  the gate runs, would have failed.** The generic rule: *grep for the struct, do not trust the line
  numbers in this report* (`grep -rn "ResetReport {" a9pwn/src`).
* **Already recorded (no edit needed):** whether the reset was refused or real —
  `reset_evidence` → `ResetEvidence` (`types.rs:401-417`), traced by `record_reset`
  (`stages.rs:2573-2575`) and gated by `reset_gate` (`stages.rs:2621-2639`).

### E5-2 — a per-round `marker_read{serial_len, pwnd, live|cached}` record

* **Call site:** `stages.rs:1980` — `let id = usb.identity();` followed by `id.is_pwned()`
  (`:1981-1989`); the per-round PWND check mirroring gaster's per-iteration serial read
  (`gaster.c:1243` → `:202-218`).
* **Why `pwnd` can be a stale value:** `identity()` (`usb.rs:1225-1234`) falls back silently on a
  failed read: `Err(_) => self.identity.clone(),` (`usb.rs:1233`). A failed live read returns the
  **cached open-time** identity, so "PWND absent" can be stale and `serial_len = 0` can be a null
  read (LINUX-HANDOFF §4.6).
* **Smallest correct edit:** add `pub fn identity_read(&self) -> (DeviceIdentity, bool)` (`true` =
  live), keep `identity()` as a wrapper so no other caller changes, use it at `stages.rs:1980`, and
  emit one event per round: `marker_read{serial_len=<id.serial.chars().count()>, pwnd=<…>,
  live|cached}`. Do not put the serial itself in the trace (hard rule 2). Our own run shows the
  fields that matter are available today only in the final verdict (`serial_len=113`,
  `our-run1.txt.stdout.txt:36`) — not per round.

### E5-3 — the final read must retry instead of racing a re-enumeration — **SUPERSEDED: IMPLEMENTED**

> **Status (revision 5, T3-R F4): the Lead implemented this himself while the review ran.** At
> `a9pwn/src/main.rs` `f57ce965…`/812 the single-attempt arm this section targets is **gone**,
> replaced by a bounded re-open loop (`while wait_started.elapsed() < Duration::from_millis(2_000)`
> with a 50 ms pause, approximately `:445-459`), a live re-read message (`:480-486`), and — E5-5's
> requirement — retention of the capability measured while the device was present. The section is
> kept because the *reason* still applies to any future single-shot read, and because E5-4's
> wall-clock principle was applied in the same edit (`wait_started.elapsed()` at `:447`, `:471-475`).
> If the reader finds a single-attempt `open_first_dfu()` at the end of a run, the item is live
> again. The proposal below is the pre-implementation text, at `main.rs` `5365e281…`/523.

* **Call site:** `main.rs:421` — `let (id, driver, cap) = match Transport::open_first_dfu() { … }`,
  a single attempt issued immediately after `stages::run_with_tracer` returns (`main.rs:415`), i.e.
  ~0.7 ms after a drop that may still be re-enumerating (LINUX-HANDOFF §4.6). `run_with_tracer`
  returns `RunOutcome::Pwned` the instant the loop's marker read succeeds (`stages.rs:1980-1989`),
  and in both captures the marker is read on a device that has re-enumerated twice
  (`our-run1.txt`: 1:008 → 1:009 → 1:010).
* **Smallest correct edit:** reuse the existing bounded retry. `open_with_retry`
  (`stages.rs:2653-2680`, 600 tries × `usb_timeout_ms`) is private to `stages`; make it **`pub`**
  (not `pub(crate)`) and call it at `main.rs:421`. **Compile note (reviewer finding):** `main.rs` is
  a separate crate from the library — `main.rs:9` is `use a9pwn::stages::{…}` and `lib.rs:21` is
  `pub mod stages;` — so `pub(crate)` would not be visible and the first draft's edit would have
  failed with `E0603`.
* Keep the failure visible: the current `Err(_)` discards the message (`main.rs:423`).

### E5-4 — record wall-clock absence, not an open-attempt count

* **Call site:** `open_with_retry` (`stages.rs:2653-2680`). The failure message reports an
  **estimate**: `"no DFU device after {OPEN_RETRY_TRIES} open attempts (~{} ms)"` with
  `OPEN_RETRY_TRIES * opts.timeout_ms()` (`:2676-2679`) = 600 × 5 = 3000 ms of *pause*, excluding
  the cost of each failed open. Note `OPEN_RETRY_TRIES` is **600** (`stages.rs:2651`), not 19; the
  "19 attempts" figure in LINUX-HANDOFF §4.8 is an observed attempt count from a run that opened
  on its 19th try; it is compatible with the current 600 bound and is not attributed to any build.
* **Correction to revision 1 (reviewer finding):** revision 1 called this "a 10× overstatement" by
  comparing 3000 ms against the measured 285-292 ms for *19* attempts. That comparison is invalid —
  285-292 ms for 19 attempts is ≈15 ms per attempt, so 600 attempts would be ≈9 s, and the
  modelled 3000 ms is a **lower bound** (pause only), not an overstatement. The defect is the
  *kind* of number, not its size: a modelled pause wearing a measured name. Report the measured
  elapsed time instead.
* **Smallest correct edit:** `let started = Instant::now();` before the loop at `:2656`; report
  `started.elapsed().as_millis()` in the `open_retry_ok` event (`:2660-2664`) and in the final `Err`
  (`:2676-2679`). `Instant` is already imported (`stages.rs:31`), so this compiles as-is.

### E5-5 — a failed open must not overwrite a capability read while the device was present — **SUPERSEDED: IMPLEMENTED**

> **Status (revision 5, T3-R F4): implemented by the Lead at `main.rs` `f57ce965…`/812.** The
> `Err(_) => (DeviceIdentity::default(), DriverClass::Unknown, ResetCapability::Unknown)` arm no
> longer exists. A failed re-open now falls back to
> `capability_measured_while_present.unwrap_or((Unknown, Unknown))` (declared `:387`, set `:391`,
> used approximately `:461-478`) and prints that the identity "is a DEFAULT, not a reading, and the
> capability is the value measured before the run … rather than a degraded Unknown". The proposal
> below is the pre-implementation text; it is kept for the Linux caveat that follows it, which is
> still live.

* **Call site:** `main.rs:421-425` (pre-implementation):

  ```rust
  Err(_) => (DeviceIdentity::default(), a9pwn::types::DriverClass::Unknown,
             ResetCapability::Unknown),
  ```

* **Why it matters:** that arm erases the capability the run measured *while the device was
  present* (`run_rounds` measured it at `stages.rs:2000-2001` and recorded it in the `device`
  event, `:2001-2016`). A capability read taken while the device is absent is **UNREAD**, never
  `Unknown` (LINUX-HANDOFF §8 rule 2).
* **Smallest correct edit:** keep the last *measured* capability/driver alongside the identity —
  have `run_with_tracer` return the session's `ResetCapability`/`DriverClass` (measured once at
  `stages.rs:2000-2001`) and use that in the `Err` arm, recording that the final open failed. If
  the interface cannot grow, make the `Err` arm carry a distinct "unread" marker and suppress any
  capability-derived verdict.
* **Linux face of the same defect, MEASURED — and worse than the arm above.** In our own pwned run
  the *successful* capability measurement was itself `Unknown`: the run printed
  `driver_class=unknown reset_capability=unknown` (`our-run1.txt.stdout.txt:30`), classified two
  resets as `resets_pipe_cycle` and none as `resets_real`, warned `evidence "driver cannot reset"`
  after resets that returned SUCCESS in 236562 µs (`:1`) and 235440 µs (`:6`), and printed a
  **High-confidence `[NO_RESET_CAPABILITY]` verdict — "checkm8 can never fire"** (`:29`) on the run
  whose stdout also says `checkm8 landed.` (`:11`). The binary used there (`a9pwn-93a93aed`) predates the current Linux driver
  measurement (`linux_driver_reading`, `usb.rs:3493`, `Real` at `:3549`), so this specific output
  should be re-measured on the current build; but the lesson is E5-5's, in Linux form: an
  *unmeasured* driver must not become a *negative* capability claim. Note the run needed
  `--allow-winusb` to get past the gate at `stages.rs:2025-2041` at all — a Windows-specific escape
  flag on a Linux host.

---

## 6. Documented deviations from gaster — for the reviewer's stage-semantics check

The task asked for "the two documented DEVIATIONs". Three candidate rows exist; which two depends on
the document, so all three are recorded with current status.

1. **V05 — the reset's result handling.** `a9pwn/docs/VERIFICATION-live-run.md:97`, row verdict
   **"DEVIATION — bug. Placement matches; the *result handling* does not"**; the same document
   counts its ten rows as "8 MATCH, 2 DEVIATION" at `:104-108` and names the two rows V05 and V08 at
   `:108`. The reference discards the reset result (`gaster.c:197-200`) and resets unconditionally
   after every stage (`gaster.c:1268`); our port reads the report and gates: `ResetGate`
   (`stages.rs:2621-2639`), with `Unverified → ContinueLoudly`, `Refuted`/`DriverCannotReset →
   Stop`. The addendum records this as **FIXED** (addendum `:326`, `:438-448`).
   **Stage-semantics check:** the reset is still *issued* after every attempt, so the wire sequence
   is unchanged; the deviation is that a run can now **abort** where gaster would continue — so a
   failed run may be the gate rather than the device.
2. **V08 — the `LEAK_WINDEX` framing.** `VERIFICATION-live-run.md:100`, **"DEVIATION — the framing
   is wrong"**: `LEAK_WINDEX_GASTER = 0x0A` is the sourced value; `0x00` exists only because the
   frozen interface names it. INSPECTED: `stages.rs:61-72` documents `0x00` as uncited, the CLI flag
   `--leak-windex-ipwndfu` still selects it, and the default is `0x0A`.
   **Stage-semantics check:** wire parameters are identical to the reference when the flag is not
   passed.
3. **Addendum §10 — the pad timeout 5 ms → 40 ms** (`VERIFICATION-live-run-addendum.md:838-917`,
   row at `:849`, **"DEVIATION — authorised"**, caveats at `:869-891`). **This is REVERTED in the
   current code:** `DEFAULT_PAD_TIMEOUT_MS = 5` (`stages.rs:91`, used at `:296`), i.e. gaster's own
   `usb_timeout` (`gaster.c:227`, `:1632`), with `--pad-timeout-ms` left as the deliberate
   experiment. **Stage-semantics check:** today the pad's timeout matches the reference; the
   addendum's §10.3 false-pass argument (40 ms catching a 21-37 ms watchdog) no longer applies to
   the default, and both Linux runs show the genuine pad STALL arriving in 736/889 µs, well inside
   5 ms.

---

## 7. Adjacent findings that bear on the next run

1. **`Ep0RateLine::A9_SECUREROM_DFU` does not hold on this host.** The model
   (`usb.rs:890-894`; documented at `usb.rs:841` as "MEASURED on the A9 in SecureROM DFU, three
   independent ways" — the source does **not** call it Windows-specific) predicts
   2.57 ms + 32 × 1.043 ms ≈ 35.9 ms for 2048 B. MEASURED here: 935-992 µs in both runs, ~36×
   faster. The 34.9/35.0 ms completions belong to the earlier session (LINUX-HANDOFF §4.1:119).
   Conclusion: the model is host-transport-dependent; never use it to predict packet counts on this
   host, and note it is the reason the same `4,5,0,1,2,3` windows behave oppositely here. (The
   source's own `spread_packets` warning at `usb.rs:848-861` already says the fit scatters.)
2. **On Linux, gaster's windows cannot reliably cut mid-transfer** (0 ms cuts at 70-117 µs; ≥1 ms
   completes
   2048 B in ~0.95 ms). Our port inherits this exactly — which is why the reference's pass is
   reproducible, and why the packet-quantised sweep is unnecessary (§4.2).
3. **`PATCH_UPLOAD_SHORT` fires on a successful Linux pwn** — MEASURED in `our-run1`
   (`our-run1.jsonl` seq 50/52/58, `stdout:9`); see §3.4. Read the marker, not that predicate.
4. **task-9 RAN: the wLength × latency ladder found a KNEE at 128 bytes, not the slope the
   wLength hypothesis predicted.** MEASURED, `a9pwn-traces/linux/e3-sweep.table.txt` (wire: `e3-sweep.txt:1-12`),
   shape `pad`, cold on a **pwned** device, nothing cancelled by the tool, per-row deadline 250 ms,
   wire deltas computed from the capture:

   | wLength | status | libusb `sz` | wire `C` | S→C |
   |---|---|---|---|---|
   | 0 | STALL | 0 | `-32 / 0` | 187 µs |
   | 16 | STALL | 0 | `-32 / 0` | 185 µs |
   | 48 | STALL | 0 | `-32 / 0` | 175 µs |
   | 64 | STALL | 0 | `-32 / 0` | 171 µs |
   | **128** | **TIMED_OUT** | **64** | **`-2 / 64`** | **250,049 µs** |

   The ladder **stopped by design at the first `TIMED_OUT`**; the tool's own archived verdict says
   so — `SWEEP STOPPED … NOT a valid slope` (`e3-sweep.table.txt:18-20`) and
   `"verdict":"INCOMPLETE: ladder stopped after a wedged row"` (`e3-sweep.json`). **Every point is
   N=1** (`e3-sweep.table.txt:24-28`, all `N 1`, spread 0 — an artifact of one round, not a
   measured jitter). The port reset (rc=0) followed and the pwn survived it.
   **Reading, grounded where the instrument grounds it:** at ≤ 64 B the *latency* is flat (171-187 µs)
   while the length varies 64-fold, and the tool's own classifier is latency-based — that is
   **deliberation-consistent**, not a claim about bytes: §8 item 2 records that a `sz` of 0 on a
   STALL cannot be read as "nothing was consumed" (T3-R F20). At 128 B one 64-byte packet is
   reported consumed on both instruments and the request then never answers — no STALL, it NAKs
   until libusb's deadline. The change is qualitative, from **one sample per point**, so "knee" is a
   description of the data, not a fitted feature (T3-R F22).
   **Attribution (T3-R F21):** the device here is **pwned**, so this is the **pwned EP0 path**; the
   736/889 µs STALL the hypothesis is about happened pre-pwn on the SecureROM
   (`e4-gaster-1.txt:57-58`, `our-run1.txt:59-60`). Nothing in this tree establishes that a pwned
   device's `bm=0,b=0` path is served by the ROM, so these rows are **not** attributed to the ROM —
   that needs a stock (power-cycled) control.
   **Two further caveats that bound what this can mean** (both from the Lead, and both load-bearing):
   (i) **the pad here is COLD** — in the exploit it is issued immediately *after* an aborted
   2048-byte DNLOAD (and, in the winning attempt-3, after *two completed* 2048-byte DNLOADs and two
   drains, `our-run1.jsonl` seq 19/21/22/24/25/26), so the 736/889 µs STALL is not described by this
   sweep at all; (ii) the opt-in `dnload` shape was not taken and must not be fitted as ROM
   behaviour on a pwned device.
5. **What that does to the Windows inversion hypothesis — now unresolved, in both directions.** The Windows
   figure (`2.57 + 20 × 1.043 = 23.43 ms` for 1280 B) still matches the eight recorded completions
   in `VERIFICATION-live-run-addendum.md:864-865` with residuals −2.03, −0.53, +1.07, +1.87, +3.77,
   +4.47, −1.93, +13.17 ms (five within 2.1 ms, four within ±2.00; a ninth point at `usb.rs:846`,
   23.02 ms), and the Linux pad STALLs at 736/889 µs — a per-packet cost differing ~28-36×. But the
   cold-pad ladder is **flat at ≤64 B**, which is direct evidence *against* "the pad consumes its
   `wLength`" as a general property. The 21-37 ms figure therefore has no confirmed mechanism: the
   post-abort state is the remaining candidate, and the documents that call it a watchdog or a false
   pass are neither confirmed nor refuted. (For the record, the phrase "every SETUP pass is a false
   pass" is HANDOFF §6.7's heading, `HANDOFF.md:339`; addendum §10.3's own words are "SETUP would
   'pass' with no corruption".) **Unstated consequence worth saying:** if the pad really did consume
   its data stage on Windows, then the Windows runs' failure to pwn needs an explanation *other*
   than the false-pass story this project has been telling — that has not been given.
   **Next run — pad-after-abort, now built and round-3 reviewed (`ep0cut --mode abort-pad`,
   29 tests).** Per length: the pad **cold ×3** (median, n and spread printed; the spread widens that
   point's tolerance), **a reset between the arms** so the treatment arm does not inherit the cold
   arm's history, then the aborted 2048-byte DNLOAD, then the pad at `L` with **no reset between
   those two** (that adjacency is the exploit's). The decisive length 1280 is **first**; any wedged
   **pad** row resets (the abort row is *expected* to end `CANCELLED` — that is the cut, not a
   wedge); `--abort-us` moves the abort window. **What it can and cannot show (T3-R A2, accepted):**
   its observable is a status/`sz`/latency *equality*, so **`CHANGED` proves state-dependence, not
   consumption** — the abort's cancel also leaves an EP0-recovery cost that a post-abort pad can
   absorb. Only a **rising after-arm slope at the served-transfer per-packet cost** supports
   consumption; flat supports refusal. A point whose cold arm wedged or whose cold repeats disagreed
   on status is **NO BASELINE — unclassifiable, never a silent "same"** (T3-R R2/R5), and a run with
   no classifiable point says so and exits 1 rather than printing a confident negative (T3-R R1,
   which was a BLOCKER: an empty ladder used to print "does NOT change" with `incomplete:false`).
   **Scope (T3-R A3, accepted):** the run is on a **pwned** device and therefore measures the pwned
   EP0 path — attribute to the SecureROM only with a stock (power-cycled) control. **And it is the
   ISOLATED sequence (T3-R A4, accepted):** the real attempt-3 pad followed two completed DNLOADs and
   two drains, so a flat result reads as "the isolated abort→pad did not reproduce 736/889 µs", not
   as a refutation.
   **THE STOCK COLD ROW RAN, and it lands in the rule's third branch — but it establishes more
   than "non-monotone".** MEASURED by the Lead (verified here from
   `a9pwn-traces/linux/stock-pad-1280.table.txt` / wire `stock-pad-1280.txt`, sha256 `4bd8814b…`):
   a freshly **power-cycled STOCK SecureROM** (`PWND` absent, devnum 57), **no abort anywhere**,
   `--shape pad,getdesc --lengths 0,64,1280 --repeats 3`:

   | shape | wLength | status | sz | median (min/max) |
   |---|---|---|---|---|
   | pad | 0 | STALL | 0 | 158 µs (154/169) |
   | pad | 64 | STALL | 0 | 174 µs (172/177) |
   | **pad** | **1280** | **TIMED_OUT** | **64** | **250,113 µs (250,084/250,151)** |
   | getdesc | 0 / 64 / 1280 | COMPLETED | 0 / 64 / 198 | 68 / 73 / 154 µs |

   Wire, all three pad-1280 rows: `C … -2 / 64` — the device **ACKed exactly one 64-byte packet and
   then NAKed**, until libusb's own 250 ms deadline ended the URB. (So the "250,113 µs" is the
   *host's* deadline, never a device latency: see the tool defect below.)

   **What it establishes.**
   1. **The pad's STALL is not intrinsic to the request.** On a cold stock ROM the exploit's exact
      bytes (`00 00 0000 0000 0500`) do **not** STALL: one packet is accepted and then the endpoint
      goes silent.
   2. In **both** winning runs the identical bytes STALLed in **736 µs (ours) / 889 µs
      (reference)** immediately after an aborted 2048-byte DNLOAD (`our-run1.txt:59-60`,
      `e4-gaster-1.txt:57-58`). The request bytes are the same; the preceding state is not.
   3. ⇒ **SETUP's pass condition is a CREATED response.** The preceding state — the aborted DNLOAD
      at minimum, and in the reference attempt also two completed 2048-byte DNLOADs and two drains —
      is load-bearing for the STALL. This is the strongest mechanistic statement this project has
      about SETUP, and it explains the asymmetry the earlier rounds kept circling: a *cold* pad is
      harmless (it wedges the endpoint after one packet), while the *exploit's* pad is the primitive.
   4. **"The pad intrinsically consumes its `wLength`" is refuted** — the cold pad consumes one
      packet. And the post-abort figure is **latency-consistent with the pad's full transfer**: the
      request carries `wLength = 1280` = **20 packets maximum**, and the measured baselines and
      per-packet costs give **156 + 20 × 29.0 = 736 µs** (ours) and **158 + 20 × 36.6 ≈ 890 µs**
      (gaster's) — the full 20 packets at the same rate as the 2048-B DNLOAD
      (935-992/32 = 29.2-31.0 µs/packet). Cold, the same request carries **one** packet and stops.
      **This is a LATENCY inference, not a wire byte count** (T3-R round 5 F1, accepted — and the
      earlier revision's "~25-30 packets ≈ 1.6-1.9 KB" was arithmetically impossible, since a
      1280-byte control transfer cannot carry more than 20 packets): the post-abort STALL's wire
      `actual_length` is **0** (`our-run1.txt:162`, `e4-gaster-1.txt:158`), and §8 item 2 keeps open
      whether a STALL zeroes that field. The cold row's `-2 / 64` *is* wire evidence — of one
      packet, not of a drain.
      **And the conservative explanation must be named beside the favourable one:** the aborted
      DNLOAD leaves the DFU machine in its cut-download state (`bState = 5`), and a malformed request
      in *that* state may be refused **with zero bytes consumed** — fully consistent with the wire's
      `-32 / 0` and requiring no corruption at all. Deciding between "the abort turns the pad into a
      full 20-packet transfer that then STALLs" and "the abort changes only the refusal path" needs a
      per-packet instrument — the same one PATCH's 48 bytes need.
   5. One competing explanation of the Windows 21-37 ms completions is now dead ("the pad is
      intrinsically length-proportional"). **Two** survivors remain, and this row does not separate
      them: the abort-created full-length drain (above), and the abort-changed *refusal* path with
      zero consumption. Both are consistent with the Windows timings at the Windows per-packet rate
      and with a post-abort pad; only a Windows host plus a per-packet instrument can decide
      (`LINUX-HANDOFF` §6 E4), §8 item 5.

   **Caveats, stated so the claim is not over-read.** n=3 at one length on one boot of one device;
   the cold and post-abort numbers come from different sessions; the winning-run pad followed
   *more* than the abort (two completed DNLOADs + two drains), so "the abort specifically" is still
   not isolated — that is exactly what `--mode abort-pad` tests; the one-packet outcome proves the
   device ACKed one packet, not where those bytes went; and this row says nothing about Windows.
   **New sub-question it opens:** *why* does the ROM accept one packet of an invalid request and
   then wedge, rather than STALLing? That is a ROM-internal behaviour (the endpoint stops answering
   while the device stays enumerated, recoverable only by a port reset) and no source we own
   explains it.
6. **The genuine pad STALL on Linux is sub-millisecond: 745 µs (trace) / 736 µs (wire) in ours and
   889 µs in gaster's.** Both inside gaster's 5 ms and inside our default 5 ms pad timeout. No
   timing workaround is needed on this host. Note the tension with item 4: those sub-millisecond
   STALLs are *post-abort* pads, which is exactly the state the cold ladder did not test.

---

## 8. What I could NOT determine

1. **Whether the 48 bytes of PATCH's data stage were physically consumed.** Both runs show the same
   `-32 / 0`, and the same signature appears on the pad, which gaster's own pass condition requires
   to have been consumed for the standard mechanism to hold. **The task-9 cold ladder sharpens this
   rather than settling it:** a *cold* malformed `bm=0,b=0` request at 0-64 bytes is refused flatly
   with **0 bytes reported by both instruments**, and PATCH's 48-byte `bm=2,b=3` request sits in
   exactly that length band and reported `-32 / 0` in 164-167 µs. So the cold evidence favours "not
   consumed" for the 48 bytes, while the *mechanism* argument (the 48 bytes are the only carrier of
   `callback = insecure_memory_base`) favours "consumed". In the exploit both requests follow prior
   state (the aborted DNLOAD), so the real analogue is **PATCH-after-SETUP-and-SPRAY**, not a cold
   PATCH. Needs a per-packet handshake (analyser) or that run.
2. **Whether usbmon's `length` is 0 for a STALLed control-OUT because the HCD zeroes
   `actual_length` or because nothing moved.** Revision 5 adds a positive control: the task-9
   `pad` 128 row terminated by *timeout* (not STALL) and both instruments agreed on 64 bytes
   (`e3-sweep.txt:9-10` `-2 / 64`; libusb `sz = 64`). So the field is populated on OUT timeouts.
   Every STALL termination in every capture still shows 0, with the wire agreeing — whether that is
   "nothing moved" or "zeroed on STALL" is not settled by any file I have.
3. **Whether a *cold* pad's handling depends on its `wLength` — partly answered.** MEASURED:
   the *latency* is flat at ≤64 B (171-187 µs) and the 128 B row consumes one reported packet
   before going silent (§7 item 4), so "deliberation" is latency-supported. But the byte-level
   claim ("no data consumed") is **not** assertable — §8 item 2's ambiguity stands — and the rows
   are from a **pwned** device, so they describe the pwned EP0 path, not the ROM. What is still
   open is the *post-abort* pad (item 6) and the stock-device cold 1280 B pad (item 7).
4. ~~**Whether Linux loses partial counts on cancelled control transfers.**~~ **RESOLVED in revisions
   4-5 — it does not, on the async path, in both directions.** `ep0cut` cutting `GET_DESCRIPTOR(3,4)`
   at µs deadlines reported graded 64/0/64/128/192/198 on cancelled IN rows
   (`e1-ep0cut-ladder.txt:4-19`), the corrected build passes both controls on hardware
   (`e1-ep0cut-corrected.txt.stdout.txt:23-26`), and the task-9 sweep's OUT `pad` row at 128 B
   reported `sz = 64` with the wire agreeing (`e3-sweep.txt:9-10`). What remains open is narrower:
   the **synchronous** path discards the count on a timeout — partly the sync API's single-`int`
   return (`sync.c:144-153`), partly our transport mapping any `rc < 0` to `transferred = 0` (our
   `TIMEOUT 0` vs the wire's `-2 / 528`) — and that is the Lead's to track. The old printed
   `=> NO PARTIAL ON A CUT TRANSFER` (now in the `Cancelled` arm of `probe-partial-count`) should
   still not be quoted as a measurement.
5. **Whether the Windows 21-37 ms pad completions were a device watchdog** — now **narrowed**. The
   stock cold row (§7 item 5) kills the "intrinsically length-proportional" explanation and leaves
   the abort-created drain as the survivor, but a Windows host is still required to test it.
6. **Whether the 736/889 µs post-abort pad STALL is data consumption or a property of the preceding
   aborted DNLOAD.** Three readings, all consistent with the captures: (i) the abort turns the pad
   into a full 20-packet transfer that then STALLs (latency-consistent, §7 item 5 point 4);
   (ii) the abort changes only the *refusal* path, with zero bytes consumed — the aborted DNLOAD
   leaves `bState = 5` (cut download), where a malformed request can be refused in ~0.75-0.9 ms
   without touching the data; (iii) the abort is not the load-bearing element at all — the winning
   runs also had two completed 2048-byte DNLOADs and two drains before it. The cold row (§7 item 5)
   shows the *cold* pad does not STALL, so *something* in that preceding state is load-bearing.
   `--mode abort-pad` isolates the abort-only variant; separating (i) from (ii) needs a per-packet
   instrument. **Highest-value remaining measurement.**
7. **Whether a pwned device's `bm=0,b=0` (pad) path is served by the ROM at all** — T3-R round 2's
   residual doubt, now partly retired by the **stock** row (which needs no such assumption): the
   cold-stock and cold-pwned ladders agree qualitatively (one packet then silence at 128 B pwned,
   at 1280 B stock). What remains is whether the *post-abort* pad on a pwned device behaves like the
   post-abort pad on a stock device.
8. **What the ROM does with `SET_FEATURE(bm=2, b=3, wValue=0, wIndex=0x80)` when it carries a data
   stage.** Not determinable from `gaster.c`, our sources, or usbmon; the ROM's code is not in this
   tree. (The request is a standards violation either way: `SET_FEATURE` with recipient ENDPOINT has
   no data stage, and `wIndex=0x80` targets EP0-IN, which cannot be halted.)
9. **Whether the post-PATCH bus reset is strictly required** for the marker. Both captures contain
   it and no control run without it, so they cannot separate "the overwritten callback fired on the
   reset" from "the payload made the device re-enumerate". gaster's source says the reset is the
   trigger (`gaster.c:1268`) and the payload writes the marker (`gaster.c:1110`), but the captures
   alone do not prove causality for the reset.
10. **Which two rows "the two documented DEVIATIONs" means** — three candidate deviations exist
    (§6); all three are recorded rather than guessed.

---

## 9. Corrections applied in revisions 2 and 3 (for the reviewer)

Adversarial review of revision 1 found, and this revision fixes:

1. Δt for the RESET-stage suffix DNLOAD was 143 µs; it is **142 µs** (`e4-gaster-1.txt:7-8`).
2. The `=> NO PARTIAL` print was cited as `main.rs:481-486`; it is **`main.rs:502-505`**.
3. "600 × 5 = 3000 ms is a 10× overstatement of 285-292 ms" was invalid (that measurement is for 19
   attempts) — replaced with "the model is a pause-only lower bound; report the measured elapsed
   time" (§5 E5-4).
4. "Index-4 latency 150-160 µs" was a selection; the seven reads span **112-190 µs**.
5. E5-3 proposed `pub(crate)`; `main.rs` is a separate crate, so it must be **`pub`**.
6. E5-1 omitted the `ResetReport` literals that would fail to compile (`usb.rs:1966`, `:4025`);
   `unverified` at `:4043` is a functional update and inherits the field.
7. `HANDOFF §4.3/§4.5/§4.6` → **`LINUX-HANDOFF`** (HANDOFF §4 has no subsections); the heading and
   the two prose citations of `§4.7`/`§4.3` are fixed as well.
8. "Windows-only calibration" attributed to `Ep0RateLine` was not in the source; reworded, and
   dated to the earlier session via LINUX-HANDOFF §4.1.
9. (Old §7 numbering.) §7.4's "890 µs predicted vs 889 µs measured" was circular (36.6 µs was
   derived from the same two numbers); replaced with the exact Windows residuals — **corrected a
   second time** to the right signs (`measured − predicted`) with "five within 2.1 ms", after a
   re-review found four signs flipped and the ±2.00 ms count off by one. Revision 5 then withdrew
   the inference the item supported (§7 items 4-5).
10. "n=1 Linux pad STALL" ignored our own run; there are **two** (736/745 µs and 889 µs), and the
    ninth Windows point recorded at `usb.rs:846` (23.02 ms) is now noted.
11. The "+9 µs ⇒ not consumed" claim was stated at three different strengths; now one statement,
    with both runs' values, both readings, and an explicit note that a single-packet delta and a
    20-packet average are not comparable.
12. The 0-length latency point is a `bm=2,b=3` SET_FEATURE, not the pad; the cross-shape use is now
    called out where it is used.
13. "Nothing could have been consumed in 117 µs" softened to "no complete packet-plus-turnaround".
14. The +30 bytes' **content** is now labelled INFERRED (usbmon prints 32 data bytes); the length
    change stays MEASURED, and `gaster.c:1110` is cited for the string.
15. E5-5's "sole source of `RESET_CAPABILITY_UNKNOWN`" was wrong on Linux: our own run produced the
    same verdict from a *successful* open with an unmeasured driver; added, with the measured
    stdout evidence.
16. `§6.4` references → `§7.4`. (The revision-1 wording about a `usbmuxd/udev` attribution was
    removed rather than carried over; no such attribution remains in the body.)
17. `usb.rs` citations re-pinned at `c46ce084…`/5724 lines, with the quoted-code method recorded;
    the stale `ffceef2e` cross-reference was removed.
18. Added `our-run1` throughout as the second, independent run (it also resolves the "one point"
    and "n=1" weaknesses above).
19. Second review pass (revision 3) additionally fixed: the residual signs and the "±2 ms" count
    (item 9); `serial_len=113` → `our-run1.txt.stdout.txt:36` and `driver_class=unknown` → `:30`
    (the values were right, the line numbers were off by one); the 236562 µs figure attached to
    `:1` alone with `:6`'s 235440 µs beside it; the `trace.rs` manifest claim dropped (the file has
    been edited); quoted ranges corrected to `stages.rs:1691-1707` and `usb.rs:1485-1490`; and
    "cannot cut mid-transfer" softened to "cannot reliably cut".
20. Revision 4: open question #4 answered and closed (§4.4, §8.4) — `ep0cut`'s µs-deadline ladder cut
    `GET_DESCRIPTOR(3,4)` and the cancelled rows reported graded 64/0/64/128/192/198; the async path
    on Linux carries real partials, so branch A holds. The narrower sync-path defect (a timeout
    reports 0 while the wire moved 528 bytes) is kept open and attributed.
21. Revision 4: `tools/arlo/ep0cut` now builds again (the in-flight `Option<u8>` refactor did not
    compile), has `--mode sweep` (the wLength × latency ladder, no cancels, `--dry-run`, both
    malformed shapes plus the `GET_DESCRIPTOR` control), **29 unit tests** (18 at revision 4, 19 at
    revision 5; the abort-pad and round-3 regression tests brought it to 24), and a RUNBOOK. Its `cut`
    mode's control 1 was also wrong in the archived runs: it demanded `CANCELLED / sz = 0` on the
    first row, and the run where that row returned `CANCELLED / 64` was printed `INVALID LADDER` —
    the check rejected the measurement it existed to collect.

### Revision 5 — the T3-R durable review, and two new datasets

T3-R (owner `stages-reviewer`, task-4) reviewed revisions 3-4 and returned 1 BLOCKER, 4 MATERIAL and
13 NIT findings. Every one was reproduced against the files before being applied; none is disputed.
In addition the Lead supplied two hardware datasets and one correction. Items:

22. **Marker index — Correction (Lead).** Revisions 1-4 asserted the marker "is at index 6
    where the pre-pwn device served index 4". That is a snapshot, not a property: the declared
    `iSerialNumber` moves. All occurrences corrected (§2 table, §3.3); the rule recorded is "read the
    index the device descriptor declares", with a non-marker string at that index as the negative
    control. The PATCH-causality evidence is restated as "no marker-bearing read before PATCH" and
    survives. **Read item 32 with this one: only the index-4 → 228 B half is archived; the
    "index 6 → 0 B" half is Lead-reported and not in any capture.**
23. **T3-R F1 BLOCKER — E5-1's compile note was incomplete.** There are **three** exhaustive
    `ResetReport` literals, not two: `usb.rs` production and test, plus **`stages.rs:3423`** in its
    own `reset_report` helper. T3-R applied the first draft's edit on a scratch copy and got
    `E0063` at `stages.rs:3423` — `cargo test`, i.e. the gate, would have failed. §5 E5-1 now lists
    all three and says to grep for the struct rather than trust line numbers. (The Lead has warned
    the task-10 owner.)
24. **T3-R F2 — the two archived `ep0cut` runs failed *different* controls**, and neither passed
    both: `e1-ep0cut.txt` C1 OK / C2 failed (255-vs-198); `e1-ep0cut-ladder.txt` C1 failed (the row
    contained the answer) / C2 OK. §4.4's note now says exactly that, and records that the corrected
    `cut_controls` **has since passed both controls on hardware**
    (`e1-ep0cut-corrected.txt.stdout.txt:23-26`, `VERDICT PARTIALS SURVIVE CANCELLATION … sz=64`).
25. **T3-R F3 — direction.** The E1 ladder cuts an IN transfer; the exploit aborts an OUT DNLOAD.
    §4.4 now separates the two and records the upgrade: the task-9 `pad` 128 row is an **OUT** cut
    that reported `sz = 64` with the wire agreeing (`e3-sweep.txt:9-10`), so partial reporting is
    **measured in both directions**; the exploit's own aborted DNLOAD has still only ever reported a
    wire-corroborated 0.
26. **T3-R F4 — E5-3 and E5-5 are SUPERSEDED: implemented by the Lead** at `main.rs`
    `f57ce965…`/812 (bounded 2 s re-open loop, `capability_measured_while_present` retention,
    wall-clock reporting). Both sections carry a status banner with the new sites; the original
    proposals are kept as history and as a guard for any future single-shot read.
27. **T3-R F5 / F6 / F9 / F10 / F11 / F12 / F13 / F14 / F17 / F18 — citation and disclosure fixes.**
    `serial_len=113` is `stdout:36`; §2's ours-range is `:165-177` and ours has **four** `a1 03`
    reads in the PATCH tail (the fourth is our post-PATCH reset's 100 ms pre-read, which gaster does
    not issue — a real wire deviation, noted in §2); the `stdout:4` quote is marked non-contiguous;
    `abort_min` is `stages.rs:297`; V05/V08 are named at `VERIFICATION-live-run.md:108`; `req_out`
    calls `control_out` directly, not `req_ctrl`; the Windows/Linux per-packet gap is "~28-36×"; the
    "every SETUP pass is a false pass" phrase is HANDOFF §6.7's heading (`HANDOFF.md:339`), not the
    addendum's words; the pad row's cross-shape baseline subtraction is disclosed with consistent
    re-computations; and the sync-path defect is described as partly a libusb-API limitation
    (`sync.c:144-153`) and partly our transport's `rc < 0 ⇒ transferred = 0` mapping.
28. **T3-R F7 — `usb.rs` and `main.rs` re-pinned and re-warned.** §0 now warns about both files,
    records their movement, and says to re-resolve by symbol; §5's header repeats it.
29. **T3-R F15 — the refuted claim is now named:** `LINUX-HANDOFF.md:228-231` §6 E3(b)'s
    "transferred length = 48 ⇒ accepted; 0 ⇒ PATCH is a no-op" cannot be read off that field (§3.2).
30. **T3-R F8 — the unit-test count.** 18 → 19 (JSON test, revision 4) → 23 (four abort-pad
tests) → **24** (the round-3 no-points/aggregate regressions). T3-R rounds 2-3 kept finding stale
counts; the RUNBOOK and §7 item 5 now read 24.
31. **task-9 dataset — the KNEE (§7 items 4-6).** MEASURED: cold `pad` is flat at ≤64 B
    (`-32 / 0`, 171-187 µs on the wire) and at 128 B one 64-byte packet is reported consumed and
    the request then NAKs until libusb's 250 ms deadline (`-2 / 64`). The two bounding caveats are
    recorded — the pad is **cold** (the exploit's pad follows an aborted DNLOAD) and the device is
    **pwned** (so a `dnload` row measures gaster's payload, not the ROM). The Windows-watchdog
    inversion of revision 4 is therefore **withdrawn as unproven in both directions**, and the next
    experiment is specified: **pad-after-abort**, which needs a new `ep0cut` sequence mode.

### Revision 5, round 2 — T3-R's second pass (on rev 5) and its accepted fixes

T3-R round 2 answered both of my questions and returned 7 further findings (4 MATERIAL, 3 NIT), all
accepted and applied. Items:

32. **T3-R F19 — one half of the index correction is unarchived.** The index-4 → 228 B read is
    archived (`e3-sweep.txt:26`, `:30`; `e1-ep0cut-corrected.txt.stdout.txt:18-21`); the
    "index 6 → 0 B" half is **not in any capture** — T3-R grepped the whole trace tree and every
    `06 0306` on disk returned 228. §3.3 now labels the halves separately (MEASURED vs
    Lead-reported). **Cross-document contradiction:** `RUNG1-EVIDENCE.md:212-216` still asserts the
    invalidated property verbatim ("the marker is served at index 6 … while index 4 still returns
    the PRE-PWN 198-byte string"); it is the Lead's file, so the report flags it and asks for it to
    be marked superseded or archived.
33. **T3-R F20 — §7 item 4 grounded in latency, not in `sz`.** "No data consumed at ≤64 B" is
    withdrawn; the flat *latency* is the evidence, and §8 item 2's "0-on-a-STALL is ambiguous"
    stands.
34. **T3-R F21 — attribution scoped.** §7 item 4 and §8 item 3 now say the rows describe the
    **pwned EP0 path**, not the SecureROM, and that the 736/889 µs STALL being explained happened
    pre-pwn.
35. **T3-R F22 — N=1 and the tool's own verdict quoted.** All five points are N=1; the archived
    output says `SWEEP STOPPED … NOT a valid slope` (`e3-sweep.table.txt:18-20`) and
    `"verdict":"INCOMPLETE: ladder stopped after a wedged row"` (`e3-sweep.json`). "Knee" is now
    labelled a description of one sample per point, not a fitted feature.
36. **T3-R F23 / F24 / F25 — citations, pin, test count.** The `-2 / 64` row is
    `e3-sweep.txt:9-10`, not `:11-12` (three places); the post-sweep index read is `:26`, not
    `:30-33`; §0's `usb.rs` hash is `6b2bda4e…` (same 5996 lines, different content) with a note
    that the hash moves while the length does not; the unit-test count is **23** everywhere
    (§9 item 30, RUNBOOK).
37. **T3-R Q1/Q2 — all eight items implemented in `tools/arlo/ep0cut` before its first hardware
    run.** A1: the cold arm is now **first** in each point (it was last, i.e. measured after both
    interventions it is the baseline for). A2: the verdict fits the **after-arm slope** and states
    that `CHANGED` proves state-dependence, not consumption (wedge-recovery confound). A3: the
    scope line is in the tool's own header and the RUNBOOK. A4: it is described as the **isolated**
    abort→pad, with the missing attempt-3 history named as a live alternative. B1: the noise-floor
    justification now cites the archived 171-187 µs cross-row range, not an N=1 "spread of 0".
    B2: the cold arm is repeated (default 3) so the verdict's own falsification is satisfiable.
    B3: default lengths are **1280 first**, any wedged row (cold included) resets, and
    `--continue-after-timeout` is in the runbook recipe. B4: "wedges even cold" is its own outcome,
    no longer reported as a state effect. 23 tests; `--dry-run` reviewed. **Round 3 then falsified
    these fixes themselves — items 39-46 below — so this item describes the intermediate state, not
    the shipping one.**
38. **The remaining decisive number (T3-R, and accepted):** a **cold 1280 B pad on a stock
    (power-cycled) device** — never measured, and the one value that would settle §7 item 5 without
    any abort at all. It is the Lead's call, and it is now recorded as open question §8 item 7.

### Revision 5, round 3 — T3-R falsified the abort-pad fixes, and it found a BLOCKER

T3-R round 3 reviewed the *fixes* rather than the prose, and returned 1 BLOCKER, 5 MATERIAL and 3
NIT findings on `tools/arlo/ep0cut`'s `abort-pad`. All accepted and fixed **before the mode's first
hardware run**; the tool is now at 29 tests. Items:

39. **T3-R R1 BLOCKER — an empty ladder printed a confident negative.** `abort_pad_verdict` had no
    guard for `points.is_empty()`, and two documented paths reach it (a cold wedge at the first
    length without `--continue-after-timeout`; an unreaped abort), so a run that measured nothing
    printed "the preceding aborted DNLOAD does NOT change the pad's handling" with
    `incomplete:false` and exit 0. Fixed: an empty ladder says **NO POINTS MEASURED — this is NOT a
    negative finding**, every early stop now sets `early_stop` and reaches the JSON's `incomplete`
    flag, and the process exits 1. A no-points test was added — its absence is why the suite passed.
40. **T3-R R2 — a cold wedge inserted a reset between the arms but still classified the point.** A
    length whose cold arm wedged was compared against a post-abort arm taken after a reset, and the
    difference was reported as `CHANGED`. Fixed with a `NoBaseline` outcome (cold wedged or cold
    repeats mixed) that is excluded from the CHANGED list and cannot produce a negative verdict.
41. **T3-R R3 — the cold repeats changed the treatment arm's history.** Three pads immediately before
    a heap-corruption step can change what the abort acts on. Fixed: a reset between the arms, and
    the banner no longer calls the sequence "the exploit's own order" — only the abort→pad adjacency
    is claimed.
42. **T3-R R4 — the drift estimate was collected and never used.** `cold_n`/`cold_spread_us` were
    written and read nowhere, while five places (RUNBOOK, dry-run, the verdict's own FALSIFIED IF,
    §7 item 5, §9 item 37) claimed the spread was printed. Fixed: the per-point line prints
    `n`/`spread`, and the tolerance is `max(STATE_EFFECT_FLOOR_US, that point's spread)`.
43. **T3-R R5 — the synthetic cold sample depended on repeat order.** It paired the median latency
    with the *first* repeat's status/`sz`, so reversing two rows could flip `Same` to a wedge.
    Fixed with a pure, tested `aggregate_cold` (median latency, majority status, explicit `mixed`
    flag) — order-independent by construction.
44. **T3-R R6 / R7 / R8 — wording and cross-reference fixes.** The run header no longer says the mode
    ignores `--repeats` (it uses them for the cold arm); the RUNBOOK's reset rule now says "any
    wedged **pad** row" and explains that the abort row is *expected* to end `CANCELLED`; and item 22
    points at item 32 so the index correction cannot be read half-way.
45. **What round 3 confirms about the process.** The BLOCKER was in code written **after** the
    previous review and **before** hardware — exactly the window where a false negative would have
    looked like a result. Two of the three rounds have now found problems in the *fixes*, not the
    originals; the report's §8 rule ("a check earns trust by having been shown to fail") applies to
    the instrument as much as to the measurement.
46. **The open measurement is unchanged and still the Lead's:** the stock cold 1280 B pad (§8
    item 7), with T3-R's pre-registered decision rule recorded in §7 item 5.

### Revision 6 — the stock cold pad row, and the tool defects it exposed

47. **The stock cold row ran and is analysed in §7 item 5.** MEASURED (Lead; verified here from
    `stock-pad-1280.table.txt` / `stock-pad-1280.txt`, sha256 `4bd8814b…`): on a power-cycled STOCK
    SecureROM with **no abort**, the exploit's own pad bytes are **ACKed for exactly one 64-byte
    packet and then the endpoint goes silent** (`-2 / 64`, ended only by libusb's 250 ms deadline),
    where both winning runs STALL the identical bytes in 736/889 µs after an aborted 2048-byte
    DNLOAD. **SETUP's STALL is therefore a created response** — the strongest mechanistic statement
    this project has about SETUP — and "the pad intrinsically consumes its `wLength`" is refuted.
    Caveats (n=3, one length, one boot; cross-session comparison; the abort is not yet isolated from
    the two completed DNLOADs and drains; nothing about Windows) are recorded with the claim.
48. **Tool defect found by that run — a slope fitted through a host deadline.** `--mode sweep`'s
    auto-verdict printed `DATA CONSUMPTION (a) SUPPORTED` with **12792.6 µs/packet** because the
    fitted points included a `TIMED_OUT` row whose "latency" is libusb's 250 ms deadline. Fixed:
    `is_silent_status`/`answered`/`wedged` predicates; slope fitting and the noise floor use
    **answered rows only** and the excluded lengths are printed; `Claim::Wedge` was added to the
    verdict vocabulary so the tool agrees with the pre-registered rule; a per-packet number is
    refused when either endpoint row is unanswered; and a consumption claim below a wedge now needs
    an answered **span of ≥2 packets**. A regression test encodes the real run
    (`the_measured_stock_row_is_a_wedge_not_consumption`) and asserts the old 12792.6 figure cannot
    reappear.
49. **C2's wording was wrong, not its logic — and I disagree with the reported diagnosis.** The Lead
    read `C2 WEAK` as "the control is structurally unable to pass because `getdesc` returns
    `min(wLength, 198)`". It *can* pass: any two asked lengths above the descriptor size return the
    same 198 bytes, so the default ladder (256/512/1024/1280/2048) gives five C2 points. The run's
    ladder was `0,64,1280`, which yields exactly one — hence WEAK. Fixed as a **message** problem:
    C2 now prints `NOT EVALUABLE with this ladder`, explains the `min(wLength, N)` behaviour, says
    it is expected for a short ladder rather than a failure, and tells the operator to add lengths
    above the descriptor size.
50. **T3-R round 4 (R9-R16), all accepted.** `aggregate_cold` now treats **`sz` disagreement** as a
    mixed condition (status agreement is not enough when the byte count is what the classifier
    compares) and uses the same median convention for `sz` as for latency (R9/R15); the baseline is
    now genuinely cold for **every** point — a reset at the **start** of each point, since without it
    point *k+1*'s cold arm followed point *k*'s abort+pad and biased the classifier toward a false
    `Same` (R10); a completed ladder that yields **no classifiable point** now exits 1 as well, and
    the report says `incomplete` means "ladder stopped", not "a result exists" (R11); the cold-wedge
    path no longer takes two resets back to back (R12); the tolerance text and header are accurate
    (R13); a mixed baseline displays **MIXED** rather than an arbitrary tied status (R14); and the
    `NO CLASSIFIABLE POINT` branch has the test it lacked (R16). 25 tests.
51. **Structural note worth keeping (T3-R's, accepted).** Three of the four review rounds found
    problems in the *fixes*; round 4's four remaining holes were **all in the I/O sequence**
    (baseline state, reset placement, exit-code path) while the pure functions were clean and
    tested. The suite cannot see that class — which is why the discipline is "an adversarial pass
    over every fix", not "a green suite".

### Revision 6, round 5 — T3-R on the stock analysis and the fixed tool

52. **T3-R F1 MATERIAL — §7 item 5 point 4's arithmetic was impossible, and the correct arithmetic is
    stronger.** A `wLength = 1280` control transfer carries at most **20** packets, so the earlier
    "~25-30 packets ≈ 1.6-1.9 KB" could not be right. Corrected to the capped, baseline-plus-rate
    form: **156 + 20 × 29.0 = 736 µs** and **158 + 20 × 36.6 ≈ 890 µs** — the full 20 packets at the
    DNLOAD's own measured rate. The claim is now labelled a **latency inference, not a wire byte
    count** (the post-abort STALL's wire `actual_length` is 0; §8 item 2 keeps that ambiguity open),
    and the **conservative reading is named beside it**: `bState = 5` after the abort may make the
    ROM refuse the pad in ~0.75-0.9 ms **with zero consumption**, needing no corruption. §8 item 6
    now lists all three readings and what would separate them.
53. **T3-R F2 MATERIAL — a row with disagreeing repeats was invisible to the sweep's claim.** Such a
    row is neither `answered` nor `wedged`, so it was excluded from every fit *without a note* and
    did not trigger the wedge branch — the decisive row could drop out while the shape still got a
    confident claim. Fixed: `UNUSABLE rows` are reported, and a clean consumption/deliberation claim
    is refused while the longest tested row is among them.
54. **T3-R F3/F4 — non-monotone silence, and the decision printed.** Silence is not necessarily
    monotone (a reset between rows lets a longer row answer after a shorter one went silent), so a
    non-monotone pattern now says so and yields `Indeterminate` rather than the wedge claim. The
    wedge branch also prints the **decision**, not just its ingredients: *"consumption below a wedge
    needs ≥ X µs/packet over ≥ 2 answered packets; this ladder: Y µs/packet over Z packet(s) ⇒ …"* —
    this project's own rule about modelled numbers wearing measured names.
55. **T3-R F5 — the redundant end reset.** With a start-of-point reset in place, the after-silent
    reset now fires only when the run is stopping (leaving the device recovered); when the ladder
    continues, the next point's start reset is the same recovery. (27 tests at that point; 29
    after round 6.) The reviewer's
    state-reproduction check (`--mode abort-pad --lengths 64,1280,64 --repeats 3`) is in the RUNBOOK
    as the cheap falsifier for "the reset prefix reproduces state".55. **T3-R F5 — the redundant end reset.** With a start-of-point reset in place, the after-silent
    reset now fires only when the run is stopping (leaving the device recovered); when the ladder
    continues, the next point's start reset is the same recovery. The reviewer's
    state-reproduction check (`--mode abort-pad --lengths 64,1280,64 --repeats 3`) is in the RUNBOOK
    as the cheap falsifier for "the reset prefix reproduces state".

### Revision 6, round 6 — output composition, and the end of the review series

T3-R round 6 verified all five round-5 fixes and returned three composition defects (1 MATERIAL,
2 NIT). All accepted; **29 tests**.

56. **G1 MATERIAL — the printed decision could contradict the claim beside it.** The claim included
    `longest_unusable` but the decision string did not, so a ladder with silence at a shorter length
    plus disagreeing repeats at the longest printed `… => WEDGE` directly above an `INDETERMINATE`
    claim. Fixed by construction: the claim is computed first and the decision string ends with
    `claim.as_str()`, so the two cannot disagree. A regression test uses exactly that ladder shape.
57. **G2 — `>= NaN us/packet`** is now `UNAVAILABLE (no served calibration)`, with a test that
    asserts the string cannot contain `NaN`.
58. **G3 — a literal 14-space run** in the `UNUSABLE rows` note is collapsed.
59. **The review series ends here, and I agree with stopping.** (T3-R then re-verified G1-G3
    independently — the claim-before-string ordering at the source, the `UNAVAILABLE` text, and the
    rendered `\`-continuation — and stood down with no further findings.) Six rounds; every finding accepted;
    the last two rounds' findings are composition-level, not measurement-level. The remaining risk in
    this instrument is not in its pure functions — it is in the two questions only hardware can
    answer: **does the reset prefix reproduce state** (`--mode abort-pad --lengths 64,1280,64
    --repeats 3`), and **what does the post-abort pad actually do on the wire** (a stock `abort-pad`
    run, or a per-packet instrument). T3-R's stated condition for re-opening the reset/arm design is
    recorded: if the state-reproduction check drifts systematically, the design is back in scope.

---

*End of report. Every `gaster.c` and `a9pwn/src/*` citation is resolvable by one grep at the
revision pin in §0; the `usb.rs` citations are additionally quoted so a concurrent edit cannot hide
them.*
