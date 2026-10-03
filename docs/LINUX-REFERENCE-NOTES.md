# LINUX-REFERENCE-NOTES — PATCH's pass condition, SETUP's `sz`, and the E5 log spec

**Task:** `task-3` (analysis only). **Author:** `stages-analyst`.
**Write scope honoured:** this file only. No code was edited; the phone was never opened by this
agent (no `a9pwn run/reset/ident/plan/probe-*`, no libusb, no driver work). Every hardware number
below was produced by the **Lead** and read back from the files cited; labels are `MEASURED`
(from a file/tool), `INSPECTED` (read in source), `INFERRED` (derived).

> **Revision 3** (§9 lists every correction). Revision 1 was adversarially reviewed; the reviewer
> found 6 BLOCKER/MATERIAL errors (a wrong Δt, three wrong line citations, two proposals that would
> not compile, a wrong overstatement, several wrong document section numbers) and, more importantly,
> pointed at a run this report had not seen: **`a9pwn` itself pwned the phone on Linux at 14:28**
> (`a9pwn-traces/linux/our-run1.*`). That run is now the primary evidence and it independently
> confirms every load-bearing claim. A second adversarial pass over revision 2 found no BLOCKER —
> only citation slips and one mis-signed set of residuals — all applied as revision 3.
> Corrections are listed in §9 so the reviewer can check the fixes rather than re-derive them.

## 0. Revision pin — read this before checking any line number

`a9pwn/src/usb.rs` was being edited by other teammates continuously while this report was written
(4040 → 4972 → 4979 → 5724 lines). Every `usb.rs` citation was re-resolved (by **quoted code**,
not by line) at:

| file | sha256 (first 16) | lines |
|---|---|---|
| `research/refs/gaster/gaster.c` | `9aadab9db873b3e2…` | 1667 |
| `a9pwn/src/stages.rs` | `79ef56553a89559f…` | 3823 |
| `a9pwn/src/main.rs` | `5365e2819dceb662…` | 523 |
| `a9pwn/src/payload.rs` | `e3607cb89d1b2a8d…` | 755 |
| `a9pwn/src/usb.rs` | `c46ce084e80a405a…` | 5724 |

`stages.rs` (`79ef5655…`) matches the LINUX-HANDOFF manifest, so its line numbers are stable.
(`trace.rs` has been edited since the manifest — `4918751ad3cd3ae4…` — but no `trace.rs` line is
cited here, so nothing depends on it.) **`usb.rs` is a moving target**: it has been observed at
4040/4972/4979/5724 lines during this session; where a line number is load-bearing the code is
quoted too, so re-resolve by quote if the file has moved again.

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
   unnecessary here and would be a new variable the Linux reference never exercises.**
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
| PATCH suffix / end / walk | `:165-173` | `:162-171` | -2 (5-5.1 ms each) |
| serial descriptor **before** PATCH | `:160` **198 B** | `:156` **198 B** | index 4 |
| serial descriptor **after** PATCH | `:226` **228 B** | `:220` **228 B** | **index 6** |
| device address across the drop | 1:008 → 1:009 → 1:010 | 1:005 → 1:006 → 1:007 | re-enumeration |

**The Lead's decode attributed line 87 to PATCH; it is SPRAY's stall.** Evidence, three ways:
(a) `wLength = 0` is `checkm8_usb_request_stall` exactly (`gaster.c:889-894`), whose only A9 caller
is the spray triple (`gaster.c:901-902`) — the other caller at `:1198` is gated to
`cpid ∈ {0x8001,0x8010,0x8011,0x8015,0x8012}`; (b) in both captures that request is immediately
followed by the leak read (`wIndex=0x0A`, `wValue=0x0304`, 64 B, 1 ms abort), the no-leak read
(193 B, 1 ms) and the trailing CLR_STATUS of `3*EP0_MAX_PACKET_SZ+1 = 193` (`gaster.c:910`) —
the spray triple, in order; (c) the 48-byte request is immediately followed by the 528-byte
payload, the 16-byte suffix, the zero-length end DNLOAD and three `DFU_GET_STATUS` reads — the
fixed PATCH order of `gaster.c:1211-1222`. The decisive disambiguation is our **own labelled
trace**: `our-run1.jsonl` seq 37 `"label": "spray_request_stall" … "w_length": 0` and seq 48
`"label": "patch_overflow_callback" … "w_length": 48`, in that order. `sz = 0` is confirmed
independently by seq 26 (`setup_pad_request`, `w_length: 1280`, `status: STALL`) and by the
printed sweep (`our-run1.txt.stdout.txt:4`: `abort_xfer=0 … pad_req=1280 pad_status=STALL
pad_micros=745`).

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
| pad STALL | 0x500 = 1280 | **736 µs** | **889 µs** | 29 µs (ours) / 36.6 µs (gaster), after subtracting the 156/158 µs baseline |
| SET_FEATURE STALL, no data | 0 | 156 µs | 158 µs | — baseline |
| SET_FEATURE STALL, 48 B | 0x30 = 48 | 164 µs (**+8**) | 167 µs (**+9**) | 8-9 µs |

* The pad's latency **scales with its `wLength`** at the DNLOAD's per-packet order of magnitude in
  both runs — that is what "the pad's 1280-byte data stage is consumed" predicts, and it is the
  reason to doubt the Windows "watchdog" reading (§7.4). INFERRED (two points, different request
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

**What would settle it, cheapest first:**
1. **Latency vs `wLength` on one request shape.** The two runs already bracket it (0 → 156/158 µs,
   1280 → 736/889 µs for the pad; 0 → 156/158 µs, 48 → 164/167 µs for the SET_FEATURE). A flat
   curve ⇒ refusal at the arming stage; a curve growing ~29-37 µs per 64 B ⇒ the data stage is
   consumed. This also settles §7.4.
2. **A per-packet analyser** for one PATCH: `DATA0/ACK` then `IN/STALL` versus `DATA0/STALL`.
3. **The end-to-end oracle, which needs no new instrument:** the PWND marker after the post-PATCH
   reset.

### 3.3 The one observable that proves PATCH fired

MEASURED in both runs: after the PATCH sequence and the post-PATCH reset, the re-enumerated
device's serial descriptor is **228 bytes** where it was **198 bytes** (`our-run1.txt:160` before,
`:226` after; `e4-gaster-1.txt:156` before, `:220` after), and it is served at **index 6** where
the pre-pwn device served index 4. Supporting measurements: the payload's `C length == 528`
proves the payload reached the device (`our-run1.txt:164`), and the 198-byte read after the SPRAY
drop proves the device was **not** pwned before PATCH (`our-run1.txt:160`; in gaster's run the
same sequence is `:144` → `:156` → PATCH → `:220`), which removes the only competing cause.
The **content** of the +30 bytes is INFERRED, not measured: usbmon prints only 32 data bytes, so
the string identity comes from `gaster.c:1110` (`memcpy(A9.pwnd, pwnd_str, strlen(pwnd_str));`,
`pwnd_str = " PWND:[checkm8]"`, `gaster.c:154`, used by the checker at `:811`), and from our own
trace, which reports `PWND marker present: Some("checkm8")` and `serial_len=113`
(`our-run1.txt.stdout.txt:11`, `:29`). 228 = 2 + 2×113 and 198 = 2 + 2×98, i.e. +15 UTF-16 units =
the 15-character marker — the arithmetic closes.

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

and the transport fabricates `transferred = 0` for **every** non-`Ok` return (`usb.rs:1485-1490`,
quoted code — re-resolve if `usb.rs` has moved again):

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
(`stages.rs:1730-1740` → `req_ctrl` → `usb_timeout_ms`) and our completeness test is
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
(`stages.rs:446-451`). With the shipped defaults (`usb_timeout_ms = 5`, `abort_min = 0`,
`stages.rs:81`, `:296`) the sweep walks `4,5,0` and passes on the third attempt — MEASURED in
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

**A 0 alone cannot conclude NO-PARTIAL**, and that is what the existing E1 runs show. MEASURED from
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

**How to make it decisive on this host.** Window granularity is ms and the DNLOAD takes ~0.95 ms,
so gaster's windows cannot land mid-data. Options, cheapest first: (i) run
`a9pwn run --stage setup --setup-budget N` under usbmon with `--usb-timeout-ms 2` (first window
1 ms, transfer ~0.95 ms — a boundary case that will cut mid-transfer occasionally over a long
sweep) and look for any attempt where the `C length` is nonzero while the trace says `xfer=0`;
(ii) note that the 5 ms timeout path is already calibrated to report a partial (`-2 / 528` in both
runs), so the divergence test is well-posed; (iii) accept the reference's own result: both runs
pwned with `sz = 0`, so the question does not gate the exploit. This report recommends (iii) plus
(i) as opportunistic evidence, and explicitly **not** building the sweep.

---

## 5. Q3 — the five E5 log additions, with exact edit sites

Line numbers at the pin in §0 (usb.rs at `c46ce084…`; re-resolve by symbol if it moved). Each is a
*proposal*; no code was changed.

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
  **Compile note (reviewer finding):** `ResetReport` has two exhaustive struct literals —
  `usb.rs:1966` (production) and `:4025` (test) — which would fail `E0063`; the third
  (`usb.rs:4043`, `..delivered.clone()`) is a functional update and inherits the new field. The
  first draft omitted them and would not have compiled.
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

### E5-3 — the final read must retry instead of racing a re-enumeration

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

### E5-5 — a failed open must not overwrite a capability read while the device was present

* **Call site:** `main.rs:421-425`:

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
   `:107`. The reference discards the reset result (`gaster.c:197-200`) and resets unconditionally
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
4. **The Windows 21.4-37 ms "pad watchdog" is probably not a watchdog.** INFERRED, with numbers:
   the Windows rate line puts 1280 bytes at `2.57 + 20 × 1.043 = 23.43 ms`; the eight completions
   recorded in `VERIFICATION-live-run-addendum.md:864-865` (21.4, 22.9, 24.5, 25.3, 27.2, 27.9,
   21.5, 36.6 ms) give residuals `measured − predicted` of −2.03, −0.53, +1.07, +1.87, +3.77,
   +4.47, −1.93, +13.17 ms: **five within 2.1 ms** (four within ±2.00), with the 36.6 ms point at
   +56 %. `usb.rs:846` records a ninth pad point (23.02 ms, residual −0.41) and `usb.rs:848-861`
   warns the pad cluster scatters over 15 ms while the DNLOAD completions scatter over 3 ms — so
   the fit is suggestive, not tight. On Linux the same event is a pad STALL at 736/889 µs for
   1280 bytes — same mechanism, per-packet cost differing ~28×. If that reading is right,
   HANDOFF §6.7 and LINUX-HANDOFF §4.3 and the addendum §10.3 ("every SETUP pass is a false pass") are inverted: the
   pad consumed its data stage on Windows too, and the "hard floor at 21 ms" was the data stage,
   not a device timer. **Falsification test:** pad latency vs `wLength` (flat ⇒ watchdog; linear ⇒
   data consumption). Highest-value cheap experiment this report can name.
5. **The genuine pad STALL on Linux is sub-millisecond: 745 µs (trace) / 736 µs (wire) in ours and
   889 µs in gaster's.** Both inside gaster's 5 ms and inside our default 5 ms pad timeout. No
   timing workaround is needed on this host, and no Linux measurement in either capture shows a
   false STALL in the 21-37 ms band.

---

## 8. What I could NOT determine

1. **Whether the 48 bytes of PATCH's data stage were physically consumed.** Both runs show the same
   `-32 / 0`, and the same signature appears on the pad, which gaster's own pass condition requires
   to have been consumed for the standard mechanism to hold. The +8/+9 µs marginal cost is below
   the pad's per-packet cost but is not zero. Needs a per-packet handshake (analyser) or the
   `wLength`-vs-latency curve (§3.2).
2. **Whether usbmon's `length` is 0 for a STALLed control-OUT because the HCD zeroes
   `actual_length` or because nothing moved.** The only nonzero-length error terminations in the
   captures are timeouts (`-2 / 528`), a different completion path. Not settled by any file I have.
3. **Whether the pad's 736/889 µs is data consumption or device deliberation.** Two lengths, two
   runs, same request shape; the latency scales with `wLength` in both, but there is no third length
   to fit a slope.
4. **Whether Linux loses partial counts on cancelled control transfers.** Cannot be settled with
   ms-granular windows on this device (§4.4). The existing `probe-partial-count` runs do not settle
   it: three of four had a device answering nothing (two 100 ms `IDENT_TIMEOUT_MS` timeouts at open),
   and the fourth's cut (126-148 µs) is inside the device's own 112-190 µs answer-latency spread.
   The printed `=> NO PARTIAL ON A CUT TRANSFER` conclusion (`main.rs:502-505`) should not be quoted
   as a measurement.
5. **Whether the Windows 21-37 ms pad completions were a device watchdog** (§7.4) — needs a
   Windows-host re-measurement or the Linux `wLength`-vs-latency curve.
6. **What the ROM does with `SET_FEATURE(bm=2, b=3, wValue=0, wIndex=0x80)` when it carries a data
   stage.** Not determinable from `gaster.c`, our sources, or usbmon; the ROM's code is not in this
   tree. (The request is a standards violation either way: `SET_FEATURE` with recipient ENDPOINT has
   no data stage, and `wIndex=0x80` targets EP0-IN, which cannot be halted.)
7. **Whether the post-PATCH bus reset is strictly required** for the marker. Both captures contain
   it and no control run without it, so they cannot separate "the overwritten callback fired on the
   reset" from "the payload made the device re-enumerate". gaster's source says the reset is the
   trigger (`gaster.c:1268`) and the payload writes the marker (`gaster.c:1110`), but the captures
   alone do not prove causality for the reset.
8. **Which two rows "the two documented DEVIATIONs" means** — three candidate deviations exist
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
9. §7.4's "890 µs predicted vs 889 µs measured" was circular (36.6 µs was derived from the same two
   numbers); replaced with the exact Windows residuals — **corrected a second time** to the right
   signs (`measured − predicted`) with "five within 2.1 ms", after a re-review found four signs
   flipped and the ±2.00 ms count off by one.
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

---

*End of report. Every `gaster.c` and `a9pwn/src/*` citation is resolvable by one grep at the
revision pin in §0; the `usb.rs` citations are additionally quoted so a concurrent edit cannot hide
them.*
