# VERIFICATION — a9pwn vs the gaster reference, for the FIRST LIVE RUN

**Task:** `task-2` (HANDOFF §7 item 3 / task-10). **Author:** `gaster-analyst`.
**Written:** immediately before the first checkm8 attempt against the attached iPhone SE 1st gen
(A9 s8003, CPID 0x8003, BDID 0x02, n69ap, stock SecureROM DFU, `USB\VID_05AC&PID_1227`, driver
`libusbK`).

**Deliverable status:** COMPLETE for the ten required claims. An ADDENDUM is owed — see §8.

**This audit touched no hardware.** Nothing here was produced by running `a9pwn`. The two rows
marked MEASURED are the Lead's own measurements, quoted with attribution.

---

## 0. Scope, method, and what "evidence" means here

* **Primary reference:** `research/refs/gaster/gaster.c` (1667 lines, Apache-2.0). Every reference
  cell in §1 cites it.
* **Secondary sources, judged not trusted:** `a9pwn/docs/GASTER-SPEC.md` and
  `research/A9-CHECKM8-PAYLOAD.md`. See §7.
* **Prior art consulted only where it is the primary witness for its own claim:**
  `research/refs/ipwndfu/checkm8.py` (see §6, which is where this changed an answer).
* **m1n1's source was not read** (HANDOFF §0.5, §9.9 — maintainer policy forbids AI/LLM use).
* **Labels** (HANDOFF §9.5): **MEASURED** = a value read off the device or produced by running the
  tool; **INSPECTED** = read in source; **INFERRED** = a conclusion drawn from INSPECTED evidence.
  Almost every row below is INSPECTED. An uncited row would not be evidence and is not present.

### 0.1 Frozen hashes — all seven verified as read

Read with `Get-FileHash -Algorithm SHA256`. **Every prefix matches the task's frozen list**, so the
verification below describes a fixed revision and not a moving target.

| File | SHA-256 as read | Matches frozen prefix |
|---|---|---|
| `src/stages.rs` | `A64476ECBD992A11DE34A8B99D0B2DEE2F6825EDD406E27F6EB5C39F09BFD0C3` | ✅ `A64476ECBD992A11…` |
| `src/payload.rs` | `E3607CB89D1B2A8D4D9E6D0D29872A89A1341D1CD14B2E793A66172E0FCF67B5` | ✅ `E3607CB89D1B2A8D…` |
| `src/config.rs` | `514CF83FA535294BA1FD18604A725316832681220A0BBFE7783AA880788CCA35` | ✅ `514CF83FA535294B…` |
| `src/usb.rs` | `9C9B290895E48527BF8BF3AE3FB15AFB198E7F8E95828F8D5888D69A869666A3` | ✅ `9C9B290895E48527…` |
| `src/types.rs` | `B316AB36D4F56D2E8500C1112C717FBB098020F58E4AC0BDA63518691BD4807D` | ✅ `B316AB36D4F56D2E…` |
| `src/trace.rs` | `C2420E80E1CFFCD3B45E4CA2610D7A7DBC2FA1140A457C1B74E61AD58A59E308` | ✅ `C2420E80E1CFFCD3…` |
| `src/verdict.rs` | `9300E7089F38DA1D924495FB63D68CE995EE51766907D0104EBAE634495A4D81` | ✅ `9300E7089F38DA1D…` |

> **⚠ `stages.rs` IS ABOUT TO CHANGE.** `diagnostics-engineer`/`stages-engineer` are fixing the two
> defects in §4 below (the post-stage reset gate and `leak_wvalue`). `A64476ECBD992A11…` describes
> the **PRE-FIX** file that every `stages.rs` row in this document was verified against. Any row
> citing `stages.rs` must be re-read against the new hash. That delta check is the owed ADDENDUM
> (§8), and it covers only the three reset-gate call sites and `leak_wvalue` — not the whole file.

> **⚠ TWO FILES CHANGED WHILE THIS WAS BEING WRITTEN — MEASURED, not predicted.** A re-hash after
> the report was written showed the frozen set was no longer intact, and both files kept moving
> afterwards. **See `VERIFICATION-live-run-addendum.md` §0 for the full revision list and §4 for the
> delta verification of the three fixed regions.** Final observed state:
>
> | File | Frozen / as-audited | Later revisions observed | Affected rows |
> |---|---|---|---|
> | `src/stages.rs` | `A64476ECBD992A11…` 2428 | `CE5CE6C315393238…` 2809 → `33C9B309F41B8C63…` 2720 → `5DAF61C4EC81E95F…` 2770 → locked mid-write | **All `stages.rs:NNN` citations in this document are stale.** The substance is unaffected — each cited construct was located and re-read in the new revisions for the three regions the fix touched (addendum §4). Cite functions, not lines. |
> | `src/trace.rs` | `C2420E80E1CFFCD3…` 1353 | `480DD6A09C001C1F…` 1402 → `063D1918CC649C94…` 1430 → `4EAB4C26C09E7F17…` 1470 → `19FA3A55A27C03AF…` 1480 | **§10 (Appendix A) was written against `480DD6A0…`, not the frozen hash.** The B6 fix (§4) postdates it and changes `Tracer::reset` to take `ResetEvidence` — §10's line numbers for that function are stale, and B6 is now fixed. |
> | `src/verdict.rs` | `9300E7089F38DA1D…` | `2E0FDDB70AE21905…` (then stable) | This document cites `verdict.rs` line numbers read at `9300E708…`. The code strings (`verdict.rs:72` `CONFIG_ROW_MISMATCH`, `:94` `RUN_ABORTED`) and the deviation narrative (`:963-992`) were re-checked at `2E0FDDB7…` and still resolve; **re-resolve any other `verdict.rs:NNN` before quoting it.** |
>
> | `src/usb.rs` | `9C9B290895E48527…` 1984 | `6C991F82DDAF42B3…` 2432 → `F4BB507BC8BE6FD7…` 2431 | **Finding A (`dfu_state_name`) is FIXED in the new revision** — see addendum §6.1. The rows this document bases on `usb.rs` (V09/Q9 wire read, §4 B1's `:1036`/`:1081`, B2's `identity()`/`ctrl_sync`) were all re-checked against the new revision: the identity path still reads the wire descriptor, `parse_instance_id` is still test-only, and `declared_i_serial` is still not exposed. Only the line numbers moved. |
>
> `payload.rs` `E3607CB89D1B2A8D…` and `config.rs` `514CF83FA535294B…` and `types.rs`
> `B316AB36D4F56D2E…` are **byte-identical to the frozen values**, so every row resting on them is
> unaffected — including all of §1's payload/config rows, §2's deliberate deviations, and §3's
> answers to Q3/Q7/Q9/Q10. Those are the rows that matter most, and they are intact. (`usb.rs` was
> byte-identical when this document was written and has since changed; the correction is in the table
> above, and the substance held.)

### 0.2 The Lead's two MEASURED facts, used as oracles below

1. **`a9pwn ident` (Lead, MEASURED, read-only, over the wire)** read the string descriptor:
   `CPID:8003 CPRV:01 CPFM:03 SCEP:01 BDID:02 ECID:[REDACTED-IDENTITY] IBFL:1C SRTG:[iBoot-2234.0.0.2.22]`
   — **lowercase `iBoot`, space-separated.** The uppercase `IBOOT` seen earlier came from the
   Windows PnP instance path, which normalises. The wire descriptor is canonical. HANDOFF §3's
   `SRTG (boot) = IBOOT-2234.0.0.2.22` is the PnP form, not the wire form — same string, different
   spelling, and the distinction matters for exactly one reason recorded in §3 row V09.
2. **`a9pwn plan` (Lead, MEASURED)** resolved `config : s8003 Malta (A9)`, `overwrite_pad : 0x500`,
   `insecure_base : 0x180380000`, `payload_dest = 0x00000001800E0F08`, built a 528-byte payload and
   a 48-byte overwrite, `blob sha256 c4fb5fd4b799ae7c5901634e2f75503aaad8cb1a9c663e2a1eb703bbeab4b345`.

These two close claims 3 and 9 **end-to-end on the real device**, which is stronger than anything
source reading can offer. They are the only MEASURED rows in this document.

---

## 1. The ten claims

Verdict key: **MATCH** = our behaviour equals the reference's; **DEVIATION** = it differs (with
"deliberate" or "bug" stated); **UNVERIFIABLE** = cannot be settled without hardware.

| # | Claim | Reference | Ours | Verdict | Label |
|---|---|---|---|---|---|
| **V01** | SETUP pass condition is **STALL on the pad request** — not OK, not TIMEOUT | `gaster.c:853` (pad `bm=0,b=0,wValue=0,wIndex=0`, length `config_overwrite_pad - transfer_ret.sz`, then `&& transfer_ret.ret == USB_TRANSFER_STALL`) | `stages.rs:631` sends the pad; `stages.rs:655-681` passes **only** when `pad.is_some()` **and** `p.status == XferStatus::Stall` | **MATCH** | INSPECTED |
| **V02** | Abort window sequence is **4,5,0,1,2,3** — `usb_timeout - 1` then `(t+1) % 6` | `gaster.c:849` `usb_abort_timeout = usb_timeout - 1`; `gaster.c:857` `(usb_abort_timeout+1) % (usb_timeout - usb_abort_timeout_min + 1) + usb_abort_timeout_min` | `stages.rs:220-222` start; `stages.rs:226-239` advance; `stages.rs:242-250` composed sweep; wired at `stages.rs:530` and `stages.rs:695` | **MATCH** | INSPECTED |
| **V03** | `payload_dest = 0x1800E0F08` (`boot_tramp_end - 192 - 56`); `0x1800E0C00` anywhere would be a bug | `gaster.c:1111` (`- payload_handle_checkm8_request_sz(192) - sizeof(handle_checkm8_request)(56)`); 192 from `gaster.c:1069`, 56 from `gaster.c:1019-1021`, `boot_tramp_end` from `gaster.c:632` | `payload.rs:220-229` derives it; `payload.rs:240` writes it at A9+0x10; `payload.rs:284` traces it | **MATCH** — and **MEASURED** end-to-end by the Lead's `plan` (`payload_dest = 0x1800E0F08`) | MEASURED |
| **V04** | PATCH overflow uses **`wIndex = 0x80`**; hardcoded 0 is a bug | `gaster.c:1211` `send_usb_control_request(handle, 2, 3, 0, 0x80, overwrite, overwrite_sz, …) && …== USB_TRANSFER_STALL`; `overwrite_sz = 48` (`gaster.c:111-113` → `gaster.c:91-96`) | `stages.rs:1168-1179` `CtrlReq{bm:2, b:3, value:0, index:0x80, length:48}` via `req_out` (`stages.rs:337-340`); STALL gate `stages.rs:1191-1203` | **MATCH** — but **no test pins it** (§3, Q4) | INSPECTED |
| **V05** | A reset follows **every** stage attempt, and after PATCH it is the trigger that fires the overwritten `dfu_handle_bus_reset` | `gaster.c:1268` `reset_usb_handle(handle)` inside the `if(!pwned)` block, after every stage, pass or fail; the overwritten pointer is written at `gaster.c:1112` | `stages.rs:1516-1524` (round loop) and `stages.rs:1766` → `reset_device` (`stages.rs:1808-1866`) | **DEVIATION — bug.** Placement matches; the *result handling* does not (§4 B1) | INSPECTED |
| **V06** | A9 spray is **ONE `stall`+`leak`+`no_leak` triple retried whole** — no 40× loop, no `config_hole`, no `config_large_leak`; `wIndex = 0x0A`, `wValue = (3<<8)\|i_serial` | `gaster.c:900` `large_leak==0`; `gaster.c:901` cpid set; `gaster.c:902` `while(!stall \|\| !leak \|\| !no_leak) {}`; `gaster.c:910` trailing CLR_STATUS of `3*EP0_MAX_PACKET_SZ+1` | `stages.rs:1002-1125`; stall `stages.rs:957-961`; leak `stages.rs:969-975` (len `0x40`, abort 1 ms); no_leak `stages.rs:978-992` (len `0xC1`, abort 1 ms); short-circuit order `stages.rs:1071,1072,1081,1092`; CLR_STATUS `stages.rs:1113` | **MATCH** for structure and wire parameters; **DEVIATION (deliberate)** for the bound and the two refusals | INSPECTED |
| **V07** | `A9_STRUCT_SIZE = 104` (13×u64), `HANDLE_CHECKM8_STRUCT_SIZE = 56` (7×u64), and our written field offsets agree with the reference's | `gaster.c:1010-1012` (A9: `pwnd[2]` + 11 u64); `gaster.c:1019-1021` (handle: 7 u64); field writes `gaster.c:1108-1123` and `gaster.c:1126-1132`; `dfu_callback_t` = 48 with `callback` at 32 (`gaster.c:91-96`) | `payload.rs:18` (104), `:21` (56), `:25` (48), `:29` (32); A9 writes `payload.rs:238-250` (0x00…0x60); handle writes `payload.rs:254-260` (0x00…0x30) | **MATCH** | INSPECTED |
| **V08** | `LEAK_WINDEX_GASTER = 0x0A` vs `LEAK_WINDEX_IPWNDFU = 0x00` — "the one unresolved parameter" | `gaster.c:52` `#define USB_MAX_STRING_DESCRIPTOR_IDX (10)`, used at `gaster.c:866`, `:875`, `:886` | `stages.rs:49` = `0x0A`; `stages.rs:61` = `0x00`; default `stages.rs:178`; CLI `main.rs:91-94` | **DEVIATION — the framing is wrong.** The live run uses `0x0A`; the "alternative" is a phantom value (§6) | INSPECTED |
| **V09** | The A9 row is keyed on the **SRTG** substring | `gaster.c:624` `strstr(usb_serial_num, " SRTG:[iBoot-2234.0.0.2.22]")` → CPID 0x8003; `gaster.c:641` `" SRTG:[iBoot-2234.0.0.3.3]"` → 0x8000 — case-**sensitive**, needle has a **leading space** | `config.rs:175` expected `"iBoot-2234.0.0.2.22"`; `config.rs:239` `srtg.eq_ignore_ascii_case(expected_srtg)`; parsing `types.rs:261-291` (normalise `types.rs:267`, split `:268`, trim brackets `:274`, SRTG `:285`) | **MATCH on the value; DEVIATION (deliberate, in our favour) on the comparison.** Cannot fire on this unit — see Q9 | MEASURED (Lead's `ident`) |
| **V10** | `verify_blob_hashes()` fails **loudly**, and its pinned digests match INTERFACE.md §3 | not applicable (our own control; the *blobs* are gaster's) | `payload.rs:97-130`; constants `payload.rs:40-41` = `A698045FAE09ACDC…` / `C0C213047A890218…`, matching `INTERFACE.md:186-187` and the Lead's measured digests; callers `payload.rs:161`, `stages.rs:1304`, `stages.rs:1624`, `main.rs:232`, `main.rs:277` | **MATCH** — it compares and returns `Err`; it does not warn | INSPECTED |

**Row count: 10 / 10 covered — 8 MATCH, 2 DEVIATION, 0 UNVERIFIABLE** *as row verdicts*. Of the
eight MATCH rows, **two carry a deliberate deviation nested inside them** — V06 (the sweep bound and
the two path refusals) and V09 (the comparison is more permissive than the reference's) — and both
are marked as such in their own cells rather than being counted twice. The two DEVIATION rows are
**V05 (a bug: §4 B1)** and **V08 (the framing of the "unresolved parameter" is wrong: §6)**.

Away from the ten rows, and counted separately: **5 deliberate deviations** (§2, D1–D5) and
**6 numbered defects** (§4, B1–B6, of which B1 and B6 are live-run killers and share one root cause).
The `UNVERIFIABLE` label attaches in this document to individual *consequences* rather than to rows
— they are collected in §5 (dangers 1b, 3 and 7) and in the conservatism ledger (§7).

---

## 2. DELIBERATE DEVIATIONS — each with its consequence

These are differences from the reference that are **intended, documented in our source, and not
bugs**. They are listed separately so that a reader comparing our JSONL against gaster's stdout does
not read them as faults — which is precisely what `verdict.rs` asks for at `verdict.rs:963-972`.

| # | Deviation | Reference | Ours | Why, and the consequence for a live run |
|---|---|---|---|---|
| **D1** | **Config refusal is stricter than the reference** | `gaster.c:624,641` select the A9 row from the SRTG substring alone; any A9 in SecureROM DFU takes that path | `config.rs:205-249`: requires a CPID in `{0x8000,0x8003}` **and** a non-empty SRTG **and** an SRTG that matches the row's build string, else `Err` | Verdict code `CONFIG_ROW_MISMATCH` (`verdict.rs:72`, reached from `RunOutcome::Unsupported` at `verdict.rs:335` and `:275`; documented as a deviation at `verdict.rs:963-992`). **Consequence:** gaster with a mismatched SRTG waits forever with `cpid == 0` and no output (`gaster.c:809-813`, `wait_usb_handle` at `gaster.c:206-215`); we refuse by name. This is the deviation the task called out, and it is the *good* kind. **On this unit it cannot fire** (§3, Q9). |
| **D2** | **SRTG comparison is case-insensitive and separator-tolerant** | `gaster.c:624` `strstr` — case-sensitive, and the needle includes a **leading space**, so gaster itself would *fail* on a Windows underscore-normalised descriptor | `types.rs:267` `_`→space, `types.rs:268` `split_whitespace`, `types.rs:274` strips `[`/`]`, `config.rs:239` `eq_ignore_ascii_case` | **Consequence:** we accept descriptor spellings gaster rejects. Strictly more permissive on the SRTG string, and the permissiveness is what makes the port work on Windows at all. Documented at `config.rs:198-204`. |
| **D3** | **SETUP sweep is bounded and instrumented** | `gaster.c:852` `for(;;)` with no output; 35 KB of one repeated line is what that cost this project | `stages.rs:546-575` with `SetupBudget` (`stages.rs:145-152`, default 20 000 attempts / 600 000 ms), every attempt traced (`stages.rs:638-642`), plus a degenerate-sweep warning (`stages.rs:769-802`) | **Consequence — practical, not correctness:** the reference cannot exit SETUP; ours exits after ≤ 10 min. **The budget is per `stage_setup` call, i.e. per round** (`SetupStats::new` at `stages.rs:532`), so a 64-round run in which SETUP never converges can spin for **≈10.6 hours**, and SPRAY shares the same budget (`stages.rs:1040`), so ≈21 h in the worst case. Budget the wall-clock before starting. |
| **D4** | **SPRAY refuses paths we do not drive instead of approximating them** | `gaster.c:911-915` large-leak branch; `gaster.c:904-908` non-A9 branch | `stages.rs:1003-1013` refuses `large_leak != 0`; `stages.rs:1014-1024` refuses a non-A9 cpid | **Consequence:** a wrong heap layout is refused by name (`SPRAY_UNSUPPORTED_LARGE_LEAK` / `SPRAY_UNSUPPORTED_CHIP`) rather than driven with the A9 sequence. Unreachable on this unit — both A9 configs carry `large_leak == 0` (`config.rs:126`, `config.rs:156`), pinned by `config.rs:306-312` and `stages.rs:2420-2427`. |
| **D5** | **SETUP/SPRAY extra guards that the reference does not have** | gaster has no pad-length check and no refused-transfer detection | `SETUP_PAD_LENGTH_INVALID` (`stages.rs:615-626`); `TRANSPORT_DEVICE_LOST` on a refused transfer (`stages.rs:595-607`); `window_span` clamps `abort_min` (`stages.rs:226-230`); `advance_abort_window` clamps the window (`stages.rs:237`); blob verification before every build (`payload.rs:161`) | **Consequence: all unreachable at the live configuration.** `overwrite_pad = 0x500` fits a u16 with room to spare, `abort_min = 0 ≤ usb_timeout = 5`, and the window is always inside `[0,5]`. The clamps exist because gaster would evaluate `(usb_timeout - abort_min + 1)` as **0** and divide by zero if `abort_min > usb_timeout` — a trap gaster only half-avoids, since `gaster.c:1635-1638` rejects *strictly greater* but allows **equal**, which collapses the modulus to 1. Our handling of that degenerate case is D3's warning, and it is correct. |

---

## 3. The Lead's specific questions, answered

### Q9 (the one that mattered most) — is our SRTG match case-sensitive, and can this device be refused as `CONFIG_ROW_MISMATCH`?

**No on both counts, and the match is now measured rather than argued.**

* The comparison is `config.rs:239`:
  `if !srtg.eq_ignore_ascii_case(expected_srtg)` — **case-insensitive** (`eq_ignore_ascii_case`, not
  `==`), so `IBOOT` and `iBoot` both match.
* Separators are handled in two independent places before that: `types.rs:267` replaces `_` with a
  space and `types.rs:268` splits on `split_whitespace()`, so the Windows underscore form and the
  libusb space form produce the same tokens; `types.rs:274` then strips `[` and `]`, and
  `types.rs:285` stores the bare value. Expected value: `config.rs:175` = `"iBoot-2234.0.0.2.22"`.
* The live path does not even *see* the PnP instance string: `usb.rs:492-529` reads the string
  descriptor over the wire (`usb.rs:531-539`: `bm=0x80, b=6, wValue=(3<<8)|index, wIndex=0x0409`),
  and `DeviceIdentity::parse_instance_id` (`types.rs:326-331`) is **never called outside tests**.
* **MEASURED (Lead):** `a9pwn ident` read `SRTG:[iBoot-2234.0.0.2.22]` from the device and
  `a9pwn plan` then resolved `config : s8003 Malta (A9)` and `overwrite_pad : 0x500`. So
  `config_for_identity` (`config.rs:205-249`) accepts this unit, called from `stages.rs:1384`
  (round loop) and `stages.rs:1666` (single-stage). **`CONFIG_ROW_MISMATCH` cannot fire for this
  device.**

**What the two named tests actually prove, versus what they assume** — the task asked for this
distinction and it is not a formality:

| Test | Proves | Assumes |
|---|---|---|
| `resolves_the_attached_device_both_casings` (`config.rs:368-377`) | `eq_ignore_ascii_case` accepts both `IBOOT-` and `iBoot-` spellings of the same string, and that the upper-cased identity yields CPID 0x8003 / `PayloadKind::A9` | That `LIVE_8003` (`config.rs:260-261`) is what the device sends. It is a **hand-written literal**, not a capture. |
| `resolves_the_windows_underscore_descriptor` (`config.rs:380-388`) | The `_`-separated form parses to the same identity and resolves | Same. It also assumes SetupAPI's normalisation is exactly "space → underscore" and nothing else. |

Neither test can fail because of anything the phone does. They pin **our parser's tolerance**, not
the device's string. The device's string was pinned by the Lead's `ident` read, and because that
string is the **lowercase space form**, the case-insensitive branch is in fact **not exercised at
all** on this unit — `eq_ignore_ascii_case` succeeds on a plain equality. That is the honest reading:
the mechanism that made us worry is present and correct, but on this device it is dormant.

**Residual risk, stated for completeness:** the whole gate reduces to *the parsed `srtg` token must
equal `iBoot-2234.0.0.2.22` ignoring case*. Nothing about brackets or separators can break that,
because they are normalised away. The only way to fail is a genuinely different bootrom build
string, which would mean the config addresses are wrong anyway. If it ever fires, `verdict.rs:979-988`
already adds the sentence that tells the reader the refusal is a table key and not the chip.

### Q3 — is `payload_dest` 0x1800E0F08 everywhere, and is `0x1800E0C00` anywhere?

**Yes, and no.**

* Derived at `payload.rs:220-229` as `boot_tramp_end - (HANDLE_CODE_LEN + HANDLE_CHECKM8_STRUCT_SIZE)`
  = `0x1800E1000 - (192 + 56)`; written at `payload.rs:240` (`put(0x10, payload_dest)`).
* `0x1800E0C00` appears **only** as a comment (`payload.rs:217`) and as a deliberate negative
  assertion (`payload.rs:753`). No code path can emit it.
* **MEASURED (Lead):** `a9pwn plan` printed `payload_dest = 0x00000001800E0F08` and
  `blob sha256 c4fb5fd4…`, which is the digest pinned at `payload.rs:632`. The number is therefore
  confirmed on the real device, not merely derived.
* **The named test pins the right number.** `payload_dest_is_gasters_not_ipwndfus`
  (`payload.rs:743-754`) asserts four things: the blob value at offset `0xC0` is `0x1800E0F08`; it
  equals `boot_tramp_end - 248`; `dest + 192 + 56 == boot_tramp_end` **exactly** (the invariant that
  makes it gaster's value and not a coincidence); and `assert_ne!(dest, 0x1800E0C00)`. That is a
  correct pin, including the negative.

### Q4 — where is the PATCH `wIndex = 0x80` set, and what test pins it?

* **Set at `stages.rs:1175`**, inside the `CtrlReq` built at `stages.rs:1169-1179`
  (`bm: 2, b: 3, value: 0, index: 0x80`), sent by `req_out` (`stages.rs:337-340`), with the STALL
  gate at `stages.rs:1191-1203`. It matches `gaster.c:1211` exactly, including the shared 0x80 with
  gaster's own `checkm8_usb_request_stall` (`gaster.c:893`). `stages.rs:1142-1148` documents the
  a9ctl contrast.
* **No test pins it. This is a real coverage gap, and it is the gap that matters most for the
  HANDOFF §8.5 bug class.** The test module (`stages.rs:2065-2428`) contains **no test that calls
  `stage_patch`** — grep confirms `patch` appears in that file only in doc comments, implementation
  code, and two `println!` strings (`stages.rs:2020-2021`, `stages.rs:1793`). The `w_index: 0`
  occurrences at `stages.rs:2190, 2215, 2243, 2298, 2338` are `XferResult` fixtures for other
  assertions, not constraints on PATCH. The only place the value 0x80 appears is the code itself and
  the human-readable plan text at `stages.rs:2020-2021`, which is output, not an assertion.
  **Consequence:** a future edit that changed `index: 0x80` to `0` — the exact defect §8.5 was
  written about — would be caught by nothing in the suite.
* The same gap covers **all of SPRAY's wire parameters.** `stage_spray`'s only test,
  `spray_guards_are_specific` (`stages.rs:2420-2427`), asserts the *config table* has
  `large_leak == 0` and `hole == 0`; it does not exercise the request parameters. `wIndex = 0x0A`,
  `wValue = (3<<8)|i_serial`, lengths `0x40`/`0xC1` and the CLR_STATUS length `0xC1` are pinned by
  inspection alone.

### Q1/Q2 — do the sweep tests pin the **reference's** behaviour or merely our own?

They pin the reference's, but not every test does it on its own. Precisely:

| Test | What it actually pins |
|---|---|
| `sweep_starts_at_usb_timeout_minus_one` (`stages.rs:2077-2081`) | The **start**: `initial_abort_window(5,0) == 4`, matching `gaster.c:849`. It tests the pure helper; the wiring into the loop is at `stages.rs:530` and is INSPECTED, not tested. |
| `advance_formula_is_gaster_857` (`stages.rs:2086-2098`) | The **formula**: from each `t` in `0..=5`, `advance_abort_window` gives `[1,2,3,4,5,0]`. Note it feeds its **own 0-origin input**, so on its own it does **not** pin the acceptance sequence `4,5,0,1,2,3` — a reader who stopped here could not tell 4-start from 0-start. |
| `sweep_exercises_every_distinct_window` (`stages.rs:2104-2111`) | **This is the one that pins `4,5,0,1,2,3`.** It composes `initial_abort_window` + `advance_abort_window` via `sweep_windows(5,0,12)` and asserts `seq[..6] == [4,5,0,1,2,3]`, that it repeats, and that the six windows are the set `{0,1,2,3,4,5}`. That is the reference's sequence, exactly. |
| `pad_predicate_matches_gaster_853` (`stages.rs:2268-2273`) | **Only two-thirds of `gaster.c:853`.** It pins `pad_request_len` — the `transferred < overwrite_pad ⇒ pad of overwrite_pad - transferred` half — with four cases including the boundary `0x4FF→1` and the exclusions `0x500→None`, `0x800→None`. The **STALL** half is *not* in this test. Its name over-promises. |
| `stalling_the_pad_is_recorded_as_stall_only` (`stages.rs:2332-2350`) | The STALL half, but at the **counter** level (`pad_stalls == 1`, `pad_ok == pad_timeouts == pad_other == 0`), not at the pass-gate level. |
| `abort_completed_mirrors_gasters_wrapper` (`stages.rs:2209`) / `a_refused_transfer_is_distinguishable_from_a_reaped_error` (`stages.rs:2237`) | That `abort_completed` treats any reaped terminal status as "completed" — mirroring `gaster.c:220-223` and `gaster.c:282` (`return completed != 0`), including the deliberate decision to pad after a host-side `Error` (`stages.rs:252-270`). Verified correct against the reference. |

**So:** the *sequence* `4,5,0,1,2,3` and the pad *length predicate* are genuinely pinned to the
reference. The **STALL pass gate itself** — `stages.rs:656` — is reached only through
`stage_setup`, which no test can call without a `Transport`. `pad_predicate_matches_gaster_853` is
therefore **not** the test its name suggests; the STALL requirement rests on inspection of
`stages.rs:655-681`.

### Q6 — is the A9 spray exactly one triple, retried whole, with the right parameters, and are `config_hole` / `config_large_leak` / a 40× loop truly absent?

**Yes to all of it.**

* `gaster.c:900-902`: the A9 branch is selected by `config_large_leak == 0` **and** cpid in
  `{0x7001,0x7000,0x7002,0x8003,0x8000}`, and is literally
  `while(!checkm8_usb_request_stall(handle) || !checkm8_usb_request_leak(handle) || !checkm8_no_leak(handle)) {}`
  — one triple, retried whole, with `||` short-circuit.
* Ours: `stages.rs:1060-1109`. The stall gate is `s.status == XferStatus::Stall` (`stages.rs:1071`);
  the leak is issued only if it passed (`stages.rs:1072-1074`); its success is
  `abort_completed(&l) && l.transferred == 0` (`stages.rs:1079`), matching gaster's
  `&& transfer_ret.sz == 0` (`gaster.c:866`); `no_leak` likewise (`stages.rs:1088`), matching
  `gaster.c:886`. The short-circuit is recorded in the trace rather than hidden
  (`stages.rs:1092-1098`).
* Wire parameters: stall = `bm=2, b=3, wValue=0, wIndex=0x80, len 0` (`stages.rs:958` ↔ `gaster.c:893`);
  leak = `bm=0x80, b=6, wValue=(3<<8)|i_serial, wIndex=opts.leak_windex, len 0x40, abort 1 ms`
  (`stages.rs:972` ↔ `gaster.c:866`); no_leak = same with `len 0xC1, abort 1 ms` (`stages.rs:981-989`
  ↔ `gaster.c:886`); trailing CLR_STATUS with `len 3*EP0_MAX_PACKET_SZ + 1` (`stages.rs:1113` ↔
  `gaster.c:910`). `wValue` is built at `stages.rs:964-966` from the **declared** `i_serial`
  (`usb.rs:423`, `:437`, `:445`) — the same source as gaster's `device_descriptor.i_serial_number`.
* **40× loop: absent.** No `for _ in 0..40` or equivalent exists in `stages.rs`; the only repetition
  is the unbounded-until-budget `loop` at `stages.rs:1033`.
* **`config_hole`: absent.** The `hole` field exists only in `config.rs` (always 0:
  `config.rs:127`, `:159`, pinned by `config.rs:306-312`) and in a test at `stages.rs:2425`. No
  iteration over it exists in `stages.rs` — matching `gaster.c:905`, which is the non-A9 branch.
* **`config_large_leak`: absent as a driven path.** `stages.rs:1003-1013` refuses it by name rather
  than iterating (`gaster.c:911-915`), and the field is 0 for both A9 rows.

### Q8 — `LEAK_WINDEX_GASTER = 0x0A` vs `LEAK_WINDEX_IPWNDFU = 0x00`: what exactly is unresolved?

**Exactly what is unresolved:** whether the A9 SecureROM's leaked-string-descriptor handler requires
`wIndex = 0x0A` (gaster) on this silicon. That is the whole of it, and **it is not a two-way choice
between two sourced values.**

| Value | Provenance | Verdict |
|---|---|---|
| **`0x0A`** | `gaster.c:52` `#define USB_MAX_STRING_DESCRIPTOR_IDX (10)`, used at `gaster.c:866`, `:875`, `:886` | **Sourced.** This is gaster's A9 value. |
| **`0x00`** | `INTERFACE.md:200` (`stages.rs:61`), described at `stages.rs:54-60` as "what ipwndfu's `USBRequestLeak` passes as wIndex" | **Unsupported.** §6 below shows the vendored ipwndfu uses `0x40A`, and has no A9 row at all. |
| **`0x40A`** | `research/refs/ipwndfu/checkm8.py:123-124` (`usb_req_leak` / `usb_req_no_leak`), and also `:118-120` (`leak` / `no_leak`) | **Sourced, but for other SoCs** — ipwndfu's generic value. |

**What the live run will use by default: `0x0A`.** `RunOptions::default` sets
`leak_windex: LEAK_WINDEX_GASTER` (`stages.rs:178`, pinned by `stages.rs:2360`), and the CLI only
overrides it when `--leak-windex-ipwndfu` is passed (`main.rs:91-94`). **HANDOFF §6.3's command line
contains no such flag, so the run uses `0x0A`.** The flag's name is a misnomer: it selects an
uncited `0x00`, not ipwndfu's value.

**What a trace observable would tell us we picked wrong.** The discriminator is the leak's byte
count, not its status:

* Wrong-wIndex signature in the JSONL: repeated `spray_iteration` events with `stall_status=STALL`
  (the stall request does **not** depend on `leak_windex` — it is hardcoded `0x80` at
  `stages.rs:958`) but `leak_status=OK` with `leak_xfer=<nonzero>`, so `leaks` stays 0 and the stage
  ends with `SPRAY_BUDGET_EXHAUSTED` at `stages.rs:1057` after 20 000 iterations, reporting
  `stalls>0 leaks=0 no_leaks=0`.
* **Honest limit of that observable:** gaster's leak predicate is `sz == 0`, not `ret == OK`
  (`gaster.c:866` and the wrapper at `gaster.c:262-276`), and our port mirrors it
  (`stages.rs:1079`). A *STALLed* leak also reports 0 bytes, so if the wrong wIndex causes a STALL
  rather than a data return, **both candidate values satisfy the predicate** and the trace cannot
  discriminate. In that case the wrong choice would surface only later, as PATCH failing or an
  absent `PWND` marker — i.e. as a failure with no attributable cause. That is the reason this
  parameter deserves to be resolved, and it is also why the A/B the comment proposes at
  `stages.rs:59-60` is weaker than it sounds.

### Q10 — does the verification path fail loudly and compare against the right constants?

**Yes, it compares, and it fails loudly in all four entry points.**

* Constants: `payload.rs:40-41` = `A698045FAE09ACDC5BFAFC26EF3FE7848F1454B8CE8847FDC45396CC18A532B2`
  and `C0C213047A8902186392396CB7E57C096626B4812B61E07C2CF7CF6B99A9889C`, byte-identical to
  `INTERFACE.md:186-187` and to the digests the Lead measured on disk.
* `verify_blob` (`payload.rs:97-118`) checks **length first** (`payload.rs:103-109`, so a swap that
  preserved a digest still fails) then SHA-256 (`payload.rs:110-116`) and returns `Err`. There is no
  warn-only path: the strings are `"... A swapped blob is a silently different exploit; refusing to
  build."`
* Entry points: `build_payload` calls it first (`payload.rs:161`), so a bad blob cannot be built into
  something sendable; `run` (`stages.rs:1304`) and `run_one_stage` (`stages.rs:1624`) return
  `RunOutcome::Aborted`; `plan` prints `BLOB VERIFICATION FAILED` and exits `EXIT_TRANSPORT` = 6
  (`main.rs:232-235`); `selftest` counts a failure and exits 6 (`main.rs:277-283`, `:304-312`).
* Tests: `sha256_matches_published_vectors` (`payload.rs:436`), `embedded_blobs_match_their_documented_hashes`
  (`payload.rs:455`), `one_corrupted_byte_fails_verification` (`payload.rs:465`).

| # | Claim | Reference | Ours | Verdict | Label |
|---|---|---|---|---|---|
| **V10a** | It fails loudly rather than warning | — | `payload.rs:110-116` `Err`; `main.rs:232-235`, `main.rs:277-283`, `stages.rs:1304`, `stages.rs:1624` | **MATCH** | INSPECTED |
| **V10b** | Pinned digests equal INTERFACE.md §3 | `INTERFACE.md:186-187` | `payload.rs:40-41` | **MATCH** | INSPECTED |
| **V10c** | The built blob is itself pinned | — | `payload.rs:626-635` pins `c4fb5fd4b799ae7c5901634e2f75503aaad8cb1a9c663e2a1eb703bbeab4b345` | **MATCH**, and **MEASURED** by the Lead's `plan` output | MEASURED |

---

## 4. DEFECTS — undocumented or self-contradicting deviations

These are **not** deliberate. Ordered by severity.

### B1 — 🔴 LIVE-RUN KILLER: the post-stage reset gate aborts the run before SPRAY

**What the code does.** After every stage attempt:

* round loop: `stages.rs:1555-1568`
  `if !report.bus_reset_delivered && !opts.allow_winusb { return RunOutcome::Aborted(…) }`
* single-stage path: `stages.rs:1840-1849`, inside `reset_device` (`stages.rs:1808-1866`), called
  from `stages.rs:1729` (precondition) and `stages.rs:1766` (post-stage).

**Why `bus_reset_delivered` is almost always false.** `usb.rs:1081` sets
`bus_reset_delivered: evidence.delivered()`, and `ResetEvidence::delivered()` is true **only** for
`Delivered` (`types.rs:408-410`). `reset_evidence` (`types.rs:430-460`) returns `Delivered` only for:

```
(Some(DFU_STATE_MANIFEST_WAIT_RESET), Some(APP_IDLE | DFU_IDLE))   → Delivered   types.rs:446-450
```

Everything else — including idle-before/idle-after and any unreadable state — is `Unverified`
(`types.rs:454-458`), which the same crate documents as *"not success; not failure"*
(`types.rs:387-391`, and the user-facing wording at `usb.rs:228-235`).

**Why that is fatal here.** Only two places park the DFU machine in state 8:
`stage_reset`'s MANIFEST walk (`stages.rs:407-439`, matching `gaster.c:829-834`) and PATCH's trailing
walk (`stages.rs:1246-1253`, matching `gaster.c:1220-1222`). **Nothing after SETUP and nothing after
SPRAY parks it.** The last transfers of SETUP are an aborted 0x800-byte DNLOAD (`stages.rs:580-588`)
and the `bm=0,b=0` pad request (`stages.rs:631`); SPRAY's last transfers are the leak pair and a
CLR_STATUS. So the state read at `usb.rs:1036` immediately before those resets cannot be 8, and the
verdict can only be `Unverified` → abort.

**Consequences, concretely** — **⚠ CORRECTED after the addendum: the abort is in round 1, not round 2.**
The first version of this section said round 1's reset is `Delivered` and round 1 passes. **That was
wrong**, and the Lead's hardware measurement is what refuted it: `stage_reset`'s trailing 64-byte flush
(`gaster.c:840`; `stages.rs:478-491` pre-fix) is sent **after** the MANIFEST walk has verified state 8,
and it moves the machine back out of `MANIFEST_WAIT_RESET` — the Lead measured state **5**
(`dfuDNLOAD-IDLE`) at the next `GET_STATUS`, which is `usb.rs:1036` inside `Transport::reset`. So the
reset after RESET is *also* classified `Unverified`, and the abort lands at the end of **round 1**.
See `VERIFICATION-live-run-addendum.md` §1 Claim 3 for the full derivation. The corrected
consequences, which are worse than originally reported:

1. `a9pwn run --rounds 64 --trace …` (HANDOFF §6.3). **Round 1 is RESET, and its own reset is
   `Unverified` → the run returns `RunOutcome::Aborted` at the end of round 1** → verdict
   `RUN_ABORTED` (`verdict.rs:94`). **SETUP is never attempted.** SPRAY and PATCH are never reached.
   The exploit cannot complete, and it fails before the first interesting stage.
2. `a9pwn run --stage setup --stop-after-setup-stall` (HANDOFF §6.3 step 4). The single-stage path
   runs RESET as a precondition and resets after it (`stages.rs:1729` pre-fix); that reset classifies
   `Unverified` and aborts **before SETUP runs at all**. So the diagnostic reports a reset refusal
   instead of the SETUP verdict it exists to produce. **The step-4 proof would be lost**, and it would
   be lost without SETUP ever having been exercised — so the run would teach nothing about the pad
   STALL either. `a9pwn run --stage reset` and `--stage spray`/`--stage patch` fail the same way, on
   their precondition reset.
3. The abort message blames the reset — *"the bus reset after SETUP was not delivered"* — when the
   reset was very likely delivered and merely unobservable. That is the failure-class confusion this
   project's §9.6 rule exists to prevent, inverted: one real outcome reported as another. Aggravated
   by B6, below: the trace line for that same reset was labelled `reset_pipe_cycle`, accusing libusbK
   of a failure the measurement does not support.

**This is a deviation, not a port.** gaster discards the reset result outright —
`gaster.c:197-200` is `static void reset_usb_handle(...) { libusb_reset_device(handle->device); }`
with no use of the return — and `gaster.c:1268` resets unconditionally.

**Suggested fix (not my write scope; `stages.rs` is stages-engineer's).** Make only `Refuted`
(`types.rs:451-453`), `DriverCannotReset` (`types.rs:437-439`) and the `Err` arm fatal, and let
`Unverified` continue with the loud warning `ResetReport::note` already carries. Treating the
crate's own four-way enum as a boolean is what reintroduced the collapse that `ResetEvidence` was
created to prevent. **Interim workaround if the run cannot wait:** `--allow-winUsb`/`--allow-winusb`
currently disables *both* this gate and the WinUSB gate (`stages.rs:1840`, `:1555`) — but it also
removes the guard against the genuine no-op-reset failure mode, so using it spends the one shot to
buy a workaround. I would not.

**Trace observable:** a line with `predicate=bus_reset_delivered`, `ok=false`, and
`when=post-stage … DFU state <X> -> <Y>` where `X` is not `8 (manifestWaitReset)`.

### B2 — 🟠 `leak_wvalue()` issues a real GET_DESCRIPTOR twice per spray iteration

`stages.rs:964-966`:

```rust
fn leak_wvalue(io: &StageIo) -> u16 {
    (3u16 << 8) | io.usb.identity().i_serial as u16
}
```

`Transport::identity()` (`usb.rs:474-484`) is a **live read** — deliberately so, as its own comment
says at `usb.rs:465-473`, adding *"Do not call it between SETUP and PATCH"* — and it reaches the wire
through `serial_descriptor()` (`usb.rs:492-529`) → `read_string_descriptor()` (`usb.rs:531-539`) →
`ctrl_sync()` → `libusb_control_transfer` (`usb.rs:640-674`). It is called once from
`usb_request_leak` (`stages.rs:970`) and once from `no_leak` (`stages.rs:979`).

* **Reference:** gaster reads the cached `device_descriptor.i_serial_number` (`gaster.c:866`) and
  sends **three** EP0 requests per A9 spray iteration.
* **Ours:** **five** — two extra `GET_DESCRIPTOR(3, i_serial)` transfers of up to 255 bytes, inserted
  between the stall, the leak and the no-leak.
* **Why it matters:** the A9 spray is a heap-shaping sequence; the identity and order of EP0 setup
  packets is the mechanism, not incidental traffic. An extra setup packet with a different `wLength`
  allocates differently from the 0x40/0xC1 pair the sequence is built around. It also makes each
  iteration slower, which matters when the whole stage is racing a budget.
* **Severity: INFERRED, not measured.** I cannot say off-hardware whether the extra request breaks
  the corruption or merely shifts it. I can say it is a deviation from the reference in the one loop
  that must not deviate, and that it is avoidable at zero cost: `i_serial` is already cached on the
  transport at open (`usb.rs:423`, `:430`, `:437`, `:445`) and exposed in spirit by
  `Transport::ident_index()` (`usb.rs:587-589`). **Fix assigned by the Lead to stages-engineer.**
* Also note the code contradicts its own file's rule: `usb.rs:472` says not to call it between SETUP
  and PATCH, and `stages.rs:965` calls it inside SPRAY, which is exactly that window.

### B3 — 🟡 `abort_completed` lets a *refused* transfer count as a successful leak

`stages.rs:1079` and `:1088` score a leak as satisfied when `abort_completed(&l) && l.transferred == 0`,
where `abort_completed` (`stages.rs:271-273`) is `!matches!(r.status, XferStatus::NoDevice)`. A
transport that has been poisoned returns the `refused` shape — `Error`, 0 µs, no abort window
(`usb.rs:970`+, and `abort_was_refused` at `stages.rs:282-284` detects exactly that shape). Such a
result passes `abort_completed` and has `transferred == 0`, so **a device that dies between the
stall and the leak would score both the leak and the no-leak as successes and SPRAY would return
`Pass` on a dead handle.**

* **Reference:** gaster's predicate is `send_..._async_no_data(...) && transfer_ret.sz == 0`, and the
  helper returns `completed != 0` (`gaster.c:282`) — false when the transfer was never reaped, so
  gaster would retry rather than accept.
* **Bounded consequence:** PATCH then fails, or the reset gate (B1) aborts. So this cannot
  manufacture a false `PWNED`; it can only misattribute *where* the run died — which, for a tool
  whose entire purpose is honest failure classification, is still a defect.
* **Fix:** apply the existing `abort_was_refused` test in SPRAY's leak/no-leak predicates, as SETUP
  already does at `stages.rs:595`.

### B4 — 🟡 The tests pin the pure helpers, not the wire

Not a behaviour bug; a **verification** defect, and the reason this audit exists. Restated from §3:
no test calls `stage_patch` or `stage_spray`. The parameters most likely to be wrong in a port —
PATCH's `wIndex = 0x80`, SPRAY's `wIndex`/`wValue`/`0x40`/`0xC1`, the CLR_STATUS length — are pinned
by inspection only. By contrast `payload.rs` has excellent coverage (13 tests including a pinned
built-blob digest), and the pure sweep helpers are well pinned. The gap is exactly the transport-facing
half.

### B5 — 🟡 A false statement inside the frozen-surface documentation

`stages.rs:56-58` asserts that `0x00` *"is what ipwndfu's `USBRequestLeak` passes as `wIndex`"*.
`research/refs/ipwndfu/checkm8.py:123` passes `0x40A`. See §6. The same comment correctly records that
`a9ctl/src/checkm8.rs:108` used `0x40A` — so the file knows the right number and attributes it to the
wrong place. Minor in effect, but this is a `FROZEN SURFACE` doc comment (`stages.rs:1`) and it is
the provenance record for a parameter the task calls "the one unresolved" — so it is the worst
possible place for an unsourced value to be presented as a sourced one.

### B6 — 🔴 THE TRACE FALSE-ACCUSES THE DRIVER: `Unverified` resets are logged as `reset_pipe_cycle`

**This is the same root cause as B1 — `ResetEvidence`'s four-way enum collapsed into a `bool` — but
it corrupts the *record* rather than the control flow, and it survives B1's fix if only the abort
condition is changed.**

`Tracer::reset` (`trace.rs:574-581`, read at the post-change hash `480DD6A0…`):

```rust
/// Typed shortcut for a port reset. Prefer this over a bare `event` string:
/// `delivered == false` means the call returned but only pipes were cycled,
/// which is a measurement, not a guess.
pub fn reset(&mut self, delivered: bool, note: &str) {
    let k = if delivered { kind::RESET_REAL } else { kind::RESET_PIPE_CYCLE };
```

The doc comment at `trace.rs:572-573` asserts that `false` *means* "only pipes were cycled". It does
not. `delivered` is passed as `report.bus_reset_delivered` (`stages.rs:1542`, `stages.rs:1829`),
which is `false` for **three distinct** outcomes: `Refuted`, `Unverified`, and `DriverCannotReset`
(`types.rs:408-410`). Only `DriverCannotReset` and `Refuted` mean the pipes-only story; **`Unverified`
means "a real port reset was requested on a capable driver and the device showed no observable
change"** — which is what `types.rs:387-391` and `usb.rs:228-235` both go out of their way to say is
*"not success; not failure"*.

**Consequences.**

1. **The JSONL asserts a measurement that was not made.** A run that ends on B1's abort writes
   `"kind": "reset_pipe_cycle"` for `when=post-stage`. A reader — or the Lead, at 2 a.m., deciding
   what to fix — is told "libusbK only cycled pipes". The correct next action is *"nothing is wrong
   with the reset; look at the classifier"*, and the trace says the opposite. This is the same shape
   as the HANDOFF §3 misdiagnosis: a plausible-looking wrong value, this time machine-generated.
2. **It suppresses the verdict that would have named the real problem.** `RESET_NOT_DELIVERED` is
   gated at `verdict.rs:279-283` by `resets_attempted > 0 && resets_real == 0 && resets_pipe_cycle == 0`.
   Because `Unverified` increments `resets_pipe_cycle` (`trace.rs:533-536`), any single unobservable
   reset permanently disables that verdict for the run — the code cannot report "no reset was
   delivered" once something merely *unverifiable* has happened.
3. **It is reachable on the very first live run**, because B1 guarantees a non-`Delivered` reset at
   the end of **round 1** (see the correction in §4 B1 and addendum §1 Claim 3).

**Fix, and it must be done together with B1.** The enum has to reach the tracer: either
`Tracer::reset` takes `ResetEvidence` (or a three-way label) and emits distinct kinds, or
`stages.rs` stops passing a `bool`. Fixing only the `if !report.bus_reset_delivered` condition
leaves every subsequent trace lying about the driver. `kind::RESET` (`trace.rs:73`) already exists
for "attempted, unclassified" (`trace.rs:528`), so the vocabulary for a correct three-way split is
already present.

**Trace observable:** any `"kind":"reset_pipe_cycle"` line whose `note` contains
`"issued, effect unverified"` or `"DELIVERED"`-absent wording — i.e. the kind and the note disagree.
The note is built by `reset_note` (`usb.rs:171-260`) and carries the honest verdict string, so the
contradiction is self-documenting inside a single line.

---

## 5. WHAT WOULD MAKE THE FIRST LIVE RUN FAIL

Ranked most dangerous first. Each row gives the observable that would confirm it in the JSONL trace,
so the Lead can identify it **during** the run rather than after.

| # | Danger | Severity | Source | JSONL observable that confirms it |
|---|---|---|---|---|
| **1** | **B1 — the post-stage reset gate aborts at the end of ROUND 1, after RESET, before SETUP is ever attempted.** The exploit cannot complete, and it fails before the first interesting stage. *(Corrected: the first version of this row said round 2 — the Lead's hardware measurement of state 5 after `stage_reset`'s flush refuted that. See addendum §1 Claim 3.)* | 🔴 Certain, mechanical | `stages.rs:1555`, `stages.rs:1840`; `types.rs:446-450`; `usb.rs:1081`, `usb.rs:1036`; `gaster.c:840` | `predicate=bus_reset_delivered` with `ok=false` and `DFU state 5 (…) -> …` where the "before" value is **5**, preceded by a successful `stage_pass` for **RESET** (not SETUP). Final outcome `RUN_ABORTED`, not `SETUP_NEVER_STALLED`. **If you see this, the reset is not the problem — the classifier is.** |
| **1b** | **B6 — the trace false-accuses the driver: every non-`Delivered` reset is logged as `reset_pipe_cycle`.** Same root cause as B1 (four-way enum collapsed to `bool`), corrupts the record rather than the control flow, and **survives a B1 fix that only changes the abort condition**. It also permanently disables the `RESET_NOT_DELIVERED` verdict (`verdict.rs:279-283`). | 🔴 Certain, mechanical | `trace.rs:574-581` (new hash `480DD6A0…`); `stages.rs:1542`, `:1829`; `types.rs:408-410`; `trace.rs:533-536` | Any line with `"kind":"reset_pipe_cycle"` whose own `detail`/`note` carries the honest `Unverified` wording (`"issued, effect unverified"`, `usb.rs:171-260`) — i.e. the kind and the note contradict each other inside one line. Expected on the first run, on the B1 abort. |
| **2** | **The one unresolved parameter (V08) is wrong.** `wIndex = 0x0A` is gaster's value and the default, but it has never run on this silicon, and the documented alternative (`0x00`) is unsourced while ipwndfu's real value (`0x40A`) is not reachable from our CLI. | 🟠 Real unknown | `stages.rs:49`, `:61`, `:178`; `main.rs:91-94`; `gaster.c:52`, `:866`; `checkm8.py:123-124` | `spray_iteration` events with `stall_status=STALL` but `leak_status=OK` and `leak_xfer=<nonzero>` repeatedly, ending in `SPRAY_BUDGET_EXHAUSTED` with `stalls>0 leaks=0`. **If instead every leak STALLs, this trace cannot tell you the wIndex was wrong** (see Q8) — the run would fail later with no attributable cause. |
| **3** | **B2 — two extra GET_DESCRIPTORs per spray iteration**, inside the heap-shaping loop, contradicting `usb.rs:472`'s own instruction. | 🟠 Deviation, consequence UNVERIFIABLE | `stages.rs:964-966`, `:970`, `:979`; `usb.rs:474-484`, `:531-539`, `:640-674`; cf. `gaster.c:866` | Not directly observable as a predicate. Indirectly: `spray_iteration` lines interleaved with `seq` numbers that advance by 2 more than the reference's 3-per-iteration, and a SPRAY that never converges while `stall_status=STALL` throughout. |
| **4** | **SETUP never STALLs.** The failure the previous session chased (the 384-timeout log). | 🟠 Possible, and pre-existing | `gaster.c:853`; `stages.rs:655-681` | `setup_attempt` lines whose `pad_status` is `TIMEOUT` (not `STALL`) throughout, with `distinct_abort_windows=6` proving the sweep really varied; then `SETUP_BUDGET_EXHAUSTED`, verdict `SETUP_NEVER_STALLED` or `PAD_TIMEOUT_NOT_STALL`. If `distinct_abort_windows=1`, read `setup_degenerate_sweep` — the sweep is one experiment wearing six labels. |
| **5** | **Wall-clock, not correctness: the budget is per round.** SETUP ≤ 600 s and SPRAY ≤ 600 s per round (D3), so a 64-round run can occupy ≈10.6 h (SETUP only) or ≈21 h. A run left unattended may look hung. | 🟡 Practical | `stages.rs:145-152`, `:532`, `:549-575`, `:1040-1058` | `setup_attempt` / `spray_iteration` `seq` climbing steadily while `round` stays constant, then `SETUP_BUDGET_EXHAUSTED` / `SPRAY_BUDGET_EXHAUSTED`. Set `--setup-budget` deliberately. |
| **6** | **B3 — a refused leak scores as a successful one** if the device dies between the stall and the leak. | 🟡 Bounded | `stages.rs:271-273`, `:1079`, `:1088`; cf. `gaster.c:282` | `spray_iteration` with `stall_status=STALL`, `leak_status=ERROR`, `leak_xfer=0`, `no_leak_status=ERROR`, `no_leak_xfer=0`, immediately followed by `stage_pass` for SPRAY and then a PATCH failure. `libusb_rc` on those transfers will be the refused shape (0 µs, no abort window). |
| **7** | **A regression in the wire parameters (PATCH `wIndex`, SPRAY lengths) would be caught by nothing** — B4. | 🟡 Latent | `stages.rs:2065-2428` (no PATCH/SPRAY test) | Not detectable from a trace. This is a reason to run `a9pwn selftest` and `a9pwn plan` and to diff `plan`'s field trace against §2 of this document **before** the run. |
| **8** | **`CONFIG_ROW_MISMATCH`** — the failure the task feared. | ⚪ **Closed by measurement** | `config.rs:239`; `types.rs:267-285`; Lead's `ident`/`plan` | Would appear as `event=unsupported` then verdict `CONFIG_ROW_MISMATCH`. **Cannot occur for this unit**: the wire descriptor is the lowercase space form. If it ever appears, the cause is a genuinely different bootrom build string, and the config addresses would be wrong anyway. |

---

## 6. What the ipwndfu comparison changed (finding beyond the ten claims)

HANDOFF §8.8 records at least four errors in `research/A9-CHECKM8-PAYLOAD.md` and instructs that
`GASTER-SPEC.md` be trusted over it. I found nothing further in that class by reading the ten claims
— the ten all check out against `gaster.c`. What I did find is a **provenance error in our own
frozen surface**, which matters more because it is the one a live run depends on:

**`LEAK_WINDEX_IPWNDFU = 0x00` has no support in the vendored ipwndfu, and the vendored ipwndfu has
no A9 support at all.**

* `research/refs/ipwndfu/checkm8.py:122-124` — the leak family, signature at `checkm8.py:47`:
  * `usb_req_stall(device)` = `libusb1_no_error_ctrl_transfer(device, 0x2, 3, 0x0, 0x80, 0x0, 10)`
    — identical to gaster's `checkm8_usb_request_stall` (`gaster.c:893`).
  * `usb_req_leak(device)` = `(…, 0x80, 6, 0x304, 0x40A, 0x40, 1)` → **`wIndex = 0x40A`**,
    `wLength = 0x40`. Matches gaster's leak length (`gaster.c:866`) but **not** its `wIndex`.
  * `usb_req_no_leak(device)` = `(…, 0x80, 6, 0x304, 0x40A, 0x41, 1)` → **`wIndex = 0x40A`**,
    `wLength = 0x41`. gaster uses `0xC1` (`gaster.c:886`); ipwndfu uses `0x41`.
* `research/refs/ipwndfu/checkm8.py:118-120` — the other family (`stall`/`leak`/`no_leak`) also uses
  `wIndex = 0x40A`, with lengths `0xC0`/`0xC0`/`0xC1`.
* **No ipwndfu row exists for CPID 0x8000 or 0x8003.** `all_exploit_configs()` (`checkm8.py:439-449`)
  lists `0x8947, 0x8950, 0x8955, 0x8960, 0x8002, 0x8004, 0x8010, 0x8011, 0x8015`, and
  `exploit_config` (`checkm8.py:451-461`) exits with *"This is not a compatible device"* for anything
  else. **ipwndfu's checkm8 cannot exploit A9**, so it cannot be a second opinion on any A9 parameter.

Therefore:

1. `0x00` is **not** ipwndfu's value and should not be labelled as it. The statement at
   `stages.rs:56-58` is false as written (B5).
2. The genuine alternative to gaster's `0x0A` is `0x40A`, and **`0x40A` is unreachable from the
   CLI** (`main.rs:91-94` offers only `0x0A` and `0x00`). If the run fails and the standing
   hypothesis is "wrong wIndex", the tool as frozen cannot test the hypothesis it would want.
3. Because ipwndfu has no A9 row, `0x0A` is the **only sourced value for this silicon**, which
   strengthens the case for running with the default rather than treating this as a coin-flip.
   (The `0x40A` vs `0x0A` relationship — the same low byte with a `0x400` qualifier — is a lead
   worth recording but is INFERRED, not evidence.)
4. Secondary note for completeness, not a recommendation: ipwndfu's `no_leak` length for the A9-adjacent
   family is `0x41` while gaster's is `0xC1`. We follow gaster (`stages.rs:987`), correctly, since
   gaster is our reference — but if the no-leak semantics ever look wrong, that is a second
   parameter with two divergent sources and no hardware evidence.

**GASTER-SPEC.md:** a full independent citation audit was run (read-only, INSPECTED). **All ten
checked items AGREE with `gaster.c`**, and the spec's citations for
`gaster.c:849/853/857/1111/1211/1268` locate the right code, including correctly attributing
`0x1800E0C00` to ipwndfu/King and `0x1800E0F08` to gaster (`GASTER-SPEC.md:738`, `:757`, `:775-777`,
`:798`, `:807-808`, `:881`) — confirmed against ipwndfu's own value at
`research/refs/ipwndfu-hd/src/ipwndfu/checkm8.py:592`. It remains a SECONDARY source and **none of my
rows rest on it**.

But **HANDOFF §8.8's instruction to trust the spec over `A9-CHECKM8-PAYLOAD.md` should not be read as
"the spec is clean."** It is not. Six errors were found elsewhere in it; two are real and one of those
is a wrong-branch citation of exactly the kind that misleads a porter:

| # | Error in `GASTER-SPEC.md` | Evidence | Severity |
|---|---|---|---|
| **A1** | `GASTER-SPEC.md:719` (G20) cites **`gaster.c:1160`** for the A9 assignment to `usb_serial_number_string_descriptor`. `gaster.c:1160` is the **non-A9** branch's `handle_checkm8_request.memcpy_addr = memcpy_addr;`. The A9 assignment is `gaster.c:1119`. | `gaster.c:1119`; `gaster.c:1155-1160` | **Real.** A wrong-branch citation: a reader checking the spec's claim would land in code for a different SoC and could conclude the value is unused. `1160` looks like a typo for `1119`. |
| **A2** | `GASTER-SPEC.md:689` states the transfer buffer is freed **after** the transfer object is destroyed (`gaster.c:250, 278-280`). It is the reverse: `free(buf)` at `gaster.c:278` runs **before** `libusb_free_transfer(transfer)` at `gaster.c:280`. | `gaster.c:277-281` (verified by direct read) | **Real.** The cited range refutes the sentence it supports. Harmless for our port — we hold the buffer in a `Vec` — but it is an inverted claim about reference lifetime semantics. |
| A3 | `GASTER-SPEC.md:199`+`:202` lists `DFU_UPLOAD 2` as CONFIRMED from "`gaster.c:29-52`". `gaster.c` never defines `DFU_UPLOAD` (0 hits); the value 2 appears only as a bare literal at `gaster.c:1484`. | `gaster.c:29-52`; `gaster.c:1484` | Minor. A constant attributed to a header block that does not contain it. |
| A4 | `GASTER-SPEC.md:956` says "**five** vendored/reference blobs" while `:25-27` records three hashes and `:872` says "3 files". | internal | Minor, internal contradiction. |
| A5 | `GASTER-SPEC.md:602-603` says `usb_abort_timeout_min == usb_timeout` degenerates the cycle "to one value". It is accepted (`gaster.c:1635` uses `>`, not `>=`) but yields **two** distinct windows, not one: `usb_timeout - 1` on the first attempt and `usb_timeout` thereafter. | `gaster.c:849`, `:857`, `:1635` | Minor — and note our `stages.rs:769-802` degenerate-sweep warning and `stages.rs:2130-2148` test describe the same two-window shape correctly, so our code is right where the spec is loose. |
| A6 | `GASTER-SPEC.md:298` calls `0xC1` "the same off-by-one that Y2/Y3 use"; Y2's length is `0x40` (`gaster.c:866`) — only Y3/Y4 use `0xC1` (`gaster.c:886`, `:910`). | `gaster.c:866`, `:886`, `:910` | Minor, imprecise grouping. |

Two further notes the audit established, both useful:

* The spec's §4.2 hexdump/instruction-word claims and all `gaster.c` citations hit their targets
  within a line or two (202 citation sites checked), and its 16-field A9 row matches
  `gaster.c:625-640` exactly field by field. The errors above are the exceptions, not the rule.
* Our `D5` claim that gaster inherits the degenerate-sweep trap is **confirmed** by the reference's
  own argument parsing: `gaster.c:1635-1638` rejects `abort_min > usb_timeout` and silently resets it
  to 0, but permits equality. The spec's wording (A5) is the looser description of the same fact.

### 6.1 `research/A9-CHECKM8-PAYLOAD.md` — four NEW errors, and a certification in the spec that is wrong

HANDOFF §8.8 lists four errors in this document. An independent pass (read-only, INSPECTED) confirmed
all four against `gaster.c` and found **four more that directly contradict `gaster.c`/`payload_A9.S`**,
plus two numeric slips anchored to the vendored ipwndfu rather than to gaster. The task asked for a
fifth error; there are four. Reported as findings, each with both sides:

| # | Error | Document | Correct, with citation |
|---|---|---|---|
| **P1** | **Struct-offset table is wrong.** The doc puts `dfu_handle_request` at `+0x10` and `gUSBSerialNumber` at `+0x18` (and says at `:120` "Both offsets line up"). | `A9-CHECKM8-PAYLOAD.md:115-118`, `:120` | `gaster.c:1011` gives `payload_dest` `+0x10`, `dfu_handle_bus_reset` `+0x18`, `dfu_handle_request` `+0x20`, `gUSBSerialNumber` `+0x40` — which our own builder writes at `payload.rs:241`, `:242`, `:246` and which `payload.rs:549-554` pins. Runtime proof: `gaster.c:1106` copies only `payload_sz = 176` of the 280-byte bin (`gaster.c:1043-1045`) and `gaster.c:1122` lays the 104-byte struct on the bin's last 104 bytes, so `payload_dest` lands at blob offset 192 = struct `+0x10`. **Distinct from the known instruction-attribution error**: this is a field-offset claim. |
| **P2** | **"one 616 B blob at `PAYLOAD_DEST` + 0x800 B `data` buffer"** — wrong size *and* wrong destination. | `A9-CHECKM8-PAYLOAD.md:179` | Size: `gaster.c:1071` callocs `176 + 104 + 192 + 56 = `**`528`**, and `gaster.c:1104-1134` ends with `data_sz = 528`, sent at `gaster.c:1213-1215`. Our port agrees and asserts it (`payload.rs:533`: `assert_eq!(built.blob.len(), 528, "176 + 104 + 192 + 56")`). The `0x800` term belongs only to the **non-A9** branch (`gaster.c:1073`). Destination: the blob is uploaded from offset 0 of the transfer (`gaster.c:1213-1215`); only the 248-byte handler+struct is copied to `payload_dest`, by the payload itself (`gaster.c:1124`, `payload_A9.S:40-45`). So it is neither 616 bytes nor "at `PAYLOAD_DEST`". |
| **P3** | **Clean-room recipe pointer arithmetic.** The doc says gaster's `payload_A9.S` copies the handler to `PAYLOAD_DEST + 0x18` and stores `PAYLOAD_DEST + 0x18` at `PAYLOAD_PTR`. | `A9-CHECKM8-PAYLOAD.md:403` | `payload_A9.S:34`/`:44` copy the handler to `PAYLOAD_DEST` itself, and `:37-39` store `PAYLOAD_DEST + 0xC` into `0x1800878F8`. The `+0x18` is ipwndfu's 24-byte x7-trampoline prefix; gaster's prefix is 3 instructions = `0xC` (`payload_handle_checkm8_request.S:29-31`). |
| **P4** | **"that pointer being zeroed by `checkm8_nopaddingcorruption_arm64.S:36`"** — wrong instruction *and* wrong target. | `A9-CHECKM8-PAYLOAD.md:120` | In the vendored ipwndfu file that line is `LDR X1, =usb_create_string_descriptor` — a load; nothing in that file zeroes memory. The only pointer zeroing in gaster's A9 payload is `payload_A9.S:35-36` `str xzr,[x2]`, which zeroes `dfu_handle_bus_reset` = `0x180087928` (struct `+0x18`), **not** the `PAYLOAD_PTR`/`dfu_handle_request` `0x1800878F8` (`+0x20`) the sentence refers to. Wrong under either reading. |
| P5 | Numeric: "384 + 576 = 912 B" — the arithmetic does not close (384 + 576 = 960; 912 = 384 + **528**). | `A9-CHECKM8-PAYLOAD.md:362` | The constants are right (`checkm8.py:223-224`) and the doc's own `:163` says 528 — the cell conflates a size limit with the delivered size. ipwndfu-anchored, not gaster-anchored. |
| P6 | Numeric: "For 0.00001 this spins for a real 10 µs". | `A9-CHECKM8-PAYLOAD.md:335`, `:231`, `:270` | `checkm8.py:76` spins `timeout/1000.0` = 1e-8 s = **10 ns**, exactly as the doc itself computes at `:331`. The structural point stands; the magnitude is 1000× off. ipwndfu-anchored. |

**🔴 The most valuable finding in this subsection is not in the document — it is in our own spec.**
`GASTER-SPEC.md:750` states: *"`research/A9-CHECKM8-PAYLOAD.md:175-179` says this correctly."* **It does
not.** Line 179 of that range is the 616-byte error (P2) — so the spec certifies the exact line range
that contains an error, **while the spec's own table at `GASTER-SPEC.md:737` states `528`
correctly.** A reader who follows the certification instead of the table inherits the wrong number
with the spec's blessing. Both halves were verified by me directly (`GASTER-SPEC.md:737-751`,
`A9-CHECKM8-PAYLOAD.md:172-181`), not accepted on report.

**Consequence for us: none.** Our builder is correct where the document is wrong — `payload.rs:533`
asserts 528, `payload.rs:549-562` pins every A9 field at its gaster offset, and the Lead's `plan`
produced a 528-byte payload with digest `c4fb5fd4…`, matching the pinned value at `payload.rs:632`.
This subsection is a warning about which documents may be quoted as authority before the run, not a
defect in the port. **Corrected guidance for the tree: the SRTG row and the struct offsets are safe to
quote from `GASTER-SPEC.md`; the `175-179` certification is not, and `A9-CHECKM8-PAYLOAD.md` should
not be cited for anything without re-deriving it from `gaster.c` — it now has eight confirmed errors,
not four.**

---

## 7. Conservatism ledger — what this document does NOT establish

Stated so nobody reads more confidence into it than is there:

1. **Nothing here was run.** No `a9pwn` invocation, no hardware, no device state changed. Every
   "MATCH" is a source-level equivalence, not a verified behaviour. The two MEASURED rows are the
   Lead's, quoted with attribution.
2. **No test suite was executed.** I read tests, I did not run `cargo test`. "Test X pins Y" means I
   read the assertions in X; whether the suite currently passes is `diagnostics-engineer`'s report.
3. **B1's certainty rests on one INSPECTED premise:** that `DFU_GETSTATUS` immediately before the
   post-SETUP reset does not report `bState == 8`. Nothing in SETUP's request sequence
   (`stages.rs:580-695`) sends the manifest-completing 0-length DNLOAD that `dfu_set_state_wait_reset`
   uses (`stages.rs:408`), so I am confident — but it is a premise about device behaviour, not a
   reading of our code. **The trace line named in §5 row 1 settles it either way within seconds of
   the run starting, and it costs nothing to look.**
4. **B2's consequence is UNVERIFIABLE off-hardware.** I assert the deviation; I do not assert it
   breaks the exploit.
5. **The `0x40A`-vs-`0x0A` relationship is INFERRED.** The only MEASURED facts about the parameter are
   that gaster uses `0x0A` and ipwndfu uses `0x40A`.
6. **Coverage is the ten required claims plus what I tripped over.** This is not a full audit of
   `trace.rs` or `verdict.rs`; those judgments were in flight as subagent work when this was written
   and will arrive in the addendum if they land.

---

## 8. Status and remaining work

**DONE — folded into this document, not owed:**

1. ✅ **The `trace.rs` / `verdict.rs` counter audit.** Folded in as **§10 (Appendix A)**. It answered
   the decisive question the right way: `setup_stall_seen` increments **only** in the pad branch
   (`trace.rs:863`, gated at `:842`/`:849-856`), so **`SETUP_NEVER_STALLED` does not lie** on the
   shipped caller path. It also found three verdict codes that can never fire in a real run
   (**B7**, §10.2) and two counters that cannot distinguish two different failures (§10.3c, §10.3d).
   Audit revision: `trace.rs` `480DD6A0…` (uncommitted), `verdict.rs` `2E0FDDB7…`.
2. ✅ **The `GASTER-SPEC.md` citation audit.** Folded into **§6**. All ten checked items AGREE, but
   the spec is not error-free: six further errors, two of them real (A1 wrong-branch citation, A2 an
   inverted lifetime claim). A1 and A2 were re-verified by me directly against `gaster.c:1117-1121`
   and `:1158-1162` / `:277-281` rather than accepted on report.
3. ⏳ **`research/A9-CHECKM8-PAYLOAD.md`.** My own reading found **no fifth error** beyond HANDOFF
   §8.8's four; the four known ones are consistent with `gaster.c` as described there (`payload_dest`,
   the "6-byte" overwrite that is 48 bytes, the instruction attribution, and the false claim that the
   A9 spray cannot loop forever — the last is refuted by `gaster.c:902`'s unbounded
   `while(...) {}`). A second, independent pass over that document was still running when this was
   written; if it produces a fifth error it becomes §10.4, and **no row in this document depends on
   it either way.** Stated as pending rather than guessed.

**OWED — the addendum proper:**

4. **Re-verify the `stages.rs` delta.** When stages-engineer reports the new hash, re-read **only**
   these regions and state whether the fix restored reference behaviour (`gaster.c:197-200`, `:1268`,
   `:866`) or introduced a new deviation:
   * the three reset-gate call sites — `stages.rs:1555`, `:1729`, `:1766`/`:1840`;
   * `leak_wvalue` (`stages.rs:964-966`) plus its two callers (`stages.rs:970`, `:979`);
   * **the two `tracer.reset(report.bus_reset_delivered, …)` sites (`stages.rs:1542`, `:1829`) and
     `Tracer::reset` itself (`trace.rs:574-581`)** — B6 is not fixed by changing only the abort
     condition, so the addendum must check the *labelling* as well as the *gate*.
   Output: `VERIFICATION-live-run-addendum.md`. The whole file will **not** be re-verified. As of this
   writing `stages.rs` is **still** at `A64476ECBD992A11…` — the fix has not landed.

---

## 9. Bottom line for the Lead

Read §5 rows 1 and 1b before issuing any command. **As `stages.rs` stands at `A64476ECBD992A11…`,
the exploit cannot complete: the run aborts after SETUP because the post-stage reset is classified
`Unverified` and `Unverified` is treated as failure.** That is one condition in two places
(`stages.rs:1555`, `stages.rs:1840`), it contradicts `ResetEvidence`'s own four-way design, and it
contradicts gaster, which ignores the reset result entirely (`gaster.c:197-200`). Its twin (B6) means
that even the *record* of that abort will misname the cause — the trace will say
`reset_pipe_cycle`, accusing libusbK of cycling pipes when the measurement says the opposite. **Fix
B1 and B6 together**, or the first live attempt produces a log that sends you after the wrong
component.

Everything the Lead asked to be checked against the reference checks out: the STALL pass condition
(`gaster.c:853`), the `4,5,0,1,2,3` sweep (`gaster.c:849,857`), `payload_dest = 0x1800E0F08`
(`gaster.c:1111`, MEASURED on the device), PATCH `wIndex = 0x80` (`gaster.c:1211`), the reset after
every attempt (`gaster.c:1268`), the single A9 spray triple with no 40× loop and no
`config_hole`/`config_large_leak` (`gaster.c:900-910`), the 104/56/48-byte structs and every field
offset (`gaster.c:1010-1021`, `:1108-1132`), the SRTG key (`gaster.c:624,641` — cannot refuse this
unit), and the loud blob verification (`payload.rs:97-130`).

Three things stand between this port and that run: **B1 and B6, which are mechanical and certain and
must be fixed as one change (the reset gate and the reset label); the one genuinely unresolved
parameter in §3/Q8; and B2, a deviation inside the loop that must not deviate.**

---

## 10. APPENDIX A — folded in: the `trace.rs` / `verdict.rs` audit

The tracer audit promised in §8 item 2 landed. It was read at
`trace.rs` SHA-256 `480DD6A09C001C1FCEB3FE7A85B38D7737D8AD071FFF1E365BA50375C94CAA2A`
(1402 lines, 56 541 bytes) — **a different revision from the one frozen for this task**
(`C2420E80…`, 1353 lines, 54 010 bytes), and one that is **uncommitted work**: the git index holds
`src/trace.rs` at blob `cc2bf469…` while the worktree holds `9c0e58ca…`. The revision was stable
across the read (hash identical before and after). Verdict.rs was also re-read at its new hash. Line
numbers in this appendix are for `480DD6A0…`, **not** the frozen file, and every `verdict.rs:NNN`
below is from `2E0FDDB7…`. Both are INSPECTED, not run.

### 10.1 Verified good — including the one question that decides whether a verdict can lie

* **`setup_stall_seen` is incremented ONLY by the pad request.** The pad branch is entered only when
  `labelled` (label contains `"pad"`) **or** `structural` holds — `abort_after_ms.is_none() &&
  (bm & 0x80) == 0 && b_request != DFU_DNLOAD && w_length != EP0_MAX_PACKET_SZ` (`trace.rs:849-856`)
  — and the async path returns early at `trace.rs:842`. On the shipped caller this is exact:
  `stages.rs:580-589` sends the swept abort as `"setup_abort_dnload"` (`0x21/DFU_DNLOAD/0x800` →
  async → return), and `stages.rs:631-632` sends the pad as `"setup_pad_request"` (contains `"pad"`,
  `bm = b = 0`) → `trace.rs:863`. **So `SETUP_NEVER_STALLED` cannot be satisfied by an unrelated
  STALL: the verdict does not lie on this axis.** A test pins the 0x800 case explicitly
  (`trace.rs:1114`, *"the 0x800 async must never count as a pad request"*). Two caller-side holes
  remain latent: any *other* SETUP OUT transfer whose label happened to contain `"pad"` would
  inflate it (`trace.rs:849`), and an unlabelled genuine pad of exactly `w_length == 0x40` would be
  excluded by `trace.rs:853` (impossible via `stages.rs`, whose label is fixed).
* **Nothing is dropped and nothing is sampled.** There is no ring buffer, no bounded queue, no
  sampling: `xfer()` always writes (`trace.rs:493-514`) and `write_line` always attempts
  (`trace.rs:800-805`). With `trace_path` set, **every transfer that reaches `xfer()` reaches the
  file**, except on a counted write error, a missed final flush, or abrupt process death.
* **The frozen interface is intact.** All six methods of `INTERFACE.md:254-264` are present
  (`trace.rs:440/472/526/669/674/773`) and the frozen `Counters` fields (`INTERFACE.md:266-276`) are
  untouched. Eight public methods are **additive** — `t_micros:458`, `lines_written:463`,
  `reset:574`, `round:584`, `enumerated:594`, `device_path:612`, `open_failed:619`, `predicate:632`
  — and additive is not a contract violation. Callers: `predicate` (`stages.rs:423/432/564/651/670/
  1061/1181/1528/1816`), `round` (`stages.rs:1457`), `reset` (`stages.rs:1542/1829`).
* **The two failing tests were already repaired at this revision.** From the git baseline
  (`cc2bf469…`): `open_failure_and_path_length_are_recorded_with_their_source` contradicted itself —
  it set a 271-byte path then asserted `!device_path_overflows_libusb()` against a 256-byte capacity
  and a `len >= 256` predicate; and `stage_status_helper_names_where_a_status_happened` asserted
  `"SETUP=1 PATCH=1"` while the implementation rendered in `BTreeMap` key order (`"PATCH" < "SETUP"`).
  Both now pass by construction (fixture reduced to 121 at `trace.rs:1304`, rendering in
  `STAGE_ORDER` at `trace.rs:284-308`). The other twenty tests in `trace.rs:892-1402` were traced
  against the code and none can fail at this revision. **INSPECTED, not run** — no `cargo test` was
  executed.

### 10.2 🔴 B7 — three verdict codes can never fire in a real run

`Tracer::enumerated` (`trace.rs:594`), `Tracer::device_path` (`trace.rs:612`) and
`Tracer::open_failed` (`trace.rs:619`) are the **only** writers of `Counters::discovery_recorded`,
`device_path_len`, `last_open_errno` and `last_open_error`. I grepped every file in `src/` for call
sites: **the only callers are `trace.rs`'s own tests** (`trace.rs:1276`, `:1286`, `:1297`, `:1304`,
`:1305`, `:1335-1339`). No shipped path — not `main.rs`, not `stages.rs`, not `usb.rs` — ever calls
them. (`usb.rs:323` counts into a local variable only.)

Consequences:

1. `counters.discovery_recorded` is **always false** in production, so the entire block at
   `verdict.rs:220-232` is unreachable, and with it **`DEVICE_PATH_TOO_LONG`** (`verdict.rs:695`
   and `:62`), **`WRONG_DRIVER_BOUND`** (`verdict.rs:743`, `:57`) and **`DRIVER_BOUND_NOT_LOADED`**
   (`verdict.rs:804`, `:59`). These are three of the four helpers that HANDOFF §7 blocker #1 lists as
   the work of `diagnostics-engineer`. They are implemented, they compile, and **their unit tests are
   green because the tests set `c.discovery_recorded = true` by hand** (`verdict.rs:1799`, `:1814`,
   `:1828`, `:2008`, `:2023`, `:2037`). Green tests over an unreachable branch.
2. The realistic failure — **the a5AC:1227 node is present but the open fails**, e.g. the driver
   binding regressed to WinUSB/oem45.inf, or a stale node — falls through to
   `verdict.rs:234-242` and is reported as **`DEVICE_ABSENT`**, "the device is not there", when the
   device *is* there. The census evidence string in that verdict will read `"no census taken"`
   (`verdict.rs:361-363`), which is at least honest about why no census exists. That is exactly the
   four-problems-one-message collapse HANDOFF §9.6 forbids, in the layer built to prevent it.
3. **Fix belongs in the caller, not in `trace.rs`** — something in the open/enumeration path must
   call those three methods. Out of my write scope (`main.rs` is Lead-only, `usb.rs` is
   transport-engineer's).

**Trace observable:** the absence of a `"kind":"enumerated"` line in a run that failed to find or
open the device, followed by a verdict of `DEVICE_ABSENT`. A trace whose only discovery-side evidence
is `"no census taken"` cannot distinguish "no phone attached" from "phone attached, driver wrong".

### 10.3 Other folded-in findings, each with its consequence

| # | Finding | Citation (`480DD6A0…`) | Consequence for the live run |
|---|---|---|---|
| a | **The JSONL key SET varies per line.** The *order* of present keys is fixed and asserted, but optional keys are omitted when `None`. | `Line` struct `trace.rs:386-420`; optional-skip `:392-419`; positional order test `:988-1013` | Reading the trace: never assume a field is present (`w_index`, `abort_after_ms`, `libusb_rc`, `transferred` are all optional). A viewer that requires a fixed column set will mis-parse. Relevant to `tooling-engineer`'s JSONL viewer. |
| b | **A second `Tracer` on the same path silently destroys the first run's lines.** `File::create` truncates; there is no append mode and no in-log notice. | `trace.rs:435-442` | **Operational:** do not reuse a trace path across attempts. A round-1 trace overwritten by a round-2 invocation is evidence destroyed with no record that it existed. |
| c | **`abort_window_pinned()` cannot tell "the modulus collapsed" from "the windows were never recorded".** `setup_attempts >= 2 && abort_sweep.len() == 1` is satisfied by one windowed attempt plus N unwindowed ones. | `trace.rs:325-327`; consumer `verdict.rs:294`; the discriminator `setup_async_unreported` exists at `trace.rs:825` but is not consulted | If SETUP fails, `ABORT_WINDOW_PINNED` may assert a collapsed sweep on evidence that only shows one window was *reported*. Read the `abort_after_ms` field on the `setup_abort_dnload` lines before believing it — see §5 row 4. |
| d | **`SPRAY_LEAK_NOT_ZERO` merges two different defects.** `spray_leak_requests` / `spray_leak_not_zero` count gaster's 0x40 leak (`gaster.c:866`) and its 0xC1 no-leak (`gaster.c:886`) as one thing, and the verdict's evidence names both lengths in one sentence. | `trace.rs:880-887`; consumer `verdict.rs:1310-1330` | Blunts the Q8 diagnostic: the *counter* cannot say which request misbehaved. **The per-line `spray_iteration` JSONL still can** (`leak_status`/`leak_xfer` vs `no_leak_status`/`no_leak_xfer`, `stages.rs:1075-1098`), which is why §5 row 2's observable is written against the raw lines rather than the verdict. |
| e | **`spray_stall_not_stalling` counts ANY non-`Stall` status but the verdict blames the bootrom.** `Error`/`Cancelled` (host-side, or a dead handle) produce the same code as a genuine NAK. | `trace.rs:874-877`; consumer `verdict.rs:1291-1301` | If SPRAY dies on B2/B3 grounds the verdict may accuse the bootrom of "not diverting the request" when the transport never delivered it. |
| f | **`setup_pad_errors` merges `Error` and `NoDevice`, but the verdict says "failed at the host".** | `trace.rs:865`; consumer `verdict.rs:1214` | A device that vanished mid-pad is reported as a host-side error. Low impact: `verdict.rs:247-249` pre-empts `NoDevice` earlier on most paths. |
| g | Dead contract-violating fallback: on a serialize error the hand-built line carries `seq`/`stage`/`kind`/`detail` and **no `t_micros`**. Practically unreachable (serde cannot fail for this struct). | `trace.rs:792-798` | None today; recorded because it is the one path that could emit a line missing a required key. |
| h | Cosmetic disagreement: `summary_lines`' per-stage line renders in `BTreeMap` (lexicographic) order while `stages_with_status` renders in pipeline order — two renderings of the same data, different order. | `trace.rs:702-707` vs `:284-308` | Cosmetic only. |

**What this appendix does not claim.** No test was run; "cannot fail" in 10.1 means I read the
assertions and the code together. The audit covered the shipped paths I could trace by grep; a
caller outside `src/` (there is none in this crate, but `lib.rs` re-exports exist) was not searched.
`main.rs` is Lead-owned and was read for call sites only.
