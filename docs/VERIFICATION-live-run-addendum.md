# VERIFICATION — ADDENDUM 1

**Parent:** `a9pwn/docs/VERIFICATION-live-run.md` (task-2). **Author:** `gaster-analyst`.
**Subject:** the post-stage reset gate claim, two new hardware-gate defects, and the `stages.rs` delta.
**Read-only. No hardware touched. Nothing run.**

---

## 0. Provenance — and why the delta verdict is PROVISIONAL

Everything in §1, §2 and §3 is **hash-independent**: it rests on `gaster.c` (Apache-2.0, unchanged),
`types.rs` `B316AB36D4F56D2E…` (unchanged), and `usb.rs` `9C9B290895E48527…` (unchanged). Those
verdicts are final.

The `stages.rs` delta in §4 is **provisional**, because `stages.rs` and `trace.rs` were being
rewritten *while this addendum was written*. MEASURED, by repeated `Get-FileHash`:

| File | Revisions observed (SHA-256 prefix, line count) |
|---|---|
| `src/stages.rs` | `A64476ECBD992A11…` 2428 (the frozen pre-fix file) → `CE5CE6C315393238…` 2809 → `33C9B309F41B8C63…` 2720 → `5DAF61C4EC81E95F…` 2770 → **unreadable: "being used by another process"** |
| `src/trace.rs` | `C2420E80E1CFFCD3…` 1353 (frozen) → `480DD6A09C001C1F…` 1402 → `063D1918CC649C94…` 1430 → `4EAB4C26C09E7F17…` 1470 → `19FA3A55A27C03AF…` 1480 |

Individual reads of `stages.rs` returned **four different totals within twenty minutes**
(2809 → 2769 → 2763 → 2720 → 2770). **This is a moving target, and the project's own rule is not to
verify one.** So §4 records *which revision each observation was made against* and declines to issue a
final verdict. That is not hedging: a line number in a file that is being rewritten is not evidence,
and the parent document's §0.1 already says so.

---

## 1. The Lead's claim, verified — 1 and 2 CONFIRMED, 3 CONFIRMED and it corrects my own report, 4 REFUTED as phrased (conclusion still right)

### Claim 1 — the shape of `checkm8_stage_reset`. **CONFIRMED**

`gaster.c:840` is one `&&` chain, and its order is exactly as stated:

| Step | Source | Requirement |
|---|---|---|
| 16-byte DNLOAD | `gaster.c:840`; `DFU_FILE_SUFFIX_LEN` = 16 at `gaster.c:41` | `ret == USB_TRANSFER_OK && sz == 16` |
| MANIFEST walk | `gaster.c:833` (`dfu_set_state_wait_reset`) | zero-length DNLOAD (OK, `sz == 0`), then `GET_STATUS` must report `DFU_STATUS_OK` **and** state 6, then 7, then 8 |
| 64-byte DNLOAD | `gaster.c:840`; `EP0_MAX_PACKET_SZ` = 0x40 at `gaster.c:40` | `ret == USB_TRANSFER_OK && sz == 0x40` |

State constants: `DFU_STATE_MANIFEST_SYNC` = 6 (`gaster.c:45`), `DFU_STATE_MANIFEST_WAIT_RESET` = 8
(`gaster.c:48`), `DFU_STATE_MANIFEST` = 7. Our port reproduces the same order and the same three
requirements: `stages.rs:451-463` (suffix), `:465` (walk), `:478-491` (64-byte flush) — the *pre-fix*
revision, where I read them in the parent document. **INSPECTED.**

### Claim 2 — the 64-byte DNLOAD un-parks the machine. **CONFIRMED in substance** (the measurement is the Lead's; my inference is INFERRED)

The flush is sent **after** the walk has verified state 8, and it is not optional: the reference
demands it be accepted with all 0x40 bytes (`gaster.c:840`). In DFU 1.1 a DNLOAD received in
`dfuMANIFEST-WAIT-RESET` re-enters a download, so the machine leaves state 8. The Lead MEASURED state
**5** read by the very next `GET_STATUS`, which is `dfu_status_state` at `usb.rs:1036` inside
`Transport::reset` (`usb.rs:1035-1036`) — i.e. read before `libusb_reset_device` is called, so it is
the state the reset actually saw. State 5 is `dfuDNLOAD-IDLE` in the DFU 1.1 numbering, which is the
numbering this bootrom demonstrably uses: gaster checks for 6 and 8 (`gaster.c:45`, `:48`), both
standard.

**The one alternative explanation, considered and rejected.** Could the `GET_STATUS` read itself have
moved the state from 8 to 5, making the flush innocent? No: if a `GET_STATUS` were state-changing, the
walk's own three reads could not have observed 6 → 7 → 8 in that order, and on this hardware they did
(§3, finding B). There is no coherent story in which a read produces exactly the manifest progression
and then silently rewinds to 5. The state change is therefore attributable to the 64-byte DNLOAD —
**INFERRED**, from one MEASURED reading plus the reference's own acceptance condition.

### Claim 3 — `Delivered` is unreachable after RESET, and only reachable after PATCH. **CONFIRMED — and it corrects an error in my parent report**

`reset_evidence` (`types.rs:445-450`) returns `Delivered` **only** for
`(Some(MANIFEST_WAIT_RESET), Some(APP_IDLE | DFU_IDLE))`. Because the flush precedes the state read,
the `dfu_state_before` after the RESET stage is 5 (measured), not 8 → the match falls to
`_ => Unverified` (`types.rs:454-458`). So:

* **After RESET: `Delivered` is impossible by construction.** CONFIRMED.
* **After PATCH: `Delivered` is achievable**, because PATCH's trailing walk (`gaster.c:1220-1222`;
  our `stages.rs:1406-1408` pre-fix) parks state 8 and **nothing follows it before the reset at
  `gaster.c:1268`** — no flush. CONFIRMED. So the gate's `Delivered` is reachable exactly once per
  round, on the reset that fires the overwritten `dfu_handle_bus_reset` (`gaster.c:1112` + `:1268`).

**⚠ THIS CORRECTS MY PARENT REPORT, and the Lead's measurement is why.** The parent document's B1 and
§5 row 1 say the pre-fix run "aborts at round 2" and that "round 1 is RESET: it *does* park the
machine, so its reset is `Delivered` and round 1 passes." **That is wrong.** Round 1's own reset —
the one after RESET — is classified `Unverified`, because `stage_reset`'s flush un-parks the machine
before `Transport::reset` reads it. The consequences are worse than I reported:

| Command | What the pre-fix code actually did |
|---|---|
| `a9pwn run --rounds 64` | Aborts at the **end of round 1**, after RESET. **SETUP is never attempted.** |
| `a9pwn run --stage setup --stop-after-setup-stall` | Aborts on the RESET **precondition** reset (the call now at `stages.rs:1879`), before SETUP runs. The diagnostic never ran. |
| `a9pwn run --stage reset` | Aborts on its own post-stage reset, after a successful RESET. |
| `a9pwn run --stage spray` / `--stage patch` | Same — the precondition reset aborts first. |

So under the pre-fix code **no multi-stage command could complete a single round.** Corrected in the
parent document; the correction is logged there rather than silently patched.

### Claim 4 — "fires where it is least meaningful and can never fire where it is most meaningful". **REFUTED as phrased. The conclusion drawn from it is nevertheless correct.**

The sentence is inverted, and the inversion matters because it *understates* the severity.

* What is true: `Delivered` is achievable **only** on the post-PATCH reset — and that is the **most**
  meaningful one, the trigger that fires the overwritten `dfu_handle_bus_reset` (`gaster.c:1112`,
  `:1268`). So the gate is *satisfiable* exactly where it matters, not where it does not.
* What is also true: the gate **aborted** on the three maintenance resets (post-RESET, post-SETUP,
  post-SPRAY), where the evidence can never be `Delivered`. And since RESET is round 1, it aborted
  before ever reaching the one reset that could have been verified.
* So the accurate statement of the defect is: **"the gate aborted on every reset whose evidence could
  never be `Delivered`, and therefore never reached the one reset that could be"** — not "it fires
  where it is least meaningful". The predicate was pointed the right way; the *abort* was applied to
  the wrong evidence class. If the premise "fires where it is least meaningful" were taken at face
  value, a reader could conclude the gate was harmless-but-misplaced. It was not: it was fatal in
  round 1.
* **The conclusion stands and is correct:** continuing on `Unverified` while stopping on
  `Refuted`/`DriverCannotReset` **matches** the reference — gaster discards the reset result and
  resets unconditionally (`gaster.c:197-200`, `:1268`) — and it does not weaken the check, because the
  two cases that *do* stop are the two that are positive evidence of non-delivery. It is also more
  honest than the reference: gaster cannot tell a pipe cycle from a reset at all
  (`windows_winusb.c:3419`).

**Verdict on the claim: 1 ✓, 2 ✓, 3 ✓, 4 ✗ as stated / ✓ as concluded.** The code change the Lead
derived is right; the sentence used to justify it is not, and should not go into the record as
written.

---

## 2. Finding A — `usb.rs:264 dfu_state_name` is scrambled: a defect with its own row. **CONFIRMED**

`usb.rs` is at `9C9B290895E48527…` — **unchanged**, so this is still live. The table's non-constant
arms are wrong against the DFU 1.1 numbering that the rest of the codebase uses:

| `bState` | DFU 1.1 name (correct) | `usb.rs:264-278` says | Line |
|---|---|---|---|
| 0 | appIDLE | `appIDLE` ✓ | `usb.rs:266` |
| 1 | appDETACH | **`dfuDNLOAD-IDLE`** ✗ | `usb.rs:271` |
| 2 | dfuIDLE | `dfuIDLE` ✓ | `usb.rs:267` |
| 3 | dfuDNLOAD-SYNC | **`dfuDNBUSY`** ✗ | `usb.rs:272` |
| 4 | dfuDNBUSY | **`dfuDNLOAD-SYNC`** ✗ (3 and 4 swapped) | `usb.rs:273` |
| 5 | **dfuDNLOAD-IDLE** | **`dfuMANIFEST-SYNC`** ✗ | `usb.rs:274` |
| 6 | dfuMANIFEST-SYNC | `manifestSync` ✓ | `usb.rs:268` |
| 7 | dfuMANIFEST | `manifest` ✓ | `usb.rs:269` |
| 8 | dfuMANIFEST-WAIT-RESET | `manifestWaitReset` ✓ | `usb.rs:270` |
| 9 / 10 | dfuUPLOAD-IDLE / dfuERROR | ✓ | `usb.rs:275-276` |

**No logic is affected, and I confirm the Lead's reason:** every decision in the reset path compares
**numeric constants**, never names — `reset_evidence` at `types.rs:445-451` uses
`DFU_STATE_MANIFEST_WAIT_RESET`/`APP_IDLE`/`DFU_IDLE`, whose values are pinned by test at
`types.rs:903-907`, and `dfu_state_name` is not used in any comparison anywhere.

**Blast radius, which the Lead asked me to bound.** `dfu_state_name` has **exactly one production
caller**: the `state` closure inside `reset_note` (`usb.rs:186`, used at `usb.rs:189`), which builds
`ResetReport::note` (`usb.rs:162`). That note is embedded in the reset trace lines
(`stages.rs:1539`/`:1552` pre-fix) and in the reset `Aborted` messages. **No other diagnostic string
in the crate is derived from it** — verified by grep across `src/` (the remaining hits are type
declarations and the test at `usb.rs:1848-1852`). So the wrong names can only ever have appeared on
reset lines and reset failure messages, which is exactly where the Lead saw one.

Two further observations that sharpen the fix:

1. **The test that should have caught this does not.** `dfu_state_names_are_accurate`
   (`usb.rs:1848-1852`) asserts only `dfu_state_name(0)`, `(2)`, `(8)` and `(0xFE)` — **precisely the
   four entries that were already right.** The four wrong arms (1, 3, 4, 5) are asserted by nothing.
   The fix should add those four assertions, or the bug will be reintroduced the same way.
2. **A second, correct table now exists in `stages.rs`.** The `stages.rs` I read at `33C9B309…`
   defines its own `dfu_state_label` (`stages.rs:2036-2046`) which is **right** — `5 =>
   "dfuDNLOAD-IDLE"` — and it feeds `dfu_state_pair`/`reset_facts`. So the codebase now carries two
   `bState` tables, one correct and one wrong. They must be reconciled to one (the `stages.rs` one),
   or a future reader will pick the wrong one. **This is a note about a revision that was mid-flight;
   re-check it against the final hash.**

**Trace observable if it is not fixed:** a reset line reading `DFU state 5 (dfuMANIFEST-SYNC)` for a
state whose correct name is `dfuDNLOAD-IDLE` — self-evidently wrong once you know that
`dfuMANIFEST-SYNC` is 6, which the same line's other half may print as `6 (manifestSync)`.

---

## 3. Finding B — the RESET-stage verification is REAL. **CONFIRMED by independent reading**

The Lead is right to insist on this, because it is what makes Claim 2 a measurement rather than an
assumption. `dfu_check_status` does not merely check that *a* reply arrived:

```
stages.rs:441-444   (pre-fix revision A64476EC…)
    let ok = r.status == XferStatus::Ok
        && r.transferred == 6
        && buf[0] == status
        && buf[4] == state;
```

* `r.transferred == 6` — the full `DFU_GETSTATUS` reply, not a truncated one.
* `buf[0] == status` — the **bStatus** byte must equal `DFU_STATUS_OK`.
* `buf[4] == state` — the **bState** byte must equal the requested state, and byte 4 is where DFU 1.1
  puts `bState` in the 6-byte reply (`bStatus`, `bwPollTimeout[3]`, `bState`, `iString`).

And the walk requires all three in order, refusing at the first mismatch
(`stages.rs:459-471` pre-fix): `MANIFEST_SYNC` (6) → `MANIFEST` (7) → `MANIFEST_WAIT_RESET` (8). The
Lead reports all three passed on hardware. That is a **real** verification: the device positively
reported `bState = 6`, then `7`, then `8`. It is not a decorative check, and it is the reason Claim 2's
state-5 reading carries weight — the same instrument that read 5 read 6, 7 and 8 in sequence first.

**One precision on the citation:** the Lead's `stages.rs:406-409` was the position in an intermediate
revision. In the frozen pre-fix file (`A64476ECBD992A11…`, the revision the parent document describes)
the comparison is at **`stages.rs:396-399`** and the walk at **`:415-431`**; in the revision I read at
`33C9B309…` it had moved to **`:441-444`**, and the PATCH walk to `:1406-1408`. Cite the function name,
not the line, until the file settles. **INSPECTED.**

---

## 4. The `stages.rs` delta — verification of the three regions, PROVISIONAL

The Lead asked for exactly three regions plus the new wrapper. I read each in the revisions recorded
below. **Verdicts are provisional** because the file kept moving (§0).

### 4.1 The reset gate — **FIXED, and it restores reference behaviour**

Read at `stages.rs` `33C9B309F41B8C63…` (2720 lines) and `5DAF61C4EC81E95F…` (2770 lines).

`stages.rs:1970-1982` (in `33C9B309…`) defines a pure gate:

```rust
pub fn reset_gate(evidence: ResetEvidence, allow_winusb: bool) -> ResetGate {
    match evidence {
        ResetEvidence::Delivered            => ResetGate::Continue,
        ResetEvidence::Unverified           => ResetGate::ContinueLoudly,
        ResetEvidence::Refuted | ResetEvidence::DriverCannotReset =>
            if allow_winusb { ResetGate::ContinueLoudly } else { ResetGate::Stop },
    }
}
```

* The `bool` collapse is gone: the gate takes `ResetEvidence` itself. `Unverified` **continues**
  (loudly), `Refuted` and `DriverCannotReset` **stop**, and `--allow-winusb` downgrades the stop to a
  loud continue instead of silently removing the evidence.
* **This matches the reference** — gaster discards the result and continues (`gaster.c:197-200`,
  `:1268`) — **and it is strictly more informative than the reference**, which cannot distinguish a
  pipe cycle from a reset at all. It is **not** a weakening: the two stopping cases are precisely the
  two that are positive evidence of non-delivery.
* Both call sites now route through one function, `reset_after_attempt`
  (`stages.rs:2101-2157` in `33C9B309…`): the round loop at `stages.rs:1702` and the single-stage
  precondition at `stages.rs:1879` (observed in a later revision). The parent report's B1 was the same
  wrong condition written twice; it is now written once. That is the right fix for a duplicated defect.
* **B6 is fixed in the same change**, and correctly: `record_reset` (`stages.rs:2091-2092`) calls
  `tracer.reset(r.evidence, …)` — the enum, not a `bool` — and `Tracer::reset` now maps all four
  variants to four distinct kinds (`trace.rs:651-657`, read at `19FA3A55A27C03AF…`):
  `Delivered → reset_real`, `DriverCannotReset → reset_pipe_cycle`, `Refuted → reset_refuted`,
  `Unverified → reset_unverified` (constant at `trace.rs:91`). **`Unverified` can no longer be logged
  as a pipe cycle**, so the trace no longer false-accuses the driver. This is exactly what B6 asked
  for. Note the new kind `reset_unverified` is an *addition* to the tracer's vocabulary
  (`trace.rs:91`) — additive, not a contract change, and `verdict.rs` will need to count it if
  `RESET_NOT_DELIVERED` is to stay meaningful (`verdict.rs:279-283` reads `resets_real` and
  `resets_pipe_cycle` only).

**New deviation introduced by the fix?** None found in these two regions. Two things to watch, both
flagged rather than asserted because of the churn:

1. `ResetGate::Stop` is still reachable from `Refuted`. `Refuted` requires `before == 8`, which
   (per §1 Claim 3) can only happen on the post-PATCH reset. So a post-PATCH `Refuted` — the device
   still parked after the reset that was supposed to fire the callback — correctly stops the run. That
   is the *most* valuable stop the tool has, and the fix preserves it. Good.
2. `reset_warning` is now printed to **stdout** on every `Unverified` reset (`stages.rs:2142-2192` in
   `33C9B309…`). Every round will print a warning line. That is intended ("never silent") but it makes
   a 64-round run noisy; the JSONL event `bus_reset_not_proven` is the greppable signal.

### 4.2 `leak_wvalue` — **FIXED; the two extra EP0 transfers are gone**

Read at `stages.rs` `33C9B309F41B8C63…`.

```rust
pub fn leak_wvalue(ident_index: u8) -> u16 { (3u16 << 8) | ident_index as u16 }   // stages.rs:1068-1070
```

Callers now pass the **cached** index: `usb_request_leak` at `stages.rs:1081` and `no_leak` at
`stages.rs:1089` both use `io.usb.ident_index()`, which is `self.ident_index.get()` — a `Cell` read
(`usb.rs:587-589`), no control transfer. The primitive is pure and testable. So the spray is back to
gaster's **three** EP0 requests per iteration (`gaster.c:902`), and B2's deviation is closed.

**One residual, minor and worth recording — the cached variable is not the one gaster uses.**
gaster's `wValue` is `(3 << 8) | device_descriptor.i_serial_number` (`gaster.c:866`) — the index
**declared in the device descriptor**. Our `ident_index()` is the index that **answered the
identification read** (`usb.rs:585-589`). They are set to the same value at open (`usb.rs:430` from
`declared_i_serial` at `usb.rs:423`) and only diverge if the declared index failed and a fallback
(3 or 4, `usb.rs:87-88`) answered instead — because `serial_descriptor()` tries the declared index
**first** (`usb.rs:495-497`) and only overwrites `ident_index` on a fallback hit (`usb.rs:511`, `:524`).
On this unit: the descriptor parsed, `usb.rs:586` records the device descriptor as declaring **4**, so
`ident_index == declared == 4` and the `wValue` byte is gaster's. **MATCH in effect on this hardware,
via a differently-defined variable.** If a future run's `ident` ever read the descriptor from index 3
while the descriptor declares 4, the leak would carry 3 where gaster sends 4 — an observable
divergence from the reference in the one request that must not diverge. The zero-cost way to remove
the residual is to expose the cached `declared_i_serial` (`usb.rs:423`/`:437`) and use that; the
`Transport::identity().i_serial` accessor would work but costs a wire read, which is the whole point
of the fix, so a cached getter is the right form.

### 4.3 The rest of the delta — `--stop-after-setup-stall` and `run_with_tracer`

* **`--stop-after-setup-stall` is now reachable on the single-stage path.** The flag's honouring site
  is `stages.rs:1448` (`passed && stage == Stage::Setup && opts.stop_after_setup_stall`), and the
  round-loop `stop_here` handling follows the reset (`stages.rs:1750-1760` in one revision). Because
  the gate no longer aborts on `Unverified`, control now reaches the diagnostic stop instead of the
  reset refusal — which was the parent report's B1 secondary consequence. **PROVISIONAL**: the
  ordering of the post-stage reset versus the `stop_here` check is exactly the kind of thing the
  current churn can change, and it should be re-read against the final hash.
* **`run_with_tracer` — NOT FOUND.** The Lead asked me to re-verify "the new `run_with_tracer`
  wrapper". A grep across `src/` finds **no symbol of that name** in any revision I read. Either it
  was renamed before landing, exists only as a proposal, or is still in flight. **Reported as
  not-found rather than assumed to exist.** If it is meant to exist, this is the check that says it
  did not land yet.

### 4.4 What the parent document now needs

The parent `VERIFICATION-live-run.md` cites `stages.rs` line numbers throughout, all of them against
`A64476ECBD992A11…` (2428 lines). **Every `stages.rs:NNN` citation in it is now stale** — the file has
been at four revisions since, and one delta shifted `dfu_check_status` from `:396-399` to `:441-444`.
The parent document carries a prominent note to that effect; the substantive rows there are
unaffected, because `payload.rs`, `config.rs`, `usb.rs` and `types.rs` are all still byte-identical to
the values verified. **Cite functions, not lines, for `stages.rs` until the file stops changing.**

---

## 5. Summary

| Item | Verdict | Label |
|---|---|---|
| Claim 1 — `checkm8_stage_reset` shape | **CONFIRMED** | INSPECTED (`gaster.c:833`, `:840`, `:41`, `:40`, `:45`, `:48`) |
| Claim 2 — the 64-byte flush un-parks the machine | **CONFIRMED** (measurement is the Lead's; the rejection of the alternative explanation is mine) | MEASURED (Lead) + INFERRED |
| Claim 3 — `Delivered` unreachable after RESET, reachable only after PATCH | **CONFIRMED**, and it corrects my own B1: the pre-fix abort was in **round 1**, and no multi-stage command could finish a round | INSPECTED (`types.rs:445-458`, `gaster.c:1220-1222`, `:1268`) |
| Claim 4 — "fires where least meaningful" | **REFUTED as phrased**; the conclusion (continue on `Unverified`, stop on `Refuted`/`DriverCannotReset`) is **CORRECT** and matches the reference | INSPECTED |
| A — `dfu_state_name` scrambled | **CONFIRMED**, still live at `usb.rs` `9C9B290895E48527…`; logic unaffected; one production caller; its own test checks only the correct entries; a second correct table now exists in `stages.rs` | INSPECTED |
| B — RESET verification is real | **CONFIRMED** independently (`dfu_check_status` checks 6 bytes, bStatus and bState; the walk requires 6→7→8) | INSPECTED |
| Delta — reset gate | **FIXED**, restores reference behaviour, no new deviation found | INSPECTED, **PROVISIONAL** |
| Delta — `leak_wvalue` | **FIXED**; two extra EP0 transfers removed; one minor residual (`ident_index` vs the declared `i_serial`) | INSPECTED, **PROVISIONAL** |
| Delta — `run_with_tracer` | **NOT FOUND** in any revision read | INSPECTED |

**Provisional because:** `stages.rs` and `trace.rs` were being written during this audit — five and
four observed revisions respectively, one hash read refused by the OS because an editor held the file.
The three substantive `stages.rs` regions are verified **as of `33C9B309F41B8C63…` / `5DAF61C4EC81E95F…`**.
When the writes stop, re-read only those regions and confirm; the reset gate, `leak_wvalue` and the
`record_reset`/`Tracer::reset` pair are where a regression would hide.

---

## 6. POST-ADDENDUM OBSERVATIONS — four files now in flight, and finding A is already fixed

Recorded after §1–§5 were written, because the tree kept moving. **These are observations of
in-flight revisions, not verdicts.** Hashes as observed, with line counts, at the time of writing:

| File | Frozen / first audited | Now | Movement |
|---|---|---|---|
| `src/usb.rs` | `9C9B290895E48527…` 1984 | `F4BB507BC8BE6FD7…` 2431 | **+447 lines — finding A is FIXED in it** |
| `src/verdict.rs` | `9300E7089F38DA1D…` 2261 | `A1F391090004FB32…` 2388 | **+127 — the reset predicate is being rewritten (see below)** |
| `src/stages.rs` | `A64476ECBD992A11…` 2428 | `EE88B58D42D8310A…` 3203 | +775 |
| `src/trace.rs` | `C2420E80E1CFFCD3…` 1353 | `035A9EDE0BB97E28…` 1552 | +199 |

### 6.1 Finding A — `dfu_state_name` — **FIXED**

At `usb.rs:402` the table is now correct: `usb.rs:405` `1 => "appDETACH"`, `:407`
`3 => "dfuDNLOAD-SYNC"`, `:408` `4 => "dfuDNBUSY"`, `:409` `5 => "dfuDNLOAD-IDLE"` — the four wrong
arms repaired, with the 3/4 swap undone. Two things the fix got right beyond the values:

* **The doc comment records the defect rather than hiding it** (`usb.rs:379-394`), stating the correct
  DFU 1.1 numbering, naming the four wrong entries, and noting "the numeric constants were right, so
  no decision was affected" — which matches §2 exactly.
* **The weak test was strengthened, which was the actual hazard.** `dfu_state_names_are_accurate`
  (`usb.rs:2255-2292`) now asserts **all eleven** values in a table (`:2259`, `:2263`, …), then
  re-asserts 1/3/4/5 individually (`:2276-2279`) and pins 11 and 0xFE as `"unrecognised"`
  (`:2291-2292`). The comment at `usb.rs:2252` says it outright: *"A subset check cannot catch a table
  error, so this now …"*. That is the right lesson to have written down.

**So this defect is closed.** The only remaining item from §2 is the **duplicate table**: `usb.rs:402`
and the `stages.rs` `dfu_state_label` now *both* correct, which is a maintenance hazard rather than a
bug. The Lead has assigned reconciliation to one source.

### 6.2 Finding B7 — still unwired, but the API half has landed

Re-grepped across `src/`: `Tracer::enumerated` (`trace.rs:672`), `device_path` (`:690`) and
`open_failed` (`:697`) are still called **only from `trace.rs`'s own tests** (`:1419`, `:1429`,
`:1440`, `:1447-1448`, `:1478-1482`). The two new hits in `usb.rs` — `:1579` and `:1669` — are **doc
comments** (`///     Some(len) => tracer.device_path(len, &note),`), i.e. worked examples for the
caller that does not exist yet. **So `counters.discovery_recorded` is still always false in
production and `DEVICE_PATH_TOO_LONG` / `WRONG_DRIVER_BOUND` / `DRIVER_BOUND_NOT_LOADED` still cannot
fire.** §10.2's finding stands; the transport-side API is ready and the wiring is not.
`DeviceIdentity::parse_instance_id` (`types.rs:326`) also remains test-only (`:831`, `:839`), so the
parent report's V09/Q9 conclusion is unaffected by the churn.

### 6.3 The FOURTH delta region — `RESET_NOT_DELIVERED`. Already being rewritten, and the rewrite cites Claim 3

The Lead asked for `verdict.rs:279-283` to be verified in the final pass. At the revision read here,
`verdict.rs` already carries a new comment at `:290-295` that reproduces this addendum's Claim 3
almost word for word:

> *"Non-delivery must be **measured**. `resets_unverified > 0` alone proves nothing: the exploit's own
> sequence parks the DFU machine in MANIFEST_WAIT_RESET only for the reset after PATCH, so after
> RESET/SETUP/SPRAY `Unverified` is the only possible outcome and a run that continues past it must
> still be classified by what actually failed downstream."*

It also references a counter, `resets_unverified`, which did not exist in the `trace.rs` I audited in
the parent document's §10 — consistent with the +199 lines there. **So the defect the Lead described
("an all-`Unverified` run would report that resets were attempted and none was recorded as delivered,
a causal claim `Unverified` does not support") is being fixed in the same wave as B1/B6.**

**For the final pass, the fourth region therefore has three parts, not one:**
1. the predicate itself — that a run which continued past `Unverified` is not classified as
   non-delivery on the strength of `resets_real == 0`;
2. that `resets_unverified` is **incremented only** by `ResetEvidence::Unverified` and by nothing else
   (the parent's §10.3c pattern — a counter that cannot distinguish two failures is the recurring
   defect in this file);
3. that `NO_RESET_CAPABILITY` (`verdict.rs:196-201` per the stages.rs comment at `:2129`) is still
   not triggered by an `Unverified` reset on a good libusbK driver — the failure mode the B6 fix was
   explicitly shaped to avoid.

### 6.4 Framing accepted from the Lead, for the record

The Lead withdrew their claim-4 sentence and adopted the corrected statement. The wording that should
stand in the record is theirs, and it is accurate:

> The post-stage gate required `ResetEvidence::Delivered` after every attempt; the reference's RESET
> stage leaves the machine at state 5 by its own design (its 64-byte flush, `gaster.c:840`), so the
> gate aborted at the end of round 1 and SPRAY/PATCH were unreachable. The fix continues on
> `Unverified` and stops only on `Refuted`/`DriverCannotReset`, which is strictly more informative
> than the reference, which cannot distinguish a pipe reset from a real one at all (`gaster.c:197-200`).

**Confirmed by the Lead's own hardware trace, independently of my reading:** `run --stage reset`
passed the RESET stage after verifying 6 → 7 → 8 and then aborted on its own post-stage reset. That is
Claim 3 observed end-to-end rather than inferred — the strongest evidence in this addendum, and it
arrived after §1 was written.

**Task-2 remains OPEN.** The Lead will send an explicit FREEZE with the settled hashes of `stages.rs`,
`trace.rs`, `verdict.rs`, `usb.rs` and `main.rs`; the final pass will then cover the three original
regions **plus** §6.3 as a fourth, and nothing else.

---

# 7. FINAL DELTA PASS — at the FROZEN hashes

**FREEZE received. All nine hashes verified as read**, independently of the six regions below:
`config.rs` `514CF83FA535294B…`, `lib.rs` `6ED236AE7B1B8AB9…`, `main.rs` `113A8319A55C03A5…`,
`payload.rs` `E3607CB89D1B2A8D…`, `stages.rs` `95C31EF94B0AF25C…`, `trace.rs` `724F53C670EE439A…`,
`types.rs` `F5230359EAF5752C…`, `usb.rs` `19D177F0650B87AF…`, `verdict.rs` `191C89F3C54EBB4C…`.
The stale `.tmpdir/verdict.rs.tmp` is indeed gone. **All nine match.** Every row below is against a
fixed revision and is final.

## 7.1 One line per region

| # | Region (frozen lines) | Reference | Verdict | Note |
|---|---|---|---|---|
| **1** | Reset gate and all three call sites — `ResetGate` `:2066`, `reset_gate` `:2094`, `record_reset` `:2215`, `reset_after_attempt` `:2225`; call sites `:1783`, `:1953`, `:1997` | `gaster.c:1268` (reset after every attempt), `gaster.c:197-200` (result discarded) | **MATCH** | `Unverified → ContinueLoudly` (`:2097`), `Refuted`/`DriverCannotReset → Stop` (`:2098-2103`), `Err → Aborted` unless `--allow-winusb` (`:2243-2249`), gate driven by `report.evidence` (`:2263`). **Neither old `!report.bus_reset_delivered && !opts.allow_winusb` condition survives** — `bus_reset_delivered` now appears only as the *recorded* predicate value (`:2257-2258`), never as a control condition. All three call sites route through the one function. |
| **2** | `leak_wvalue` `:1101`, callers `:1117`/`:1126`, `spray_begin` `:1203` | `gaster.c:52` (`USB_MAX_STRING_DESCRIPTOR_IDX` = 10), `gaster.c:866` (leak), `:886` (no-leak), `:910` (clr) | **MATCH** | Pure `(3<<8)\|ident_index`; both callers pass `io.usb.ident_index()` — a `Cell` read (`usb.rs:770`), no transfer. **No `Transport::identity()` call remains between SETUP and PATCH**: the only `.identity()` sites are `main.rs:189/249/352/394` (ident/preflight/plan), the once-per-round read at `stages.rs:1634`/`:1885`, and the post-reset re-open at `:2023` — all outside the spray/patch request path, and matching gaster's own per-iteration serial read (`gaster.c:1243` → `:203-215`). `spray_begin` prints the cached index, the leak/no-leak wIndex and all three lengths up front, so the whole sequence is auditable on one line. |
| **3** | `setup_passed` `:353` wired at `:736`; the double-count claim | `gaster.c:853` | **MATCH**, double-count **CONFIRMED FIXED** | `setup_passed` is the *whole* of `gaster.c:853`: `pad_request_len(...).is_none() → false` reproduces `sz < config_overwrite_pad`, then `matches!(pad, Some(p) if p.status == Stall)` reproduces `transfer_ret.ret == USB_TRANSFER_STALL`. **The count is now exactly one per STALL:** `pad_stalls` increments only inside `record_pad` (`:891`), which runs once per pad request (`:709`); the second increment that used to sit in the pass branch is gone, documented at `:732-735`. Tests pin it — `:2837` asserts `(pad_stalls, pad_ok, pad_timeouts, pad_other) == (1,0,0,0)` for one STALL, `:2759` asserts `pad_stalls == 1`. A refused abort still cannot pass (pad is `None` → `false`), and `SETUP_PAD_LENGTH_INVALID` remains the u16 guard. |
| **4** | `leak_satisfied` `:323`, `spray_transport_lost` `:1141` in the SPRAY loop | `gaster.c:902` (the triple), `gaster.c:220-223`/`:282` (every terminal status counts as completed) | **MATCH** | `leak_satisfied` = `abort_completed(r) && !abort_was_refused(r) && r.transferred == 0` — gaster's `completed != 0 && sz == 0` (`:866`, `:886`) **plus** the refusal guard, which repairs B3: a poisoned handle returning the refused shape can no longer score as a leak success. `spray_transport_lost` is reached from all three request sites under `io.usb.is_poisoned()` (`:1254`, `:1269`, `:1281`) and reports `TRANSPORT_DEVICE_LOST` instead of burning 20 000 transfers that never reach the wire. The `\|\|` short-circuit order is preserved (`:1261`, `:1272`, `:1288-1290`). |
| **5** | Request constructors and `patch_overflow_req` `:1357` | `gaster.c:1211` (overflow `bm=2,b=3,wValue=0,wIndex=0x80`), `gaster.c:893`, `:866`, `:886`, `:910` | **MATCH** | `patch_overflow_req` (`:1357-1365`) = `bm=2, b=3, value=0, index=0x80` — the §8.5 value, now a **pure constructor pinned by a test** rather than by inspection, which closes the B4 gap I raised. `spray_stall_req` (`:1040-1048`) = `2/3/0/0x80/0`; `spray_leak_req` (`:1052-1060`) = `0x80/6/wvalue/windex/EP0_MAX_PACKET_SZ`; `spray_no_leak_req` (`:1064-1072`) = same with `3*EP0_MAX_PACKET_SZ+1`; `spray_clr_status_req` (`:1076-1084`) = `0x21/CLRSTATUS/0/0/0xC1`. Every value checked against the **reference line**, not against the new tests. |
| **6** | `types.rs:461-470` truth-table change | `gaster.c:829-834` (RESET walk), `:1220-1222` (PATCH walk), `:1268`, `:197-200` | **UNVERIFIABLE** — sound in principle, one constructible false-positive path, one free measurement settles it | Not wrong; not a blocker. See §7.2 and §7.3. |

## 7.2 Region 6 — the change is surgical; every other cell verified unchanged

The new code hoists one cell above the claim check (`types.rs:461-470`):

```rust
if capability == ResetCapability::Real
    && libusb_rc == LIBUSB_SUCCESS
    && matches!((dfu_state_before, dfu_state_after),
                (Some(DFU_STATE_MANIFEST_WAIT_RESET), Some(after))
                if after == DFU_STATE_APP_IDLE || after == DFU_STATE_DFU_IDLE)
{ return ResetEvidence::Delivered; }
```

I enumerated the function exhaustively over `(capability, interface_claimed, rc, state pair)` and
compared old against new. **Exactly one cell changed**, as the Lead stated:

| `capability` | `interface_claimed` | `rc` | `(before, after)` | Old | New | Changed? |
|---|---|---|---|---|---|---|
| Real | **false** | SUCCESS | `(8, {0,2})` | `DriverCannotReset` | **`Delivered`** | ✅ **the one change** |
| Real | true | SUCCESS | `(8, {0,2})` | `Delivered` | `Delivered` | no |
| Real | **false** | failed | `(8, {0,2})` | `DriverCannotReset` | `DriverCannotReset` | no — the `rc` gate added at `:462` |
| Real | true | failed | `(8, {0,2})` | `Unverified` | `Unverified` | no |
| Real | **false** | SUCCESS | `(8, 8)` | `DriverCannotReset` | `DriverCannotReset` | no — **`Refuted` is still reachable only with the claim true** (`:481-483`) |
| Real | **false** | SUCCESS | any other pair | `DriverCannotReset` | `DriverCannotReset` | no |
| Real | true | SUCCESS | `(8, 8)` | `Refuted` | `Refuted` | no |
| Real | true | SUCCESS | any other pair | `Unverified` | `Unverified` | no |
| **PipeCycleOnly / Unknown** | either | either | any pair | `DriverCannotReset` | `DriverCannotReset` | no — `:461` still demands `capability == Real`, so **the WinUSB guard is NOT weakened** |

That last row is what would have made this a killer had it gone the other way. It did not: a
`PipeCycleOnly` driver can never reach `Delivered`.

The two supporting arguments in the Lead's justification, **independently confirmed**:

1. **`interface_claimed` is a stale snapshot and libusb can satisfy the condition itself.**
   `interface_claimed` comes from `handle.claim_interface(0)` at open (`usb.rs:581`), is stored at
   `:620` and **never updated**; the accessor at `usb.rs:774` is called from nowhere. Meanwhile
   `Transport::reset` issues a `DFU_GETSTATUS` **before** `libusb_reset_device` (`usb.rs:1175`, then
   `:1179`), and that transfer goes through `ctrl_sync` → `libusb_control_transfer`
   (`usb.rs:1139-1141`) — the auto-claim path. So by the time the reset runs, interface 0 is claimed
   **whether or not the open-time snapshot says so**. The snapshot is therefore not evidence that the
   call was skipped, exactly as the type's own doc argues (`types.rs:432-440`).
2. **State 8 is the reference's parked state, so an `8 → idle` move is real evidence — when the reset
   caused it.** The walk that establishes 8 is `gaster.c:829-834`; the PATCH path re-establishes it at
   `gaster.c:1220-1222` immediately before the reset at `:1268`.

## 7.3 Region 6 — the attack: one constructible false-positive path

I was asked to construct any path where the state pair moves `8 → idle` without a delivered bus reset.
I found one, and it is not contrived.

**The cell does not establish what *caused* the transition — only that the two reads differed.** So if
anything other than the reset can move the machine out of state 8 inside the observation window, the
cell returns `Delivered` on no evidence. Two sub-variants, and the second is the sharp one:

* **(i) The bootrom leaves `MANIFEST-WAIT-RESET` on its own.** DFU 1.1 says state 8 persists until a USB
  reset, so this requires the bootrom to deviate from the spec — unmeasured. But the window is **not**
  the microseconds of the reset call: `dfu_state_after` is sampled in a loop of up to
  `DFU_STATE_POST_ATTEMPTS = 3` attempts at `DFU_STATE_TIMEOUT_MS = 100 ms` each (`usb.rs:71`, `:76`,
  `:1197-1203`), so `after` can be read up to **~300 ms** after `libusb_reset_device` returned. The cell
  does not care *when* the transition happened.
* **(ii) `DFU_GETSTATUS` may itself advance `bState` in this bootrom — and our own code already suggests
  it might.** gaster's walk issues three consecutive `GET_STATUS` reads and expects **6, then 7, then 8**
  (`gaster.c:833`). That progression is normally attributed to the device advancing on its own schedule
  after the zero-length DNLOAD — but it is *equally* consistent with a minimal SecureROM implementation
  that **reports the current state and then advances it**, one state per poll. Under that model the
  `before` read reports 8 **and advances the machine to idle**; if the reset is then skipped, the `after`
  read reports `0/2`; and the cell returns `Delivered` having observed nothing but its own side effect.
  This also re-explains the Lead's measured state 5 after the RESET stage: under advance-on-read the
  walk's third read un-parks the machine and the 64-byte flush then sets 5 — indistinguishable from the
  flush-alone explanation. **The existing measurement does not settle which model is true.**

**How to settle it — free, decisive, on the first PATCH round, with the frozen binary.** PATCH's
MANIFEST walk (`gaster.c:1220-1222`) is followed by the reset at `:1268` with **no intervening wire
traffic** — no flush, unlike RESET. So the post-PATCH `before` read is the *fourth* consecutive
`GET_STATUS` after the walk:

* `DFU state 8 (manifestWaitReset) -> 0 (appIDLE)` (or `-> 2`): three walk reads plus a fourth all left
  the machine at 8 → **`GET_STATUS` does not advance the state, the cell is sound, and the change is
  safe.**
* `DFU state X -> Y` with **X ≠ 8**: the machine moved between two consecutive reads with nothing on the
  wire between them → **the read (or a sub-300 ms autonomous timeout) moves it, and the cell is a
  false-positive generator.**

**Severity if it is a false positive — and this is why it is not a killer: it cannot cost the run.** A
false `Delivered` yields `ResetGate::Continue` (`stages.rs:2096`) instead of `ContinueLoudly` (`:2097`)
— it **silences one warning** and labels one counter `reset_real` instead of `reset_unverified`. It
makes `Stop` *less* likely, never more; `Refuted` — the only state-based stop — is untouched because it
requires `(8,8)` with the claim true (`types.rs:481-483`). So the cost is **reporting accuracy in one
counter**, not exploit behaviour. **I am not asking you to hold the run for it**; I am asking you to read
that one trace line when it appears, because it decides whether `resets_real` can be trusted afterwards.

**One pre-existing risk in the neighbourhood, not caused by this change.** If `claim_interface(0)` fails
at open, nothing warns: `ResetCapability` is derived from the driver (`types.rs:524`), not from the
claim, so `preflight` passes; and `Transport::interface_claimed()` (`usb.rs:774`) is called from nowhere.
Such a run reaches the first post-stage reset with `interface_claimed == false`; if the state did **not**
move, the cell returns `DriverCannotReset` and the gate **Stops**. The changed cell narrows this but does
not remove it. A one-line preflight warning on `interface_claimed() == false` would close it for free.

## 7.4 Close-out

**All six regions pass: five MATCH, one UNVERIFIABLE** — with a free decisive test and a bounded,
non-blocking consequence. No deviation was introduced by any of the fixes. Nothing found in this pass
warrants holding the run.

Every finding from the parent document that could have cost the one shot is now either fixed and
verified against the frozen hash, or bounded and stated: **B1** (gate — fixed; three call sites
confirmed; old condition gone from the tree), **B2** (`leak_wvalue` — fixed; no `identity()` in the
loop), **B3** (`leak_satisfied` — fixed; refusal guard added), **B4** (wire parameters — now pure,
test-pinned constructors), **B6** (`Tracer::reset` takes `ResetEvidence`; `Unverified` gets its own
kind), **A** (`dfu_state_name` — fixed, with the weak test strengthened), **B5** (the false ipwndfu
provenance claim — corrected in `stages.rs:1050-1098`'s doc, which now cites `Transport::ident_index`
and forbids `identity()`).

**Still open, and deliberately not mine to fix:**
* **V08 — `LEAK_WINDEX_IPWNDFU = 0x00`** remains uncited (ipwndfu's real value is `0x40A`,
  `research/refs/ipwndfu/checkm8.py:123-124`) and `0x40A` remains unreachable from the CLI. The live run
  uses gaster's `0x0A` by default, which is the only sourced value. **A design decision for the Lead.**
* **B7 — three dead verdict codes** (`DEVICE_PATH_TOO_LONG`, `WRONG_DRIVER_BOUND`,
  `DRIVER_BOUND_NOT_LOADED`): the API half has landed, the wiring has not, so `discovery_recorded` is
  still always false in production. Assigned; reported so a "device present but unopenable" failure is
  not mistaken for `DEVICE_ABSENT`.
* **§7.3's one measurement** — the post-PATCH `DFU state` line, read once, from the first PATCH round.

---

# 8. FIRST LIVE RESULT — the four questions, answered on the reference side

Input: the Lead's first live run on the frozen revision (binary `429E27A5`): `run --stage reset`
PASSED with 6→7→8 verified; `run --stage setup --stop-after-setup-stall --setup-budget 2000` produced
~900 identical attempts in which the aborted transfer moved **0 of 2048 bytes** and the pad request
**TIMEOUTed every time** (never STALLed). All claims below are INSPECTED against `gaster.c` unless
marked MEASURED (the Lead's) or INFERRED.

## 8.1 Q1 — is our three-request sequence byte-identical to `gaster.c:848-860`, in order? **YES, MATCH. Not a deviation.**

| # | Request | gaster.c | Ours (frozen) | Identical? |
|---|---|---|---|---|
| 1 | async DNLOAD | `:853` `send_usb_control_request_async_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, DFU_MAX_TRANSFER_SZ, usb_abort_timeout, …)` → `0x21/0x01/wValue 0/wIndex 0/wLength 0x800`, aborted after the window | `stages.rs:656-664` `req_async(io, 0x21, DFU_DNLOAD, 0, 0, DFU_MAX_TRANSFER_SZ, window)` → same five parameters; `req_async` passes `window` as `cancel_after_ms` (`:411-421`) | ✅ |
| 2 | pad request | `:853` `send_usb_control_request_no_data(handle, 0, 0, 0, 0, config_overwrite_pad - transfer_ret.sz, …)` → `0x00/0x00/0/0/(0x500 - sz)` | `stages.rs:707` `req_no_data(io, 0, 0, 0, 0, len as u16)` with `len = pad_request_len(0x500, transferred)` (`:690`, `:334-339`) | ✅ — and with `sz = 0` both compute **1280**, which is the measured `pad_req=1280` |
| 3 | follow-up DNLOAD | `:856` `send_usb_control_request_no_data(handle, 0x21, DFU_DNLOAD, 0, 0, EP0_MAX_PACKET_SZ, NULL)` → `0x21/0x01/0/0/0x40` | `stages.rs:762` `req_no_data(io, 0x21, DFU_DNLOAD, 0, 0, EP0_MAX_PACKET_SZ)` | ✅ |

Order matches, and so does the **conditional** structure: gaster sends the drain only when the `if` at
`:853` fails; ours sends it only after `setup_passed` returns false (`:736` → `:762`). **No extra
transfer, and no deviation.**

**One clarification the trace format needs, because I misread it first and the Lead may have too.**
`after_abort_status` / `after_abort_xfer` / `after_abort_rc` are **not a second transfer** — they are
the *same* `abort` transfer's fields printed twice: `attempt_line` builds
`pad_req={len} after_abort_status={abort.status} after_abort_xfer={abort.transferred}/{abort.requested}
after_abort_rc={abort.libusb_rc} …` (`stages.rs:925-935`). So `abort_xfer=0/2048` and
`after_abort_xfer=0/2048` are one measurement of one 0x800 transfer, and there is exactly **one**
2048-byte request per attempt. The prefix reads as if a second one followed the pad; it does not. That
naming is worth changing before more traces are read.

## 8.2 Q2 — would gaster have measured `sz = 0`, and is a 0-byte abort itself the anomaly?

**Two separable answers, and they point in opposite directions.**

**(a) `sz = 0` does not stop gaster, and our pad arithmetic is what gaster would issue.** gaster's
predicate is `transfer_ret.sz < config_overwrite_pad` (`gaster.c:853`), i.e. `0 < 0x500` → **true**. So
gaster proceeds to the pad request, with length `0x500 - 0 = 1280` — the maximum. `sz = 0` sits at the
edge of the reference's design envelope but inside it. **So a 0-byte abort is not, by itself, a
deviation and not by itself a failure:** gaster's control flow is unaffected, and our behaviour is
indistinguishable from gaster's given the same device responses.

**(b) But `abort_xfer = 0` is NOT trustworthy as a statement about the device on this host, and I will
not read it as one.** `transfer->actual_length` is only defined for a transfer libusb *completed*. For a
**cancelled** URB the Windows backend reports the partial count only if it tracked it; a cancelled
transfer reporting `0` is equally consistent with "the device accepted nothing" and with "libusb has no
partial count to report for a cancelled URB". **Both hypotheses fit `abort_xfer=0` and I cannot separate
them from the trace.** This matters because they imply opposite diagnoses:

* *If the device accepted nothing* — the bootrom never entered the DNLOAD data stage, and the pad's
  TIMEOUT is the same refusal seen one request later. Then the sweep is inert for a device-side reason
  and no host timing change will help.
* *If libusb simply does not report it* — the primitive may be working exactly as designed, `sz = 0` is
  a reporting artefact, the pad length of 1280 is correct, and the **only** real failure is the pad not
  STALLing.

**So, answering the Lead's framing directly: the reference's primitive does not *require* partial
acceptance — its predicate tolerates `sz = 0` — but the mechanism's whole point is to choose a pad
length from `sz`, so a permanently-zero `sz` makes the sweep a single experiment. Whether `sz` is truly
zero is UNVERIFIABLE from this trace.** The one measurement that settles it: cancel a transfer that the
device is known to accept (e.g. a large control-IN the bootrom answers), and see whether `transferred`
is ever non-zero on a cancelled URB. If it is not, `abort_xfer` is unusable as device evidence.

**(c) The pad TIMEOUT is the actual failing predicate, and the reference fails the same way.**
gaster's pad request is a *synchronous* control transfer with timeout `usb_timeout` (`gaster.c:227`
passes `usb_timeout` to `libusb_control_transfer`). On timeout, `ret = LIBUSB_ERROR_TIMEOUT`, which is
neither `>= 0` nor `LIBUSB_ERROR_PIPE`, so gaster maps it to `USB_TRANSFER_ERROR` (`gaster.c:233-237`)
— **not** `USB_TRANSFER_STALL`. Its predicate `transfer_ret.ret == USB_TRANSFER_STALL` (`:853`) is then
false, and gaster loops forever. **Our port reproduces this exactly**, and `PAD_TIMEOUT_NOT_STALL`
names it. This *is* HANDOFF §8.4's diagnosis, now measured: the device NAKs the pad instead of
STALLing, and the reference has no answer for that either.

**(d) One hard numeric deviation I can assert, and it is transport-side.** gaster expects the pad's
synchronous timeout to be `usb_timeout` = **5 ms** (`gaster.c:227` with the default at `:1631-1633`).
The measured `pad_micros ≈ 14,900` is **~3× the configured value**, so the timeout is not being applied
as the reference applies it. That is a concrete, citable discrepancy for transport-engineer, and it is
the one thing in this region I would call a deviation rather than a device behaviour.

## 8.3 Q3 — what does gaster's timing model require of the abort window, and would a ~10 ms floor make the sweep impossible?

**The reference's timing model, in full:**

* `usb_timeout = 5` ms (`gaster.c:1631-1633`) is used for **three different things**: the async
  transfer's own libusb timeout (`gaster.c:255` `libusb_fill_control_transfer(…, usb_timeout)`), every
  synchronous control request (`:227`), and the sleep between `wait_usb_handle` opens (`:214`).
* The **abort window** is a *separate* deadline: `tv = {usb_abort_timeout/1000, (usb_abort_timeout%1000)*1000}`
  (`gaster.c:257-258`), after which `libusb_cancel_transfer` is called in a loop (`:259-261`).
* The window cycles `4,5,0,1,2,3` (`:849`, `:857`) — so gaster's **first** experiment is 4 ms, and
  window 0 (immediate cancel) is only the third attempt.

**What the model requires.** The window must be able to land the cancel at *different points* of the
2048-byte data stage, so that `sz` differs between windows and a window can be found where the pad
STALLs. The sweep is a search over `sz`, with `sz` as the observable. It is not a search over "abort
earlier than the whole transfer", because the predicate needs `sz < 0x500` — i.e. it needs the cancel
to land **before 1280 bytes have crossed**, not merely before all 2048.

**Would a ~10 ms floor make it impossible? No — and on this evidence the floor is not the proximate
cause.** Three reasons, in order of strength:

1. **Window 0 is 26× faster than the floor and produced the same result.** Measured: 437 µs at window 0
   vs ~11.5 ms at windows 1-5. If `sz` responded to abort latency at all, window 0 should differ from
   the rest. It did not — `abort_xfer=0` for **all six** windows. So the parameter is inert at both
   ends of a 26× span, which is not a resolution problem.
2. **The floor collapses 5 of 6 windows into one experiment, which is a real regression from the
   reference's intent — but "5 of 6" is not "impossible".** Window 0 remains a genuinely different
   experiment (437 µs). And our own detector already names this class of defect:
   `frozen_sweep_notice` / `abort_window_pinned` exist precisely to catch "one experiment wearing N
   labels" (`stages.rs:723-729`), which is the `a9ctl` failure the Lead cited. **So the floor is a
   defect the tool can already see and report — it is not a silent one.**
3. **The failing predicate is the pad's status, not the abort's timing.** The trace shows the pad
   returning TIMEOUT on every attempt. Even a perfect host timing implementation would have produced
   `sz = 0` here (if the device is refusing), and the pad would still TIME OUT. Changing the abort floor
   cannot turn a TIMEOUT into a STALL.

**So: the ~10 ms floor is a real, citable defect in the sweep's resolution and should be fixed — but it
is not why SETUP fails, and fixing it will not by itself make SETUP converge.**

## 8.4 Q4 — is the abort floor fatal? **No. I will not say the primitive cannot work on this host.**

Explicitly, because the Lead asked for a plain answer:

* **The primitive is not shown to be broken.** Our three requests are byte-identical to the reference's,
  in the reference's order (§8.1). The reference's own control flow would loop forever on this device
  (§8.2c). That is the known failure HANDOFF §8.4 documents, reproduced faithfully — **evidence the port
  is right, not evidence the primitive is dead.**
* **The floor cannot be the root cause**, for the three reasons in §8.3, the strongest being that
  window 0 is 26× faster and changed nothing.
* **What I would say instead**, and it is narrower: *the abort window's value is not observable in the
  measured latency on this host, so the sweep cannot vary the one parameter it was built to vary; and
  `abort_xfer` is not trustworthy as a device measurement until we know whether libusb reports
  `actual_length` for a cancelled URB.* Those are two fixable defects and two open measurements — **not**
  a conclusion that checkm8's SETUP primitive is unimplementable here.
* **The honest ceiling on my answer:** I have reasoned from the reference and the Lead's numbers. I have
  not measured the host, and the ~11.5 ms floor's origin is transport-engineer's question, which the Lead
  has already assigned. If their answer shows the cancel is issued *after* an unconditional ~11 ms wait
  that also swallows window 0, that would change §8.3 — but the measured 437 µs at window 0 rules that
  out as written.

**Ranked, for the record:** (1) the pad NAKs instead of STALLing — device-side, reference-faithful,
`PAD_TIMEOUT_NOT_STALL` names it; (2) `abort_xfer` is unverified as device evidence — needs one
measurement; (3) the pad's 5 ms timeout is being applied as ~15 ms — citable transport deviation;
(4) the ~11.5 ms abort floor collapses 5 of 6 windows — real, visible, not causal.

---

# 9. WHAT THE PAD STALL ACTUALLY REQUIRES — semantics of the primitive

Input: three live runs (MEASURED, Lead). The tick fix works (windows truncate at 1185 / 1657 / 4403 /
5376 µs). Run 2 (12 rounds): **3 pad STALLs in 154 attempts** — the pass condition reached for the
first time — then SPRAY and PATCH ran, payload uploaded twice, no PWND. Run 3 (64 rounds):
**0 STALLs in 31,000 pad requests.** Every aborted 0x800 DNLOAD in every run reports
`abort_xfer=0/2048`; `abort_completed_full` was 0. A full elevated re-enumeration leaves the DFU state
at 5, so state 5 is this bootrom's resting value and the state machine is not a reset oracle.

## 9.1 I must correct my own §8.2 answer first

In §8.2 I said `abort_xfer=0` is not trustworthy as device evidence, because `actual_length` is only
defined for a completed transfer. **Having now read our primitive, that was wrong, and it matters.**
`usb.rs:1135` sets `(*transfer).timeout = 0` — libusb's own transfer timeout is **disabled on purpose**
— and the doc at `usb.rs:1049-1055` gives the reason: with no second terminator, a cancelled transfer
carries a real partial `actual_length` instead of being relabelled a timeout with none, citing
`windows_common.c:825-832` (on `ERROR_OPERATION_ABORTED` libusb copies the kernel's partial length and
*then* reports `CANCELLED`). The count is read after the reap (`usb.rs:1192-1193`) and the code argues
it is directly comparable with `wLength` and with gaster's `sz` (`:1201-1206`).

So the design intent is that `abort_xfer` **is** the real data-stage count, and the weight shifts to
"the device genuinely accepted ~0 bytes". **That correction produces the answer to the Lead's question,
so it is load-bearing rather than cosmetic.**

## 9.2 Q1 — what must physically happen for the pad to STALL

**The shape, as `gaster.c:848-860` implements it** (INFERRED — the ROM's internals are not in this
tree): the 0x800 `DFU_DNLOAD` is submitted and then **cancelled** (`gaster.c:853` via
`send_usb_control_request_async_no_data`, cancel loop at `:259-261`); the very next request is the pad,
whose request is **`bm=0, b=0`** — a malformed request with no valid handler — and whose **length is
computed** as `config_overwrite_pad - sz` so that the aborted transfer plus the pad total exactly
`overwrite_pad`. The STALL is the pass condition because it is the observable that the ROM consumed the
corrupted state.

**Does the primitive require the DNLOAD to have started moving data? On the evidence: NO.** Three
independent reasons:

1. **The reference's control flow cannot tell.** `transfer_ret.sz` appears only in
   `sz < config_overwrite_pad` (`gaster.c:853`), which `sz = 0` satisfies. gaster sends the same pad
   and loops the same way.
2. **The reference's arithmetic merely *expects* `sz` to vary** — `overwrite_pad - sz` is only a
   meaningful subtraction if `sz` moves, and `DFU_MAX_TRANSFER_SZ` (0x800) exceeds
   `config_overwrite_pad` (0x500, `gaster.c:626`) by 0x300, leaving headroom for a range of `sz`. So the
   *design* anticipates partial acceptance. That is evidence about intent, not about mechanism.
3. **The live data settles it.** Run 2 produced **3 pad STALLs in 154 attempts while every abort
   reported `abort_xfer=0`.** Given §9.1 — the count is designed to be trustworthy — a transfer that
   moved **zero** data-stage bytes still produced the dangling state three times. **So the primitive
   needs the DNLOAD to have been *submitted and then cancelled*; it does not need bytes to have
   crossed.**

**The semantic reading of TIMEOUT vs STALL — and this is the useful part.** The pad request is
malformed (`bm=0, b=0` — bRequest 0 with OUT direction; a reserved combination). A ROM that *serviced*
such a request normally would reject it **unconditionally and immediately**, and the pass condition
would be met on attempt 1. It is not. The pad **NAKs**: 31,000 TIMEOUTs in run 3 against 3 STALLs
total. A control-request TIMEOUT means the device never serviced the request.

So **STALL is not "the ROM rejected a malformed request because it was malformed". STALL is "the ROM's
EP0 handler finally ran to completion on that request"** — which happens only when the cancelled
transfer left the handler in the freed-but-callable state checkm8 needs. Three consequences:

* The default state is **EP0 stuck/busy**, and the rare success is **the handler completing**. The
  failure is not "the pad was wrong"; it is "EP0 never got there".
* It explains the **drain DNLOAD** at `gaster.c:856` / our `stages.rs:762`. It is not a flush. It is the
  nudge that unsticks EP0 so the *next* async DNLOAD can be submitted at all, and both implementations
  treat its result as discardable (gaster passes `NULL`; ours checks only `NoDevice`, `:764`).
* It reclassifies the search: the target is **not** "get data into the aborted transfer" (settled: not
  required) but **"hit the cancel timing that leaves EP0's handler dangling"** — a **race**, whose hit
  rate is state-dependent. That is consistent with 3/154 in one run and 0/31,000 in another: not a
  constant probability, a state-dependent one.

**A mechanistic consequence the Lead should have: the pad length is pinned at 1280, so the sweep has
lost a degree of freedom.** With `sz` fixed at 0, `config_overwrite_pad - sz` is always **1280 — the
maximum**. gaster's design couples two variables (`window → sz → pad length`); on this device that
coupling is broken and only the abort timing remains. The pad's *length* is not being searched, it is
being assumed. That is a real reduction in the search space and it is the best mechanistic explanation
for the low hit rate. **One diagnostic implication, offered as a hypothesis and explicitly NOT a
recommendation to ship:** the reference's own arithmetic makes pad length a free parameter of the
corruption, so a deliberately non-reference experiment — *force* `pad_len` across a range instead of
deriving it from `sz` — would test whether length or timing is the binding constraint. It departs from
the reference and must be labelled as such.

**Honest boundary.** Whether the ROM allocates its `dfu_callback_t` on the **SETUP packet** or on the
**first accepted data packet** is a property of the A9 SecureROM. **No source in this tree contains
it:** `gaster.c` does not, `GASTER-SPEC.md` describes gaster rather than the ROM, and m1n1's source is
off limits (HANDOFF §0.5). So that specific question is **UNVERIFIABLE from source**, and settling it
needs bootrom RE. What *is* settled empirically is the practical form of the Lead's question: **data
movement is not a prerequisite for the dangling state.**

## 9.3 Q2 — behavioural differences other than timing values. One found, and you can stop looking

| # | Behaviour | gaster | ours | Verdict |
|---|---|---|---|---|
| a | **The async transfer's own libusb timeout** | `usb_timeout` = **5 ms**, passed at `gaster.c:255` — a **second terminator** alongside the cancel deadline `tv` (`:257-261`) | **disabled**: `(*transfer).timeout = 0` (`usb.rs:1135`), documented `usb.rs:1049-1055` | **DIFFERENCE — deliberate, documented, benign.** Window 5 (5 ms) equals `usb_timeout`, so gaster's timeout and cancel *race* at that one window; windows 4, 0, 1, 2, 3 all cancel first. Ours is **strictly more deterministic**, and this is precisely why our `abort_xfer` is trustworthy where gaster's might not be. It affects at most 1 of 6 windows and is the *opposite* of a defect. |
| b | **Is the aborted transfer reaped before the pad is issued?** | Yes: the loop exits only when `completed != 0`, set by `usb_async_cb` for any terminal status (`gaster.c:220-223`, loop `:259-261`) | Yes: `pump_until_reaped(..., deadline, deadline + HARD_GRACE)` (`usb.rs:1170`); if the callback never ran it **poisons the handle** and returns `Error` rather than driving on (`:1173-1190`) | **EQUIVALENT**, and ours fails safer (gaster returns false and skips the pad; we surface `TRANSPORT_DEVICE_LOST`). |
| c | **Drain position and semantics** | `gaster.c:856`, after the failed `if` at `:853`; synchronous with `usb_timeout`; result discarded (`NULL`) | `stages.rs:762`, after `setup_passed` fails at `:736`; synchronous; only `NoDevice` checked (`:764`) | **EQUIVALENT.** |
| d | **`completed` semantics / which statuses count** | `completed = 1` for **any** terminal status (`:220-223`); everything except OK and PIPE maps to `USB_TRANSFER_ERROR` (`:272-274`) | any reaped status except `NoDevice` counts as completed (`abort_completed`, `stages.rs:289`) | **EQUIVALENT** for the predicate at `:853`. |
| e | **Payload content of the aborted DNLOAD** | `malloc` + `memset(p_data, 0, w_len)` (`gaster.c:489-491`) → 2048 zero bytes | `vec![0u8; len]` in `req_async` | **EQUIVALENT** (2048 zeros). |
| f | **How the cancel deadline is spent** | `tv` declared once (`:245`), set once (`:257-258`), passed `&tv` on **every** loop iteration (`:259`) — and `libusb_handle_events_timeout_completed` may *modify* the timeval, so later iterations get a shortened slice | one absolute `deadline` pumped in slices to `deadline + HARD_GRACE` (`usb.rs:1169-1170`) | **Structural difference, low consequence.** Both bound the window; ours is bounded and its `micros` is reportable against the window, and the tick fix proves the window is now honoured. |

**Conclusion for Part 2: stop looking there.** One behavioural difference exists, it is deliberate and
documented, it is confined to a race gaster has at a single window, and it makes our implementation
*more* deterministic than the reference. Byte-level equivalence was already established; behaviour-level
equivalence is as close as source analysis can get.

## 9.4 Where that leaves the failure — ranked, all device-side

1. **The race is not being won often enough.** 3/154 vs 0/31,000 in two runs of the same code says the
   hit rate is state-dependent, not a fixed probability. The next question is *what state differs*, and
   that is a hardware question: what the ROM's EP0 does between the reopen and the first attempt.
2. **The pad length is frozen at 1280** (§9.2), so only the timing axis is being searched. Highest-value
   untested hypothesis.
3. **`abort_xfer=0` is now believed real**, which means the device accepts ~0 bytes of the DNLOAD at
   every window — so `sz` cannot be steered, and neither can the pad length derived from it.
4. **Not on the list any more:** the byte sequence (§7.1 region 5), the reaping semantics, the drain,
   `completed` semantics, the DNLOAD content, and the abort-window resolution (fixed and verified).

**No source-level defect remains in the SETUP path.** Everything above is a property of the device's
response to a correct implementation of the reference's sequence.

---

# 10. DELTA — the pad timeout 5 ms → 40 ms

**Revision verified:** `stages.rs` `A82A5CF0C380552E0BBE3A49B9AA1AB788E3DD63E4A6B84803D19CD68A7F6FBD`
(3592 lines) — matches the Lead's manifest exactly. All claims INSPECTED.

**The change:** `RunOptions.pad_timeout_ms` default 40 (`stages.rs:86`, `:229`, `:247-248`), a pure
`pad_timeout()` seam (`:274-276`), a dedicated `req_ctrl_with_timeout` (`:435-443`) used only at the pad
call site (`:798-808`), `setup_begin` reporting both timeouts (`:694-697`).

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 1 | The pad timeout now 40 ms where `gaster.c:227` uses `usb_timeout` = 5 ms | **DEVIATION — authorised, justified in direction, with two caveats** | `gaster.c:227` → `:467-480` → global `usb_timeout` (`:1631-1633`) |
| 2 | `usb_timeout_ms` untouched in value and in reach | **MATCH** | `stages.rs:247`, `:265`, `:532`, `:680`, `:685`, `:874`, `:1208`, `:1410`; tests `:3032`, `:3050-3084` |
| 3 | The pad request's bytes unchanged | **MATCH** | `stages.rs:798-808` (`bm=0, b=0, wValue=0, wIndex=0, wLength = overwrite_pad − transferred`) vs `gaster.c:853` |
| 4 | The new seam cannot alter the drain DNLOAD or the GET_STATUS reads | **MATCH** | `req_ctrl_with_timeout` has exactly two callers — `:456` (via `req_ctrl`, passing `usb_timeout_ms`) and `:798` (the pad) — and `req_ctrl` is now a one-line delegation (`:454-457`) |

## 10.1 Why the deviation is right in direction

`gaster.c:227` reaches the pad through `send_usb_control_request_no_data`, which uses the **global**
`usb_timeout`, default 5 ms (`gaster.c:1631-1633`). That one number serves **four unrelated roles**:
the async transfer's own libusb timeout (`:255`), every synchronous request (`:227`), the
`wait_usb_handle` poll interval (`:214`), and the base of the abort-window derivation (`:849`, `:857`).
**So gaster's 5 ms for the pad is not a device-latency budget — it is the same global used as a
device-discovery poll interval.** Decoupling the pad's timeout is therefore *better* than the
reference, and this change does it without touching the other three roles (item 2).

The measurement supports the reading: every answered pad took **21.4 / 22.9 / 24.5 / 25.3 / 27.2 /
27.9 ms** (run 2) and **21.5 / 36.6 ms** (run 4) — all eight above 21 ms — against a nominal 5 ms that
the code's own doc says the Windows tick inflates to ~8-31 ms (`stages.rs:213`). The old configuration
was a **race between two host-side quantisations**, not a measurement of the device.

## 10.2 Caveat A — it is not purely a listening change

In USB, if the device NAKs the **setup** packet no data stage occurs at all; if it ever ACKs it, the
1280-byte data stage runs. A longer timeout widens the interval in which the device may **change its
answer**, and the possible changes include NAK→**ACK**, not only NAK→STALL. The reference's 5 ms also
bounded *how much of the ROM interaction could happen*; 40 ms does not. The wire bytes are identical
(item 3), but "we listen longer" and "the device has more opportunity to accept the data stage" are
different statements, and **this change should not be recorded as observation-only.**

## 10.3 Caveat B — the false-pass risk, which fits run 2 exactly

All eight answered pads fell in **21.4-36.6 ms with none below 21**. A timing-sensitive *race* — the
cancel landing at different points of the ROM's EP0 handling — should spread across the whole window,
sub-millisecond upward. **A hard floor at ~21 ms looks like a fixed device-side latency: a time-driven
transition, not a race.** If this ROM STALLs a stuck EP0 request on a ~20-40 ms watchdog, then:

* gaster's 5 ms would never see it on any host;
* our 5 ms saw it only when the tick inflated the timeout past ~28 ms — which explains
  **run 2 (3 STALLs in 154 attempts) vs run 3 (0 in 31,000)** as tick-phase luck rather than device
  state;
* **40 ms would catch it on essentially every attempt — SETUP would "pass" with no corruption, which is
  precisely run 2's signature: SETUP passed, payload uploaded twice, no PWND.**

## 10.4 The decisive test, and what to read in the next run

**Cheap discriminator, using the option that already exists.** Run the same SETUP at
`pad_timeout_ms = 20`. If the STALLs are the ~21-28 ms transition, a 20 ms timeout should catch **none**
of run 2's answers and at most one of run 4's. If STALLs persist at 20 ms at a similar rate, the timeout
was never the binding constraint and the STALLs are more likely genuine.

**Three numbers to read in the 40 ms run, the first as a red flag rather than a win:**

1. **STALL rate.** checkm8's SETUP is meant to *search* for a state. A pass condition satisfied on
   essentially every attempt is a watchdog; a corruption-driven STALL should remain a minority outcome
   that is now *reliably detectable* instead of a lottery.
2. **STALL latency spread.** Pinned in the same 21-28 ms band strengthens the watchdog reading; a
   spread including sub-millisecond weakens it.
3. **Does PATCH then produce PWND?** "STALL on essentially every pad + PATCH still fails" means the pass
   condition has become vacuous. `pad_micros` is on every attempt line, so both distributions are
   recoverable from the trace.

**Would I have made this change?** The **decoupling**, yes — and earlier. Raising the value to 40 ms
blind, **no**: 40 ms is precisely the setting at which a watchdog STALL and a corruption STALL become
indistinguishable, so §10.4's test should have been paired with it. That test is the one thing still
owed, and it is cheap. **Nothing here justifies holding the run** — items 2, 3 and 4 show the requests,
the window derivation and the pass condition are all unchanged, so the port remains faithful to the
reference in every respect except the one authorised timeout.

---

# 11. THE 0x800 DNLOAD IS NEVER REGISTERED — a condition the reference cannot handle

**Measurement (Lead, MEASURED, clean device, `--stage setup --stop-after-setup-stall
--setup-budget 50 --probe-setup-state`):** 50 attempts, 50 pad requests, 0 STALLs, 50 TIMEOUTs;
DFU state after the aborted DNLOAD is **5 (dfuDNLOAD-IDLE) in 50/50**, with "0 bytes" moved. In the
same run the RESET stage's own DNLOADs all succeed: `reset_dnload_suffix` **16/16 OK**,
`reset_set_wait_reset_dnload_0` OK, `reset_dnload_flush` **64/64 OK**.

## 11.1 Q1 — does the reference depend on the ROM registering the DNLOAD? **YES, and gaster would be silently broken here too**

The pass condition at `gaster.c:853` is `<pad>.ret == USB_TRANSFER_STALL` — a **state-dependent**
outcome of a request whose bytes never vary. The only thing that varies between attempts is
`usb_abort_timeout` (`:849`, `:857`). **So the sweep's entire premise is that the aborted DNLOAD
mutated ROM state, and the pad's STALL is the observable of that mutation.** If the ROM refuses the
setup packet and allocates nothing, the pad's outcome becomes a device constant, uncontrollable from
the host.

And gaster cannot detect that: `sz < config_overwrite_pad` (`:853`) is *satisfied* by `sz = 0`
(`0 < 0x500`), so gaster sends the pad anyway, gets no STALL, and **loops forever** — `gaster.c:852`
is a `for(;;)` with no logging whatsoever in the loop. **That is the unbounded silent wait this
rewrite exists to eliminate.** HANDOFF §8.4's diagnosis was right but stopped one level too shallow:
the device is not merely NAKing the pad, it is **refusing the DNLOAD**, and the pad's NAK is
downstream of that.

`DFU_MAX_TRANSFER_SZ = 0x800` is a hardcoded `#define` (`gaster.c:44`), used at `:853`, `:982`,
`:1073`, `:1214`, `:1500`. **gaster never reads the device's declared `wTransferSize`** — no
`GET_DESCRIPTOR` of type 0x21 exists anywhere in the file. That is an assumption, not a measurement,
and it is the top-ranked suspect below. The probe in `stages.rs` (`probe_dfu_state` `:711`, guarded by
`probe_setup_state` `:278`/`:846`) is the first instrument in this project able to detect this
condition.

## 11.2 Q2 — ranked candidates, two already dead from existing data

| Rank | Candidate | Status |
|---|---|---|
| **1** | **A length cap on an accepted DNLOAD** | **LIVE, and bounded to (528, 2048].** Run 2 reported "payload uploaded successfully twice": PATCH's chunk is `DFU_MAX_TRANSFER_SZ` (`stages.rs:1696`) and the A9 blob is **528 bytes** (`payload.rs:533`), so that was **one synchronous 528-byte DNLOAD of the same request shape as the SETUP abort, returning OK with all 528 bytes.** With the RESET stage's 16/64-byte successes, the device accepts sync DNLOADs of 0, 16, 64 and **528** bytes and refuses the 2048-byte one. |
| **1a** | **The DFU Functional Descriptor's `wTransferSize`** | **LIVE, and readable.** `GET_DESCRIPTOR(0x21)`, 9 bytes → `bmAttributes`, `wDetachTimeOut`, `wTransferSize`, `bcdDFUVersion`. If `wTransferSize < 0x800`, gaster's constant is the bug and this is the answer — a measurement, not a sweep. Cheapest and most authoritative. |
| **2** | **The abort cancels before the setup stage completes** | **LIVE.** Every window ever swept is 1.2-5.4 ms. If the ROM NAKs the setup for *longer* than 5.4 ms, all six windows look identical — 0 bytes — and the sweep never explored a window long enough. One run at 50-100 ms settles it. |
| **3** | **A required preceding state after the bus reset** | **Dead for free, pending one grep of existing traces.** `setup_drain_dnload` (`stages.rs:969`) is a **64-byte synchronous DNLOAD issued after the port reset in every attempt**. If its status is OK, small DNLOADs work after the reset and this candidate is refuted at zero cost. It is a separate `xfer` event in the JSONL, not in the attempt line. |
| **4** | **`wValue` / block numbering** | **WEAK.** The RESET stage's 16- and 64-byte DNLOADs use `wValue = 0, wIndex = 0` (`gaster.c:840`) — **identical request fields to the SETUP abort** (`:853`). Only `wLength` differs. |
| — | **Unhandled-request semantics for the pad** | **Not a candidate — a consequence.** `bm=0, b=0` is malformed; a ROM with no handler NAKs it forever regardless of length. That is why the pad TIMEOUTs. |

## 11.3 Q3 — the two probes I would run before the length sweep

**0. The before-probe (offered by stages-engineer) — take it, but it is nearly redundant now.** The
after-probe reads 5 with **0 bytes moved**; a registered-and-completed block is impossible (that needs
bytes) and a mid-download would read 3 or 4. So "5 with 0 bytes" already means "nothing happened" with
reasonable confidence. Its real value is for the *next* experiments, where the state is expected to
move — add it there rather than as a standalone run.

**1. The DFU Functional Descriptor read.** Read-only, one transfer, may name the answer. Before
anything that sends a large DNLOAD.

**2. Read `setup_drain_dnload`'s status from existing traces.** Free; refutes or confirms rank 3.

**3. A synchronous 2048-byte DNLOAD, with the state probe** — separates **length** from the
**async/cancel** confound in one shot. State-changing (a completed 2048-byte DNLOAD is a real download
block), so label it. Complementary: **an async DNLOAD of 528 bytes**, a length the device accepts
synchronously, isolating the async/cancel path — with the nuance that 528 bytes is ~1.1 ms of bus time,
so it will often *complete* rather than be cancelled, and that is itself informative.

**4. Only then the length sweep**, with both probes and the window recorded per point, labelled
diagnostic — gaster only ever sends 0x800 at `:853`, so a working length would then have to be
justified against `gaster.c:44` rather than adopted because it moved the state.

**Why length-sweep-first is wrong:** it varies length while leaving the async/cancel difference in
place at every point, so any boundary found cannot be attributed to length rather than cancellation;
and three of its five points (64/128/512) are already answered by the 16/64/528 successes.

## 11.4 Retrospective — this confirms §10's caveat B, and it was not speculative

The probe proves the download never started, so **the pad's STALL can never have been
corruption-driven on this device.** Run 2's 3 STALLs were the ROM STALLing the malformed pad on its
own. **Had the 40 ms pad timeout been in place, those would have become routine vacuous "passes"**,
and SETUP would have reported success on a device whose primitive never fires. The pad-timeout theory
is retired — but the change would have *manufactured* the failure mode it was meant to fix, and the
"STALL rate ≈ 100% is a red flag, not a win" rule (§10.4) is now established rather than speculative.

## 11.5 Bottom line

**No port defect.** The requests, lengths, order, pass condition and window derivation are all the
reference's, and the request fields are identical to the small DNLOADs this device *accepts*. What has
been found is a condition the reference can neither handle nor report. The uncomfortable version,
stated plainly: **if the ROM refuses a 0x800 `DFU_DNLOAD` outright, checkm8's SETUP primitive as
specified cannot execute on this unit, and gaster could not have exploited it either.**

---

# 12. THE DRAIN DNLOAD STALLs 2/3 OF THE TIME — the reference defines the signal and never reads it

**Measurement (Lead, MEASURED, grepped from existing traces):** the 64-byte `DFU_DNLOAD`
(`bm=0x21, b=1, wValue=0, wIndex=0`): run 2 — 157 total, 51 OK, 103 STALL, 0 TIMEOUT; run 4 — 14,580
total, 4,879 OK, 9,700 STALL; probe-state2 — 51 total, 17 OK, 34 STALL; wire-setup — 1 total, 1 OK.

## 12.1 Precision first: that shape is TWO different requests

`bm=0x21, b=1, wValue=0, wIndex=0, wLength=0x40` is used by both
`reset_dnload_flush` (`gaster.c:840`, **checked**: `ret == OK && sz == EP0_MAX_PACKET_SZ`) and
`setup_drain_dnload` (`gaster.c:856`, **unchecked**). A byte-level grep merges them, and the counts are
consistent with the merge (probe-state2: 51 = 50 drains + 1 flush; run 2: 157 = 154 drains + 3
flushes). Since the RESET flush measures **64/64 OK**, the drain-only STALL rate is slightly above 2/3.
**The split is not bookkeeping — it is the evidence (§12.3).**

## 12.2 What a STALL on the drain means, in reference terms

**gaster defines the signal and never reads it.** `gaster.c:856` passes `NULL` (result discarded),
`send_usb_control_request_no_data` returns `true` unconditionally (`:239`), and the `for(;;)` at `:852`
does not branch on it. **But the choice of request is the semantics:** gaster's idiom for "clear the
DFU status" is `DFU_CLR_STATUS` (`:843`, `:910`, `:915`, `:1617`). **At `:856` it deliberately does not
use it — it sends a 64-byte `DFU_DNLOAD`.** A DNLOAD is a **download-context** operation: one EP0
packet pushed into the ROM's download state machine. So the drain's function is to **advance** a
download context that the failed attempt left stuck, and a STALL on it means **the ROM refuses to
advance that context.**

## 12.3 The contrast: identical bytes, opposite outcomes, different context

| Request | Bytes | Context | Result |
|---|---|---|---|
| `reset_dnload_flush` (`gaster.c:840`) | `0x21/1/0/0/0x40` | after a clean MANIFEST walk | **64/64 OK** |
| `setup_drain_dnload` (`gaster.c:856`) | `0x21/1/0/0/0x40` | after an aborted 2048-byte DNLOAD + a malformed pad | ~**33% OK / 67% STALL** |

**So the SETUP attempt is not a no-op: it measurably degrades the ROM's download context.**

## 12.4 Correction to §11 — the strong form of "the ROM never registers the request" is refuted

§11 concluded, from the state probe reading 5, that the ROM never registers the request. **The drain
data refutes the strong form.** The DFU *logical* state only advances when a DNLOAD **completes**, so a
**registered-but-unfed** download leaves it at 5 while the USB/EP0 layer is dirty — and the drain's 2/3
STALL rate is direct evidence that layer **is** dirty. Revised: **something is being registered, the
attempt does change ROM state, and the state probe is blind to it because it reads the wrong layer.**

**Corollary — I over-sold the before-probe.** §11.3 rank 0 said to take stages-engineer's before-probe
first. It measures the *same logical state*, so it cannot see a USB-layer degradation either; its only
value is confirming the 5 baseline. **The drain is the instrument; the state probes are secondary.**

## 12.5 The mundane alternative, which the stable rate favours

The pad is a **1280-byte** control-OUT that the host abandons (TIMEOUT = we gave up mid-data-stage).
Abandoning a control-OUT mid-data-stage leaves EP0 in the data stage, so the next request — the drain —
may be STALLed simply because **EP0 was left mid-transfer by the abandoned pad**, with no
checkm8-relevant corruption. That hypothesis predicts a **constant** STALL rate, and the measured rate
is strikingly stable: **67% (run 2), 68% (probe-state2), 67% (run 4).** A corruption *index* would more
plausibly drift with run state. **The mundane reading is currently the better-supported one.**

**The discriminator, and it is cheap:** run a **pad-only** sequence with no aborted DNLOAD. If the drain
still STALLs ~2/3 of the time, the abandoned pad alone causes it and the drain is a consequence, not an
index. If the drain is then clean, the aborted DNLOAD is required and the drain really is a window into
the mechanism.

## 12.6 Re-ranking (cf. §11.2)

* **Promoted: §11 rank 2** — the abort leaves a context the ROM will not advance. Now has a mechanism
  and a per-attempt index.
* **Demoted: §11 rank 1, the pure length cap.** The drain is **64 bytes and STALLs 2/3 of the time**;
  the RESET flush is **64 bytes and is 100% OK**. **Same length, different outcome ⇒ the refusal is
  context-dependent, not length-dependent.** A pure cap would refuse 2048 in every context and accept 64
  in every context.
* **Unchanged: rank 3**, partially refuted — small DNLOADs do work after the reset, 51 times in run 2.
* **Dead: rank 4** — fields identical to the small DNLOADs that succeed.
* **Rank 1a keeps its place and gains a fork:** `wTransferSize < 0x800` ⇒ a genuine cap and
  `gaster.c:44`'s `#define` is the bug; `wTransferSize ≥ 0x800` ⇒ **no cap, the problem is contextual,
  the descriptor is a dead end, and §12.7's window correlation becomes the only line.**

## 12.7 Three free checks in existing traces, in value order

1. **Does the drain's status correlate with the abort window on the same attempt?** If `drain=OK`
   clusters on particular windows, then **the abort window controls the ROM's context** — the first
   positive evidence that the aborted transfer registers and that the sweep's window is a real control
   rather than six labels. **The most valuable table available from existing data, because it tests the
   sweep's entire premise.**
2. **Was there ever a pad STALL immediately following a drain STALL?** If never, `drain=OK` is a
   necessary precondition and run 2's three successes should sit inside drain-OK streaks.
3. **Run 2 and run 4 share the aggregate drain rate (~67% STALL) but differ in pad outcome** (3 STALLs
   vs 0), so the *aggregate* rate does not explain the run-to-run difference. Recorded so the aggregate
   is not over-read.

**Observability ask, and it is why this went unseen for six runs:** the drain is logged as a *separate*
xfer event (`stages.rs:969`), so no attempt line carries both the pad and the drain outcome. **Put the
drain's status on the attempt line beside `pad_status`.** A two-request causal chain visible only across
two JSONL records is not visible at all.
