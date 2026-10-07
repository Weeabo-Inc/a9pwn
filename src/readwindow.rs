//! The **trigger-only SRAM read window**: one request, no command mailbox, no `DNLOAD`.
//!
//! # The problem this exists for
//!
//! `a9boot/HANDLER-RELOCATION.md` §1-2 answers the question the task was set with: the checkm8
//! handler **code** is not in the DFU buffer. The install copies it to `0x1800E0F08` and repoints
//! the ROM's persistent request hook (`*0x1800878F8`) at it; the one-shot `dfu_callback_t.callback`
//! that the overflow wrote to `0x180380000` is consumed by the first transfer and is not (and need
//! not be) repointed. What *is* in the buffer is the handler's **command mailbox**
//! (`insecure_memory_base = 0x180380000`): every command is delivered by a `DNLOAD` into that
//! buffer, executed by the EXEC/MEMC arm out of it, and the reply is read back from it by
//! `usb_core_do_transfer(0x80, mailbox, wLength, 0)`.
//!
//! That is the collision. A staged iBSS occupies `0x180380000..`, and from DFU state 5 — what a
//! held image leaves behind — the ROM consumes a `DNLOAD` as image data, so the mailbox can no
//! longer be written at all (`a9boot/READBUF.md` §1, MEASURED: `STAGED_IMAGE_MISMATCH`, then
//! `TIMEOUT`). The state that keeps the endpoint alive is the state in which our staging is eaten.
//!
//! # The request
//!
//! The read-window handler (`payloads/payload_handle_checkm8_readwindow.S`) adds one request code
//! that takes **its source from the request itself**:
//!
//! ```text
//!   bmRequestType 0xA1  bRequest 0x1F
//!   wValue  = window index   -> source = 0x180000000 + (wValue << 12)
//!   wIndex  = 0              (not read)
//!   wLength = byte count     -> the reply is exactly wLength bytes read from source
//! ```
//!
//! Because the source and the length come from the setup packet and the reply is produced by
//! `usb_core_do_transfer` from that source, the request needs **no `DNLOAD` and no mailbox**, so it
//! works while the buffer holds a staged image. The stock `0xA1/2 wValue 0xFFFF` arm is unchanged.
//!
//! # The bounds are the handler's, not the host's
//!
//! On this part an access outside the ROM's mapped SRAM **does not fault**: it stalls the bus and
//! there is no exception to recover (`RUNG2-EVIDENCE.md` §6.0p rule 1; the PMGR read that cost a
//! device). So the arm bounds its own read *before* any load — `index < 0x400`, `wLength != 0`, and
//! `(index << 12) + wLength <= 0x400000` — and tails into the ROM handler, which STALLs an unknown
//! class request, when any of them fails. The host then refuses locally too, and this module's
//! predicate is **derived from the handler's own instruction words** (see [`decode_read_arm`]) so
//! the two cannot drift apart silently.
//!
//! Everything here is device-free.

use crate::usb::CtrlReq;

// ---------------------------------------------------------------------------------------
// The request, and the window it can address
// ---------------------------------------------------------------------------------------

/// `bmRequestType`: class, interface, device-to-host. Same direction the stock trigger uses.
pub const READ_BM: u8 = 0xA1;
/// **The primary read rides the request that is PROVEN to reach the handler: `0xA1/2`**
/// (checkm8's own trigger code). MEASURED 2026: a brand-new bRequest (`0xA1/0x1F`) was silent
/// twice, so a novel request code is not a safe carrier — the ROM's USB core may filter what it
/// does not know before our handler is consulted. `0xA1/2` is distinguished from the stock trigger
/// by `wIndex`, below.
pub const READ_A12_BREQUEST: u8 = 0x02;
/// **The only `wValue` that reaches a handler: `0xFFFF`.** MEASURED on hardware, both directions:
/// `0xA1/0x1F` silent, `0xA1/2` with `wValue != 0xFFFF` silent (0 bytes, error, 4-5 µs), and
/// `0xA1/2` with `wValue == 0xFFFF` / `wIndex == 0` PASS with `DONE_MAGIC` + retval. So the read
/// rides this form and takes its window from `wIndex`.
pub const READ_TRIGGER_VALUE: u16 = 0xFFFF;
/// The `wIndex` below which the request is the stock command form rather than a read.
pub const READ_WINDEX_COMMAND: u16 = 0;
/// The **secondary** encoding: `bmRequestType 0xA1, bRequest 0x1F` (unassigned in DFU 1.1). Kept
/// because it costs four instructions and it is the experiment that settled the filtering question;
/// it is no longer the default, because on hardware it was silent.
pub const READ_NEW_BREQUEST: u8 = 0x1F;
/// The 16-bit word the handler compares for the secondary encoding: `bmRequestType | bRequest<<8`.
pub const READ_NEW_WORD: u16 = (READ_NEW_BREQUEST as u16) << 8 | READ_BM as u16;

/// The MEASURED mapped SRAM window: `0x180000000..0x180400000`, identity, 16 KiB pages at level 3
/// (`RUNG2-EVIDENCE.md` §6.0f(g): `0x1803FF000` MAPPED, `0x180400000` UNMAPPED).
pub const SRAM_BASE: u64 = 0x1_8000_0000;
/// 4 MiB — the whole measured window.
pub const SRAM_LEN: u64 = 0x40_0000;
/// The window granule the `wValue` index selects: `source = SRAM_BASE + (index << 12)`.
pub const GRANULE_SHIFT: u32 = 12;

/// Offset of the read arm inside the handler **code** (before the appended struct).
///
/// Pinned so the decode cannot silently follow a moved label, and asserted by
/// [`decode_read_arm`] against the instruction that must be there.
pub const ARM_OFF: usize = 0xEC;
/// Offset of the dispatch (`ldrh w2,[x0]; cmp w2,#0x2A1; b.eq _a1_2; …`) and of the literal that
/// carries the secondary request code.
pub const DISPATCH_OFF: usize = 0x0C;
/// The routed-form selection, and the **order that is the safety property**:
/// `ldrh w5,[x0,#2]` (wValue) / `mov w6,#0xFFFF` / `cmp` / `b.ne legacy` /
/// `ldrh w5,[x0,#4]` (wIndex) / `cbz w5, legacy` / `b arm`. The mailbox is never loaded on this
/// path.
pub const A12_OFF: usize = 0x28;
pub const WVALUE_LOAD_OFF: usize = 0x28;
pub const TRIGGER_MOV_OFF: usize = 0x2C;
pub const TRIGGER_CMP_OFF: usize = 0x30;
pub const WINDEX_LOAD_OFF: usize = 0x38;
pub const WINDEX_CBZ_OFF: usize = 0x3C;
pub const REQUEST_LITERAL_LOAD_OFF: usize = 0x18;
pub const REQUEST_LITERAL_OFF: usize = 0x13C;
/// Offset of `movz x1,#0x8000,lsl #16` / `movk x1,#0x1,lsl #32` inside the arm.
pub const ARM_MOVZ_OFF: usize = 0x114;
pub const ARM_MOVK_OFF: usize = 0x118;

// ---------------------------------------------------------------------------------------
// Encoding helpers (only the handful of forms this arm uses)
// ---------------------------------------------------------------------------------------

fn word(code: &[u8], off: usize) -> Result<u32, String> {
    let end = off + 4;
    if end > code.len() {
        return Err(format!(
            "HANDLER_ARM_SHORT: no 32-bit instruction at +{off:#x} (code is {} bytes)",
            code.len()
        ));
    }
    Ok(u32::from_le_bytes(code[off..end].try_into().unwrap()))
}

/// `MOVZ` (64-bit and 32-bit) and `MOVK` (64-bit), which is all the arm uses for constants.
/// Returns `(value, is_movk)`.
fn decode_mov_wide(w: u32) -> Option<(u64, bool)> {
    // sf(1) opc(2) 100101 hw(2) imm16(16) Rd(5)
    let top = w & 0x7F80_0000;
    let is_movk = matches!(w & 0xFF80_0000, 0xF280_0000);
    let is_movz64 = matches!(w & 0xFF80_0000, 0xD280_0000);
    let is_movz32 = matches!(w & 0xFF80_0000, 0x5280_0000);
    if !(is_movk || is_movz64 || is_movz32) {
        return None;
    }
    let _ = top;
    let hw = (w >> 21) & 0x3;
    let imm16 = ((w >> 5) & 0xFFFF) as u64;
    Some((imm16 << (hw * 16), is_movk))
}

/// `SUBS <Wd>, <Wn>, #imm12{, lsl #12}` — i.e. `CMP Wn, #imm`.
fn decode_cmp_imm(w: u32) -> Option<u32> {
    if w & 0xFF00_0000 != 0x7100_0000 {
        return None;
    }
    let imm12 = (w >> 10) & 0xFFF;
    let sh = (w >> 22) & 0x1;
    Some(imm12 << (sh * 12))
}

/// `CBZ <Wt>, label`.
fn decode_cbz(w: u32) -> Option<(u32, i64)> {
    if w & 0x7F00_0000 != 0x3400_0000 {
        return None;
    }
    let rt = w & 0x1F;
    let imm19 = ((((w >> 5) & 0x7FFFF) as i64) << 45) >> 45; // sign-extend 19 bits
    Some((rt, imm19 << 2))
}

/// `B` / `B.cond` — returns `(is_cond, offset)`.
fn decode_branch(w: u32) -> Option<(bool, i64)> {
    if w & 0xFC00_0000 == 0x1400_0000 {
        let imm26 = ((w & 0x03FF_FFFF) as i64) << 38 >> 38; // sign-extend 26 bits
        return Some((false, imm26 << 2));
    }
    if w & 0xFF00_0010 == 0x5400_0000 {
        let imm19 = (((w >> 5) & 0x7FFFF) as i64) << 45 >> 45;
        return Some((true, imm19 << 2));
    }
    None
}

/// `LDR <Xt|Wt>, <label>` (literal). Returns `(is_64, literal_address)`.
fn decode_ldr_literal(w: u32, pc: usize) -> Option<(bool, usize)> {
    if w & 0xFF00_0000 == 0x5800_0000 {
        let imm19 = (((w >> 5) & 0x7FFFF) as i64) << 45 >> 45;
        return Some((true, (pc as i64 + (imm19 << 2)) as usize));
    }
    if w & 0xFF00_0000 == 0x1800_0000 {
        let imm19 = (((w >> 5) & 0x7FFFF) as i64) << 45 >> 45;
        return Some((false, (pc as i64 + (imm19 << 2)) as usize));
    }
    None
}

/// `LSL <Wd>, <Wn>, #shift` as this arm assembles it (`UBFM`, shift = 32 - immr).
fn decode_lsl32(w: u32) -> Option<u32> {
    if w & 0xFFC0_0000 != 0x5300_0000 {
        return None;
    }
    let immr = (w >> 16) & 0x3F;
    let shift = (32 - immr) % 32;
    Some(shift)
}

// ---------------------------------------------------------------------------------------
// The decoded arm — the single source of truth for the predicate
// ---------------------------------------------------------------------------------------

/// The read arm as the **bytes on disk** describe it. Every field is decoded from an instruction;
/// none is a constant copied into this file. A mutated blob therefore decodes to a different arm
/// and the predicate changes with it — which is what makes the pinned tests able to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadArm {
    /// The 16-bit request word of the secondary encoding (`bmRequestType | bRequest << 8`).
    pub request_word: u16,
    /// The `wValue` that makes `0xA1/2` the routed form — decoded from the handler's own `mov`.
    pub trigger_value: u16,
    /// `source = base + (index << granule_shift)`.
    pub base: u64,
    pub granule_shift: u32,
    /// The index limit from `cmp wIndex, #limit`; an index at or above it is refused.
    pub index_limit: u32,
    /// The offset limit from `mov wEnd, #limit`; an end at or above it... strictly *above* is
    /// refused, so an end exactly at the limit is legal (the half-open window ends at SRAM top).
    pub offset_limit: u32,
    /// Does the arm refuse a zero-length read (`cbz wLength`)?
    pub refuses_zero_length: bool,
}

impl ReadArm {
    /// The window this arm would serve for `(index, len)`, or `None` for its own refusal.
    pub fn window(&self, index: u32, len: u32) -> Option<(u64, u32)> {
        if self.refuses_zero_length && len == 0 {
            return None;
        }
        if index >= self.index_limit {
            return None;
        }
        let off = (index as u64) << self.granule_shift;
        let end = off + len as u64;
        if end > self.offset_limit as u64 {
            return None;
        }
        Some((self.base + off, len))
    }

    /// Does this arm answer the secondary `0xA1/0x1F` encoding?
    pub fn matches(&self, request_word: u16) -> bool {
        request_word == self.request_word
    }

    /// Does this arm treat the request as a **read**? The routed form, a non-zero `wIndex`, and
    /// it is the `wValue` check that comes first in the handler — a request that fails it never
    /// reaches the `wIndex` test at all.
    pub fn matches_read(&self, bm: u8, b: u8, wvalue: u16, windex: u16) -> bool {
        bm == READ_BM
            && b == READ_A12_BREQUEST
            && wvalue == self.trigger_value
            && windex != READ_WINDEX_COMMAND
    }
}

/// Decode the read arm out of a handler **code** region.
///
/// Fails, by name, when the bytes are not the read-window handler — including when they are the
/// stock handler. That failure is the red control in `tests`: *the stock install has no read arm,
/// so a trigger-only read cannot be served by it.*
pub fn decode_read_arm(code: &[u8]) -> Result<ReadArm, String> {
    // 1. The dispatch literal must be where the source says and must carry the request word.
    let ldr = word(code, REQUEST_LITERAL_LOAD_OFF)?;
    let (is_64, lit_addr) = decode_ldr_literal(ldr, REQUEST_LITERAL_LOAD_OFF)
        .ok_or_else(|| "HANDLER_ARM_SHAPE: the dispatch is not `ldr Wt,<literal>`".to_string())?;
    if is_64 {
        return Err("HANDLER_ARM_SHAPE: the dispatch literal load is 64-bit, not 32-bit".into());
    }
    if lit_addr != REQUEST_LITERAL_OFF {
        return Err(format!(
            "HANDLER_ARM_SHAPE: the request literal is at +{lit_addr:#x}, not +{REQUEST_LITERAL_OFF:#x}"
        ));
    }
    let request_word = (word(code, lit_addr)? & 0xFFFF) as u16;
    if request_word != READ_NEW_WORD {
        return Err(format!(
            "HANDLER_REQUEST_WORD: the handler's secondary code is 0x{request_word:04X}, not \
             0x{READ_NEW_WORD:04X}"
        ));
    }

    // 1b. The routed form: `wValue == 0xFFFF` first, then `wIndex != 0` decides read vs command.
    //     Both are read out of the bytes — the immediate is decoded, not assumed.
    let wvalue_load = word(code, WVALUE_LOAD_OFF)?;
    if wvalue_load & 0xFFC0_0000 != 0x7940_0000 || (wvalue_load >> 10) & 0xFFF != 1 {
        return Err(format!(
            "HANDLER_ARM_SHAPE: +{WVALUE_LOAD_OFF:#x} is not `ldrh Wt,[X0,#2]` (word {wvalue_load:#010x})"
        ));
    }
    let (trigger_value, _) = decode_mov_wide(word(code, TRIGGER_MOV_OFF)?)
        .ok_or_else(|| "HANDLER_ARM_SHAPE: no `mov Wt,#imm` for the routed wValue".to_string())?;
    let trigger_value = trigger_value as u16;
    if trigger_value != READ_TRIGGER_VALUE {
        return Err(format!(
            "HANDLER_TRIGGER_VALUE: the handler routes on wValue 0x{trigger_value:04X}, not \
             0x{READ_TRIGGER_VALUE:04X}"
        ));
    }
    let windex_load = word(code, WINDEX_LOAD_OFF)?;
    if windex_load & 0xFFC0_0000 != 0x7940_0000 || (windex_load >> 10) & 0xFFF != 2 {
        return Err(format!(
            "HANDLER_ARM_SHAPE: +{WINDEX_LOAD_OFF:#x} is not `ldrh Wt,[X0,#4]` (word {windex_load:#010x})"
        ));
    }
    if decode_cbz(word(code, WINDEX_CBZ_OFF)?).is_none() {
        return Err("HANDLER_ARM_SHAPE: no `cbz wIndex` before the read branch".to_string());
    }
    // The mailbox must NOT be loaded before the read branch. The first `ldr x20,=insecure_memory_base`
    // in the handler must lie *after* the branch to the arm — that ordering is the safety property.
    let branch_to_arm = word(code, WINDEX_CBZ_OFF + 4)?;
    match decode_branch(branch_to_arm) {
        Some((false, off)) if (WINDEX_CBZ_OFF as i64 + 4 + off) as usize == ARM_OFF => {}
        other => {
            return Err(format!(
                "HANDLER_ARM_SHAPE: the read branch at +{:#x} does not target the arm \
                 (decoded {other:?})",
                WINDEX_CBZ_OFF + 4
            ))
        }
    }
    // The safety property is about CONTROL FLOW, not layout: the read path executes only the
    // dispatch block, and that block must contain no way to reach the mailbox — neither a load of
    // the mailbox address (`ldr x20,=<pool slot>`) nor a dereference of it (`ldr x0,[x20]`, which
    // is how the stock arm reads the magic). The stock body sitting *later* in the file is fine:
    // the read branch never falls into it.
    let dispatch_end = WINDEX_CBZ_OFF + 4;
    for off in (DISPATCH_OFF..dispatch_end).step_by(4) {
        let w = word(code, off)?;
        // `ldr x0,[x20]` = 0xF9400280, and `ldr x20,<literal>` = 0x5800_xxxx with Rt == 20.
        let derefs_mailbox = w == 0xF940_0280;
        let loads_mailbox_literal =
            (w & 0xFF00_0000 == 0x5800_0000) && (w & 0x1F) == 20;
        if derefs_mailbox || loads_mailbox_literal {
            return Err(format!(
                "HANDLER_MAILBOX_IN_DISPATCH: at +{off:#x} the dispatch reaches the mailbox \
                 (word {w:#010x}); the read path must not be able to touch it"
            ));
        }
    }

    // 2. The arm's entry must be the target of the `b` in the dispatch chain, and it must start
    //    with `ldrh wValue` / `ldrh wLength` — the shape that makes the source a request field.
    let b = word(code, 0x24)?;
    match decode_branch(b) {
        Some((false, off)) if (0x24i64 + off) as usize == ARM_OFF => {}
        other => {
            return Err(format!(
                "HANDLER_ARM_SHAPE: +0x24 is not `b +{ARM_OFF:#x}` (decoded {other:?})"
            ))
        }
    }
    let first = word(code, ARM_OFF)?;
    // `ldrh Wt,[Xn,#imm]` (unsigned offset form 0x79400000). The 12-bit immediate is scaled by
    // the access size: byte offset 4 (wIndex) is imm12 = 2, byte offset 6 is imm12 = 3.
    if first & 0xFFC0_0000 != 0x7940_0000 || (first >> 10) & 0xFFF != 0x2 {
        return Err(format!(
            "HANDLER_ARM_SHAPE: the arm does not start with `ldrh Wt,[X0,#4]` — it must take the \
             window from wIndex, not wValue (word {first:#010x})"
        ));
    }
    let second = word(code, ARM_OFF + 4)?;
    if second & 0xFFC0_0000 != 0x7940_0000 || (second >> 10) & 0xFFF != 0x3 {
        return Err(format!(
            "HANDLER_ARM_SHAPE: +{:#x} is not `ldrh Wt,[X0,#6]` (word {second:#010x})",
            ARM_OFF + 4
        ));
    }

    // 3. The three refusals, decoded.
    let cbz = decode_cbz(word(code, ARM_OFF + 8)?)
        .ok_or_else(|| "HANDLER_ARM_SHAPE: no `cbz` before the bounds".to_string())?;
    let refuses_zero_length = cbz.0 == second & 0x1F; // the register the length was loaded into
    let index_limit = decode_cmp_imm(word(code, ARM_OFF + 0xC)?)
        .ok_or_else(|| "HANDLER_ARM_SHAPE: no `cmp wIndex,#limit`".to_string())?;
    let granule_shift = decode_lsl32(word(code, ARM_OFF + 0x14)?)
        .ok_or_else(|| "HANDLER_ARM_SHAPE: no `lsl wEnd,wIndex,#shift`".to_string())?;
    let offset_limit = decode_mov_wide(word(code, ARM_OFF + 0x1C)?)
        .ok_or_else(|| "HANDLER_ARM_SHAPE: no `mov wEnd,#limit`".to_string())?
        .0 as u32;

    // 4. The base, from `movz`/`movk` (order and shift both checked).
    let (movz_value, movz_is_movk) = decode_mov_wide(word(code, ARM_MOVZ_OFF)?)
        .ok_or_else(|| "HANDLER_ARM_SHAPE: no `movz` for the base".to_string())?;
    if movz_is_movk {
        return Err("HANDLER_ARM_SHAPE: the base starts with `movk`, not `movz`".into());
    }
    let (movk_value, movk_is_movk) = decode_mov_wide(word(code, ARM_MOVK_OFF)?)
        .ok_or_else(|| "HANDLER_ARM_SHAPE: no `movk` for the base".to_string())?;
    if !movk_is_movk {
        return Err("HANDLER_ARM_SHAPE: the second base instruction is not `movk`".into());
    }
    let base = movz_value | movk_value;

    Ok(ReadArm {
        request_word,
        trigger_value,
        base,
        granule_shift,
        index_limit,
        offset_limit,
        refuses_zero_length,
    })
}

/// The arm of the vendored read-window handler, or an error naming what is wrong with the blob.
pub fn vendored_arm() -> Result<ReadArm, String> {
    decode_read_arm(&crate::payload::PAYLOAD_HANDLE_CHECKM8_READWINDOW
        [..crate::payload::READWINDOW_CODE_LEN])
}

// ---------------------------------------------------------------------------------------
// Host-side request building and judging
// ---------------------------------------------------------------------------------------

/// Refusals, one per predicate. Each has a firing control in `tests` that makes it fire by name.
pub const MISALIGNED: &str = "READ_WINDOW_MISALIGNED";
pub const ZERO_LENGTH: &str = "READ_WINDOW_ZERO_LENGTH";
pub const OUTSIDE_SRAM: &str = "READ_WINDOW_OUTSIDE_SRAM";
pub const INDEX_RANGE: &str = "READ_WINDOW_INDEX_RANGE";
pub const SHORT_REPLY: &str = "READ_WINDOW_SHORT_REPLY";
/// **`wIndex == 0` is not window 0 — it is the stock command form.** The handler's dispatch is
/// `ldrh w5,[x0,#4]` / `cbz w5,_legacy`: a zero `wIndex` leaves the read arm entirely and runs the
/// legacy/stock arm, which loads `[mailbox]` and — on a stale `EXEC_MAGIC` — `blr`s a function
/// pointer read out of the buffer. So `0x180000000` (its own granule index 0) is **not addressable
/// by this read**, and the tool must refuse it rather than emit it and print the mailbox as memory.
/// `matches_read` (the handler's own predicate) already excludes `windex == 0`; this is that same
/// exclusion applied where the request is built.
pub const WINDEX_IS_COMMAND: &str = "READ_WINDOW_WINDEX_IS_COMMAND";

/// Turn an absolute `addr`/`len` into the `wValue` index this arm expects, or refuse by name.
///
/// The predicate is the arm's own: `index < index_limit`, the whole window inside
/// `base..base+offset_limit`, and a non-zero length.
pub fn window_index(arm: &ReadArm, addr: u64, len: u16) -> Result<u16, String> {
    if len == 0 {
        return Err(format!(
            "{ZERO_LENGTH}: a zero-length read is not a read (the handler refuses it too, via `cbz`)"
        ));
    }
    if addr < arm.base {
        return Err(format!(
            "{OUTSIDE_SRAM}: {addr:#x} is below the mapped SRAM window {:#x}",
            arm.base
        ));
    }
    let off = addr - arm.base;
    if off % (1u64 << arm.granule_shift) != 0 {
        return Err(format!(
            "{MISALIGNED}: {addr:#x} is not aligned to the handler's {}-byte granule",
            1u64 << arm.granule_shift
        ));
    }
    let index = off >> arm.granule_shift;
    // `wIndex == 0` is the stock command form, not window 0 (see `WINDEX_IS_COMMAND`). Refuse it
    // here, where the request would otherwise be built: the handler's `cbz w5,_legacy` means the
    // read arm is never entered for this index.
    if index == READ_WINDEX_COMMAND as u64 {
        return Err(format!(
            "{WINDEX_IS_COMMAND}: {addr:#x} is granule index 0, and wIndex 0 is NOT a read — the \
             handler's `cbz` leaves the read arm and the stock arm loads [mailbox] and can blr a \
             function pointer out of whatever is staged there. Window 0 is therefore unreachable by \
             this encoding; start at {:#x} (index 1).",
            arm.base + (1u64 << arm.granule_shift)
        ));
    }
    if index >= arm.index_limit as u64 {
        return Err(format!(
            "{INDEX_RANGE}: window index {index} is at or past the handler's limit {} \
             (window {:#x} .. {:#x})",
            arm.index_limit,
            arm.base,
            arm.base + arm.offset_limit as u64
        ));
    }
    let end = off
        .checked_add(len as u64)
        .ok_or_else(|| format!("{OUTSIDE_SRAM}: {addr:#x}+{len} wraps"))?;
    if end > arm.offset_limit as u64 {
        return Err(format!(
            "{OUTSIDE_SRAM}: {addr:#x}+{len:#x} ends at {:#x}, past the handler's limit {:#x} \
             (mapped SRAM is {:#x}..{:#x})",
            arm.base + end,
            arm.base + arm.offset_limit as u64,
            arm.base,
            arm.base + arm.offset_limit as u64
        ));
    }
    Ok(index as u16)
}

/// The control request that performs the read, over **the routed form**: `0xA1/2` with
/// `wValue = 0xFFFF` (the only `wValue` MEASURED to reach a handler) and the window in `wIndex`
/// (`wIndex == 0` is the stock command form).
///
/// Both other encodings were MEASURED filtered on hardware: the novel `0xA1/0x1F` (silent) and
/// `0xA1/2` with `wValue != 0xFFFF` (0 bytes, error, 4-5 µs). This one is the form the control
/// PASSED.
///
/// **Safety, and its limit.** With *this* handler resident the read is safe by construction: the
/// handler checks `wValue`, then `wIndex`, and branches to the arm **without loading the mailbox**,
/// so a stale `EXEC_MAGIC` cannot be executed. With the **stock** handler resident this request is
/// a **hazard**, not a read: the stock arm requires `wValue == 0xFFFF` and then loads the mailbox
/// magic, so a stale `EXEC_MAGIC` there is a wild execute. The request is reachable, not
/// unconditionally safe, and the difference is which handler is resident.
pub fn read_window_request(arm: &ReadArm, addr: u64, len: u16) -> Result<CtrlReq, String> {
    let index = window_index(arm, addr, len)?;
    // The host's policy bound, separate from the arm's safety bound: two read tools in this tree
    // must not disagree about what a window is (see `READ_MAX_LEN`).
    if len > READ_MAX_LEN {
        return Err(format!(
            "{TOO_LONG}: {len:#x} bytes in one reply; the session's window is {READ_MAX_LEN:#x} \
             (a9boot/READBUF.md §9 reads windows of 0x1000). Split the span into consecutive \
             windows. The handler's own bound is the SRAM window and is wider than this; this is a \
             host policy bound, and it is the one both tools use."
        ));
    }
    Ok(CtrlReq::new(
        READ_BM,
        READ_A12_BREQUEST,
        arm.trigger_value,
        index,
        len,
    ))
}

/// The **secondary** encoding (`0xA1/0x1F`), kept for the record and for the experiment that
/// settled the request-filtering question. Not the default: MEASURED silent on hardware.
pub fn read_window_request_newcode(arm: &ReadArm, addr: u64, len: u16) -> Result<CtrlReq, String> {
    let index = window_index(arm, addr, len)?;
    if len > READ_MAX_LEN {
        return Err(format!("{TOO_LONG}: {len:#x} exceeds {READ_MAX_LEN:#x}"));
    }
    Ok(CtrlReq::new(READ_BM, READ_NEW_BREQUEST, index, 0, len))
}

/// Judge a read window's reply by **content**: it must be exactly the number of bytes asked for.
///
/// There is no magic to look for here and that is the point: this reply is raw memory, not a
/// command's `{DONE_MAGIC, ret}` framing. A caller that judged it as a command would call every
/// successful read a failure (`a9boot/READBUF.md` §8 makes the same distinction).
pub fn judge_read_window(reply: &[u8], requested: usize) -> Result<(), String> {
    if reply.len() != requested {
        return Err(format!(
            "{SHORT_REPLY}: the device returned {} byte(s) of the {requested} asked for. A short \
             reply is not a partial answer and must not be hashed, compared or reported as bytes \
             of the image.",
            reply.len()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The hook slot, so a read of its page answers "which handler is installed?"
// ---------------------------------------------------------------------------------------

/// `dfu_handle_request` — the 8-byte slot in ROM RAM that `payload_A9` repoints to the copied
/// handler's body (see `a9boot/HANDLER-RELOCATION.md` §1.2, INSPECTED from the blob). It is
/// `0x180087000 + 0x8F8`, so it lies in window index `0x87`.
pub const HOOK_SLOT: u64 = 0x1800_878F8;
/// The value the hook holds when the **stock** handler is installed (`payload_dest + 0xC`).
pub const HOOK_STOCK: u64 = 0x1800_E0F14;
/// The value the hook holds when **this** handler is installed (`0x1800E0E88 + 0xC`).
pub const HOOK_READWINDOW: u64 = 0x1800_E0E94;
/// The ROM's own request handler (`handle_interface_request`), i.e. the hook was never set.
pub const HOOK_ROM: u64 = 0x1_0000_F1B0;

/// If `[addr, addr+len)` covers [`HOOK_SLOT`], decode it and name what it says. `None` when the
/// window does not cover the slot — never a guess from a partial read.
///
/// This is the instrument for "is the handler installed *and* reached": a read that returns the
/// window's own bytes can only have been served by a handler that reads from the request, and the
/// value it returns says *which* handler that was. A stock handler answers this request from the
/// mailbox instead, so the bytes at this offset will not be a plausible hook value at all.
pub fn hook_in_window(addr: u64, len: u16, bytes: &[u8]) -> Option<(u64, &'static str)> {
    let end = addr.checked_add(len as u64)?;
    if HOOK_SLOT < addr || HOOK_SLOT + 8 > end {
        return None;
    }
    let off = (HOOK_SLOT - addr) as usize;
    if off + 8 > bytes.len() {
        return None;
    }
    let v = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
    let what = match v {
        HOOK_READWINDOW => "the readwindow handler — installed AND reached",
        HOOK_STOCK => "the STOCK handler — the readwindow install did not land",
        HOOK_ROM => "the ROM's own handle_interface_request — the hook was never set",
        _ => "not a value any install of ours writes (see the raw bytes)",
    };
    Some((v, what))
}

/// What the arm would serve, as a sentence for `a9pwn plan`-style output. Never a claim that a
/// device did anything: it is a description of the installed handler, from the handler's bytes.
pub fn plan_line(arm: &ReadArm, addr: u64, len: u16) -> String {
    match read_window_request(arm, addr, len) {
        Ok(r) => format!(
            "read window {addr:#x}+{len:#x}: bmRequestType {:#04x} bRequest {:#04x} wValue {:#06x} \
             (source {:#x}) wLength {:#06x} — no DNLOAD, no mailbox",
            // F2 (review/04): the routed encoding puts the window in `wIndex`; `wValue` is the
            // 0xFFFF marker, so `base + (value << 12)` described a non-existent 0x18FFFF000.
            r.bm, r.b, r.value, arm.base + ((r.index as u64) << arm.granule_shift), r.length
        ),
        Err(e) => format!("read window {addr:#x}+{len:#x}: REFUSED — {e}"),
    }
}

// ---------------------------------------------------------------------------------------
// The handler-shape probe: the one request that is safe on EVERY handler and still separates
// the OLD encoding from the routed one
// ---------------------------------------------------------------------------------------
//
// ## The mismatch this exists for
//
// The routed read needs `wValue == 0xFFFF`. That is also the value that arms the **stock**
// data-driven path, and the value that the **old** read-window handler (`wValue` = index,
// `wIndex = 0xA95A`) falls through to the legacy path with. So:
//
// | resident handler | routed read (`wValue 0xFFFF, wIndex != 0`) |
// |---|---|
// | this (routed) handler | the read arm — safe, mailbox untouched |
// | old read-window handler | `wIndex != 0xA95A` -> legacy -> `wValue == 0xFFFF` -> **stock data-driven arm** |
// | stock handler | `wValue == 0xFFFF` -> **stock data-driven arm** |
//
// i.e. new client + old handler is the wild-execute case, and an operator who rebuilds one side
// and not the other walks into it. The client cannot read the hook to check first: the only
// instrument that decodes the hook is the read itself. Hence this probe, and the explicit
// acknowledgement below it.
//
// ## What the probe is, and why it is safe on every handler
//
// ```
// bmRequestType 0xA1, bRequest 0x02, wValue 0x00E0 (never 0xFFFF), wIndex 0xA95A, wLength 0x40
// ```
//
// * **old handler**: `wIndex == 0xA95A` selects its read arm, which reads the window at
//   `0x180000000 + (wValue << 12)` = `0x1800E0000` — a bounded SRAM read, no mailbox access.
// * **routed handler**: `wValue != 0xFFFF` -> legacy -> `wValue != 0xFFFF` -> reply from the
//   mailbox, **without loading `[mailbox]`**.
// * **stock handler**: identical to the routed one's path — reply from the mailbox, no magic load.
//
// So **no handler loads `[mailbox]` for this request**, and none can execute anything. The reply
// content is what discriminates: the old handler answers with the live trampoline slot at
// `0x1800E0000` (MEASURED empty in DFU, `RE-TRAMPOLINE.md` §3 — all zero), while the routed and
// stock handlers both answer with the mailbox's first 0x40 bytes (the held image's DER header when
// an image is staged).
//
// ## What it cannot tell you, said plainly
//
// **It cannot separate the routed handler from the STOCK one.** The routed handler's only unique
// behaviour sits behind `wValue == 0xFFFF`, which is exactly the value that arms the stock path, so
// no safe request can ask for it. Stock-vs-routed is therefore covered by the **install record**
// (`PATCH blob : handler=… sha256 …`, printed on every run) and by the operator's explicit
// acknowledgement — not by the wire.
pub const SHAPE_PROBE_VALUE: u16 = 0x00E0;
/// The old encoding's discriminator, reused as this probe's selector so the old handler answers
/// from a window rather than falling through to its legacy path.
pub const SHAPE_PROBE_MAGIC: u16 = 0xA95A;
/// The window the old handler will read for [`SHAPE_PROBE_VALUE`]: `0x1800E0000`.
pub const SHAPE_PROBE_WINDOW: u64 = 0x1800_E0000;

/// The shape verdicts. One per outcome, so "the old handler answered", "the routed or stock
/// handler answered" and "nothing answered" cannot be confused.
pub const SHAPE_OLD_HANDLER: &str = "HANDLER_SHAPE_OLD_WVALUE_INDEX";
pub const SHAPE_ROUTED_OR_STOCK: &str = "HANDLER_SHAPE_ROUTED_OR_STOCK";
pub const SHAPE_UNKNOWN: &str = "HANDLER_SHAPE_UNKNOWN";

/// The safe probe request. **Never `wValue == 0xFFFF`** — see the module comment.
pub fn shape_probe_request(len: u16) -> CtrlReq {
    CtrlReq::new(
        READ_BM,
        READ_A12_BREQUEST,
        SHAPE_PROBE_VALUE,
        SHAPE_PROBE_MAGIC,
        len,
    )
}

/// Classify the probe's reply. `None` is used for "no reply at all", which is `SHAPE_UNKNOWN`
/// rather than either of the two positive answers.
pub fn classify_shape(reply: &[u8]) -> (&'static str, String) {
    if reply.is_empty() {
        return (
            SHAPE_UNKNOWN,
            "the shape probe returned no bytes: no statement about which handler is resident. The \
             routed read is NOT authorised by this result."
                .to_string(),
        );
    }
    if reply.iter().all(|b| *b == 0) {
        return (
            SHAPE_OLD_HANDLER,
            format!(
                "the reply is all zero, which is what the OLD handler answers: it selected its read \
                 arm on wIndex 0x{SHAPE_PROBE_MAGIC:04X} and read the live trampoline slot at \
                 {SHAPE_PROBE_WINDOW:#x} (MEASURED empty in DFU). A routed read now would take the \
                 legacy path on that handler, hit the stock data-driven arm on wValue 0xFFFF, and \
                 load [mailbox] — DO NOT send the routed read against this device."
            ),
        )
    }
    (
        SHAPE_ROUTED_OR_STOCK,
        format!(
            "the reply is non-zero, so the OLD handler is excluded: it would have answered from \
             {SHAPE_PROBE_WINDOW:#x}. The resident handler is the routed one or the stock one, and \
             no safe request can tell those two apart (the routed handler's unique behaviour needs \
             wValue 0xFFFF, the value that arms the stock path). The install record — `PATCH blob : \
             handler=… sha256 …` — is what covers that gap."
        ),
    )
}

/// The gate between the shape probe and the hazardous routed read (instrument fix 3; review/04
/// F4). The routed read (`wValue 0xFFFF`) is safe only against the routed/stock handler; against
/// anything else it is the wild-execute path. `SHAPE_UNKNOWN` used to print a warning and SEND
/// ANYWAY — the dangerous request went out exactly when the instrument had no information. Now
/// only a positive `SHAPE_ROUTED_OR_STOCK` authorises the read; `SHAPE_OLD_HANDLER` and
/// `SHAPE_UNKNOWN` both refuse by name, and `allow_unknown` (`--unsafe-shape-unknown`, the
/// operator's explicit, deliberately unsafe override) is the only way an unknown proceeds.
pub fn shape_gate(code: &str, allow_unknown: bool) -> Result<(), String> {
    match code {
        SHAPE_ROUTED_OR_STOCK => Ok(()),
        SHAPE_OLD_HANDLER => Err(format!(
            "{SHAPE_OLD_HANDLER}: the OLD handler is resident — the routed read would take its \
             legacy path on wValue 0xFFFF, load [mailbox] and can `blr` a function pointer out of \
             whatever is staged there (the round-6 wild execute). The routed read was NOT sent."
        )),
        SHAPE_UNKNOWN if allow_unknown => Ok(()),
        _ => Err(format!(
            "{SHAPE_UNKNOWN}: the probe produced no statement about which handler is resident, and \
             the routed read is NOT authorised by an unknown answer — it is the wild-execute path \
             against every handler but the routed one. The read was NOT sent. (--unsafe-shape-\
             unknown overrides this, deliberately unsafely.)"
        )),
    }
}

// ---------------------------------------------------------------------------------------
// Running it on a device
// ---------------------------------------------------------------------------------------

/// **The precondition could not be read at all**: the ROM did not answer its own `GET_STATUS`.
///
/// Checked **immediately before** the read, in the same invocation, on the *ROM's* own path
/// (`0xA1/0x03`, served by ROM code at `0x10000F1B0`) and not through our channel — rule 15: the
/// instrument must not depend on the thing being diagnosed. Rule 14: read fresh, never cached.
///
/// **Why the state *number* is not the gate (rule 13).** Two different states both read `8`: the
/// checkm8 aftermath, where the channel answers every command (MEASURED 5/5), and the aftermath of
/// the ROM *committing a valid image*, where it answers nothing. A gate that waited for the number
/// would pass in both, so the honest check is weaker: *the ROM answered this invocation, and here
/// is the state it reported*. The number is printed and the operator judges it; a silent read is a
/// named refusal, not a retry.
///
/// This is also why `a9boot-host`'s `exec::poll_to_state8` is **not** called here. It lives in a
/// different crate (no dependency edge exists and `INTERFACE.md` §0.4 forbids adding one) and — more
/// importantly — it would wait for state 8, while the state in which a **held** image can be read at
/// all is state 5 (`a9boot/READBUF.md` §1: at 5 the ROM eats a `DNLOAD`, which is exactly why this
/// request needs none). A read instrument that refuses the one state it exists for is the wrong
/// instrument. `--expect-state N` is the explicit form of the number check, opt-in.
pub const PREFLIGHT_SILENT: &str = "READ_WINDOW_PREFLIGHT_ROM_SILENT";
/// The device left the request pending and returned no bytes. Nothing came back.
pub const SILENT: &str = "READ_WINDOW_SILENT";
/// The device returned fewer bytes than asked for. Never hashed, compared or reported (U-19's class).
pub const SHORT: &str = "READ_WINDOW_SHORT";
/// The window does not match the bytes supplied to compare against at that offset.
pub const MISMATCH: &str = "READ_WINDOW_MISMATCH";
/// The read itself failed at the transport, one named outcome per status (instrument fix 2;
/// review/04 F8). Every non-`Ok` status used to collapse into `SILENT`, which is a claim about
/// the DEVICE ("returned 0 of N bytes") when the failure is on the WIRE — and the sync API's
/// substituted `transferred = 0` made the collapse look measured. A STALL in particular is the
/// observable that says "the request did not reach our arm (or the handler refused it)" and must
/// not be reported in the same words as a timeout.
pub const STALL: &str = "READ_WINDOW_STALL";
pub const TIMEOUT: &str = "READ_WINDOW_TIMEOUT";
pub const NO_DEVICE: &str = "READ_WINDOW_NO_DEVICE";
pub const IO: &str = "READ_WINDOW_IO";
/// The host's own policy bound on a single reply. **The ARM-side bound is the safety bound**; this
/// one exists so two read tools in this tree do not disagree about what a window is.
///
/// `0x1000` is the session's agreed window size: `a9boot/READBUF.md` §9 reads windows of `0x1000`,
/// and the handler's own window granule is `0x1000`, so a window never needs to be larger — a
/// longer span is walked as consecutive windows. The handler itself would serve any span that fits
/// mapped SRAM; refusing here keeps one reply to one transfer's worth of data.
pub const READ_MAX_LEN: u16 = 0x1000;
pub const TOO_LONG: &str = "READ_WINDOW_TOO_LONG";
/// A state the operator required with `--expect-state` was not the state the ROM reported.
pub const UNEXPECTED_STATE: &str = "READ_WINDOW_UNEXPECTED_STATE";

/// The outcome of one read, with the counters a verdict needs (rule 14's corollary).
///
/// Not `PartialEq`: `CtrlReq` (in `usb.rs`, another owner's file) carries no comparison derives,
/// and an outcome is read by field in the transcript rather than compared whole.
#[derive(Debug, Clone)]
pub struct ReadOutcome {
    pub addr: u64,
    pub len: u16,
    /// The request actually sent, or the one that *would* have been sent in a dry run.
    pub request: CtrlReq,
    /// The ROM's own `GET_STATUS` state read immediately before, or `None` when it was silent.
    pub state_before: Option<u8>,
    /// `Some(refusal)` when nothing was sent.
    pub refused: Option<String>,
    /// `PLANNED` (dry run), `OK`, `SILENT`, `SHORT`, a transport outcome
    /// (`STALL`/`TIMEOUT`/`NO_DEVICE`/`IO`), or a refusal name.
    pub code: String,
    /// The bytes received. Empty unless `code == OK`.
    pub bytes: Vec<u8>,
    pub transferred: usize,
    /// Is `transferred` a measurement? `false` only after a failed transfer, where the sync API's
    /// `transferred = 0` is FABRICATED (see `XferResult::transferred_measured` and `usb.rs`).
    pub transferred_known: bool,
    /// What libusb had written into the buffer when a FAILED transfer ended: evidence, with an
    /// UNVERIFIED length — never reported as memory (`code != OK` keeps it out of `bytes`).
    pub prefix_unverified: Vec<u8>,
    pub micros: u64,
    /// The transport status token for the read itself (`OK`, `TIMEOUT`, ...).
    pub transport: String,
}

impl ReadOutcome {
    pub fn ok(&self) -> bool {
        self.code == "OK"
    }
    /// A dry run built the request and sent nothing. Not a success, not a failure.
    pub fn planned(&self) -> bool {
        self.code == "PLANNED"
    }
}

/// Shannon entropy of `bytes` in bits/byte, and as a fraction of the window's own ceiling.
///
/// **Per window, never one number** (`a9boot/IBSS-UPLOAD.md` §3.7): a whole-region average hides a
/// partial staging. 256 samples over 256 values have an expected distinct count of ~162, so the
/// ceiling-normalised fraction is the comparable figure, not the raw bits/byte.
pub fn entropy(bytes: &[u8]) -> (f64, f64) {
    if bytes.is_empty() {
        return (0.0, 0.0);
    }
    let mut counts = [0u32; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0f64;
    for c in counts {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    let ceiling = (bytes.len().min(256) as f64).log2();
    (h, if ceiling > 0.0 { h / ceiling } else { 0.0 })
}

/// The fraction of bytes that are printable ASCII (0x20..=0x7E).
pub fn printable_fraction(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let n = bytes.iter().filter(|b| (0x20..=0x7E).contains(*b)).count();
    n as f64 / bytes.len() as f64
}

/// The first `n` bytes as hex, for a transcript. The caller bounds `n`.
pub fn hex_preview(bytes: &[u8], n: usize) -> String {
    bytes
        .iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// One report of a reply **as memory**: no magic, no framing, no command semantics.
///
/// The `DONE_MAGIC` demand that a command reply uses must never be applied here: this reply is raw
/// bytes, and a successful read judged as a command would be called a failure (U-19's class;
/// `a9boot/IBSS-UPLOAD.md` §12.2's `RAW_UPLOAD_READS_BUFFER` is the same distinction).
pub fn memory_report(bytes: &[u8]) -> String {
    let (h, frac) = entropy(bytes);
    format!(
        "{} byte(s) of memory · entropy {h:.3} bits/byte ({frac:.3} of the window's own ceiling) · \
         printable {:.1}% · first {}: {}",
        bytes.len(),
        printable_fraction(bytes) * 100.0,
        hex_preview(bytes, 48).len() / 2,
        hex_preview(bytes, 48)
    )
}

/// Compare a reply against the bytes of `expected` at `offset` — the machine-decided MATCH/MISMATCH.
/// A short reply never reaches here (`judge_bytes` refuses it first).
pub fn compare(expected: &[u8], offset: usize, got: &[u8]) -> Result<(), String> {
    let end = offset
        .checked_add(got.len())
        .ok_or_else(|| format!("{MISMATCH}: the comparison offset overflows"))?;
    if end > expected.len() {
        return Err(format!(
            "{MISMATCH}: the window ends at {end}, past the end of the {} bytes supplied to compare \
             against. That is a wrong image base or a wrong length, not a mismatch in the image.",
            expected.len()
        ));
    }
    if expected[offset..end] != *got {
        let first = expected[offset..end]
            .iter()
            .zip(got)
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        return Err(format!(
            "{MISMATCH}: the first differing byte is at +{first:#x} in the window (device {:#04x}, \
             file {:#04x})",
            got[first], expected[offset + first]
        ));
    }
    Ok(())
}

/// Judge a reply **by its length**, which is all the contract says (`transferred == 0` is silence).
///
/// Call this ONLY on a measured transfer (`XferResult::transferred_measured`): a failed transfer
/// is named by its transport outcome (`STALL`/`TIMEOUT`/`NO_DEVICE`/`IO`) before this is reached,
/// so a `0` here is the device's own silence — not the sync API's substituted count (fix 2).
pub fn judge_bytes(transferred: usize, requested: usize) -> Result<(), String> {
    if transferred == 0 {
        return Err(format!(
            "{SILENT}: the device returned 0 of the {requested} bytes asked for. A silent read is \
             not a read of zeros — it is no answer, and it is never reported as contents."
        ));
    }
    if transferred < requested {
        return Err(format!(
            "{SHORT}: the device returned {transferred} of {requested} bytes. A graded partial is \
             not a window and must not be hashed, compared or reported as memory."
        ));
    }
    Ok(())
}


/// `PLANNED` — a dry run built the request and sent nothing.
pub const PLANNED: &str = "PLANNED";

/// The precondition read, as two separate facts: what state the ROM reported, and what the
/// transport said about the read itself. `None` state means *unread*, never "unchanged".
pub fn preflight(t: &mut crate::usb::Transport, timeout_ms: u32) -> (Option<u8>, String) {
    // The ROM's own DFU_GET_STATUS (0xA1/0x03, 6 bytes), not our channel: rule 15.
    let req = CtrlReq::new(0xA1, crate::DFU_GETSTATUS, 0, 0, 6);
    let mut buf = [0u8; 6];
    let r = t.control(req, &mut buf, timeout_ms);
    let state = if r.transferred >= 5 { Some(buf[4]) } else { None };
    (state, format!("{:?}", r.status))
}

/// Run one read window. **The only function here that touches a device.**
///
/// Order, and each step's reason:
///
/// 1. the arm predicate and the host's window bound — a bad address or length costs **nothing**,
///    no transfer is built, because the handler's bound is the safety bound and the host's is the
///    policy bound;
/// 2. the ROM's own `GET_STATUS`, **fresh in this invocation** (rule 14) and on the ROM's path
///    (rule 15) — reported, and refused by name if it does not answer;
/// 3. the read `0xA1/0x1F`, judged by **length only** and reported as memory.
///
/// A dry run stops after step 1 and reports the exact SETUP fields it would send.
pub fn run(
    t: &mut crate::usb::Transport,
    arm: &ReadArm,
    addr: u64,
    len: u16,
    timeout_ms: u32,
    expect_state: Option<u8>,
    dry_run: bool,
) -> ReadOutcome {
    let request = match read_window_request(arm, addr, len) {
        Ok(r) => r,
        Err(e) => {
            return ReadOutcome {
                addr,
                len,
                request: CtrlReq::new(READ_BM, READ_A12_BREQUEST, arm.trigger_value, 0, len),
                state_before: None,
                refused: Some(e.clone()),
                code: e.split(':').next().unwrap_or(e.as_str()).to_string(),
                bytes: Vec::new(),
                transferred: 0,
                transferred_known: true,
                prefix_unverified: Vec::new(),
                micros: 0,
                transport: "NOT_SENT".to_string(),
            }
        }
    };

    if dry_run {
        return ReadOutcome {
            addr,
            len,
            request,
            state_before: None,
            refused: None,
            code: PLANNED.to_string(),
            bytes: Vec::new(),
            transferred: 0,
            transferred_known: true,
            prefix_unverified: Vec::new(),
            micros: 0,
            transport: "NOT_SENT".to_string(),
        };
    }

    let (state_before, preflight_transport) = preflight(t, timeout_ms);
    if state_before.is_none() {
        return ReadOutcome {
            addr,
            len,
            request,
            state_before,
            refused: Some(format!(
                "{PREFLIGHT_SILENT}: the ROM did not answer its own DFU_GET_STATUS before the read \
                 (transport {preflight_transport}). Nothing was sent: without a live precondition \
                 read, silence from the read itself could not be told apart from a device that is \
                 gone."
            )),
            code: PREFLIGHT_SILENT.to_string(),
            bytes: Vec::new(),
            transferred: 0,
            transferred_known: true,
            prefix_unverified: Vec::new(),
            micros: 0,
            transport: preflight_transport,
        };
    }
    if let Some(want) = expect_state {
        if state_before != Some(want) {
            return ReadOutcome {
                addr,
                len,
                request,
                state_before,
                refused: Some(format!(
                    "{UNEXPECTED_STATE}: --expect-state {want} was required but the ROM reported \
                     {}. Nothing was sent. (A number is not a state, rule 13; this refusal is the \
                     operator's own gate being enforced, and it is honest about which number it \
                     saw.)",
                    state_before.unwrap()
                )),
                code: UNEXPECTED_STATE.to_string(),
                bytes: Vec::new(),
                transferred: 0,
                transferred_known: true,
                prefix_unverified: Vec::new(),
                micros: 0,
                transport: preflight_transport,
            };
        }
    }

    let mut buf = vec![0u8; len as usize];
    let r = t.control(request, &mut buf, timeout_ms);
    let transferred = r.transferred.min(buf.len());
    let transport = format!("{:?}", r.status);
    // INSTRUMENT FIX 2 (review/04 F8): a failed transfer carries NO transferred length — the sync
    // API substitutes 0 (`usb.rs`, named there) — so it must not be judged as "the device returned
    // 0 of N bytes". The failure is named per status, and what libusb had written into the buffer
    // SURVIVES as `prefix_unverified` (length unverified) instead of being discarded: for a STALL
    // of the routed read that prefix is the only recoverable evidence.
    if !r.transferred_measured() {
        let code = match r.status {
            crate::types::XferStatus::Stall => STALL,
            crate::types::XferStatus::Timeout => TIMEOUT,
            crate::types::XferStatus::NoDevice => NO_DEVICE,
            _ => IO,
        };
        return ReadOutcome {
            addr,
            len,
            request,
            state_before,
            refused: Some(format!(
                "{code}: the read did not complete — transport {transport} (libusb_rc {}). The \
                 synchronous control API reports NO length on failure, so `transferred` is not a \
                 measurement here and \"the device returned 0 of {len} bytes\" would be a fabricated \
                 claim. What libusb had written into the buffer survives as `prefix_unverified` \
                 (length UNVERIFIED, not memory): {}",
                r.libusb_rc,
                hex_preview(&buf, 48)
            )),
            code: code.to_string(),
            bytes: Vec::new(),
            transferred: 0,
            transferred_known: false,
            prefix_unverified: buf,
            micros: r.micros,
            transport,
        };
    }
    match judge_bytes(r.transferred, len as usize) {
        Ok(()) => ReadOutcome {
            addr,
            len,
            request,
            state_before,
            refused: None,
            code: "OK".to_string(),
            bytes: buf[..transferred].to_vec(),
            transferred,
            transferred_known: true,
            prefix_unverified: Vec::new(),
            micros: r.micros,
            transport,
        },
        Err(e) => ReadOutcome {
            addr,
            len,
            request,
            state_before,
            refused: Some(e.clone()),
            code: e.split(':').next().unwrap_or(e.as_str()).to_string(),
            bytes: Vec::new(),
            transferred,
            transferred_known: true,
            prefix_unverified: Vec::new(),
            micros: r.micros,
            transport,
        },
    }
}

/// Parse `ADDR:LEN`, both decimal or `0x`-prefixed. Refuses a missing colon rather than guessing a
/// length: the length is half the request.
pub fn parse_window(s: &str) -> Result<(u64, u16), String> {
    let (a, l) = s
        .split_once(':')
        .ok_or_else(|| format!("{s:?} is not ADDR:LEN (both parts decimal or 0x-hex)"))?;
    let parse = |t: &str| -> Result<u64, String> {
        let t = t.trim();
        match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            Some(h) => u64::from_str_radix(h, 16),
            None => t.parse::<u64>(),
        }
        .map_err(|e| format!("{t:?}: {e}"))
    };
    let addr = parse(a).map_err(|e| format!("address {e}"))?;
    let len = parse(l).map_err(|e| format!("length {e}"))?;
    let len = u16::try_from(len).map_err(|_| {
        format!("length {len:#x} does not fit the 16-bit wLength field; split it into windows")
    })?;
    Ok((addr, len))
}

/// The SETUP fields, as the wire sees them, for a dry run and for a transcript.
pub fn setup_fields(r: &CtrlReq) -> String {
    format!(
        "bmRequestType {:#04x}  bRequest {:#04x}  wValue {:#06x}  wIndex {:#06x}  wLength {:#06x}",
        r.bm, r.b, r.value, r.index, r.length
    )
}

/// A one-line JSON transcript in the house shape (`result` + `detail`, plus the counters). Kept
/// hand-built and minimal: the crate has no serde_json use on this path and a read transcript does
/// not need one.
pub fn json_line(out: &ReadOutcome, arm: Option<&ReadArm>) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let detail = match &out.refused {
        Some(e) => format!("\"{}\"", esc(e)),
        None => "null".to_string(),
    };
    // F2 (review/04): the routed encoding puts the window in `wIndex`; `wValue` is the 0xFFFF
    // marker, so `base + (value << 12)` emitted 0x18FFFF000 (6710882304) as `source` for EVERY
    // routed read — outside mapped SRAM — while the human lines printed the right address. The
    // JSON's `source` is computed from `index` like every other line, and is covered by
    // `control_json_line_source_comes_from_windex_not_wvalue`.
    let source = match arm {
        Some(a) => format!("{}", a.base + ((out.request.index as u64) << a.granule_shift)),
        None => "null".to_string(),
    };
    let (bits, frac, printable) = if out.bytes.is_empty() {
        (0.0, 0.0, 0.0)
    } else {
        let (b, f) = entropy(&out.bytes);
        (b, f, printable_fraction(&out.bytes))
    };
    format!(
        "{{\"tool\":\"a9pwn\",\"command\":\"readwindow\",\"addr\":\"{:#x}\",\"len\":{},\
         \"bmRequestType\":\"{:#04x}\",\"bRequest\":\"{:#04x}\",\"wValue\":{},\"wIndex\":{},\
         \"wLength\":{},\"source\":{source},\"state_before\":{},\"transferred\":{},\
         \"transferred_known\":{},\"prefix_unverified_hex\":\"{}\",\
         \"transport\":\"{}\",\"micros\":{},\"entropy_bits_per_byte\":{bits:.6},\
         \"entropy_fraction\":{frac:.6},\"printable\":{printable:.6},\"hex\":\"{}\",\
         \"result\":\"{}\",\"detail\":{detail}}}",
        out.addr,
        out.len,
        out.request.bm,
        out.request.b,
        out.request.value,
        out.request.index,
        out.request.length,
        match out.state_before {
            Some(s) => s.to_string(),
            None => "null".to_string(),
        },
        out.transferred,
        out.transferred_known,
        hex_preview(&out.prefix_unverified, 32),
        out.transport,
        out.micros,
        hex_preview(&out.bytes, 32),
        out.code,
    )
}

/// Does the modified handler keep the stock `0xFFFF` arm? Read from the bytes, not asserted:
/// the arm is preserved iff the exec/memc dispatch and the `wValue == 0xFFFF` gate are both there.
pub fn stock_arm_preserved(code: &[u8]) -> Result<(), String> {
    // The gate: `mov w1,#0xFFFF` then `ldrh w2,[x19,#2]` then `cmp w1,w2` then `b.ne`.
    let has_mov_ffff = code.windows(4).any(|w| {
        u32::from_le_bytes(w.try_into().unwrap()) == 0x529F_FFE1
    });
    // The exec arm's dispatch: `ldr x0,[x20]` then a literal compare against exec_magic.
    let has_mailbox_load = code
        .windows(4)
        .any(|w| u32::from_le_bytes(w.try_into().unwrap()) == 0xF940_0280);
    if !has_mov_ffff || !has_mailbox_load {
        return Err(
            "HANDLER_STOCK_ARM_LOST: the modified handler no longer contains the stock \
             `wValue == 0xFFFF` gate and/or the mailbox dispatch. The read arm is additive; the \
             stock arm must survive, or every existing command path changes behaviour silently."
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{HandlerVariant, PAYLOAD_HANDLE_CHECKM8_REQUEST, READWINDOW_CODE_LEN};

    fn arm() -> ReadArm {
        vendored_arm().expect("the vendored read-window handler must decode")
    }

    // -- the decoder is falsifiable on its own ------------------------------------------------

    /// The decoders must agree with the assembler's own encoding of the forms the arm uses.
    /// Hand-built words, so this test fails if a decoder is subtly wrong (it cannot pass by
    /// agreeing with the blob it is used to read).
    #[test]
    fn encoding_helpers_round_trip_hand_built_instructions() {
        // movz x1, #0x8000, lsl #16  -> 0xD2B00001 ; movk x1, #1, lsl #32 -> 0xF2C00021
        assert_eq!(decode_mov_wide(0xD2B0_0001).unwrap(), (0x8000u64 << 16, false));
        assert_eq!(decode_mov_wide(0xF2C0_0021).unwrap(), (1u64 << 32, true));
        assert_eq!(decode_mov_wide(0x52A0_0806).unwrap(), (0x400000, false));
        // cmp w3, #0x400  -> 0x7110007F
        assert_eq!(decode_cmp_imm(0x7110_007F), Some(0x400));
        // cbz w4, +0  -> 0x34000004
        assert_eq!(decode_cbz(0x3400_0004), Some((4, 0)));
        // cbz w4, -0x20 -> imm19 = -8 -> 0x34FFFF04
        assert_eq!(decode_cbz(0x34FF_FF04), Some((4, -0x20)));
        // b.ne -4
        assert_eq!(decode_branch(0x54FF_FFE1), Some((true, -4)));
        // lsl w5, w3, #12 -> 0x53144C65 (UBFM immr = 32-12 = 20)
        assert_eq!(decode_lsl32(0x5314_4C65), Some(12));
        // b .-8 and b.eq .+8
        assert_eq!(decode_branch(0x17FF_FFFE), Some((false, -8)));
        assert_eq!(decode_branch(0x5400_0040), Some((true, 8)));
        // ldr w3, +0x124 at +0x18 -> target 0x13C (the 0x1F literal)
        let ldr = 0x1800_0923u32;
        assert_eq!(decode_ldr_literal(ldr, 0x18), Some((false, 0x13C)));
        // mov w6, #0xFFFF (the routed wValue) decodes as a wide move
        assert_eq!(decode_mov_wide(0x529F_FFE6).unwrap().0, 0xFFFF);
        // A word of a different shape decodes to None, not to a plausible value.
        assert_eq!(decode_cmp_imm(0xD503_3FDF), None);
        assert_eq!(decode_lsl32(0xD503_3FDF), None);
        assert_eq!(decode_cbz(0xD503_3FDF), None);
    }

    // -- the red control: the stock handler cannot serve a read --------------------------------

    /// **The falsifier's red half, at the install level.** The stock handler has no read arm and no
    /// such request code, so `decode_read_arm` must fail on it — by name, and not by accident of a
    /// short buffer. If this ever succeeds, the "stock handler needs new code" premise is gone and
    /// every conclusion built on it has to be re-derived.
    #[test]
    fn control_the_stock_handler_has_no_read_arm() {
        let stock = &PAYLOAD_HANDLE_CHECKM8_REQUEST[..crate::payload::HANDLE_CODE_LEN];
        let e = decode_read_arm(stock).unwrap_err();
        assert!(
            e.starts_with("HANDLER_ARM_SHAPE") || e.starts_with("HANDLER_REQUEST_WORD"),
            "the stock handler must fail the arm decode by name, got {e}"
        );
        assert_eq!(HandlerVariant::Stock.code_len(), 192);
        assert_eq!(HandlerVariant::ReadWindow.code_len(), READWINDOW_CODE_LEN);
    }

    /// ...and the read-window handler must decode, with every field at the value the source
    /// intends. These are not re-derived from the constants: they are the decode's output.
    #[test]
    fn the_read_window_handler_decodes_to_the_measured_window() {
        let a = arm();
        assert_eq!(a.request_word, 0x1FA1);
        assert_eq!(a.request_word, READ_NEW_WORD);
        assert_eq!(a.trigger_value, READ_TRIGGER_VALUE, "decoded from the handler's own mov");
        assert_eq!(a.base, SRAM_BASE);
        assert_eq!(a.granule_shift, GRANULE_SHIFT);
        assert_eq!(a.index_limit, (SRAM_LEN >> GRANULE_SHIFT) as u32);
        assert_eq!(a.offset_limit, SRAM_LEN as u32);
        assert!(a.refuses_zero_length);
        // The two numbers that define the window are internally consistent: the index limit and
        // the offset limit describe the same 4 MiB.
        assert_eq!(a.index_limit as u64 * (1 << a.granule_shift), a.offset_limit as u64);
    }

    /// The arm must contain **no way to reach the mailbox**. Its only literal load is the request
    /// word; it loads no pool slot. (The pool slots are the only route to a ROM address in this
    /// handler, and `insecure_memory_base` is slot 1.)
    #[test]
    fn the_read_arm_cannot_reach_the_command_mailbox() {
        let blob = crate::payload::PAYLOAD_HANDLE_CHECKM8_READWINDOW;
        let code = &blob[..READWINDOW_CODE_LEN];
        let mut literals = Vec::new();
        for off in (ARM_OFF..READWINDOW_CODE_LEN).step_by(4) {
            if let Some((_, addr)) = decode_ldr_literal(word(code, off).unwrap(), off) {
                literals.push((off, addr));
            }
        }
        assert_eq!(
            literals.len(),
            1,
            "the arm must load exactly one literal (usb_core_do_transfer) and nothing else; a new \
             literal load in the arm is how a mailbox reference could creep back in: {literals:?}"
        );
        // That one literal must be the pool slot for usb_core_do_transfer (0x7FFFFFF6), not the
        // mailbox slot (0x7FFFFFF1).
        let (_off, addr) = literals[0];
        // The literal lives in the appended struct (the pool), which is *after* the code slice.
        assert!(addr >= READWINDOW_CODE_LEN, "the literal must be a pool slot");
        let value = u64::from_le_bytes(blob[addr..addr + 8].try_into().unwrap());
        assert_eq!(value, 0x7FFF_FFF6, "the arm's only literal is not the mailbox");
        assert_ne!(value, 0x7FFF_FFF1, "the arm loaded insecure_memory_base");
    }

    // -- the green half: the request the arm serves --------------------------------------------

    /// Staging an image into `0x180380000..` covers the mailbox. The read request still names
    /// `0x180384000` and the arm still serves it — because nothing in the request or the arm
    /// touches the mailbox.
    #[test]
    fn an_image_over_the_mailbox_does_not_move_the_read_window() {
        let a = arm();
        // A 254,480-byte iBSS covers 0x180380000..0x1803BE210 — the command mailbox at
        // 0x180380000 included.
        let image_base = 0x1_8038_0000u64;
        let image_len = 254_480u64;
        let mailbox = 0x1_8038_0000u64;
        assert!((image_base..image_base + image_len).contains(&mailbox));
        // A window inside the image (past the mailbox and past the 11 KiB in-place payload).
        let (addr, len) = (0x1_8038_4000u64, 0x1000u16);
        assert!((image_base..image_base + image_len).contains(&(addr + len as u64 - 1)));
        let index = window_index(&a, addr, len).expect("the window is legal");
        assert_eq!(index, 0x384);
        assert_eq!(a.window(index as u32, len as u32).unwrap().0, addr);
    }

    // -- refusals, each with a firing control --------------------------------------------------

    #[test]
    fn control_every_refusal_fires_by_name() {
        let a = arm();
        let e = window_index(&a, 0x1_8038_4000, 0).unwrap_err();
        assert!(e.starts_with(ZERO_LENGTH), "{e}");

        let e = window_index(&a, 0x1_8038_8001, 0x10).unwrap_err();
        assert!(e.starts_with(MISALIGNED), "{e}");

        let e = window_index(&a, 0x1_7FFF_F000, 0x10).unwrap_err();
        assert!(e.starts_with(OUTSIDE_SRAM), "{e}");

        // index 0x400 is exactly the limit -> refused by the index predicate.
        let e = window_index(&a, SRAM_BASE + (0x400 << 12), 0x10).unwrap_err();
        assert!(e.starts_with(INDEX_RANGE), "{e}");

        // Inside the index limit but crossing the top of SRAM -> outside.
        let e = window_index(&a, SRAM_BASE + (0x3FF << 12), 0x1001).unwrap_err();
        assert!(e.starts_with(OUTSIDE_SRAM), "{e}");

        let e = judge_read_window(&[0u8; 15], 16).unwrap_err();
        assert!(e.starts_with(SHORT_REPLY), "{e}");
    }

    /// The refusals must not fire on legal windows — including both ends of the window.
    ///
    /// `SRAM_BASE` (granule index 0) is deliberately **not** in this list: index 0 is the stock
    /// command form, not window 0, and refusing it is the whole point of [`WINDEX_IS_COMMAND`].
    /// The lowest legal window is index 1.
    #[test]
    fn control_legal_windows_do_not_fire() {
        let a = arm();
        for (addr, len) in [
            (SRAM_BASE + 0x1000, 1),
            (SRAM_BASE + 0x1000, 0x1000),
            (SRAM_BASE + (0x3FF << 12), 0x1000),
            (SRAM_BASE + (0x3FF << 12), 1),
        ] {
            assert!(
                window_index(&a, addr, len).is_ok(),
                "{addr:#x}+{len:#x} must be legal"
            );
        }
        judge_read_window(&[0u8; 16], 16).expect("a full reply is a read");
    }

    /// A window that ends **exactly** at the top of SRAM is legal and its last byte is inside;
    /// one byte further is refused. (The window start must be granule-aligned, so "the last byte
    /// of SRAM" is reachable only as the tail of the last aligned window, not as its own window.)
    #[test]
    fn the_top_of_sram_is_inclusive_of_its_last_byte() {
        let a = arm();
        let last = SRAM_BASE + (0x3FF << 12);
        let (src, len) = a.window(0x3FF, 0x1000).expect("the last aligned window is legal");
        assert_eq!(src, last);
        assert_eq!(src + len as u64, SRAM_BASE + SRAM_LEN);
        assert!(window_index(&a, last, 0x1001).is_err(), "one byte past the top must refuse");
    }

    // -- the mutation control: the bounds must be load-bearing ---------------------------------

    /// **A check earns trust by being shown to fail.** Change the handler's offset limit in a copy
    /// of its bytes and the *same* request that was refused becomes accepted — so the pinned test
    /// above is testing the bytes, not a constant in this file.
    #[test]
    fn mutation_of_the_offset_limit_changes_the_predicate() {
        let mut code = crate::payload::PAYLOAD_HANDLE_CHECKM8_READWINDOW[..READWINDOW_CODE_LEN]
            .to_vec();
        let before = decode_read_arm(&code).unwrap();
        assert_eq!(before.offset_limit, 0x40_0000);

        // `mov w6, #0x400000` at ARM_OFF+0x1C: the imm16 lives in bits[20:5]. Set it to 0x80 ->
        // 0x800000, i.e. a limit twice the real SRAM window. This is a one-field mutation, exactly
        // the class of edit a reviewer must catch; the decoder must follow it.
        let off = ARM_OFF + 0x1C;
        let mut w = u32::from_le_bytes(code[off..off + 4].try_into().unwrap());
        w = (w & !(0xFFFF << 5)) | (0x80u32 << 5);
        code[off..off + 4].copy_from_slice(&w.to_le_bytes());
        let after = decode_read_arm(&code).expect("the mutated arm still decodes");
        assert_eq!(after.offset_limit, 0x80_0000, "the decode did not follow the bytes");

        // A window that starts inside SRAM but ends 2 bytes past the top: the real arm refuses it,
        // and the mutant accepts it. That is the failure mode the bounds exist to prevent (an
        // unmapped read stalls the bus on this part, with no exception to recover).
        let addr = SRAM_BASE + (0x3FF << 12);
        assert!(window_index(&before, addr, 0x1002).is_err(), "real arm must refuse");
        assert!(
            window_index(&after, addr, 0x1002).is_ok(),
            "mutant must be shown to accept what the real bounds refuse"
        );
    }

    /// The request word is read from the bytes, not assumed: a blob whose literal says a different
    /// request code is refused by name.
    #[test]
    fn mutation_of_the_request_word_is_refused_by_name() {
        let mut code = crate::payload::PAYLOAD_HANDLE_CHECKM8_READWINDOW[..READWINDOW_CODE_LEN]
            .to_vec();
        code[REQUEST_LITERAL_OFF] = 0xA1;
        code[REQUEST_LITERAL_OFF + 1] = 0x2A; // 0x2AA1
        let e = decode_read_arm(&code).unwrap_err();
        assert!(e.starts_with("HANDLER_REQUEST_WORD"), "{e}");
    }

    // -- the wire form -------------------------------------------------------------------------

    /// The **primary** encoding rides the request checkm8 proves reaches the handler (`0xA1/2`),
    /// with the window in `wValue`, the magic in `wIndex` and the length in `wLength`. Both the
    /// magic and the distinction from the stock trigger are asserted **against the decoded arm**,
    /// so this test follows the bytes.
    #[test]
    fn the_routed_encoding_is_wvalue_ffff_with_the_window_in_windex() {
        let a = arm();
        let r = read_window_request(&a, 0x1_8038_4000, 0x1000).unwrap();
        assert_eq!(r.bm, READ_BM);
        assert_eq!(r.b, READ_A12_BREQUEST, "the request the control PASSED");
        assert_eq!(r.value, READ_TRIGGER_VALUE, "wValue 0xFFFF — the only routed value");
        assert_eq!(r.value, a.trigger_value);
        assert_eq!(r.index, 0x384, "wIndex = window index");
        assert_ne!(r.index, READ_WINDEX_COMMAND, "wIndex 0 is the command form");
        assert_eq!(r.length, 0x1000);
        assert!(a.matches_read(r.bm, r.b, r.value, r.index));
        // The stock command form is (0xA1/2, wValue 0xFFFF, wIndex 0) — routed, not a read.
        assert!(!a.matches_read(READ_BM, READ_A12_BREQUEST, READ_TRIGGER_VALUE, 0));
        // A non-0xFFFF wValue is not a read either: the handler checks wValue FIRST.
        assert!(!a.matches_read(READ_BM, READ_A12_BREQUEST, 0x384, 0x384));
        // And the secondary form is not the routed one.
        assert!(!a.matches_read(READ_BM, READ_NEW_BREQUEST, READ_TRIGGER_VALUE, 0x384));
    }

    /// **The encoded check is byte-driven, and the mutation proves it.** Change the handler's
    /// `mov w6,#0xFFFF` immediate to `0xFFFE` in a copy of the blob: the decode follows, and a
    /// request that the real handler treats as a read is no longer matched — so the `wValue` gate
    /// is not a constant in this file.
    #[test]
    fn mutation_of_the_trigger_value_changes_the_predicate() {
        let mut code =
            crate::payload::PAYLOAD_HANDLE_CHECKM8_READWINDOW[..READWINDOW_CODE_LEN].to_vec();
        let before = decode_read_arm(&code).unwrap();
        assert_eq!(before.trigger_value, 0xFFFF);
        // MOVZ w6, #imm16: imm16 lives in bits[20:5]. Set it to 0xFFFE.
        let off = TRIGGER_MOV_OFF;
        let mut w = u32::from_le_bytes(code[off..off + 4].try_into().unwrap());
        w = (w & !(0xFFFF << 5)) | (0xFFFEu32 << 5);
        code[off..off + 4].copy_from_slice(&w.to_le_bytes());
        // The routed value is a HARD gate: a blob that routes on anything else is refused by name,
        // with the decoded value in the message. That is stronger than a changed predicate — there
        // is no way to run an arm whose gate we did not read.
        let e = decode_read_arm(&code).unwrap_err();
        assert!(e.starts_with("HANDLER_TRIGGER_VALUE"), "{e}");
        assert!(e.contains("0xFFFE"), "the refusal must quote what it decoded: {e}");
        // And the decode of the *unmutated* bytes is what the request builder uses, so a request
        // is only ever built for the gate that is really in the handler.
        assert_eq!(read_window_request(&before, SRAM_BASE + 0x1000, 0x1000).unwrap().value, 0xFFFF);
    }

    /// **The routed form keeps the mailbox out of the read path, by control flow.** The dispatch
    /// block (`0x0C..0x44`) contains no mailbox dereference and no load of the mailbox address;
    /// the stock body's `ldr x0,[x20]` exists but is reached only through `_legacy`, which a read
    /// never enters. Verified both ways: the dispatch is clean, and the stock dereference *does*
    /// exist elsewhere (so the clean result is not "the instruction was not found").
    #[test]
    fn the_read_branch_leaves_the_mailbox_behind() {
        let code = &crate::payload::PAYLOAD_HANDLE_CHECKM8_READWINDOW[..READWINDOW_CODE_LEN];
        let dispatch_end = WINDEX_CBZ_OFF + 4;
        for off in (DISPATCH_OFF..dispatch_end).step_by(4) {
            let w = word(code, off).unwrap();
            assert_ne!(w, 0xF940_0280, "mailbox dereference at +{off:#x} in the dispatch");
            assert!(
                !((w & 0xFF00_0000 == 0x5800_0000) && (w & 0x1F) == 20),
                "mailbox literal load at +{off:#x} in the dispatch"
            );
        }
        // The stock dereference must still EXIST — in the legacy body, outside the dispatch block.
        let stock_deref = (dispatch_end..READWINDOW_CODE_LEN)
            .step_by(4)
            .any(|o| word(code, o).unwrap() == 0xF940_0280);
        assert!(
            stock_deref,
            "the stock arm's `ldr x0,[x20]` must still be present in the legacy body: its absence \
             would mean this control is checking a handler that is not the one described"
        );
    }

    /// The **secondary** encoding (`0xA1/0x1F`) is still built and still decodable, and it must not
    /// be confusable with the routed one: a different bRequest, and it is MEASURED filtered.
    #[test]
    fn the_secondary_encoding_is_a1_1f_with_windex_zero() {
        let a = arm();
        let r = read_window_request_newcode(&a, 0x1_8038_4000, 0x1000).unwrap();
        assert_eq!(r.b, READ_NEW_BREQUEST);
        assert_eq!(r.index, 0);
        assert_eq!(r.value, 0x384);
        assert_eq!((r.b as u16) << 8 | r.bm as u16, a.request_word);
        assert!(!a.matches_read(r.bm, r.b, r.value, r.index));
    }

    // -- the handler-shape probe ---------------------------------------------------------------

    /// **The probe is safe on every handler because it never uses `wValue == 0xFFFF`.** That is the
    /// whole reason it can be sent before anything else: stock, old and routed all answer it
    /// without loading `[mailbox]`. If someone "simplifies" it to the routed value, this test fails.
    #[test]
    fn the_shape_probe_never_uses_the_routed_value() {
        let r = shape_probe_request(0x40);
        assert_eq!(r.bm, READ_BM);
        assert_eq!(r.b, READ_A12_BREQUEST);
        assert_ne!(r.value, READ_TRIGGER_VALUE, "the probe must not arm the stock data-driven path");
        assert_eq!(r.value, SHAPE_PROBE_VALUE);
        assert_eq!(r.index, SHAPE_PROBE_MAGIC, "the old handler selects its arm on this wIndex");
        assert_ne!(r.index, READ_WINDEX_COMMAND);
        assert_eq!(r.length, 0x40);
        // And the window the old handler will read for it is the trampoline slot, not the mailbox.
        assert_eq!(
            SRAM_BASE + ((SHAPE_PROBE_VALUE as u64) << GRANULE_SHIFT),
            SHAPE_PROBE_WINDOW
        );
        assert_ne!(SHAPE_PROBE_WINDOW, 0x1803_8000, "the probe must not read the mailbox window");
    }

    /// Three outcomes, each named, and the two positive ones are told apart by content:
    /// all-zero = the OLD handler (it read the empty trampoline slot); non-zero = routed or stock
    /// (both answered from the mailbox); empty = unknown, which authorises nothing.
    #[test]
    fn control_the_shape_classifier_names_all_three_outcomes() {
        let (code, why) = classify_shape(&[0u8; 0x40]);
        assert_eq!(code, SHAPE_OLD_HANDLER);
        assert!(why.contains("DO NOT send the routed read"), "{why}");
        assert!(why.contains("0x1800e0000"), "{why}");

        let mut image = vec![0u8; 0x40];
        image[..4].copy_from_slice(&[0x30, 0x83, 0x03, 0xe2]);
        let (code, why) = classify_shape(&image);
        assert_eq!(code, SHAPE_ROUTED_OR_STOCK);
        assert!(why.contains("OLD handler is excluded"), "{why}");
        assert!(why.contains("cannot tell those two apart") || why.contains("no safe request can tell"), "{why}");

        let (code, why) = classify_shape(&[]);
        assert_eq!(code, SHAPE_UNKNOWN);
        assert!(why.contains("NOT authorised"), "{why}");
    }

    /// The hook classifier names each install and refuses to guess at anything else. The window
    /// that covers the slot is index 0x87; the slot is at +0x8F8 inside it.
    #[test]
    fn control_the_hook_classifier_names_each_install_and_nothing_else() {
        let addr = 0x1800_87000u64;
        let len = 0x1000u16;
        let mut buf = vec![0u8; len as usize];
        let off = (HOOK_SLOT - addr) as usize;
        assert_eq!(off, 0x8F8);
        for (v, want) in [
            (HOOK_READWINDOW, "readwindow"),
            (HOOK_STOCK, "STOCK"),
            (HOOK_ROM, "ROM"),
        ] {
            buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
            let (got, what) = hook_in_window(addr, len, &buf).expect("the window covers the slot");
            assert_eq!(got, v);
            assert!(what.to_lowercase().contains(&want.to_lowercase()), "{v:#x}: {what}");
        }
        buf[off..off + 8].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        let (_, what) = hook_in_window(addr, len, &buf).unwrap();
        assert!(what.contains("not a value"), "{what}");
        // A window that does not cover the slot returns None, not a guessed value.
        assert!(hook_in_window(0x1800_84000, 0x1000, &buf).is_none());
        assert!(hook_in_window(addr, len, &buf[..0x100]).is_none());
        // The off-by-one case: a window ending one byte short of the slot's last byte.
        assert!(hook_in_window(addr, 0x8F8 + 8 - 1 - 0x000, &vec![0u8; 0x8FF]).is_none());
    }

    /// `plan_line` must say REFUSED for a refused window and must not silently print an address.
    #[test]
    fn the_plan_line_says_refused_rather_than_nothing() {
        let a = arm();
        let ok = plan_line(&a, 0x1_8038_4000, 0x1000);
        assert!(ok.contains("bmRequestType 0xa1"), "{ok}");
        assert!(ok.contains("no DNLOAD, no mailbox"), "{ok}");
        let bad = plan_line(&a, 0x1_9000_0000, 0x10);
        assert!(bad.contains("REFUSED"), "{bad}");
        assert!(bad.contains(INDEX_RANGE), "{bad}");
        let below = plan_line(&a, 0x1_7FFF_F000, 0x10);
        assert!(below.contains(OUTSIDE_SRAM), "{below}");
    }

    // -- the report is memory, not a command reply ---------------------------------------------

    /// Entropy on inputs whose answers are known independently: a constant window is 0.0, a window
    /// of all 256 byte values is exactly 8.0, and the ceiling fraction is 1.0 there.
    #[test]
    fn entropy_matches_known_answers() {
        assert_eq!(entropy(&[0u8; 256]).0, 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        let (h, frac) = entropy(&all);
        assert!((h - 8.0).abs() < 1e-9, "256 distinct values: {h}");
        assert!((frac - 1.0).abs() < 1e-9, "fraction {frac}");
        // The finite-sample trap (`a9boot/IBSS-UPLOAD.md` §3.7): 256 samples cannot reach 8.0 by
        // chance, and the normalised fraction is what makes windows comparable anyway.
        let (h2, frac2) = entropy(&[0u8; 4]);
        assert_eq!((h2, frac2), (0.0, 0.0));
        assert_eq!(entropy(&[]), (0.0, 0.0));
    }

    #[test]
    fn printable_fraction_and_hex_preview_are_exact() {
        assert_eq!(printable_fraction(b"AB\x00\xff"), 0.5);
        assert_eq!(printable_fraction(&[]), 0.0);
        assert_eq!(hex_preview(&[0xde, 0xad, 0xbe, 0xef], 3), "deadbe");
        assert_eq!(hex_preview(&[0x00], 16), "00");
    }

    /// The report must never mention `DONE_MAGIC` and must carry length + entropy + hex — the
    /// three things a memory read has, and the one thing it does not.
    #[test]
    fn memory_report_is_a_memory_report() {
        let r = memory_report(&[0u8; 16]);
        assert!(r.contains("16 byte(s) of memory"), "{r}");
        assert!(r.contains("entropy 0.000 bits/byte"), "{r}");
        assert!(r.contains("00000000000000000000000000000000"), "{r}");
        assert!(!r.to_lowercase().contains("magic"), "{r}");
    }

    /// `judge_bytes` names silence and short replies, and the refusal text says they are not
    /// contents. Both firing controls are here; the success control is a full reply.
    #[test]
    fn control_judge_bytes_names_silence_and_short_replies() {
        let e = judge_bytes(0, 16).unwrap_err();
        assert!(e.starts_with(SILENT), "{e}");
        assert!(e.contains("not a read of zeros"), "{e}");
        let e = judge_bytes(15, 16).unwrap_err();
        assert!(e.starts_with(SHORT), "{e}");
        judge_bytes(16, 16).expect("a full reply is a window");
    }

    /// `compare` decides MATCH/MISMATCH by bytes, and says *where* the first difference is. A
    /// window that would run past the supplied file is its own refusal (a wrong base, not a
    /// mismatch in the image).
    #[test]
    fn control_compare_is_machine_decided_and_says_where() {
        let file: Vec<u8> = (0..32u8).collect();
        compare(&file, 8, &file[8..16]).expect("identical bytes match");
        let e = compare(&file, 8, &[0u8; 8]).unwrap_err();
        assert!(e.starts_with(MISMATCH), "{e}");
        assert!(e.contains("+0x0 in the window"), "{e}");
        let e = compare(&file, 28, &[0u8; 8]).unwrap_err();
        assert!(e.starts_with(MISMATCH), "{e}");
        assert!(e.contains("past the end"), "{e}");
    }

    // -- the stock arm must survive inside the modified handler --------------------------------

    /// The read arm is **additive**. The stock `0xFFFF` gate and the mailbox dispatch must still be
    /// in the modified handler, or every existing command path would change behaviour silently.
    #[test]
    fn the_modified_handler_still_contains_the_stock_arm() {
        stock_arm_preserved(&crate::payload::PAYLOAD_HANDLE_CHECKM8_READWINDOW[..READWINDOW_CODE_LEN])
            .expect("the stock arm must survive");
        // Firing control: remove the `mov w1,#0xFFFF` gate from a copy and the check fails.
        let mut code =
            crate::payload::PAYLOAD_HANDLE_CHECKM8_READWINDOW[..READWINDOW_CODE_LEN].to_vec();
        let at = code
            .windows(4)
            .position(|w| u32::from_le_bytes(w.try_into().unwrap()) == 0x529F_FFE1)
            .expect("the gate is present to begin with");
        code[at..at + 4].copy_from_slice(&0xD503_201Fu32.to_le_bytes());
        let e = stock_arm_preserved(&code).unwrap_err();
        assert!(e.starts_with("HANDLER_STOCK_ARM_LOST"), "{e}");
    }

    // -- the host's own window bound -----------------------------------------------------------

    /// The host refuses a reply longer than the session's agreed window, by name, and the reason
    /// says the ARM bound is wider — so the two tools tell one story.
    #[test]
    fn control_the_host_window_bound_is_named_and_explained() {
        let a = arm();
        let e = read_window_request(&a, SRAM_BASE + 0x1000, READ_MAX_LEN + 1).unwrap_err();
        assert!(e.starts_with(TOO_LONG), "{e}");
        assert!(e.contains("0x1000"), "{e}");
        read_window_request(&a, SRAM_BASE + 0x1000, READ_MAX_LEN)
            .expect("the session window is allowed");
    }

    /// **The firing control for `WINDEX_IS_COMMAND`.** `0x180000000` is granule index 0, and index
    /// 0 is the stock command form: the handler's `cbz w5,_legacy` never enters the read arm, and
    /// the legacy arm loads `[mailbox]` and can `blr` a function pointer out of staged bytes. The
    /// request is refused **before** it is built, so nothing reaches the device — and the two
    /// sibling builders refuse it too, or the refusal would be one call site deep.
    #[test]
    fn control_window_zero_is_refused_because_windex_zero_is_the_command_form() {
        let a = arm();
        let e = window_index(&a, SRAM_BASE, 0x1000).unwrap_err();
        assert!(e.starts_with(WINDEX_IS_COMMAND), "{e}");
        // Not a length or range accident: the length is the ordinary window, and index 1 succeeds.
        assert!(window_index(&a, SRAM_BASE + 0x1000, 0x1000).is_ok());
        let e = read_window_request(&a, SRAM_BASE, 0x1000).unwrap_err();
        assert!(e.starts_with(WINDEX_IS_COMMAND), "{e}");
        let e = read_window_request_newcode(&a, SRAM_BASE, 0x1000).unwrap_err();
        assert!(e.starts_with(WINDEX_IS_COMMAND), "{e}");
        // The refused request is what the trace would have recorded — assert it is never built.
        assert_eq!(READ_WINDEX_COMMAND, 0, "index 0 is the command form by definition");
    }

    #[test]
    fn control_parse_window_refuses_a_missing_length_and_accepts_both_bases() {
        assert_eq!(parse_window("0x180384000:0x1000").unwrap(), (0x1_8038_4000, 0x1000));
        assert_eq!(parse_window("6446137344:4096").unwrap(), (0x1_8038_4000, 4096));
        let e = parse_window("0x180384000").unwrap_err();
        assert!(e.contains("ADDR:LEN"), "{e}");
        let e = parse_window("0x180384000:0x10000").unwrap_err();
        assert!(e.contains("16-bit"), "{e}");
    }

    /// **The firing control for `shape_gate`** (instrument fix 3, review/04 F4): the hazardous
    /// routed read may only follow a POSITIVE `SHAPE_ROUTED_OR_STOCK`. Unknown refuses by name
    /// unless the operator's explicit override is passed; the OLD handler refuses even with the
    /// override, because that is a positive hazard identification, not missing information.
    #[test]
    fn control_shape_gate_refuses_everything_but_a_positive_probe() {
        assert!(shape_gate(SHAPE_ROUTED_OR_STOCK, false).is_ok());
        let e = shape_gate(SHAPE_OLD_HANDLER, false).unwrap_err();
        assert!(e.starts_with(SHAPE_OLD_HANDLER), "{e}");
        assert!(e.contains("NOT sent"), "{e}");
        let e = shape_gate(SHAPE_UNKNOWN, false).unwrap_err();
        assert!(e.starts_with(SHAPE_UNKNOWN), "{e}");
        assert!(e.contains("NOT authorised"), "{e}");
        // The override is explicit and never a default.
        assert!(shape_gate(SHAPE_UNKNOWN, true).is_ok());
        assert!(
            shape_gate(SHAPE_OLD_HANDLER, true).is_err(),
            "a positively identified OLD handler is refused even with the override"
        );
    }

    /// F2's firing control: `json_line`'s `source` comes from `wIndex` (the routed window) and is
    /// inside mapped SRAM — never the `wValue`-derived 0x18FFFF000. Also pins `transferred_known`
    /// and the unverified prefix into the transcript (instrument fix 2).
    #[test]
    fn control_json_line_source_comes_from_windex_not_wvalue() {
        let a = arm();
        let addr = 0x1_8038_4000u64;
        let ok = ReadOutcome {
            addr,
            len: 0x1000,
            request: read_window_request(&a, addr, 0x1000).unwrap(),
            state_before: Some(5),
            refused: None,
            code: "OK".to_string(),
            bytes: vec![0u8; 0x1000],
            transferred: 0x1000,
            transferred_known: true,
            prefix_unverified: Vec::new(),
            micros: 42,
            transport: "Ok".to_string(),
        };
        let line = json_line(&ok, Some(&a));
        assert!(line.contains(&format!("\"source\":{}", addr)), "{line}");
        assert!(!line.contains("6710882304"), "0x18FFFF000 is the F2 bug: {line}");
        assert!(line.contains("\"transferred_known\":true"), "{line}");
        // A failed transfer keeps its prefix as UNVERIFIED, in the transcript, and says the count
        // is not a measurement.
        let stalled = ReadOutcome {
            code: STALL.to_string(),
            bytes: Vec::new(),
            transferred: 0,
            transferred_known: false,
            prefix_unverified: vec![0xAA, 0xBB],
            refused: Some("stalled".to_string()),
            transport: "Stall".to_string(),
            ..ok
        };
        let line = json_line(&stalled, Some(&a));
        assert!(line.contains("\"transferred_known\":false"), "{line}");
        assert!(line.contains("\"prefix_unverified_hex\":\"aabb\""), "{line}");
    }
}

