//! a9pwn — `gaster`'s checkm8, rewritten in Rust with instrumentation built in.
//!
//! The algorithm is deliberately *not* redesigned. checkm8 is a timing-sensitive
//! bootrom heap corruption; every deviation from the reference implementation is
//! a new silent failure mode. What this crate adds is:
//!
//!   * a transport layer that reports what actually happened, per transfer,
//!     including the abort window it used and how many bytes got through;
//!   * an honest reset report, because on Windows a "reset" can silently be a
//!     pipe cycle and that single fact decides whether the exploit can fire;
//!   * a bounded, fully instrumented SETUP sweep instead of an unbounded
//!     `for(;;)` that prints nothing;
//!   * failure classification that distinguishes four problems which would
//!     otherwise produce one identical message.
//!
//! Reference: `research/refs/gaster/gaster.c` (Apache-2.0, 0x7ff/gaster).
//! Interface contract: `INTERFACE.md`. Read it before touching a module.

pub mod config;
pub mod payload;
pub mod readwindow;
pub mod stages;
pub mod trace;
pub mod types;
pub mod usb;
pub mod verdict;

/// gaster's compile-time constants, kept identical on purpose.
pub const EP0_MAX_PACKET_SZ: u16 = 0x40;
pub const DFU_FILE_SUFFIX_LEN: u16 = 16;
pub const DFU_MAX_TRANSFER_SZ: u16 = 0x800;
pub const APPLE_VID: u16 = 0x05AC;
pub const DFU_MODE_PID: u16 = 0x1227;

/// DFU class requests the bootrom's DFU state machine answers.
pub const DFU_DNLOAD: u8 = 1;
pub const DFU_UPLOAD: u8 = 2;
pub const DFU_GETSTATUS: u8 = 3;
pub const DFU_CLRSTATUS: u8 = 4;

/// `DFU_GET_STATUS` reply, 6 bytes (gaster `dfu_check_status`).
/// Layout: `bStatus[0]`, `bwPollTimeout[1..4]`, `bState[4]`, `iString[5]`.
pub const DFU_STATUS_OK: u8 = 0x00;
/// `appIDLE` — the DFU machine is idle and answering class requests.
pub const DFU_STATE_APP_IDLE: u8 = 0;
/// `dfuIDLE` — the DFU machine is idle in DFU mode. What a bus reset leaves
/// behind, and therefore the state a *delivered* reset reads back.
pub const DFU_STATE_DFU_IDLE: u8 = 2;
pub const DFU_STATE_MANIFEST_SYNC: u8 = 6;
pub const DFU_STATE_MANIFEST: u8 = 7;
/// `MANIFEST_WAIT_RESET` — parked, waiting for a bus reset and answering
/// nothing else. Only a real bus reset clears it, which is what makes it the
/// one state that can prove a reset happened (`stage_reset` drives it here).
pub const DFU_STATE_MANIFEST_WAIT_RESET: u8 = 8;

/// The string the payload writes into `gUSBSerialNumber` on success.
pub const PWND_STRING: &str = " PWND:[checkm8]";
