//! Per-SoC bootrom configuration. FROZEN SURFACE — see `INTERFACE.md` §3.
//!
//! Every address here is an absolute address inside one specific SecureROM
//! image. A single wrong value does not produce a wrong answer, it produces a
//! payload that jumps into nothing — so each field carries the `gaster.c` line
//! it was taken from, and `config_for_identity` refuses an identity it cannot
//! place exactly rather than falling back to a plausible table entry.
//!
//! # Which key selects which entry
//!
//! gaster keys its address table on the **`SRTG` build string** (gaster.c:624
//! for `iBoot-2234.0.0.2.22` → CPID 0x8003, gaster.c:641 for
//! `iBoot-2234.0.0.3.3` → CPID 0x8000) and keys the *payload kind* on the
//! **CPID** alone (`cpid == 0x8003 || cpid == 0x8000`, gaster.c:1042). It never
//! consults `CPRV`. We follow the same two keys — and then require both, because
//! gaster's failure mode when neither matches is an unbounded silent wait
//! (`cpid` stays 0, `checkm8_check_usb_device` returns false, `wait_usb_handle`
//! loops forever with no output at all).
//!
//! `CPRV` is carried in [`SocConfig::cprv`] as the revision the values were
//! captured from and is *checked against the identity by the caller*, not used
//! as a hard gate here: gaster pwns an A9 whose `SRTG` matches regardless of
//! `CPRV`, and refusing on a revision gaster accepts would be inventing a
//! restriction that costs us the device. See [`SocConfig::cprv_note`].

use crate::types::DeviceIdentity;

/// Which payload blob a device's PATCH stage requires.
///
/// `A9` is the only kind whose blob is vendored in this crate
/// (`payloads/README.md`); the other two exist because the interface freezes
/// them and `build_payload` must refuse them by name instead of guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    A9,
    NotA9,
    NotA9Armv7,
}

impl PayloadKind {
    pub fn name(&self) -> &'static str {
        match self {
            PayloadKind::A9 => "A9",
            PayloadKind::NotA9 => "NotA9",
            PayloadKind::NotA9Armv7 => "NotA9Armv7",
        }
    }
}

/// One SecureROM image's worth of addresses, in gaster's own field order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocConfig {
    pub cpid: u32,
    pub cprv: u32,
    pub name: &'static str,
    /// gaster `config_overwrite_pad`: the clamp on the aborted transfer, and
    /// therefore the length of the pad request.
    pub overwrite_pad: u32,
    /// gaster `config_large_leak`. 0 on A9: the A9 SPRAY path is selected by
    /// `config_large_leak == 0` (gaster.c:900).
    pub large_leak: u32,
    /// gaster `config_hole`. 0 on A9: only the non-A9 SPRAY branch uses it
    /// (gaster.c:905).
    pub hole: u32,
    pub ttbr0_vrom_off: u64,
    /// Only the non-A9 `usb_rop_callbacks` path uses this (gaster.c:1102).
    pub ttbr0_sram_off: u64,
    pub insecure_memory_base: u64,
    pub dfu_handle_bus_reset: u64,
    pub dfu_handle_request: u64,
    pub memcpy_addr: u64,
    pub g_usb_serial_number: u64,
    pub usb_create_string_descriptor: u64,
    pub usb_serial_number_string_descriptor: u64,
    pub patch_addr: u64,
    pub boot_tramp_end: u64,
    pub ttbr0_addr: u64,
    /// gaster's `pwnd_str` (gaster.c:154). 15 bytes; written into a zeroed
    /// 16-byte field, which is why the A9 struct's `pwnd` is `uint64_t pwnd[2]`.
    pub pwnd_string: &'static str,
}

impl SocConfig {
    /// `pwnd_str` as the payload wants it: 15 bytes, no NUL.
    pub fn pwnd_bytes(&self) -> &'static [u8] {
        self.pwnd_string.as_bytes()
    }

    /// `ttbr0_addr + ttbr0_vrom_off` — the A9 struct's `ttbr0_vrom_addr`
    /// (gaster.c:1120).
    pub fn ttbr0_vrom_addr(&self) -> u64 {
        self.ttbr0_addr + self.ttbr0_vrom_off
    }

    /// A sentence when the identity's `CPRV` disagrees with the revision this
    /// config was captured from, else `None`.
    ///
    /// Deliberately *not* a refusal: gaster never reads `CPRV`, and the two A9
    /// entries share every address, so a revision difference that gaster would
    /// pwn through must not be turned into an error here. It is worth saying out
    /// loud all the same — "we are running addresses from a different revision"
    /// is exactly the kind of thing that should be visible before the attempt.
    pub fn cprv_note(&self, id: &DeviceIdentity) -> Option<String> {
        match id.cprv {
            Some(v) if v != self.cprv => Some(format!(
                "CPRV mismatch: device reports 0x{v:02X}, this config was captured from \
                 0x{:02X}. gaster does not read CPRV (gaster.c:624-657 keys on SRTG), so this \
                 is not a refusal, but the addresses are from a different revision than this unit",
                self.cprv
            )),
            _ => None,
        }
    }
}

/// CPID 0x8003 — s8003 "Malta", the die on our attached iPhone SE 1st gen.
///
/// Source: `gaster.c:624-640`, the ` SRTG:[iBoot-2234.0.0.2.22]` branch.
/// `cprv` is 0x01 from this project's own capture of the attached unit
/// (`a9pwn/src/types.rs` `LIVE`, and `readmes/a9ctl-README.md`).
pub const A9_8003: SocConfig = SocConfig {
    cpid: 0x8003,
    cprv: 0x01,
    name: "s8003 Malta",
    overwrite_pad: 0x500,                     // gaster.c:626
    large_leak: 0,                            // not assigned on A9; gaster.c:174 static init, gaster.c:900 gate
    hole: 0,                                  // not assigned on A9; gaster.c:174 static init, gaster.c:905 use
    ttbr0_vrom_off: 0x400,                    // gaster.c:631
    ttbr0_sram_off: 0,                        // not assigned on A9; gaster.c:1102 non-A9 path only
    insecure_memory_base: 0x180380000,        // gaster.c:637
    dfu_handle_bus_reset: 0x180087928,        // gaster.c:636
    dfu_handle_request: 0x1800878F8,          // gaster.c:634
    memcpy_addr: 0x100011030,                 // gaster.c:629
    g_usb_serial_number: 0x180087958,         // gaster.c:633
    usb_create_string_descriptor: 0x10000E354, // gaster.c:639
    usb_serial_number_string_descriptor: 0x1800807DA, // gaster.c:640
    patch_addr: 0x10000812C,                  // gaster.c:627
    boot_tramp_end: 0x1800E1000,              // gaster.c:632
    ttbr0_addr: 0x1800C8000,                  // gaster.c:628
    pwnd_string: crate::PWND_STRING,          // gaster.c:154
};

/// CPID 0x8000 — s8000 "Maui" (the A9 we ran against in the previous session:
/// `CPRV:20`, `BDID:04`, `SRTG:[iBoot-2234.0.0.3.3]`).
///
/// Source: `gaster.c:641-657`. Every address is **identical to CPID 0x8003**,
/// which is not a copy-paste mistake: gaster really does carry the same values
/// in both branches, because both A9 fabrications shipped the same SecureROM
/// layout. The only difference is the `SRTG` build string the entry is valid
/// for. A test pins that equality so nobody "fixes" one of them.
pub const A9_8000: SocConfig = SocConfig {
    cpid: 0x8000,
    cprv: 0x20,
    name: "s8000 Maui",
    overwrite_pad: 0x500,                     // gaster.c:643
    large_leak: 0,                            // as above
    hole: 0,                                  // as above
    ttbr0_vrom_off: 0x400,                    // gaster.c:648
    ttbr0_sram_off: 0,                        // as above
    insecure_memory_base: 0x180380000,        // gaster.c:654
    dfu_handle_bus_reset: 0x180087928,        // gaster.c:653
    dfu_handle_request: 0x1800878F8,          // gaster.c:651
    memcpy_addr: 0x100011030,                 // gaster.c:646
    g_usb_serial_number: 0x180087958,         // gaster.c:650
    usb_create_string_descriptor: 0x10000E354, // gaster.c:656
    usb_serial_number_string_descriptor: 0x1800807DA, // gaster.c:657
    patch_addr: 0x10000812C,                  // gaster.c:644
    boot_tramp_end: 0x1800E1000,              // gaster.c:649
    ttbr0_addr: 0x1800C8000,                  // gaster.c:645
    pwnd_string: crate::PWND_STRING,          // gaster.c:154
};

/// The `SRTG` build string each entry's addresses are valid for. This is the
/// key gaster's table actually uses (gaster.c:624, gaster.c:641).
const A9_8003_SRTG: &str = "iBoot-2234.0.0.2.22";
const A9_8000_SRTG: &str = "iBoot-2234.0.0.3.3";

static CONFIGS: [SocConfig; 2] = [A9_8003, A9_8000];

/// Every SoC this crate can actually drive: the two A9 dies whose payload blobs
/// are vendored. gaster supports more (gaster.c:519-808); their blobs are not in
/// `payloads/`, so listing their addresses here would advertise a config that
/// `build_payload` must then refuse.
pub fn all_configs() -> &'static [SocConfig] {
    &CONFIGS
}

/// Resolve the SoC config and payload kind for a device identity.
///
/// Refuses — loudly, and naming what it saw — when:
///
/// * there is no `CPID` at all (nothing to identify the die);
/// * the `CPID` is not one of the two A9 dies this crate carries values for;
/// * the `SRTG` build string is absent (that is iBSS/LLB DFU, not SecureROM:
///   the addresses would be for a different image and the payload would jump
///   into nothing), or does not match the entry's build.
///
/// The `SRTG` comparison is case-insensitive on purpose. gaster's `strstr` is
/// case-sensitive and its table says `iBoot-2234.0.0.2.22` (gaster.c:624),
/// while this project's own captures of real units record `IBOOT-2234.0.0.2.22`
/// (`a9pwn/src/types.rs` `LIVE`; `readmes/a9ctl-README.md:35`). A case-sensitive
/// match would refuse the only device we own; the bootrom build string is the
/// same string either way. (This is also why `a9ctl`'s
/// `config_for_serial` — case-sensitive `serial.contains` — is suspect.)
pub fn config_for_identity(id: &DeviceIdentity) -> Result<(SocConfig, PayloadKind), String> {
    let cpid = id.cpid.ok_or_else(|| {
        format!(
            "the serial descriptor carries no CPID, so the die cannot be identified. \
             serial: {:?}",
            id.serial
        )
    })?;

    let (cfg, expected_srtg) = match cpid {
        0x8003 => (A9_8003, A9_8003_SRTG),
        0x8000 => (A9_8000, A9_8000_SRTG),
        other => {
            return Err(format!(
                "CPID 0x{other:04X} is not in this crate's table. Only the A9 dies 0x8000 \
                 (s8000 Maui) and 0x8003 (s8003 Malta) are supported, because only their \
                 payload blobs are vendored (payloads/README.md). gaster supports more SoCs \
                 (gaster.c:519-808); those blobs are not embedded here, and guessing their \
                 addresses would produce a payload that jumps into nothing."
            ))
        }
    };

    let srtg = id.srtg.as_deref().unwrap_or("").trim();
    if srtg.is_empty() {
        return Err(format!(
            "CPID 0x{cpid:04X} is an A9, but the serial descriptor has no SRTG. That is iBSS/LLB \
             DFU, not SecureROM DFU: the A9 table's addresses are for the SecureROM builds \
             {A9_8003_SRTG} / {A9_8000_SRTG} and would be wrong for any other image. \
             gaster silently waits forever in this state (cpid never gets assigned). \
             serial: {:?}",
            id.serial
        ));
    }
    if !srtg.eq_ignore_ascii_case(expected_srtg) {
        return Err(format!(
            "CPID 0x{cpid:04X} expects SRTG {expected_srtg} but the device reports SRTG \
             {srtg:?}. The addresses are per bootrom build, so this is refused rather than \
             guessed. serial: {:?}",
            id.serial
        ));
    }

    Ok((cfg, PayloadKind::A9))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(serial: &str) -> DeviceIdentity {
        DeviceIdentity::parse(serial)
    }

    /// The live capture of our attached unit, verbatim from `types.rs`.
    const LIVE_8003: &str = "CPID:8003 CPRV:01 CPFM:03 SCEP:01 BDID:02 \
                             ECID:00112233445566AA IBFL:1C SRTG:[IBOOT-2234.0.0.2.22]";
    const LIVE_8000: &str = "CPID:8000 CPRV:20 CPFM:03 SCEP:01 BDID:04 \
                             ECID:0011223344556677 IBFL:1C SRTG:[iBoot-2234.0.0.3.3]";

    #[test]
    fn table_holds_exactly_the_two_a9_dies() {
        let all = all_configs();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].cpid, 0x8003);
        assert_eq!(all[1].cpid, 0x8000);
    }

    /// Every field of the 0x8003 entry, against the gaster line it came from.
    /// A wrong address here is a payload that jumps into nothing, so this test
    /// names the reference for each value rather than restating the struct.
    #[test]
    fn cpid_8003_fields_are_exactly_gaster_624_640() {
        let c = A9_8003;
        assert_eq!(c.cpid, 0x8003, "gaster.c:625");
        assert_eq!(c.name, "s8003 Malta", "readmes/a9ctl-README.md:96");
        assert_eq!(c.overwrite_pad, 0x500, "gaster.c:626");
        assert_eq!(c.patch_addr, 0x10000812C, "gaster.c:627");
        assert_eq!(c.ttbr0_addr, 0x1800C8000, "gaster.c:628");
        assert_eq!(c.memcpy_addr, 0x100011030, "gaster.c:629");
        assert_eq!(c.ttbr0_vrom_off, 0x400, "gaster.c:631");
        assert_eq!(c.boot_tramp_end, 0x1800E1000, "gaster.c:632");
        assert_eq!(c.g_usb_serial_number, 0x180087958, "gaster.c:633");
        assert_eq!(c.dfu_handle_request, 0x1800878F8, "gaster.c:634");
        assert_eq!(c.dfu_handle_bus_reset, 0x180087928, "gaster.c:636");
        assert_eq!(c.insecure_memory_base, 0x180380000, "gaster.c:637");
        assert_eq!(c.usb_create_string_descriptor, 0x10000E354, "gaster.c:639");
        assert_eq!(
            c.usb_serial_number_string_descriptor, 0x1800807DA,
            "gaster.c:640"
        );
        assert_eq!(c.ttbr0_vrom_addr(), 0x1800C8400, "gaster.c:1120");
        assert_eq!(c.pwnd_string, " PWND:[checkm8]", "gaster.c:154");
        assert_eq!(c.pwnd_bytes().len(), 15, "strlen(pwnd_str), gaster.c:1110");
        assert_eq!(c.cprv, 0x01, "types.rs LIVE / readmes/a9ctl-README.md");
    }

    /// The A9-specific zeroes are load-bearing: `large_leak == 0` is what
    /// selects the A9 SPRAY branch, and `hole`/`ttbr0_sram_off` belong to the
    /// non-A9 paths only.
    #[test]
    fn a9_only_zeroes_are_pinned() {
        for c in all_configs() {
            assert_eq!(c.large_leak, 0, "gaster.c:900 selects the A9 spray path");
            assert_eq!(c.hole, 0, "gaster.c:905 is the non-A9 path");
            assert_eq!(c.ttbr0_sram_off, 0, "gaster.c:1102 is the non-A9 path");
        }
    }

    #[test]
    fn cpid_8000_fields_are_exactly_gaster_641_657() {
        let c = A9_8000;
        assert_eq!(c.cpid, 0x8000, "gaster.c:642");
        assert_eq!(c.overwrite_pad, 0x500, "gaster.c:643");
        assert_eq!(c.patch_addr, 0x10000812C, "gaster.c:644");
        assert_eq!(c.ttbr0_addr, 0x1800C8000, "gaster.c:645");
        assert_eq!(c.memcpy_addr, 0x100011030, "gaster.c:646");
        assert_eq!(c.ttbr0_vrom_off, 0x400, "gaster.c:648");
        assert_eq!(c.boot_tramp_end, 0x1800E1000, "gaster.c:649");
        assert_eq!(c.g_usb_serial_number, 0x180087958, "gaster.c:650");
        assert_eq!(c.dfu_handle_request, 0x1800878F8, "gaster.c:651");
        assert_eq!(c.dfu_handle_bus_reset, 0x180087928, "gaster.c:653");
        assert_eq!(c.insecure_memory_base, 0x180380000, "gaster.c:654");
        assert_eq!(c.usb_create_string_descriptor, 0x10000E354, "gaster.c:656");
        assert_eq!(
            c.usb_serial_number_string_descriptor, 0x1800807DA,
            "gaster.c:657"
        );
        assert_eq!(c.cprv, 0x20, "the previous session's unit, a9ctl README:33");
    }

    /// gaster really does carry identical addresses for both A9 branches. Pin
    /// it so a future "fix" that makes one of them differ fails here.
    #[test]
    fn both_a9_entries_share_every_address() {
        let (a, b) = (A9_8003, A9_8000);
        assert_eq!(a.overwrite_pad, b.overwrite_pad);
        assert_eq!(a.large_leak, b.large_leak);
        assert_eq!(a.hole, b.hole);
        assert_eq!(a.ttbr0_vrom_off, b.ttbr0_vrom_off);
        assert_eq!(a.ttbr0_sram_off, b.ttbr0_sram_off);
        assert_eq!(a.insecure_memory_base, b.insecure_memory_base);
        assert_eq!(a.dfu_handle_bus_reset, b.dfu_handle_bus_reset);
        assert_eq!(a.dfu_handle_request, b.dfu_handle_request);
        assert_eq!(a.memcpy_addr, b.memcpy_addr);
        assert_eq!(a.g_usb_serial_number, b.g_usb_serial_number);
        assert_eq!(
            a.usb_create_string_descriptor,
            b.usb_create_string_descriptor
        );
        assert_eq!(
            a.usb_serial_number_string_descriptor,
            b.usb_serial_number_string_descriptor
        );
        assert_eq!(a.patch_addr, b.patch_addr);
        assert_eq!(a.boot_tramp_end, b.boot_tramp_end);
        assert_eq!(a.ttbr0_addr, b.ttbr0_addr);
        assert_eq!(a.pwnd_string, b.pwnd_string);
        assert_ne!(a.cpid, b.cpid);
        assert_ne!(a.cprv, b.cprv);
    }

    #[test]
    fn resolves_the_attached_device_both_casings() {
        let upper = config_for_identity(&ident(LIVE_8003)).expect("IBOOT- casing");
        assert_eq!(upper.0.cpid, 0x8003);
        assert_eq!(upper.1, PayloadKind::A9);
        let lower = config_for_identity(&ident(
            "CPID:8003 CPRV:01 SRTG:[iBoot-2234.0.0.2.22]",
        ))
        .expect("iBoot- casing");
        assert_eq!(lower.0, upper.0);
    }

    #[test]
    fn resolves_the_windows_underscore_descriptor() {
        let id = ident(
            "CPID:8003_CPRV:01_CPFM:03_SCEP:01_BDID:02_ECID:00112233445566AA_IBFL:1C_\
             SRTG:[IBOOT-2234.0.0.2.22]",
        );
        let (cfg, kind) = config_for_identity(&id).expect("underscore form");
        assert_eq!(cfg.cpid, 0x8003);
        assert_eq!(kind, PayloadKind::A9);
    }

    #[test]
    fn resolves_the_8000_unit() {
        let (cfg, kind) = config_for_identity(&ident(LIVE_8000)).expect("8000");
        assert_eq!(cfg.cpid, 0x8000);
        assert_eq!(kind, PayloadKind::A9);
    }

    /// A die we have no blob for must be refused, and the message must name the
    /// die and say why. Defaulting to a "plausible" entry is how this project
    /// has burned sessions.
    #[test]
    fn unknown_cpid_is_refused_by_name() {
        let e = config_for_identity(&ident(
            "CPID:8010 CPRV:11 BDID:0C SRTG:[iBoot-2696.0.0.1.33]",
        ))
        .unwrap_err();
        assert!(e.contains("0x8010"), "{e}");
        assert!(e.contains("not in this crate's table"), "{e}");
    }

    #[test]
    fn missing_cpid_is_refused() {
        let e = config_for_identity(&ident("SRTG:[iBoot-2234.0.0.2.22]")).unwrap_err();
        assert!(e.contains("no CPID"), "{e}");
    }

    /// `SRTG` absent means this is not SecureROM DFU. Refusing here is the
    /// difference between "wrong boot stage" and "the exploit does not work".
    #[test]
    fn missing_srtg_is_refused_as_wrong_boot_stage() {
        let e = config_for_identity(&ident("CPID:8003 CPRV:01 BDID:02")).unwrap_err();
        assert!(e.contains("iBSS"), "{e}");
        assert!(e.contains("no SRTG"), "{e}");
    }

    #[test]
    fn mismatched_srtg_is_refused_with_both_values() {
        let e = config_for_identity(&ident("CPID:8003 SRTG:[iBoot-9999.0.0.1.1]")).unwrap_err();
        assert!(e.contains("iBoot-2234.0.0.2.22"), "{e}");
        assert!(e.contains("iBoot-9999.0.0.1.1"), "{e}");
    }

    /// The two A9 builds must not be silently interchangeable.
    #[test]
    fn the_two_builds_do_not_cross_resolve() {
        let e = config_for_identity(&ident("CPID:8000 SRTG:[iBoot-2234.0.0.2.22]")).unwrap_err();
        assert!(e.contains("iBoot-2234.0.0.3.3"), "{e}");
        let e = config_for_identity(&ident("CPID:8003 SRTG:[iBoot-2234.0.0.3.3]")).unwrap_err();
        assert!(e.contains("iBoot-2234.0.0.2.22"), "{e}");
    }

    #[test]
    fn cprv_mismatch_notes_but_does_not_refuse() {
        let id = ident("CPID:8003 CPRV:11 SRTG:[iBoot-2234.0.0.2.22]");
        let (cfg, _) = config_for_identity(&id).expect("CPRV is not a gate");
        let note = cfg.cprv_note(&id).expect("mismatch must be reported");
        assert!(note.contains("0x11"), "{note}");
        assert!(note.contains("not a refusal"), "{note}");

        let same = ident(LIVE_8003);
        assert!(cfg.cprv_note(&same).is_none());
        let unknown = ident("CPID:8003 SRTG:[iBoot-2234.0.0.2.22]");
        assert!(cfg.cprv_note(&unknown).is_none(), "absent CPRV is not a mismatch");
    }
}
