# RUNBOOK — the reference `gaster` on Linux against the attached A9

**Commissioned by the Lead. Author: `gaster-analyst`.**
**Status: PREPARATION ONLY. Nothing in §3.2 or §4 has been run. No device access, no driver
binding, no `pnputil`, nothing that opens `VID_05AC&PID_1227`.**
**Step 1 (the build) IS DONE and verified — §2, §3.**

---

## 1. What this experiment is for, and the one thing that limits it

**Purpose:** decide whether checkm8's SETUP stage fails because of our Windows host or because of
this device. If the reference pwns from Linux, the remaining work is a port. If it fails from Linux
too, the SETUP primitive as specified does not execute on this unit.

**The limiting fact, stated first because it decides how to read the result.** The Linux environment
available here is WSL 2 reached through `usbipd-win`, which is a **network-transported USB stack**.
The tree's own feasibility study already assessed this path and ranked it **below a bare-metal Linux
boot**, for three named reasons — the third of which threatens this experiment directly:

> **USBIP is a network-transported USB stack** — device enumeration, control transfers and especially
> resets are mediated by the `usbip` client/server pair. checkm8 is a timing- and reset-sensitive
> exploit; **SPECULATIVE but likely:** the added latency/jitter and the virtual host controller's reset
> semantics will hurt reliability, and `libusb_reset_device()` over USBIP is not the same operation as
> a real port reset.
> — `a9lab/IPWNDFU-FEASIBILITY.md:176` (Rank 4, catch 3)

And `usbipd-win`'s own README says of attaching: *"Attaching devices to a client is non-persistent.
You will have to re-attach after a reboot, **or when the device resets** or is physically
unplugged/replugged."* gaster resets the device after **every** stage attempt (`gaster.c:1268`).

**So the result is asymmetric, and the asymmetry should drive the decision:**

* **A gaster SETUP success is decisive and cheap** — a pad STALL is a pad STALL regardless of
  transport, and it would prove the primitive fires on this unit and the failure is host-side. That
  is the outcome worth buying a runbook for.
* **A gaster failure is NOT decisive.** It cannot distinguish "this device refuses the 0x800 DNLOAD"
  from "the transport cannot carry the reset/timing". **The Lead's stated decision rule — "If gaster
  *also* fails, we have measured that checkm8's SETUP as specified does not work on this unit" — is
  not supported by this experimental design.**

**Recommendation, in rank order.** (1) Run the usbipd route exactly as in §4 as a *bounded, cheap
first probe* — a success ends the question. (2) Treat a failure as inconclusive and go to the
decisive version: **bare-metal Linux live-USB boot on this same PC** (the phone stays plugged into the
same physical machine; only the OS changes), which is `IPWNDFU-FEASIBILITY.md:148-153` Rank 1 and is
the only path with no unproven platform assumptions. Do not spend a long session tuning the usbip
route, and do not let its failure close the question.

---

## 2. The build — DONE, and its provenance

### 2.1 What was actually built, and from what

| Item | Value |
|---|---|
| Upstream | `0x7ff/gaster`, commit **`7fffffff38a1bed1cdc1c5bae0df70f14395129b`** (2023-02-02 15:00:25 +0300, "Update") |
| Tree state | **Working tree ≡ HEAD, CRLF-only.** `git status` lists 11 modified files, but `git diff --ignore-cr-at-eol --stat` is **empty** and every file shows exactly equal insertions/deletions (2898/2898). `file` confirms CRLF terminators. **No substantive modification exists.** |
| `gaster.c` | sha256 `9aadab9db873b3e2ce85b530069937d03b9a73e0d4699241037943b928552605` (CRLF working-tree form) |
| `Makefile` | sha256 `aeceb10abeaf537161c4f71dac316eeea2b7ed7566a5db0c4b0f278f3af0f8a4` |
| `payload_A9.bin` | sha256 `a698045fae09acdc5bfafc26ef3fe7848f1454b8ce8847fdc45396cc18a532b2` |
| `payload_handle_checkm8_request.bin` | sha256 `c0c213047a8902186392396cb7e57c096626b4812b61e07c2cf7cf6b99a9889c` |

**Both payload digests are byte-identical to the constants our port vendors and verifies**
(`a9pwn/src/payload.rs:40-41`, `INTERFACE.md:186-187`). That is the provenance fact that matters most:
**the reference build embeds exactly the blobs `a9pwn` embeds**, so a behavioural difference between
the two cannot be a payload difference.

Build location: `/root/gaster` — **the distro's ext4, never over `/mnt/*`** (9p/drvfs has no real
hardlinks and broken symlink semantics). Sources were copied with
`cp -a /mnt/e/Reverseing/Arlo/research/refs/gaster/. /root/gaster/` and hashed inside the distro to
confirm they matched the Windows-side hashes before compiling.

### 2.2 Environment (all MEASURED in the distro)

| Item | Value |
|---|---|
| Distro | Ubuntu 24.04.5 LTS, WSL 2, kernel `6.18.40.1-microsoft-standard-WSL2` |
| Compiler actually used | **`cc` → gcc 13.3.0** |
| `clang` | 18.1.3 (present but **not used** — see the note below) |
| `make` | GNU Make 4.3 |
| libusb | **1.0.27-1** (dev headers installed in step 2.4); runtime `libusb-1.0.so.0` |
| OpenSSL | `libcrypto.so.3`, `/usr/include/openssl/evp.h` present |
| `xxd` | present (`/usr/bin/xxd`, from vim-common) |

> **⚠ Provenance note on the compiler.** `Makefile:3` says `CC ?= clang`, but **the build used `cc`
> (gcc)**, and make prints `cc -Wall -Wextra -Wpedantic -DHAVE_LIBUSB …`. `?=` sets a variable only if
> it is *not already defined*, and GNU make predefines `CC = cc` from its built-in rules — so the
> clang intent is inert. **This is not a defect and needs no fix**; it is recorded so nobody later
> assumes the binary was built by clang, and so a rebuild on a machine where the default differs is
> recognised as a different artifact.

### 2.3 The exact error the unmodified tree produces (as commissioned — reported, not patched)

First build attempt, sources untouched, default flags:

```
cc -Wall -Wextra -Wpedantic -DHAVE_LIBUSB gaster.c lzfse.c -o gaster -lusb-1.0 -lcrypto -Os
gaster.c:17:17: fatal error: libusb-1.0/libusb.h: No such file or directory
   17 | #       include <libusb-1.0/libusb.h>
      |                 ^~~~~~~~~~~~~~~~~~~~~
compilation terminated.
make: *** [Makefile:20: libusb] Error 1
```

**Cause: the libusb development headers were not installed.** Only the runtime library
(`libusb-1.0.so.0`) was present. Nothing in the source was wrong, and nothing was patched.

### 2.4 The exact build command, and the binary it produced

```bash
# the one missing declared dependency
wsl -u root -d Ubuntu-24.04 -- apt-get install -y libusb-1.0-0-dev

# the build (sources unmodified, no CC override, faithful to the Makefile)
wsl -d Ubuntu-24.04 -- make -C /root/gaster libusb
```

Result — **exit 0**, generated headers deleted by the Makefile afterwards as designed:

| Item | Value |
|---|---|
| Path | `/root/gaster/gaster` |
| Size | 46,992 bytes |
| **sha256** | **`5e52a06f8422de1ed1abfbf26c2993f798a38a4d589e52ba178c745a71a58c65`** |
| Type | ELF 64-bit LSB PIE, x86-64, dynamically linked, **not stripped** |
| Links | `libusb-1.0.so.0`, `libcrypto.so.3`, `libc.so.6`, `libudev.so.1` |

**How to re-verify that a later rebuild is the same artifact:** re-run the two commands and compare
the sha256 above. Two things can legitimately change it — a different `CC`, and newline handling in
the copied sources — so compare against this hash *and* against the source hashes in §2.1 rather than
assuming.

### 2.5 Provenance checks performed on the binary itself

1. **Both payload blobs are embedded verbatim.** A hex-dump substring search of the binary finds
   `payload_A9.bin` (280 bytes) and `payload_handle_checkm8_request.bin` (248 bytes) as **exact byte
   sequences** — not merely same-length data. This is the strongest available statement that the
   binary carries the audited payloads.
2. **The expected symbols are present** (`nm`): `gaster_checkm8`, `checkm8_stage_patch`,
   `checkm8_usb_request_stall`, `checkm8_usb_request_leak`, `checkm8_no_leak`, `dfu_set_state_wait_reset`,
   `dfu_check_status.constprop.0.isra.0`, `send_usb_control_request_async_no_data.part.0`,
   `usb_timeout`, `usb_abort_timeout_min`, `config_overwrite_pad`, `config_hole`, `config_large_leak`,
   `boot_tramp_end`, `payload_A9_bin`, `payload_A9_bin_len`. **Note:** `checkm8_stage_reset`,
   `checkm8_stage_setup` and `checkm8_stage_spray` have **no symbol** — `-Os` inlined them into
   `gaster_checkm8`. That is expected and is not a missing-code signal; `checkm8_stage_patch` is
   present because it is too large to inline.
3. **The device IDs are compiled in**: `main` sets `0x122705ac` (`0x05AC:0x1227`) on the `reset` path
   (disassembly at `main+0x10e`). The binary is aimed at exactly this device.
4. **The usage path provably cannot touch USB.** `main`'s argument-mismatch branch
   (`gaster.c:1655-1665`) is only `printf`/`puts`/`strcmp` — the disassembly contains no libusb call
   on that path. The binary was therefore executed with no arguments safely, and it ran:
   ```
   usb_timeout: 5
   usb_abort_timeout_min: 0
   Usage: env /root/gaster/gaster options
   … options list …
   ```
   **`usb_timeout: 5` and `usb_abort_timeout_min: 0` are the reference defaults of
   `gaster.c:1631-1638`, read back from the compiled artifact.** Exit code 1 (usage), as expected.

---

## 3. Device presentation — what is possible, and what is not yet verified

### 3.1 What is confirmed present

| Requirement | State |
|---|---|
| `usbipd-win` | **5.3.0** at `C:\Program Files\usbipd-win\usbipd.exe` (MEASURED) |
| usbipd service (`USBIP Device Host`) | must be **running**; verify in the Services app or `Get-Service usbipd` |
| WSL 2 distro running | **`Ubuntu-24.04` is Running** (MEASURED) |
| WSL 2 kernel USBIP support | **`usbip-core.ko`, `usbip-host.ko`, `vhci-hcd.ko` all present** in `/lib/modules/6.18.40.1-microsoft-standard-WSL2/kernel/drivers/usb/usbip/` (MEASURED) — this resolves the feasibility report's Rank-4 catch 2 |
| No USB bus in WSL by default | **`/sys/bus/usb/drivers` does not exist** (MEASURED). Expected: WSL 2 has no physical USB; the virtual controller only appears once `vhci-hcd` is loaded. |
| Userspace `usbip` client in the distro | **MISSING** — and **not required.** The vendor README puts `usbip` in the **non-WSL 2** path only; for WSL 2 the attach is done from Windows by `usbipd`, and the Linux side needs only the kernel modules. |
| Distro default user | **uid 0 (root)** (MEASURED) — so no udev rule is needed for `/dev/bus/usb/*` access |

### 3.2 The command sequence — **DO NOT RUN. The Lead runs every device action.**

```powershell
# ── WINDOWS, ELEVATED (administrator). One-time per device; 'bind' PERSISTS ACROSS REBOOTS. ──
usbipd list                            # find the BUSID of the 05ac:1227 node; note the busid
usbipd bind --busid=<BUSID>            # share it. Requires admin. Persistent.
```

```powershell
# ── WINDOWS, NOT elevated. NON-persistent: re-attach after every reboot / reset / replug. ──
wsl -l -v                              # ensure Ubuntu-24.04 is Running first
usbipd attach --wsl --busid=<BUSID>    # usbipd attaches it into the WSL 2 kernel
```

```bash
# ── INSIDE WSL Ubuntu-24.04 ──
modprobe vhci-hcd                      # loads the virtual host controller; may already be loaded
lsusb                                  # expect: 05ac:1227  (Apple … DFU Mode)
ls -l /dev/bus/usb/*/*                 # libusb needs a node here; root, so no udev rule
```

**Elevation:** only `usbipd bind` (and `usbipd list` when run alongside it) needs administrator
privileges. `usbipd attach --wsl` explicitly **does not**. Confirmed from the vendor README, not
inferred.

### 3.3 Two prerequisites you must verify yourself, because I could not without touching the device

1. **Does `usbipd bind` replace the Windows-side driver binding?** The feasibility report states that
   while attached *"the device is claimed by usbipd's stub driver — it disappears from the Windows
   side (`usbipd unbind` restores it)"* (`IPWNDFU-FEASIBILITY.md:177`). If true, **`a9pwn` will stop
   seeing the device through libusbK for the duration**, and the working configuration HANDOFF §3
   documents must be re-established afterwards. **Labelled INFERRED — check the `State` column of
   `usbipd list` and Device Manager before and after.** Plan the recovery *before* binding:
   `usbipd detach --busid=<BUSID>` (or `usbipd unbind --busid=<BUSID>`) and then confirm with
   `a9pwn preflight` that libusbK is still bound, re-running `a9drv bind …` if not.
2. **Whether a host-initiated port reset survives the USBIP hop.** `gaster.c:1268` resets after every
   attempt and `gaster.c:197-200` discards the result, so gaster **cannot tell you** if the reset was
   a no-op — exactly the failure mode HANDOFF §8.1 documents for WinUSB. This is the single biggest
   threat to the experiment's interpretability and the reason §1's asymmetry exists.

---

## 4. The exact gaster invocation, and how to read its output

### 4.1 Invocation

```bash
# from inside WSL Ubuntu-24.04. Run as root (the distro's default), so libusb can open the node.
/root/gaster/gaster pwn
```

There are no flags. `main` accepts exactly one of `reset`, `pwn`, `decrypt src dst`,
`decrypt_kbag kbag`; anything else prints usage (`gaster.c:1639-1665`). The two **environment
variables** are gaster's only tuning knobs (`gaster.c:1627-1638`):

| Variable | Default | Meaning | Note |
|---|---|---|---|
| `USB_TIMEOUT` | **5** | One global: every synchronous control request's timeout (`:227`), the async transfer's own libusb timeout (`:255`), the `wait_usb_handle` poll interval (`:214`), and the base of the abort-window derivation (`:849`, `:857`) | **Leave at 5.** It is the reference's value and it is what "gaster as specified" means. |
| `USB_ABORT_TIMEOUT_MIN` | **0** | Floor of the abort window cycle | **Leave at 0** → the sweep is the documented `4,5,0,1,2,3`. Raising it collapses the sweep's resolution. |

**Do not set either one for the decisive run.** Setting `USB_TIMEOUT` would no longer be testing the
reference as written, and it would confound the pad-timeout question specifically, since gaster's pad
request uses this same global (`:227`).

### 4.2 What gaster prints, in order — SUCCESS

```
usb_timeout: 5
usb_abort_timeout_min: 0
[libusb] Waiting for the USB handle with VID: 0x5AC, PID: 0x1227
Found the USB handle.
CPID: 0x8003                       ← gaster.c:810; the SRTG match succeeded
Stage: RESET                       ← gaster.c:1246
ret: true                          ← gaster.c:1263
Stage: SETUP                       ← gaster.c:1250
ret: true                          ← gaster.c:1263 — THE PAD STALLED. This is the line that matters.
Stage: SPRAY
ret: true
Stage: PATCH
ret: true
Now you can boot untrusted images. ← gaster.c:1271
```

**Success criterion, precisely:** ` PWND:[checkm8]` present in the device's serial-number string
descriptor. gaster's own test is `strstr(usb_serial_num, pwnd_str)` with
`pwnd_str = " PWND:[checkm8]"` (`gaster.c:811`, `:154`), evaluated inside
`checkm8_check_usb_device` on every loop iteration. The user-visible proof is
`Now you can boot untrusted images.`, and the process **exits 0** (`main` sets `ret = 0` only when
`gaster_checkm8` returns true). Cross-check independently inside WSL:

```bash
lsusb -d 05ac:1227 -v | grep -i iSerial     # expect the PWND:[checkm8] marker
```

### 4.3 Every failure mode gaster can print

| Output | Meaning | Source |
|---|---|---|
| `Usage: env <path> options` + list | Bad arguments | `gaster.c:1655-1665` (reproduced here) |
| `[libusb] Waiting for the USB handle with VID: 0x5AC, PID: 0x1227` **repeating forever** | No libusb handle. **This is a hang, not an error** — `wait_usb_handle` loops forever with `sleep_ms(usb_timeout)` between attempts | `gaster.c:206-215` |
| `Found the USB handle.` then silence, no `CPID:` | `checkm8_check_usb_device` matched nothing, so `cpid` stayed 0 and it returned false → the loop re-opens and waits again. **Most likely cause here: the SRTG substring did not match.** | `gaster.c:809-813`, `:1243` |
| `Stage: RESET` … `ret: false` repeatedly | RESET fails each round; the loop continues, resetting and re-opening | `gaster.c:1258-1268` |
| **`Stage: SETUP` and then nothing, forever** | **The expected signature of the failure we are chasing.** gaster is inside the `for(;;)` at `gaster.c:852` | `gaster.c:850-858` |

### 4.4 How to tell "stuck" from "working" — and it is the crux

**You cannot tell from gaster's output. That is the defect this rewrite exists to remove.**
`checkm8_stage_setup` is a `for(;;)` (`gaster.c:852`) and the sweep prints **nothing at all** — no
attempt count, no abort window, no pad result. After `Stage: SETUP` there is exactly one observable:
the absence of the next line. A gaster that is converging and a gaster that is burning attempts
forever look identical.

**Therefore the observer must be outside gaster. Use the kernel's USB monitor inside WSL:**

```bash
mount -t debugfs none /sys/kernel/debug 2>/dev/null   # may already be mounted
modprobe usbmon                                        # if not built in
cat /sys/kernel/debug/usb/usbmon/0u                    # or: tcpdump -i usbmon0 -w /tmp/gaster.pcap
```

What to look for on the wire, per SETUP attempt — this is the sequence our own trace records and
gaster's source specifies, so a working gaster will show it repeating, and a stuck one will show
nothing new:

1. `bmRequestType 0x21, bRequest 1 (DNLOAD), wValue 0, wIndex 0, wLength 0x800` — the **aborted**
   transfer (`gaster.c:853`). Its data stage will *not* complete; expect to see it cut short.
2. `bmRequestType 0x00, bRequest 0, wValue 0, wIndex 0, wLength 0x500` — the **pad** request
   (`gaster.c:853`). **This is the one to watch.** A `STALL` handshake here is the pass condition; a
   stream of NAKs (our Windows trace's `TIMEOUT`) is the known failure.
3. `bmRequestType 0x21, bRequest 1, wLength 0x40` — the **drain** (`gaster.c:856`), whose result
   gaster discards.

Counting (1) and (2) over a minute tells you whether gaster is sweeping at all; watching (2)'s
handshake tells you, directly and for the first time on this device from a non-Windows host, whether
the pad ever STALLs. **`usbmon` is the only instrument that can answer the question this experiment
exists to ask** — gaster itself will not.

---

## 5. What this experiment does NOT settle

Stated as a list, because each line is a claim someone will otherwise make afterwards.

1. **It does not test whether our port is byte-faithful.** That is established by source comparison
   against `gaster.c` (§7 of the parent addendum), and gaster's behaviour on a Linux host cannot
   validate our requests either way.
2. **A gaster failure does not establish that checkm8's SETUP cannot work on this unit.** The
   transport is unvalidated: no proven real port reset, documented detach-on-reset, and added
   latency/jitter (`IPWNDFU-FEASIBILITY.md:176`). The tree's own report ranks this path below
   bare-metal Linux for exactly that reason. **Only a gaster SETUP success is decisive.**
3. **A gaster success would not identify which of our host-side differences mattered.** The two hosts
   differ in at least four ways at once — pad timeout (5 ms vs our 40 ms), reset capability
   (libusbK real reset vs USBIP-mediated), timer behaviour (Linux `usleep`/`epoll` vs Windows tick),
   and libusb build (1.0.27/1.0.24). A success establishes "it can work from Linux", which is enough
   to redirect effort but not enough to name the fix.
4. **It does not test the pad-timeout question.** gaster's pad uses 5 ms (`gaster.c:227`). If gaster's
   SETUP passes, we learn the pad STALLs within 5 ms on that host; if it hangs, we learn nothing about
   whether our 40 ms was right.
5. **It does not reveal `sz`.** gaster never logs `transfer_ret.sz`. So the question that prompted
   this — whether the aborted 0x800 DNLOAD ever moves a byte — cannot be answered from gaster's
   output. `usbmon` (§4.4) comes closest: it shows how far the aborted transfer's data stage got.
6. **It is not statistically comparable to our sweep.** Our runs are 154 to 31,000 logged attempts
   with per-attempt outcomes; gaster's SETUP has no attempt limit and no logging. A gaster that
   "seemed to hang for ten minutes" is not a measurement of a STALL rate.
7. **It does not settle anything about the PATCH stage or the spray**, which have their own parameter
   questions (`V08`, the phantom `LEAK_WINDEX_IPWNDFU`) already recorded in the parent document.

---

## 6. Pre-flight checklist for the Lead

- [ ] `Get-Service usbipd` → Running
- [ ] `wsl -l -v` → `Ubuntu-24.04` Running
- [ ] `/root/gaster/gaster` sha256 == `5e52a06f8422de1ed1abfbf26c2993f798a38a4d589e52ba178c745a71a58c65`
      (rebuild with §2.4 if not; re-check the source hashes in §2.1 first)
- [ ] Decide and write down the **recovery plan** for the Windows-side driver binding before running
      `usbipd bind` (§3.3 item 1) — `usbipd unbind` + `a9pwn preflight`, and `a9drv bind …` if needed
- [ ] Start `usbmon` capture **before** gaster, or the SETUP stage will be unobservable (§4.4)
- [ ] `USB_TIMEOUT` / `USB_ABORT_TIMEOUT_MIN` unset in the gaster environment (§4.1)
- [ ] Decide the time budget: if `Stage: SETUP` prints and nothing follows for N minutes, stop and
      read the `usbmon` capture rather than waiting. **gaster has no timeout and will sweep forever.**
- [ ] If gaster fails: do **not** conclude the unit is unexploitable (§5 item 2). Go to bare-metal
      Linux live USB, which is the decisive version of this experiment.
