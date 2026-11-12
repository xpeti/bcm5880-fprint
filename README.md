# bcm5880-fprint — Dell ControlVault 2 (Broadcom BCM5880) fingerprint on Linux

A working, clean-room **Linux `libfprint` driver** for the **Dell ControlVault 2 /
Broadcom BCM5880 "USH"** fingerprint reader — USB **`0a5c:5834`** — found in many
Dell Latitude laptops (5290/5490/5590, 7290/7390/7480/7490, E7470, …).

This reader was considered *unsupported on Linux for about a decade*: mainline
`libfprint` doesn't drive it, and Dell only ships a closed driver for the newer
ControlVault **3** "Citadel" sensors. This project reverse-engineers **exactly how the
chip's secure session works** and ships a native `libfprint` TOD driver that
**enrolls and verifies on the real hardware** — fingerprint `sudo` and login work on
Fedora.

> Companion project: [`bcm5880-nfc`](../bcm5880-nfc) — the *contactless/NFC* side of
> the same chip. The two run **at the same time**: `fprintd` (fingerprint) and `pcscd`
> (NFC) coexist on one BCM5880 — fingerprint login and NFC card reading both work
> concurrently. See [Fingerprint + NFC together](#fingerprint--nfc-together).

> ⚠️ **Unofficial.** Not affiliated with or endorsed by Dell, Broadcom or Canonical.
> This is interoperability reverse-engineering of a device you own. It ships **no
> proprietary code** — only original tools, protocol notes, and USB captures.

---

## Status — working

| Capability | State |
|---|---|
| Talk to the chip over USB (libusb) | ✅ `probe.c` |
| Secure-session handshake, pull chip public key | ✅ |
| **Full session crypto — understood & reproduced** | ✅ **validated offline (`decrypt.py`)** |
| **Secure session on the real chip** | ✅ handshake, RSA key transport, encrypted commands round-trip |
| **Full CV2 command set reverse-engineered** | ✅ open `0x02`, discard `0x6d`, begin `0x8a`, capture `0x66`, submit `0x6c`, end `0x68`, commit `0x6e`, identify `0x73`, reset `0x5d`, close `0x04`, chipinfo `0x39` |
| **Enroll on the chip, end-to-end** | ✅ capture loop → chip mints a template-id → encrypted commit `0x6e` stores the template |
| **Verify / identify (match-on-chip)** | ✅ **correct finger → match, wrong finger → no-match, on hardware** |
| **Native `libfprint` TOD driver** | ✅ `driver/` — loads in `fprintd`, enroll + verify end-to-end |
| **`fprintd-enroll` / `fprintd-verify`** | ✅ store a print, return match / no-match |
| **PAM login / `sudo` by fingerprint** | ✅ via `authselect`, password fallback intact |
| **Runs alongside the NFC reader** | ✅ `fprintd` + `pcscd` concurrently |

**The whole chain works.** The ControlVault 2 "secure session" cryptography — the exact
reason the device couldn't be driven on Linux — is fully reverse-engineered and verified
byte-for-byte offline, and the native `libfprint` TOD driver drives the chip through a
**complete enroll *and* verify on real hardware**: it loads in `fprintd`, runs the full
handshake, enrolls a finger (encrypted commit `0x6e` — the step the CV3 driver
fundamentally *cannot* do), and **matches** on verify. `fprintd-enroll`, `fprintd-verify`,
and fingerprint `sudo`/login all work.

### How the match was cracked

Two things were needed to make `0x73` identify report a match on this chip:

1. **A fresh secure session per identify.** The verify flow is
   `0x02 open → [ 0x66 capture → open a FRESH 0x02 session → 0x73 identify on that fresh
   handle ] × rounds → 0x04`. Re-using the capture session's handle for `0x73` returns an
   empty/`0x85` body; a freshly opened session handle returns a real result body.
2. **Multiple rounds.** The match verdict is the response body's first `tag0` (`1` = match,
   `0` = no-match) — **not** the `+0x14` header byte. The chip may need several
   capture→identify rounds before it reports the match, so the driver loops (up to 15
   rounds) and stops on the first `verdict == 1`.

The enroll likewise needs a `0x5d` fingerprint-reset first; then the capture loop runs
until the `0x6c` submit handle prefix-flips `00 → 01`, yielding a chip template-id, which
`0x6e` commit stores.

---

## Why this chip was "impossible"

The open-source world already has a binary **ControlVault *3*** driver from Canonical
(`libfprint-2-tod-1-broadcom.so`). You can even byte-patch it to bind the CV2 `0a5c:5834`,
and it will **detect, open, capture and run the enrollment state machine** — but
enrollment always fails at the final **commit**, and verify never matches.

Root cause: **CV2 requires the fingerprint template to be stored through an encrypted
"secure session"; CV3 does not.** The CV3 driver has *no* session cryptography at all (its
only crypto primitive is a bare `SHA256`). It sends the commit in *plaintext*; the CV2
chip rejects it, so nothing is ever stored and there is nothing to match against.

Driving CV2 therefore means **implementing the ControlVault Secure Session** that the
Windows driver (`BIPDll.dll`) performs. This repo is that work.

---

## How the chip works

### USB interfaces
`0a5c:5834` exposes four interfaces; the fingerprint path is **interface 0** ("USH"):
bulk OUT `0x01`, bulk IN `0x81`, interrupt IN `0x85` (status). Interface 2 is the
contactless CCID used by `bcm5880-nfc`. The two paths use **different interfaces**, which
is why fingerprint and NFC can run at the same time.

### Command framing (plaintext)
Every command is a 44-byte header plus a parameter area:

```
+0x00 u32  marker = 1
+0x04 u32  total length
+0x08 u16  command id          (0x39 chipinfo, 0x82 setup, 0x23 getpubkey, 0x6e commit, …)
+0x0a u16  flags               (bit0 = payload is encrypted/secure-session)
+0x0c u32  lib version = 2
+0x10 u32  session handle      (assigned by the chip during the handshake)
+0x14 u32  0
+0x28 u32  parameter length
+0x2c ...  parameters
```
The host sends the 44-byte command to bulk OUT `0x01`, reads an 8-byte status
`[status u32][length u32]` from interrupt IN `0x85`, then reads `length` bytes of
response from bulk IN `0x81`.

### The secure-session handshake
```
0x39  GetChipInfo      -> 848-byte text blob (USH_CHIPID, USH_CV_VER, firmware versions…)
0x82  setup
0x23  GetCVPublicKey   -> request carries [20-byte host field][u32 selector]
                          selector 0 = RSA-2048 path, 1 = ECDH P-256 path
                          response = chip public key (+ a trailing 20-byte "chip nonce")
                          and the chip assigns a session handle
0x24  key transport    -> host sends its nonce to the chip:
                          RSA path: RSA-2048(chip_pubkey, host_nonce[20])  (256-byte block)
                          ECDH path: host P-256 public key, so both sides derive a shared secret
```

The host only *verifies* the chip's certificate (and you can skip that — you own the
chip). There is **no provisioned host secret and no host signature**: the host key is
ephemeral / a fresh random nonce. That is why this is reproducible at all. The RSA path
requires reading the chip modulus **little-endian**.

### Session keys
```
ENC key  = SHA1( chip_nonce[20] ‖ host_nonce[20] )[0:16]      -> AES-128
HMAC key = SHA1( "CV secure session blob\0" )                 -> 20 bytes, FIXED
           = dbac7907f35763292a6b4ca4134d1ec85ceda31b
```
(`chip_nonce` is the last 20 bytes of the `0x23` response parameter; `host_nonce` is the
20 bytes the host transports in `0x24`.) There is a **single session key** — no second
ECDH/Key2 wall: all feature commands decrypt with this one key.

### Encrypted command frame (MAC-then-encrypt, AES-128-CBC)
```
[44-byte header, with a 16-byte IV at +0x18 sent IN CLEAR, inner_len at +0x28]
[ ciphertext ]

ciphertext = AES-128-CBC( ENC, IV,
                 PKCS7( body ‖ HMAC[20] ‖ counter_u32 ‖ 4-byte align ) )

HMAC = HMAC-SHA1( HMAC key, header[0x00:0x2c] (incl. the IV and total length)
                            ‖ body ‖ counter_u32 )

counter = per-session command index, starts at 0, +1 per command.
```
The 20-byte HMAC is encrypted *together with* the command body. The IV is produced by the
host RNG and sent in clear in the header. Response frames use the same layout with a
chip-chosen IV.

All of the above is **validated**: `decrypt.py` decrypts a real captured Windows session
(two independent sessions, multiple commands) and recomputes every HMAC correctly.

---

## How it was reverse-engineered

The ControlVault chip is **fragile**: a single malformed secure-session command makes its
firmware watchdog-reset into an SBI bootloader (`0a5c:5831`) that only a **cold power-off**
recovers. So trial-and-error on the chip is not viable — the protocol has to be exactly
right *before* it is sent. The trick that made this tractable was to take the chip out of
the loop entirely:

1. In a disposable **disk overlay** (the real disk untouched), patch the Windows
   `bipdll.dll` RNG so it emits a **deterministic** byte pattern (`00 01 02 …`) instead of
   random — so the host nonce and all IVs become known.
2. Boot that Windows in a VM with the chip passed through, and capture the USB traffic on
   the Linux host with `usbmon`. The Dell ControlVault service establishes a secure
   session on its own — **no Windows Hello / TPM needed**.
3. Because the host nonce and IV are known, the whole captured session can be **decrypted
   and reverse-engineered entirely offline**, iterating against a static capture with
   **zero risk to the chip**.

The command opcodes were recovered by disassembling the CV3 `broadcom.so` (which ships
symbols) — each feature is a `push 0xNN` before `cvhManageCVAPICall`. See
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full write-up.

---

## What's in this repo

| Path | What |
|---|---|
| `driver/bcm5880cv2.c` | Native **`libfprint` TOD driver**: async `FpDevice` subclass driving the chip over libusb via `FpiSsm` state machines — handshake, enroll, and verify. |
| `driver/cv2_session.[ch]` | Reusable, **pure (no-USB) session crypto**: key derivation, encrypted frame build/parse, RSA `0x24` key transport. Validated byte-for-byte. |
| `driver/Makefile` | Builds + installs the TOD driver `.so`. |
| `driver/ARCHITECTURE.md` | Driver design: vfuncs, the handshake/enroll/verify state machines. |
| `probe.c` | libusb tool: runs the handshake, pulls the chip's public key, computes the shared secret, **and always closes the session**. |
| `session_test.py` | End-to-end secure-session proof on the real chip (handshake → RSA `0x24` → encrypted command → decrypt reply). |
| `decrypt.py` | Offline decryptor/validator for a captured secure session. Reproduces key derivation, AES-128-CBC and HMAC-SHA1 exactly. |
| `captures/win-session-detnonce.pcapng` | Windows CV2 secure session captured with a **deterministic** host RNG — the reference used to crack the crypto. |
| `captures/linux-enroll-plaintext.pcapng` | The CV3-driver enrollment on Linux, sent in plaintext — the commands that just needed wrapping in the session crypto. |
| `chip-rsa-modulus.hex` | The example chip's RSA-2048 public modulus (device-public, for reference). |
| `docs/PROTOCOL.md` | Full protocol + crypto spec and the RE methodology. |

No Dell/Broadcom binaries or decompiled proprietary code are included.

---

## Install (Fedora)

### 1. Build dependencies

```bash
sudo dnf install git make gcc libusb1-devel openssl-devel \
                 fprintd fprintd-pam libfprint-tod
```

### 2. Build the driver

TOD drivers compile against libfprint's *internal* driver API, which the runtime package
doesn't ship — you need the **libfprint-tod source** matching your installed
`libfprint-2-tod-1`, plus its meson build dir (for the generated `fp-enums.h`):

```bash
# fetch + build the matching libfprint-tod source once
dnf download --source libfprint-tod
rpm2cpio libfprint-tod-*.src.rpm | cpio -idmv
tar xf libfprint-*.tar.* && cd libfprint-*
meson setup build && ninja -C build
cd -

# build + install the BCM5880 driver
cd driver
make LIBFPRINT_SRC=/path/to/libfprint-src LIBFPRINT_BUILD=/path/to/libfprint-src/build
sudo make install          # drops the .so into /usr/lib64/libfprint-2/tod-1/
sudo systemctl restart fprintd
```

### 3. Enroll and verify

```bash
fprintd-enroll            # press the finger, varied positions, until "enroll-completed"
fprintd-verify            # press again -> "verify-match"
```

### 4. Fingerprint login / `sudo` (PAM)

Fedora uses **authselect** (not `pam-auth-update`):

```bash
sudo authselect enable-feature with-fingerprint
sudo authselect apply-changes
```

This adds `auth sufficient pam_fprintd.so` to the stack: `sudo`, the login screen and the
lock screen accept your fingerprint, **and your password still works** (fingerprint is
*sufficient*, not *required* — no lockout risk). Keep a root shell open the first time, as
with any PAM change.

> **Recovery:** if a bad command ever drops the chip to `0a5c:5831` (bootloader), fully
> **power the laptop off and cold-boot** (a warm reboot is not enough) — the BIOS
> re-uploads the firmware on a cold start.

---

## Fingerprint + NFC together

The BCM5880 is one USB device with separate interfaces: the fingerprint path is
**interface 0** (USH), the contactless/NFC CCID is **interface 2**. `fprintd` claims
interface 0 only, `pcscd` (with the [`bcm5880-nfc`](../bcm5880-nfc) patched `libccid`)
drives interface 2 — so **both daemons run at the same time**. On this setup, with
`fprintd` active and holding interface 0, `pcscd` reads an NFC card (e.g. a YubiKey 5 NFC
over the contactless reader) cleanly, and fingerprint `sudo`/login keeps working. Enable
both for boot:

```bash
sudo systemctl enable --now pcscd.socket   # NFC (see bcm5880-nfc for the patched libccid)
# fprintd is socket/D-Bus-activated and always available
```

---

## Remaining work (contributions welcome)

1. **Verify the response HMAC** in `cv2_session` (currently decrypt-only) before trusting
   match results in security-sensitive contexts.
2. Surface enroll progress/retries more cleanly through `fprintd`, and tune the verify
   round cap (the chip matches faster right after a cold boot; it slows after many ops).
3. Package the driver (COPR / `.rpm`, udev/polkit notes) now that enroll + verify work.

⚠️ **Chip fragility:** always open exactly one session and close it (`0x04` + handle);
never hammer the device with speculative commands. A wrong secure-session command can drop
the chip to its bootloader until a full power-off.

## License

GPLv3 — see [LICENSE](LICENSE). Protocol documentation is original work describing observed
behaviour for interoperability.
