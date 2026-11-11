# bcm5880-fprint — Dell ControlVault 2 (Broadcom BCM5880) fingerprint on Linux

Reverse-engineering and (in-progress) Linux driver for the **Dell ControlVault 2 /
Broadcom BCM5880 "USH"** fingerprint reader — USB **`0a5c:5834`** — found in many
Dell Latitude laptops (5290/5490/5590, 7290/7390/7480/7490, E7470, …).

This reader has been considered *unsupported on Linux for about a decade*: mainline
`libfprint` doesn't drive it, and Dell only ships a closed driver for the newer
ControlVault **3** "Citadel" sensors. This project documents **exactly how the chip's
secure session works** and provides tooling that already talks to the chip and
reproduces its cryptography.

> Companion project: [`bcm5880-nfc`](../bcm5880-nfc) — the *contactless/NFC* side of
> the same chip, which is already fully working on Linux.

> ⚠️ **Unofficial.** Not affiliated with or endorsed by Dell, Broadcom or Canonical.
> This is interoperability reverse-engineering of a device you own. It ships **no
> proprietary code** — only original tools, protocol notes, and USB captures.

---

## Status

| Capability | State |
|---|---|
| Talk to the chip over USB (libusb) | ✅ `probe.c` |
| Secure-session handshake, pull chip public key | ✅ |
| P-256 ECDH shared secret with the chip | ✅ |
| **Full session crypto — understood & reproduced** | ✅ **validated offline** |
| **Secure session established on the real chip** | ✅ **`session_test.py` — handshake, RSA key transport, encrypted command accepted, chip healthy** |
| Decrypt a real Windows session end-to-end | ✅ `decrypt.py` |
| **Native `libfprint` TOD driver — secure session end-to-end** | ✅ **`driver/` — loads in `fprintd`, binds the device, runs the full handshake (`0x39`→`0x82`→`0x23`→`0x24`), chip accepts the RSA key transport, session derived; chip healthy** |
| **Native encrypted commands round-trip on the chip** | ✅ **wrapped `0x02` open-object + `0x04` close verified: chip replies decrypt to valid data (object handle); requires reading the chip modulus little-endian** |
| **Full CV2 command set reverse-engineered** | ✅ **open `0x02`, discard `0x6d`, begin `0x8a`, capture `0x66`, submit `0x6c`, end `0x68`, commit `0x6e`, identify `0x73`, close `0x04`, chipinfo `0x39`, setup `0x82` — from the CV3 `broadcom.so` disassembly + the plaintext enroll capture** |
| **Enroll on the chip, end-to-end** | ✅ **host-assisted capture loop → chip signals `0x59` COMPLETE → encrypted commit `0x6e` returns `0x8d`, byte-for-byte identical to the real CV3 driver. The encrypted commit the CV3 driver never could do.** |
| Verify / identify (match-on-chip) | 🚧 **pipeline runs end-to-end (fresh handshake → `0x73` arm → `0x66` capture → `0x73` match); chip captures & compares but does not yet report a match — final piece** |
| `libfprint` driver build | ✅ `driver/Makefile` |

**The hard part is done.** The ControlVault 2 "secure session" cryptography — the
exact reason the device couldn't be driven on Linux — has been completely reverse
engineered and **verified byte-for-byte offline**, and the native `libfprint` TOD
driver (`driver/`) now drives the chip through a **complete fingerprint enrollment on
the real hardware**: it loads in `fprintd`, runs the full handshake, opens an object,
runs the host-assisted capture loop until the chip reports the enrollment **COMPLETE
(`0x59`)**, and sends the **encrypted commit (`0x6e`)** — which the chip accepts with
the exact `0x8d` result the original Windows/CV3 driver produces. That encrypted
commit is the thing the CV3 driver fundamentally *cannot* do, and it works here.

What remains is the **match** side: the verify pipeline runs end-to-end (the chip
captures the finger and compares), but does not yet report a match. The command flow
and parameters are confirmed identical to the CV3 driver's `cvif_fingerprint_identify`;
the last gap is being closed with a decryptable reference capture of a real
enroll+verify.

---

## Why this chip was "impossible"

The open-source world already has a binary **ControlVault *3*** driver from Canonical
(`libfprint-2-tod-1-broadcom.so`). You can even make it bind to the CV2 `0a5c:5834`
with a few byte-patches, and it will **detect, open, capture and run the enrollment
state machine**. But enrollment always fails at the final **commit** step, and verify
never matches.

Root cause: **CV2 requires the fingerprint template to be stored through an encrypted
"secure session"; CV3 does not.** The CV3 driver has *no* session cryptography at all
(its only crypto primitive is a bare `SHA256`). It sends the commit command in
*plaintext*; the CV2 chip rejects it, so the template is never stored and there is
nothing to match against.

So driving CV2 means **implementing the ControlVault Secure Session (CSS)** that the
Windows driver (`BIPDll.dll`) performs. This repo is that work.

---

## How the chip works

### USB interfaces
`0a5c:5834` exposes four interfaces; the fingerprint path is **interface 0** ("USH"):
bulk OUT `0x01`, bulk IN `0x81`, interrupt IN `0x85` (status). (Interface 2 is the
contactless CCID used by `bcm5880-nfc`.)

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
ephemeral / a fresh random nonce. That is why this is reproducible at all.

### Session keys
```
ENC key  = SHA1( chip_nonce[20] ‖ host_nonce[20] )[0:16]      -> AES-128
HMAC key = SHA1( "CV secure session blob\0" )                 -> 20 bytes, FIXED
           = dbac7907f35763292a6b4ca4134d1ec85ceda31b
```
(`chip_nonce` is the last 20 bytes of the `0x23` response parameter; `host_nonce` is
the 20 bytes the host transports in `0x24`.)

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
The 20-byte HMAC is encrypted *together with* the command body. The IV is produced by
the host RNG and sent in clear in the header. Response frames use the same layout with
a chip-chosen IV.

All of the above is **validated**: `decrypt.py` decrypts a real captured Windows
session (two independent sessions, multiple commands) and recomputes every HMAC
correctly.

---

## How it was reverse-engineered

The ControlVault chip is **fragile**: a single malformed secure-session command makes
its firmware watchdog-reset into an SBI bootloader (`0a5c:5831`, "config 0
descriptor??") that only a **cold power-off** recovers. So trial-and-error on the chip
is not viable — the protocol has to be exactly right *before* it is sent.

The trick that made this tractable was to take the chip out of the loop entirely:

1. In a disposable **disk overlay** (the real disk untouched), patch the Windows
   `bipdll.dll` RNG so it emits a **deterministic** byte pattern (`00 01 02 …`) instead
   of random — so the host nonce and all IVs become known.
2. Boot that Windows in a VM with the chip passed through, and capture the USB traffic
   on the Linux host with `usbmon`. The Dell ControlVault service establishes a secure
   session on its own — **no Windows Hello / TPM needed**.
3. Because the host nonce and IV are now known, the whole captured session can be
   **decrypted and the crypto reverse-engineered entirely offline**, iterating against
   a static capture with **zero risk to the chip**.

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full write-up.

---

## What's in this repo

| Path | What |
|---|---|
| `probe.c` | libusb tool: runs the handshake, pulls the chip's P-256/RSA public key, computes an ECDH shared secret, **and always closes the session** (see the fragility note). |
| `session_test.py` | End-to-end secure-session **proof on the real chip**: handshake → RSA `0x24` key transport → send an encrypted command → decrypt the chip's encrypted reply. One careful run; always closes the session. |
| `decrypt.py` | Offline decryptor/validator for a captured secure session. Reproduces the key derivation, AES-128-CBC and HMAC-SHA1 exactly. |
| `driver/bcm5880cv2.c` | Native **`libfprint` TOD driver**: async `FpDevice` subclass driving the chip over libusb via `FpiSsm` state machines. Runs the handshake and establishes the secure session in `fprintd`; enroll/verify in progress. |
| `driver/cv2_session.[ch]` | Reusable, **pure (no-USB) session crypto** shared by the driver: key derivation, encrypted frame build/parse, and the RSA `0x24` key-transport block. Validated byte-for-byte. |
| `driver/ARCHITECTURE.md` | Design of the driver: vfuncs, the handshake/enroll/verify state machines, and how it reuses the session crypto. |
| `captures/win-session-detnonce.pcapng` | Windows CV2 secure session captured with a **deterministic** host RNG — the reference used to crack the crypto. |
| `captures/linux-enroll-plaintext.pcapng` | The CV3-driver enrollment on Linux, sent in plaintext (`2300/2400/0200/6600/6e`) — the enroll/commit commands that just need wrapping in the session crypto. |
| `chip-rsa-modulus.hex` | The example chip's RSA-2048 public modulus (device-public, for reference). |
| `docs/PROTOCOL.md` | Full protocol + crypto spec and the RE methodology. |

No Dell/Broadcom binaries or decompiled proprietary code are included.

## Setup on Fedora

Interface 0 is shared with the chip's contactless/NFC CCID. If you also run the NFC
side ([`bcm5880-nfc`](../bcm5880-nfc)), stop its daemon before using the fingerprint
path, and vice-versa.

```bash
# 1. Build dependencies
sudo dnf install git make gcc libusb1-devel openssl-devel python3-pycryptodomex python3-pyusb

# 2. Build the libusb probe
make

# 3. Free interface 0 (the NFC stack / fprintd may hold it)
sudo systemctl stop pcscd pcscd.socket fprintd

# 4. Talk to the chip: handshake, pull its public key, ECDH
sudo ./probe

# 5. Prove the full secure session end-to-end on your chip
sudo python3 session_test.py        # expect: "*** SESSION WORKS ON THE CHIP ***"
```

If `session_test.py` prints the success line and `lsusb -d 0a5c:5834` still shows the
device afterwards, your chip speaks the exact protocol in this repo.

> **Recovery:** if a bad command ever drops the chip to `0a5c:5831` (bootloader),
> fully **power the laptop off and cold-boot** (a warm reboot is not enough) — the
> firmware is re-uploaded by the BIOS on a cold start.

### fprintd / `libfprint` integration — work in progress

The goal is a `libfprint`-compatible driver so `fprintd-enroll` / `fprintd-verify`
just work. See [`docs/DRIVER.md`](docs/DRIVER.md) for the design (a secure-session
layer in front of the stock ControlVault driver) and the current state. Install
instructions will land here once the driver enrolls and verifies.

## Build & run the probe (minimal)

```bash
make
sudo systemctl stop pcscd pcscd.socket fprintd
sudo ./probe
```

## Remaining work (contributions welcome)

1. **Make verify match.** Enroll + encrypted commit (`0x6e` → `0x8d`) already store a
   template on the chip, and the identify flow (`0x73`) is byte-identical to the CV3
   driver's — yet the chip reports no match. The remaining unknown is isolated to how
   a committed template becomes matchable; the plan is to decrypt a real
   enroll+verify reference (deterministic-nonce capture) and diff it against ours.
2. Polish enroll completion (the chip signals COMPLETE with `0x59`, or `0x8c`
   "enrollment full" after ~4 samples on this firmware) and surface progress/retries
   cleanly through `fprintd`.
3. Package the driver (install path, udev/polkit notes) once verify matches.

⚠️ **Chip fragility:** always open exactly one session and close it (`0x04` + handle);
never hammer the device with speculative commands. A wrong secure-session command can
drop the chip to its bootloader until a full power-off.

## License

GPLv3 — see [LICENSE](LICENSE). Protocol documentation is original work describing
observed behaviour for interoperability.
