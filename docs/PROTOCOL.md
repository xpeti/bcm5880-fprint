# ControlVault 2 (BCM5880) — protocol & secure-session specification

This document describes, for interoperability, how the Dell ControlVault 2 /
Broadcom BCM5880 fingerprint chip (`0a5c:5834`, interface 0) talks to its host —
in particular the **Secure Session** used to store and match fingerprint templates.
It is written from original observation (USB captures + behaviour) and contains no
proprietary source.

## 1. Transport

Interface 0 ("USH"), bulk OUT `0x01`, bulk IN `0x81`, interrupt IN `0x85`.

A transaction is:
1. Host writes the command (44-byte header + params) to bulk OUT `0x01`.
2. Host reads 8 bytes from interrupt IN `0x85`: `[status u32 LE][resp_len u32 LE]`.
   `status == 0` means OK.
3. Host reads `resp_len` bytes from bulk IN `0x81`.

## 2. Command header (44 bytes, `0x2c`)

| off | size | field |
|----:|-----:|-------|
| 0x00 | 4 | marker = `01 00 00 00` |
| 0x04 | 4 | total length (whole frame) |
| 0x08 | 2 | command id |
| 0x0a | 2 | flags — **bit 0 = payload encrypted** (secure session) |
| 0x0c | 4 | lib version = 2 |
| 0x10 | 4 | session handle (0 before the handshake; assigned by `0x23`) |
| 0x14 | 4 | 0 |
| 0x18 | 16 | **AES-CBC IV** (only in encrypted frames; sent in clear) |
| 0x28 | 4 | parameter length |
| 0x2c | … | parameters |

In *plaintext* frames bytes `0x18..0x27` are zero; in *encrypted* frames they carry
the IV.

### Command ids seen
`0x39` get chip info · `0x82` session setup · `0x23` get-public-key / get-context
(assigns the handle) · `0x24` host key transport · `0x04` close session (+handle) ·
`0x02`/`0x66`/`0x6c`/`0x2f`/`0x68`/`0x8a` enrollment-cycle commands ·
**`0x6e` commit enrollment** · `0x73` feature-set.

## 3. Secure-session handshake

```
0x39  -> 848-byte ASCII chip-info blob (USH_CHIPID, USH_CV_VER=01000235, firmware
         versions, USH_USBD_PID=00005834, ...). NOT the public key.
0x82  -> small setup/ack.
0x23  GetCVPublicKey
      request param (24 B): [20 B host field][u32 selector]
          selector = 0 -> RSA-2048 key-transport path (what Dell's Windows driver uses)
          selector = 1 -> ECDH P-256 path (also supported by the chip)
      response param:
          RSA path: 256-byte RSA modulus (exponent 0x10001) + info + trailing 20 B
                    *** the modulus is LITTLE-endian (CryptoAPI blob order) ***
          ECDH path: 64-byte P-256 public point (X‖Y) + info
          ...and the chip assigns a session handle (returned at header +0x10).
          The last 20 bytes of the response param are the chip_nonce.
0x24  key transport
      RSA path:  param = RSA-2048(chip_pubkey, host_nonce[20])   (PKCS#1 v1.5, 256 B)
                 build as: c = PKCS1(nonce)^e mod n, where n = int(modulus, LITTLE-endian),
                 then reverse the 256-byte ciphertext (CryptoAPI little-endian output).
                 Reading the modulus big-endian yields a wrong key: the chip decrypts a
                 different host nonce, the derived session key mismatches, and the first
                 encrypted command comes back undecryptable (observed: +0x14=15, empty body).
      ECDH path: param = [20 B nonce][64 B host P-256 public point]
0x04  close session: param = [u32 len=4][session handle]   (ALWAYS send this)
```

The host authenticates nothing to the chip — the host key is ephemeral (ECDH) or a
fresh random nonce (RSA). Certificate verification of the chip is optional for an
owner of the device.

## 4. Session key derivation (validated)

```
host_nonce  : 20 B, host RNG
chip_nonce  : last 20 B of the 0x23 response parameter

ENC key  = SHA1( chip_nonce ‖ host_nonce )[0:16]          # AES-128
HMAC key = SHA1( "CV secure session blob\0" )             # 23 bytes incl. NUL, fixed
         = dbac7907 f3576329 2a6b4ca4 134d1ec8 5ceda31b
```

## 5. Encrypted command frame (validated)

Scheme is **MAC-then-encrypt** with AES-128-CBC:

```
plaintext_blob = body ‖ HMAC[20] ‖ counter_u32 ‖ 4-byte align
ciphertext     = AES-128-CBC( ENC, IV, PKCS7(plaintext_blob) )

HMAC = HMAC-SHA1( HMAC key,
                  frame_header[0x00:0x2c]       # includes total length and the IV
                  ‖ body
                  ‖ counter_u32 )

frame = header(0x2c, flags bit0 = 1, IV at 0x18, inner_len = len(body) at 0x28)
        ‖ ciphertext
```

* `IV` is 16 bytes from the host RNG, placed at header `+0x18` and left in clear.
* `counter` is a per-session command index, starting at 0 and incremented by 1 for
  each command. It is **not** transmitted in clear — it is part of both the HMAC input
  and the encrypted blob.
* Response frames are identical but the chip supplies its own IV.

The command `body` is itself a small structure (a CV "parameter list" of little-endian
`u32`s, e.g. a 0x66 body embeds the session handle). Those bodies are visible in
plaintext in the Linux CV3-driver capture, so implementing CV2 is a matter of wrapping
them in the frame above.

## 6. Reverse-engineering method (offline, chip-safe)

The chip firmware watchdog-resets into an SBI bootloader (`0a5c:5831`) on any
malformed secure-session command, recoverable only by a full power-off. To avoid
touching the chip during development:

1. In a throwaway disk overlay, patch the host crypto library's RNG to emit a
   deterministic pattern, so `host_nonce` and all IVs are known values.
2. Boot that image with the chip attached and capture USB with `usbmon`. The vendor
   service opens a secure session at start-up on its own (no biometric login needed).
3. With the nonce/IV known, derive the keys and **decrypt the whole capture offline**;
   iterate crypto hypotheses against the static capture until every HMAC verifies —
   never risking the chip. `decrypt.py` is that validator.

## 7. Implementation notes

* Only one session at a time; always `0x04`-close it. Leaking sessions exhausts the
  chip's slots and triggers the watchdog reset.
* The enroll flow (from the plaintext Linux capture) is cycles of
  `2300 → 2400 → 0200 → 6600/7300`, followed by **commit `0x6e`**. On CV2 every one of
  those must travel inside the secure-session frame of §5; the CV3 driver sends them
  bare, which is why its commit is rejected.
* Verify/identify is match-on-chip (the template never leaves the secure element),
  which `libfprint` supports directly.
