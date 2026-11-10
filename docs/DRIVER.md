# libfprint-compatible driver — design

Goal: make `fprintd-enroll` / `fprintd-verify` work on ControlVault 2 (`0a5c:5834`).

## Why a secure-session *shim* rather than a from-scratch driver

Canonical already ships a `libfprint` TOD driver for ControlVault **3**
(`libfprint-2-tod-1-broadcom.so`). With a few byte patches it binds to CV2 and runs
the **entire enrollment state machine** correctly — it opens the device, drives the
sensor capture, and walks the enroll cycle (`3900 / 0200 / 0400 / 6600 / 6e …`). The
*only* thing it cannot do is the ControlVault 2 **secure session**: it has no session
crypto, so it sends every command in plaintext and the CV2 chip rejects the
template-storing `commit` (`0x6e`).

We proved (see `../session_test.py`) that the secure session itself is fully
reproducible on the real chip. So the smallest correct driver is a **thin
secure-session layer in front of the stock driver**, implemented as an `LD_PRELOAD`
shim that intercepts the driver's libusb traffic:

```
 fprintd ── libfprint ── CV3 driver ──[libusb bulk/interrupt]──┐
                                                               │  LD_PRELOAD shim
                                                               ▼
   establishes the CV2 secure session once, then for each command:
     OUT (plaintext from the driver)  ->  set session handle, AES-128-CBC encrypt,
                                          append HMAC-SHA1 + counter, flags |= encrypted
     IN  (encrypted from the chip)    ->  decrypt, present plaintext to the driver
```

The shim reuses *all* of the driver's enrollment, capture and fprintd integration and
adds only the ~200 lines of crypto we already validated.

## Interception points (`dlsym(RTLD_NEXT, …)`)

- `libusb_bulk_transfer` — OUT endpoint `0x01` (commands), IN endpoint `0x81`
  (responses).
- `libusb_interrupt_transfer` — IN endpoint `0x85` (8-byte `[status][len]`).

On the first command the shim lazily runs the handshake itself (`0x39 / 0x82 /
0x23 / 0x24`) using the *real* libusb functions, derives `ENC`/`HMAC` keys and the
session handle, then:

1. **OUT on `0x01`:** if the command is a post-handshake "session" command, rewrite
   its header (session handle, `flags |= 1`), build the encrypted frame (IV, AES-CBC,
   HMAC-SHA1 over header+body+counter, per-session counter++), and forward it. The
   handshake commands the driver itself emits (`0x39`) pass through untouched.
2. The shim performs the full round trip (write + read status + read body) against the
   chip, **decrypts** the reply, and buffers the plaintext.
3. **interrupt `0x85` / bulk IN `0x81`:** serve the buffered plaintext status/body so
   the stock driver sees exactly what it would have seen on a CV3 chip.

## Crypto (validated — see `../docs/PROTOCOL.md`)

```
ENC  = SHA1(chip_nonce ‖ host_nonce)[0:16]         AES-128-CBC, IV in clear at hdr+0x18
HMAC = HMAC-SHA1(SHA1("CV secure session blob\0"),
                 header[0:0x2c] ‖ body ‖ counter_u32)   (20 B, encrypted with the body)
frame body(plaintext) = body ‖ HMAC ‖ counter_u32 ‖ align , PKCS7-padded
counter = per-session, starts 0, +1 per command
0x24 host_nonce transport = reverse( RSA-2048-PKCS1( chip_modulus, host_nonce ) )
```

## Status / TODO

- [x] Secure session proven on hardware (`session_test.py`).
- [ ] `cv2-session-shim.c`: interception + session + wrap/unwrap + response buffering.
- [ ] Decide exactly which command ids must be wrapped once a session exists
      (CV3 sends `3900/0200/0400/6600/6800/2f00/6c00/6e00`; `3900` is pre-session).
- [ ] Verify an end-to-end `fprintd-enroll` stores a template and `fprintd-verify`
      matches (match-on-chip).

## Development discipline (chip safety)

Develop the frame builder **offline** against `../captures/` (byte-exact) before
sending anything. Keep exactly one session open and always close it. A malformed
secure-session command drops the chip to its bootloader until a cold power-off.

## Integration findings (live testing)

- The stock CV3 driver imports **synchronous** `libusb_bulk_transfer` /
  `libusb_interrupt_transfer`, so an `LD_PRELOAD` shim CAN intercept its command
  traffic (confirmed: the shim's interposed `libusb_bulk_transfer` fires on the
  driver's `0x39`). libfprint *core* uses libgusb (async `libusb_submit_transfer`)
  for enumeration, but the driver's per-command I/O is sync and interceptable.
- **To test via fprintd** the shim must be injected into the fprintd daemon
  (`Environment=LD_PRELOAD=…/cv2-session-shim.so` systemd drop-in, or run the daemon
  manually so it owns the `net.reactivated.Fprint` bus name). Plain `fprintd-enroll`
  otherwise D-Bus-activates an un-shimmed daemon.
- The crypto is byte-exact (a standalone C test rebuilds a captured frame exactly);
  the remaining work is debugging the in-driver `establish()` + response buffering
  against a live enroll (needs a finger swipe).

## ⚠️ Shim architectural blocker (resolved understanding)

The `LD_PRELOAD` shim **cannot** do blocking synchronous libusb I/O from inside a
driver callback: libfprint runs libusb's event handling on a **single GMainLoop
thread**, and the driver's command callbacks run on that same thread. The shim's
`establish()` does synchronous `libusb_interrupt_transfer` (EP 0x85) which blocks
that thread, so libusb events are never pumped and the chip's reply never completes
→ `LIBUSB_ERROR_TIMEOUT`. (The identical code works standalone — `session_test.py` —
precisely because there is no competing async event loop.)

**Consequences / the real path:**
- A sync-I/O interposition shim is the wrong shape. Either (a) write a **from-scratch
  libfprint driver** that performs the session using libfprint's async USB API
  (`fpi_usb_transfer*`) — the proper, upstreamable solution — or (b) a shim that does
  NO independent I/O: establish the session out-of-band, then only encrypt/decrypt the
  driver's own in-place transfers. (a) is cleaner.
- The session crypto and the on-chip protocol are fully proven (`session_test.py`),
  so a from-scratch driver is "only" the libfprint enroll/verify state machine +
  wiring the validated session underneath.
