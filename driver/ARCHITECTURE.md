# From-scratch libfprint driver for ControlVault 2 — architecture

Goal: a `libfprint` TOD driver so `fprintd-enroll`/`fprintd-verify` work natively on
`0a5c:5834`, wrapping the (proven) CV2 secure session under a proper async driver.

## Why not the LD_PRELOAD shim
The shim hit a hard wall: libfprint runs libusb event handling on a single
GMainLoop thread, so blocking **synchronous** libusb I/O from inside a driver
callback deadlocks the loop (`LIBUSB_ERROR_TIMEOUT`). See `../docs/DRIVER.md`.
A real driver must use libfprint's **async** USB API, which integrates with the loop.

## Shape (modelled on the in-tree match-on-chip drivers: `elanmoc`, `synaptics`)
- A `FpDevice` subclass via `G_DEFINE_TYPE (FpiDeviceBcm5880Cv2, …, FP_TYPE_DEVICE)`.
- Export `fpi_tod_shared_driver_get_type()` → the GType (TOD entry point).
- `class_init` sets: `id_table = {{ .vid=0x0a5c, .pid=0x5834 }}`, `type=FP_DEVICE_TYPE_USB`,
  `scan_type=FP_SCAN_TYPE_PRESS`, `nr_enroll_stages=N`, and the vfuncs:
  `open, close, enroll, verify, identify, delete, list`.
- USB via **async** `fpi_usb_transfer_new` / `fpi_usb_transfer_fill_bulk` /
  `fpi_usb_transfer_submit` driven by `FpiSsm` state machines (exactly the elanmoc
  `fp_cmd_run_state` pattern). Interface 0, EP OUT `0x01` / IN `0x81` / interrupt `0x85`.
- Build: `shared_module(..., dependencies: dependency('libfprint-2-tod-1'))`, install
  to the `tod_driversdir`, plus a udev rule binding `0a5c:5834`.

## Session integration — reuse `cv2_session.[ch]` (done, validated)
`cv2_session.c` is pure crypto (no USB), validated byte-for-byte:
- `cv2_session_init(chip_nonce, host_nonce, handle)` → derives AES-128 ENC key and
  the fixed HMAC-SHA1 key.
- `cv2_build_rsa_block(modulus, host_nonce)` → the `0x24` RSA key-transport block.
- `cv2_wrap(cmdid, flags, body)` / `cv2_unwrap(frame)` → encrypt/decrypt command frames.
The driver only does the USB (async) and calls these between transfers.

## State machines to implement
1. **open**: USB reset + claim iface 0 → handshake SSM:
   `0x39` → `0x82` → `0x23`(selector 0) [parse handle + chip_nonce + modulus] →
   build `0x24` (`cv2_build_rsa_block`, fresh random host_nonce) → `cv2_session_init`.
   Then `fpi_device_open_complete`.
2. **enroll**: `nr_enroll_stages` cycles, each: drive the chip capture
   (`2300/2400/0200/6600` — bodies known from `../captures/linux-enroll-plaintext.pcapng`,
   now sent via `cv2_wrap`), call `fpi_device_enroll_progress` per stage; finally the
   encrypted **commit `0x6e`**; store the print (`fpi_print_set_device_stored`) and
   `fpi_device_enroll_complete`.
3. **verify/identify**: capture → encrypted `identify` → `fpi_device_verify_report`
   / `fpi_device_identify_report` (match-on-chip).
4. **delete/list**: manage on-chip templates.

## Chip-safety discipline (unchanged)
Every produced frame can be checked offline against `../captures/` before it is sent.
One session, always closed (`0x04`). A malformed secure-session command drops the
chip to its bootloader until a cold power-off.

## Status
- [x] `cv2_session.[ch]` — reusable, validated session crypto (round-trip + byte-exact).
- [x] Exact TOD SDK obtained (libfprint-v1.94.10+tod1 source); driver shape mapped
      from `elanmoc`/example TOD driver.
- [ ] GObject skeleton + handshake SSM in `open` (first milestone — establishes the
      session natively, no finger needed to verify).
- [ ] enroll / verify / identify SSMs.
- [ ] meson build against `libfprint-2-tod-1`, install, udev bind, end-to-end test.
