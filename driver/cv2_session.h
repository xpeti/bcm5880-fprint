/* cv2_session.h — ControlVault 2 secure-session crypto (pure, no USB).
 *
 * Reusable building blocks for a libfprint driver: key derivation, encrypted
 * command frame build/parse, and the RSA-2048 0x24 key-transport block. The
 * driver supplies USB I/O (async fpi_usb_transfer); these functions are pure.
 *
 * All of this is validated byte-for-byte against real captures (see
 * ../decrypt.py, ../session_test.py, ../docs/PROTOCOL.md). SPDX: GPL-3.0-or-later
 */
#ifndef CV2_SESSION_H
#define CV2_SESSION_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t  enc_key[16];     /* AES-128 */
    uint8_t  hmac_key[20];    /* HMAC-SHA1 key = SHA1("CV secure session blob\0") */
    uint8_t  handle[4];       /* session handle from the 0x23 response */
    uint32_t counter;         /* per-session command index, starts 0 */
} cv2_session;

/* Derive ENC key from the 20-byte chip nonce (tail of the 0x23 response param)
 * and the 20-byte host nonce; also sets the fixed HMAC key and the counter. */
void cv2_session_init(cv2_session *s, const uint8_t chip_nonce[20],
                      const uint8_t host_nonce[20], const uint8_t handle[4]);

/* Build the RSA-2048 PKCS#1 0x24 key-transport block (256 bytes, CryptoAPI byte
 * order) from the chip modulus (big-endian, 256 B) and host nonce (20 B). */
int  cv2_build_rsa_block(const uint8_t modulus[256], const uint8_t host_nonce[20],
                         uint8_t out[256]);

/* Wrap a plaintext CV command (header+body, 'in'/'inlen') into an encrypted frame.
 * cmdid/flags come from the plaintext command; uses a fresh random IV and s->counter
 * (incremented). Returns frame length written to 'out' (caller buffer >= inlen+64). */
int  cv2_wrap(cv2_session *s, uint16_t cmdid, uint16_t driver_flags,
              const uint8_t *body, uint32_t bodylen, uint8_t *out, size_t outcap);

/* Decrypt an encrypted response frame in-place view: returns the plaintext body
 * length and copies the body into 'body_out'. */
int  cv2_unwrap(const cv2_session *s, const uint8_t *frame, int framelen,
                uint8_t *body_out, size_t bodycap);

#endif
