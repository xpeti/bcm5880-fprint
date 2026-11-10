/* cv2_session.c — ControlVault 2 secure-session crypto (pure, no USB).
 * Validated byte-for-byte against real captures. SPDX: GPL-3.0-or-later */
#include "cv2_session.h"
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

static void put32(uint8_t *p, uint32_t v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static uint32_t le32(const uint8_t *p){ return p[0]|p[1]<<8|p[2]<<16|((uint32_t)p[3]<<24); }

void cv2_session_init(cv2_session *s, const uint8_t chip_nonce[20],
                      const uint8_t host_nonce[20], const uint8_t handle[4])
{
    uint8_t buf[40], d[20];
    memcpy(buf, chip_nonce, 20);
    memcpy(buf + 20, host_nonce, 20);
    SHA1(buf, 40, d);
    memcpy(s->enc_key, d, 16);
    SHA1((const uint8_t *)"CV secure session blob\0", 23, s->hmac_key);
    memcpy(s->handle, handle, 4);
    s->counter = 0;
}

int cv2_build_rsa_block(const uint8_t modulus[256], const uint8_t host_nonce[20],
                        uint8_t out[256])
{
    BIGNUM *n = BN_bin2bn(modulus, 256, NULL);
    BIGNUM *e = NULL; BN_dec2bn(&e, "65537");
    RSA *rsa = RSA_new();
    RSA_set0_key(rsa, n, e, NULL);
    int r = RSA_public_encrypt(20, host_nonce, out, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (r != 256) return -1;
    for (int i = 0; i < 128; i++) { uint8_t t = out[i]; out[i] = out[255-i]; out[255-i] = t; } /* CryptoAPI */
    return 0;
}

int cv2_wrap(cv2_session *s, uint16_t cmdid, uint16_t driver_flags,
             const uint8_t *body, uint32_t bodylen, uint8_t *out, size_t outcap)
{
    uint8_t iv[16]; RAND_bytes(iv, 16);
    int blob = bodylen + 20 + 8;
    int pad = 16 - (blob % 16);
    int ctlen = blob + pad;
    if (outcap < (size_t)(0x2c + ctlen)) return -1;
    /* CV2 encrypted flags: command's low byte | bit0, high byte forced to 0x02 */
    unsigned eflags = ((driver_flags & 0xff) | 1) | 0x0200;
    uint8_t *hdr = out;
    memset(hdr, 0, 0x2c);
    hdr[0] = 1; put32(hdr + 4, 0x2c + ctlen);
    hdr[8] = cmdid; hdr[9] = cmdid >> 8;
    hdr[0x0a] = eflags; hdr[0x0b] = eflags >> 8; hdr[0x0c] = 2;
    memcpy(hdr + 0x10, s->handle, 4);
    memcpy(hdr + 0x18, iv, 16);
    put32(hdr + 0x28, bodylen);
    /* HMAC-SHA1( hmac_key, header[0:0x2c] || body || counter_u32 ) */
    uint8_t macin[0x2c + 4096 + 4]; int mi = 0;
    memcpy(macin, hdr, 0x2c); mi = 0x2c;
    memcpy(macin + mi, body, bodylen); mi += bodylen;
    put32(macin + mi, s->counter); mi += 4;
    uint8_t mac[20]; unsigned int ml = 20;
    HMAC(EVP_sha1(), s->hmac_key, 20, macin, mi, mac, &ml);
    /* plaintext blob = body || mac || 8 zero bytes, PKCS7 to ctlen */
    uint8_t pt[4096]; int p = 0;
    memcpy(pt, body, bodylen); p = bodylen;
    memcpy(pt + p, mac, 20); p += 20;
    memset(pt + p, 0, 8); p += 8;
    for (int i = 0; i < pad; i++) pt[p++] = pad;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int ol = 0, fl = 0;
    EVP_EncryptInit_ex(c, EVP_aes_128_cbc(), NULL, s->enc_key, iv);
    EVP_CIPHER_CTX_set_padding(c, 0);
    EVP_EncryptUpdate(c, out + 0x2c, &ol, pt, ctlen);
    EVP_EncryptFinal_ex(c, out + 0x2c + ol, &fl);
    EVP_CIPHER_CTX_free(c);
    s->counter++;
    return 0x2c + ctlen;
}

int cv2_unwrap(const cv2_session *s, const uint8_t *frame, int framelen,
               uint8_t *body_out, size_t bodycap)
{
    if (framelen < 0x2c) return -1;
    const uint8_t *iv = frame + 0x18;
    uint32_t bodylen = le32(frame + 0x28);
    if (bodylen > bodycap) return -1;
    uint8_t pt[4096];
    EVP_CIPHER_CTX *d = EVP_CIPHER_CTX_new(); int dl = 0, dfl = 0;
    EVP_DecryptInit_ex(d, EVP_aes_128_cbc(), NULL, s->enc_key, iv);
    EVP_CIPHER_CTX_set_padding(d, 0);
    EVP_DecryptUpdate(d, pt, &dl, frame + 0x2c, framelen - 0x2c);
    EVP_DecryptFinal_ex(d, pt + dl, &dfl);
    EVP_CIPHER_CTX_free(d);
    memcpy(body_out, pt, bodylen);      /* body; [body][HMAC20][counter] follow */
    return bodylen;
}
