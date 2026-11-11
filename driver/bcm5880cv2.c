/*
 * libfprint TOD driver for Dell ControlVault 2 / Broadcom BCM5880 (0a5c:5834).
 * Wraps the (reverse-engineered, validated) CV2 secure session under a proper
 * async libfprint driver.  SPDX: GPL-3.0-or-later
 *
 * Status: open/handshake establishes the secure session; enroll/verify are the
 * next milestone.  See ARCHITECTURE.md.
 */
#define FP_COMPONENT "bcm5880cv2"

#include "drivers_api.h"
#include "cv2_session.h"

#define EP_OUT 0x01
#define EP_IN  0x81
#define EP_ST  0x85
#define CV_TIMEOUT 3000

struct _FpiDeviceBcm5880Cv2
{
  FpDevice    parent;
  cv2_session sess;
  FpiSsm     *task_ssm;        /* current operation SSM (open/enroll/verify) */
  /* per-command scratch */
  guint8     *cmd;            /* command to send (owned) */
  gsize       cmd_len;
  gboolean    enc;           /* current command/response is secure-session wrapped */
  gboolean    drain_extra;   /* read one extra async status (0x85 event) after the body */
  guint       status_skips;  /* async finger events (st=3) skipped while awaiting a cmd status */
  guint8      status[8];      /* [status u32][len u32] from EP 0x85 */
  guint8     *resp;           /* response body buffer (plaintext after unwrap) */
  gsize       resp_len;
  guint32     result_code;    /* response header +0x14 field: verify match result (0=match, 0x89=no finger, 0x85=no match) */
  /* enroll bookkeeping */
  guint8      obj_handle[4];  /* object-session handle from the 0x02 response body */
  guint       enroll_stage;   /* accepted enrollment samples (0x6c +0x14==0) */
  guint       submits;        /* total 0x6c submits (loop cap) */
  guint       poll_count;     /* 0x66 polls waiting for the current finger press */
  guint8      digest[20];     /* last 0x66 image digest */
  guint8      sample[4][80];   /* accepted-sample data from 0x6c responses, for create_template */
  gsize       sample_len[4];
  guint       nsamples;
  FpPrint    *enroll_print;
  gboolean    verify_matched; /* verify verdict latched before closing the object */
  guint8      verify_hash[20]; /* SHA1(username) template id passed to the 0x73 identify */
};
G_DECLARE_FINAL_TYPE (FpiDeviceBcm5880Cv2, fpi_device_bcm5880cv2, FPI, DEVICE_BCM5880CV2, FpDevice)
G_DEFINE_TYPE (FpiDeviceBcm5880Cv2, fpi_device_bcm5880cv2, FP_TYPE_DEVICE)

G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_bcm5880cv2_get_type ();
}

static const FpIdEntry id_table[] = {
  { .vid = 0x0a5c, .pid = 0x5834 },
  { .vid = 0,      .pid = 0 },
};

/* ---- async CV command: OUT(0x01) -> status(0x85) -> body(0x81) ----
 * Implemented as a tiny 3-state SSM chained via fpi_usb_transfer. The result
 * (status + body) is left in the device struct for the caller's continuation. */
enum { CV_SEND, CV_STATUS, CV_BODY, CV_DRAIN, CV_NUM };

/* completion for the optional trailing async-event read: ignore timeouts/errors
 * (the event is best-effort), then finish the command SSM. */
static void
cv_drain_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      fp_warn ("cv drain: no/failed async event (%s) — ok", error->message);
      g_error_free (error);
    }
  else
    {
      FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
      guint32 st = GUINT32_FROM_LE (*(guint32 *) transfer->buffer);
      fp_warn ("cv drain: async event st=0x%x", st);
      (void) self;
    }
  fpi_ssm_mark_completed (transfer->ssm);
}

/* completion for draining an async event's body (st=3, len>0): discard it and re-read
 * the real command status. */
static void
cv_evt_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  if (error) g_error_free (error);
  fpi_ssm_jump_to_state (transfer->ssm, CV_STATUS);
}

static void
cv_ssm_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  FpiUsbTransfer *t;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CV_SEND:
      t = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk_full (t, EP_OUT, self->cmd, self->cmd_len, NULL);
      t->ssm = ssm;
      fpi_usb_transfer_submit (t, CV_TIMEOUT, NULL, fpi_ssm_usb_transfer_cb, NULL);
      break;
    case CV_STATUS:
      t = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_interrupt_full (t, EP_ST, self->status, sizeof self->status, NULL);
      t->ssm = ssm;
      fpi_usb_transfer_submit (t, CV_TIMEOUT, NULL, fpi_ssm_usb_transfer_cb, NULL);
      break;
    case CV_BODY:
      {
        guint32 st, len;
        memcpy (&st,  self->status + 0, 4); st  = GUINT32_FROM_LE (st);
        memcpy (&len, self->status + 4, 4); len = GUINT32_FROM_LE (len);
        fp_dbg ("cv status=0x%x len=%u enc=%d", st, len, self->enc);
        /* 0x85 carries both command results AND async finger events (st=3; len=0, or len>0
         * with a small payload on EP_IN). A late event can arrive on this channel just
         * before a command's real status; drain it and re-read rather than erroring. */
        if (st == 3 && self->status_skips++ < 64)
          {
            if (len == 0) { fpi_ssm_jump_to_state (ssm, CV_STATUS); return; }
            t = fpi_usb_transfer_new (dev);        /* discard the event body, then re-status */
            fpi_usb_transfer_fill_bulk (t, EP_IN, len);
            t->ssm = ssm;
            fpi_usb_transfer_submit (t, CV_TIMEOUT, NULL, cv_evt_cb, NULL);
            return;
          }
        if (st != 0)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "CV status 0x%x", st));
            return;
          }
        g_clear_pointer (&self->resp, g_free);
        self->resp = g_malloc0 (len ? len : 1);
        self->resp_len = len;
        if (len == 0) { fpi_ssm_jump_to_state (ssm, CV_DRAIN); return; }
        t = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_bulk_full (t, EP_IN, self->resp, len, NULL);
        t->ssm = ssm;
        fpi_usb_transfer_submit (t, CV_TIMEOUT, NULL, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;
    case CV_DRAIN:
      /* unwrap the (now complete) encrypted response body in place */
      if (self->enc && self->resp_len >= 0x2c)
        {
          /* the frame header is plaintext; +0x14 carries the verify match result */
          self->result_code = GUINT32_FROM_LE (*(guint32 *) (self->resp + 0x14));
          guint8 body[4096];
          int bl = cv2_unwrap (&self->sess, self->resp, self->resp_len, body, sizeof body);
          fp_dbg ("cv unwrap -> %d body bytes", bl);
          g_clear_pointer (&self->resp, g_free);
          self->resp = g_memdup2 (body, bl > 0 ? bl : 1);
          self->resp_len = bl > 0 ? bl : 0;
        }
      /* some commands (0x66 capture) emit a trailing async status event; drain it.
       * It may or may not arrive, so a short timeout is non-fatal (see cv_drain_cb). */
      if (self->drain_extra)
        {
          self->drain_extra = FALSE;
          t = fpi_usb_transfer_new (dev);
          fpi_usb_transfer_fill_interrupt (t, EP_ST, 8);
          t->ssm = ssm;
          /* doubles as the finger-present wait during enroll polling */
          fpi_usb_transfer_submit (t, 1500, NULL, cv_drain_cb, NULL);
          return;
        }
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

/* run one CV command (raw bytes already framed); on completion, jump the parent
 * SSM to its next state. */
static void
cv_cmd_cb (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  if (error) { fp_warn ("cv_cmd failed: %s", error->message); fpi_ssm_mark_failed (self->task_ssm, error); return; }
  fpi_ssm_next_state (self->task_ssm);
}

static void
cv_cmd (FpDevice *dev, guint8 *cmd, gsize len)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  g_clear_pointer (&self->cmd, g_free);
  self->cmd = cmd; self->cmd_len = len; self->status_skips = 0;
  FpiSsm *s = fpi_ssm_new (dev, cv_ssm_run, CV_NUM);
  fpi_ssm_start (s, cv_cmd_cb);
}

/* ---- TLV body helpers (fields are [u32 tag=0][u32 len][len bytes]) ---- */
static guint8 *
tlv_put (guint8 *p, const void *val, guint32 len)
{
  guint32 t = 0;
  memcpy (p, &t, 4);                 p += 4;
  guint32 l = GUINT32_TO_LE (len);   memcpy (p, &l, 4); p += 4;
  if (len) { memcpy (p, val, len);   p += len; }
  return p;
}

/* Send a plaintext CV command (handshake-era framing): 0x2c header + body. */
static void
cv_plain (FpDevice *dev, guint16 cmd, guint16 flags, const guint8 handle[4],
          const guint8 *body, guint32 bodylen, gboolean drain_extra)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  gsize n = 0x2c + bodylen;
  guint8 *c = g_malloc0 (n);
  c[0] = 1; { guint32 v = GUINT32_TO_LE (n); memcpy (c + 4, &v, 4); }
  c[8] = cmd; c[9] = cmd >> 8; c[0x0a] = flags; c[0x0b] = flags >> 8; c[0x0c] = 2;
  if (handle) memcpy (c + 0x10, handle, 4);
  { guint32 v = GUINT32_TO_LE (bodylen); memcpy (c + 0x28, &v, 4); }
  if (bodylen) memcpy (c + 0x2c, body, bodylen);
  self->enc = FALSE; self->drain_extra = drain_extra;
  cv_cmd (dev, c, n);
}

/* Send an encrypted (secure-session) CV command: cv2_wrap handles header+handle. */
static void
cv_enc (FpDevice *dev, guint16 cmd, guint16 cv3_flags,
        const guint8 *body, guint32 bodylen, gboolean drain_extra)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  guint8 buf[4096];
  int n = cv2_wrap (&self->sess, cmd, cv3_flags, body, bodylen, buf, sizeof buf);
  if (n < 0) { fpi_ssm_mark_failed (self->task_ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL)); return; }
  self->enc = TRUE; self->drain_extra = drain_extra;
  cv_cmd (dev, g_memdup2 (buf, n), n);
}

/* ---- open: handshake 0x39 -> 0x82 -> 0x23 -> 0x24 -> derive session ---- */
static const guint8 CMD39[] = {1,0,0,0,0x38,0,0,0,0x39,0,0x40,4,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x0c,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0};
static const guint8 CMD82[] = {1,0,0,0,0x38,0,0,0,0x82,0,0x40,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x0c,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0};

enum { OPEN_39, OPEN_82, OPEN_23, OPEN_24, OPEN_DONE, OPEN_NUM };

static void
open_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  fp_warn ("open SSM state %d", fpi_ssm_get_cur_state (ssm));
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_39:
      /* the handshake is always plaintext; clear enc/drain left over from a prior op
       * (e.g. a verify re-handshake after an enroll) so responses aren't mis-unwrapped */
      self->enc = FALSE; self->drain_extra = FALSE;
      cv_cmd (dev, g_memdup2 (CMD39, sizeof CMD39), sizeof CMD39);
      break;
    case OPEN_82:
      cv_cmd (dev, g_memdup2 (CMD82, sizeof CMD82), sizeof CMD82);
      break;
    case OPEN_23:
      {
        guint8 *c = g_malloc0 (0x44);
        c[0]=1; c[4]=0x44; c[8]=0x23; c[0x0a]=0x41; c[0x0c]=2; c[0x28]=0x18;
        for (int i=0;i<20;i++) c[0x2c+i]=i;   /* host field; selector at +0x40 stays 0 = RSA */
        cv_cmd (dev, c, 0x44);
      }
      break;
    case OPEN_24:
      {
        /* parse 0x23 response: handle @+0x10, param @+0x2c (modulus[256] + ... + chip_nonce[20]) */
        guint8 *r = self->resp; gsize rl = self->resp_len;
        fp_warn ("OPEN_24: rl=%zu", rl);
        if (rl < 0x2c + 256 + 24) { fp_warn ("rl too small"); fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO)); return; }
        guint8 handle[4], modulus[256], chip_nonce[20], host_nonce[20], block[256];
        memcpy (handle, r + 0x10, 4);
        memcpy (modulus, r + 0x2c, 256);
        memcpy (chip_nonce, r + rl - 24, 20);
        for (int i=0;i<20;i++) host_nonce[i] = g_random_int_range (0, 256);
        int rsa_rc = cv2_build_rsa_block (modulus, host_nonce, block);
        fp_warn ("OPEN_24: handle=%02x%02x%02x%02x mod0=%02x rsa_rc=%d", handle[0],handle[1],handle[2],handle[3], modulus[0], rsa_rc);
        if (rsa_rc != 0)
          { fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL)); return; }
        cv2_session_init (&self->sess, chip_nonce, host_nonce, handle);
        guint8 *c = g_malloc0 (0x2c + 256);
        c[0]=1; *(guint32*)(c+4)=GUINT32_TO_LE(0x2c+256); c[8]=0x24; c[0x0a]=0x41; c[0x0c]=2;
        memcpy (c+0x10, handle, 4); *(guint32*)(c+0x28)=GUINT32_TO_LE(256); memcpy (c+0x2c, block, 256);
        cv_cmd (dev, c, 0x2c + 256);
      }
      break;
    case OPEN_DONE:
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
open_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  fp_warn ("open_done error=%s", error ? error->message : "none (OK)");
  fpi_device_open_complete (dev, error);
}

static void
dev_open (FpDevice *device)
{
  GError *error = NULL;
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (device);
  fp_warn ("dev_open");
  g_usb_device_reset (fpi_device_get_usb_device (device), &error);
  g_clear_error (&error);
  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device), 0, 0, &error))
    { fp_warn ("claim failed: %s", error->message); fpi_device_open_complete (device, error); return; }
  self->task_ssm = fpi_ssm_new (device, open_run, OPEN_NUM);
  fpi_ssm_start (self->task_ssm, open_done);
}

static void
dev_close (FpDevice *device)
{
  GError *error = NULL;
  g_usb_device_release_interface (fpi_device_get_usb_device (device), 0, 0, &error);
  fpi_device_close_complete (device, error);
}

/* ---- enroll ----
 * Secure session is already live (from dev_open). In CV2 every object/enroll command
 * is wrapped in the session (unlike CV3, which sends them plaintext). Flow mirrors the
 * captured enrollment: 0x02 open object -> 0x8a begin -> {0x66 poll, 0x6c submit}* ->
 * 0x68 end -> 0x6e commit -> 0x04 close.
 *
 * Capture bodies are CV2 forms where known (0x02/0x66, decrypted from the Windows
 * secure-session capture); 0x8a/0x6c/0x68 reuse the CV3 plaintext-capture structure
 * (same enrollment semantics). The commit (0x6e) is gated by EN_COMMIT_ENABLED while the
 * capture loop and completion signal are being validated on real hardware. */
#define EN_COMMIT_ENABLED 1
#define EN_MAX_STAGES      8
#define EN_MAX_POLLS       40   /* ~1.5 s each -> ~60 s to present a finger per stage */
#define EN_MAX_SUBMITS     40   /* cap total 0x6c submits while waiting for the 0x59 complete */
#define EN_COMMIT_SAMPLES  24   /* last-resort safety only. This chip's firmware accepts ~4 samples
                                 * then signals "enrollment full" with 0x8c (not 0x59); the 0x8c
                                 * handler below is the real completion trigger. Committing on the
                                 * raw accept count (before the chip signals done) finalises an
                                 * incomplete enrollment -> commit returns 0x8e (vs 0x8d) and the
                                 * stored template does not match. Wait for the chip's 0x8c. */

/* 0x02 open-object body (CV2): {tag0 len4 = 0x4d} {tag1 len0}x3. The response carries the
 * object handle (= session handle). */
static const guint8 BODY_02[] = {
  0x00,0x00,0x00,0x00, 0x04,0x00,0x00,0x00, 0x4d,0x00,0x00,0x00,
  0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
  0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
  0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
};
/* 0x8a begin / 0x68 end: {tag0 len4 = 0}. */
static const guint8 BODY_8A68[] = {
  0x00,0x00,0x00,0x00, 0x04,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
};

/* 0x66 capture-poll body (CV2): {tag0 len4 = obj_handle}{tag0 len4 = 1}{tag0 len4 = 0x23}. */
static guint8 *
build_66 (const guint8 handle[4], gsize *len)
{
  guint8 *b = g_malloc0 (36); guint8 *p = b;
  p = tlv_put (p, handle, 4);
  guint32 one = GUINT32_TO_LE (1);     p = tlv_put (p, &one, 4);
  guint32 k23 = GUINT32_TO_LE (0x23);  p = tlv_put (p, &k23, 4);
  *len = 36; return b;
}
/* 0x6c submit-sample body: {tag0 len4 = obj_handle}{tag0 len0x14 = digest}{tag2 len0}. */
static guint8 *
build_6c (const guint8 handle[4], const guint8 digest[20], gsize *len)
{
  guint8 *b = g_malloc0 (48); guint8 *p = b;
  p = tlv_put (p, handle, 4);
  p = tlv_put (p, digest, 20);
  guint32 tag2 = GUINT32_TO_LE (2); memcpy (p, &tag2, 4); p += 4; /* tag=2 */
  memset (p, 0, 4); p += 4;                                       /* len=0 */
  *len = 48; return b;
}

enum { EN_OPEN, EN_DISCARD, EN_BEGIN, EN_POLL, EN_SUBMIT, EN_END, EN_CREATE, EN_COMMIT, EN_CLOSE, EN_DONE, EN_NUM };

static void
enroll_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  fp_dbg ("enroll SSM state %d (stage %u)", fpi_ssm_get_cur_state (ssm), self->enroll_stage);
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case EN_OPEN:
      cv_enc (dev, 0x02, 0x0440, BODY_02, sizeof BODY_02, FALSE);
      break;
    case EN_DISCARD:
      {
        /* object handle came back in the 0x02 response */
        guint8 *r = self->resp; gsize rl = self->resp_len;
        if (rl < 12) { fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO)); return; }
        memcpy (self->obj_handle, r + 8, 4);
        fp_warn ("enroll: object handle = %02x%02x%02x%02x",
                 self->obj_handle[0], self->obj_handle[1], self->obj_handle[2], self->obj_handle[3]);
        /* discard any stale/dangling enrollment left by a prior aborted enroll, so the
         * chip accepts fresh samples (otherwise every 0x6c comes back 0x8c) */
        guint8 body[12]; tlv_put (body, self->obj_handle, 4);
        cv_enc (dev, 0x6d, 0x0440, body, sizeof body, FALSE);
      }
      break;
    case EN_BEGIN:
      cv_enc (dev, 0x8a, 0x0440, BODY_8A68, sizeof BODY_8A68, FALSE);
      break;
    case EN_POLL:
      {
        /* blocks on the chip until a finger is present; returns a 20-byte image digest.
         * The trailing async status event is drained (drain_extra=TRUE). */
        gsize n; guint8 *b = build_66 (self->obj_handle, &n);
        cv_enc (dev, 0x66, 0x0442, b, n, TRUE);
        g_free (b);
      }
      break;
    case EN_SUBMIT:
      {
        /* 0x66 response body: {tag0 len0x14 = digest} -> digest at +8.
         * 0x66 is non-blocking: with no finger it returns an empty body, so keep polling
         * (the drain in EN_POLL waits ~1.5 s on the finger-event interrupt between tries). */
        guint8 *r = self->resp; gsize rl = self->resp_len;
        if (rl < 28)
          {
            if (++self->poll_count > EN_MAX_POLLS)
              { fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "no finger detected (timeout)")); return; }
            fpi_ssm_jump_to_state (ssm, EN_POLL);
            return;
          }
        self->poll_count = 0;
        memcpy (self->digest, r + 8, 20);
        fp_warn ("enroll stage %u: got digest %02x%02x%02x%02x…",
                 self->enroll_stage, self->digest[0], self->digest[1], self->digest[2], self->digest[3]);
        gsize n; guint8 *b = build_6c (self->obj_handle, self->digest, &n);
        cv_enc (dev, 0x6c, 0x0440, b, n, FALSE);
        g_free (b);
      }
      break;
    case EN_END:
      {
        /* 0x6c submit done. The chip signals enrollment state in the response +0x14:
         *   0x59 = enrollment COMPLETE (enough samples) -> end + commit
         *   0x00 = this sample accepted -> count it, capture the next
         *   else (0x89/0x8c/…) = sample not accepted (retry) -> capture again, no progress */
        self->submits++;
        guint32 rc = self->result_code;
        fp_warn ("enroll: 0x6c +0x14=0x%x (accepted=%u submits=%u)", rc, self->enroll_stage, self->submits);
        if (rc == 0x59)
          {
            fp_warn ("enroll: chip reports COMPLETE");
            fpi_device_enroll_progress (dev, EN_MAX_STAGES, NULL, NULL);
            cv_enc (dev, 0x68, 0x0440, BODY_8A68, sizeof BODY_8A68, FALSE);
            break;
          }
        if (rc == 0x8c && self->enroll_stage >= 3)
          {
            /* this chip signals "enrollment full" with 0x8c after ~4 accepted samples
             * rather than 0x59; treat it as completion and finalise. */
            fp_warn ("enroll: chip full (0x8c) after %u accepts -> COMPLETE", self->enroll_stage);
            fpi_device_enroll_progress (dev, EN_MAX_STAGES, NULL, NULL);
            cv_enc (dev, 0x68, 0x0440, BODY_8A68, sizeof BODY_8A68, FALSE);
            break;
          }
        if (rc == 0)
          {
            /* accepted sample: stash the 20-byte digest (what cvhSaveReturnValues extracts
             * from the 0x6c response) for create_template (0x6f) */
            if (self->nsamples < 4)
              {
                const guint8 *dig = (self->resp_len >= 32) ? self->resp + 12 : self->digest; /* digest in the 0x6c resp */
                memcpy (self->sample[self->nsamples], dig, 20);
                self->sample_len[self->nsamples] = 20;
                self->nsamples++;
                fp_warn ("enroll: stashed digest %u = %02x%02x%02x%02x…", self->nsamples, dig[0], dig[1], dig[2], dig[3]);
              }
            self->enroll_stage++;
            fpi_device_enroll_progress (dev, MIN (self->enroll_stage, EN_MAX_STAGES), NULL, NULL);
            /* fallback: if the chip accepts samples but never signals 0x59 (seen on a chip
             * degraded by heavy testing), commit once we have enough accepted samples */
            if (self->enroll_stage >= EN_COMMIT_SAMPLES)
              {
                fp_warn ("enroll: %u accepted samples -> committing (no 0x59)", self->enroll_stage);
                fpi_device_enroll_progress (dev, EN_MAX_STAGES, NULL, NULL);
                cv_enc (dev, 0x68, 0x0440, BODY_8A68, sizeof BODY_8A68, FALSE);
                break;
              }
          }
        if (self->submits > EN_MAX_SUBMITS)
          { fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "enrollment did not complete")); return; }
        fpi_ssm_jump_to_state (ssm, EN_POLL);
      }
      break;
    case EN_CREATE:
      /* The real CV enroll flow has NO 0x6f create_template (verified byte-for-byte against
       * the CV3 plaintext capture: 0x02 -> 0x8a -> (0x66 -> 0x6c)xN -> 0x68 -> 0x6e -> 0x04).
       * The template is built on-chip from the accumulated 0x6c submits; the speculative
       * 0x6f errored (0x73) and invalidated the enrollment before commit. Skip to commit. */
      fp_warn ("enroll: 0x68 end result +0x14=0x%x -> commit", self->result_code);
      fpi_ssm_jump_to_state (ssm, EN_COMMIT);
      break;
    case EN_COMMIT:
#if EN_COMMIT_ENABLED
      {
        fp_warn ("enroll: committing (0x6e)");
        guint8 body[64]; guint8 *p = body;
        p = tlv_put (p, self->obj_handle, 4);                 /* {tag0 len4 handle} */
        /* {tag0 len0x14 = 20 ZEROS}. Verified against the CV3 plaintext capture: the commit's
         * 20-byte field is all zeros and the tag2/tag2/tag3 params are empty — the template is
         * already stored on-chip from the 0x6c submits. A non-zero id (e.g. SHA1 of the
         * username) stored it under a hash the empty-hash identify (0x73) could not find. */
        guint8 id[20] = { 0 };
        p = tlv_put (p, id, 20);
        /* trailing fields verbatim from the capture: {tag2 len0}{tag2 len0}{tag3 len0} */
        static const guint8 tail[24] = { 2,0,0,0, 0,0,0,0,  2,0,0,0, 0,0,0,0,  3,0,0,0, 0,0,0,0 };
        memcpy (p, tail, 24); p += 24;
        cv_enc (dev, 0x6e, 0x0440, body, 64, FALSE);
      }
      break;
#else
      fpi_ssm_jump_to_state (ssm, EN_CLOSE);
      break;
#endif
    case EN_CLOSE:
      {
        fp_warn ("enroll: 0x6e commit result +0x14=0x%x", self->result_code);
        guint8 body[12]; tlv_put (body, self->obj_handle, 4);
        cv_enc (dev, 0x04, 0x0040, body, sizeof body, FALSE);
      }
      break;
    case EN_DONE:
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
enroll_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  fp_warn ("enroll_done: %s", error ? error->message : "capture loop OK");
  if (!error && !EN_COMMIT_ENABLED)
    error = fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                      "capture loop validated (%u stages); commit disabled this build",
                                      self->enroll_stage);
  if (error)
    fpi_device_enroll_complete (dev, NULL, error);
  else
    {
      /* match-on-chip: the template lives on the device; keep a reference print */
      fpi_print_set_type (self->enroll_print, FPI_PRINT_RAW);
      fpi_print_set_device_stored (self->enroll_print, TRUE);
      fpi_device_enroll_complete (dev, g_object_ref (self->enroll_print), NULL);
    }
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  fpi_device_get_enroll_data (dev, &self->enroll_print);
  self->enroll_stage = 0;
  self->submits = 0;
  self->nsamples = 0;
  self->poll_count = 0;
  self->task_ssm = fpi_ssm_new (dev, enroll_run, EN_NUM);
  fpi_ssm_start (self->task_ssm, enroll_done);
}

/* ---- verify / identify (match-on-chip) ----
 * The identify command 0x73 captures the finger and matches it against the stored
 * templates internally; the result is in the response header +0x14 field:
 *   0x00 = match, 0x89 = no finger yet (keep polling), anything else = no match.
 * Body (plen 68) from the CV3 driver disassembly (cv_do_fingerprint_identify): the
 * 0x48 (sensor type) and 0x53e2 (capture param) fields are essential — without them
 * the chip just acks with no match attempt. */
#define VER_MAX_POLLS 40

static guint8 *
build_73 (const guint8 handle[4], const guint8 *probe, gsize probe_len, const guint8 *hash, gsize *len)
{
  /* identify body (from cv_do_fingerprint_identify disasm):
   *   {tag0 handle}{tag0 0x48}{tag0 0x53e2}{tag0 0}{tag2 = probe feature}{tag3 = template hash}
   * The tag2 carries the just-captured probe digest (relayed from the 0x66 capture, exactly like
   * the enroll 0x6c relays its digest) so the chip has something to match; the arm call passes none.
   * tag3 is the optional template id to match against (w_hash); empty = match any. */
  gsize hl = hash ? 20 : 0;
  guint8 *b = g_malloc0 (64 + probe_len + hl); guint8 *p = b;
  guint32 v;
  p = tlv_put (p, handle, 4);
  v = GUINT32_TO_LE (0x48);   p = tlv_put (p, &v, 4);
  v = GUINT32_TO_LE (0x53e2); p = tlv_put (p, &v, 4);
  v = GUINT32_TO_LE (0);      p = tlv_put (p, &v, 4);
  v = GUINT32_TO_LE (2);           memcpy (p, &v, 4); p += 4;   /* tag2 = probe feature */
  v = GUINT32_TO_LE (probe_len);   memcpy (p, &v, 4); p += 4;
  if (probe_len) { memcpy (p, probe, probe_len); p += probe_len; }
  v = GUINT32_TO_LE (3);  memcpy (p, &v, 4); p += 4;            /* tag3 = template hash */
  v = GUINT32_TO_LE (hl); memcpy (p, &v, 4); p += 4;
  if (hl) { memcpy (p, hash, hl); p += hl; }
  *len = p - b; return b;
}

enum { VER_OPEN, VER_ARM, VER_CAPTURE, VER_SUBMIT, VER_CHECK, VER_CLOSE, VER_DONE, VER_NUM };

static void
verify_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  fp_dbg ("verify SSM state %d", fpi_ssm_get_cur_state (ssm));
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VER_OPEN:
      cv_enc (dev, 0x02, 0x0440, BODY_02, sizeof BODY_02, FALSE);
      break;
    case VER_ARM:
      {
        /* object handle came back in the 0x02 response */
        if (self->resp_len < 12) { fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO)); return; }
        memcpy (self->obj_handle, self->resp + 8, 4);
        /* 0x73 arms the verify capture (like 0x8a arms the enroll capture); no probe yet */
        gsize n; guint8 *b = build_73 (self->obj_handle, NULL, 0, NULL, &n);
        cv_enc (dev, 0x73, 0x0442, b, n, TRUE);
        g_free (b);
      }
      break;
    case VER_CAPTURE:
      {
        /* poll the capture until a finger is present */
        gsize n; guint8 *b = build_66 (self->obj_handle, &n);
        cv_enc (dev, 0x66, 0x0442, b, n, TRUE);
        g_free (b);
      }
      break;
    case VER_SUBMIT:
      {
        guint8 *r = self->resp; gsize rl = self->resp_len;
        if (rl < 28)                                  /* no finger yet -> keep polling */
          {
            if (++self->poll_count > VER_MAX_POLLS)
              { fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "no finger (timeout)")); return; }
            fpi_ssm_jump_to_state (ssm, VER_CAPTURE);
            return;
          }
        memcpy (self->digest, r + 8, 20);
        fp_warn ("verify: captured finger %02x%02x%02x%02x…", self->digest[0], self->digest[1], self->digest[2], self->digest[3]);
        /* match the just-captured finger against the stored templates — relay the captured
         * probe digest in tag2 so the chip has the finger to compare (was empty before) */
        gsize n; guint8 *b = build_73 (self->obj_handle, self->digest, 20, NULL, &n);
        cv_enc (dev, 0x73, 0x0442, b, n, TRUE);
        g_free (b);
      }
      break;
    case VER_CHECK:
      fp_warn ("verify: 0x73 result +0x14 = 0x%x (attempt %u)", self->result_code, self->poll_count);
      if (self->result_code == 0)
        {
          self->verify_matched = TRUE;
          fp_warn ("verify: MATCH ✓");
          fpi_ssm_jump_to_state (ssm, VER_CLOSE);
          break;
        }
      /* 0x89 = no finger yet, 0x85 = this sample didn't match. Each 0x73 is a fresh
       * capture+identify, so keep retrying (re-capture + re-identify) to give the user
       * time to present the finger well — report no-match only after exhausting the window. */
      if (++self->poll_count <= VER_MAX_POLLS)
        {
          fpi_ssm_jump_to_state (ssm, VER_CAPTURE);
          return;
        }
      self->verify_matched = FALSE;
      fp_warn ("verify: no match (exhausted %u attempts)", self->poll_count);
      fpi_ssm_jump_to_state (ssm, VER_CLOSE);
      break;
    case VER_CLOSE:
      {
        guint8 body[12]; tlv_put (body, self->obj_handle, 4);
        cv_enc (dev, 0x04, 0x0040, body, sizeof body, FALSE);
      }
      break;
    case VER_DONE:
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
verify_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  fp_warn ("verify_done: %s", error ? error->message : (self->verify_matched ? "MATCH" : "no match"));
  if (error) { fpi_device_verify_complete (dev, error); return; }

  FpPrint *print = NULL;
  fpi_device_get_verify_data (dev, &print);
  fpi_device_verify_report (dev,
                            self->verify_matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                            self->verify_matched ? print : NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

/* verify needs a FRESH secure session (the chip won't re-open an object in the session
 * that was just used for an enroll) — matching the Windows flow, which re-handshakes
 * before every verify. So run the open handshake SSM first, then the verify SSM. */
static void
vhs_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  if (error) { fp_warn ("verify handshake failed: %s", error->message); fpi_device_verify_complete (dev, error); return; }
  self->poll_count = 0;
  self->verify_matched = FALSE;
  self->task_ssm = fpi_ssm_new (dev, verify_run, VER_NUM);
  fpi_ssm_start (self->task_ssm, verify_done);
}

static void
dev_verify (FpDevice *dev)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  /* template id to match against = SHA1(username) of the print being verified
   * (same id the enroll commit stored the template under) */
  memset (self->verify_hash, 0, sizeof self->verify_hash);
  FpPrint *print = NULL;
  fpi_device_get_verify_data (dev, &print);
  const char *user = print ? fp_print_get_username (print) : NULL;
  if (user)
    {
      gsize dl = sizeof self->verify_hash;
      GChecksum *ck = g_checksum_new (G_CHECKSUM_SHA1);
      g_checksum_update (ck, (const guchar *) user, -1);
      g_checksum_get_digest (ck, self->verify_hash, &dl);
      g_checksum_free (ck);
    }
  self->task_ssm = fpi_ssm_new (dev, open_run, OPEN_NUM);
  fpi_ssm_start (self->task_ssm, vhs_done);
}

static void
fpi_device_bcm5880cv2_init (FpiDeviceBcm5880Cv2 *self) {}

static void
fpi_device_bcm5880cv2_class_init (FpiDeviceBcm5880Cv2Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Dell ControlVault 2 (BCM5880)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = 8;
  dev_class->temp_hot_seconds = -1;
  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  /* identify intentionally left unset for now: advertising it makes fprintd run a
   * duplicate-detection identify *before* enroll, which we can't satisfy yet. Enabled
   * once the capture/match path works. */
}
