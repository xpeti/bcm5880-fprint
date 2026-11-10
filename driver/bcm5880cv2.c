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
  guint8      status[8];      /* [status u32][len u32] from EP 0x85 */
  guint8     *resp;           /* response body buffer */
  gsize       resp_len;
  void      (*cmd_done)(FpDevice *dev);  /* called when a cv command round-trip completes */
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
enum { CV_SEND, CV_STATUS, CV_BODY, CV_NUM };

static void
cv_ssm_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBcm5880Cv2 *self = FPI_DEVICE_BCM5880CV2 (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
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
        fp_warn ("cv status=0x%x len=%u", st, len);
        if (st != 0)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "CV status 0x%x", st));
            return;
          }
        g_clear_pointer (&self->resp, g_free);
        self->resp = g_malloc0 (len ? len : 1);
        self->resp_len = len;
        if (len == 0) { fpi_ssm_mark_completed (ssm); return; }
        t = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_bulk_full (t, EP_IN, self->resp, len, NULL);
        t->ssm = ssm;
        fpi_usb_transfer_submit (t, CV_TIMEOUT, NULL, fpi_ssm_usb_transfer_cb, NULL);
      }
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
  self->cmd = cmd; self->cmd_len = len;
  FpiSsm *s = fpi_ssm_new (dev, cv_ssm_run, CV_NUM);
  fpi_ssm_start (s, cv_cmd_cb);
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

/* enroll/verify/identify: next milestone (drive capture + wrap commands via cv2_wrap) */
static void dev_enroll   (FpDevice *d){ fpi_device_enroll_complete   (d, NULL, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED, "enroll WIP")); }
static void dev_verify   (FpDevice *d){ fpi_device_verify_complete   (d, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED, "verify WIP")); }
static void dev_identify (FpDevice *d){ fpi_device_identify_complete (d, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED, "identify WIP")); }

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
  dev_class->identify = dev_identify;
}
