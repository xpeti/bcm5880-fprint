/* Standalone libfprint harness: enroll then verify, driving the TOD driver as root. */
#include <fprint.h>
#include <stdio.h>
#include <string.h>

static void enroll_progress (FpDevice *dev, gint done, FpPrint *print, gpointer u, GError *err)
{ printf (">>> enroll stage %d%s\n", done, err ? " (retry)" : ""); fflush (stdout); }
static void match_cb (FpDevice *dev, FpPrint *match, FpPrint *print, gpointer u, GError *err)
{ printf (">>> match_cb: %s%s\n", match ? "MATCH" : "no-match", err ? " (err)" : ""); fflush (stdout); }

int main (int argc, char **argv)
{
  GError *err = NULL;
  FpContext *ctx = fp_context_new ();
  GPtrArray *devs = fp_context_get_devices (ctx);
  if (!devs || devs->len == 0) { printf ("no devices\n"); return 1; }
  FpDevice *dev = g_ptr_array_index (devs, 0);
  printf ("device: %s\n", fp_device_get_name (dev)); fflush (stdout);
  if (!fp_device_open_sync (dev, NULL, &err)) { printf ("open failed: %s\n", err->message); return 1; }
  printf ("opened OK\n"); fflush (stdout);

  const char *mode = argc > 1 ? argv[1] : "both";
  if (!strcmp (mode, "verify"))
    {
      FpPrint *ref = fp_print_new (dev);
      fp_print_set_finger (ref, FP_FINGER_RIGHT_INDEX);
      fp_print_set_username (ref, "petr");
      printf ("=== VERIFY: press the enrolled finger ===\n"); fflush (stdout);
      gboolean match = FALSE; FpPrint *matched = NULL;
      gboolean ok = fp_device_verify_sync (dev, ref, NULL, match_cb, NULL, &match, &matched, &err);
      if (!ok) printf ("VERIFY op failed: %s\n", err ? err->message : "?");
      else     printf ("=== VERIFY RESULT: %s ===\n", match ? "MATCH \342\234\223" : "NO MATCH \342\234\227");
      goto out;
    }

  FpPrint *tmpl = fp_print_new (dev);
  fp_print_set_finger (tmpl, FP_FINGER_RIGHT_INDEX);
  fp_print_set_username (tmpl, "petr");
  printf ("=== ENROLL: press finger repeatedly, different parts ===\n"); fflush (stdout);
  FpPrint *enrolled = fp_device_enroll_sync (dev, tmpl, NULL, enroll_progress, NULL, &err);
  if (!enrolled) { printf ("ENROLL FAILED: %s\n", err ? err->message : "?"); goto out; }
  printf ("=== ENROLL OK ===\n"); fflush (stdout);
  g_clear_error (&err);
  printf ("=== VERIFY: press the SAME finger ===\n"); fflush (stdout);
  gboolean match = FALSE; FpPrint *matched = NULL;
  gboolean ok = fp_device_verify_sync (dev, enrolled, NULL, match_cb, NULL, &match, &matched, &err);
  if (!ok) printf ("VERIFY op failed: %s\n", err ? err->message : "?");
  else     printf ("=== VERIFY RESULT: %s ===\n", match ? "MATCH \342\234\223" : "NO MATCH \342\234\227");

out:
  { GError *e2 = NULL; fp_device_close_sync (dev, NULL, &e2); }
  printf ("closed\n");
  return 0;
}
