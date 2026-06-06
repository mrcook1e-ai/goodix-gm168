/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * gm168_usb_errors.h — central USB error classification.
 *
 * Before G3, callbacks treated only G_USB_DEVICE_ERROR_TIMED_OUT and
 * G_IO_ERROR_CANCELLED specially; every other error fell through to
 * `fpi_ssm_mark_failed (ssm, error)` with no diagnosis. In particular,
 * device-removed (`G_USB_DEVICE_ERROR_NO_DEVICE`) looked the same as a
 * generic IO glitch — so unplug mid-session produced a confusing generic
 * error to fprintd instead of FP_DEVICE_ERROR_REMOVED.
 *
 * This header centralises the mapping. Callbacks branch on the enum
 * rather than chained g_error_matches calls. The OTHER vs IO split exists
 * for the future G4 recover() hook: IO errors are recoverable via reset,
 * OTHER are not (they're domain mismatches that mean the caller already
 * built a custom error).
 *
 * See docs/AUDIT.md §2.2 (finding H3), docs/HARDENING.md §G3.
 */
#ifndef GM168_USB_ERRORS_H
#define GM168_USB_ERRORS_H

#include <glib.h>
#include <gio/gio.h>
#include <gusb.h>

typedef enum {
    GM168_USB_ERR_OTHER     = 0,  /* error->domain is not USB/GIO     */
    GM168_USB_ERR_CANCELLED,      /* G_IO_ERROR_CANCELLED             */
    GM168_USB_ERR_TIMEOUT,        /* G_USB_DEVICE_ERROR_TIMED_OUT     */
    GM168_USB_ERR_NO_DEVICE,      /* unplug / sensor reset            */
    GM168_USB_ERR_IO,             /* any other G_USB_DEVICE_ERROR     */
} GM168UsbErrorClass;

static inline GM168UsbErrorClass
gm168_classify_usb_error (const GError *error)
{
    if (!error)
        return GM168_USB_ERR_OTHER;
    if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        return GM168_USB_ERR_CANCELLED;
    if (g_error_matches (error, G_USB_DEVICE_ERROR,
                         G_USB_DEVICE_ERROR_TIMED_OUT))
        return GM168_USB_ERR_TIMEOUT;
    if (g_error_matches (error, G_USB_DEVICE_ERROR,
                         G_USB_DEVICE_ERROR_NO_DEVICE))
        return GM168_USB_ERR_NO_DEVICE;
    if (error->domain == G_USB_DEVICE_ERROR)
        return GM168_USB_ERR_IO;
    return GM168_USB_ERR_OTHER;
}

/* Human-readable class name for logs. */
static inline const char *
gm168_usb_error_class_name (GM168UsbErrorClass c)
{
    switch (c) {
        case GM168_USB_ERR_CANCELLED: return "CANCELLED";
        case GM168_USB_ERR_TIMEOUT:   return "TIMEOUT";
        case GM168_USB_ERR_NO_DEVICE: return "NO_DEVICE";
        case GM168_USB_ERR_IO:        return "IO";
        case GM168_USB_ERR_OTHER:     return "OTHER";
    }
    return "?";
}

#endif /* GM168_USB_ERRORS_H */
