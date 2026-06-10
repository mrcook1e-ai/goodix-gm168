/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * gm168_log.c — per-session structured text log implementation.
 *
 * See gm168_log.h for API documentation.
 */

#include "gm168_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <glib.h>

/* ──────────────────────────────────────────────────────────────────────────
 * Internal helpers
 * ────────────────────────────────────────────────────────────────────────── */

static double
log_elapsed (const Gm168Log *log)
{
    return (double)(g_get_monotonic_time () - log->t0_us) / 1e6;
}

/* Emit hex bytes for `len` bytes of `data`, max GM168_LOG_HEX_INLINE inline.
 * Returns the number of bytes not shown (overflow).                        */
static guint32
write_hex (FILE *fp, const guint8 *data, guint32 len)
{
    guint32 show = len < GM168_LOG_HEX_INLINE ? len : GM168_LOG_HEX_INLINE;
    for (guint32 i = 0; i < show; i++) {
        if (i) fputc (' ', fp);
        fprintf (fp, "%02X", data[i]);
    }
    return len - show;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Public API
 * ────────────────────────────────────────────────────────────────────────── */

void
gm168_log_open (Gm168Log *log)
{
    memset (log, 0, sizeof (*log));

    /* Resolve session directory: $GM168_LOG_DIR or ~/.goodix-gm168/sessions */
    const char *env_dir = g_getenv ("GM168_LOG_DIR");
    g_autofree char *dir =
        (env_dir && *env_dir)
            ? g_strdup (env_dir)
            : g_strdup_printf ("%s/.goodix-gm168/sessions", g_get_home_dir ());

    if (g_mkdir_with_parents (dir, 0755) != 0) {
        g_warning ("gm168_log: cannot create log dir %s: %s",
                   dir, g_strerror (errno));
        return;
    }

    /* Filename: gm168-YYYYMMDD-HHMMSS.log */
    time_t now_t  = time (NULL);
    struct tm *tm = localtime (&now_t);
    log->path = g_strdup_printf (
        "%s/gm168-%04d%02d%02d-%02d%02d%02d.log",
        dir,
        tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
        tm->tm_hour,        tm->tm_min,      tm->tm_sec);

    log->fp = fopen (log->path, "w");
    if (!log->fp) {
        g_warning ("gm168_log: cannot open %s: %s",
                   log->path, g_strerror (errno));
        g_clear_pointer (&log->path, g_free);
        return;
    }

    log->t0_us = g_get_monotonic_time ();

    /* Write header banner. */
    char ts[32];
    strftime (ts, sizeof (ts), "%Y-%m-%d %H:%M:%S", tm);
    fprintf (log->fp,
             "══════════════════════════════════════════════════════════════════\n"
             " GM168  %s\n"
             "══════════════════════════════════════════════════════════════════\n"
             "\n",
             ts);
    fflush (log->fp);
}

void
gm168_log_close (Gm168Log *log)
{
    if (!log || !log->fp) return;

    double total = log_elapsed (log);
    fprintf (log->fp,
             "\n"
             "══════════════════════════════════════════════════════════════════\n"
             " session  %.3f s\n"
             " log      %s\n"
             "══════════════════════════════════════════════════════════════════\n",
             total, log->path);

    fclose (log->fp);
    log->fp = NULL;
    g_clear_pointer (&log->path, g_free);
}

void
gm168_log_ev (Gm168Log *log, const char *cat, const char *fmt, ...)
{
    if (!log || !log->fp) return;

    gint64 now = g_get_monotonic_time ();

    /* Delta from previous event line — shows per-operation latency. */
    if (log->last_ev_us) {
        gint64 delta_ms = (now - log->last_ev_us) / 1000;
        fprintf (log->fp, " +%8.3f  %-5s  [+%4lldms]  ",
                 log_elapsed (log), cat, (long long)delta_ms);
    } else {
        fprintf (log->fp, " +%8.3f  %-5s  [  ---  ]  ",
                 log_elapsed (log), cat);
    }
    log->last_ev_us = now;

    va_list ap;
    va_start (ap, fmt);
    vfprintf (log->fp, fmt, ap);
    va_end (ap);

    fputc ('\n', log->fp);
    fflush (log->fp);
}

void
gm168_log_tx (Gm168Log *log, const char *label, const guint8 *data, guint32 len)
{
    if (!log || !log->fp || !data || len == 0) return;

    fprintf (log->fp, " +%8.3f  tx     ", log_elapsed (log));
    guint32 overflow = write_hex (log->fp, data, len);
    if (overflow)
        fprintf (log->fp, " +%u b", overflow);
    if (label && *label)
        fprintf (log->fp, "  [%s]", label);
    fputc ('\n', log->fp);
    fflush (log->fp);
}

void
gm168_log_rx (Gm168Log *log, const char *label, const guint8 *data, guint32 len)
{
    if (!log || !log->fp || !data || len == 0) return;

    fprintf (log->fp, " +%8.3f  rx     ", log_elapsed (log));
    guint32 overflow = write_hex (log->fp, data, len);
    if (overflow)
        fprintf (log->fp, " +%u b", overflow);
    if (label && *label)
        fprintf (log->fp, "  [%s]", label);
    fputc ('\n', log->fp);
    fflush (log->fp);
}

void
gm168_log_touch_divider (Gm168Log *log)
{
    if (!log || !log->fp) return;

    log->touch_count++;
    fprintf (log->fp,
             "\n +%8.3f  ── touch #%d ─────────────────────────────────────────\n",
             log_elapsed (log), log->touch_count);
    fflush (log->fp);
}
