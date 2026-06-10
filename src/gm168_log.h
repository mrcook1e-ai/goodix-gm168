/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * gm168_log.h — per-session structured text log for the GM168 driver.
 *
 * One file per dev_open/dev_close cycle, written to
 *   $GM168_LOG_DIR/gm168-YYYYMMDD-HHMMSS.log
 * (default: ~/.goodix-gm168/sessions/).
 *
 * Always active — no env flag required. enroll_grid.sh sets
 * GM168_LOG_DIR=$SESSION_DIR so the log lands next to the PGMs and grid PNG.
 *
 * Line format:
 *   " +TTTTTT.TTT  CAT    message"
 * where TTTTTT.TTT is elapsed seconds since dev_open.
 * TX/RX hex dumps share the same timestamp + "tx"/"rx" category.
 *
 * Integration points (in pipeline order):
 *   dev_open       → gm168_log_open  (&self->log)
 *   dev_close      → gm168_log_close (&self->log)
 *   everywhere     → GM168_LOG_* macros
 */
#ifndef GM168_LOG_H
#define GM168_LOG_H

#include <stdio.h>
#include <glib.h>

/* First N bytes shown inline in a TX/RX line; remainder noted as "+N b". */
#define GM168_LOG_HEX_INLINE  32

typedef struct {
    FILE   *fp;
    gint64  t0_us;          /* g_get_monotonic_time() at log open           */
    gint64  last_ev_us;     /* time of previous gm168_log_ev call; 0=none   */
    int     touch_count;    /* incremented by gm168_log_touch_divider       */
    int     stage_count;    /* incremented in rearm_completed on submit     */
    char   *path;           /* dir + "/gm168-YYYYMMDD-HHMMSS.log"; g_free'd */

    /* Timing anchors set by caller for elapsed-in-phase calculation.      */
    gint64  init_start_us;
    gint64  rearm_start_us;

    /* Quality from last accepted capture, used in STAGE line.            */
    gfloat  last_quality;
} Gm168Log;

/* ── Lifecycle ─────────────────────────────────────────────────────────── */
void gm168_log_open          (Gm168Log *log);
void gm168_log_close         (Gm168Log *log);

/* ── Event lines ───────────────────────────────────────────────────────── */
/* cat should be exactly 5 chars (or shorter, padded by the format).       */
void gm168_log_ev            (Gm168Log *log, const char *cat,
                               const char *fmt, ...) G_GNUC_PRINTF(3,4);

/* ── USB dump lines ────────────────────────────────────────────────────── */
/* label: short human label appended after the hex bytes, e.g. "cmd=0xD0"  */
void gm168_log_tx            (Gm168Log *log, const char *label,
                               const guint8 *data, guint32 len);
void gm168_log_rx            (Gm168Log *log, const char *label,
                               const guint8 *data, guint32 len);

/* ── Touch divider ─────────────────────────────────────────────────────── */
void gm168_log_touch_divider (Gm168Log *log);

/* ── Convenience macros ────────────────────────────────────────────────── */
#define GM168_LOG_INIT(L,...)   gm168_log_ev((L), "INIT ", ##__VA_ARGS__)
#define GM168_LOG_TLS(L,...)    gm168_log_ev((L), "TLS  ", ##__VA_ARGS__)
#define GM168_LOG_BG(L,...)     gm168_log_ev((L), "BG   ", ##__VA_ARGS__)
#define GM168_LOG_CAP(L,...)    gm168_log_ev((L), "CAP  ", ##__VA_ARGS__)
#define GM168_LOG_REARM(L,...)  gm168_log_ev((L), "REARM", ##__VA_ARGS__)
#define GM168_LOG_LIFT(L,...)   gm168_log_ev((L), "LIFT ", ##__VA_ARGS__)
#define GM168_LOG_STAGE(L,...)  gm168_log_ev((L), "STAGE", ##__VA_ARGS__)
#define GM168_LOG_RECOV(L,...)  gm168_log_ev((L), "RECOV", ##__VA_ARGS__)
#define GM168_LOG_WARN(L,...)   gm168_log_ev((L), "WARN!", ##__VA_ARGS__)
#define GM168_LOG_ERR(L,...)    gm168_log_ev((L), "ERROR", ##__VA_ARGS__)

#endif /* GM168_LOG_H */
