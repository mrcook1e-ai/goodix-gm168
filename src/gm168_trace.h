/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * gm168_trace.h — opt-in per-state timing for SSMs.
 *
 * Off by default. Enabled by setting `$GM168_TRACE=1` before the runner
 * (debug.sh/run.sh propagate env). When on, emits one g_warning line per
 * state transition with elapsed wall-clock since the previous state. Lines
 * are tagged `[TRACE]` and survive the debug.sh filter via the WARNING
 * pattern.
 *
 * Output format:
 *     [TRACE] <ssm>:<state> took <us> us
 *     [TRACE] === <ssm> SSM done ===
 *
 * Where <state> is the integer enum value from the matching state-machine
 * declaration in goodix_gm168.c (INIT_*, CAP_*, REARM_*, DEINIT_*). Map by
 * reading the enums; we deliberately don't ship name tables here to keep
 * this header zero-maintenance — the goal is *measurement*, not pretty
 * printing. Once G7 traces inform the per-state table in HARDENING.md §3,
 * names can be added if useful.
 *
 * Intended use:
 *   - dev_activate:          gm168_trace_init (&self->trace);
 *   - <ssm>_run_state top:   gm168_trace_state(&self->trace, "INIT", state);
 *   - <ssm>_completed:       gm168_trace_ssm_done(&self->trace, "INIT");
 *
 * Threading: all SSM callbacks fire on the GLib main loop, so no
 * synchronisation is needed for the trace struct.
 *
 * See docs/HARDENING.md §G7, docs/AUDIT.md §6 (foundation for §G13 tuning).
 */
#ifndef GM168_TRACE_H
#define GM168_TRACE_H

#include <glib.h>

typedef struct {
    gboolean    enabled;
    const char *last_ssm;       /* not owned — string literal from caller   */
    int         last_state;
    gint64      last_us;
} GM168Trace;

/* Cache the env-var read once per activate. Subsequent re-reads of getenv
 * are cheap but we avoid the call cost on every state transition.         */
static inline void
gm168_trace_init (GM168Trace *t)
{
    const char *v = g_getenv ("GM168_TRACE");
    t->enabled    = (v != NULL && v[0] != '\0' && v[0] != '0');
    t->last_ssm   = NULL;
    t->last_state = -1;
    t->last_us    = 0;
}

/* Call at the TOP of each <ssm>_run_state callback, before the switch.
 * Closes out the timer on the previous state and starts a new one for
 * `state`. The very first call after gm168_trace_init silently primes
 * the timer (nothing to close out yet).                                  */
static inline void
gm168_trace_state (GM168Trace *t, const char *ssm, int state)
{
    if (!t->enabled) return;
    gint64 now = g_get_monotonic_time ();
    if (t->last_ssm) {
        g_warning ("[TRACE] %s:%d took %lld us",
                   t->last_ssm, t->last_state,
                   (long long)(now - t->last_us));
    }
    t->last_ssm   = ssm;
    t->last_state = state;
    t->last_us    = now;
}

/* Call from <ssm>_completed. Closes the timer on the SSM's final state
 * (typically an *_ACK that advanced via fpi_ssm_mark_completed without a
 * follow-up gm168_trace_state call) and emits the SSM-done marker.       */
static inline void
gm168_trace_ssm_done (GM168Trace *t, const char *ssm)
{
    if (!t->enabled) return;
    gint64 now = g_get_monotonic_time ();
    if (t->last_ssm) {
        g_warning ("[TRACE] %s:%d took %lld us (final)",
                   t->last_ssm, t->last_state,
                   (long long)(now - t->last_us));
    }
    g_warning ("[TRACE] === %s SSM done ===", ssm);
    t->last_ssm   = NULL;
    t->last_state = -1;
}

#endif /* GM168_TRACE_H */
