/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Goodix GM168 Driver for libfprint
 *
 * Fully asynchronous implementation using FpiSsm.
 * Protocol verified via Binary Ninja (Wbdi.dll), Frida hooks, and USB traces.
 */

#define FP_COMPONENT "goodix_gm168"

#include "fpi-image-device.h"
#include "drivers_api.h"
#include <gusb.h>
#include <string.h>
#include "gm168_cal.h"

#include "goodix_proto.h"
#include "goodix_tls.h"
#include "gm168_timeouts.h"
#include "gm168_trace.h"
#include "gm168_usb_errors.h"
#include "gm168_log.h"

#include <math.h>

/* CLAHE tiling for 64x80 frames: 4x5 grid of 16x16 contextual regions.
 * Clip limit is the max bin population (out of TILE_PX=256) before
 * excess gets redistributed; ~6% mirrors skimage's clip_limit=0.03 we
 * prototyped against captured FRAME pairs. */
#define GM168_CLAHE_TILE_W   16
#define GM168_CLAHE_TILE_H   16
#define GM168_CLAHE_TX       (GM168_FRAME_W / GM168_CLAHE_TILE_W)  /* 4 */
#define GM168_CLAHE_TY       (GM168_FRAME_H / GM168_CLAHE_TILE_H)  /* 5 */
#define GM168_CLAHE_CLIP     16  /* of 256 px per tile.  Tried 6 (under-
                                  * boosts real ridges, 55% NBIS fail) and
                                  * the unclipped variant (over-boosts
                                  * noise into spurious ridges).  16 was
                                  * the empirical sweet spot at ~44% fail. */

/* Use EP addresses from goodix_proto.h:
 *   GOODIX_GM168_EP_OUT      0x01
 *   GOODIX_GM168_EP_IN       0x83
 *   GOODIX_GM168_EP_IN_SIZE  (16 * 1024)
 */

/*
 * Wire layout of one TLS frame (verified via Frida + WbdiEnclave RE):
 *   10564 bytes total = 80 wire rows × 132 bytes + 4-byte trailer
 *   Each wire row: 96 bytes of 12-bit-packed pixel data + 36 zero pad bytes
 *   80 × 96 bytes encode 80 × 64 logical pixels; the enclave transposes them
 *   to 64 × 80 row-major uint16 = what the preprocessor consumes.
 */
#define GM168_TLS_FRAME_SIZE   10564
#define GM168_TLS_PAYLOAD_SIZE 10560   /* 80 wire rows × 132 bytes */
#define GM168_WIRE_ROWS        80
#define GM168_WIRE_ROW_STRIDE  132     /* bytes per wire row */
#define GM168_WIRE_ROW_DATA    96      /* non-zero bytes per wire row */
#define GM168_FRAME_W          80      /* final image width */
#define GM168_FRAME_H          64      /* final image height */
#define GM168_FRAME_PIXELS     (GM168_FRAME_W * GM168_FRAME_H)
#define GM168_FRAME_BYTES      (GM168_FRAME_PIXELS * 2)
/* Number of dark frames averaged at init to suppress temporal noise. The
 * single-frame BG used previously produced std ~60 in the final image; with
 * N=5 averaging std rises closer to the Windows-preprocessor reference (91). */
#define GM168_BG_FRAMES        5
/* Retry / timeout constants moved to gm168_timeouts.h (see G13). */

// --- INITIALIZATION STATE MACHINE ---
enum init_states {
    INIT_WAKEUP = 0,
    INIT_WAKEUP_DELAY,
    INIT_RESET,
    INIT_RESET_ACK,
    INIT_VERSION,
    INIT_VERSION_ACK,
    /* PSK bootstrap: if /etc/goodix-gm168/psk.bin (or $GOODIX_GM168_DIR/psk.bin)
     * was not loaded at activate, walk cmd 0xE4 to dump the sealed blob from
     * the MCU, save it, and fail SSM with instructions for the Windows
     * unseal step. Otherwise GATE jumps straight to INIT_TLS_START. */
    INIT_PSK_GATE,
    INIT_PSK_READ_SEND,
    INIT_PSK_READ_RECV,
    INIT_TLS_START,
    INIT_TLS_START_ACK,
    INIT_TLS_RX,
    INIT_TLS_DELAY,
    INIT_TLS_TX_PULL,
    /* Post-TLS setup: Windows sends SET_PARAM + DEL_TMPL×2 before SESSION_INIT */
    INIT_SET_PARAM,
    INIT_SET_PARAM_ACK,
    INIT_DEL_TMPL_1,
    INIT_DEL_TMPL_1_ACK,
    INIT_DEL_TMPL_2,
    INIT_DEL_TMPL_2_ACK,
    INIT_SESSION,
    INIT_SESSION_ACK,
    /* Windows sends 0xD6 (POWER) between SESSION_INIT and ARM */
    INIT_D6_POST,
    INIT_D6_POST_ACK,
    INIT_ARM,
    INIT_ARM_ACK,
    INIT_FDT,
    INIT_FDT_ACK,
    INIT_BG_TRIG,        /* trigger background capture (no finger) */
    INIT_BG_RX,          /* receive background frame               */
    INIT_BG_PROCESS,     /* accumulate into background_sum         */
    INIT_BG_LOOP_CHECK,  /* loop to BG_TRIG until GM168_BG_FRAMES summed,
                          * then fall through to rearm chain ONCE  */
    INIT_BG_REARM_34_1,  /* rearm FDT for touch-driven runtime     */
    INIT_BG_REARM_34_1_ACK,
    INIT_BG_REARM_34_2,
    INIT_BG_REARM_34_2_ACK,
    INIT_BG_REARM_DELAY,
    INIT_BG_REARM_AE,
    INIT_BG_REARM_AE_ACK,
    INIT_BG_REARM_32,
    INIT_BG_REARM_32_ACK,
    INIT_NUM_STATES
};

struct _FpDeviceGoodixGm168 {
    FpImageDevice parent;

    GoodixGM168TlsServer tls;
    gboolean             tls_done;

    guint8     *img_buf;
    gsize       img_len;
    gsize       img_cap;
    GByteArray *stitch_buf;
    guint32     stitch_expected; /* expected total B2 packet size, 0 = unknown */

    FpiUsbTransfer *poll_transfer;
    /* G8: single cancellable threaded through every fpi_usb_transfer_submit
     * call. dev_deactivate cancels it so in-flight reads abort within ms
     * instead of riding out their per-submit timeout (up to 2 s). Created
     * fresh in dev_activate, cancelled+unrefed in dev_deactivate.        */
    GCancellable   *io_cancellable;

    int      tls_retry;      /* iteration counter for the TLS receive loop */
    int      ack_retry;      /* re-listen counter for ack_cb and bg_rx_cb;
                              * reset every time a state advance happens     */
    gboolean deactivating;
    gboolean active_state;
    gboolean active_capture; /* TRUE while capture SSM runs -- suppress poll restart */

    /* Background (dark) reference, GM168_FRAME_PIXELS uint16 values in
     * row-major 64×80 layout. NULL until the BG-capture loop finishes
     * INIT_BG_LOOP_CHECK with bg_frames_captured == GM168_BG_FRAMES. */
    guint16 *background;
    /* Per-pixel accumulator used during multi-frame BG averaging. Sized
     * GM168_FRAME_PIXELS, freed once `background` is computed.            */
    guint32 *background_sum;
    int      bg_frames_captured;

    /* PSK bootstrap state, used only when psk.bin was missing at activate. */
    gboolean psk_loaded;
    guint8   sealed_psk[GOODIX_GM168_SEALED_PSK_LEN];
    guint32  sealed_offset;

    /* Quality-gated capture (Windows-style retry-until-good).
     *
     * Reverse-engineered from Wbdi.dll _LogicSwipeProcess + PreprocessSwipeImage:
     * Windows continuously captures while finger is on the sensor, runs each
     * frame through the preprocessor which returns (quality, coverage), and
     * keeps only frames with quality>=65 && coverage>=25. Best-of-N is the
     * actual submitted template. We replicate that here with a simpler
     * quality proxy (std-dev of central region, saturation gate).
     *
     * State across attempts within ONE touch event:
     *   best_img        — currently-best FpImage (we own a ref)
     *   best_quality    — its score (higher = better)
     *   capture_attempt — how many captures we've tried this touch
     *   capture_start_us — monotonic timestamp of first attempt
     * All four are reset at touch-detect (poll_cb) and after submit.       */
    FpImage *best_img;
    gfloat   best_quality;
    int      capture_attempt;
    gint64   capture_start_us;

    /* Dual-capture (Windows enroll pattern): take 2 frames per touch
     * without REARM between them, pick the better one.  Matches the
     * pcap-observed Windows flow (SCAN_TRIG → image → SCAN_TRIG → image
     * → FDT_SETUP) measured in patches/goodix.pcapng @ +7.427..+7.536s.
     * dual_pending_img holds frame #1 while we capture frame #2.       */
    FpImage *dual_pending_img;
    gfloat   dual_pending_quality;
    gboolean dual_in_second;        /* TRUE while waiting for frame #2  */

    /* G7: opt-in per-state timing trace. Enabled by $GM168_TRACE=1.      */
    GM168Trace trace;

    /* Structured per-session text log. Opened in dev_open, closed in
     * dev_close. Always-on: no env flag required.                       */
    Gm168Log log;
    int      log_stage_count;  /* # images submitted this activate session */

    /* G1: wall-clock deadline for the currently-running SSM. Set by
     * start_*_ssm helpers and checked at the top of each *_run_state
     * before the switch. 0 means "no deadline armed" (e.g. between
     * SSMs).                                                              */
    gint64 ssm_deadline_us;

    /* G3: once a callback sees G_USB_DEVICE_ERROR_NO_DEVICE, the device
     * is gone. We surface FP_DEVICE_ERROR_REMOVED to libfprint and stop
     * submitting new transfers. Reset on dev_activate.                   */
    gboolean device_dead;

    /* G11 (H8): consecutive CAP_RX timeouts within the current capture
     * cycle. Reset on every successful RX. After GM168_CAP_RX_RETRIG_AFTER
     * timeouts, jump to CAP_TRIG once to re-issue the scan command —
     * covers the case where the sensor "forgot" the trigger (e.g. after
     * a soft reset). Beyond that we let the watchdog or quality-gate
     * budget kill the capture.                                            */
    int capture_rx_timeouts;

    /* Persistent heap buffer for TLS decryption (GOODIX_GM168_EP_IN_SIZE bytes).
     * Replaces 5 × 16 KB stack buffers in the SSM states.                   */
    guint8  *tls_dec_buf;
};

#define GM168_CAP_RX_RETRIG_AFTER 2

/* Quality-gate tunables.
 *
 * THRESH — std-dev of central 48×64 region of the byte-stretched frame.
 *          Empirical: a touching-finger frame on this sensor sits at
 *          ~45-70; a dark/saturated frame sits below 15. Cal data:
 *          observe values via fp_dbg("quality=...") to refine.
 * MAX_ATTEMPTS — bound the loop so a flaky touch doesn't hang.
 * BUDGET_MS    — total wall-clock budget per touch. Windows uses 300ms
 *                (0x12c) as "submit threshold" + 600ms (0x258) as
 *                "too slow". 600ms is a safe upper bound.
 * RETRY_DELAY_MS — shorter REARM delay used between retry captures
 *                  (the regular submit path keeps 1500ms).             */
#define GM168_QUALITY_THRESH         25.0f
#define GM168_MAX_CAPTURE_ATTEMPTS   6
#define GM168_CAPTURE_BUDGET_MS      600
#define GM168_REARM_RETRY_DELAY_MS   200

/* G1: capture SSM deadline must exceed the quality-gate budget — otherwise
 * a healthy max-attempts capture would trip the watchdog. */
_Static_assert (GM168_CAPTURE_DEADLINE_MS > GM168_CAPTURE_BUDGET_MS,
                "G1: capture deadline must exceed budget");

/* PSK file paths — overridable via $GOODIX_GM168_DIR for non-root testing. */
static char *
gm168_psk_dir (void)
{
    const char *d = g_getenv ("GOODIX_GM168_DIR");
    return g_strdup (d ? d : "/etc/goodix-gm168");
}

/* Read 32 bytes from <dir>/psk.bin into goodix_gm168_psk. Silent on ENOENT
 * (first-run case), warns on size/IO mismatch. Returns TRUE iff PSK loaded. */
static gboolean
gm168_load_psk_from_file (void)
{
    g_autofree char *dir  = gm168_psk_dir ();
    g_autofree char *path = g_build_filename (dir, "psk.bin", NULL);
    g_autofree gchar *buf = NULL;
    gsize len = 0;
    GError *err = NULL;

    if (!g_file_get_contents (path, &buf, &len, &err)) {
        if (!g_error_matches (err, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            fp_warn ("goodix-gm168: cannot read %s: %s", path, err->message);
        g_clear_error (&err);
        return FALSE;
    }
    if (len != sizeof (goodix_gm168_psk)) {
        fp_warn ("goodix-gm168: %s wrong size %zu (want %zu)",
                 path, len, sizeof (goodix_gm168_psk));
        return FALSE;
    }
    memcpy (goodix_gm168_psk, buf, sizeof (goodix_gm168_psk));
    fp_dbg ("goodix-gm168: PSK loaded from %s", path);
    return TRUE;
}

/* Write the captured sealed blob to <dir>/sealed.bin. Returns the path (out)
 * for inclusion in the user-facing error message. */
static gboolean
gm168_save_sealed_blob (const guint8 *blob, gsize len,
                        char **out_path, GError **error)
{
    g_autofree char *dir = gm168_psk_dir ();
    g_mkdir_with_parents (dir, 0755);
    *out_path = g_build_filename (dir, "sealed.bin", NULL);
    return g_file_set_contents (*out_path, (const gchar *)blob,
                                (gssize)len, error);
}

G_DECLARE_FINAL_TYPE (FpDeviceGoodixGm168, fpi_device_goodix_gm168, FPI, DEVICE_GOODIX_GM168, FpImageDevice)
G_DEFINE_TYPE (FpDeviceGoodixGm168, fpi_device_goodix_gm168, FP_TYPE_IMAGE_DEVICE);

static void
append_to_buf (FpDeviceGoodixGm168 *self, const guint8 *data, gsize len)
{
    if (self->img_len + len > self->img_cap) {
        /*
         * Grow the buffer.  Start at 64 KiB, then double each time.
         * If a single chunk is larger than the doubled capacity (unusual
         * but theoretically possible), grow to exactly what is needed.
         * Update img_cap only *after* a successful realloc so the state
         * stays consistent if we ever bail out early.
         */
        gsize needed  = self->img_len + len;
        gsize new_cap = (self->img_cap == 0) ? 65536 : self->img_cap * 2;
        if (new_cap < needed)
            new_cap = needed;
        if (new_cap <= self->img_cap) {
            /* Overflow: img_cap is already at or past SIZE_MAX/2 */
            fp_err ("goodix-gm168: image buffer overflow, dropping %zu bytes", len);
            return;
        }
        self->img_buf = g_realloc (self->img_buf, new_cap);
        self->img_cap = new_cap;
    }
    memcpy (self->img_buf + self->img_len, data, len);
    self->img_len += len;
}

static void
on_tls_done (GoodixGM168TlsServer *tls, GError *error, gpointer ud)
{
    (void)tls;
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (ud);
    if (!error) {
        self->tls_done = TRUE;
        fp_dbg ("TLS HANDSHAKE DONE");
        {
            double ms = (self->log.init_start_us > 0)
                      ? (g_get_monotonic_time () - self->log.init_start_us) / 1000.0
                      : 0.0;
            GM168_LOG_TLS (&self->log, "✓ handshake done  (%.0f ms)", ms);
        }
    } else {
        fp_warn ("TLS error: %s", error->message);
        GM168_LOG_ERR (&self->log, "TLS failed: %s", error->message);
    }
}

/*
 * Decode one TLS plaintext frame (10560 payload bytes) into a 64×80 row-major
 * uint16 image (5120 pixels). Returns 0 on success, -1 on bad input size.
 *
 * Algorithm (verified pixel-perfect against Windows preprocessor output via
 * Frida — see RESEARCH.md "TL;DR — Final Algorithm"):
 *   1. de-pad: from each of 80 wire rows (132 bytes), keep the first 96 data
 *      bytes (the trailing 36 are zero padding) → 7680 bytes compact stream
 *   2. for each 6-byte group, unpack 4 × 12-bit pixels (b0..b5 → P0..P3)
 *      and write each pixel into out[(k%64)*80 + k/64], which inlines the
 *      80×64-to-64×80 transpose the Windows enclave performs.
 *
 * `in` must point at the 10560-byte payload (the TLS plaintext minus the
 * trailing 4-byte CRC — note that the first byte is *not* a header, the
 * data starts at offset 0).
 */

/* Envelope-based local contrast stretch.
 *
 * Reproduces the Windows Wbdi.dll preprocessor (sub_18010a460). Verified
 * byte-for-byte in a Python prototype against Frida-captured FRAME outputs.
 *
 * The trick: estimate the local DARK and BRIGHT envelopes (= min/max over
 * a window matching the ridge period) along rows and columns independently,
 * then per-pixel normalise: out = 0xff - ((px - low) * 255 / (high - low)).
 * Inversion at the end matches FPI_IMAGE_COLORS_INVERTED.
 *
 * Background reference is required: Windows runs a multi-stage FPN remover
 * inside its smoother (sub_180112a00 etc.) which we don't reproduce. Without
 * background subtraction, column-FPN dominates the 11-pixel envelope window
 * and the output collapses to noise. With `bg` we subtract per-pixel offset
 * and recenter into u16 before the rest of the pipeline runs as in Windows.
 *
 * `raw` is the freshly decoded u16 frame, `bg` the averaged dark reference
 * (may be NULL — then we run on raw directly, which is noisy but lets the
 * code still produce something during the BG-capture init window). `out`
 * receives the final u8 image.
 */
#define GM168_ENV_WIN   11   /* ridge-period-ish; matches Windows. */
#define GM168_ENV_HALF  (GM168_ENV_WIN / 2)

/* ---------------------------------------------------------------------------
 * Preprocessor stages.
 *
 * `gm168_envelope_stretch` is the orchestrator. Each stage is a small named
 * helper so we can A/B individual passes (toggle by editing the orchestrator
 * or via env flags) and so the math sits close to its comment.
 *
 * Convention: each helper takes pre-allocated input/output buffers sized
 * GM168_FRAME_PIXELS (= 80*64 guint16, or guint8 for the final stage). No
 * helper allocates persistent state.
 * ------------------------------------------------------------------------- */

/* Stage 0a (alternative) — Wbdi Cal2 stage, RE'd byte-perfect formula:
 *     out[i] = (cal1[i] - raw[i]) * 8192 / cal2[i]
 * where cal1[] is the "no-finger" bright reference (CAL_SECONDARY in
 * Frida dumps), cal2[] is the per-pixel gain (CAL_SCALE). Both ship as
 * static C arrays in gm168_cal.h (median over 18 Frida-captured frames,
 * SID 20260605023917 on the developer's sensor).
 *
 * Replaces the (raw - bg + 0x800) approach when GM168_USE_CAL2=1. Note
 * the polarity inversion: where the finger blocks light (raw < cal1),
 * the output is POSITIVE and proportional to the absorption. So the
 * output of cal2_stage is "fingerprint signal" in the right polarity
 * for the downstream Wbdi-style envelope/stretch.
 *
 * Output range: roughly [-X, +X] with X depending on (cal1-raw) span.
 * We saturate to [0, 0xFFFF] u16. Negative values get clamped to 0
 * (those are mostly bg-noisy pixels outside the finger anyway).
 *
 * Per-device limitation: the baked-in tables work on the dev sensor only.
 * Cross-device requires either re-capture or RE of the calib_windows.dat
 * → runtime cal1/cal2 transform inside preprocessor_init. */
static void
gm168_cal2_stage (const guint16 *raw, guint16 *out)
{
    const int N = GM168_FRAME_PIXELS;
    for (int i = 0; i < N; i++) {
        gint32 num = ((gint32) GM168_CAL1[i] - (gint32) raw[i]) * 8192;
        guint16 denom = GM168_CAL2[i];
        gint32 v;
        if (denom == 0) {
            v = 0;
        } else {
            /* Half-up rounding, matching Wbdi's `(num + denom/2) / denom`. */
            if (num >= 0)
                v = (num + denom / 2) / denom;
            else
                v = -(((-num) + denom / 2) / denom);
        }
        if (v < 0)        v = 0;
        if (v > 0xFFFF)   v = 0xFFFF;
        out[i] = (guint16) v;
    }
}

/* Stage 0a — FPN correction: subtract bg, recenter at 0x800 to stay in u16.
 * Without this the 3x3 binomial cannot kill column FPN and the envelope
 * downstream amplifies the noise. Pass-through (memcpy) when bg is NULL. */
static void
gm168_bg_subtract (const guint16 *raw, const guint16 *bg, guint16 *out)
{
    const int N = GM168_FRAME_PIXELS;
    if (!bg) {
        memcpy (out, raw, sizeof (guint16) * N);
        return;
    }
    for (int i = 0; i < N; i++) {
        gint32 d = (gint32) raw[i] - (gint32) bg[i] + 0x800;
        if (d < 0)      d = 0;
        if (d > 0xFFF)  d = 0xFFF;
        out[i] = (guint16) d;
    }
}

/* Stage 0b — 3x3 median, in-place on the bg-subtracted signal.
 * Kills isolated single-pixel outliers (flicker pixels whose temporal noise
 * doesn't average over GM168_BG_FRAMES, and the rare sensor speck). Median is
 * edge-preserving so it doesn't soften ridges. Borders pass through. */
static void
gm168_median3x3 (guint16 *buf)
{
    const int W = GM168_FRAME_W;
    const int H = GM168_FRAME_H;
    const int N = GM168_FRAME_PIXELS;
    guint16 *tmp = g_new (guint16, N);
    memcpy (tmp, buf, sizeof (guint16) * N);
    for (int y = 1; y < H - 1; y++) {
        for (int x = 1; x < W - 1; x++) {
            guint16 w[9];
            int k = 0;
            for (int dy = -1; dy <= 1; dy++)
                for (int dx = -1; dx <= 1; dx++)
                    w[k++] = tmp[(y+dy)*W + (x+dx)];
            for (int a = 1; a < 9; a++) {
                guint16 v = w[a]; int b = a - 1;
                while (b >= 0 && w[b] > v) { w[b+1] = w[b]; b--; }
                w[b+1] = v;
            }
            buf[y*W + x] = w[4];
        }
    }
    g_free (tmp);
}

/* Stage 0.5 — Wallis-style local-mean subtraction with mid-gray offset.
 * Byte-perfect port of Wbdi.dll sub_180112a00 (verified 2026-06-05 against
 * 35 SMOOTH_IN/MASK/OUT triples, SID 20260605004528, 0 mismatches).
 *
 * Per pixel: out = clamp_lo0(in - mean_window + 3000), mean over an 11x11
 * window clamped to bounds. We run with mask=all-ones, so the window count
 * is a closed form and we only need one integral image.
 *
 * OPT-IN via GM168_USE_WALLIS. Default off: enabling regresses enroll from
 * 5/5 to stage-3 fail because our downstream (HENV/VENV + percentile stretch)
 * is tuned for signals that still carry low-freq variation, which Wallis
 * removes. Re-enabling needs the matching port of sub_18010a460 (Wbdi's
 * own stretch), not just this smoother. */
static void
gm168_smooth_wallis (guint16 *buf)
{
    const int W = GM168_FRAME_W;
    const int H = GM168_FRAME_H;
    const int N = GM168_FRAME_PIXELS;
    const int R = 5;
    const guint32 OFFSET = 0xbb8;
    const int IW = W + 1;
    guint32 *iv = g_new0 (guint32, IW * (H + 1));
    for (int y = 0; y < H; y++) {
        guint32 row_sum = 0;
        for (int x = 0; x < W; x++) {
            row_sum += buf[y*W + x];
            iv[(y+1)*IW + (x+1)] = iv[y*IW + (x+1)] + row_sum;
        }
    }
    guint16 *tmp = g_new (guint16, N);
    for (int y = 0; y < H; y++) {
        int r0 = y - R; if (r0 < 0) r0 = 0;
        int r1 = y + R; if (r1 >= H) r1 = H - 1;
        for (int x = 0; x < W; x++) {
            int c0 = x - R; if (c0 < 0) c0 = 0;
            int c1 = x + R; if (c1 >= W) c1 = W - 1;
            guint32 sV = iv[(r1+1)*IW + (c1+1)]
                       - iv[r0*IW     + (c1+1)]
                       - iv[(r1+1)*IW + c0]
                       + iv[r0*IW     + c0];
            guint32 sM = (guint32)(r1 - r0 + 1) * (guint32)(c1 - c0 + 1);
            guint32 mean = (sV + sM / 2) / sM;     /* half-up rounding */
            gint32 v = (gint32) buf[y*W + x] - (gint32) mean + (gint32) OFFSET;
            if (v < 0) v = 0;
            tmp[y*W + x] = (guint16) v;
        }
    }
    memcpy (buf, tmp, sizeof (guint16) * N);
    g_free (tmp);
    g_free (iv);
}

/* Stage 1 — 3x3 binomial blur (1,2,1;2,4,2;1,2,1)/16. Byte-perfect match of
 * Wbdi.dll sub_180112820. `(s + 8) >> 4` reproduces the +2-inside / <<1 /
 * +4-outside rounding sequence there. Borders keep input value. */
static void
gm168_binomial3x3 (const guint16 *src, guint16 *out)
{
    const int W = GM168_FRAME_W;
    const int H = GM168_FRAME_H;
    const int N = GM168_FRAME_PIXELS;
    memcpy (out, src, sizeof (guint16) * N);
    for (int y = 1; y < H - 1; y++) {
        for (int x = 1; x < W - 1; x++) {
            int s = src[(y-1)*W + (x-1)]
                  + 2 * src[(y-1)*W + x]
                  + src[(y-1)*W + (x+1)]
                  + 2 * src[y*W + (x-1)]
                  + 4 * src[y*W + x]
                  + 2 * src[y*W + (x+1)]
                  + src[(y+1)*W + (x-1)]
                  + 2 * src[(y+1)*W + x]
                  + src[(y+1)*W + (x+1)];
            out[y*W + x] = (guint16) ((s + 8) >> 4);
        }
    }
}

/* Stage 2 — Horizontal sliding-window min/max, window = GM168_ENV_WIN.
 * Edge-replicate clamping on inputs. */
static void
gm168_envelope_h (const guint16 *src, guint16 *low, guint16 *high)
{
    const int W = GM168_FRAME_W;
    const int H = GM168_FRAME_H;
    for (int y = 0; y < H; y++) {
        const guint16 *row = src + y * W;
        for (int x = 0; x < W; x++) {
            guint16 mn = 0xFFFF, mx = 0;
            for (int dx = -GM168_ENV_HALF; dx <= GM168_ENV_HALF; dx++) {
                int xi = x + dx;
                if (xi < 0) xi = 0;
                if (xi >= W) xi = W - 1;
                guint16 v = row[xi];
                if (v < mn) mn = v;
                if (v > mx) mx = v;
            }
            low[y*W + x]  = mn;
            high[y*W + x] = mx;
        }
    }
}

/* Stage 3 — Vertical sliding-window min/max. */
static void
gm168_envelope_v (const guint16 *src, guint16 *low, guint16 *high)
{
    const int W = GM168_FRAME_W;
    const int H = GM168_FRAME_H;
    for (int x = 0; x < W; x++) {
        for (int y = 0; y < H; y++) {
            guint16 mn = 0xFFFF, mx = 0;
            for (int dy = -GM168_ENV_HALF; dy <= GM168_ENV_HALF; dy++) {
                int yi = y + dy;
                if (yi < 0) yi = 0;
                if (yi >= H) yi = H - 1;
                guint16 v = src[yi*W + x];
                if (v < mn) mn = v;
                if (v > mx) mx = v;
            }
            low[y*W + x]  = mn;
            high[y*W + x] = mx;
        }
    }
}

/* Stage 4 — Combine H+V envelopes into one overall envelope, in place on
 * the V buffers: low = min(low_h, low_v), high = max(high_h, high_v). */
static void
gm168_envelope_combine (const guint16 *low_h, const guint16 *high_h,
                        guint16 *low_v, guint16 *high_v)
{
    const int N = GM168_FRAME_PIXELS;
    for (int i = 0; i < N; i++) {
        if (low_h[i]  < low_v[i])  low_v[i]  = low_h[i];
        if (high_h[i] > high_v[i]) high_v[i] = high_h[i];
    }
}

/* Stage 5 — X-stencil morph close (port of sub_18010f1f0).
 *   Interior: 5-point X (center + NW/NE/SW/SE).
 *   Edges:    3-point — center plus the two diagonals on the inward side.
 *   Corners:  2-point — center plus the single inward diagonal partner.
 * high uses MIN (erodes); low uses MAX (dilates). */
static void
gm168_morph_close_x5 (const guint16 *low_in, const guint16 *high_in,
                      guint16 *low_out, guint16 *high_out)
{
    const int W = GM168_FRAME_W;
    const int H = GM168_FRAME_H;
    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            int i = y * W + x;
            guint16 hi = high_in[i];
            guint16 lo = low_in[i];
            int top    = (y == 0);
            int bot    = (y == H - 1);
            int left   = (x == 0);
            int right  = (x == W - 1);

            /* Collect the up to 4 diagonal partners that exist for this
             * pixel given its border position. */
            int partners[4];
            int np = 0;
            if (!top && !left)   partners[np++] = (y-1)*W + (x-1);
            if (!top && !right)  partners[np++] = (y-1)*W + (x+1);
            if (!bot && !left)   partners[np++] = (y+1)*W + (x-1);
            if (!bot && !right)  partners[np++] = (y+1)*W + (x+1);

            for (int k = 0; k < np; k++) {
                guint16 h = high_in[partners[k]];
                guint16 l = low_in [partners[k]];
                if (h < hi) hi = h;
                if (l > lo) lo = l;
            }
            high_out[i] = hi;
            low_out[i]  = lo;
        }
    }
}

/* Stage 0b — Finger-presence mask (Wbdi `sub_18010a460`'s `arg4+0x10`).
 *
 * For each pixel, average |raw - bg| over a 7x7 neighbourhood; if the
 * local signal strength is above GM168_MASK_THRESH (default 200 in
 * 12-bit ADC units), the pixel is "touched", otherwise "empty".
 *
 * The mask is consumed by `local_stretch` which only normalises
 * touched pixels — empty regions stay at the neutral init value (0x80)
 * and don't generate fake ridges that confuse NBIS MINDTCT.
 *
 * Without this gate our `local_stretch` reproduces Wbdi math but
 * stretches ADC noise everywhere; MINDTCT then either fails minutiae
 * extraction (~36 % of our captures in the wild) or invents bogus
 * minutiae in pure-noise zones which tank verify accuracy.
 *
 * If `bg` is NULL (very early init, no calibration done yet), the
 * mask is set to "all touched" — caller falls back to the legacy
 * stretch-everywhere behaviour. */
static void
gm168_finger_mask (const guint16 *raw, const guint16 *bg, guint8 *mask)
{
    const int W = GM168_FRAME_W;
    const int H = GM168_FRAME_H;
    const int R = 3;  /* 7x7 window */

    const gchar *env = g_getenv ("GM168_MASK_THRESH");
    const int thresh = env ? atoi (env) : 200;

    if (!bg) {
        memset (mask, 0xFF, (size_t) W * H);
        return;
    }

    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            int sum = 0, count = 0;
            for (int dy = -R; dy <= R; dy++) {
                int ny = y + dy;
                if (ny < 0 || ny >= H) continue;
                for (int dx = -R; dx <= R; dx++) {
                    int nx = x + dx;
                    if (nx < 0 || nx >= W) continue;
                    int d = (int) raw[ny * W + nx] - (int) bg[ny * W + nx];
                    if (d < 0) d = -d;
                    sum += d;
                    count++;
                }
            }
            int avg = count ? sum / count : 0;
            mask[y * W + x] = (avg > thresh) ? 0xFF : 0;
        }
    }
}

/* Stage 6 — Per-pixel normalisation + invert to NBIS polarity.
 *   v   = (signal - C) * 255 / (A - C)
 *   out = 0xff - clamp(v, 0, 255)
 *
 * Two cases get the neutral 0x80 instead of normalising:
 *
 * 1. A <= C (collapsed envelope) — happens in high-pressure saturated
 *    areas where the 11px window sits entirely on one ridge or in a
 *    uniform valley. Always masked.
 *
 * 2. A - C below GM168_WEAK_GAP env threshold — weak-signal zones,
 *    typically the empty corners where no finger is touching.  Without
 *    this mask the stretch happily normalises pure ADC noise into
 *    confident-looking fake ridges, which feeds bogus minutiae into
 *    NBIS and tanks verify accuracy.  Windows Wbdi flags but doesn't
 *    modify here — for our smaller sensor area, masking helps NBIS
 *    ignore the noise.  Default 0 = legacy behaviour (no masking);
 *    try 400-800 to see effect.  Units are 12-bit envelope counts.   */
static void
gm168_local_stretch (const guint16 *signal,
                     const guint16 *low, const guint16 *high,
                     const guint8 *mask,
                     guint8 *out)
{
    const int N = GM168_FRAME_PIXELS;
    const gchar *env = g_getenv ("GM168_WEAK_GAP");
    const gint32 weak_gap = env ? atoi (env) : 0;

    for (int i = 0; i < N; i++) {
        if (mask && mask[i] == 0) {
            /* Empty zone — leave at neutral so NBIS MINDTCT sees a
             * flat featureless area and doesn't try to find ridges
             * in pure ADC noise. */
            out[i] = 0x80;
            continue;
        }
        gint32 A = high[i];
        gint32 C = low[i];
        gint32 denom = A - C;
        if (denom <= weak_gap) {
            out[i] = 0x80;
        } else {
            gint32 v = ((gint32) signal[i] - C) * 255 / denom;
            if (v < 0)   v = 0;
            if (v > 255) v = 255;
            out[i] = (guint8) (0xFF - v);
        }
    }
}

/* Orchestrator: glue the stages together.
 *
 *  raw,bg -> [bg-sub + median] -> src
 *  src    -> [wallis (opt-in)] -> src        (GM168_USE_WALLIS=1 to enable)
 *  src    -> [binomial 3x3]    -> smoothed
 *  smoothed -> [HENV, VENV]    -> low_h/high_h, low_v/high_v
 *           -> [combine]       -> low_v/high_v (overall)
 *           -> [morph X5]      -> low_h/high_h (final A/C)
 *  smoothed,A,C -> [stretch]   -> out (u8)
 *
 * Each Wbdi-correspondence is documented on the helper. To skip a stage for
 * an A/B test, comment its call here — buffer aliasing is set up so that
 * skipping any stage still leaves the pipeline well-formed. */
static void
gm168_envelope_stretch (const guint16 *raw, const guint16 *bg, guint8 *out)
{
    const int N = GM168_FRAME_PIXELS;

    guint16 *src      = g_new (guint16, N);
    guint16 *smoothed = g_new (guint16, N);
    guint16 *low_h    = g_new (guint16, N);
    guint16 *high_h   = g_new (guint16, N);
    guint16 *low_v    = g_new (guint16, N);
    guint16 *high_v   = g_new (guint16, N);

    if (g_getenv ("GM168_USE_CAL2")) {
        /* Wbdi-style FPN+gain correction using baked-in cal1/cal2 tables.
         * Median and Wallis follow as in the Wbdi pipeline. */
        gm168_cal2_stage (raw, src);
        if (g_getenv ("GM168_USE_MEDIAN")) gm168_median3x3 (src);
        if (!g_getenv ("GM168_NO_WALLIS"))  gm168_smooth_wallis (src);
    } else {
        gm168_bg_subtract (raw, bg, src);
        if (bg) gm168_median3x3 (src);
        if (g_getenv ("GM168_USE_WALLIS"))
            gm168_smooth_wallis (src);
    }

    gm168_binomial3x3 (src, smoothed);
    gm168_envelope_h  (smoothed, low_h, high_h);
    gm168_envelope_v  (smoothed, low_v, high_v);
    gm168_envelope_combine (low_h, high_h, low_v, high_v);
    gm168_morph_close_x5 (low_v, high_v, low_h, high_h);

    /* Finger mask — gated by GM168_FINGER_MASK env, NULL = legacy path */
    guint8 *fmask = NULL;
    if (g_getenv ("GM168_FINGER_MASK")) {
        fmask = g_new0 (guint8, N);
        gm168_finger_mask (raw, bg, fmask);
    }

    /* Diagnostic: dump the per-pixel envelope gap (high - low) and the
     * finger mask so the single_touch renderer can show where the
     * pipeline is masking noise vs amplifying signal.  Same gate as
     * the frame dumps in capture_completed. */
    {
        const gchar *dump_dir = NULL;
#ifdef GM168_DEBUG
        dump_dir = g_getenv ("GM168_DUMP_DIR");
        if (!dump_dir) dump_dir = "/tmp";
#else
        if (g_getenv ("GM168_DUMP_FRAMES")) {
            dump_dir = g_getenv ("GM168_DUMP_DIR");
            if (!dump_dir) dump_dir = "/tmp";
        }
#endif
        if (dump_dir) {
            static int env_seq = 0;
            env_seq++;
            guint16 *gap = g_new (guint16, N);
            for (int i = 0; i < N; i++) {
                gint32 d = (gint32) high_h[i] - (gint32) low_h[i];
                if (d < 0) d = 0;
                if (d > 0xFFFF) d = 0xFFFF;
                gap[i] = (guint16) d;
            }
            g_autofree gchar *p_gap = g_strdup_printf ("%s/gm168_%03d_envgap.bin",
                                                       dump_dir, env_seq);
            FILE *f = fopen (p_gap, "wb");
            if (f) { fwrite (gap, 2, N, f); fclose (f); }
            g_free (gap);

            if (fmask) {
                g_autofree gchar *p_mask = g_strdup_printf ("%s/gm168_%03d_fmask.bin",
                                                            dump_dir, env_seq);
                FILE *fm = fopen (p_mask, "wb");
                if (fm) { fwrite (fmask, 1, N, fm); fclose (fm); }
            }
        }
    }

    gm168_local_stretch  (smoothed, low_h, high_h, fmask, out);

    g_free (src);
    g_free (smoothed);
    g_free (low_h);
    g_free (high_h);
    g_free (low_v);
    g_free (high_v);
    g_clear_pointer (&fmask, g_free);
}

static int
gm168_decode_frame (const guint8 *in, gsize in_len, guint16 *out)
{
    if (in_len < (gsize)(GM168_WIRE_ROWS * GM168_WIRE_ROW_STRIDE))
        return -1;

    guint8 compact[GM168_WIRE_ROWS * GM168_WIRE_ROW_DATA];
    for (int r = 0; r < GM168_WIRE_ROWS; r++)
        memcpy (compact + r * GM168_WIRE_ROW_DATA,
                in     + r * GM168_WIRE_ROW_STRIDE,
                GM168_WIRE_ROW_DATA);

    int k = 0;
    for (int i = 0; i < GM168_WIRE_ROWS * GM168_WIRE_ROW_DATA; i += 6) {
        guint8 b0 = compact[i+0], b1 = compact[i+1], b2 = compact[i+2];
        guint8 b3 = compact[i+3], b4 = compact[i+4], b5 = compact[i+5];
        guint16 pix[4] = {
            ((b0 & 0x0F) << 8) | b1,
            (b3 << 4)          | (b0 >> 4),
            ((b5 & 0x0F) << 8) | b2,
            (b4 << 4)          | (b5 >> 4),
        };
        for (int j = 0; j < 4; j++)
            out[((k + j) % GM168_FRAME_H) * GM168_FRAME_W
              + ((k + j) / GM168_FRAME_H)] = pix[j];
        k += 4;
    }
    return 0;
}



// --- ASYNC COMMAND HELPERS ---

static void
process_rx_buffer_for_tls(FpDeviceGoodixGm168 *self, const guint8 *buf, gsize len)
{
    gsize offset = 0;
    while (offset < len) {
        guint8 type = buf[offset];
        if (type == GOODIX_GM168_PKT_TLS) { // 0xB0 TLS record
            if (offset + 4 > len) break;
            guint16 b0_len = (guint16)buf[offset+1] | ((guint16)buf[offset+2] << 8);
            if (b0_len == 0 || offset + 4 + b0_len > len) break;
            goodix_gm168_tls_feed (&self->tls, buf + offset + 4, b0_len);
            offset += 4 + b0_len;
        } else if (type == GOODIX_GM168_PKT_CMD) { // 0xA0 Command ACK
            if (offset + 4 <= len) {
                guint16 a0_len = (guint16)buf[offset+1] | ((guint16)buf[offset+2] << 8);
                offset += 4 + a0_len;
            } else { break; }
        } else if (type == GOODIX_GM168_PKT_IMG) { // 0xB2 Image packet
            if (offset + 4 > len) break;           /* bounds check before reading length field */
            guint16 b2_len;
            const guint8 *tls_data = goodix_gm168_decode_img (buf + offset, len - offset, &b2_len);
            if (tls_data && b2_len > 0) {
                goodix_gm168_tls_feed (&self->tls, tls_data, b2_len);
            }
            guint16 total_len = (guint16)buf[offset+1] | ((guint16)buf[offset+2] << 8);
            offset += 4 + total_len;
        } else {
            break; // Drop anything unknown
        }
    }
}

static void
ack_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error);

/* G1 forward declarations — bodies live after ssm_advance_cb. */
static inline void gm168_ssm_deadline_set (FpDeviceGoodixGm168 *self, guint ms);
static gboolean    gm168_ssm_deadline_expired (FpDeviceGoodixGm168 *self,
                                               FpiSsm              *ssm,
                                               const char          *ssm_name);

/* G3 forward declaration. */
static gboolean    gm168_handle_fatal_usb_error (FpDeviceGoodixGm168 *self,
                                                 FpiSsm              *ssm,
                                                 GError             **error_p,
                                                 const char          *where);

/* Re-listen helper for ack_cb: re-arms the EP_IN read for the same SSM unless
 * we're shutting down or we've exceeded the retry budget. Returns TRUE if a
 * new transfer was submitted, FALSE if the SSM was failed instead. */
static gboolean
ack_resubmit_or_fail (FpDeviceGoodixGm168 *self, FpDevice *device, FpiSsm *ssm,
                      const char *reason)
{
    if (self->deactivating) {
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
            FP_DEVICE_ERROR_GENERAL, "ack_cb cancelled (deactivating)"));
        return FALSE;
    }
    if (++self->ack_retry > GM168_USB_RX_RETRY_LIMIT) {
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
            FP_DEVICE_ERROR_PROTO,
            "ack_cb stuck (%s): %d re-listens with no progress",
            reason, self->ack_retry));
        return FALSE;
    }
    FpiUsbTransfer *next = fpi_usb_transfer_new (device);
    fpi_usb_transfer_fill_bulk (next, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
    next->ssm = ssm;
    fpi_usb_transfer_submit (next, GM168_USB_RX_TIMEOUT_MS,
                             self->io_cancellable, ack_cb, NULL);
    return TRUE;
}

/* ACK callback — validates status and re-listens on transient non-ACK packets.
 * State advances reset ack_retry; without a cap a misbehaving sensor sending
 * only B0/empty packets would loop here forever. */
static void
ack_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (device);

    if (error) {
        if (gm168_handle_fatal_usb_error (self, transfer->ssm, &error, "ack_cb"))
            return;
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            fpi_ssm_mark_failed (transfer->ssm, error);
        else
            g_error_free (error);
        return;
    }

    if (transfer->actual_length > 0) {
        guint8 type = transfer->buffer[0];

        /* Debug: RAW hex dump of ANY incoming packet */
        GString *hs = g_string_new("");
        for (int i = 0; i < MIN(transfer->actual_length, 32); i++)
            g_string_append_printf(hs, "%02X ", transfer->buffer[i]);
        fp_dbg("ack_cb: RAW IN (%zd bytes): %s%s", transfer->actual_length, hs->str, 
               transfer->actual_length > 32 ? "..." : "");
        g_string_free(hs, TRUE);

        if (type == GOODIX_GM168_PKT_CMD) {
            /* A0 packets come in two flavours:
             *   IMMEDIATE: [A0][6][0][hsum][B0][pL][pH][echo][status][bsum]  buffer[4]=0xB0
             *   FINAL:     [A0][5][0][hsum][echo][2][0][status][bsum]        buffer[4]=echo_cmd
             *
             * Only advance the SSM on IMMEDIATE (buffer[4]==0xB0). FINAL ACKs are
             * trailing notifications that arrive in the *next* state's ack window
             * and must be drained without counting as progress, otherwise each
             * plaintext command causes a cascading one-state shift. */
            if (transfer->actual_length >= 5 &&
                transfer->buffer[4] != GOODIX_GM168_PKT_TLS) {
                /* FINAL ACK — drain and re-listen */
                fp_dbg ("ack_cb: A0 FINAL echo=0x%02X — re-listen",
                        transfer->buffer[4]);
                FpiUsbTransfer *t2 = fpi_usb_transfer_new (device);
                fpi_usb_transfer_fill_bulk (t2, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
                t2->ssm = transfer->ssm;
                fpi_usb_transfer_submit (t2, GM168_USB_RX_TIMEOUT_MS,
                                         self->io_cancellable, ack_cb, NULL);
                return;
            }
            if (transfer->actual_length >= 9) {
                guint8 echo   = transfer->buffer[7];
                guint8 status = transfer->buffer[8];
                fp_dbg ("ack_cb: A0 imm echo=0x%02X status=0x%02X",
                        echo, status);
                if (status == GOODIX_GM168_STATUS_BAD_CMD) {
                    fpi_ssm_mark_failed (transfer->ssm,
                                         fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                   "MCU rejected command (status=0xFF)"));
                    return;
                }
            }
            process_rx_buffer_for_tls (self, transfer->buffer, transfer->actual_length);
            self->ack_retry = 0;
            fpi_ssm_next_state (transfer->ssm);
        } else if (type == GOODIX_GM168_PKT_IMG) {
            /* Encrypted application packet (B2). Process whatever TLS data it
             * carries, then advance — capture-time B2 handling lives in the
             * capture SSM, not here. */
            fp_dbg ("ack_cb: received B2 packet (len %zd)", transfer->actual_length);
            process_rx_buffer_for_tls (self, transfer->buffer, transfer->actual_length);
            self->ack_retry = 0;
            fpi_ssm_next_state (transfer->ssm);
        } else {
            /* B0 (TLS handshake) or other packets during init — re-listen. */
            process_rx_buffer_for_tls (self, transfer->buffer, transfer->actual_length);
            ack_resubmit_or_fail (self, device, transfer->ssm, "non-A0 packet");
        }
    } else {
        /* Empty packet — re-listen. */
        ack_resubmit_or_fail (self, device, transfer->ssm, "empty packet");
    }
}

static void
transfer_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (device);
    if (error) {
        if (gm168_handle_fatal_usb_error (self, transfer->ssm, &error, "transfer_cb"))
            return;
        if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            fpi_ssm_mark_failed (transfer->ssm, error);
        else
            g_error_free(error);
        return;
    }
    fpi_ssm_next_state (transfer->ssm);
}

static void
async_send_cmd (FpiSsm *ssm, FpDevice *dev, guint8 cmd, const guint8 *payload, guint16 payload_len)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    guint32 pkt_len;
    guint8 *pkt = goodix_gm168_encode_cmd (cmd, payload, payload_len, &pkt_len);

    /* Log every outgoing packet (first 32 bytes inline). */
    {
        char label[16];
        snprintf (label, sizeof (label), "cmd=%02Xh", cmd);
        gm168_log_tx (&self->log, label, pkt, pkt_len);
    }

    FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_bulk_full (transfer, GOODIX_GM168_EP_OUT, pkt, pkt_len, g_free);
    transfer->ssm = ssm;
    fpi_usb_transfer_submit (transfer, GM168_USB_TX_TIMEOUT_MS,
                             self->io_cancellable, transfer_cb, NULL);
}

/* Submits an EP_IN read that funnels back into ack_cb, which validates the
 * packet type / status code before advancing the SSM. */
static void
async_recv_ack (FpiSsm *ssm, FpDevice *dev, int timeout_ms)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_bulk (transfer, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
    transfer->ssm = ssm;
    fpi_usb_transfer_submit (transfer, timeout_ms,
                             self->io_cancellable, ack_cb, NULL);
}


// --- DE-INITIALIZATION STATE MACHINE ---
enum deinit_states {
    DEINIT_POWER = 0,
    DEINIT_NUM_STATES
};

static void
deinit_run_state (FpiSsm *ssm, FpDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    gm168_trace_state (&self->trace, "DEINIT", fpi_ssm_get_cur_state (ssm));
    if (gm168_ssm_deadline_expired (self, ssm, "DEINIT")) return;

    switch (fpi_ssm_get_cur_state (ssm)) {
        case DEINIT_POWER:
            /* Was: async_send_cmd(POWER, 0x00 0x00) — power the sensor
             * off. Removed because fprintd does deactivate→activate
             * between every enroll stage, and the power-off → wake-up
             * cycle leaves the sensor's internal TLS state machine in
             * a confused state that breaks the next handshake (observed
             * with "SSL_accept failed" + watchdog timeout on stage 2).
             *
             * The sensor is bus-powered anyway; leaving it on between
             * activates costs nothing. INIT_RESET (0x60) at the top of
             * the next init still clears MCU session state.             */
            fpi_ssm_mark_completed (ssm);
            break;
        default:
            g_assert_not_reached ();
    }
}

static void
deinit_completed (FpiSsm *ssm, FpDevice *dev, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    FpImageDevice *img_dev = FP_IMAGE_DEVICE(dev);

    gm168_trace_ssm_done (&self->trace, "DEINIT");
    self->ssm_deadline_us = 0;

    /* G10 (M10): pass the error through to libfprint instead of swallowing
     * it. fprintd uses this to decide whether the device needs a re-probe.
     * Power-off failure usually means the sensor is wedged (e.g. cancelled
     * mid-TLS); surfacing the error gives the next layer up a chance to
     * react. fpi_image_device_deactivate_complete takes ownership of the
     * GError, so we don't free it here.                                  */
    if (error)
        fp_warn ("Deinit failed: %s", error->message);

    fpi_image_device_deactivate_complete (img_dev, error);
}


/* Generic timeout callback used by SSMs that need a brief delay between states */
static void
ssm_advance_cb (FpDevice *dev, gpointer user_data)
{
    FpiSsm *ssm = user_data;
    fpi_ssm_next_state (ssm);
}

/* G1: arm the SSM watchdog. Called from start_*_ssm helpers. ms=0 disarms. */
static inline void
gm168_ssm_deadline_set (FpDeviceGoodixGm168 *self, guint ms)
{
    self->ssm_deadline_us = ms
        ? g_get_monotonic_time () + (gint64)ms * 1000
        : 0;
}

/* G1: check the watchdog at the top of every *_run_state. Returns TRUE
 * (and fails the SSM) if the deadline has been reached. Caller should
 * `return` immediately after a TRUE result.                              */
static gboolean
gm168_ssm_deadline_expired (FpDeviceGoodixGm168 *self, FpiSsm *ssm,
                            const char *ssm_name)
{
    if (self->ssm_deadline_us == 0) return FALSE;
    if (g_get_monotonic_time () < self->ssm_deadline_us) return FALSE;
    fp_warn ("SSM watchdog: %s exceeded wall-clock deadline", ssm_name);
    self->ssm_deadline_us = 0; /* disarm so we don't double-fail */
    fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
        FP_DEVICE_ERROR_GENERAL,
        "%s SSM exceeded watchdog deadline", ssm_name));
    return TRUE;
}

/* G3: shared handler for terminal USB error classes. Call this at the top
 * of every USB callback's `if (error)` branch. Returns TRUE iff the error
 * was consumed (helper freed it, marked the SSM, and the caller should
 * `return`). FALSE means the caller should keep its existing handling
 * (TIMEOUT retry, CANCELLED silence, OTHER fail).
 *
 * Currently consumes:
 *   - NO_DEVICE: sets self->device_dead, surfaces FP_DEVICE_ERROR_REMOVED.
 * Future (G4) will also consume IO via recover_run_state.                */
static gboolean
gm168_handle_fatal_usb_error (FpDeviceGoodixGm168 *self, FpiSsm *ssm,
                              GError **error_p, const char *where)
{
    if (!error_p || !*error_p) return FALSE;
    GError *error = *error_p;
    GM168UsbErrorClass cls = gm168_classify_usb_error (error);
    if (cls == GM168_USB_ERR_NO_DEVICE) {
        fp_warn ("%s: device removed (NO_DEVICE) — marking dead", where);
        self->device_dead = TRUE;
        fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (
            FP_DEVICE_ERROR_REMOVED,
            "device disappeared during %s: %s", where, error->message));
        g_error_free (error);
        *error_p = NULL;
        return TRUE;
    }
    /* G4 hook lives here — IO class will become recoverable. For now,
     * other classes fall through to the caller's existing logic.        */
    return FALSE;
}

static void
init_tls_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    if (error) {
        if (g_error_matches(error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT)) {
            g_error_free (error);
            if (self->tls_done)
                fpi_ssm_jump_to_state (transfer->ssm, INIT_SET_PARAM);
            else {
                // Return to RX if still waiting
                fpi_ssm_jump_to_state (transfer->ssm, INIT_TLS_RX);
            }
            return;
        }
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }

    if (transfer->actual_length > 0) {
        process_rx_buffer_for_tls(self, transfer->buffer, transfer->actual_length);
    }
    fpi_ssm_next_state (transfer->ssm);
}


static void
init_tls_tx_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
    if (error) {
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }
    // Jump back to pull more until empty
    fpi_ssm_jump_to_state (transfer->ssm, INIT_TLS_TX_PULL);
}


/* Note: legacy PSK-provisioning helpers (init_psk_read_ack_cb,
 * init_psk_read_hash_ack_cb, async_send_tls_cmd) were removed. The 0x43
 * PSK_READ command is encrypted via TLS, and the sensor on this device is
 * already provisioned with the captured REAL_PSK, so reading the stored PSK
 * back is unnecessary. Unprovisioned / factory-reset MCUs would need IAP
 * mode + SetIapModeGeneva — out of scope for this driver. */

/* Scan a raw EP_IN buffer for an A0 packet whose echo_cmd matches `want`.
 * The MCU may emit stale B0/TLS packets between commands; we have to walk
 * the buffer the same way process_rx_buffer_for_tls does and only take the
 * A0 ACK that actually answers our cmd. Returns TRUE iff found, with extra
 * pointing inside `buf`. */
static gboolean
find_a0_ack (const guint8 *buf, gsize len, guint8 want,
             guint8 *status_out, guint8 **extra_out, guint16 *extra_len_out)
{
    gsize offset = 0;
    while (offset + 4 <= len) {
        guint8  type = buf[offset];
        guint16 ilen = (guint16)buf[offset+1] | ((guint16)buf[offset+2] << 8);
        gsize   pkt  = (gsize)4 + ilen;
        if (offset + pkt > len)
            return FALSE;
        if (type == GOODIX_GM168_PKT_CMD) {
            guint8  echo, status;
            guint8 *extra = NULL;
            guint16 extra_len = 0;
            if (goodix_gm168_decode_ack (buf + offset, pkt,
                                         &echo, &status, &extra, &extra_len) &&
                echo == want) {
                *status_out    = status;
                *extra_out     = extra;
                *extra_len_out = extra_len;
                return TRUE;
            }
        }
        offset += pkt;
    }
    return FALSE;
}

/* RX callback for INIT_PSK_READ_RECV: scans for the cmd 0xE4 A0 ACK in the
 * incoming buffer, copies its data slice into self->sealed_psk, then either
 * loops back to SEND for the next chunk or — once 324 bytes are gathered —
 * persists the blob and fails the SSM with instructions for the Windows
 * half. Non-A0 (TLS/B0) packets are tolerated and the read is re-armed. */
static void
psk_read_rx_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *error)
{
    (void)ud;
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    if (error) {
        fpi_ssm_mark_failed (t->ssm, error);
        return;
    }

    guint8  status = 0;
    guint8 *extra = NULL;
    guint16 extra_len = 0;
    if (!find_a0_ack (t->buffer, t->actual_length, GOODIX_GM168_CMD_SPEC_DATA,
                      &status, &extra, &extra_len)) {
        /* Stale ACK (e.g. version 0x20 still pending) or B0 noise — re-listen
         * on the SAME callback. Using ack_resubmit_or_fail would funnel the
         * next packet into ack_cb and skip past INIT_PSK_READ_RECV. */
        if (self->deactivating) {
            fpi_ssm_mark_failed (t->ssm, fpi_device_error_new_msg (
                FP_DEVICE_ERROR_GENERAL, "psk_read cancelled (deactivating)"));
            return;
        }
        if (++self->ack_retry > GM168_USB_RX_RETRY_LIMIT) {
            fpi_ssm_mark_failed (t->ssm, fpi_device_error_new_msg (
                FP_DEVICE_ERROR_PROTO,
                "cmd 0xE4 stuck: %d re-listens without E4 ack",
                self->ack_retry));
            return;
        }
        FpiUsbTransfer *next = fpi_usb_transfer_new (dev);
        fpi_usb_transfer_fill_bulk (next, GOODIX_GM168_EP_IN,
                                    GOODIX_GM168_EP_IN_SIZE);
        next->ssm = t->ssm;
        fpi_usb_transfer_submit (next, GM168_USB_RX_TIMEOUT_MS, self->io_cancellable, psk_read_rx_cb, NULL);
        return;
    }

    if (status != GOODIX_GM168_STATUS_OK || extra_len < 8) {
        fpi_ssm_mark_failed (t->ssm, fpi_device_error_new_msg (
            FP_DEVICE_ERROR_PROTO,
            "cmd 0xE4 NAK (status=%02x extra_len=%u)", status, extra_len));
        return;
    }

    /* extra layout: [tag_echo:4 LE][data_len:4 LE][data:N] */
    guint32 chunk = (guint32)extra[4]        |
                    (guint32)extra[5] <<  8  |
                    (guint32)extra[6] << 16  |
                    (guint32)extra[7] << 24;
    if (chunk > (guint32)(extra_len - 8) ||
        self->sealed_offset + chunk > sizeof (self->sealed_psk)) {
        fpi_ssm_mark_failed (t->ssm, fpi_device_error_new_msg (
            FP_DEVICE_ERROR_PROTO,
            "cmd 0xE4 bounds: chunk=%u extra=%u off=%u",
            chunk, extra_len, self->sealed_offset));
        return;
    }
    memcpy (self->sealed_psk + self->sealed_offset, extra + 8, chunk);
    self->sealed_offset += chunk;
    self->ack_retry = 0;

    if (self->sealed_offset < sizeof (self->sealed_psk)) {
        fpi_ssm_jump_to_state (t->ssm, INIT_PSK_READ_SEND);
        return;
    }

    /* Got all 324 bytes — persist and fail with a user-facing instruction. */
    g_autofree char *path = NULL;
    GError *save_err = NULL;
    if (!gm168_save_sealed_blob (self->sealed_psk, sizeof (self->sealed_psk),
                                 &path, &save_err)) {
        fpi_ssm_mark_failed (t->ssm, save_err);
        return;
    }
    fp_warn ("goodix-gm168: sealed PSK saved to %s", path);
    fpi_ssm_mark_failed (t->ssm, fpi_device_error_new_msg (
        FP_DEVICE_ERROR_GENERAL,
        "Sealed PSK written to %s. Boot into Windows, run "
        "tools/windows/gm168_unseal.ps1 -SealedBlob %s -OutPsk psk.bin, "
        "then copy psk.bin next to sealed.bin and re-run the driver.",
        path, path));
}

static void bg_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error);

static void
init_run_state (FpiSsm *ssm, FpDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    gm168_trace_state (&self->trace, "INIT", fpi_ssm_get_cur_state (ssm));
    if (gm168_ssm_deadline_expired (self, ssm, "INIT")) return;

    switch (fpi_ssm_get_cur_state (ssm)) {
        case INIT_WAKEUP:
            fp_dbg("INIT_WAKEUP");
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_WAKEUP, NULL, 0);
            break;
        case INIT_WAKEUP_DELAY:
            /* MCU does not ACK the WakeUp (0x11) — just wait briefly. */
            fpi_device_add_timeout (dev, GM168_WAKEUP_DELAY_MS, ssm_advance_cb, ssm, NULL);
            break;

        case INIT_RESET:
            fp_dbg("INIT_RESET - Clearing previous TLS state");
            {
                /* 0x60 resets MCU state; without it the MCU keeps replying
                 * with stale D0 (TLS_START) packets to subsequent requests.
                 */
                const guint8 p60[] = {0x01, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_SESSION_INIT, p60, 2);
            }
            break;
        case INIT_RESET_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;

        case INIT_VERSION:
            fp_dbg("INIT_VERSION");
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_VERSION, NULL, 0);
            break;
        case INIT_VERSION_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;

        case INIT_PSK_GATE:
            if (self->psk_loaded) {
                fpi_ssm_jump_to_state (ssm, INIT_TLS_START);
            } else {
                fp_warn ("goodix-gm168: psk.bin missing — reading sealed PSK from MCU");
                self->sealed_offset = 0;
                fpi_ssm_next_state (ssm);
            }
            break;

        case INIT_PSK_READ_SEND:
            {
                /* 16-byte body for cmd 0xE4: chunk_size, offset, tag, reserved
                 * (all u32 LE). See docs/PSK.md "MCU wire format for cmd 0xE4". */
                guint32 remaining = GOODIX_GM168_SEALED_PSK_LEN - self->sealed_offset;
                guint32 want = remaining < GOODIX_GM168_SEALED_PSK_CHUNK
                               ? remaining : GOODIX_GM168_SEALED_PSK_CHUNK;
                guint8 body[16] = {0};
                body[0]  =  want                & 0xFF;
                body[1]  = (want         >> 8)  & 0xFF;
                body[4]  =  self->sealed_offset & 0xFF;
                body[5]  = (self->sealed_offset >> 8) & 0xFF;
                /* tag 0xbb010002 stored as bytes 02 00 01 BB */
                body[8]  = (GOODIX_GM168_SEALED_PSK_TAG      ) & 0xFF;
                body[9]  = (GOODIX_GM168_SEALED_PSK_TAG >>  8) & 0xFF;
                body[10] = (GOODIX_GM168_SEALED_PSK_TAG >> 16) & 0xFF;
                body[11] = (GOODIX_GM168_SEALED_PSK_TAG >> 24) & 0xFF;
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_SPEC_DATA,
                                body, sizeof (body));
            }
            break;

        case INIT_PSK_READ_RECV:
            {
                FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
                fpi_usb_transfer_fill_bulk (t, GOODIX_GM168_EP_IN,
                                            GOODIX_GM168_EP_IN_SIZE);
                t->ssm = ssm;
                fpi_usb_transfer_submit (t, GM168_USB_RX_TIMEOUT_MS, self->io_cancellable, psk_read_rx_cb, NULL);
            }
            break;

        case INIT_TLS_START:
            {
                fp_dbg("INIT_TLS_START");
                const guint8 payload[] = {0x00, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_TLS_START, payload, 2);
            }
            break;
        case INIT_TLS_START_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;

        case INIT_TLS_RX:
            /* Cap TLS read loop iterations (~60s wall time). */
            if (self->tls_done) {
                self->tls_retry = 0;
                fpi_ssm_jump_to_state(ssm, INIT_SET_PARAM);
            } else if (++self->tls_retry > GM168_TLS_RETRY_LIMIT) {
                fpi_ssm_mark_failed (ssm,
                    fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                        "TLS handshake timeout after %d iterations",
                        GM168_TLS_RETRY_LIMIT));
            } else {
                FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
                fpi_usb_transfer_fill_bulk (t, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
                t->ssm = ssm;
                fpi_usb_transfer_submit (t, GM168_USB_RX_SHORT_TIMEOUT_MS, self->io_cancellable, init_tls_rx_cb, NULL);
            }
            break;

        case INIT_TLS_DELAY:
            fpi_device_add_timeout (dev, GM168_TLS_PUMP_DELAY_MS, ssm_advance_cb, ssm, NULL);
            break;

        case INIT_TLS_TX_PULL:
            {
                guint8 *tls_out = self->tls_dec_buf;
                int out_n = goodix_gm168_tls_pull (&self->tls, tls_out, GOODIX_GM168_EP_IN_SIZE);
                if (out_n > 0) {
                    guint32 b0_len;
                    guint8 *b0 = goodix_gm168_encode_tls (tls_out, (guint16)out_n, &b0_len);
                    FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
                    fpi_usb_transfer_fill_bulk_full (t, GOODIX_GM168_EP_OUT, b0, b0_len, g_free);
                    t->ssm = ssm;
                    fpi_usb_transfer_submit (t, GM168_USB_TX_TIMEOUT_MS, self->io_cancellable, init_tls_tx_cb, NULL);
                } else if (self->tls_done) {
                    /* TLS handshake done — proceed to session setup. The
                     * INIT_OTP_READ (cmd 0x43) state from the legacy LFSR
                     * seed-extraction path was removed: the sensor never
                     * answers it on already-provisioned devices and SSM
                     * would die on a 5 s timeout.                          */
                    self->tls_retry = 0;
                    fpi_ssm_jump_to_state (ssm, INIT_SET_PARAM);
                } else {
                    fpi_ssm_jump_to_state (ssm, INIT_TLS_RX);
                }
            }
            break;

        case INIT_SET_PARAM:
            fp_dbg("INIT_SET_PARAM");
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_SET_PARAM,
                            goodix_gm168_set_param, goodix_gm168_set_param_len);
            break;
        case INIT_SET_PARAM_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        case INIT_DEL_TMPL_1:
            fp_dbg("INIT_DEL_TMPL_1");
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_DEL_TMPL,
                            goodix_gm168_del_tmpl, goodix_gm168_del_tmpl_len);
            break;
        case INIT_DEL_TMPL_1_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        case INIT_DEL_TMPL_2:
            fp_dbg("INIT_DEL_TMPL_2");
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_DEL_TMPL,
                            goodix_gm168_del_tmpl, goodix_gm168_del_tmpl_len);
            break;
        case INIT_DEL_TMPL_2_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;

        case INIT_SESSION:
            fp_dbg("INIT_SESSION");
            {
                const guint8 p60[] = {0x01, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_SESSION_INIT, p60, 2);
            }
            break;
        case INIT_SESSION_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        case INIT_D6_POST:
            fp_dbg("INIT_D6_POST");
            {
                const guint8 d6[] = {0x00, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_POWER, d6, 2);
            }
            break;
        case INIT_D6_POST_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        case INIT_ARM:
            fp_dbg("INIT_ARM");
            {
                const guint8 pAE[] = {0x00, 0x01, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_IRQ_ARM, pAE, 3);
            }
            break;
        case INIT_ARM_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        case INIT_FDT:
            fp_dbg("INIT_FDT");
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_SETUP,
                            goodix_gm168_fdt_setup, goodix_gm168_fdt_setup_len);
            break;
        case INIT_FDT_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_LONG_TIMEOUT_MS);
            break;

        case INIT_BG_TRIG:
            fp_dbg ("INIT_BG_TRIG - capturing background frame");
            self->img_len = 0;
            g_byte_array_set_size (self->stitch_buf, 0);
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_SCAN_TRIGGER,
                            goodix_gm168_capture_payload,
                            goodix_gm168_capture_payload_len);
            break;

        case INIT_BG_RX:
            {
                FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
                fpi_usb_transfer_fill_bulk (t, GOODIX_GM168_EP_IN,
                                            GOODIX_GM168_EP_IN_SIZE);
                t->ssm = ssm;
                t->short_is_error = FALSE;
                fpi_usb_transfer_submit (t, GM168_USB_RX_TIMEOUT_MS, self->io_cancellable, bg_rx_cb, NULL);
            }
            break;

        case INIT_BG_PROCESS:
            {
                GByteArray *sb = self->stitch_buf;
                /* Parse stitch_buf identically to CAP_PROCESS: handle all
                 * three packet types (B0/B2/A0) and consume from the head.
                 * The previous version handled only B2+A0 and bailed on B0,
                 * making which captures contributed to the BG average
                 * non-deterministic across activations — a top suspect for
                 * "enroll OK / verify miss". */
                while (sb->len > 0) {
                    guint8 type = sb->data[0];
                    guint32 pkt_len = 0;

                    if (type == GOODIX_GM168_PKT_TLS) { /* B0 */
                        guint16 b0_inner = (sb->len >= 3) ?
                            ((guint16)sb->data[1] | ((guint16)sb->data[2] << 8)) : 0;
                        pkt_len = 4 + b0_inner;
                        if (sb->len < pkt_len || pkt_len == 0) break;

                        guint16 tls_len = 0;
                        const guint8 *tls = goodix_gm168_decode_tls (sb->data, pkt_len, &tls_len);
                        if (tls && tls_len > 0) {
                            goodix_gm168_tls_feed (&self->tls, tls, tls_len);
                            guint8 *dec = self->tls_dec_buf;
                            GError *err = NULL;
                            int dec_n = goodix_gm168_tls_recv (
                                &self->tls, dec, GOODIX_GM168_EP_IN_SIZE, &err);
                            if (dec_n > 0)
                                append_to_buf (self, dec, dec_n);
                            else if (err)
                                fp_err ("INIT_BG_PROCESS B0: TLS decrypt error: %s", err->message);
                            if (err) g_error_free (err);
                        }
                        g_byte_array_remove_range (sb, 0, pkt_len);

                    } else if (type == GOODIX_GM168_PKT_IMG) { /* B2 */
                        guint16 b2_inner = (sb->len >= 3) ?
                            ((guint16)sb->data[1] | ((guint16)sb->data[2] << 8)) : 0;
                        pkt_len = 4 + b2_inner;
                        if (sb->len < pkt_len || pkt_len == 0) break;

                        guint16 tls_len = 0;
                        const guint8 *tls = goodix_gm168_decode_img (sb->data, pkt_len, &tls_len);
                        if (tls && tls_len > 0) {
                            goodix_gm168_tls_feed (&self->tls, tls, tls_len);
                            guint8 *dec = self->tls_dec_buf;
                            GError *err = NULL;
                            int dec_n = goodix_gm168_tls_recv (
                                &self->tls, dec, GOODIX_GM168_EP_IN_SIZE, &err);
                            if (dec_n > 0)
                                append_to_buf (self, dec, dec_n);
                            else if (err)
                                fp_err ("INIT_BG_PROCESS B2: TLS decrypt error: %s", err->message);
                            if (err) g_error_free (err);
                        }
                        g_byte_array_remove_range (sb, 0, pkt_len);

                    } else if (type == GOODIX_GM168_PKT_CMD) { /* A0 */
                        guint16 a0_inner = (sb->len >= 3) ?
                            ((guint16)sb->data[1] | ((guint16)sb->data[2] << 8)) : 0;
                        pkt_len = 4 + a0_inner;
                        if (sb->len < pkt_len || pkt_len == 0) break;
                        g_byte_array_remove_range (sb, 0, pkt_len);

                    } else {
                        fp_dbg ("INIT_BG_PROCESS: unknown type=0x%02X — dropping stitch buffer", type);
                        g_byte_array_set_size (sb, 0);
                        break;
                    }
                }

                /* Match capture's gating: wait for the full TLS plaintext
                 * frame (incl. 4-byte trailer) before decoding. If short,
                 * loop back to RX to accumulate more — do NOT trigger a
                 * fresh capture, which would discard the partial frame. */
                if (self->img_len >= (gsize)GM168_TLS_FRAME_SIZE) {
                    guint16 tmp[GM168_FRAME_PIXELS];
                    if (gm168_decode_frame (self->img_buf, self->img_len, tmp) == 0) {
                        if (!self->background_sum)
                            self->background_sum =
                                g_new0 (guint32, GM168_FRAME_PIXELS);
                        for (int i = 0; i < GM168_FRAME_PIXELS; i++)
                            self->background_sum[i] += tmp[i];
                        self->bg_frames_captured++;
                        fp_dbg ("BG capture %d/%d",
                                self->bg_frames_captured, GM168_BG_FRAMES);
                    } else {
                        fp_warn ("INIT_BG_PROCESS: decode failed");
                    }
                    self->img_len = 0;
                    fpi_ssm_next_state (ssm); /* → INIT_BG_LOOP_CHECK */
                } else {
                    fp_dbg ("INIT_BG_PROCESS: partial frame %zu / %d, re-RX",
                            self->img_len, GM168_TLS_FRAME_SIZE);
                    fpi_ssm_jump_to_state (ssm, INIT_BG_RX);
                }
            }
            break;

        case INIT_BG_LOOP_CHECK:
            /* Loop back to BG_TRIG for more dark frames (no rearm between
             * captures — rearm would put sensor into "wait for touch" state
             * and a subsequent direct 0x20 hangs). Rearm runs only AFTER
             * the last frame, transitioning to runtime touch-driven mode. */
            if (self->bg_frames_captured < GM168_BG_FRAMES) {
                fp_dbg ("BG loop: %d/%d done, capturing more",
                        self->bg_frames_captured, GM168_BG_FRAMES);
                fpi_ssm_jump_to_state (ssm, INIT_BG_TRIG);
            } else {
                guint16 *bg = g_new (guint16, GM168_FRAME_PIXELS);
                for (int i = 0; i < GM168_FRAME_PIXELS; i++)
                    bg[i] = (guint16)(self->background_sum[i] /
                                      (guint32)self->bg_frames_captured);
                g_free (self->background);
                self->background = bg;
                g_clear_pointer (&self->background_sum, g_free);
                /* Verification log for the INIT_BG_PROCESS B0-fix:
                 * with no finger on the sensor, this checksum + min/max/sum
                 * must be reproducible across activations. Drift here = BG
                 * pipeline is still non-deterministic. */
                {
                    guint32 sum = 0, xorhash = 0;
                    guint16 lo = 0xFFFF, hi = 0;
                    for (int i = 0; i < GM168_FRAME_PIXELS; i++) {
                        sum += bg[i];
                        xorhash = (xorhash * 31u) ^ bg[i];
                        if (bg[i] < lo) lo = bg[i];
                        if (bg[i] > hi) hi = bg[i];
                    }
                    fp_dbg ("BG averaged %d frames: hash=0x%08X sum=%u min=%u max=%u",
                            self->bg_frames_captured, xorhash, sum, lo, hi);
                    {
                        double ms = (self->log.init_start_us > 0)
                                  ? (g_get_monotonic_time () - self->log.init_start_us) / 1000.0
                                  : 0.0;
                        GM168_LOG_BG (&self->log, "×%d  hash=%08Xh  (%.0f ms)",
                                      self->bg_frames_captured, xorhash, ms);
                    }
                }
                fpi_ssm_next_state (ssm); /* → INIT_BG_REARM_34_1 */
            }
            break;

        case INIT_BG_REARM_34_1:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_REARM,
                            goodix_gm168_fdt_rearm, goodix_gm168_fdt_rearm_len);
            break;
        case INIT_BG_REARM_34_1_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case INIT_BG_REARM_34_2:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_REARM,
                            goodix_gm168_fdt_rearm, goodix_gm168_fdt_rearm_len);
            break;
        case INIT_BG_REARM_34_2_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case INIT_BG_REARM_DELAY:
            fpi_device_add_timeout (dev, GM168_REARM_DELAY_MS, ssm_advance_cb, ssm, NULL);
            break;
        case INIT_BG_REARM_AE:
            {
                const guint8 ae[] = {0x00, 0x01, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_IRQ_ARM, ae, 3);
            }
            break;
        case INIT_BG_REARM_AE_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case INIT_BG_REARM_32:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_SETUP,
                            goodix_gm168_fdt_setup, goodix_gm168_fdt_setup_len);
            break;
        case INIT_BG_REARM_32_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;

        default:
            g_assert_not_reached ();
    }
}


static void start_polling(FpDeviceGoodixGm168 *self);
static void start_capture_ssm(FpDeviceGoodixGm168 *self);


static void
init_completed (FpiSsm *ssm, FpDevice *dev, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);

    gm168_trace_ssm_done (&self->trace, "INIT");
    self->ssm_deadline_us = 0;

    if (error) {
        fp_warn("Initialization failed: %s", error->message);
        GM168_LOG_ERR (&self->log, "init failed: %s", error->message);
        fpi_image_device_activate_complete (img_dev, error);
        return;
    }

    fp_dbg("Device completely armed and initialized");
    {
        double ms = (self->log.init_start_us > 0)
                  ? (g_get_monotonic_time () - self->log.init_start_us) / 1000.0
                  : 0.0;
        GM168_LOG_INIT (&self->log, "✓ armed  (%.0f ms)", ms);
    }
    self->log_stage_count = 0;
    fpi_image_device_activate_complete (img_dev, NULL);

    // We do NOT start polling for touch here.
    // libfprint will request it via change_state.
}



// --- CAPTURE STATE MACHINE ---
enum capture_states {
    CAP_TRIG = 0,
    CAP_RX,
    CAP_PROCESS,
    CAP_NUM_STATES
};

static void
capture_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    if (error) {
        if (gm168_handle_fatal_usb_error (self, transfer->ssm, &error, "capture_rx_cb"))
            return;
        if (g_error_matches(error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT)) {
            g_error_free (error);
            /* G11 (H8): after N consecutive RX timeouts the sensor
             * has likely forgotten the SCAN trigger (e.g. soft reset
             * mid-capture). Re-issue TRIG once; subsequent timeouts
             * still loop CAP_RX until the deadline / budget trips.    */
            self->capture_rx_timeouts++;
            if (self->capture_rx_timeouts == GM168_CAP_RX_RETRIG_AFTER) {
                fp_warn ("capture_rx_cb: %d consecutive timeouts — re-trigger",
                         self->capture_rx_timeouts);
                fpi_ssm_jump_to_state (transfer->ssm, CAP_TRIG);
            } else {
                fpi_ssm_jump_to_state (transfer->ssm, CAP_RX);
            }
            return;
        }
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }

    self->capture_rx_timeouts = 0;  /* G11 (H8): real RX → reset counter */
    g_byte_array_append (self->stitch_buf, transfer->buffer, transfer->actual_length);
    fpi_ssm_next_state(transfer->ssm);
}

/* Background capture rx callback — loops in INIT_BG_RX until enough data */
static void
bg_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    if (error) {
        if (gm168_handle_fatal_usb_error (self, transfer->ssm, &error, "bg_rx_cb"))
            return;
        /* Cancelled / deactivating: abort the SSM cleanly, do not keep
         * issuing reads against a closing device.                        */
        if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            fpi_ssm_mark_failed (transfer->ssm, error);
            return;
        }
        /* Timeout is OK — keep reading. Other errors: skip BG, continue. */
        if (!g_error_matches (error, G_USB_DEVICE_ERROR,
                              G_USB_DEVICE_ERROR_TIMED_OUT)) {
            fp_warn ("bg_rx_cb: error %s, skipping background", error->message);
        }
        g_error_free (error);
    } else if (transfer->actual_length > 0) {
        g_byte_array_append (self->stitch_buf, transfer->buffer,
                             transfer->actual_length);
    }

    if (self->stitch_buf->len >= (gsize)GM168_TLS_FRAME_SIZE) {
        self->ack_retry = 0;
        fpi_ssm_next_state (transfer->ssm);  /* → INIT_BG_PROCESS */
        return;
    }

    if (self->deactivating) {
        fpi_ssm_mark_failed (transfer->ssm, fpi_device_error_new_msg (
            FP_DEVICE_ERROR_GENERAL, "bg_rx_cb cancelled (deactivating)"));
        return;
    }
    if (++self->ack_retry > GM168_USB_RX_RETRY_LIMIT) {
        fpi_ssm_mark_failed (transfer->ssm, fpi_device_error_new_msg (
            FP_DEVICE_ERROR_PROTO,
            "bg_rx_cb stuck: %d re-listens, buf=%u/%d bytes",
            self->ack_retry, self->stitch_buf->len, GM168_TLS_FRAME_SIZE));
        return;
    }

    FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_bulk (t, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
    t->ssm = transfer->ssm;
    t->short_is_error = FALSE;
    fpi_usb_transfer_submit (t, GM168_USB_RX_TIMEOUT_MS, self->io_cancellable, bg_rx_cb, NULL);
}

static void start_rearm_ssm(FpDeviceGoodixGm168 *self, GError *enroll_err, FpImage *img);
static void start_rearm_retry_ssm(FpDeviceGoodixGm168 *self);
static void start_recover_ssm(FpDeviceGoodixGm168 *self); /* G4 */
static gfloat gm168_quality_metric (const guint8 *img);

static void
capture_run_state (FpiSsm *ssm, FpDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    gm168_trace_state (&self->trace, "CAP", fpi_ssm_get_cur_state (ssm));
    if (gm168_ssm_deadline_expired (self, ssm, "CAP")) return;

    switch (fpi_ssm_get_cur_state (ssm)) {
        case CAP_TRIG:
            fp_dbg("CAP_TRIG");
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_SCAN_TRIGGER,
                            goodix_gm168_capture_payload, goodix_gm168_capture_payload_len);
            break;

        case CAP_RX:
            {
                /* G2: cap the USB read at whatever's left of the quality-gate
                 * budget. Before this, CAP_RX submitted with a flat 1000 ms
                 * timeout while BUDGET_MS=600, so a sensor going quiet
                 * mid-capture cost up to 400 ms of dead air before the
                 * post-RX budget check could fire and submit best.
                 *
                 * Floor at 50 ms: even if budget is technically exhausted,
                 * give one final shot — quality-gate's accept check in
                 * capture_completed handles "budget elapsed" cleanly. The
                 * 50 ms is ~2× a typical good capture (~25 ms observed
                 * across G7 traces).                                       */
                gint64 elapsed_ms = self->capture_start_us
                    ? (g_get_monotonic_time () - self->capture_start_us) / 1000
                    : 0;
                gint64 remaining_ms = (gint64)GM168_CAPTURE_BUDGET_MS - elapsed_ms;
                if (remaining_ms < 50) remaining_ms = 50;
                guint timeout_ms = (guint)MIN ((gint64)GM168_USB_RX_SHORT_TIMEOUT_MS,
                                               remaining_ms);

                FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
                fpi_usb_transfer_fill_bulk (t, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
                t->ssm = ssm;
                t->short_is_error = FALSE;
                fpi_usb_transfer_submit (t, timeout_ms, self->io_cancellable, capture_rx_cb, NULL);
            }
            break;

        case CAP_PROCESS:
            {
                GByteArray *sb = self->stitch_buf;

                /* G11 (M7): if a previous CAP_PROCESS already decrypted a
                 * full frame and stitch_buf still has unprocessed tail bytes
                 * (next frame's prefix), don't loop through them — finish
                 * the current capture and let the next SSM run pick them
                 * up. Without this we'd waste a CAP_RX cycle.              */
                if (self->img_len >= (gsize)GM168_TLS_FRAME_SIZE) {
                    fp_dbg ("CAP_PROCESS: frame already complete (%zu bytes)",
                            self->img_len);
                    fpi_ssm_mark_completed (ssm);
                    return;
                }

                while (sb->len > 0) {
                    guint8 type = sb->data[0];
                    guint32 pkt_len = 0;

                    if (type == GOODIX_GM168_PKT_TLS) { /* B0 */
                        guint16 b0_inner = (sb->len >= 3) ? ((guint16)sb->data[1] | ((guint16)sb->data[2] << 8)) : 0;
                        pkt_len = 4 + b0_inner;
                        if (sb->len < pkt_len || pkt_len == 0) break;

                        guint16 tls_len = 0;
                        const guint8 *tls = goodix_gm168_decode_tls (sb->data, pkt_len, &tls_len);
                        if (tls && tls_len > 0) {
                            goodix_gm168_tls_feed (&self->tls, tls, tls_len);
                            /* Handshake usually happens in INIT, but keep for robustness */
                            guint8 *dec = self->tls_dec_buf;
                            GError *err = NULL;
                            int dec_n = goodix_gm168_tls_recv (&self->tls, dec, GOODIX_GM168_EP_IN_SIZE, &err);
                            if (dec_n > 0) {
                                append_to_buf (self, dec, dec_n);
                            } else if (err) {
                                /* dec_n==0 with err==NULL is SSL_ERROR_WANT_READ — normal, not an error */
                                fp_err("CAP_PROCESS B0: TLS decryption error: %s", err->message);
                                g_error_free (err);
                            }
                        }
                        g_byte_array_remove_range (sb, 0, pkt_len);

                    } else if (type == GOODIX_GM168_PKT_IMG) { /* B2 */
                        guint16 b2_inner = (sb->len >= 3) ? ((guint16)sb->data[1] | ((guint16)sb->data[2] << 8)) : 0;
                        pkt_len = 4 + b2_inner;
                        fp_dbg("CAP_PROCESS B2: sb->len=%u, b2_inner=%u, pkt_len=%u", sb->len, b2_inner, pkt_len);
                        if (sb->len < pkt_len || pkt_len == 0) {
                            fp_dbg("CAP_PROCESS B2: Need more data (sb->len < pkt_len)");
                            break;
                        }

                        guint16 tls_len = 0;
                        const guint8 *tls = goodix_gm168_decode_img (sb->data, pkt_len, &tls_len);
                        fp_dbg("CAP_PROCESS B2: decode_img returned tls=%p, tls_len=%u", tls, tls_len);
                        if (tls && tls_len > 0) {
                            goodix_gm168_tls_feed (&self->tls, tls, tls_len);
                            guint8 *dec = self->tls_dec_buf;
                            GError *err = NULL;
                            int dec_n = goodix_gm168_tls_recv (&self->tls, dec, GOODIX_GM168_EP_IN_SIZE, &err);
                            if (dec_n > 0) {
                                append_to_buf (self, dec, dec_n);
                            } else if (err) {
                                /* dec_n==0 with err==NULL is SSL_ERROR_WANT_READ — normal, not an error */
                                fp_err("CAP_PROCESS B2: TLS decryption error: %s", err->message);
                                g_error_free (err);
                            }

                            /* Accumulate until the full TLS plaintext frame
                             * has been decrypted (one frame can arrive across
                             * multiple B2 packets). */
                            if (self->img_len >= (gsize)GM168_TLS_FRAME_SIZE) {
                                fp_dbg ("CAP_PROCESS: B2 image fully decrypted (%zu bytes)",
                                        self->img_len);
                                fpi_ssm_mark_completed (ssm);
                                return;
                            } else {
                                fp_dbg ("CAP_PROCESS: B2 partial %d bytes, total %zu / %d",
                                        dec_n, self->img_len, GM168_TLS_FRAME_SIZE);
                            }
                        }
                        self->stitch_expected = 0;
                        g_byte_array_remove_range (sb, 0, pkt_len);

                    } else if (type == GOODIX_GM168_PKT_CMD) { /* A0 */
                        guint16 a0_inner = (sb->len >= 3) ? ((guint16)sb->data[1] | ((guint16)sb->data[2] << 8)) : 0;
                        pkt_len = 4 + a0_inner;
                        if (sb->len < pkt_len || pkt_len == 0) break;

                        guint8 echo = (pkt_len >= 8) ? sb->data[7] : 0;
                        fp_dbg ("CAP_PROCESS: CMD ACK echo=0x%02X len=%u", echo, pkt_len);
                        g_byte_array_remove_range (sb, 0, pkt_len);

                    } else {
                        /* G11 (H7): standard framing-resync — drop one byte
                         * and let the loop try again. Previous code wiped
                         * the entire buffer, which would lose legitimate
                         * data if a single byte was corrupted mid-stream.
                         * Garbage runs simply get shifted off until we hit
                         * a real type marker or empty the buffer.          */
                        fp_dbg ("CAP_PROCESS: unknown type=0x%02X — resync, drop 1 byte", type);
                        g_byte_array_remove_range (sb, 0, 1);
                    }
                }
                /* Need more data or buffer empty */
                fpi_ssm_jump_to_state (ssm, CAP_RX);
            }
            break;

        default:
            g_assert_not_reached ();
    }
}


static void
capture_completed (FpiSsm *ssm, FpDevice *dev, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    FpImageDevice *img_dev = FP_IMAGE_DEVICE(dev);

    gm168_trace_ssm_done (&self->trace, "CAP");
    self->ssm_deadline_us = 0;

    self->active_capture = FALSE;

    if (error) {
        if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            g_error_free(error);
            return;
        }
        /* Capture failed (timeout, decode etc). If quality-gate already
         * has a viable best from earlier attempts within this touch,
         * submit it instead of dropping the whole stage with an error —
         * this is the only thing that keeps us going when the sensor
         * stops answering after one bad/saturated frame mid-retry.
         * Also covers dual-capture: if dual #2 errored but #1 is in
         * dual_pending_img, submit #1. */
        FpImage *fallback = self->best_img ? self->best_img
                                           : self->dual_pending_img;
        gfloat   fallback_q = self->best_img ? self->best_quality
                                             : self->dual_pending_quality;
        if (fallback) {
            self->best_img             = NULL;
            self->best_quality         = 0.0f;
            self->dual_pending_img     = NULL;
            self->dual_pending_quality = 0.0f;
            self->dual_in_second       = FALSE;
            int submit_n               = self->capture_attempt;
            self->capture_attempt      = 0;
            fp_warn ("quality-gate: capture errored mid-retry — submit best q=%.2f after %d attempts (%s)",
                     fallback_q, submit_n, error->message);
            g_error_free (error);
            start_rearm_ssm (self, NULL, fallback);
            return;
        }
        fpi_image_device_session_error (img_dev, error);
        start_rearm_ssm (self, NULL, NULL);
        return;
    }

    fp_dbg("Capture completed. Image size: %zu", self->img_len);

    if (self->img_len >= (gsize)GM168_TLS_PAYLOAD_SIZE) {

        fp_dbg ("capture: decrypted %u-byte payload, head=%02X%02X%02X%02X%02X%02X%02X%02X",
                (guint32)self->img_len,
                self->img_buf[0], self->img_buf[1], self->img_buf[2], self->img_buf[3],
                self->img_buf[4], self->img_buf[5], self->img_buf[6], self->img_buf[7]);

#ifdef GM168_DEBUG
        {
            g_autoptr(GDateTime) now = g_date_time_new_now_local ();
            g_autofree gchar *filename =
                g_date_time_format (now, "capture_%Y%m%d_%H%M%S.bin");
            FILE *f = fopen (filename, "wb");
            if (f) {
                fwrite (self->img_buf, 1, self->img_len, f);
                fclose (f);
                fp_warn ("Raw decrypted payload saved to %s", filename);
            }
        }
#endif

        guint16 *raw16 = g_new (guint16, GM168_FRAME_PIXELS);
        if (gm168_decode_frame (self->img_buf, self->img_len, raw16) != 0) {
            g_free (raw16);
            GError *err = fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID);
            start_rearm_ssm (self, err, NULL);
            return;
        }

        FpImage *fp_img = fp_image_new (GM168_FRAME_W, GM168_FRAME_H);
        fp_img->flags = FPI_IMAGE_PARTIAL | FPI_IMAGE_COLORS_INVERTED;
        fp_img->ppmm = 19.685f; /* 500 DPI — required by NBIS MINDTCT */

        /* Envelope-based local contrast stretch — matches the Windows
         * preprocessor byte-for-byte on test captures (modulo the
         * smoother).  The earlier CLAHE+Gaussian pipeline lived behind
         * GM168_USE_CLAHE/GM168_NO_CLAHE flags for A/B comparison; the
         * envelope path consistently won, so the CLAHE branch was
         * dropped in Stage B cleanup. */
        gm168_envelope_stretch (raw16, self->background, fp_img->data);

        /* Diagnostic frame dump (raw16 / bg16 / final 8-bit) used by
         * scripts/single_touch.sh.  Triggered by either the compile-time
         * GM168_DEBUG flag (always-on debug build) or the runtime
         * GM168_DUMP_FRAMES env var (zero cost when unset).  The target
         * directory is GM168_DUMP_DIR if set, otherwise /tmp.            */
        {
            const gchar *dump_dir = NULL;
#ifdef GM168_DEBUG
            dump_dir = g_getenv ("GM168_DUMP_DIR");
            if (!dump_dir) dump_dir = "/tmp";
#else
            if (g_getenv ("GM168_DUMP_FRAMES")) {
                dump_dir = g_getenv ("GM168_DUMP_DIR");
                if (!dump_dir) dump_dir = "/tmp";
            }
#endif
            if (dump_dir) {
                static int dbg_seq = 0;
                dbg_seq++;
                g_autofree gchar *p_raw = g_strdup_printf ("%s/gm168_%03d_raw16.bin", dump_dir, dbg_seq);
                FILE *f1 = fopen (p_raw, "wb");
                if (f1) { fwrite (raw16, 2, GM168_FRAME_PIXELS, f1); fclose (f1); }
                if (self->background) {
                    g_autofree gchar *p_bg = g_strdup_printf ("%s/gm168_%03d_bg16.bin", dump_dir, dbg_seq);
                    FILE *f2 = fopen (p_bg, "wb");
                    if (f2) { fwrite (self->background, 2, GM168_FRAME_PIXELS, f2); fclose (f2); }
                }
                g_autofree gchar *p_pgm = g_strdup_printf ("%s/gm168_%03d_fpimg.pgm", dump_dir, dbg_seq);
                FILE *f4 = fopen (p_pgm, "wb");
                if (f4) {
                    fprintf (f4, "P5\n%d %d\n255\n", GM168_FRAME_W, GM168_FRAME_H);
                    fwrite (fp_img->data, 1, GM168_FRAME_PIXELS, f4);
                    fclose (f4);
                }
                fp_warn ("frame dump: seq=%d → %s/gm168_%03d_*", dbg_seq, dump_dir, dbg_seq);
            }
        }
        g_free (raw16);

        /* ── Quality-gate (Windows-style retry-until-good) ──────────────
         * Score this frame. Keep it as the current best if it beats
         * what we already have. Submit best when:
         *   - score ≥ THRESH (good enough), or
         *   - attempt count reached the cap, or
         *   - wall-clock budget exhausted.
         * Otherwise re-arm fast and capture another frame. */
        gfloat   q       = gm168_quality_metric (fp_img->data);
        gint64   now_us  = g_get_monotonic_time ();
        gint64   elapsed = (now_us - self->capture_start_us) / 1000; /* ms */
        self->capture_attempt++;

        fp_dbg ("quality-gate: attempt=%d quality=%.2f elapsed=%lldms (thresh=%.1f)",
                self->capture_attempt, q, (long long)elapsed,
                GM168_QUALITY_THRESH);

        /* Always keep at least one frame in best_img so the "submit on
         * timeout" path has something to send even when every capture
         * scored zero (e.g. all-saturated). Subsequent frames only
         * replace best if they strictly beat its score. */
        if (!self->best_img || q > self->best_quality) {
            if (self->best_img) g_object_unref (self->best_img);
            self->best_img     = fp_img;       /* ownership transfer */
            self->best_quality = q;
            fp_img = NULL;
        } else {
            g_object_unref (fp_img);
            fp_img = NULL;
        }

        /* Accept conditions, by priority:
         *   - first attempt was fully saturated (q==0): nothing to gain
         *     by retrying — this sensor doesn't deliver a fresh frame
         *     within the 200 ms quick-rearm window after a saturated
         *     capture (empirically observed: retry hangs until watchdog).
         *     Submit it; NBIS will reject and prompt the user for retry.
         *   - good enough already: thresh hit.
         *   - tried enough times.
         *   - wall-clock budget exhausted.                                 */
        gboolean accept = (self->best_quality == 0.0f                    ||
                           self->best_quality >= GM168_QUALITY_THRESH    ||
                           self->capture_attempt >= GM168_MAX_CAPTURE_ATTEMPTS ||
                           elapsed >= GM168_CAPTURE_BUDGET_MS);

        if (!accept && self->best_img) {
            /* Retry: short rearm, then another capture cycle. */
            GM168_LOG_CAP (&self->log, "best=%.2f  att=%d  %lldms  → RETRY",
                           self->best_quality, self->capture_attempt, (long long)elapsed);
            start_rearm_retry_ssm (self);
            return;
        }

        /* Dual-capture: after the first quality-accepted frame, fire a
         * second SCAN_TRIG WITHOUT rearm — finger is still on the sensor,
         * FDT is already consumed by the first capture.  This matches the
         * Windows enroll pattern observed in patches/goodix.pcapng and
         * doubles the minutiae coverage per touch. */
        if (!self->dual_in_second) {
            int attempts_so_far = self->capture_attempt;
            self->dual_pending_img     = self->best_img;
            self->dual_pending_quality = self->best_quality;
            self->best_img             = NULL;
            self->best_quality         = 0.0f;
            self->capture_attempt      = 0;
            self->dual_in_second       = TRUE;
            GM168_LOG_CAP (&self->log,
                           "q=%.2f  att=%d  %lldms  → DUAL #1, capturing #2",
                           self->dual_pending_quality, attempts_so_far,
                           (long long)elapsed);
            start_capture_ssm (self);
            return;
        }

        /* Second capture done — pick the better of the two. */
        self->dual_in_second = FALSE;
        FpImage *to_submit;
        gfloat   submit_q;
        if (self->best_quality > self->dual_pending_quality) {
            to_submit = self->best_img;
            submit_q  = self->best_quality;
            if (self->dual_pending_img)
                g_object_unref (self->dual_pending_img);
            GM168_LOG_CAP (&self->log,
                           "dual: pick #2  q=%.2f  (#1=%.2f dropped)",
                           submit_q, self->dual_pending_quality);
        } else {
            to_submit = self->dual_pending_img;
            submit_q  = self->dual_pending_quality;
            if (self->best_img)
                g_object_unref (self->best_img);
            GM168_LOG_CAP (&self->log,
                           "dual: pick #1  q=%.2f  (#2=%.2f dropped)",
                           submit_q, self->best_quality);
        }
        self->best_img             = NULL;
        self->best_quality         = 0.0f;
        self->dual_pending_img     = NULL;
        self->dual_pending_quality = 0.0f;
        self->capture_attempt      = 0;

        if (to_submit) {
            fp_warn ("quality-gate: SUBMIT (best of dual) quality=%.2f",
                     submit_q);
            self->log.last_quality = submit_q;
            GM168_LOG_CAP (&self->log, "q=%.2f  → SUBMIT", submit_q);
            start_rearm_ssm (self, NULL, to_submit);
        } else {
            /* Should not happen — first attempt always saves the frame as
             * best (initial best_quality is 0 and q is at least 0). Keep
             * the guard just in case. */
            GError *err = fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID);
            start_rearm_ssm (self, err, NULL);
        }

    } else {
        GError *err = fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID);
        start_rearm_ssm(self, err, NULL);
    }
}


static void
start_capture_ssm(FpDeviceGoodixGm168 *self)
{
    self->img_len = 0;
    self->stitch_expected = 0;
    g_byte_array_set_size(self->stitch_buf, 0);
    self->active_capture = TRUE;
    self->capture_rx_timeouts = 0;  /* G11 (H8) */

    gm168_ssm_deadline_set (self, GM168_CAPTURE_DEADLINE_MS);
    FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), capture_run_state, CAP_NUM_STATES);
    fpi_ssm_start (ssm, capture_completed);
}


// --- POLLING LOOP ---

static void
poll_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    FpImageDevice *img_dev = FP_IMAGE_DEVICE(dev);
    /* G10 (M9): clear early. The in-flight transfer has been consumed by
     * the time this callback runs (libfprint frees it on return), so this
     * pointer is the "do we expect another callback?" flag for the
     * idempotency guard in start_polling. Any restart path inside this
     * callback explicitly calls start_polling, which sees the NULL and
     * issues a new submit — exactly what we want. GLib serialises USB
     * callbacks on the main loop, so there is no concurrent reader.      */
    self->poll_transfer = NULL;

    if (error) {
        GM168UsbErrorClass cls = gm168_classify_usb_error (error);

        /* G3: device removed mid-poll. Surface FP_DEVICE_ERROR_REMOVED
         * to fprintd and stop. No SSM to fail here — we go through
         * image_device_session_error.                                    */
        if (cls == GM168_USB_ERR_NO_DEVICE) {
            fp_warn ("poll_cb: device removed (NO_DEVICE) — marking dead");
            self->device_dead = TRUE;
            g_error_free (error);
            fpi_image_device_session_error (img_dev,
                fpi_device_error_new_msg (FP_DEVICE_ERROR_REMOVED,
                    "device disappeared during poll"));
            return;
        }

        if (cls == GM168_USB_ERR_TIMEOUT) {
            g_error_free (error);
            if (!self->deactivating && self->active_state)
                start_polling(self);
            return;
        }

        if (cls == GM168_USB_ERR_CANCELLED) {
            g_error_free(error);
            return;
        }

        fp_warn("Poll failed: %s", error->message);
        fpi_image_device_session_error(img_dev, error);
        return;
    }

    if (transfer->actual_length >= 8) {
        guint8 *buf = transfer->buffer;
        /* Touch event: A0 packet with echo=0x32, status=0x02. */
        if (buf[0] == GOODIX_GM168_PKT_CMD &&
            transfer->actual_length >= GOODIX_GM168_TOUCH_PKT_LEN &&
            goodix_gm168_is_touch_event (buf, transfer->actual_length)) {
            fp_dbg ("*** Touch Detected (A0 echo=0x32 status=0x02) ***");
            gm168_log_touch_divider (&self->log);
            /* Fresh touch → reset quality-gate state. Previous best (if
             * any leaked through e.g. a deactivate mid-retry) is freed. */
            if (self->best_img) {
                g_object_unref (self->best_img);
                self->best_img = NULL;
            }
            if (self->dual_pending_img) {
                g_object_unref (self->dual_pending_img);
                self->dual_pending_img = NULL;
            }
            self->best_quality         = 0.0f;
            self->dual_pending_quality = 0.0f;
            self->dual_in_second       = FALSE;
            self->capture_attempt      = 0;
            self->capture_start_us     = g_get_monotonic_time ();

            fpi_image_device_report_finger_status (img_dev, TRUE);
            start_capture_ssm (self);
            return;
        }
        /* B0 packets seen during polling are not touch events — ignore. */
    }

    /* Do not restart polling while a capture is in flight. */
    if (!self->deactivating && self->active_state && !self->active_capture)
        start_polling(self);
}

static void
start_polling(FpDeviceGoodixGm168 *self)
{
    if (self->deactivating) return;
    /* Idempotent: poll_cb and dev_change_state can both invoke us. Without
     * this guard two concurrent in-flight transfers race on the same EP. */
    if (self->poll_transfer != NULL) {
        fp_dbg ("start_polling: already polling, skipping");
        return;
    }

    self->poll_transfer = fpi_usb_transfer_new (FP_DEVICE (self));
    fpi_usb_transfer_fill_bulk (self->poll_transfer, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
    self->poll_transfer->short_is_error = FALSE;
    fpi_usb_transfer_submit (self->poll_transfer, GM168_USB_RX_SHORT_TIMEOUT_MS, self->io_cancellable, poll_cb, NULL);
}


// --- QUALITY METRIC ---

/* Std-deviation of central 48x64 region of a 64x80 byte image, with a
 * saturation gate: returns 0 if the frame is mostly clamped to 0x00 or
 * 0xFF (those frames have meaningless std but cheat the metric).
 *
 * Why "central region": ridges live in the middle, the outer border on
 * this sensor is illumination falloff and hot pixels. The Windows
 * preprocessor checks coverage too — central crop is our cheap proxy.
 *
 * Why std-dev: real fingerprint frames after envelope-stretch have
 * substantial pixel spread (ridges vs valleys ~ 80-120 byte range);
 * dark/empty/saturated frames sit near a constant. Std-dev is the
 * cheapest, most robust single number that captures both. */
static gfloat
gm168_quality_metric (const guint8 *img)
{
    const int x0 = 16, x1 = 64;  /* central 48 cols out of W=80 */
    const int y0 = 8,  y1 = 56;  /* central 48 rows out of H=64 */
    const int n  = (x1 - x0) * (y1 - y0);
    guint32 sum = 0;
    int sat_lo = 0, sat_hi = 0;
    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            guint8 v = img[y * GM168_FRAME_W + x];
            sum += v;
            if (v <= 2)   sat_lo++;
            if (v >= 253) sat_hi++;
        }
    }
    gfloat sat_pct = (gfloat)(sat_lo + sat_hi) / (gfloat)n;
    if (sat_pct > 0.30f) return 0.0f;     /* too saturated → reject */

    gfloat mean = (gfloat)sum / (gfloat)n;
    gfloat ssd  = 0.0f;
    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            gfloat d = (gfloat)img[y * GM168_FRAME_W + x] - mean;
            ssd += d * d;
        }
    }
    return sqrtf (ssd / (gfloat)n);
}

// --- REARM STATE MACHINE ---

enum rearm_states {
    REARM_34_1 = 0,
    REARM_34_1_ACK,
    REARM_34_2,
    REARM_34_2_ACK,
    REARM_DELAY,
    REARM_AE,
    REARM_AE_ACK,
    REARM_32,
    REARM_32_ACK,
    REARM_WAIT_LIFT,
    REARM_NUM_STATES
};

// We store temporary data for rearm completion
struct RearmData {
    GError  *err;
    FpImage *img;
    /* TRUE = quality-gate wants another capture: skip finger-off report,
     * skip image_captured, just re-arm and start_capture_ssm again. */
    gboolean retry;
    /* TRUE = wait_lift_cb saw an FDT touch event (quick-tap), meaning
     * the FDT fired and was consumed.  On timeout we must jump back to
     * REARM_32 to re-arm FDT; without this start_polling listens on a
     * dead FDT and the sensor appears frozen.                          */
    gboolean consumed_touch;
    /* Number of times wait_lift_cb has already jumped back to REARM_32.
     * Capped at GM168_WAIT_LIFT_MAX_REARMS to break the residual-
     * capacitance loop where FDT re-fires immediately after every re-arm. */
    gint rearm32_count;
    /* Set when cap is reached: re-arm FDT in REARM_32 then skip the
     * wait_lift loop entirely.  Ensures polling starts with FDT armed. */
    gboolean fdt_rearm_only;
};


/* Submitted from REARM_WAIT_LIFT: re-listen while finger is present.
 * Advances SSM on timeout (finger gone) or explicit non-touch FDT packet. */
static void
wait_lift_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    if (error) {
        if (gm168_handle_fatal_usb_error (self, transfer->ssm, &error, "wait_lift_cb"))
            return;
        if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT)) {
            g_error_free (error);
            fp_dbg ("wait_lift: timeout — finger gone");
            /* If we consumed a touch event (FDT fired for a quick-tap),
             * the FDT is now disarmed.  Polling on a dead FDT means the
             * sensor will never deliver another touch event — the driver
             * appears frozen.  Jump back to REARM_32 to re-arm the FDT
             * before completing REARM.                                   */
            struct RearmData *rd = fpi_ssm_get_data (transfer->ssm);
            if (rd && rd->consumed_touch) {
                rd->consumed_touch = FALSE;
                if (rd->rearm32_count < GM168_WAIT_LIFT_MAX_REARMS) {
                    rd->rearm32_count++;
                    fp_dbg ("wait_lift: FDT consumed — re-arming REARM_32 (retry %d/%d)",
                            rd->rearm32_count, GM168_WAIT_LIFT_MAX_REARMS);
                    GM168_LOG_LIFT (&self->log, "✓ gone (FDT consumed) — re-arm");
                    fpi_ssm_jump_to_state (transfer->ssm, REARM_32);
                } else {
                    /* Cap reached: FDT is currently consumed (disarmed).
                     * Must re-arm it before completing REARM, otherwise
                     * start_polling waits forever on a dead FDT.
                     * Set fdt_rearm_only so REARM_WAIT_LIFT skips the
                     * wait and completes immediately after REARM_32.  */
                    fp_dbg ("wait_lift: FDT cap reached — re-arming FDT then completing");
                    GM168_LOG_LIFT (&self->log, "✓ gone (FDT cap — re-arm then done)");
                    rd->fdt_rearm_only = TRUE;
                    fpi_ssm_jump_to_state (transfer->ssm, REARM_32);
                }
            } else {
                GM168_LOG_LIFT (&self->log, "✓ finger gone");
                fpi_ssm_next_state (transfer->ssm);
            }
            return;
        }
        if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            /* fpi_ssm_mark_failed takes ownership of error — no need to free+alloc */
            fpi_ssm_mark_failed (transfer->ssm, error);
            return;
        }
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }

    /* G1 (freeze fix): The REARM deadline is normally checked at the top of
     * rearm_run_state(), i.e. only on state transitions.  wait_lift_cb
     * re-submits itself without advancing the SSM, so rapid or continuous
     * touches loop here forever — the deadline check in rearm_run_state
     * is never reached and the driver hangs indefinitely.
     *
     * Mirror the deadline check here so we bail out even when no state
     * transition has happened.  On expiry gm168_ssm_deadline_expired marks
     * the SSM failed, which fires rearm_completed(error) → start_recover_ssm
     * → recover_completed → start_polling, recovering the sensor.          */
    if (gm168_ssm_deadline_expired (self, transfer->ssm, "wait_lift")) return;

    const guint8 *buf = transfer->buffer;
    guint32 len = transfer->actual_length;

    if (goodix_gm168_is_touch_event (buf, len)) {
        /* Finger on sensor (or quick-tap): FDT just fired and was consumed
         * by this read.  Set consumed_touch so the timeout path knows to
         * re-arm FDT (REARM_32) before completing REARM.                 */
        struct RearmData *rd = fpi_ssm_get_data (transfer->ssm);
        if (rd) rd->consumed_touch = TRUE;
        /* Log channel capacitance values so we can distinguish real touch
         * from residual capacitance — bytes 11..22 of the 24-byte FDT pkt
         * are 6 × uint16-LE channel readings.                             */
        if (len >= GOODIX_GM168_TOUCH_PKT_LEN) {
            guint16 ch0 = buf[11] | ((guint16)buf[12] << 8);
            guint16 ch1 = buf[13] | ((guint16)buf[14] << 8);
            guint16 ch2 = buf[15] | ((guint16)buf[16] << 8);
            fp_dbg ("wait_lift: FDT touch  ch0=%u ch1=%u ch2=%u", ch0, ch1, ch2);
            GM168_LOG_LIFT (&self->log, "⚡ FDT touch  ch0=%u ch1=%u ch2=%u", ch0, ch1, ch2);
        } else {
            GM168_LOG_LIFT (&self->log, "⚡ FDT consumed (short pkt len=%u)", len);
        }
    } else if (len >= GOODIX_GM168_TOUCH_PKT_LEN &&
               buf[0] == GOODIX_GM168_PKT_CMD &&
               buf[GOODIX_GM168_TOUCH_ECHO_OFF] == GOODIX_GM168_CMD_FDT_SETUP) {
        /* FDT packet with non-touch status — explicit lift signal */
        fp_dbg ("wait_lift: FDT lift  status=0x%02X", buf[GOODIX_GM168_TOUCH_STATUS_OFF]);
        GM168_LOG_LIFT (&self->log, "✓ FDT lift  status=0x%02X", buf[GOODIX_GM168_TOUCH_STATUS_OFF]);
        fpi_ssm_next_state (transfer->ssm);
        return;
    } else {
        /* Some other packet (FINAL ACK, B0, etc.) — drain and re-listen */
        fp_dbg ("wait_lift: draining non-FDT packet (type=0x%02X len=%u)",
                len > 0 ? buf[0] : 0, len);
    }

    FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_bulk (t, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
    t->ssm = transfer->ssm;
    t->short_is_error = FALSE;
    fpi_usb_transfer_submit (t, GM168_WAIT_LIFT_POLL_MS,
                             self->io_cancellable, wait_lift_cb, NULL);
}

static void
rearm_run_state (FpiSsm *ssm, FpDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    gm168_trace_state (&self->trace, "REARM", fpi_ssm_get_cur_state (ssm));
    if (gm168_ssm_deadline_expired (self, ssm, "REARM")) return;

    switch (fpi_ssm_get_cur_state (ssm)) {
        case REARM_34_1:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_REARM,
                            goodix_gm168_fdt_rearm, goodix_gm168_fdt_rearm_len);
            break;
        case REARM_34_1_ACK:
            async_recv_ack(ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case REARM_34_2:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_REARM,
                            goodix_gm168_fdt_rearm, goodix_gm168_fdt_rearm_len);
            break;
        case REARM_34_2_ACK:
            async_recv_ack(ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case REARM_DELAY:
            {
                /* Submit path: GM168_REARM_DELAY_MS to let FDT settle before
                 * next touch. Retry path: GM168_REARM_RETRY_DELAY_MS — we
                 * know finger is still on and we want to capture another
                 * frame ASAP within our budget.                            */
                struct RearmData *rd = fpi_ssm_get_data (ssm);
                guint delay_ms = (rd && rd->retry)
                               ? GM168_REARM_RETRY_DELAY_MS
                               : GM168_REARM_DELAY_MS;
                fpi_device_add_timeout (dev, delay_ms, ssm_advance_cb, ssm, NULL);
            }
            break;
        case REARM_AE:
            {
                const guint8 ae[] = {0x00, 0x01, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_IRQ_ARM, ae, 3);
            }
            break;
        case REARM_AE_ACK:
            async_recv_ack(ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case REARM_32:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_SETUP,
                            goodix_gm168_fdt_setup, goodix_gm168_fdt_setup_len);
            break;
        case REARM_32_ACK:
            async_recv_ack(ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        case REARM_WAIT_LIFT:
            {
                struct RearmData *rd = fpi_ssm_get_data (ssm);
                if (rd && rd->retry) {
                    /* Quality-gate retry: finger is deliberately kept on.
                     * Skip lift-wait so we go directly to another capture. */
                    fpi_ssm_next_state (ssm);
                    break;
                }
                if (rd && rd->fdt_rearm_only) {
                    /* FDT cap was reached: REARM_32 just re-armed the FDT.
                     * Complete REARM immediately — polling will fire on the
                     * next real touch without waiting here. */
                    GM168_LOG_LIFT (&self->log, "✓ FDT re-armed, completing REARM");
                    fpi_ssm_next_state (ssm);
                    break;
                }
                fp_dbg ("wait_lift: watching for finger release");
                GM168_LOG_LIFT (&self->log, "watching…");
                FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
                fpi_usb_transfer_fill_bulk (t, GOODIX_GM168_EP_IN, GOODIX_GM168_EP_IN_SIZE);
                t->ssm = ssm;
                t->short_is_error = FALSE;
                fpi_usb_transfer_submit (t, GM168_WAIT_LIFT_POLL_MS,
                                         self->io_cancellable, wait_lift_cb, NULL);
            }
            break;
        default:
            g_assert_not_reached ();
    }
}

static void
rearm_completed (FpiSsm *ssm, FpDevice *dev, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    FpImageDevice *img_dev = FP_IMAGE_DEVICE(dev);
    struct RearmData *rd = fpi_ssm_get_data(ssm);

    gm168_trace_ssm_done (&self->trace, "REARM");
    self->ssm_deadline_us = 0;

    if (error) {
        /* G4 (closes M8): REARM is our level-1 recovery between captures.
         * If REARM itself failed the sensor is genuinely stuck — kick the
         * level-2 RECOVER SSM (0x60 + ARM + FDT + REARM chain). If RECOVER
         * also fails, recover_completed will surface the error properly.
         * In the meantime report finger-off so libfprint isn't holding
         * the "finger on" state through recovery.                          */
        fp_warn ("Rearm failed: %s — escalating to RECOVER", error->message);
        GM168_LOG_ERR (&self->log, "REARM failed: %s — escalating to RECOVER", error->message);
        g_error_free (error);
        /* Free any submitted-image data RearmData was holding — recover
         * means we're discarding this capture cycle.                       */
        if (rd->err) { g_error_free (rd->err); rd->err = NULL; }
        if (rd->img) { g_object_unref (rd->img); rd->img = NULL; }
        fpi_image_device_report_finger_status (img_dev, FALSE);
        start_recover_ssm (self);
        return;
    }

    /* Retry path: finger is still on (we hope), we want to grab another
     * frame for quality-gate. Skip finger-off + submit; just relaunch
     * the capture SSM. */
    if (rd->retry) {
        fp_dbg ("quality-gate: retry capture (attempt %d)",
                self->capture_attempt);
        if (!self->deactivating && self->active_state)
            start_capture_ssm (self);
        return;
    }

    /* Normal submit path — log REARM completion and stage result. */
    {
        double ms = (self->log.rearm_start_us > 0)
                  ? (g_get_monotonic_time () - self->log.rearm_start_us) / 1000.0
                  : 0.0;
        GM168_LOG_REARM (&self->log, "✓ armed  (%.0f ms)", ms);
        if (rd->img) {
            self->log_stage_count++;
            GM168_LOG_STAGE (&self->log, "#%d  q=%.2f  ✓",
                             self->log_stage_count, self->log.last_quality);
        } else if (rd->err) {
            GM168_LOG_STAGE (&self->log, "#%d  ✗  (%s)",
                             self->log_stage_count + 1, rd->err->message);
        }
    }

    fpi_image_device_report_finger_status(img_dev, FALSE);

    if (rd->err) {
        fpi_image_device_session_error(img_dev, rd->err);
    } else if (rd->img) {
        fpi_image_device_image_captured(img_dev, rd->img);
    }

    // Do not auto-resume polling here. wait for next change_state unless we're already supposed to be capturing
    if (!self->deactivating && self->active_state) {
         start_polling(self);
    }
}

static void
start_rearm_ssm(FpDeviceGoodixGm168 *self, GError *enroll_err, FpImage *img)
{
    self->log.rearm_start_us = g_get_monotonic_time ();
    GM168_LOG_REARM (&self->log, "▶");
    gm168_ssm_deadline_set (self, GM168_REARM_DEADLINE_MS);
    FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), rearm_run_state, REARM_NUM_STATES);
    struct RearmData *rd = g_malloc0(sizeof(struct RearmData));
    rd->err = enroll_err;
    rd->img = img;
    rd->retry = FALSE;
    fpi_ssm_set_data(ssm, rd, g_free);
    fpi_ssm_start (ssm, rearm_completed);
}

/* Like start_rearm_ssm but keeps the touch session alive: no finger-off
 * report, no image submission, capture SSM is relaunched in
 * rearm_completed. Used by the quality-gate retry loop in
 * capture_completed. */
static void
start_rearm_retry_ssm(FpDeviceGoodixGm168 *self)
{
    self->log.rearm_start_us = g_get_monotonic_time ();
    GM168_LOG_REARM (&self->log, "▶ (retry)");
    gm168_ssm_deadline_set (self, GM168_REARM_DEADLINE_MS);
    FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), rearm_run_state, REARM_NUM_STATES);
    struct RearmData *rd = g_malloc0(sizeof(struct RearmData));
    rd->retry = TRUE;
    fpi_ssm_set_data(ssm, rd, g_free);
    fpi_ssm_start (ssm, rearm_completed);
}

// --- G4: RECOVER STATE MACHINE -----------------------------------------
//
// Mid-session sensor wedge recovery. Mirrors a slice of init:
//   * skip WAKEUP — sensor is already powered
//   * skip TLS — session stays alive (0x60 SESSION_INIT does NOT here
//     trigger D0/TLS_START; that only happens when called pre-handshake)
//   * skip BG×5 — cached background reused (no fresh dark capture)
//
// Sequence: 0x60 SESSION_INIT → 0xAE ARM → 0x32 FDT → REARM chain
// (34 / 34 / 1500 ms / AE / 32) → sensor back in touch-wait state.
//
// Triggered from rearm_completed when REARM itself fails. If RECOVER
// fails too, the error surfaces to libfprint (image_device_session_error)
// — beyond this point we'd need full reinit (G6, TLS re-handshake).
enum recover_states {
    RECOVER_SESSION = 0,
    RECOVER_SESSION_ACK,
    RECOVER_ARM,
    RECOVER_ARM_ACK,
    RECOVER_FDT,
    RECOVER_FDT_ACK,
    RECOVER_34_1,
    RECOVER_34_1_ACK,
    RECOVER_34_2,
    RECOVER_34_2_ACK,
    RECOVER_DELAY,
    RECOVER_AE,
    RECOVER_AE_ACK,
    RECOVER_32,
    RECOVER_32_ACK,
    RECOVER_NUM_STATES
};

static void
recover_run_state (FpiSsm *ssm, FpDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    gm168_trace_state (&self->trace, "RECOVER", fpi_ssm_get_cur_state (ssm));
    if (gm168_ssm_deadline_expired (self, ssm, "RECOVER")) return;

    switch (fpi_ssm_get_cur_state (ssm)) {
        case RECOVER_SESSION:
            {
                const guint8 p60[] = {0x01, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_SESSION_INIT, p60, 2);
            }
            break;
        case RECOVER_SESSION_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        case RECOVER_ARM:
            {
                const guint8 pAE[] = {0x00, 0x01, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_IRQ_ARM, pAE, 3);
            }
            break;
        case RECOVER_ARM_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        case RECOVER_FDT:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_SETUP,
                            goodix_gm168_fdt_setup, goodix_gm168_fdt_setup_len);
            break;
        case RECOVER_FDT_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_LONG_TIMEOUT_MS);
            break;
        case RECOVER_34_1:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_REARM,
                            goodix_gm168_fdt_rearm, goodix_gm168_fdt_rearm_len);
            break;
        case RECOVER_34_1_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case RECOVER_34_2:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_REARM,
                            goodix_gm168_fdt_rearm, goodix_gm168_fdt_rearm_len);
            break;
        case RECOVER_34_2_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case RECOVER_DELAY:
            fpi_device_add_timeout (dev, GM168_REARM_DELAY_MS, ssm_advance_cb, ssm, NULL);
            break;
        case RECOVER_AE:
            {
                const guint8 ae[] = {0x00, 0x01, 0x00};
                async_send_cmd (ssm, dev, GOODIX_GM168_CMD_IRQ_ARM, ae, 3);
            }
            break;
        case RECOVER_AE_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_SHORT_TIMEOUT_MS);
            break;
        case RECOVER_32:
            async_send_cmd (ssm, dev, GOODIX_GM168_CMD_FDT_SETUP,
                            goodix_gm168_fdt_setup, goodix_gm168_fdt_setup_len);
            break;
        case RECOVER_32_ACK:
            async_recv_ack (ssm, dev, GM168_USB_RX_TIMEOUT_MS);
            break;
        default:
            g_assert_not_reached ();
    }
}

static void
recover_completed (FpiSsm *ssm, FpDevice *dev, GError *error)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);

    gm168_trace_ssm_done (&self->trace, "RECOVER");
    self->ssm_deadline_us = 0;

    if (error) {
        fp_warn ("RECOVER failed: %s — surfacing to libfprint", error->message);
        GM168_LOG_ERR (&self->log, "RECOVER failed: %s", error->message);
        fpi_image_device_session_error (img_dev, error);
        return;
    }

    fp_dbg ("RECOVER OK — sensor back to touch-wait, resuming polling");
    GM168_LOG_RECOV (&self->log, "✓ sensor recovered — resuming polling");
    /* Quality-gate state was tied to a touch that recover interrupted —
     * drop it so the next touch starts fresh.                           */
    g_clear_object (&self->best_img);
    self->best_quality      = 0.0f;
    self->capture_attempt   = 0;
    self->capture_start_us  = 0;

    if (!self->deactivating && self->active_state)
        start_polling (self);
}

static void
start_recover_ssm (FpDeviceGoodixGm168 *self)
{
    fp_warn ("starting RECOVER SSM");
    GM168_LOG_RECOV (&self->log, "▶ sensor stuck — starting RECOVER");
    gm168_ssm_deadline_set (self, GM168_RECOVER_DEADLINE_MS);
    FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), recover_run_state, RECOVER_NUM_STATES);
    fpi_ssm_start (ssm, recover_completed);
}

// --- STANDARD LIBFPRINT APIs ---

static void dev_activate (FpImageDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    self->deactivating  = FALSE;
    self->device_dead   = FALSE; /* G3 */
    self->active_capture = FALSE;
    self->ack_retry     = 0;
    self->stitch_expected = 0;
    self->sealed_offset = 0;

    /* Quality-gate state: drop any leftover best from a prior session. */
    g_clear_object (&self->best_img);
    g_clear_object (&self->dual_pending_img);
    self->best_quality         = 0.0f;
    self->dual_pending_quality = 0.0f;
    self->dual_in_second       = FALSE;
    self->capture_attempt      = 0;
    self->capture_start_us     = 0;

    /* G8: fresh cancellable per activate. g_clear_object first guards
     * against re-activate without dev_deactivate (e.g. fprintd restart). */
    g_clear_object (&self->io_cancellable);
    self->io_cancellable = g_cancellable_new();

    if (!self->stitch_buf)
        self->stitch_buf = g_byte_array_new();
    if (!self->tls_dec_buf)
        self->tls_dec_buf = g_malloc (GOODIX_GM168_EP_IN_SIZE);

    /* G7: trace timer reset for this activate. */
    gm168_trace_init (&self->trace);

    /* FAST PATH — reuse existing TLS session across deactivate/activate.
     *
     * fprintd cycles deactivate→activate between every enroll stage. The
     * sensor keeps its TLS session alive across this cycle; sending it a
     * second TLS_START (0xD0) leaves it deaf — it ACKs but never sends
     * handshake bytes back (observed: INIT_TLS_RX loops until watchdog).
     *
     * If TLS is still alive AND the background is cached, skip init
     * entirely. After the previous capture's REARM the sensor is in
     * touch-wait state; change_state(AWAIT_FINGER_ON) will start polling
     * and we're ready immediately.                                       */
    if (self->tls.ssl != NULL && self->tls_done && self->background != NULL) {
        fp_dbg ("dev_activate: fast path — TLS+BG cached, skipping init");
        self->log_stage_count = 0;
        GM168_LOG_INIT (&self->log, "▶ fast path — TLS+BG cached");
        fpi_image_device_activate_complete (dev, NULL);
        return;
    }

    /* SLOW PATH — full init. Either first activate or recovery from a
     * teardown (dev_close, error path). Free any half-initialised TLS
     * first.                                                              */
    self->tls_retry          = 0;
    self->bg_frames_captured = 0;
    self->psk_loaded         = gm168_load_psk_from_file ();
    g_clear_pointer (&self->background_sum, g_free);
    g_clear_pointer (&self->background, g_free);

    if (self->tls.ssl != NULL)
        goodix_gm168_tls_deinit (&self->tls);

    /* USB device reset to force the sensor to drop any stale TLS session
     * left over from a previous fprintd process. Without this, after a
     * fprintd restart the sensor sees our new TLS_START while it still
     * has the old session active, and responds with stale encrypted
     * records → SSL_accept fails with "unexpected message" → watchdog.
     * Release+reset+claim is the standard libusb dance for this.         */
    {
        GUsbDevice *udev = fpi_device_get_usb_device (FP_DEVICE (dev));
        g_usb_device_release_interface (udev, 0, 0, NULL);
        g_usb_device_reset (udev, NULL);
        GError *claim_err = NULL;
        g_usb_device_claim_interface (udev, 0, 0, &claim_err);
        if (claim_err) {
            fp_warn ("usb_reset: claim_interface failed: %s",
                     claim_err->message);
            fpi_image_device_activate_complete (dev, claim_err);
            return;
        }
    }

    GError *err = NULL;
    self->tls_done = FALSE;
    self->tls.on_connected = on_tls_done;
    self->tls.user_data = self;

    if (!goodix_gm168_tls_init (&self->tls, &err)) {
        fpi_image_device_activate_complete (dev, err);
        return;
    }

    self->log.init_start_us = g_get_monotonic_time ();
    GM168_LOG_INIT (&self->log, "▶ full init");
    gm168_ssm_deadline_set (self, GM168_INIT_DEADLINE_MS);
    FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (dev), init_run_state, INIT_NUM_STATES);
    fpi_ssm_start (ssm, init_completed);
}

static void dev_deactivate (FpImageDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    self->deactivating = TRUE;

    /* Free any quality-gate state that survived the session — prevents
     * us from submitting a stale image on the next activate.  Mirrors
     * the reset in dev_activate so a dual-capture that's caught mid-
     * flight doesn't hold a ~10 KiB FpImage hostage until the next
     * activation. */
    g_clear_object (&self->best_img);
    g_clear_object (&self->dual_pending_img);
    self->best_quality         = 0.0f;
    self->dual_pending_quality = 0.0f;
    self->dual_in_second       = FALSE;
    self->capture_attempt      = 0;

    if (self->io_cancellable) {
        g_cancellable_cancel(self->io_cancellable);
        g_object_unref(self->io_cancellable);
        self->io_cancellable = NULL;
    }

    /* We deliberately do NOT call goodix_gm168_tls_cancel here. fprintd
     * cycles deactivate→activate between enroll stages, and the sensor's
     * TLS session is reusable across that cycle — tearing it down forces
     * a full re-handshake which the sensor refuses (it stays in its old
     * TLS state and ignores TLS_START). The fast path in dev_activate
     * picks up the live session; full cleanup happens in the GObject
     * finalizer when the device object is destroyed.                      */

    /* G10 (H5, M4): drop transient capture state. We don't free img_buf /
     * stitch_buf here because they're reused on the next activate (sized
     * for one TLS frame each — ~10 KiB total). Truncating prevents stale
     * bytes from a previous session leaking into the next capture's
     * decode buffer if the SSM aborts before append_to_buf reinitialises
     * img_len.                                                            */
    self->img_len = 0;
    self->stitch_expected = 0;
    if (self->stitch_buf)
        g_byte_array_set_size (self->stitch_buf, 0);

    gm168_ssm_deadline_set (self, GM168_DEINIT_DEADLINE_MS);
    FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (dev), deinit_run_state, DEINIT_NUM_STATES);
    fpi_ssm_start (ssm, deinit_completed);
}

static void dev_change_state (FpImageDevice *dev, FpiImageDeviceState state)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);

    if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON) {
        self->active_state = TRUE;
        fp_dbg ("change_state: AWAIT_FINGER_ON -> starting polling");
        start_polling (self);
    } else if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF) {
        /* REARM SSM already reset the sensor (0x34×2 + 1500ms + 0x32). The
         * second report_finger_status(FALSE) unblocks FPI_DEVICE_ACTION_CAPTURE. */
        self->active_state = FALSE;
        fp_dbg ("change_state: AWAIT_FINGER_OFF -> confirming finger released");
        fpi_image_device_report_finger_status (dev, FALSE);
    } else {
        self->active_state = FALSE;
    }
}

static void dev_open (FpImageDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    gm168_log_open (&self->log);

    GError *error = NULL;
    g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)), 0, 0, &error);
    /* Since dev_close keeps the interface claimed, a re-open may see
     * BUSY ("already claimed by us"). Treat that as success.             */
    if (error && g_error_matches (error, G_USB_DEVICE_ERROR,
                                  G_USB_DEVICE_ERROR_BUSY)) {
        g_error_free (error);
        error = NULL;
    }
    fpi_image_device_open_complete (dev, error);
}

static void dev_close (FpImageDevice *dev)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (dev);
    gm168_log_close (&self->log);

    /* Do NOT tear down TLS or release the USB interface here. The sensor
     * preserves its TLS session indefinitely on its side; if we tear down
     * ours, the next dev_open's TLS_START gets stale encrypted records
     * back instead of a fresh handshake ("SSL_accept failed: unexpected
     * message" → INIT watchdog). Keeping both alive across fprintd
     * close/open cycles lets the fast path in dev_activate skip init
     * entirely. Real cleanup happens when our fprintd process exits and
     * the OS reaps the USB interface + closes our sockets.                */
    fpi_image_device_close_complete (dev, NULL);
}

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x589a, },
  { .vid = 0,      .pid = 0, },
};

static void fpi_device_goodix_gm168_init (FpDeviceGoodixGm168 *self)
{
}

static void
fpi_device_goodix_gm168_finalize (GObject *obj)
{
    FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (obj);
    if (self->tls.ssl)
        goodix_gm168_tls_deinit (&self->tls);
    g_clear_pointer (&self->stitch_buf, g_byte_array_unref);
    g_clear_pointer (&self->img_buf, g_free);
    g_clear_pointer (&self->background, g_free);
    g_clear_pointer (&self->background_sum, g_free);
    g_clear_pointer (&self->tls_dec_buf, g_free);
    g_clear_object (&self->best_img);
    g_clear_object (&self->dual_pending_img);
    g_clear_object (&self->io_cancellable);
    G_OBJECT_CLASS (fpi_device_goodix_gm168_parent_class)->finalize (obj);
}

static void fpi_device_goodix_gm168_class_init (FpDeviceGoodixGm168Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);
  G_OBJECT_CLASS (klass)->finalize = fpi_device_goodix_gm168_finalize;

  dev_class->id = "goodix_gm168";
  dev_class->full_name = "Goodix GM168";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* 80x64 sensor — each touch only covers ~5x4 mm of finger pad, the
   * pad itself is ~15x12 mm so one touch is ~7 % of usable area.  16
   * stages give the user enough rounds to vary placement (center
   * presses + tilted edge presses, à la the Windows Hello enroll UX)
   * to build a template with ~85 % pad coverage.  Reduces verify
   * false-reject rate on off-center touches roughly 2-3x vs the
   * 12-stage default we had earlier.  libfprint's image-device
   * default is 5, which doesn't give NBIS enough overlap on this
   * sensor.                                                              */
  dev_class->nr_enroll_stages = 16;
  /* libfprint's thermal model assumes a CMOS optical sensor that heats
   * up under sustained use. Our sensor is capacitive — power draw is
   * negligible and the silicon doesn't warm. The defaults trip after
   * a heavy enroll + verify burst ("Device disabled to prevent over-
   * heating"), blocking the user for minutes for no real reason.
   * Setting hot_seconds = -1 disables the model entirely.               */
  dev_class->temp_hot_seconds = -1;

  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->change_state = dev_change_state;
  img_class->deactivate = dev_deactivate;
  img_class->img_width = GM168_FRAME_W;
  img_class->img_height = GM168_FRAME_H;
}
