/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * gm168_timeouts.h — single source of truth for transport-layer timing.
 *
 * Replaces the magic numbers (2000, 1000, 1500, 50, 10, 60) that used to
 * be open-coded across goodix_gm168.c. See docs/AUDIT.md §2.1 (finding M1)
 * and docs/HARDENING.md §G13.
 *
 * Categories:
 *   - USB RX timeouts: how long fpi_usb_transfer_submit waits on EP_IN.
 *   - USB TX timeouts: same for EP_OUT.
 *   - State-transition delays: fpi_device_add_timeout values.
 *   - Retry caps: re-listen counters before declaring a stuck state.
 *
 * Values were not retuned in G13 — every constant matches what the code
 * had before. Tuning happens once G7 traces give us real measurements.
 */
#ifndef GM168_TIMEOUTS_H
#define GM168_TIMEOUTS_H

/* ---- USB RX (EP_IN) timeouts ------------------------------------------ */

/* Standard ACK read after sending a command. Most init steps use this.   */
#define GM168_USB_RX_TIMEOUT_MS         2000

/* Fast paths where the sensor answers quickly or we re-listen often:
 *   - INIT_TLS_RX        (TLS record from MCU)
 *   - CAP_RX             (capture RX inside the quality-gate budget)
 *   - poll EP_IN read
 *   - REARM 34_1/34_2/AE ACKs (sensor is in the warm-loop state)         */
#define GM168_USB_RX_SHORT_TIMEOUT_MS   1000

/* INIT_FDT_ACK: sensor takes the longest after FDT setup.                */
#define GM168_USB_RX_LONG_TIMEOUT_MS    3000

/* ---- USB TX (EP_OUT) timeouts ----------------------------------------- */

/* fpi_usb_transfer_submit on EP_OUT. TX completes within ~1ms in practice
 * but we keep slack for kernel/driver hiccups.                            */
#define GM168_USB_TX_TIMEOUT_MS         2000

/* ---- State-transition delays (fpi_device_add_timeout) ----------------- */

/* MCU does not ACK WakeUp (0x11) — just wait.                             */
#define GM168_WAKEUP_DELAY_MS           50

/* Pacing between TLS RX/TX pulls during handshake.                        */
#define GM168_TLS_PUMP_DELAY_MS         10

/* REARM_DELAY (submit path): pause between FDT_REARM(0x34) and IRQ_ARM(0xAE)
 * for the sensor's capacitive front-end to discharge before re-arming FDT.
 *
 * Windows uses ~115ms (measured from patches/goodix.pcapng enrollment
 * trace, see scripts/analyze_enroll_timing.py).  We kept 1500ms from the
 * provisioning pcap which is overkill for enrollment.  150ms = Windows
 * value + 35ms slack for slow USB hosts / usbipd.                          */
#define GM168_REARM_DELAY_MS            150

/* ---- Retry caps ------------------------------------------------------- */

/* Max consecutive re-listens in ack_cb / bg_rx_cb / psk_read_rx_cb before
 * we declare the sensor stuck. ack_retry is reset on every state advance
 * so the cap is "stuck in one state", not "stuck in the whole session".  */
#define GM168_USB_RX_RETRY_LIMIT        60

/* TLS_RX loop iterations before we declare the handshake hung.           */
#define GM168_TLS_RETRY_LIMIT           60

/* ---- G1: SSM wall-clock deadlines ------------------------------------ */
/*
 * Hard upper bound on how long any single SSM can run. Without these, a
 * misbehaving sensor cycling between "answer / partial / silence" can chew
 * through GM168_USB_RX_RETRY_LIMIT × GM168_USB_RX_TIMEOUT_MS = 60 × 2000 ms
 * = 2 minutes before the per-state retry cap finally trips. The deadline
 * trips once and fails the SSM, giving the upper layer a chance to recover.
 *
 * Values are generous: roughly 3× the worst observed time on a healthy
 * sensor, leaving room for slow USB host adapters and remote usbipd.
 */
#define GM168_INIT_DEADLINE_MS          10000  /* typical 1.95 s          */
#define GM168_CAPTURE_DEADLINE_MS       2000   /* budget 600 ms, ~3× slack */
/* GM168_WAIT_LIFT_MAX_REARMS caps how many times wait_lift_cb may jump
 * back to REARM_32.  Total wait_lift cycles = MAX_REARMS + 1 (the +1 is
 * the initial cycle before any re-arm).
 *
 * GM168_WAIT_LIFT_POLL_MS is the per-cycle USB read timeout in the
 * lift-detection loop.  Was 1000 ms (SHORT_TIMEOUT), which dominated
 * REARM wall-clock: 2×1000 = 2 s per stage just waiting for "FDT did
 * NOT re-fire".  300 ms is enough to give the user time to lift while
 * keeping the total bounded.  Windows enroll never waits for lift
 * (see scripts/analyze_enroll_timing.py): it arms FDT and immediately
 * returns to polling — we keep the wait because libfprint requires
 * a finger-off/finger-on cycle between enrollment stages.
 *
 *   max REARM time = REARM_DELAY + (MAX+1)×POLL × 2 (FDT fire + timeout)
 *                  = 150 + 2×600 = 1350 ms typical                       */
#define GM168_WAIT_LIFT_MAX_REARMS      1
#define GM168_WAIT_LIFT_POLL_MS         300
#define GM168_REARM_DEADLINE_MS         3000   /* generous: typical 1.3s  */
#define GM168_DEINIT_DEADLINE_MS        3000   /* one cmd + ACK, > RX_TIMEOUT */
#define GM168_RECOVER_DEADLINE_MS       5000   /* like init w/o TLS+BG    */

/* ---- Compile-time regression guards ---------------------------------- */
/*
 * G13 invariant: these constants must equal the original literals that
 * lived in goodix_gm168.c before the refactor. If you change any of them
 * deliberately (e.g. retuning after G7 traces), update BOTH the value AND
 * the matching _Static_assert here, with a note in HARDENING.md §3.
 * The assertions fire at compile time of any TU including this header.
 */
_Static_assert (GM168_USB_RX_TIMEOUT_MS       == 2000, "G13: RX timeout drifted");
_Static_assert (GM168_USB_RX_SHORT_TIMEOUT_MS == 1000, "G13: short RX timeout drifted");
_Static_assert (GM168_USB_RX_LONG_TIMEOUT_MS  == 3000, "G13: long RX timeout drifted");
_Static_assert (GM168_USB_TX_TIMEOUT_MS       == 2000, "G13: TX timeout drifted");
_Static_assert (GM168_WAKEUP_DELAY_MS         == 50,   "G13: wakeup delay drifted");
_Static_assert (GM168_TLS_PUMP_DELAY_MS       == 10,   "G13: TLS pump delay drifted");
_Static_assert (GM168_REARM_DELAY_MS          == 150,  "G13: rearm delay drifted (now matches Windows ~115ms + slack)");
_Static_assert (GM168_USB_RX_RETRY_LIMIT      == 60,   "G13: RX retry limit drifted");
_Static_assert (GM168_TLS_RETRY_LIMIT         == 60,   "G13: TLS retry limit drifted");

/* G1: each deadline must be loose enough to cover the legitimate path.
 * GM168_CAPTURE_BUDGET_MS is defined in goodix_gm168.c next to the other
 * quality-gate tunables — its assert lives there. */
_Static_assert (GM168_INIT_DEADLINE_MS    > GM168_USB_RX_TIMEOUT_MS, "G1: init deadline too tight");
_Static_assert (GM168_REARM_DEADLINE_MS   > GM168_REARM_DELAY_MS,    "G1: rearm deadline must exceed REARM_DELAY");
/* Total cycles = MAX_REARMS + 1; each cycle ≤ 2×POLL */
_Static_assert (GM168_REARM_DEADLINE_MS   > GM168_REARM_DELAY_MS + (GM168_WAIT_LIFT_MAX_REARMS + 1) * GM168_WAIT_LIFT_POLL_MS * 2,
                "G1: rearm deadline too tight for max FDT re-arm cycles");
_Static_assert (GM168_DEINIT_DEADLINE_MS  > GM168_USB_RX_TIMEOUT_MS, "G1: deinit deadline too tight");

#endif /* GM168_TIMEOUTS_H */
