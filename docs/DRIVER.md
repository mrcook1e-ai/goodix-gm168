# Linux Driver Internals — `goodix_gm168`

A reference for anyone picking up the driver next session. Read alongside
`goodix_gm168.c` and `RESEARCH.md`.

## File layout

```
goodix_gm168/
  goodix_gm168.c   driver core: SSMs, capture pipeline, decoder        (1390 lines)
  goodix_proto.c/h USB packet codec, PSK constants, init payload blobs
  goodix_tls.c/h   mbedtls PSK server (pumps the in-driver TLS endpoint)
  meson.build
```

## Frame size constants (single source of truth)

```c
GM168_TLS_FRAME_SIZE   10564    /* full TLS plaintext per frame      */
GM168_TLS_PAYLOAD_SIZE 10560    /* 80 wire rows × 132 bytes          */
GM168_WIRE_ROWS        80
GM168_WIRE_ROW_STRIDE  132      /* bytes per wire row                */
GM168_WIRE_ROW_DATA    96       /* non-zero bytes per wire row       */
GM168_FRAME_W          80       /* output image width                */
GM168_FRAME_H          64       /* output image height               */
GM168_FRAME_PIXELS     5120
GM168_BG_FRAMES        5        /* dark frames averaged at init      */
GM168_RX_RETRY_LIMIT   60       /* max re-listens in ack_cb/bg_rx_cb */
```

There is no leading 4-byte header in the TLS plaintext. The 4 trailing bytes
are a CRC/padding ignored by the decoder. `gm168_decode_frame()` reads the
first 10560 bytes.

## The decoder (one function, used everywhere)

```c
int gm168_decode_frame(const guint8 *in, gsize in_len, guint16 *out);
```

Two passes:
1. **De-pad** — for each of 80 wire rows, copy the first 96 data bytes into a
   compact 7680-byte buffer; the trailing 36 bytes per row are zero padding.
2. **12-bit unpack + transpose** — every 6 packed bytes yield 4 pixels P0..P3
   per the standard scheme (`P0 = (b0 & 0x0F)<<8 | b1`, etc.); each logical
   pixel `k` is written to `out[(k % 64) * 80 + (k / 64)]`, which is the
   80×64-to-64×80 transpose the Windows SGX enclave performs inline.

Verified pixel-perfect (5120/5120) against captured Windows preprocessor
input on every frame in our test set.

## State machine: init (`init_run_state`)

```
WAKEUP → WAKEUP_DELAY (50 ms)
  → RESET (0x60) → RESET_ACK
  → VERSION (0x20) → VERSION_ACK
  → TLS_START (0xD0) → TLS_START_ACK
  → TLS_RX ↔ TLS_DELAY ↔ TLS_TX_PULL    (loop until handshake done)
  → SESSION (0x60) → SESSION_ACK
  → ARM (0xAE) → ARM_ACK
  → FDT (0x32) → FDT_ACK
  → BG_TRIG (0x20) → BG_RX → BG_PROCESS  ← accumulates into background_sum
  → BG_LOOP_CHECK                        ← jumps back to BG_TRIG until N=5,
                                           then divides sum into self->background
  → BG_REARM_34_1/2/DELAY/AE/32          ← runs once, prepares sensor for touch
```

`INIT_OTP_READ` was removed — the sensor never answers 0x43 (legacy LFSR seed
extraction path, dead on this device).

## State machine: capture (`capture_run_state`)

```
CAP_TRIG (0x20) → CAP_RX → CAP_PROCESS
```

`CAP_RX` reads from EP_IN and accumulates into `stitch_buf` until enough is
buffered for the full B2 frame. `CAP_PROCESS` parses A0/B0/B2 packets, feeds
TLS data to mbedtls, accumulates decrypted payload in `img_buf` until
`>= GM168_TLS_FRAME_SIZE` bytes. Then completes the SSM.

After the SSM finishes, `capture_completed()` runs:
1. `gm168_decode_frame(img_buf, ...) → raw16[5120]`
2. If `self->background` present: `tmp[i] = raw16[i] - background[i]`.
   Else (shouldn't normally happen): per-column median subtraction fallback.
3. Percentile-clip (2..98) → `norm[5120]` uint8 normalised to 0..255.
4. `gm168_clahe(norm, clahe_out)` — 4×5 grid of 16×16 contextual regions,
   clip limit 16/256, bilinear interpolation between tile CDFs.
5. 3×3 Gaussian smoother (kernel 1/16 [[1,2,1],[2,4,2],[1,2,1]]) into
   `fp_img->data`. Tames CLAHE's single-pixel artefacts before NBIS.
6. `start_rearm_ssm(self, NULL, fp_img)` → hands off to libfprint.

Set `$GM168_NO_CLAHE=1` to skip steps 4-5 and ship the plain stretch
output — useful for A/B comparison only; CLAHE+Gaussian wins by ~20
percentage points of per-frame NBIS success on captured data.

## State machine: rearm (`rearm_run_state`)

After every capture or capture-error:

```
REARM_34_1 (0x34) → ACK
  → REARM_34_2 (0x34) → ACK
  → REARM_DELAY (1500 ms)
  → REARM_AE (0xAE) → ACK
  → REARM_32 (0x32) → ACK
```

When done, `rearm_completed` calls `fpi_image_device_report_finger_status(FALSE)`
and either reports the error or hands the image to libfprint via
`fpi_image_device_image_captured()`.

## Polling for touch (`start_polling` / `poll_cb`)

A continuous `EP_IN` read with `self->poll_cancellable`. Idempotent
(`if (self->poll_transfer != NULL) return`). On receipt:
- `A0` echo `0x32` status `0x02` → real touch → `start_capture_ssm()`
- `B0` (TLS) → ignored
- anything else → keep polling

Cancelled cleanly on `dev_deactivate()`.

## Re-listen safety (`ack_cb` / `bg_rx_cb`)

Three earlier bugs lurked here. All bounded by `GM168_USB_RX_RETRY_LIMIT`:

- `ack_resubmit_or_fail()` — wraps every re-listen in `ack_cb`. Checks
  `self->deactivating` (fails SSM cleanly if shutting down) and increments
  `self->ack_retry`. State advances reset the counter.
- `bg_rx_cb` returns immediately on `G_IO_ERROR_CANCELLED`, checks
  `deactivating`, applies the same retry cap.

## Hardening layer (G1..G13 — see HARDENING.md)

Added in the 2026-06 hardening pass. Layered defenses, from lightweight
to heavyweight, all triggered automatically:

```
per-state retry (60×)          ← misbehaving packets / re-listens
quality-gate retry (6×, 600ms) ← bad image frames
REARM SSM (1.5s)               ← standard inter-capture sensor reset
RECOVER SSM (5s)               ← G4, sensor wedged mid-session
session_error → fprintd        ← terminal failure, device re-probe
```

### Timeout table — `gm168_timeouts.h` (G13)

Single source of truth replacing magic `2000`/`1000`/`1500`/`50`/`10`
literals. Two `_Static_assert` blocks guard against accidental drift:
one in the header itself, one in `tests/test_timeouts.c` (run by
`tests/run_tests.sh unit`). Every constant is documented at its
definition.

Named groups:
- `GM168_USB_RX_TIMEOUT_MS`        (2000) — default ACK read
- `GM168_USB_RX_SHORT_TIMEOUT_MS`  (1000) — fast paths (CAP_RX, poll, REARM ACK)
- `GM168_USB_RX_LONG_TIMEOUT_MS`   (3000) — INIT_FDT_ACK
- `GM168_USB_TX_TIMEOUT_MS`        (2000)
- `GM168_WAKEUP_DELAY_MS`          (50)
- `GM168_TLS_PUMP_DELAY_MS`        (10)
- `GM168_REARM_DELAY_MS`           (1500)
- Plus deadline caps below.

### Per-state tracing — `gm168_trace.h` (G7)

`GM168_TRACE=1` env enables `[TRACE]` g_warning lines, one per state
transition with µs elapsed. Off by default. Used to measure real
timings (typical: BG_RX 50ms, BG_REARM_DELAY 1502ms, full init 1.95s,
capture 25ms, REARM 1.5s).

### SSM watchdog deadlines (G1)

Per-SSM wall-clock cap. Without these, a misbehaving sensor cycling
"answer/partial/silence" could chew through 60 × 2000 ms = 2 minutes
before per-state retry caps tripped. Now any SSM has a hard ceiling:

| SSM      | Deadline | Set in                                     | Cleared in                |
|----------|----------|--------------------------------------------|---------------------------|
| INIT     | 10 s     | `dev_activate`                             | `init_completed`          |
| CAPTURE  | 2 s      | `start_capture_ssm`                        | `capture_completed`       |
| REARM    | 4 s      | `start_rearm_ssm` / `_retry_ssm`           | `rearm_completed`         |
| RECOVER  | 5 s      | `start_recover_ssm`                        | `recover_completed`       |
| DEINIT   | 3 s      | `dev_deactivate`                           | `deinit_completed`        |

Checked at the top of every `*_run_state` via
`gm168_ssm_deadline_expired`. On trip, marks SSM failed with
`FP_DEVICE_ERROR_GENERAL`.

### USB error classification — `gm168_usb_errors.h` (G3)

Centralises `g_error_matches` into one enum:
`CANCELLED / TIMEOUT / NO_DEVICE / IO / OTHER`. The shared helper
`gm168_handle_fatal_usb_error` consumes `NO_DEVICE` everywhere it's
called (`ack_cb`, `transfer_cb`, `capture_rx_cb`, `bg_rx_cb`) by
setting `self->device_dead = TRUE` and surfacing
`FP_DEVICE_ERROR_REMOVED` to libfprint. `poll_cb` does the same inline.

### io_cancellable (G8)

Single `GCancellable` threaded through every `fpi_usb_transfer_submit`
in the driver. `dev_deactivate` cancels it → in-flight reads abort in
~ms instead of riding out per-submit timeouts (was up to 2 s).

### TLS hardening (G9)

- `goodix_gm168_tls_cancel()` — new API. `shutdown(sock_fd, SHUT_RDWR)`
  to unblock `SSL_accept` from another thread. Called from
  `dev_deactivate`. Idempotent.
- `SO_RCVTIMEO` 5 s on `sock_fd` before `SSL_accept` — handshake can't
  hang forever.
- `SSL_read` busy-loop shrunk from 50×5ms = 250 ms blocking main thread
  to 5×1ms = 5 ms. Caller re-enters via normal CAP_RX loop instead.

### Capture path resync (G11)

- `CAP_PROCESS` on unknown packet type drops one byte and continues
  (was: cleared the whole buffer, losing valid tail data).
- After 2 consecutive `CAP_RX` timeouts, jump to `CAP_TRIG` once —
  covers sensor "forgetting" the SCAN trigger after soft reset.
- `CAP_PROCESS` checks `img_len >= FRAME_SIZE` up-front and
  `mark_completed`s immediately if a previous iteration already
  finished the frame (was: another wasted CAP_RX cycle).

### Capture budget sync (G2)

`CAP_RX` submits with `min(remaining_budget_ms, 1000)` instead of a
flat 1000 ms. Sensor going quiet mid-capture used to cost up to 400 ms
of dead air before the post-RX budget check could submit best; now
budget is checked in-flight.

### RECOVER SSM (G4)

When REARM itself fails, level-2 recovery kicks in instead of silently
swallowing the error:

```
0x60 SESSION → 0xAE ARM → 0x32 FDT → 0x34/0x34/delay/0xAE/0x32
```

Skips TLS (session stays alive) and BG (cached). On success: clear
quality-gate state, `start_polling`. On failure: surface to libfprint
via `session_error` — beyond this point full reinit would be needed
(deferred to a future G6 TLS re-handshake).

## Background averaging (multi-BG)

To suppress per-pixel sensor temporal noise, the init loop captures
`GM168_BG_FRAMES` dark frames and averages them per-pixel via
`self->background_sum` (uint32). `INIT_BG_LOOP_CHECK` divides the sum and
stores into `self->background`. Rearm runs **only once** after the loop, not
between iterations — rearm sends the sensor into "wait for touch" state and
the next direct `0x20` would hang.

## Build & test

Linux/WSL on the laptop:
```bash
cd ~/goodix_gm168/libfprint/build
ninja
~/goodix_gm168/debug.sh    # img-capture single shot
~/goodix_gm168/enroll.sh   # examples/enroll, 5-stage interactive
```

With debug dumps: `meson configure -Dc_args=-DGM168_DEBUG` then `ninja`.
Per-capture binaries appear in `/tmp/gm168_<seq>_*.bin|pgm`.

PC-side analysis: `scripts/verify_driver_decode.py` for pixel-match check,
`scripts/protocol_checklist.py` for protocol timeline, both pull captures
back via `scp -P 2200`.
