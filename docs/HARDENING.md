# Transport / HW Hardening Plan

Plan to take `goodix_gm168` from "works on a clean bench" to "survives a real
laptop session" — flaky USB, suspend/resume, half-dead sensor, user yanking
a hub. Scope is strictly the transport and device-control layer; the image
pipeline is byte-perfect and out of scope here.

Status snapshot: **2026-06-06**. Algorithm done (MAE=0 on post-pipeline).
Driver lives in [src/goodix_gm168.c](../src/goodix_gm168.c).

---

## 0. STATUS (2026-06-06) — Phase 0+1+2 COMPLETE

10 of 13 G-items shipped, validated under boot-load (enroll 5/5 passed,
7 capture-cycles + 2 retries, no regressions).

| Phase | Item | Status | Closes |
|-------|------|--------|--------|
| 0 | G13 timeout table             | ✅ | M1                       |
| 0 | G7 trace macro                | ✅ | (foundation)             |
| 1 | G9 TLS cancel + bound accept  | ✅ | 🔴 C1, 🔴 C2, 🟠 H10     |
| 1 | G8 io_cancellable             | ✅ | 🟠 H1                    |
| 1 | G10 lifecycle cleanup         | ✅ | 🟠 H5, M4, M9, M10       |
| 1 | G2 CAP_RX budget sync         | ✅ | 🟠 H2                    |
| 2 | G1 SSM deadline watchdog      | ✅ | 🟠 H4, M3                |
| 2 | G3 USB error classification   | ✅ | 🟠 H3                    |
| 2 | G11 capture resync            | ✅ | 🟠 H7, H8, M7            |
| 2 | G4 RECOVER SSM                | ✅ | M8                       |
| 3 | G5 hotplug                    | ⏸  | deferred — fprintd does it |
| 3 | G12 full change_state         | ⏸  | deferred — works on 1.94.9 |
| 3 | G6 TLS re-handshake           | ⏸  | deferred — no failures seen|

**Critical (🔴): 2/2 closed. High (🟠): 9/12 closed. Medium (🟡): 7/14 closed.**

Phase 3 items deferred deliberately — see §4 "Skipped" for rationale.
Implementation notes live in [docs/DRIVER.md §Hardening](DRIVER.md).

---

## 1. What we already have (audit)

Pulled from a fresh read of the source — listing it so we don't redo work.

### Transport
- libfprint async USB via `fpi_usb_transfer_submit`.
- Per-submit timeouts:
  - 2000 ms — most ACK / PSK / BG / init-TLS-TX paths
  - 1000 ms — capture RX, poll, init-TLS-RX
  - 1500 ms — REARM inter-state delay
  - 200 ms — REARM delay in quality-gate retry loop
  - 50 / 10 ms — WAKEUP, TLS pump pacing

### Retry / re-listen safety
- `ack_resubmit_or_fail()` at [goodix_gm168.c:832](../src/goodix_gm168.c:832)
  — single wrapper for ACK re-listen; capped by `GM168_RX_RETRY_LIMIT = 60`.
- `bg_rx_cb` at [goodix_gm168.c:1608](../src/goodix_gm168.c:1608) — same cap
  for BG accumulation.
- `ack_retry` is reset on every state advance, so the cap is "stuck in one
  state", not "stuck in the whole session".
- TLS handshake capped at 60 RX/TX iterations (`tls_retry`).
- `deactivating` flag honoured in every callback — shutdown is clean.

### State machines (explicit, via libfprint SSM)
- `init_run_state`: WAKEUP → RESET(0x60) → VERSION(0x20) → TLS → SESSION(0x60)
  → ARM(0xAE) → FDT(0x32) → BG×5 → REARM-once.
- `capture_run_state`: CAP_TRIG(0x20) → CAP_RX → CAP_PROCESS.
- `rearm_run_state`: 34_1 → 34_2 → DELAY(1500ms) → AE(0xAE) → 32(0x32).
- Touch loop: `poll_cb` → A0/0x32/0x02 → `start_capture_ssm` → rearm.

### Quality-gate (already production-grade)
- Best-of-N retry at [goodix_gm168.c:1942](../src/goodix_gm168.c:1942),
  `MAX_CAPTURE_ATTEMPTS=6`, `BUDGET_MS=600`, `RETRY_DELAY_MS=200`.

---

## 2. Gaps — the real P0 list

Each gap is annotated with its current behaviour, target behaviour, and
where the fix lands.

### G1. No deadline-based watchdog per SSM
**Now.** Each USB submit has its own timeout. A misbehaving sensor cycling
through "answer / partial / silence" can chew through 60 × 2000 ms ≈ 2 min
before `ack_resubmit_or_fail` finally trips.
**Target.** Monotonic wall-clock deadline attached to each top-level SSM
(init / capture / rearm). Once exceeded → abort with `recover()` (G4),
regardless of how many tiny retries still fit under `RX_RETRY_LIMIT`.
**Where.** Add `gint64 ssm_deadline_us` to `FpDeviceGoodixGm168`; check in
`ack_resubmit_or_fail` and at every state entry.

### G2. Capture budget / USB read timeout are unsynchronised
**Now.** `BUDGET_MS = 600` is checked **after** the 1000 ms RX returns. A
sensor that goes quiet mid-capture costs us 400 ms of dead air per attempt.
**Target.** Pass `min(remaining_budget_ms, 1000)` to `fpi_usb_transfer_submit`
in capture paths. Same for ACK reads inside a quality-gated retry.
**Where.** [goodix_gm168.c:1650](../src/goodix_gm168.c:1650) and
[:944](../src/goodix_gm168.c:944) (`async_recv_ack`).

### G3. USB errors aren't classified
**Now.** Only `G_USB_DEVICE_ERROR_TIMED_OUT` is treated specially
(retry / re-listen). Other errors fall through to "SSM fail → libfprint
error path".
**Target.** Classify into four buckets and act per-bucket:

| Error                                | Action                                |
|--------------------------------------|---------------------------------------|
| `TIMED_OUT`                          | local retry (existing)                |
| `CANCELLED` (`G_IO_ERROR_CANCELLED`) | clean shutdown, no recovery           |
| `NO_DEVICE`                          | mark dead, surface to libfprint, stop |
| `IO` / `FAILED` / others             | `recover()` (G4); fail if recover fails |

**Where.** Centralise in a new `gm168_classify_usb_error(GError *)` returning
an enum used by every `*_cb`.

### G4. No mid-session sensor recovery
**Now.** RESET(0x60) only runs in `init_run_state`. A mid-capture stall has
no path back to "known good" short of `dev_close + dev_open`.
**Target.** `recover_run_state` SSM:
1. cancel any in-flight transfer
2. send 0x60 (RESET) → ACK
3. re-send ARM(0xAE), FDT(0x32) — but **skip BG averaging**, reuse cached
   `self->background`
4. resume from where the caller was (capture or poll)

Triggered by: G3's "IO/FAILED" bucket, G1's deadline, two consecutive
quality-gate exhaustions.
**Where.** New `recover_run_state` modelled on `rearm_run_state`; new helper
`start_recover_ssm(self, return_to_state)`.

### G5. No hotplug awareness
**Now.** Removal mid-session manifests as `NO_DEVICE` on the next submit
and a generic error. Re-plug does not auto-recover — fprintd has to notice
and re-open us.
**Target.** Subscribe to `GUsbContext` device-removed / device-added.
On removed: cancel everything, set `dead = TRUE`, complete current SSM
with a clean error. On added (same VID/PID/serial): emit a probe event so
fprintd re-opens cleanly.
**Where.** `dev_init` (subscribe), `dev_close` (unsubscribe).
Probably one new file `goodix_hotplug.c` to keep `goodix_gm168.c` from
growing further.

### G6. TLS recovery requires full re-open
**Now.** mbedtls error → SSM fail → device closes.
**Target.** On TLS read/write error, tear down mbedtls context, re-issue
TLS_START(0xD0) + handshake, **without** reopening the USB device. Keep
calibration in memory; only re-derive session keys.
**Where.** [src/goodix_tls.c](../src/goodix_tls.c) needs a `gm168_tls_reset()`
entry point; `init_run_state` factored so handshake states are reusable.

### G7. No structured logging of timing for the watchdog to learn from
**Now.** `fp_dbg` lines are ad-hoc; no per-state duration log.
**Target.** Per state-transition log a `state_enter`/`state_exit` pair with
elapsed µs. Off by default, on with `$GM168_TRACE=1`. Becomes the data
source for tuning the per-state max-ms table.
**Where.** Helper macro wrapping `fpi_ssm_next_state` / state callbacks.

### G8. Submits ignore the cancellable (AUDIT H1)
**Now.** 10 of 11 USB submit-points pass `NULL` for `GCancellable`. Only
`start_polling` uses `self->poll_cancellable`. `dev_deactivate` therefore
relies on the `deactivating` flag + transfer timeouts, so shutdown stalls
up to 2 s waiting for in-flight reads to time out.
**Target.** One `self->io_cancellable` covering every submit. Cancelled in
`dev_deactivate` and on any fatal error path. Existing `deactivating` checks
remain as a belt-and-braces guard.
**Where.** Add `io_cancellable` to struct (init in `dev_activate`, cancel
in `dev_deactivate`), thread it through `async_send_cmd`, `async_recv_ack`,
`ack_resubmit_or_fail`, `bg_rx_cb` re-listen, `psk_read_rx_cb` re-listen,
`init_tls_rx_cb`, `init_tls_tx_cb`, `capture_rx_cb`.

### G9. TLS thread can outlive deactivate (AUDIT C1, C2, H6, H10)
**Now.** `dev_deactivate` doesn't touch TLS. `SSL_accept` blocks on
`sock_fd` with no timeout; if handshake hangs the worker thread lives
forever until the next `dev_activate` reinit closes the fd. `SSL_read`
busy-loops up to 250 ms inside the main thread on every B2 packet.
**Target.**
1. `dev_deactivate` calls a new `goodix_gm168_tls_cancel(&self->tls)` that
   `shutdown(sock_fd, SHUT_RDWR)` to unblock the thread immediately.
2. Bound `SSL_accept` with `SO_RCVTIMEO`/poll, fail TLS handshake on
   expiry.
3. `SSL_read` retry shrinks from 50×5 ms to 5×1 ms. If still WANT_READ,
   return 0 and let the caller re-enter via the regular CAP_RX loop —
   no blocking in the main thread.
**Where.** [src/goodix_tls.c](../src/goodix_tls.c) — adds `tls_cancel`,
modifies `tls_serve_thread` and `goodix_gm168_tls_recv`. Pairs with G6
(reset) but is independent of it.

### G10. Object lifecycle gaps (AUDIT H5, M4, M9, M10)
**Now.**
- `img_buf` survives between sessions until `dev_close` ([:2390]).
- `stitch_buf` survives between sessions until `dev_close` ([:2395]).
- `start_polling` clears `poll_transfer = NULL` at the top of `poll_cb`
  before processing — re-entry can race.
- `deinit_completed` swallows the deinit error silently.
**Target.**
- `dev_deactivate` truncates (not frees) `img_buf`/`stitch_buf` to len=0.
- `poll_transfer = NULL` moves to the end of `poll_cb` (after we know we
  won't re-enter via `start_polling`).
- `deinit_completed` logs the error class and forwards `NO_DEVICE` to
  libfprint so fprintd knows the device is gone.
**Where.** [goodix_gm168.c:2037, :2335, :974].

### G11. Capture-path resync (AUDIT H7, H8, M7)
**Now.**
- `CAP_PROCESS` unknown packet-type → drops the whole `stitch_buf`
  ([:1734]).
- `capture_rx_cb` on USB timeout jumps to `CAP_RX` not `CAP_TRIG` — if
  the sensor forgot the trigger we re-listen forever.
- `CAP_PROCESS` always jumps to `CAP_RX` even when the frame is complete.
**Target.**
- Unknown type: drop one byte and continue, not the whole buffer (typical
  framing-resync pattern).
- After 2 consecutive CAP_RX timeouts within one capture cycle: jump to
  CAP_TRIG (re-send 0x20) once. After that, fail → `recover()` (G4).
- Hoist the "frame complete" check to the top of `CAP_PROCESS`, before
  the per-packet loop.
**Where.** [goodix_gm168.c:1654, :1567].

### G12. dev_change_state coverage (AUDIT H12)
**Now.** Only `AWAIT_FINGER_ON` / `AWAIT_FINGER_OFF` are handled. Other
states (`CAPTURE`, `ENROLL_STOP`, `ANALYZE_DATA`, `INACTIVE`) silently set
`active_state = FALSE`.
**Target.** Explicit switch covering every `FpiImageDeviceState`. Stop
polling only on `INACTIVE`; keep it running through CAPTURE and
ANALYZE_DATA so we don't miss a touch while libfprint is busy.
**Where.** [goodix_gm168.c:2356].

### G13. Magic numbers + tls_done race (AUDIT M1, M5, M6)
**Now.** Timeouts (2000, 1000, 1500, 50, 10) are open-coded across ~12
sites. `tls_done` is set from the TLS worker thread, read from the main
thread — works because GLib main loop serialises, but no comment or
explicit barrier.
**Target.**
- One `gm168_state_budget[]` table (see §3), referenced by every
  state-entry helper.
- `tls_done` becomes `g_atomic_int_set`/`g_atomic_int_get` with a one-line
  comment naming the producer thread.
- `INIT_BG_LOOP_CHECK` rewritten as `for (i=0; i<BG_FRAMES; i++)` style,
  not fall-through.
**Where.** New `gm168_timeouts.h`; refactor of `init_run_state` BG block.

---

## 3. Proposed per-state timeout / deadline table

Replaces the magic numbers scattered through the source. Source of truth
becomes a single `gm168_state_budget[]` table compiled in.

| State              | Expected (ms) | Max (ms) | On expire           |
|--------------------|---------------|----------|---------------------|
| WAKEUP_DELAY       | 50            | 100      | retry once → fail   |
| RESET_ACK          | 30            | 200      | recover             |
| VERSION_ACK        | 30            | 200      | recover             |
| TLS_RX / TLS_TX    | 50            | 1000     | retry, cap iters    |
| SESSION_ACK        | 30            | 200      | recover             |
| ARM_ACK            | 30            | 200      | recover             |
| FDT_ACK            | 30            | 200      | recover             |
| BG_RX              | 80            | 500      | retry, cap iters    |
| BG_PROCESS         | <1            | 50       | fail (logic bug)    |
| CAP_RX             | 100           | budget   | tied to G2          |
| CAP_PROCESS        | <5            | 50       | fail (logic bug)    |
| REARM_34_*         | 30            | 200      | recover             |
| REARM_DELAY        | 1500          | 1600     | proceed             |
| POLL_RX            | idle          | 5000     | re-listen           |

"Expected" comes from observed values on a working sensor (need G7 traces
to confirm). "Max" is the watchdog trip line.

---

## 4. Implementation order (impact / effort)

Re-ordered after audit to put the two 🔴 critical findings first. Each
phase ends in a working driver — we can stop after any of them and ship.

**Phase 0 — foundation (no behaviour change).** ~3 h.
- **G13** Timeout table + `gm168_timeouts.h`. Removes magic numbers, sets
  up G1/G2.
- **G7** Tracing macro `GM168_TRACE`. Unblocks measurement for everything
  else.

**Phase 1 — fix the 🔴 criticals + the cheapest 🟠s.** ~1 day.
- **G9** TLS cancel + bounded SSL_accept + shorter SSL_read retry.
  Addresses C1, C2, H10.
- **G8** Single `io_cancellable` threaded through every submit. Addresses
  H1, makes deactivate instant.
- **G10** Lifecycle cleanup (img_buf/stitch_buf truncate, poll_transfer
  ordering, deinit error propagation). Addresses H5, M4, M9, M10.
- **G2** Sync CAP_RX timeout with remaining budget.

**Phase 2 — watchdog + recovery.** ~1.5 days.
- **G1** SSM deadline. Builds on G13's table.
- **G3** USB error classification.
- **G11** Capture-path resync (unknown-type drop-one-byte, re-trigger on
  consecutive timeouts, hoist frame-complete check).
- **G4** `recover_run_state` SSM. The big user-facing reliability gain.

**Phase 3 — environmental robustness.** ~1 day.
- **G5** Hotplug.
- **G12** Full `dev_change_state` coverage.
- **G6** TLS re-handshake (rarest failure mode).

Total: ~3.5 dev-days. After Phase 1 the driver is already shippable —
phases 2 and 3 are quality-of-life and edge-case coverage.

### Skipped from audit (deliberate)
- **M2** (psk_read_rx_cb timeout) — PSK path runs once per provisioned
  device. Not worth special-casing.
- **M3** (ack_retry resets on advance) — bounded by G1 once watchdog is
  in. Removing the reset would break legitimate fast handshakes.
- **H11** (tls_feed partial write) — socketpair buffer is 208 KB on
  Linux, we write < 2 KB. Logged for posterity, no fix planned.
- **M11** (OpenSSL globals) — harmless on OpenSSL ≥ 1.1.
- **M13, M14** (suspend/resume, async open) — handled by libfprint
  upstream, out of our scope.
- **L1–L4** — style. Address opportunistically while touching neighbouring
  code, not as standalone work.

---

## 5. Test plan

Failure injection — none of these currently exist:

- **Suspend/resume mid-capture.** `systemctl suspend` while finger down.
  Expect: clean error to libfprint, next touch works.
- **Hub yank.** Unplug USB hub during enroll. Expect: enroll fails cleanly,
  re-plug → next enroll attempt works without `fprintd` restart.
- **Frozen sensor.** Frida-patch the Windows-side firmware emulator (or use
  a USB-IP shim) to stop replying after N packets. Expect: deadline trips,
  `recover()` runs, capture succeeds on the next touch.
- **Partial-packet / bad CRC.** USB-IP shim corrupts one B2 packet per N.
  Expect: capture errors, quality-gate retries, finally succeeds.
- **Two-finger flood.** Touch + release + touch within 50 ms × 50. Expect:
  no leaked transfer, no double-submit.

All five become bash scripts under `scripts/stress/` driven by the same
USB-IP shim. The shim itself is the next-largest dependency to build.

---

## 6. Out of scope (deliberately)

- Image pipeline changes — pipeline is byte-perfect, leave it alone.
- Enroll/match algorithm — handled by libfprint NBIS, not us.
- Power management beyond clean suspend/resume handling.
- Multi-device support — single GM168 only.
- Anything in `goodix_proto.c` beyond what `recover()` needs.
