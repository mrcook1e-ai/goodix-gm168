# Changelog

All notable changes to the goodix-gm168 driver.  Versions follow
[SemVer](https://semver.org/).

## [0.1.0] — 2026-06-10

First public release.

### Added
- libfprint driver for the Goodix GM168SEC fingerprint sensor (USB
  `27c6:589a`).  Speaks the sensor's native TLS-PSK protocol over USB
  bulk endpoints, decodes 80×64 12-bit images, hands them to NBIS via
  the standard `fpi_image_device_*` API.
- OpenSSL-based TLS-PSK server (`PSK-AES128-CBC-SHA256`).  `NO_RENEGOTIATION
  + NO_TICKET + NO_EXTENDED_MASTER_SECRET` to match the sensor's legacy
  TLS-1.0-era firmware behaviour.
- Dual-capture per touch — matches the Windows enroll pattern, picks the
  higher-quality frame.
- Structured per-session text log at `$GM168_LOG_DIR/gm168-YYYYMMDD-HHMMSS.log`
  with per-line elapsed and delta-from-previous timestamps.
- udev rule (`packaging/udev/70-goodix-gm168.rules`) — `TAG+="uaccess"`
  for the active session user, no `plugdev` group needed.
- Fedora COPR packaging (`packaging/fedora/libfprint-goodix-gm168.spec`).
- One-shot bash installer (`install.sh`) for non-COPR Fedora systems.
- PSK extraction helper for Windows (`tools/windows/gm168_unseal.ps1`) —
  DPAPI-based, no Frida / Wbdi.dll / SGX required.

### Performance
- Init: 619 ms (5-frame BG capture + FDT arm).
- TLS handshake: 132 ms typical.
- Per-touch capture: ~22 ms × 2 (dual-capture).
- Per-touch REARM: ~840 ms (down from ~2530 ms after `REARM_DELAY` and
  `wait_lift` timing tuning against Windows trace measurements).
- Full 12-stage enrollment: ~22 s wall-clock.

### Hardening
- Wall-clock SSM deadlines (INIT/CAPTURE/REARM/DEINIT/RECOVER).
- USB error classification with `RECOVER` fallback SSM.
- Cancellable wiring across activate / deactivate / cancel paths.
- Capture resync after partial frames.
- Full lifecycle cleanup in GObject finalize (TLS thread, SSL context,
  socketpair, all heap buffers).
- Per-state retry caps to prevent infinite re-listen loops.

### Reverse engineering — preserved
- All pcaps, Wbdi.dll extraction scripts, WhiteBox AES key derivation,
  RE methodology docs, and the original Goodix SDK leak live on the
  [`archive/reverse-engineering`](https://github.com/mrcook1e-ai/goodix-gm168/tree/archive/reverse-engineering)
  branch.

### Known limitations
- Sensor doesn't push "finger lifted" events — we wait for a 300 ms
  USB read timeout instead.  Means REARM has a floor of ~600 ms even
  when the user lifts immediately.
- Per-device calibration is captured at first run and reused — no
  drift compensation yet.
- Identify works but matcher accuracy on the 80×64 sensor area is
  rough — verify rejection rate is ~5-10 % on the test machine.
