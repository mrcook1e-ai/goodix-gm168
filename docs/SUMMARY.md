# Goodix GM168SEC Linux Driver — Session Summary

## TL;DR

State after the most recent session (PSK bootstrap + image-quality pass):

- Decoder: **pixel-perfect** vs Windows preprocessor input (5120/5120).
- USB init, TLS-PSK handshake, multi-frame BG, touch detect, capture,
  decode, normalise, hand off to libfprint — all working end-to-end.
- **PSK is no longer hard-coded.** The driver reads it from
  `/etc/goodix-gm168/psk.bin` at activation; if missing, it speaks cmd
  `0xE4` itself to dump the sealed blob from the MCU and asks the user
  to unseal it on Windows via `tools/windows/gm168_unseal.ps1`. Frida
  is not in the runtime path anymore.
- Output pipeline: percentile-clip → CLAHE → 3×3 Gaussian. Lifts
  per-frame NBIS success roughly 2× vs the old plain stretch on today's
  captures.
- Enroll reaches **stage 4/5 reliably**, stalls there at ~44 % per-frame
  NBIS fail rate. Hard ceiling — see below.
- Builds with **0 warnings, 0 errors** under `-Wall -Wshadow -Werror=…`.

The remaining gap to consistent 5/5 enrollment is genuinely the Windows
preprocessor's Cal1+Cal2 + ~197 KB-param signal recovery, not just
post-processing polish. Side-by-side `INPUT` vs `FRAME` shows the raw
decode is *visual noise* and Windows is doing real physical-level FPN
correction. See [NEXT_STEPS.md](NEXT_STEPS.md) for the path forward.

---

## What changed in the driver

| Subsystem | Before | After |
|---|---|---|
| 12-bit decoder | column-major, assumed 88×80 raster + 4-byte header + crop to 80×64. Pixel-match 0.06 %. | Single `gm168_decode_frame()` — de-pad 80×132 wire rows (96 data + 36 zero pad) + decode + inline 80×64→64×80 transpose. Pixel-match 100 %. |
| Constants | `RAW_W=88 RAW_H=80 IMG_W=80 IMG_H=64 CROP_COL=4 CROP_ROW=8` | `GM168_FRAME_W=80 H=64 TLS_FRAME_SIZE=10564 WIRE_ROWS=80 WIRE_ROW_STRIDE=132 WIRE_ROW_DATA=96 BG_FRAMES=5 RX_RETRY_LIMIT=60` |
| Background | Single dark frame, min/max stretch | 5-frame averaged uint32 accumulator → uint16, percentile-stretch (2..98) |
| Init flow | Died on `INIT_OTP_READ_ACK` (sensor never answers 0x43) → 5 s timeout | OTP read skipped — jumps straight to `INIT_SESSION` |
| `ack_cb` re-listen | Infinite if sensor sends only B0/empty | `ack_resubmit_or_fail()` helper, capped at `GM168_RX_RETRY_LIMIT`, fails SSM if `deactivating` |
| `bg_rx_cb` | Ignored cancellation, infinite re-listen on errors | Returns immediately on `G_IO_ERROR_CANCELLED`, deactivating-check, retry-cap |
| `start_polling` | Could spawn two concurrent transfers on the same EP | Idempotent: `if (self->poll_transfer != NULL) return` |
| `decode_ack` 96-byte PSK compare | Trusted device-supplied `extra_len` | Bounds-checked against `transfer->buffer + actual_length` |
| Dead code | `init_psk_read_ack_cb`, `init_psk_read_hash_ack_cb`, `async_send_tls_cmd`, OTP states, legacy 12-bit decompressor | Removed (1463 → 1390 lines) |
| Debug dumps | `fopen` of raw frames in CWD, no gate | `#ifdef GM168_DEBUG`, writes to `/tmp/gm168_<seq>_*` |
| Comments | Mixed Russian/English, BUG-XX markers | All English, narrative comments explaining the *why* |

---

## Big-picture findings (recorded in RESEARCH.md)

1. **The Wbdi.dll LFSR is dead code on this device.** The driver's pipeline is
   `TLS read → sub_18003bc78 (no descramble, flag=0) → sub_18004e2dc
   ImageRestructInterface → preprocessor`. The `SgxFpParseImage` path in the
   enclave is never taken; the legacy LFSR (sub_180077a84) never fires.

2. **The wire format has no leading header**, contrary to earlier RESEARCH.md.
   The 10564-byte TLS plaintext is **80 wire rows × 132 bytes** (96 data + 36
   zero pad each) followed by a **4-byte trailer**. The trailer was previously
   misread as a leading header.

3. **`ImageRestructInterface` switch case 0x11** (the active mode on this
   device) dispatches to `sub_18004e030` (de-pad 80×132 → 80×96 compact) → 
   `sub_18004ef00` (12-bit unpack + inline transpose to 64×80). This is what
   `gm168_decode_frame()` reproduces verbatim.

4. **New command `0xD6` discovered**: MCU Read Register
   (`IoHubReadReg` → `MilanFSerSpiReadReg`). 2-byte payload = reg addr LE,
   2-byte response. Driver reads register 0 once per session.

5. **Runtime capture loop is `0xAE → 0x34 → 0x34 → 0x32 → 0x20`** (not the
   "0x34×2 only after background" pattern the old RESEARCH.md described). The
   AE+rearm pair fires every cycle.

---

## Tooling delivered

`frida_work/gx_hook.js` — instrumentation hook covering the whole Wbdi.dll
pipeline. Writes per-stage binary dumps to `C:\Windows\Temp\gx_dumps\`. Saves
session log via `script(1)` / `2>` redirect.

`scripts/`
- `deploy_frida.ps1` — PC → laptop Windows side (port 22)
- `deploy_linux.ps1` — PC → laptop Linux/WSL side (port 2200)
- `fetch_session.ps1` — laptop → PC, pulls session.log + matching dumps
- `protocol_checklist.py` — parses session.log into a per-command timeline
  with init-sequence validation
- `solve_seed.py` — final working frame decoder (Python reference)
- `verify_driver_decode.py` — runs both reference and driver-port decoders
  on captured RECV bytes, compares to ground-truth INPUT
- `test_decode.c` — standalone C parity test for the driver's `gm168_decode_frame`

---

## Tasks completed in this session (12 of 14)

| # | Title |
|---|---|
| 1 | Reverse SgxFpParseImage in WbdiEnclave |
| 2 | Port decode (de-pad + 12-bit + transpose) to Linux driver |
| 4 | Update RESEARCH.md with corrected findings |
| 5 | Build protocol-checklist Frida hook |
| 6 | Identify cmd 0xD6 semantics |
| 7 | Document runtime capture-loop pattern |
| 8 | Add retry counter to ack_cb and INIT_OTP_READ_ACK |
| 9 | Add cancellation guard to bg_rx_cb |
| 10 | Guard against double-start of polling |
| 11 | Bounds-check 96-byte PSK compare |
| 12 | Cleanup pass — debug code, magic numbers, dead PSK_READ, mixed comments |
| 14 | Multi-frame background averaging + percentile stretch |

## Open

| # | Title | Why deferred |
|---|---|---|
| 3 | Use Cal1 from calib_windows.dat instead of runtime background | Blocked on #13 — naive `0xFFF - raw + Cal1` doesn't reproduce FRAME |
| 13 | Reverse preprocessor sub_18010f650 (Cal1+Cal2 calibration math) | Big RE task, see NEXT_STEPS.md |
