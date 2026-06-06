# Next Steps — Roadmap

Ordered roughly by impact-per-effort. Each item has rough effort and the
concrete starting point.

---

## P0 — Quality v3: chase verify reliability (current frontier)

**Status (2026-06-05).** The Windows preprocessor IS now reverse-engineered
and ported. Math is byte-for-byte verified in Python against Frida-captured
intermediates (HENV, VENV, STRETCH pass; MORPH passes the inner 98.5% but
the border-stencil is left as a simpler edge-replicate). The C port lives
in [goodix_gm168.c](../goodix_gm168/goodix_gm168.c) `gm168_envelope_stretch`.

Quality leap so far:
- Enroll: **5/5 stages, completes cleanly** (was 4/5 stalled with CLAHE).
- Per-frame NBIS fail: **~33%** (was 44%).
- **Verify still misses** — minutiae extracted on most captures, but they
  don't match the enrolled template. Per-capture position drift of ~1px
  on speckle-prone areas is the leading hypothesis. Tried adding a 3x3
  post-blur on output — killed too many ridges, made it worse. Tried 3x3
  MEDIAN on the bg-corrected source — visually cleaned isolated outliers
  but didn't materially change verify match rate (operator stopped before
  running full verify cycle on this build).

**What's left for v3 — ordered by expected impact:**

1. **MORPH border fix.** The X5 morph close skips border pixels (row 0,
   row H-1, col 0, col W-1). Per Frida dumps these 1.5% of pixels differ
   from Windows. Visually the artefact is short dashed-line breaks inside
   ridges near the frame edge. Cheap to fix — implement the 3-point /
   2-point reduced stencils that `sub_18010f1f0` uses on borders. The
   Binja decompile of f1f0 has the exact pattern.
2. **Multi-frame averaging before envelope.** Stretch a *temporally
   averaged* frame, not a single capture. 2-3 fast back-to-back captures
   averaged would attenuate temporal noise without softening ridges
   (unlike spatial blur). Needs minor SSM change to collect N frames per
   capture cycle.
3. **Smoother kernel reverse.** Last unknown from Wbdi.dll. We know:
   `sub_18010b910` calls `sub_180112a00` + `sub_180112820` + (optionally)
   `sub_180115410` with op-code 10. That op-code dispatcher is universal
   image-op; need to follow op=10 specifically. Effort: a couple hours
   of Binja + Python prototype.

**Where to start.** Skim [goodix_gm168.c](../goodix_gm168/goodix_gm168.c)
`gm168_envelope_stretch` for the current C. The Python prototype in
[scratch/py/preproc_proto.py](../scratch/py/preproc_proto.py) loads the
20260604231709 dump set under
[scratch/dumps/preproc_trace_20260604231709/](../scratch/dumps/preproc_trace_20260604231709/)
and validates stage by stage — use it to A/B any algorithm changes before
porting to C. Frida hook lives at
[frida_work/gx_preproc_trace.js](../frida_work/gx_preproc_trace.js); run
via `frida_work/run_preproc_trace.bat` for fresh dumps.

---

## P0 — Quality v2 (DONE): reverse the Windows preprocessor (Task #13)

**Original status (kept for history).** Tried two cheap-win passes before
committing to deep RE:

1. **CLAHE + 3×3 Gaussian post** (committed, see [goodix_gm168.c](../goodix_gm168/goodix_gm168.c)
   `gm168_clahe`). Lifts per-frame NBIS success from ~0 % (baseline percentile-
   stretch on today's noisier captures) to ~56 %. Enroll reliably reaches
   stage 4/5 but stalls there.
2. **Sauvola / Niblack / adaptive-mean binarisation.** All looked too pixel-
   jagged compared to FRAME — abandoned.

**Hard ceiling discovered.** Eyeballing `INPUT_*.bin` (raw input to Windows
preprocessor, byte-identical to our `gm168_decode_frame` output) against
the matching `FRAME_*.bin` (Windows output) shows the **raw decode is visual
noise** — column striping, no human-visible ridges. Yet Windows reliably
extracts crisp swirls. So the gap isn't post-processing polish — it's
*signal recovery*: Cal1 (dark ref), Cal2 (bright ref), and the ~197 KB
parameter block are doing physical-level FPN/gain correction we can't
approximate without RE.

> Quick proof: `scratch/enroll2/raw_vs_frame.png` (regenerable via the
> Python in this commit's discussion) shows INPUT (raw stretched) next
> to FRAME for the same finger. The fingerprint is **invisible in INPUT**
> and **crystal clear in FRAME**.

So any post-processing trick on top of our current decode (CLAHE, Gabor,
ridge enhancement) caps somewhere around the current ~56 %. The only path
to 90 %+ is RE of `sub_18010f650`.

**Current quality gap is the Windows preprocessor's per-pixel gain+offset
math using Cal1 (dark reference) and Cal2 (bright reference) from
`calib_windows.dat`,** plus a ~197 KB parameter block. Naïve
`signal = 0xFFF - raw + Cal1` does not reproduce the Windows output.

**Where to start.**
- Binary Ninja, `Wbdi.dll.bndb`, function `sub_18010f650` (called from
  `preprocessor` at RVA `0xc87b0`).
- Watch how `data_18025f070..0x84` (the 197 KB config block) is indexed.
- Calibration blob `calib_windows.dat`: Cal1 at `0x0008`, Cal2 at `0x9928`,
  both 14080 bytes (88×80 uint16). Likely cropped/transposed inside the
  preprocessor to match the 64×80 output shape.
- Frida-captured `FRAME` files in `frida_work/dumps/*_FRAME_*.bin` are ground
  truth — when the Linux port matches them byte-for-byte (the way
  `gm168_decode_frame` matches `INPUT_*.bin`), the work is done.

**Expected effort.** Several hours of focused RE plus Python prototype, then
~50–100 lines of C in the driver.

**Effect.** NBIS success rate jumps toward 95+ %, enroll consistently closes
5/5, driver becomes production-grade.

---

## P0 — Cal1+Cal2 driver path (Task #3, blocked on #13)

Once #13 is decoded, replace the multi-frame BG capture with static Cal1
loaded from a packaged `calib_windows.dat`. Also drop `INIT_BG_*` states.

**Where to start.** Implement a `gm168_load_calibration()` helper that mmap's
the blob, verifies the CRCs, and stuffs the parameters into a runtime struct.
The capture path uses that struct instead of `self->background`.

**Open question.** Is `calib_windows.dat` device-specific or universal? The
blob currently in the repo was captured from one device. Need a second sensor
to confirm.

**Effort.** Half a day after #13.

---

## P1 — PSK portability check

Today the driver ships with a hardcoded `REAL_PSK` (32 bytes) in
`goodix_proto.c:16`, captured via Frida on the development device. Unknown
whether this PSK is universal across all GM168 sensors or device-unique.

**Test.** Plug a second GM168 unit (different machine, never touched by our
Frida hook) into Linux and run the driver. If TLS handshake fails →
device-unique PSK.

**Fallback if device-unique.** Reverse `SetIapModeGeneva` in `Wbdi.dll` to
understand the IAP (In-Application Programming) protocol, then implement
factory-reset / first-time-provisioning support in the Linux driver. Real
work — flash writes are destructive and need careful testing.

**Effort to test.** 30 minutes if a second sensor is available.
**Effort to fix.** Days if IAP RE needed.

---

## P1 — End-to-end enrollment + verify

Once #13 + #3 land, the next milestone is:
1. `examples/enroll` completes 5/5 stages and persists an `FpPrint`.
2. `examples/verify` with the same finger succeeds.
3. `examples/verify` with a different finger fails (no false-positive).

Currently enroll reaches stage 3. Verify has not been tried at all.

**Effort.** Mostly testing once preprocessor is fixed.

---

## P2 — Library-of-libfprint PR submission

Get the driver merged upstream so users don't need an out-of-tree build.

**Pre-flight checklist** (mostly done):
- [x] 0 build warnings under libfprint's strict flags
- [x] No mixed-language comments, no BUG-XX markers
- [x] Debug code gated under `#ifdef`
- [x] Init / runtime / deactivate stable, no infinite loops
- [x] Decoder verified against ground-truth via standalone parity test
- [ ] At least one full enroll → verify round-trip working (blocked on #13)
- [ ] Test on a second device (blocked on PSK portability)
- [ ] Tests + udev rule + metainfo entry following libfprint conventions

**Effort.** A few days of polish + review iteration once correctness is solid.

---

## Tooling we already have and would re-use

- `frida_work/gx_hook.js` — instrument any new Wbdi.dll function as needed
  during #13. Has output to `C:\Windows\Temp\gx_dumps\`, session-id'd.
- `scripts/protocol_checklist.py` — drop-in for verifying any changes to the
  init sequence don't break command ordering.
- `scripts/verify_driver_decode.py` — drop-in for verifying any new C decode
  path matches the Python reference and the captured ground truth.
- `scripts/test_decode.c` — standalone harness pattern; same idea works for
  testing a Cal1+Cal2 port without rebuilding all of libfprint.

---

## Quick wins available without doing #13

### Already tried this session — results

| Variant | Per-frame NBIS fail | Highest enroll stage | Verdict |
|---|---|---|---|
| Old percentile-stretch (was historical baseline) | 100 % today | 2/5 | broken on noisier captures |
| CLAHE only (4×5 tiles, clip=16) | 64 % | 4/5 | better |
| **CLAHE + 3×3 Gaussian (CLIP=16) ← shipped** | **44 %** | **4/5** | **current** |
| CLAHE + Gaussian, CLIP=6 | 55 % | 3/5 | under-boosts ridges |
| CLAHE + Gaussian, no `FPI_IMAGE_COLORS_INVERTED` | 81 % | 4/5 (22 fails / 27) | polarity flip kills NBIS |
| Sauvola / Niblack / adaptive-mean binarisation | not run live | — | visually pixel-jagged, abandoned |

Set `$GM168_NO_CLAHE=1` to A/B against the plain percentile stretch.

### Other quick wins still on the table (untested)

1. **Bump `GM168_BG_FRAMES` to 10 or 20.** Slower init but lower temporal
   noise in the background reference. Marginal.
2. **Median across BG frames instead of mean.** Resists hot-pixel pollution
   of the reference.
3. **Smooth the BG (3×3 box) before subtraction.** Removes its per-pixel
   noise without losing the low-frequency offset pattern.
4. **Gabor ridge enhancement** (~200 LOC C): estimate local ridge
   orientation, apply oriented band-pass. Standard fingerprint enhancement;
   should pull the ceiling toward ~70-80 % without touching `sub_18010f650`.
5. **Mark the driver "experimental" in libfprint metainfo** and submit
   anyway. Several upstream drivers ship low-confidence and that's accepted.

None of these are strictly *needed* — they're just options if you want to
defer #13.

---

## Suggested next session order

1. Open `WbdiEnclave.signed.dll.bndb` and `Wbdi.dll.bndb` in Binary Ninja.
2. Start on `sub_18010f650` decompile. Identify Cal1 / Cal2 indexing.
3. Prototype in Python using the captured `INPUT_*` (input) and `FRAME_*`
   (Windows preprocessor output) — iterate until pixel-perfect.
4. Port to C in `goodix_gm168.c`, behind a `#define GM168_USE_CAL_PREPROC`
   for now to keep multi-BG as a fallback.
5. Drop the BG-capture init states once Cal-preproc is verified to outperform.
6. Run enroll → expect 5/5; run verify → expect match.
