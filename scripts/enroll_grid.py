#!/usr/bin/env python3
"""
enroll_grid.py — Compose an annotated grid PNG from enroll stage PGMs.

Called by enroll_grid.sh after a session, but can also be run standalone
on any directory of stage_NNN.pgm files.

Each tile shows:
  • Stage number and pass/fail status (green/red caption background)
  • Driver quality  — "drv: XX.X" — parsed from the enroll log SUBMIT line
  • Python quality  — "py:  XX.X" — computed locally with CORRECT bounds
                       (fixes the OOB bug: driver uses y1=72 on a 64-row image)
  • Attempt count and elapsed ms from the log

The dual-quality display lets you verify the OOB fix in goodix_gm168.c:2415
once it lands: driver quality should match python quality after the fix.

Usage:
    python3 scripts/enroll_grid.py \\
        --in   logs/enroll-grid-20260609-123456 \\
        --log  logs/enroll-grid-20260609-123456/enroll.log \\
        --out  logs/enroll-grid-20260609-123456.png \\
        [--cols N] [--scale N] [--no-log]

Requires: Pillow  (pip install Pillow)
"""
import argparse
import glob
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

# ---------------------------------------------------------------------------
# PGM reader (same as grid_dumps.py — kept self-contained)
# ---------------------------------------------------------------------------

def parse_pgm(path: Path) -> Tuple[int, int, bytes]:
    """Minimal P5 binary PGM reader. Returns (w, h, bytes).

    Accepts both single-line ("P5 W H 255\n") and multi-line headers
    (PGM spec allows whitespace-separated tokens between magic and pixels).
    """
    with open(path, "rb") as f:
        data = f.read()
    # Tokenize the header: read whitespace-separated tokens until we have
    # magic + 3 numbers, then the rest is pixel data after one delimiter.
    tokens: List[bytes] = []
    i = 0
    n = len(data)
    while len(tokens) < 4 and i < n:
        # Skip whitespace
        while i < n and data[i:i+1] in (b' ', b'\t', b'\n', b'\r'):
            i += 1
        # Skip comments
        if i < n and data[i:i+1] == b'#':
            while i < n and data[i:i+1] != b'\n':
                i += 1
            continue
        # Read token
        start = i
        while i < n and data[i:i+1] not in (b' ', b'\t', b'\n', b'\r'):
            i += 1
        if i > start:
            tokens.append(data[start:i])
    if len(tokens) < 4 or tokens[0] != b'P5':
        raise ValueError(f"{path}: not a P5 PGM ({b' '.join(tokens[:4])!r})")
    # Skip exactly one whitespace byte after maxval (PGM spec)
    if i < n and data[i:i+1] in (b' ', b'\t', b'\n', b'\r'):
        i += 1
    w = int(tokens[1])
    h = int(tokens[2])
    maxval = int(tokens[3])
    if maxval != 255:
        raise ValueError(f"{path}: expected 8-bit (maxval=255), got {maxval}")
    pixels = data[i:]
    if len(pixels) != w * h:
        raise ValueError(f"{path}: short read {len(pixels)} != {w * h}")
    return w, h, pixels


# ---------------------------------------------------------------------------
# Quality metric — CORRECT version
# ---------------------------------------------------------------------------
# Driver reference: goodix_gm168.c  gm168_quality_metric()
# BUG in driver (as of this session): y1 = 72, but GM168_FRAME_H = 64.
# That reads 8 rows beyond the 80×64 buffer.
#
# Correct bounds for an 80-wide × 64-tall image:
#   x: [16, 64)  — central 48 of 80 columns   (same as driver)
#   y: [8,  56)  — central 48 of 64 rows       (FIX: was [8, 72))
#
# Saturation gate: if > 30 % of pixels are ≤ 2 or ≥ 253 → quality = 0.
# Otherwise: std-dev of the region.

FRAME_W, FRAME_H = 80, 64

# Correct central-region bounds.
QM_X0, QM_X1 = 16, 64   # 48 columns
QM_Y0, QM_Y1 = 8,  56   # 48 rows   ← fix for driver y1=72 OOB

# Driver's BUGGY bounds (for reference in annotations).
QM_Y1_BUG = 72  # reads 8 rows past the end of a 64-row image


def quality_metric(data: bytes, w: int, h: int) -> Tuple[float, float]:
    """Return (correct_quality, sat_fraction) for a processed 8-bit PGM.

    correct_quality — std-dev with fixed y1=56 (not 72).
    sat_fraction    — fraction of pixels in the region that are saturated.
    """
    if w != FRAME_W or h != FRAME_H:
        # Non-standard image (e.g. scaled); compute over the whole thing.
        x0, x1, y0, y1 = 0, w, 0, h
    else:
        x0, x1, y0, y1 = QM_X0, QM_X1, QM_Y0, QM_Y1

    pix: List[int] = [data[y * w + x] for y in range(y0, y1) for x in range(x0, x1)]
    n = len(pix)
    if n == 0:
        return 0.0, 0.0

    sat = sum(1 for p in pix if p <= 2 or p >= 253)
    sat_frac = sat / n
    if sat_frac > 0.30:
        return 0.0, sat_frac

    mean = sum(pix) / n
    variance = sum((p - mean) ** 2 for p in pix) / n
    return variance ** 0.5, sat_frac


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

class StageInfo(NamedTuple):
    stage_n:   int            # 1-based, matches filename stage_NNN.pgm
    total:     int            # total stages reported by libfprint
    passed:    bool
    reason:    str            # "" if passed, error text if failed
    drv_qual:  Optional[float]  # last SUBMIT quality before this stage
    attempts:  Optional[int]
    elapsed_ms: Optional[int]


def parse_log(log_path: Path) -> Dict[int, StageInfo]:
    """Parse enroll log into {stage_n: StageInfo}.

    Parses two patterns interleaved in the log:
      quality-gate: SUBMIT quality=X after N attempts in Yms
      Enroll stage N of M passed. Yay!
      Enroll stage N of M failed with error ...
    """
    if not log_path or not log_path.exists():
        return {}

    re_submit = re.compile(
        r"quality-gate: SUBMIT quality=([\d.]+) after (\d+) attempts in (\d+)ms"
    )
    re_passed = re.compile(r"Enroll stage (\d+) of (\d+) passed")
    re_failed = re.compile(r"Enroll stage (\d+) of (\d+) failed with error (.*)")

    # Queue of SUBMIT events not yet consumed by a stage result.
    pending_submits: List[Tuple[float, int, int]] = []  # (qual, attempts, ms)
    result: Dict[int, StageInfo] = {}

    with open(log_path, "r", errors="replace") as f:
        for line in f:
            m = re_submit.search(line)
            if m:
                pending_submits.append((float(m.group(1)), int(m.group(2)), int(m.group(3))))
                continue

            m = re_passed.search(line)
            if m:
                n, total = int(m.group(1)), int(m.group(2))
                if pending_submits:
                    q, att, ms = pending_submits.pop(0)
                else:
                    q, att, ms = None, None, None
                result[n] = StageInfo(n, total, True, "", q, att, ms)
                continue

            m = re_failed.search(line)
            if m:
                n, total = int(m.group(1)), int(m.group(2))
                reason = m.group(3).strip()
                if pending_submits:
                    q, att, ms = pending_submits.pop(0)
                else:
                    q, att, ms = None, None, None
                # Failed stages don't produce a saved image, but log the info anyway.
                result[n] = StageInfo(n, total, False, reason, q, att, ms)

    return result


# ---------------------------------------------------------------------------
# Colour palette (RGB)
# ---------------------------------------------------------------------------
COL_PASS   = (40,  140,  40)   # dark green — passed
COL_FAIL   = (180,  40,  40)   # dark red   — failed
COL_NOINFO = (80,   80,  80)   # dark gray  — no log data
COL_TEXT   = (255, 255, 255)   # white text on coloured caption
COL_BG     = (200, 200, 200)   # grid background


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Compose an annotated grid PNG from enroll stage PGMs."
    )
    ap.add_argument("--in",    dest="in_dir",   required=True,
                    help="directory containing stage_NNN.pgm files")
    ap.add_argument("--out",   dest="out_path", required=True,
                    help="output PNG path")
    ap.add_argument("--log",   dest="log_path", default=None,
                    help="enroll log (from enroll_grid.sh) for driver quality "
                         "and pass/fail annotation")
    ap.add_argument("--cols",  type=int, default=4,
                    help="grid columns (default: 4)")
    ap.add_argument("--scale", type=int, default=5,
                    help="pixel scale factor (default: 5 → 80×64 → 400×320)")
    ap.add_argument("--no-log", dest="no_log", action="store_true",
                    help="skip log parsing even if --log given")
    args = ap.parse_args()

    try:
        from PIL import Image, ImageDraw, ImageFont  # type: ignore
    except ImportError:
        sys.exit("error: Pillow not installed.  pip install Pillow")

    in_dir = Path(args.in_dir)
    files = sorted(glob.glob(str(in_dir / "stage_*.pgm")))
    if not files:
        sys.exit(f"[enroll_grid] no stage_*.pgm files in {in_dir}")

    log_info: Dict[int, StageInfo] = {}
    if args.log_path and not args.no_log:
        log_info = parse_log(Path(args.log_path))
        print(f"[enroll_grid] parsed {len(log_info)} stage entries from log")

    SCALE      = max(1, args.scale)
    CAPTION_H  = 52     # two lines of text
    COLS       = max(1, args.cols)

    try:
        font_path = "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf"
        if not os.path.exists(font_path):
            font_path = "DejaVuSans.ttf"
        font      = ImageFont.truetype(font_path, 13)
        font_sm   = ImageFont.truetype(font_path, 11)
    except OSError:
        font    = ImageFont.load_default()
        font_sm = font

    tiles = []
    for i, fpath in enumerate(files):
        # ---- Extract stage number from filename ----
        m = re.search(r"stage_(\d+)\.pgm$", os.path.basename(fpath))
        stage_n = int(m.group(1)) if m else (i + 1)

        # ---- Read PGM ----
        try:
            w, h, raw_data = parse_pgm(Path(fpath))
        except Exception as e:
            print(f"[enroll_grid] skip {fpath}: {e}", file=sys.stderr)
            continue

        # ---- Compute CORRECT quality ----
        py_qual, sat = quality_metric(raw_data, w, h)

        # ---- Look up log info ----
        info: Optional[StageInfo] = log_info.get(stage_n)

        # ---- Scale grayscale image ----
        gray_img = Image.frombytes("L", (w, h), raw_data)
        gray_img = gray_img.resize((w * SCALE, h * SCALE), Image.NEAREST)
        # Convert to RGB so we can put coloured caption on same canvas
        fp_rgb = gray_img.convert("RGB")

        tile_w = fp_rgb.width
        tile_h = fp_rgb.height + CAPTION_H
        canvas = Image.new("RGB", (tile_w, tile_h), (255, 255, 255))

        # ---- Caption background ----
        if info is not None:
            cap_colour = COL_PASS if info.passed else COL_FAIL
        else:
            cap_colour = COL_NOINFO
        cap_region = Image.new("RGB", (tile_w, CAPTION_H), cap_colour)
        canvas.paste(cap_region, (0, 0))

        # ---- Paste fingerprint image below caption ----
        canvas.paste(fp_rgb, (0, CAPTION_H))

        # ---- Draw text ----
        draw = ImageDraw.Draw(canvas)

        # Line 1: stage number + status + driver quality
        status_str = "PASS ✓" if (info and info.passed) else \
                     ("FAIL ✗" if (info and not info.passed) else "???")
        total_str  = f"/{info.total}" if info else ""
        drv_str    = f"drv:{info.drv_qual:5.1f}" if (info and info.drv_qual is not None) else "drv: —"
        line1 = f"#{stage_n:02d}{total_str}  {status_str}  {drv_str}"

        # Line 2: python quality + saturation + attempts/timing
        py_str  = f"py:{py_qual:5.1f}"
        sat_str = f"sat:{sat * 100:.0f}%"
        if info and info.attempts is not None:
            att_str = f"  {info.attempts}att  {info.elapsed_ms}ms"
        else:
            att_str = ""
        line2 = f"{py_str}  {sat_str}{att_str}"

        draw.text((6,  6), line1, fill=COL_TEXT, font=font)
        draw.text((6, 26), line2, fill=COL_TEXT, font=font_sm)

        tiles.append(canvas)

    if not tiles:
        sys.exit("[enroll_grid] no tiles to render")

    # ---- Lay out grid ----
    cols = min(COLS, len(tiles))
    rows = (len(tiles) + cols - 1) // cols

    # Allow tiles of different sizes (e.g. if sensor reported different dims
    # for any tile) — grid cell = bounding box.
    cell_w = max(t.width  for t in tiles)
    cell_h = max(t.height for t in tiles)

    grid = Image.new("RGB", (cell_w * cols, cell_h * rows), COL_BG)
    for idx, tile in enumerate(tiles):
        r, c = divmod(idx, cols)
        # Centre smaller tiles in their cell.
        dx = (cell_w - tile.width)  // 2
        dy = (cell_h - tile.height) // 2
        grid.paste(tile, (c * cell_w + dx, r * cell_h + dy))

    out = Path(args.out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    grid.save(out)
    print(
        f"[enroll_grid] {len(tiles)} tiles  →  {out}  ({grid.width}×{grid.height})"
    )

    # ---- Summary ----
    if log_info:
        passed = sum(1 for s in log_info.values() if s.passed)
        failed = sum(1 for s in log_info.values() if not s.passed)
        drv_quals = [s.drv_qual for s in log_info.values()
                     if s.passed and s.drv_qual is not None]
        avg_drv = sum(drv_quals) / len(drv_quals) if drv_quals else float("nan")
        py_quals = []
        for fpath in files:
            try:
                ww, hh, dd = parse_pgm(Path(fpath))
                pq, _ = quality_metric(dd, ww, hh)
                py_quals.append(pq)
            except Exception:
                pass
        avg_py = sum(py_quals) / len(py_quals) if py_quals else float("nan")
        print(
            f"[enroll_grid] stages: {passed} PASS / {failed} FAIL  |  "
            f"avg drv quality: {avg_drv:.1f}  avg py quality: {avg_py:.1f}"
        )
        if drv_quals and py_quals:
            delta = avg_drv - avg_py
            if abs(delta) > 5.0:
                print(
                    f"[enroll_grid] NOTE: drv vs py quality diverges by {delta:+.1f} "
                    f"— expected if driver OOB bug (y1=72) is still present"
                )
            else:
                print(
                    f"[enroll_grid] drv/py quality agree (delta={delta:+.1f}) "
                    f"— OOB fix appears active"
                )


if __name__ == "__main__":
    main()
