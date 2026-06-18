#!/usr/bin/env python3
"""
single_touch_render.py — render a 4-stage pipeline grid for one capture.

Input  — a directory with these files (produced by the driver when
         GM168_DUMP_FRAMES=1 GM168_DUMP_DIR=<this-dir> is set):
           gm168_NNN_raw16.bin   80*64*2 bytes, 12-bit ADC in 16-bit LE
           gm168_NNN_bg16.bin    same shape, background frame captured at init
           gm168_NNN_fpimg.pgm   final 8-bit P5 PGM after envelope_stretch

Output — one PNG with four tiles side-by-side, each annotated:
           RAW       — raw sensor reading (12→8 bit normalized)
           BG        — background frame   (12→8 bit normalized)
           RAW − BG  — background-subtracted signal (signed, centred on 128)
           FINAL     — what NBIS sees (envelope-stretched 8-bit)

Each tile shows min/max/mean/std and saturation %, so you can pinpoint
which stage clips signal or amplifies noise.

Usage:
  python3 scripts/single_touch_render.py --in <dump_dir> --out <png_path>
  python3 scripts/single_touch_render.py --in <dump_dir> --out <png_path> --seq 002

Requires Pillow (sudo dnf install python3-pillow).
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

FRAME_W, FRAME_H = 80, 64
FRAME_PIXELS = FRAME_W * FRAME_H


# ---------------------------------------------------------------------------
# IO

def read_raw16(path: Path) -> List[int]:
    data = path.read_bytes()
    expect = FRAME_PIXELS * 2
    if len(data) != expect:
        raise ValueError(f"{path}: expected {expect} bytes, got {len(data)}")
    return list(struct.unpack(f"<{FRAME_PIXELS}H", data))


def read_pgm8(path: Path) -> List[int]:
    data = path.read_bytes()
    tokens: List[bytes] = []
    i, n = 0, len(data)
    while len(tokens) < 4 and i < n:
        while i < n and data[i:i + 1] in (b' ', b'\t', b'\n', b'\r'):
            i += 1
        if i < n and data[i:i + 1] == b'#':
            while i < n and data[i:i + 1] != b'\n':
                i += 1
            continue
        start = i
        while i < n and data[i:i + 1] not in (b' ', b'\t', b'\n', b'\r'):
            i += 1
        if i > start:
            tokens.append(data[start:i])
    if len(tokens) < 4 or tokens[0] != b'P5':
        raise ValueError(f"{path}: not P5 PGM")
    if i < n and data[i:i + 1] in (b' ', b'\t', b'\n', b'\r'):
        i += 1
    if int(tokens[1]) != FRAME_W or int(tokens[2]) != FRAME_H:
        raise ValueError(f"{path}: wrong shape")
    pixels = data[i:]
    if len(pixels) != FRAME_PIXELS:
        raise ValueError(f"{path}: short read")
    return list(pixels)


# ---------------------------------------------------------------------------
# Normalization & stats

def stats(values: List[int]) -> dict:
    n = len(values)
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n
    return {
        "min": min(values),
        "max": max(values),
        "mean": mean,
        "std": var ** 0.5,
    }


def saturation_8bit(values: List[int]) -> float:
    sat = sum(1 for v in values if v <= 2 or v >= 253)
    return sat / len(values)


def normalize_12bit_to_8bit(values: List[int]) -> List[int]:
    """Min/max stretch of 12-bit raw to 8-bit for display only."""
    lo, hi = min(values), max(values)
    span = hi - lo
    if span == 0:
        return [128] * len(values)
    return [int((v - lo) * 255 / span) for v in values]


def normalize_signed_to_8bit(values: List[int]) -> List[int]:
    """Centre signed delta at 128, scale by max absolute value."""
    if not values:
        return values
    lo, hi = min(values), max(values)
    span = max(abs(lo), abs(hi))
    if span == 0:
        return [128] * len(values)
    return [int(128 + v * 127 / span) for v in values]


# ---------------------------------------------------------------------------
# mindtct integration — direct NBIS minutiae count

_mindtct_path: Optional[str] = None
_mindtct_checked = False


def run_mindtct(pgm_path: Path) -> Optional[int]:
    """Run mindtct on a PGM and return the minutiae count, or None if
    mindtct is not installed."""
    global _mindtct_path, _mindtct_checked
    if not _mindtct_checked:
        _mindtct_path = shutil.which("mindtct")
        _mindtct_checked = True
        if not _mindtct_path:
            print("[single_touch] mindtct not on PATH — install nbis-bin "
                  "(or libfprint-tools) to get minutiae counts", file=sys.stderr)
    if not _mindtct_path:
        return None
    with tempfile.TemporaryDirectory() as td:
        prefix = Path(td) / "out"
        try:
            subprocess.run(
                [_mindtct_path, str(pgm_path), str(prefix)],
                check=True, capture_output=True, timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None
        xyt = prefix.with_suffix(".xyt")
        if not xyt.exists():
            return None
        # Each minutia is one line: "X Y THETA QUALITY"
        return sum(1 for line in xyt.read_text().splitlines() if line.strip())


# ---------------------------------------------------------------------------
# Discovery

def find_seq(in_dir: Path, wanted_seq: Optional[int]) -> int:
    pattern = re.compile(r"gm168_(\d+)_(raw16|bg16|fpimg)\.(bin|pgm)$")
    found = set()
    for f in in_dir.iterdir():
        m = pattern.match(f.name)
        if m:
            found.add(int(m.group(1)))
    if not found:
        sys.exit(f"[single_touch] no gm168_NNN_* files in {in_dir}")
    if wanted_seq is not None:
        if wanted_seq not in found:
            sys.exit(f"[single_touch] seq {wanted_seq:03d} not in {sorted(found)}")
        return wanted_seq
    return max(found)


# ---------------------------------------------------------------------------
# Tile rendering

def make_tile(pixels8: List[int], label: str, st: dict, sat: float, scale: int):
    """One labelled tile.  Returns (PIL.Image, label_lines)."""
    from PIL import Image, ImageDraw, ImageFont

    img = Image.frombytes("L", (FRAME_W, FRAME_H), bytes(pixels8))
    img = img.resize((FRAME_W * scale, FRAME_H * scale), Image.NEAREST).convert("RGB")

    CAPTION_H = 78
    tile = Image.new("RGB", (img.width, img.height + CAPTION_H), (40, 40, 40))
    tile.paste(img, (0, CAPTION_H))

    draw = ImageDraw.Draw(tile)
    try:
        font_path = "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf"
        if not os.path.exists(font_path):
            font_path = "DejaVuSans.ttf"
        font_big = ImageFont.truetype(font_path, 16)
        font_sm = ImageFont.truetype(font_path, 12)
    except OSError:
        font_big = ImageFont.load_default()
        font_sm = font_big

    draw.text((8, 6), label, fill=(255, 255, 255), font=font_big)
    line2 = f"min:{st['min']:5d}  max:{st['max']:5d}  mean:{st['mean']:6.1f}"
    line3 = f"std:{st['std']:6.2f}                sat:{sat * 100:4.1f}%"
    draw.text((8, 28), line2, fill=(220, 220, 220), font=font_sm)
    draw.text((8, 44), line3, fill=(220, 220, 220), font=font_sm)
    if "p50" in st:
        line4 = f"p10:{st['p10']:4d}  p50:{st['p50']:4d}  p90:{st['p90']:4d}"
        draw.text((8, 60), line4, fill=(180, 220, 180), font=font_sm)
    else:
        draw.text((8, 60), "min/max stretched for display", fill=(160, 160, 160), font=font_sm)
    return tile


# ---------------------------------------------------------------------------
# Main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="in_dir", required=True,
                    help="directory containing gm168_NNN_* dump files")
    ap.add_argument("--out", dest="out_path", required=True,
                    help="output PNG path")
    ap.add_argument("--seq", type=int, default=None,
                    help="dump sequence number (default: latest in dir)")
    ap.add_argument("--scale", type=int, default=5,
                    help="pixel scale factor (default: 5 → 400x320 per tile)")
    args = ap.parse_args()

    try:
        from PIL import Image
    except ImportError:
        sys.exit("error: Pillow not installed.  sudo dnf install -y python3-pillow")

    in_dir = Path(args.in_dir)
    seq = find_seq(in_dir, args.seq)

    raw_path = in_dir / f"gm168_{seq:03d}_raw16.bin"
    bg_path = in_dir / f"gm168_{seq:03d}_bg16.bin"
    pgm_path = in_dir / f"gm168_{seq:03d}_fpimg.pgm"

    if not raw_path.exists() or not pgm_path.exists():
        sys.exit(f"[single_touch] missing required dumps for seq {seq:03d}")

    raw16 = read_raw16(raw_path)
    bg16: Optional[List[int]] = read_raw16(bg_path) if bg_path.exists() else None
    final8 = read_pgm8(pgm_path)

    # envgap is dumped by gm168_envelope_stretch — index runs separately,
    # so just pick the latest available one (same touch).
    envgap_path = in_dir / f"gm168_{seq:03d}_envgap.bin"
    if not envgap_path.exists():
        # fall back to the highest-numbered envgap in the dir (single-touch
        # dump dir usually has only one)
        candidates = sorted(in_dir.glob("gm168_*_envgap.bin"))
        envgap_path = candidates[-1] if candidates else None
    envgap: Optional[List[int]] = read_raw16(envgap_path) if envgap_path and envgap_path.exists() else None

    # finger mask (only dumped when GM168_FINGER_MASK was active)
    fmask_path = in_dir / f"gm168_{seq:03d}_fmask.bin"
    if not fmask_path.exists():
        candidates = sorted(in_dir.glob("gm168_*_fmask.bin"))
        fmask_path = candidates[-1] if candidates else None
    fmask: Optional[List[int]] = None
    if fmask_path and fmask_path.exists():
        fmask = list(fmask_path.read_bytes())

    # mindtct minutiae count on the FINAL pgm — direct NBIS feedback
    mindtct_n: Optional[int] = run_mindtct(pgm_path)

    tiles = []

    raw_st = stats(raw16)
    raw8 = normalize_12bit_to_8bit(raw16)
    tiles.append(("RAW (12-bit ADC)", raw_st, saturation_8bit(raw8), raw8))

    if bg16 is not None:
        bg_st = stats(bg16)
        bg8 = normalize_12bit_to_8bit(bg16)
        tiles.append(("BG (init avg)", bg_st, saturation_8bit(bg8), bg8))

        diff = [r - b for r, b in zip(raw16, bg16)]
        diff_st = stats(diff)
        diff8 = normalize_signed_to_8bit(diff)
        tiles.append(("RAW − BG", diff_st, saturation_8bit(diff8), diff8))

    final_st = stats(final8)
    final_label = "FINAL (envelope→8b)"
    if mindtct_n is not None:
        final_label = f"FINAL  ·  minutiae:{mindtct_n}"
    tiles.append((final_label, final_st, saturation_8bit(final8), final8))

    if fmask is not None:
        mask_st = stats(fmask)
        mask_covered = sum(1 for v in fmask if v > 0) / len(fmask)
        mask_st["p10"] = 0   # repurpose the percentile slots for coverage info
        mask_st["p50"] = int(mask_covered * 100)
        mask_st["p90"] = 100
        tiles.append(("FINGER MASK", mask_st, 0.0, fmask))

    if envgap is not None:
        gap_st = stats(envgap)
        gap_sorted = sorted(envgap)
        gap_p10 = gap_sorted[len(gap_sorted) // 10]
        gap_p50 = gap_sorted[len(gap_sorted) // 2]
        gap_p90 = gap_sorted[len(gap_sorted) * 9 // 10]
        gap_st["p10"] = gap_p10
        gap_st["p50"] = gap_p50
        gap_st["p90"] = gap_p90
        gap8 = normalize_12bit_to_8bit(envgap)
        tiles.append(("ENV-GAP (high-low)", gap_st, saturation_8bit(gap8), gap8))

    rendered = [make_tile(px, lbl, st, sat, args.scale) for lbl, st, sat, px in tiles]
    tile_w = rendered[0].width
    tile_h = rendered[0].height
    grid = Image.new("RGB", (tile_w * len(rendered) + (len(rendered) - 1) * 4, tile_h),
                     (20, 20, 20))
    for i, t in enumerate(rendered):
        grid.paste(t, (i * (tile_w + 4), 0))

    out = Path(args.out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    grid.save(out)
    print(f"[single_touch] seq={seq:03d}  →  {out}  ({grid.width}×{grid.height})")

    raw_clip_lo = sum(1 for v in raw16 if v <= 4) / len(raw16)
    raw_clip_hi = sum(1 for v in raw16 if v >= 4091) / len(raw16)
    print(f"[single_touch] raw clipping: lo={raw_clip_lo*100:.1f}%  hi={raw_clip_hi*100:.1f}%")
    print(f"[single_touch] final std={final_st['std']:.1f}  sat={saturation_8bit(final8)*100:.1f}%")
    if mindtct_n is not None:
        verdict = "✓ NBIS-ok" if mindtct_n >= 8 else ("⚠ marginal" if mindtct_n >= 4 else "✗ too few")
        print(f"[single_touch] mindtct minutiae: {mindtct_n}  {verdict}")
    if fmask is not None:
        covered = sum(1 for v in fmask if v > 0) / len(fmask) * 100
        print(f"[single_touch] finger-mask coverage: {covered:.1f}%")


if __name__ == "__main__":
    main()
