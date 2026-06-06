#!/usr/bin/env python3
"""
Compose a grid PNG from /tmp/gm168_*_fpimg.pgm dumps.

Reads PGM files from --in directory, optional --log to extract per-capture
quality scores from a debug.sh-clean log, writes one PNG per --out path.

Usage:
    grid_dumps.py --in DUMPS_DIR --out grid.png [--log enroll.log] [--cols N]

PGM dumps are produced by the goodix_gm168 driver only when built with
-DGM168_DEBUG. See docs/DRIVER.md "Build & test".
"""
import argparse
import glob
import os
import re
import sys
from pathlib import Path


def parse_pgm(path: Path):
    """Minimal P5 binary PGM reader. Returns (w, h, bytes)."""
    with open(path, "rb") as f:
        magic = f.readline().strip()
        if magic != b"P5":
            raise ValueError(f"{path}: not a P5 PGM ({magic!r})")
        # Skip comments
        while True:
            line = f.readline()
            if not line.startswith(b"#"):
                break
        w, h = map(int, line.split())
        maxval = int(f.readline().strip())
        if maxval != 255:
            raise ValueError(f"{path}: expected 8-bit (maxval=255), got {maxval}")
        data = f.read(w * h)
        if len(data) != w * h:
            raise ValueError(f"{path}: short read {len(data)} != {w*h}")
        return w, h, data


# 80×64 = output frame size; raw16/bg16 dumps are 5120 uint16 in row-major.
RAW_W, RAW_H = 80, 64


def _read_u16le(path: Path):
    import struct
    with open(path, "rb") as f:
        raw = f.read(RAW_W * RAW_H * 2)
    if len(raw) != RAW_W * RAW_H * 2:
        raise ValueError(f"{path}: expected {RAW_W*RAW_H*2} bytes, got {len(raw)}")
    return list(struct.unpack(f"<{RAW_W*RAW_H}H", raw))


def parse_raw16(path: Path):
    """Read 80x64 uint16 LE into 8-bit normalised bytes for visualisation."""
    vals = _read_u16le(path)
    vmin, vmax = min(vals), max(vals)
    span = max(1, vmax - vmin)
    norm = bytes((v - vmin) * 255 // span for v in vals)
    return RAW_W, RAW_H, norm, vmin, vmax


def parse_diff16(raw_path: Path, bg_path: Path):
    """Return (raw - bg) normalised to 0..255. Negative clamped to 0.

    What envelope_stretch effectively sees as 'signal' after the first
    background subtraction. If the column FPN is present in raw AND bg
    in the same direction, this view should be much cleaner; if FPN
    survives here, BG subtraction isn't capturing it.
    """
    raw = _read_u16le(raw_path)
    bg = _read_u16le(bg_path)
    diff = [r - b for r, b in zip(raw, bg)]
    vmin, vmax = min(diff), max(diff)
    span = max(1, vmax - vmin)
    norm = bytes(max(0, min(255, (v - vmin) * 255 // span)) for v in diff)
    return RAW_W, RAW_H, norm, vmin, vmax


def parse_qualities(log_path: Path):
    """Extract per-attempt quality scores from a debug.sh enroll log.

    Returns a list in capture order, of (quality, elapsed_ms) tuples.
    Pattern matched: 'quality-gate: attempt=N quality=X.XX elapsed=Yms'
    """
    if not log_path or not log_path.exists():
        return []
    pat = re.compile(r"quality-gate: attempt=\d+ quality=([\d.]+) elapsed=(\d+)ms")
    out = []
    with open(log_path, "r", errors="replace") as f:
        for line in f:
            m = pat.search(line)
            if m:
                out.append((float(m.group(1)), int(m.group(2))))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_dir", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--log", dest="log_path", default=None,
                    help="optional debug.sh log to extract qualities")
    ap.add_argument("--cols", type=int, default=5)
    ap.add_argument("--scale", type=int, default=4)
    ap.add_argument("--with-raw", action="store_true",
                    help="if raw16.bin sibling exists, render it next to fpimg "
                         "(side-by-side compare: decoder vs preprocessor)")
    ap.add_argument("--with-bgdiff", action="store_true",
                    help="if raw16.bin AND bg16.bin exist, render (raw - bg) "
                         "normalised as a third tile — shows the signal "
                         "envelope_stretch actually sees")
    args = ap.parse_args()

    try:
        from PIL import Image, ImageDraw, ImageFont  # type: ignore
    except ImportError:
        sys.exit("error: Pillow not installed. pip install Pillow")

    files = sorted(glob.glob(os.path.join(args.in_dir, "gm168_*_fpimg.pgm")))
    if not files:
        sys.exit(f"no gm168_*_fpimg.pgm in {args.in_dir}")

    qualities = parse_qualities(Path(args.log_path)) if args.log_path else []

    SCALE = args.scale
    CAPTION_H = 28
    COLS = max(1, args.cols)
    BG = 230

    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 14)
    except OSError:
        font = ImageFont.load_default()

    tiles = []
    for i, f in enumerate(files):
        w, h, data = parse_pgm(Path(f))
        img = Image.frombytes("L", (w, h), data)
        img = img.resize((w * SCALE, h * SCALE), Image.NEAREST)

        # Optional side-by-side tiles: raw16, (raw-bg), fpimg.
        extras = []  # list of (img, label_suffix)
        if args.with_raw:
            raw_path = Path(f).with_name(Path(f).name.replace("_fpimg.pgm",
                                                              "_raw16.bin"))
            if raw_path.exists():
                rw, rh, rdata, vmin, vmax = parse_raw16(raw_path)
                ri = Image.frombytes("L", (rw, rh), rdata)
                ri = ri.resize((rw * SCALE, rh * SCALE), Image.NEAREST)
                extras.append((ri, f"  raw[{vmin}..{vmax}]"))

        if args.with_bgdiff:
            raw_path = Path(f).with_name(Path(f).name.replace("_fpimg.pgm",
                                                              "_raw16.bin"))
            bg_path  = Path(f).with_name(Path(f).name.replace("_fpimg.pgm",
                                                              "_bg16.bin"))
            if raw_path.exists() and bg_path.exists():
                dw, dh, ddata, dmin, dmax = parse_diff16(raw_path, bg_path)
                di = Image.frombytes("L", (dw, dh), ddata)
                di = di.resize((dw * SCALE, dh * SCALE), Image.NEAREST)
                extras.append((di, f"  diff[{dmin}..{dmax}]"))

        if extras:
            gap = 8
            tiles_h = max(img.height, *[e[0].height for e in extras])
            row_imgs = [e[0] for e in extras] + [img]
            tile_w = sum(t.width for t in row_imgs) + gap * (len(row_imgs) - 1)
            tile_h = tiles_h + CAPTION_H
            canvas = Image.new("L", (tile_w, tile_h), 255)
            x = 0
            for t in row_imgs:
                canvas.paste(t, (x, CAPTION_H))
                x += t.width + gap
        else:
            tile_w = img.width
            tile_h = img.height + CAPTION_H
            canvas = Image.new("L", (tile_w, tile_h), 255)
            canvas.paste(img, (0, CAPTION_H))

        draw = ImageDraw.Draw(canvas)
        seq_match = re.search(r"gm168_(\d+)_", os.path.basename(f))
        seq = seq_match.group(1) if seq_match else str(i + 1)
        label = f"#{seq}"
        if i < len(qualities):
            q, ms = qualities[i]
            label += f"  q={q:.1f}  {ms}ms"
        for _, suffix in extras:
            label += suffix
        draw.text((6, 6), label, fill=0, font=font)
        tiles.append(canvas)

    cols = min(COLS, len(tiles))
    rows = (len(tiles) + cols - 1) // cols
    tile_w, tile_h = tiles[0].size
    grid = Image.new("L", (tile_w * cols, tile_h * rows), BG)
    for i, t in enumerate(tiles):
        r, c = divmod(i, cols)
        grid.paste(t, (c * tile_w, r * tile_h))

    Path(args.out_path).parent.mkdir(parents=True, exist_ok=True)
    grid.save(args.out_path)
    print(f"[grid] {len(tiles)} tiles → {args.out_path} ({grid.width}x{grid.height})")


if __name__ == "__main__":
    main()
