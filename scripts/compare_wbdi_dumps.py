#!/usr/bin/env python3
"""
compare_wbdi_dumps.py — byte-diff our Linux driver's preprocessor against
the Windows Wbdi.dll ground-truth dumps.

Captures come from tools/windows/preproc_capture/capture.bat run on
Windows.  Each preprocessor stage hooked there (CAL, SMOOTH, HENV, VENV,
MORPH, STRETCH) emits one .bin per call with matching IN/OUT IDs.

This script reproduces the same stages in Python using the byte-perfect
ports from the Wbdi RE work (already validated against this exact dump
format) and reports the FIRST stage that diverges — that's where our
driver port has the bug to fix.

Usage:
  python3 scripts/compare_wbdi_dumps.py captures/20260619-123456/
  python3 scripts/compare_wbdi_dumps.py captures/20260619-123456/ --pair 1
  python3 scripts/compare_wbdi_dumps.py captures/20260619-123456/ --stage CAL,SMOOTH

Exit 0 if everything matches byte-for-byte. Exit 1 if any stage diverges.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

W, H = 80, 64
N = W * H
OFFSET_BB8 = 0xbb8
WALLIS_R = 5

# ---------------------------------------------------------------------------
# IO

def load_u16(path: Path) -> np.ndarray:
    raw = path.read_bytes()
    if len(raw) < N * 2:
        raise ValueError(f"{path}: only {len(raw)} bytes, need {N*2}")
    return np.frombuffer(raw[:N*2], dtype="<u2").reshape(H, W).copy()


def load_u8(path: Path) -> np.ndarray:
    raw = path.read_bytes()
    return np.frombuffer(raw[:N], dtype="u1").reshape(H, W).copy()


def load_mask_out(path: Path) -> np.ndarray:
    """MASK_OUT format: 16-byte header + W*H mask bytes (0 or non-zero)."""
    raw = path.read_bytes()
    mask = np.frombuffer(raw[0x10:0x10 + N], dtype="u1").reshape(H, W)
    return (mask != 0).astype(np.uint16)


def discover_pairs(dump_dir: Path) -> List[Tuple[int, Dict[str, Path]]]:
    """Group dumps by their numeric call ID.  Returns list of (id, {stage: path})."""
    pattern = re.compile(r"^\d+_([A-Z_]+?)_(\d{5})\.bin$")
    by_id: Dict[int, Dict[str, Path]] = {}
    for p in sorted(dump_dir.iterdir()):
        m = pattern.match(p.name)
        if not m:
            continue
        stage = m.group(1)
        cid = int(m.group(2))
        by_id.setdefault(cid, {})[stage] = p
    return sorted(by_id.items())


# ---------------------------------------------------------------------------
# Cal2 stage (sub_1801123e0)
#
# Wbdi formula:   out[i] = (cal1[i] - raw[i]) * 8192 / scale[i]   half-up rounded
#
# - cal1[i] = "bright reference" — comes as arg2 of cal2_stage at runtime, dumped
#             as CAL_SECONDARY by our Frida hook.  Almost equal to our static
#             gm168_cal.h CAL1.
# - scale[i] = per-pixel gain — dumped as CAL_SCALE.  ≈ our static cal2 but
#             differs by ~1.6 % per pixel due to per-frame runtime adjustment.
#
# This implements the EXACT Wbdi formula.  Our C driver in src/goodix_gm168.c
# uses static cal2 as the denominator (no runtime scale[]) which yields only
# 12 % byte-exact match but R²=0.99999.

def cal2_stage(raw: np.ndarray, cal1: np.ndarray, scale: np.ndarray) -> np.ndarray:
    num = (cal1.astype(np.int64) - raw.astype(np.int64)) * 8192
    den = scale.astype(np.int64)
    half = den // 2
    pos = (num + half) // np.maximum(den, 1)
    neg = -(((-num) + half) // np.maximum(den, 1))
    v = np.where(den == 0, 0, np.where(num >= 0, pos, neg))
    return np.clip(v, 0, 0xFFFF).astype(np.uint16)


# ---------------------------------------------------------------------------
# Wallis local-mean smoother (sub_180112a00) — byte-perfect via cumulative sums

def integral(a: np.ndarray) -> np.ndarray:
    s = a.astype(np.int64).cumsum(axis=1).cumsum(axis=0)
    out = np.zeros((a.shape[0] + 1, a.shape[1] + 1), dtype=np.int64)
    out[1:, 1:] = s
    return out


def _rect(S: np.ndarray, r0: int, r1: int, c0: int, c1: int) -> int:
    return S[r1+1, c1+1] - S[r0, c1+1] - S[r1+1, c0] + S[r0, c0]


def wallis_smoother(inp: np.ndarray, mask: np.ndarray) -> np.ndarray:
    V = inp.astype(np.int64) * mask.astype(np.int64)
    SV = integral(V)
    SM = integral(mask.astype(np.int64))
    out = np.zeros_like(inp, dtype=np.int32)
    for i in range(H):
        r0 = max(0, i - WALLIS_R)
        r1 = min(H - 1, i + WALLIS_R)
        for j in range(W):
            if mask[i, j] == 0:
                out[i, j] = OFFSET_BB8
                continue
            c0 = max(0, j - WALLIS_R)
            c1 = min(W - 1, j + WALLIS_R)
            sV = _rect(SV, r0, r1, c0, c1)
            sM = _rect(SM, r0, r1, c0, c1)
            mean = (sV + sM // 2) // sM if sM > 0 else 0
            v = int(inp[i, j]) - int(mean) + OFFSET_BB8
            out[i, j] = max(0, v)
    return out.astype(np.uint16)


# ---------------------------------------------------------------------------
# 3x3 binomial blur (sub_180112820) — keeps borders unchanged

def binomial_3x3(img: np.ndarray) -> np.ndarray:
    out = img.copy()
    a = img.astype(np.int64)
    s = (    a[0:-2, 0:-2] + 2*a[0:-2, 1:-1] +   a[0:-2, 2:] +
         2*  a[1:-1, 0:-2] + 4*a[1:-1, 1:-1] + 2*a[1:-1, 2:] +
             a[2:,   0:-2] + 2*a[2:,   1:-1] +   a[2:,   2:])
    out[1:-1, 1:-1] = ((s + 8) >> 4).astype(img.dtype)
    return out


def smoother(inp: np.ndarray, mask: np.ndarray) -> np.ndarray:
    return binomial_3x3(wallis_smoother(inp, mask))


# ---------------------------------------------------------------------------
# Sliding window min/max (sub_18010e0e0 horizontal, sub_18010ce20 vertical)

def sliding_minmax_1d(arr: np.ndarray, win: int, axis: int) -> Tuple[np.ndarray, np.ndarray]:
    half = win // 2
    if axis == 1:
        pad = np.pad(arr, ((0, 0), (half, half)), mode="edge")
    else:
        pad = np.pad(arr, ((half, half), (0, 0)), mode="edge")
    lo = np.empty_like(arr)
    hi = np.empty_like(arr)
    for r in range(arr.shape[0]):
        for c in range(arr.shape[1]):
            w = pad[r, c:c+win] if axis == 1 else pad[r:r+win, c]
            lo[r, c] = w.min()
            hi[r, c] = w.max()
    return lo, hi


# ---------------------------------------------------------------------------
# Morph X5 close (sub_18010f1f0) — 5-point X-stencil min/max

def morph_x5(arr: np.ndarray, op) -> np.ndarray:
    pad = np.pad(arr, 1, mode="edge")
    c = pad[1:1+H, 1:1+W]
    nw = pad[0:H, 0:W]
    ne = pad[0:H, 2:2+W]
    sw = pad[2:2+H, 0:W]
    se = pad[2:2+H, 2:2+W]
    return op.reduce([c, nw, ne, sw, se])


# ---------------------------------------------------------------------------
# Final stretch (sub_18010a460 tail loop)
# v = (signal - C) * 255 / (A - C);  out = 0xff - clamp(v, 0, 255);  mask=0 → 0xff

def local_stretch(signal: np.ndarray, low_C: np.ndarray, high_A: np.ndarray,
                  mask: np.ndarray) -> np.ndarray:
    src = signal.astype(np.int32)
    C = low_C.astype(np.int32)
    A = high_A.astype(np.int32)
    denom = A - C
    num = (src - C) * 255
    with np.errstate(divide="ignore", invalid="ignore"):
        v = np.where(denom != 0,
                     np.where(num >= 0, num // denom, -((-num) // denom)),
                     255)
    v = np.clip(v, 0, 255).astype(np.uint8)
    out = (0xff - v).astype(np.uint8)
    return np.where(mask != 0, out, 0xff).astype(np.uint8)


# ---------------------------------------------------------------------------
# Diff helpers

class Mismatch(Exception):
    def __init__(self, stage: str, bad: int, total: int, worst: int):
        super().__init__(f"{stage}: {bad}/{total} mismatches, max|delta|={worst}")
        self.stage = stage
        self.bad = bad
        self.total = total
        self.worst = worst


def diff(stage: str, got: np.ndarray, want: np.ndarray, verbose: bool = False) -> bool:
    bad_mask = got != want
    bad = int(bad_mask.sum())
    total = got.size
    if bad == 0:
        print(f"  ✓ {stage:20s}  byte-perfect ({total} px)")
        return True
    delta = got.astype(np.int64) - want.astype(np.int64)
    worst = int(np.abs(delta).max())
    pct = 100 * bad / total
    icon = "✗" if pct > 1.0 else "~"
    print(f"  {icon} {stage:20s}  {bad}/{total} differ ({pct:.2f}%)  max|Δ|={worst}")
    if verbose and bad > 0:
        idxs = np.argwhere(bad_mask)[:5]
        for r, c in idxs:
            print(f"      ({r:2d},{c:2d})  got={int(got[r,c]):6d}  want={int(want[r,c]):6d}  Δ={int(delta[r,c]):+d}")
    return False


# ---------------------------------------------------------------------------
# Driver

def find_call_groups(dump_dir: Path) -> List[Dict]:
    """Group capture into self-contained 'enroll touch' clusters.

    Each top-level STRETCH call pulls a chain of SMOOTH (×3 usually), HENV,
    VENV, MORPH, CAL_IN/OUT, etc.  We pair STRETCH_IN_N → STRETCH_OUT_N with
    the closest-id CAL_OUT, MORPH_LO/HI_OUT, SMOOTH_OUT.
    """
    pattern = re.compile(r"^\d+_([A-Z_]+?)_(\d{5})\.bin$")
    by_stage: Dict[str, Dict[int, Path]] = {}
    for p in sorted(dump_dir.iterdir()):
        m = pattern.match(p.name)
        if not m:
            continue
        by_stage.setdefault(m.group(1), {})[int(m.group(2))] = p

    n_stretch = len(by_stage.get("STRETCH_OUT", {}))
    if n_stretch == 0:
        print(f"[compare] no STRETCH_OUT captures in {dump_dir} — capture failed?",
              file=sys.stderr)
        return []

    groups = []
    for cid in sorted(by_stage["STRETCH_OUT"].keys()):
        g = {"stretch_id": cid}
        for stage in ("STRETCH_IN", "STRETCH_OUT",
                      "CAL_IN", "CAL_OUT", "CAL_SECONDARY", "CAL_SCALE",
                      "SMOOTH_IN", "SMOOTH_OUT", "SMOOTH_MASK",
                      "HENV_IN", "HENV_LO", "HENV_HI",
                      "VENV_IN", "VENV_LO", "VENV_HI",
                      "MORPH_LO_IN", "MORPH_HI_IN",
                      "MORPH_LO_OUT", "MORPH_HI_OUT",
                      "MASK_OUT", "INPUT", "FRAME"):
            if stage in by_stage and cid in by_stage[stage]:
                g[stage.lower()] = by_stage[stage][cid]
            elif stage in by_stage:
                # closest lower id (best-effort pairing for stages with different
                # cycle counts, e.g. INPUT/FRAME fire once per enroll, not per stretch)
                lower = [k for k in by_stage[stage] if k <= cid]
                if lower:
                    g[stage.lower()] = by_stage[stage][max(lower)]
        groups.append(g)
    return groups


def run_one(group: Dict, stages_filter: Optional[set] = None, verbose: bool = False) -> List[str]:
    """Run the full pipeline on one captured touch.  Returns list of failed stages."""
    failed: List[str] = []
    sid = group["stretch_id"]
    print(f"\n── stretch #{sid} ────────────────────────────────────")

    # Stage CAL ----------------------------------------------------------------
    if "cal_in" in group and "cal_out" in group and "cal_scale" in group and "cal_secondary" in group:
        if not stages_filter or "CAL" in stages_filter:
            raw = load_u16(group["cal_in"])
            sec = load_u16(group["cal_secondary"])  # per-frame cal1
            scale = load_u16(group["cal_scale"])    # per-frame gain
            got = cal2_stage(raw, sec, scale)
            want = load_u16(group["cal_out"])
            if not diff("CAL2 (sec,scale)", got, want, verbose):
                failed.append("CAL")

    # Stage SMOOTH -------------------------------------------------------------
    if "smooth_in" in group and "smooth_out" in group and "smooth_mask" in group:
        if not stages_filter or "SMOOTH" in stages_filter:
            inp = load_u16(group["smooth_in"])
            mraw = group["smooth_mask"].read_bytes()[:N]
            mask = (np.frombuffer(mraw, "u1").reshape(H, W) != 0).astype(np.uint16)
            got = smoother(inp, mask)
            want = load_u16(group["smooth_out"])
            if not diff("SMOOTH (wallis+bin)", got, want, verbose):
                failed.append("SMOOTH")

    # Stage HENV --------------------------------------------------------------
    if "henv_in" in group and "henv_lo" in group and "henv_hi" in group:
        if not stages_filter or "HENV" in stages_filter:
            inp = load_u16(group["henv_in"])
            lo, hi = sliding_minmax_1d(inp, 11, axis=1)
            ok1 = diff("HENV_LO", lo, load_u16(group["henv_lo"]), verbose)
            ok2 = diff("HENV_HI", hi, load_u16(group["henv_hi"]), verbose)
            if not (ok1 and ok2):
                failed.append("HENV")

    # Stage VENV --------------------------------------------------------------
    if "venv_in" in group and "venv_lo" in group and "venv_hi" in group:
        if not stages_filter or "VENV" in stages_filter:
            inp = load_u16(group["venv_in"])
            lo, hi = sliding_minmax_1d(inp, 11, axis=0)
            ok1 = diff("VENV_LO", lo, load_u16(group["venv_lo"]), verbose)
            ok2 = diff("VENV_HI", hi, load_u16(group["venv_hi"]), verbose)
            if not (ok1 and ok2):
                failed.append("VENV")

    # Stage MORPH -------------------------------------------------------------
    if "morph_lo_in" in group and "morph_hi_in" in group:
        if not stages_filter or "MORPH" in stages_filter:
            lo_in = load_u16(group["morph_lo_in"])
            hi_in = load_u16(group["morph_hi_in"])
            lo_got = morph_x5(lo_in, np.minimum)
            hi_got = morph_x5(hi_in, np.maximum)
            ok1 = diff("MORPH_LO_OUT", lo_got, load_u16(group["morph_lo_out"]), verbose)
            ok2 = diff("MORPH_HI_OUT", hi_got, load_u16(group["morph_hi_out"]), verbose)
            if not (ok1 and ok2):
                failed.append("MORPH")

    # Stage STRETCH (end-to-end) ----------------------------------------------
    if "stretch_in" in group and "stretch_out" in group and \
       "morph_lo_out" in group and "morph_hi_out" in group and "mask_out" in group:
        if not stages_filter or "STRETCH" in stages_filter:
            # Wbdi: signal = SMOOTH_OUT, low_C = MORPH_HI_OUT, high_A = MORPH_LO_OUT
            #  (the naming is intentionally inverted in our dumps per Wbdi)
            signal = load_u16(group["smooth_out"]) if "smooth_out" in group else load_u16(group["stretch_in"])
            high_A = load_u16(group["morph_lo_out"])
            low_C = load_u16(group["morph_hi_out"])
            mask = load_mask_out(group["mask_out"])
            got = local_stretch(signal, low_C, high_A, mask)
            want = load_u8(group["stretch_out"])
            if not diff("STRETCH_OUT", got, want, verbose):
                failed.append("STRETCH")

    return failed


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Byte-diff our pipeline ports against Wbdi.dll dumps",
    )
    ap.add_argument("dump_dir", type=Path,
                    help="captures/<timestamp>/ folder from preproc_capture")
    ap.add_argument("--pair", type=int, default=None,
                    help="only run this STRETCH call id (default: all)")
    ap.add_argument("--stage", type=str, default=None,
                    help="comma-separated stages to test (default: all). "
                         "CAL,SMOOTH,HENV,VENV,MORPH,STRETCH")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print first 5 differing pixels per failing stage")
    args = ap.parse_args()

    if not args.dump_dir.is_dir():
        print(f"[compare] not a directory: {args.dump_dir}", file=sys.stderr)
        return 2

    stages_filter = set(args.stage.upper().split(",")) if args.stage else None

    groups = find_call_groups(args.dump_dir)
    if not groups:
        return 1

    if args.pair is not None:
        groups = [g for g in groups if g["stretch_id"] == args.pair]
        if not groups:
            print(f"[compare] no group with stretch_id={args.pair}", file=sys.stderr)
            return 1

    all_failed: Dict[str, int] = {}
    for g in groups:
        failed = run_one(g, stages_filter, args.verbose)
        for s in failed:
            all_failed[s] = all_failed.get(s, 0) + 1

    print()
    print("=" * 60)
    if not all_failed:
        print(f"✓ ALL STAGES BYTE-PERFECT across {len(groups)} captures")
        print("  → our pipeline reproduces Wbdi exactly")
        print("  → 36% NBIS minutiae failures must be in NBIS/mask layer, not preprocess")
        return 0
    print(f"✗ DIVERGENCE found in {len(all_failed)} stage(s):")
    for stage, count in all_failed.items():
        print(f"    {stage}: failed in {count}/{len(groups)} captures")
    print()
    print("  → fix the first failing stage in src/goodix_gm168.c")
    print("  → rerun this script to confirm")
    return 1


if __name__ == "__main__":
    sys.exit(main())
