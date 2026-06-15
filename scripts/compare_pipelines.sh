#!/usr/bin/env bash
# compare_pipelines.sh — capture the same finger across multiple driver
# pipeline configurations, then compose a stacked PNG so it's obvious
# which env-var combo produces the best image.
#
# Variants (in order):
#   baseline       — no env vars (bg_subtract → median → envelope → stretch)
#   cal2           — GM168_USE_CAL2=1
#                    (baked-in Windows cal1/cal2 instead of bg_subtract)
#   cal2_median    — GM168_USE_CAL2=1 GM168_USE_MEDIAN=1
#                    (+ explicit median 3×3 after cal2)
#   wallis         — GM168_USE_WALLIS=1
#                    (Wallis smoother before envelope — README warns it
#                     regresses enroll, but useful image-quality comparison)
#
# Each variant requires ONE finger touch.  Lift your finger between runs.
#
# Usage:
#   ./scripts/compare_pipelines.sh
#   ./scripts/compare_pipelines.sh --variants baseline,cal2
#   ./scripts/compare_pipelines.sh --keep
#
# Output:
#   logs/compare-YYYYMMDD-HHMMSS/
#     ├ baseline.png       — single-touch grid for this variant
#     ├ cal2.png
#     ├ ...
#     └ all_variants.png   — stacked vertical grid, 1 row per variant
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="$REPO_DIR/logs/compare-$TS"
mkdir -p "$OUT_DIR"

# --- Variant table -------------------------------------------------------
# format: "label|env1=v1 env2=v2 ..."
ALL_VARIANTS=(
    "baseline|"
    "cal2|GM168_USE_CAL2=1"
    "cal2_median|GM168_USE_CAL2=1 GM168_USE_MEDIAN=1"
    "wallis|GM168_USE_WALLIS=1"
)

WANTED=""
KEEP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --variants) WANTED="$2"; shift 2 ;;
        --keep)     KEEP=1; shift ;;
        --help|-h)
            sed -n '2,/^set -euo/p' "$0" | sed -E 's/^# ?//; /^set -euo/d'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# Filter variants if --variants was given
if [[ -n "$WANTED" ]]; then
    IFS=',' read -ra wantedArr <<< "$WANTED"
    filtered=()
    for v in "${ALL_VARIANTS[@]}"; do
        lbl="${v%%|*}"
        for w in "${wantedArr[@]}"; do
            if [[ "$lbl" == "$w" ]]; then filtered+=("$v"); break; fi
        done
    done
    VARIANTS=("${filtered[@]}")
    [[ ${#VARIANTS[@]} -eq 0 ]] && { echo "no matching variants" >&2; exit 2; }
else
    VARIANTS=("${ALL_VARIANTS[@]}")
fi

# --- Run each variant ----------------------------------------------------
echo "[compare] capturing ${#VARIANTS[@]} variant(s) → $OUT_DIR"
echo

LABELS=()
for v in "${VARIANTS[@]}"; do
    label="${v%%|*}"
    envs="${v#*|}"
    LABELS+=("$label")

    echo "──────────────────────────────────────────────────"
    echo "[compare] variant: $label"
    [[ -n "$envs" ]] && echo "[compare]  env: $envs" || echo "[compare]  env: (none)"
    echo "[compare]  → lift your finger, press ENTER when ready, then touch the sensor"
    read -r
    echo

    keep_flag=""
    [[ "$KEEP" -eq 1 ]] && keep_flag="--keep"

    if [[ -n "$envs" ]]; then
        # shellcheck disable=SC2086
        env $envs "$REPO_DIR/scripts/single_touch.sh" \
            $keep_flag --label "$label" --out-dir "$OUT_DIR"
    else
        "$REPO_DIR/scripts/single_touch.sh" \
            $keep_flag --label "$label" --out-dir "$OUT_DIR"
    fi
    echo
done

# --- Compose stacked mega-grid -------------------------------------------
echo "[compare] composing stacked comparison grid"
python3 - "$OUT_DIR" "${LABELS[@]}" <<'PYEOF'
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import os, glob

out_dir = Path(sys.argv[1])
labels  = sys.argv[2:]

rows = []
for lbl in labels:
    matches = sorted(out_dir.glob(f"single-touch-*-{lbl}.png"))
    if not matches:
        print(f"[compare] skip {lbl}: no PNG found")
        continue
    img = Image.open(matches[-1])
    # add a 40px header per row with the variant label
    header_h = 40
    row = Image.new("RGB", (img.width, img.height + header_h), (20, 20, 20))
    row.paste(img, (0, header_h))
    draw = ImageDraw.Draw(row)
    try:
        font_path = "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans-Bold.ttf"
        if not os.path.exists(font_path):
            font_path = "DejaVuSans-Bold.ttf"
        font = ImageFont.truetype(font_path, 22)
    except OSError:
        font = ImageFont.load_default()
    draw.text((12, 8), f"  ▶ {lbl}", fill=(255, 230, 90), font=font)
    rows.append(row)

if not rows:
    print("[compare] no rows to compose"); sys.exit(1)

w = max(r.width for r in rows)
h = sum(r.height for r in rows) + (len(rows) - 1) * 8
stack = Image.new("RGB", (w, h), (10, 10, 10))
y = 0
for r in rows:
    stack.paste(r, ((w - r.width)//2, y))
    y += r.height + 8

out = out_dir / "all_variants.png"
stack.save(out)
print(f"[compare] wrote {out}  ({stack.width}×{stack.height})")
PYEOF

echo
echo "[compare] DONE"
echo "  per-variant grids: $OUT_DIR/<label>.png"
echo "  stacked overview : $OUT_DIR/all_variants.png"
