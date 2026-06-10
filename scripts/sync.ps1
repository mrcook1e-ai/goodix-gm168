# sync.ps1 — push local src/ (and scripts/) to Fedora and optionally build
# Usage:
#   .\scripts\sync.ps1               # sync src/ only
#   .\scripts\sync.ps1 -Scripts      # sync src/ + scripts/
#   .\scripts\sync.ps1 -Build        # sync + build
#   .\scripts\sync.ps1 -Run          # sync + build + run
#   .\scripts\sync.ps1 -Scripts -Build

param(
    [switch]$Build,
    [switch]$Run,
    [switch]$Scripts
)

$REMOTE = "mrcook1e@192.168.1.23"
$REMOTE_SRC = "~/dev/goodix-gm168/src"
$LOCAL_SRC = "$PSScriptRoot\..\src"

Write-Host "==> Syncing src/ to $REMOTE`:$REMOTE_SRC" -ForegroundColor Cyan

$files = @(
    # Core driver
    "goodix_gm168.c",
    "goodix_proto.c",
    "goodix_proto.h",
    # TLS layer
    "goodix_tls.c",
    "goodix_tls.h",
    "goodix_tls_handshake.c",
    "goodix_tls_handshake.h",
    "goodix_tls_prf.c",
    "goodix_tls_prf.h",
    "goodix_tls_record.c",
    "goodix_tls_record.h",
    # Helper headers
    "gm168_cal.h",
    "gm168_timeouts.h",
    "gm168_trace.h",
    "gm168_usb_errors.h",
    "gm168_log.h",
    # Logging module
    "gm168_log.c",
    # Build
    "meson.build"
)

foreach ($f in $files) {
    $local = Join-Path $LOCAL_SRC $f
    if (Test-Path $local) {
        Write-Host "  scp $f" -ForegroundColor Gray
        scp -q "$local" "${REMOTE}:${REMOTE_SRC}/${f}"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [!] Failed: $f" -ForegroundColor Red
            exit 1
        }
    }
}

Write-Host "==> src/ sync done" -ForegroundColor Green

# ---- Optional: push scripts/ to the laptop ----
if ($Scripts -or $Build -or $Run) {
    $REMOTE_SCRIPTS = "~/dev/goodix-gm168/scripts"
    $LOCAL_SCRIPTS  = $PSScriptRoot

    $script_files = @(
        "_lib.sh",
        "enroll.sh",
        "enroll_grid.sh",
        "enroll_grid.py",
        "grid_dumps.sh",
        "grid_dumps.py",
        "build.sh",
        "deploy.sh",
        "fetch-logs.sh"
    )

    Write-Host "==> Syncing scripts/ to $REMOTE`:$REMOTE_SCRIPTS" -ForegroundColor Cyan
    foreach ($sf in $script_files) {
        $local_s = Join-Path $LOCAL_SCRIPTS $sf
        if (Test-Path $local_s) {
            Write-Host "  scp $sf" -ForegroundColor Gray
            scp -q "$local_s" "${REMOTE}:${REMOTE_SCRIPTS}/${sf}"
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  [!] Failed: $sf" -ForegroundColor Red
                exit 1
            }
        }
    }
    # Strip Windows CRLF line endings and ensure scripts are executable.
    # Use a single-quoted here-string so PowerShell does NOT interpolate \$ or $ —
    # the sed pattern needs a bare $ (end-of-line anchor), not a literal dollar sign.
    $strip_cmd = @'
sed -i 's/\r$//' ~/dev/goodix-gm168/scripts/*.sh ~/dev/goodix-gm168/scripts/*.py 2>/dev/null; chmod +x ~/dev/goodix-gm168/scripts/*.sh 2>/dev/null; true
'@
    ssh $REMOTE $strip_cmd
    Write-Host "==> scripts/ sync done (CRLF stripped, chmod +x applied)" -ForegroundColor Green
}

if ($Build -or $Run) {
    Write-Host "==> Building on remote..." -ForegroundColor Cyan
    ssh $REMOTE "bash ~/dev/goodix-gm168/scripts/build.sh"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "==> Build FAILED" -ForegroundColor Red
        exit 1
    }
    Write-Host "==> Build OK" -ForegroundColor Green
}

if ($Run) {
    Write-Host "==> Running on remote (finger=6, update=n)..." -ForegroundColor Cyan
    ssh $REMOTE "printf '6\nn\n' | bash ~/dev/goodix-gm168/scripts/run.sh"
}
