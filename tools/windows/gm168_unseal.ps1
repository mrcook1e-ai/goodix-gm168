# gm168_unseal.ps1 — extract plaintext PSK from a sealed Goodix GM168 blob.
#
# Usage (interactive):
#   .\gm168_unseal.ps1 -SealedBlob C:\path\to\sealed_psk.bin
#                      -OutPsk     C:\path\to\psk.bin
#
# What it does:
#   1. Self-elevates to admin (UAC prompt) if not already.
#   2. Stages the sealed blob into C:\Windows\Temp\ so SYSTEM can read it.
#   3. Creates a one-shot scheduled task running as NT AUTHORITY\SYSTEM
#      that calls CryptUnprotectData on the blob (SYSTEM can decrypt any
#      user's DPAPI master key on the machine — LocalService's in our case).
#   4. Cleans up, writes the 32-byte PSK to -OutPsk, prints hex.
#
# This script does not need Wbdi.dll, Frida, or SGX. It only requires:
#   - Admin rights on Windows (UAC handles it)
#   - The sealed blob was originally produced on this Windows install
#     (same DPAPI machine keys)
#
# See docs/PSK.md for the full lifecycle context.

param(
    [Parameter(Mandatory=$true)] [string]$SealedBlob,
    [Parameter(Mandatory=$true)] [string]$OutPsk
)

$ErrorActionPreference = 'Stop'

# ---- 1. Self-elevate ----
$currentPrincipal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Elevating to admin..." -ForegroundColor Yellow
    $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$($PSCommandPath)`" " +
               "-SealedBlob `"$SealedBlob`" -OutPsk `"$OutPsk`""
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argLine -Wait
    exit
}

Write-Host "[+] Running elevated" -ForegroundColor Green

# ---- 2. Validate input ----
if (-not (Test-Path $SealedBlob)) { throw "Sealed blob not found: $SealedBlob" }
$blobBytes = [IO.File]::ReadAllBytes($SealedBlob)
Write-Host "[+] Sealed blob: $SealedBlob ($($blobBytes.Length) bytes)"

# Sanity check — DPAPI blobs start with "01000000 d08c9ddf 0115d111 8c7a00c0"
$magic = ($blobBytes[0..15] | ForEach-Object { $_.ToString('x2') }) -join ''
$expected = '01000000d08c9ddf0115d1118c7a00c0'
if ($magic -ne $expected) {
    Write-Warning "Blob doesn't start with canonical DPAPI magic."
    Write-Warning "  got:  $magic"
    Write-Warning "  want: $expected*"
    Write-Warning "Decryption will probably fail, but trying anyway."
}

# ---- 3. Stage into world-readable temp ----
$stageDir = 'C:\Windows\Temp\gm168_unseal'
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
$stagedBlob = Join-Path $stageDir 'sealed.bin'
$stagedPsk  = Join-Path $stageDir 'psk.hex'
$stagedErr  = Join-Path $stageDir 'err.txt'
$payload    = Join-Path $stageDir 'payload.ps1'
Remove-Item $stagedPsk,$stagedErr -ErrorAction SilentlyContinue
Copy-Item $SealedBlob $stagedBlob -Force

# ---- 4. Payload that SYSTEM will run ----
@"
try {
    Add-Type -AssemblyName System.Security
    `$blob = [IO.File]::ReadAllBytes('$stagedBlob')
    `$psk  = [Security.Cryptography.ProtectedData]::Unprotect(`$blob, `$null, 'CurrentUser')
    [IO.File]::WriteAllBytes('$($stagedPsk -replace '\.hex$', '.bin')', `$psk)
    [IO.File]::WriteAllText('$stagedPsk', [BitConverter]::ToString(`$psk).Replace('-','').ToLower())
} catch {
    [IO.File]::WriteAllText('$stagedErr', `$_.Exception.ToString())
}
"@ | Out-File -FilePath $payload -Encoding ascii

# ---- 5. Run as SYSTEM via scheduled task ----
$cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $payload"
$tn  = "Gm168Unseal_$([guid]::NewGuid().ToString('N').Substring(0,8))"

Write-Host "[*] Creating scheduled task '$tn' as NT AUTHORITY\SYSTEM..."
schtasks /create /tn $tn /tr "$cmd" /ru "SYSTEM" /sc ONCE /st 23:59 /F | Out-Null
schtasks /run /tn $tn | Out-Null

Write-Host "[*] Waiting for SYSTEM task to finish..."
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    if ((Test-Path $stagedPsk) -or (Test-Path $stagedErr)) { break }
}
schtasks /delete /tn $tn /F | Out-Null

# ---- 6. Report ----
if (Test-Path $stagedErr) {
    Write-Host ""
    Write-Host "[X] DPAPI failed:" -ForegroundColor Red
    Get-Content $stagedErr -Raw
    Write-Host ""
    Write-Host "Likely cause: blob was sealed on a different Windows install." -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path $stagedPsk)) {
    Write-Host "[X] No output produced (task may not have run)." -ForegroundColor Red
    exit 1
}

$pskHex = (Get-Content $stagedPsk).Trim()
$pskBin = $stagedPsk -replace '\.hex$', '.bin'

# Copy to user-requested location
$outDir = Split-Path $OutPsk
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
Copy-Item $pskBin $OutPsk -Force

# Wipe staging — sealed blob is recoverable, the plaintext PSK is sensitive
Remove-Item $stagedBlob,$pskBin,$stagedPsk,$payload -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] PSK extracted (32 bytes)" -ForegroundColor Green
Write-Host "    hex:  $pskHex"
Write-Host "    file: $OutPsk"
Write-Host ""
Write-Host "Copy $OutPsk to your Linux machine at:" -ForegroundColor Cyan
Write-Host "    /etc/goodix-gm168/psk.bin"
