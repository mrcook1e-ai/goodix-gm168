@echo off
REM ===========================================================================
REM  GM168 Wbdi preprocessor full-trace capture
REM
REM  Attaches Frida to WUDFHost.exe (the Windows process that loads Wbdi.dll),
REM  hooks every stage of sub_18010a460 (CAL, SMOOTH, HENV, VENV, MORPH,
REM  STRETCH) and dumps each intermediate buffer to disk.  We then byte-diff
REM  these against our Linux driver to find exactly where the port diverges.
REM
REM  Usage:
REM    1. Right-click → Run as administrator
REM    2. Open Settings → Sign-in options → Fingerprint
REM    3. Touch the sensor ONCE when "HOOKS_READY" appears
REM    4. Wait ~3 seconds, press Ctrl+C to stop
REM    5. Dumps land in .\captures\<timestamp>\
REM    6. Copy that folder to the Linux laptop
REM ===========================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

REM === Self-elevate if not admin ============================================
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting admin rights...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM === Find Python ==========================================================
where py >nul 2>&1
if errorlevel 1 (
    where python >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python not installed.
        echo Install from https://www.python.org/downloads/  ^(check "Add to PATH"^)
        pause
        exit /b 1
    )
    set PY=python
) else (
    set PY=py
)

REM === Install frida-tools if missing =======================================
%PY% -m pip show frida-tools >nul 2>&1
if errorlevel 1 (
    echo Installing frida-tools ^(one-time^)...
    %PY% -m pip install --quiet --upgrade frida frida-tools
    if errorlevel 1 (
        echo ERROR: pip install failed.  Run manually:
        echo   %PY% -m pip install frida frida-tools
        pause
        exit /b 1
    )
)

REM === Clear previous dumps =================================================
set DUMP_DIR=C:\Windows\Temp\gx_dumps
if exist "%DUMP_DIR%" rmdir /s /q "%DUMP_DIR%"
mkdir "%DUMP_DIR%"

REM === Wait for WUDFHost.exe to load Wbdi.dll ===============================
echo.
echo ================================================================
echo  Open Settings - Sign-in options - Fingerprint
echo  ^(this wakes the Windows biometric service which loads Wbdi.dll^)
echo ================================================================
echo.

set TRIES=0
:wait_loop
set /a TRIES+=1
tasklist /FI "IMAGENAME eq WUDFHost.exe" /M Wbdi.dll 2>nul | findstr /I WUDFHost >nul
if errorlevel 1 (
    if !TRIES! gtr 60 (
        echo TIMEOUT: WUDFHost.exe never loaded Wbdi.dll
        echo Make sure you opened Settings - Sign-in - Fingerprint
        pause
        exit /b 1
    )
    timeout /t 2 /nobreak >nul
    <nul set /p="."
    goto wait_loop
)

for /f "tokens=2" %%i in ('tasklist /FI "IMAGENAME eq WUDFHost.exe" /M Wbdi.dll ^| findstr WUDFHost') do set PID=%%i
echo.
echo Found WUDFHost PID=%PID%

REM === Attach Frida and start hooks =========================================
echo.
echo ================================================================
echo   Hooks attaching...  When you see "HOOKS_READY":
echo     1. TOUCH the sensor ONCE
echo     2. WAIT 3 seconds for all stages to dump
echo     3. Press Ctrl+C  here  to stop
echo ================================================================
echo.

%PY% -m frida -p %PID% -l gx_preproc_trace.js

REM === Bundle dumps with timestamp ==========================================
echo.
echo Saving dumps...
for /f %%a in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set TS=%%a
set OUT=captures\%TS%
if not exist captures mkdir captures
mkdir "%OUT%"
xcopy /Q /Y "%DUMP_DIR%\*" "%OUT%\" >nul 2>&1

REM === Quick stage count ====================================================
echo.
echo Captured stages:
for %%S in (INPUT CAL_IN CAL_OUT CAL_SCALE CAL_SECONDARY SMOOTH_IN SMOOTH_OUT SMOOTH_MASK HENV_IN HENV_LO HENV_HI VENV_IN VENV_LO VENV_HI MORPH_LO_IN MORPH_HI_IN MORPH_LO_OUT MORPH_HI_OUT STRETCH_IN STRETCH_OUT MASK_OUT FRAME) do (
    set CNT=0
    for /f %%c in ('dir /b /a-d "%OUT%\*_%%S_*.bin" 2^>nul ^| find /c /v ""') do set CNT=%%c
    if !CNT! gtr 0 echo   %%S: !CNT! files
)

echo.
echo ================================================================
echo  DONE.  Dumps saved to:
echo    %CD%\%OUT%
echo.
echo  Copy this folder to the Linux laptop at:
echo    ~/work/goodix-gm168/captures/
echo ================================================================
echo.
pause
