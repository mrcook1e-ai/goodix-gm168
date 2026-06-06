# Dev stack — machines, SSH, folders

How the development environment is wired across two machines, where
things live, what each piece is for.

## Two machines, three execution contexts

```
┌──────────────────────────────────┐       ┌──────────────────────────────────┐
│  PC (dev box) — Windows           │       │  Laptop — Windows + WSL          │
│  IP: <local>                      │       │  IP: 192.168.1.14                │
│                                   │       │                                  │
│  Where code is written, analysis  │  ssh  │  Where the sensor is plugged.    │
│  is done in Binary Ninja, scripts │ ====> │  Runs Wbdi.dll under WUDFHost,   │
│  are authored.                    │       │  Frida hooks, Linux drvier test. │
│                                   │       │                                  │
│  C:\Users\mrcook1e\Fingerprint\   │       │  Windows side: C:\Users\...\     │
│                                   │       │  Linux side:   ~/goodix_gm168/   │
└──────────────────────────────────┘       └──────────────────────────────────┘
```

The laptop hosts **both** a Windows install (where the Goodix sensor lives,
where Wbdi.dll runs, where DPAPI is needed) **and** WSL (where the Linux
driver builds and is exercised against the same physical sensor through
`usbipd` USB passthrough).

## SSH endpoints — they look like one box but they're two

| Endpoint | Port | What you reach | Use for |
|---|---|---|---|
| `mrcook1e@192.168.1.14 -p 22`   | 22   | Native Windows shell (OpenSSH server) | Running PowerShell, schtasks, Frida, Device Manager interactions, anything that touches Wbdi/DPAPI |
| `mrcook1e@192.168.1.14 -p 2200` | 2200 | WSL bash (sshd in WSL)                 | Building libfprint, running enroll/verify, kernel-side debug, anything Linux |

**Important:** they share the same physical disk. WSL sees Windows files
at `/mnt/c/`. The two folders below are the canonical mount points:

| From Windows | From WSL |
|---|---|
| `C:\Users\mrcook1e\Fingerprint\` | `/mnt/c/Users/mrcook1e/Fingerprint/` |
| `C:\Windows\Temp\psk_probe\` | `/mnt/c/Windows/Temp/psk_probe/` |

When deploying files, **pick the port that matches the path style**:
SCP to port 22 uses Windows paths (`C:/Users/...`), SCP to port 2200 uses
POSIX paths.

## Repository layout (PC and laptop, kept in sync)

```
C:\Users\mrcook1e\Fingerprint\
├── goodix_gm168/          Linux driver source (one .c + protocol + tls).
│                          Builds under WSL via libfprint meson.
├── docs/                  All project docs (this file lives here).
├── RESEARCH.md            Canonical reverse-engineering reference.
├── README.md              Project intro.
│
├── frida_work/            Frida instrumentation harness — runs on Windows.
│   ├── gx_hook.js                Full capture pipeline (TLS→decode→FRAME).
│   ├── psk_probe.js              PSK lifecycle probe (this session).
│   ├── hook_finger.bat           One-click launcher for gx_hook.
│   ├── run_psk_probe.bat         One-click launcher for psk_probe.
│   ├── dpapi_unseal.ps1          Standalone DPAPI decryptor (no Wbdi).
│   ├── run_unseal_as_localservice.ps1
│   │                             schtasks wrapper to run dpapi_unseal
│   │                             as LOCAL SERVICE or SYSTEM.
│   ├── check_owner.ps1           Diagnostic: who owns WUDFHost.
│   ├── host.py / parse_log.py    Log viewer + analyzer.
│   ├── viewer_server.py + browser_viewer.html
│   │                             Local web UI for inspecting captures.
│   └── (dumps land in C:\Windows\Temp\gx_dumps\ and \psk_probe\
│        — outside the repo, gitignored)
│
├── scripts/               Author-side helpers — run on PC.
│   ├── deploy_frida.ps1          PC → laptop Windows (port 22)
│   ├── deploy_linux.ps1          PC → laptop WSL    (port 2200)
│   ├── fetch_session.ps1         laptop → PC (pulls session.log + dumps)
│   ├── protocol_checklist.py     Parses session.log into a per-cmd timeline
│   ├── solve_seed.py             Python reference decoder
│   ├── verify_driver_decode.py   Parity test: driver vs reference vs Wbdi
│   ├── test_decode.c             Standalone C parity binary
│   └── various Frida/build wrappers
│
├── raw/                   Vendor binaries — NOT in git (gitignored).
│   ├── Wbdi.dll  WbdiEnclave.signed.dll
│   ├── GoodixEngineAdapter.dll  AdapterEnclave.signed.dll
│   ├── SessionService.exe  AssemblyPublicizer.exe
│   ├── WbdiUsb.inf  wbdiusb.cat  sgx_white_list_cert.bin   (these ARE tracked)
│   └── Wbdi.dll.bndb       Binary Ninja DB — local only, not in git.
│
├── calib_windows.dat      Cal1/Cal2 calibration blob (Wbdi runtime dump).
├── goodix.dat             Per-device calibration data (RESEARCH.md).
├── test/                  Quick Python search/diagnostic scripts.
│
└── scratch/               EVERYTHING ELSE — research artifacts.
    │                      Gitignored. Disposable. No promises.
    ├── images/            *.png from analysis
    ├── bins/              *.bin/*.pgm dumps
    ├── py/                throwaway scripts
    ├── logs/              session logs
    └── dumps/             captures/, new_dumps/
```

## Output / dump locations (off-repo, on laptop only)

The laptop writes binary captures to world-writable system paths because
`WUDFHost.exe` runs as `NT AUTHORITY\LOCAL SERVICE` and can't write to
the user profile.

| Path | Producer | Contents |
|---|---|---|
| `C:\Windows\Temp\gx_dumps\` | `gx_hook.js` | TLS payloads, ImageRestruct in/out, FRAME, INPUT — one file per capture stage |
| `C:\Windows\Temp\psk_probe\` | `psk_probe.js` + `run_unseal_as_localservice.ps1` | Sealed PSK blob, unsealed PSK, DPAPI diagnostics |

From PC, pull them with `scripts/fetch_session.ps1`.

## Typical workflows

### Deploy code from PC to laptop

```powershell
# Windows-side stuff (frida_work) → port 22
.\scripts\deploy_frida.ps1

# Linux driver / scripts → port 2200
.\scripts\deploy_linux.ps1
```

### Capture a Frida session

On laptop, double-click `C:\Users\mrcook1e\Fingerprint\frida_work\hook_finger.bat`
(or `run_psk_probe.bat`). It self-elevates, waits for WUDFHost+Wbdi,
attaches, writes log + binary dumps.

### Pull captures back to PC

```powershell
.\scripts\fetch_session.ps1
# scp -P 22 mrcook1e@192.168.1.14:.../session.log + matching dumps → local
```

### Build and run the driver under WSL

```bash
# from PC, jump in
ssh -p 2200 mrcook1e@192.168.1.14
# on laptop WSL
cd ~/goodix_gm168/libfprint/build
ninja
~/goodix_gm168/debug.sh      # single capture
~/goodix_gm168/enroll.sh     # 5-stage interactive
```

### Decompile a Wbdi function from PC

The Binary Ninja MCP server (`raw/Wbdi.dll.bndb` open in Binja on PC)
exposes decompile/xref/strings/hexdump endpoints. Drives the RE workflow
without manually exporting code. See `mcp__binary_ninja_mcp__*` tools.

## Git etiquette

- Commit driver code, docs, scripts, Frida hooks, vendor metadata
  (`*.inf`, `*.cat`).
- **Do not** commit `raw/*.dll`, `raw/*.exe`, `*.bndb`, anything under
  `scratch/`. These are local-only.
- Big binary captures live in `C:\Windows\Temp\...` on the laptop — not
  in the repo at all.

## Quick reference card

```
# PC → laptop file push
scp -P 22   file.ps1  mrcook1e@192.168.1.14:C:/Users/mrcook1e/Fingerprint/...
scp -P 2200 file.sh   mrcook1e@192.168.1.14:Fingerprint/...

# PC → laptop one-shot command
ssh -p 22   mrcook1e@192.168.1.14 'powershell -NoProfile -Command "..."'
ssh -p 2200 mrcook1e@192.168.1.14 'cat /mnt/c/Windows/Temp/psk_probe/...'

# Pull a file back
scp -P 22 mrcook1e@192.168.1.14:C:/Windows/Temp/psk_probe/foo.bin .
```
