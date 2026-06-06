# End-to-end PSK extraction pipeline

How to get a Goodix GM168SEC's TLS-PSK out of the sensor so the Linux
driver can talk to it.

**v1.0 (native, current — no Frida) is documented first.** The historical
v0.1 Frida-assisted path is kept below for reference but is no longer
the recommended flow.

## v1.0 — native, no Frida (current)

The driver does steps 1-3 itself on first run:

```
  Linux first run:                          Windows:

  driver_init()
    if /etc/goodix-gm168/psk.bin exists ─────→ use it, done
    else:
      send cmd 0xE4 / tag 0xbb010002          tools/windows/gm168_unseal.ps1
      assemble 324-byte sealed blob   ───────→ -SealedBlob sealed.bin
      write /etc/goodix-gm168/sealed.bin       -OutPsk     psk.bin
      print "boot into Windows, run...      ←───── copy psk.bin back
            gm168_unseal.ps1"
      exit

  next driver run → psk.bin present → TLS handshake → working
```

The native cmd `0xE4` read uses the same protocol Wbdi.dll does — we
verified it byte for byte (see [PSK.md](PSK.md)). The encoder/decoder
machinery in `goodix_proto.c` already handles all the framing, so the
driver-side bootstrap is ~30 LOC.

`$GOODIX_GM168_DIR` overrides the default `/etc/goodix-gm168/` if you
need to run unprivileged for testing.

## v0.1 — Frida-assisted (historical, kept for reference)

Use this if you want to verify the whole flow on your dev box right now.

### What you need

- Windows install where the Goodix driver was provisioned at least once
  (so the sealed PSK exists in the MCU's NVRAM)
- Frida installed (`pip install frida-tools`)
- Admin rights on Windows
- A Linux machine (or WSL) where the driver will be exercised

### Steps

```
                                                                      
   Windows                                  Linux                       
  ┌─────────────────────────────────────┐  ┌──────────────────────────┐
  │                                     │  │                          │
  │  1. Run run_psk_probe.bat           │  │                          │
  │     (Frida attaches WUDFHost,       │  │                          │
  │      forces SgxLost=1)              │  │                          │
  │     ↓                               │  │                          │
  │  2. Touch sensor / Win+L            │  │                          │
  │     ↓                               │  │                          │
  │  3. C:\Windows\Temp\psk_probe\      │  │                          │
  │     ...ReadSpec_tagbb010002.bin     │  │                          │
  │     ← 324-byte sealed blob          │  │                          │
  │     ↓                               │  │                          │
  │  4. gm168_unseal.ps1                │  │                          │
  │     -SealedBlob ...bb010002.bin     │  │                          │
  │     -OutPsk     psk.bin             │  │                          │
  │     (self-elevates; schtasks SYSTEM;│  │                          │
  │      CryptUnprotectData; cleanup)   │  │                          │
  │     ↓                               │  │                          │
  │  5. psk.bin (32 bytes plaintext)    │──┼─→ /etc/goodix-gm168/     │
  │                                     │  │   psk.bin                │
  │                                     │  │     ↓                    │
  │                                     │  │  6. driver TLS handshake │
  │                                     │  │     succeeds             │
  └─────────────────────────────────────┘  └──────────────────────────┘
```

### Commands

**On Windows (laptop):**
```powershell
# Trigger Frida hook to capture sealed blob from MCU.
# Open Settings → Sign-in options → Fingerprint, touch sensor, etc.
C:\Users\mrcook1e\Fingerprint\frida_work\run_psk_probe.bat

# When the log shows [ReadSpec <] ret=0 len=324, kill Frida with Ctrl+C.
# The blob is now at C:\Windows\Temp\psk_probe\<SID>_ReadSpec_tagbb010002_len324.bin

# Unseal it — self-elevates, runs as SYSTEM, writes 32-byte PSK
$blob = Get-ChildItem 'C:\Windows\Temp\psk_probe\*_ReadSpec_tagbb010002_len324.bin' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
C:\Users\mrcook1e\Fingerprint\frida_work\gm168_unseal.ps1 `
    -SealedBlob $blob.FullName `
    -OutPsk     C:\Users\mrcook1e\psk.bin
```

**Copy to Linux (over scp, USB stick, whatever):**
```bash
mkdir -p /etc/goodix-gm168
cp /path/to/psk.bin /etc/goodix-gm168/psk.bin
chmod 600 /etc/goodix-gm168/psk.bin
```

**On Linux:** driver reads `/etc/goodix-gm168/psk.bin` instead of the
hardcoded `REAL_PSK` constant. (Wiring in [`goodix_proto.c`](../goodix_gm168/goodix_proto.c)
is part of the v1.0 work.)

### What's safe to skip

- **The 0xbb020001 hash blob.** It's an integrity check the MCU uses
  during Wbdi handshake. Our Linux driver doesn't need it — TLS-PSK
  handshake fails fast if the PSK is wrong.

## Cross-machine portability

| Scenario | Works? | Why |
|---|---|---|
| Same Windows install, same user | ✅ | DPAPI succeeds under SYSTEM |
| Same Windows install, different user | ✅ | SYSTEM has all user master keys |
| Reinstalled Windows on same hardware | ❌ | DPAPI master keys regenerated on first login |
| Different Windows install | ❌ | Same reason |
| Provisioned device moved to new machine | ⚠️ | Need to re-provision (Settings → Remove → Add fingerprint) on the new Windows |

In other words: **the PSK is bound to a Windows install, not to the
sensor**. Move the sensor to a new machine and you need to re-provision.

## Failure modes and what they mean

| `gm168_unseal.ps1` says | Reason | Fix |
|---|---|---|
| `Key not valid for use in specified state` | Blob from a different Windows install | Re-provision on this machine |
| `No output produced (task may not have run)` | UAC declined or scheduled task subsystem broken | Run from elevated PowerShell directly |
| `Blob doesn't start with canonical DPAPI magic` | File corrupted or not a Goodix sealed blob | Re-capture via `run_psk_probe.bat` |
| Linux driver `TLS handshake failed` | Wrong PSK or wrong blob (e.g. captured from a different sensor) | Confirm the 32-byte hex matches Frida's `[Unseal <]` line in `events.log` |

## See also

- [PSK.md](PSK.md) — full reverse-engineering writeup and evidence
- [DEV_STACK.md](DEV_STACK.md) — machine/SSH/path conventions
- [`../frida_work/psk_probe.js`](../frida_work/psk_probe.js) — capture hook
- [`../tools/windows/gm168_unseal.ps1`](../tools/windows/gm168_unseal.ps1) — DPAPI utility
