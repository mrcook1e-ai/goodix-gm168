# PSK lifecycle and sharing strategy

How the TLS-PSK is generated, stored, and recovered on Goodix GM168SEC.
Everything here is **empirically verified** — see "Evidence" section.

## TL;DR

The PSK is **per-device**, generated at first Windows-driver install, stored:
- **Sealed** in the MCU NVRAM (DPAPI-encrypted, ~324 bytes)
- **Plaintext** is never persisted anywhere on the host

To make the Linux driver portable to other users, we extract the sealed
blob from the MCU over USB, then decrypt it with DPAPI under
`NT AUTHORITY\SYSTEM`. This works **without Wbdi.dll, without SGX, without
Frida**.

## Full lifecycle

### Provisioning (one-time, on first Goodix install)

In `ProcessPsk` → `PresetPskWriteKey` (`pskunify.c`, RVA `0x3a2e4`):

```
0. generate random 32-byte PSK         ← GeneratePsk
1. seal psk by sgx                     ← CryptProtectData(psk, flags=0)
                                         (Wbdi calls this "sgx" but it is
                                         plain Windows DPAPI under
                                         LOCAL SERVICE context)
2. encrypt psk by wb                   ← WhiteBox layer (sub_180001000)
3. write to mcu                        ← USB cmd 0xE4 / TLV 0xbb010002
                                         (sealed blob, ~324 bytes)
                                       ← USB cmd 0xE4 / TLV 0xbb020001
                                         (SHA-256(psk), 32 bytes — integrity)
```

### Runtime (every TLS handshake after MCU lost power / SGX state lost)

In `PresetPskIsVaildG` (RVA `0x38ea8`):

```
1. read sealed PSK from MCU            ← USB cmd 0xE4 / TLV 0xbb010002
2. unseal sgx[psk] & cal the local_hash← CryptUnprotectData(blob)
3. read hash of psk from MCU           ← USB cmd 0xE4 / TLV 0xbb020001
4. verify hash local vs mcu            ← memcmp(SHA-256(psk), mcu_hash)
```

After this, the plaintext PSK is used for TLS-PSK handshake (cipher suite
`TLS-PSK-WITH-AES-128-CBC-SHA256`).

## Evidence

Captured via Frida hook on `Wbdi.dll` running inside `WUDFHost.exe`
(see [`../frida_work/psk_probe.js`](../frida_work/psk_probe.js)):

```
[ReadSpec >] tag=0xbb010002
[ReadSpec <] ret=0 len=324 head=01000000d08c9ddf0115d1118c7a00c04fc297eb...
                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                canonical DPAPI blob magic
[Unseal >] inLen=324
[DPAPI Unprotect] flags=0x0    ← CRYPTPROTECT_USER (not LOCAL_MACHINE)
[Unseal <] ret=0 outLen=32 outHead=<REDACTED — 32-byte PSK>
                                   == loaded at runtime from
                                      /etc/goodix-gm168/psk.bin
```

Standalone DPAPI verification (no Wbdi):

```powershell
# Run as NT AUTHORITY\SYSTEM via scheduled task — see
# frida_work/run_unseal_as_localservice.ps1 (use -RunAs SYSTEM)
Add-Type -AssemblyName System.Security
$blob = [IO.File]::ReadAllBytes('...sealed_blob.bin')
$psk  = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'CurrentUser')
[BitConverter]::ToString($psk).Replace('-','').ToLower()
# → <32-byte hex, redacted — this is the actual PSK for the developer's device>
```

## DPAPI account context — important

The sealed blob is encrypted under `NT AUTHORITY\LOCAL SERVICE`
(because `WUDFHost.exe` runs as LocalService). This matters:

| Decryptor account | Works? | Why |
|---|---|---|
| `mrcook1e` (interactive user) | ❌ | Different master key |
| `NT AUTHORITY\LOCAL SERVICE` via schtasks | ❌ | Default policy denies batch logon |
| `NT AUTHORITY\SYSTEM` via schtasks | ✅ | SYSTEM can load any user's masterkey on the machine |
| `NT AUTHORITY\SYSTEM` via PsExec `-s` | ✅ | Same as above |

For the sharing utility we use **SYSTEM via Scheduled Task** — it's
self-contained (no PsExec download), runs on any Windows install.

## Sharing utility architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Linux: goodix_gm168 driver                                   │
│   On init:                                                   │
│     if (exists /etc/goodix-gm168/psk.bin)                    │
│         use it for TLS                                       │
│     else                                                     │
│         read sealed blob via USB cmd 0xE4 / tag 0xbb010002   │
│         write /etc/goodix-gm168/sealed_psk.bin               │
│         abort with "boot into Windows, run gm168_unseal.exe" │
└──────────────────────────────────────────────────────────────┘
              ↓  user copies sealed_psk.bin to Windows
┌──────────────────────────────────────────────────────────────┐
│ Windows: gm168_unseal.exe (~50 LOC C# or ~30 LOC PowerShell) │
│   1. Self-elevate to admin (UAC prompt)                       │
│   2. Create scheduled task /ru "NT AUTHORITY\SYSTEM"         │
│   3. Task: CryptUnprotectData(sealed_psk.bin) → psk.bin      │
│   4. Delete task, print success                              │
└──────────────────────────────────────────────────────────────┘
              ↓  user copies psk.bin back to Linux
┌──────────────────────────────────────────────────────────────┐
│ Linux: rerun driver — psk.bin present, TLS handshake works   │
└──────────────────────────────────────────────────────────────┘
```

Variant: Windows utility also handles USB read (libusb/HID) so user
doesn't need a Linux round-trip. Trade-off: needs Wbdi unloaded
(Device Manager → Disable) so USB endpoint is free.

## MCU wire format for cmd `0xE4` — confirmed byte-for-byte

This is what the Linux driver needs to speak to read the sealed blob
without help from Wbdi. All multi-byte values are little-endian.

### TX body (16 bytes, wrapped in the standard `A0` outer frame)

```c
struct e4_tx_body {
    uint32_t chunk_size;  // up to 0x100 (256)
    uint32_t offset;      // into the spec data buffer
    uint32_t tag;         // 0xbb010002 = sealed PSK, 0xbb020001 = PSK hash
    uint32_t reserved;    // = 0
};
```

Captured TX from `IoHubMcuSendCmd2` for the actual PSK fetch:

| # | Bytes (hex) | chunk_size | offset | tag | meaning |
|---|---|---|---|---|---|
| 027 | `00010000 00000000 020001bb 00000000` | 0x100 | 0    | 0xbb010002 | sealed PSK chunk 0 |
| 028 | `44000000 00010000 020001bb 00000000` | 0x44  | 0x100| 0xbb010002 | sealed PSK chunk 1 (last) |
| 029 | `20000000 00000000 010002bb 00000000` | 0x20  | 0    | 0xbb020001 | PSK SHA-256 hash |

Total sealed PSK length = 0x100 + 0x44 = **324 bytes** (matches the
DPAPI blob size we already verified).

### RX (after `IoHubMcuSendCmd2` strips the A0 outer frame)

```c
struct e4_rx {
    uint8_t  status;      // 0x00 = OK
    uint32_t tag_echo;    // mirrors requested tag
    uint32_t data_len;    // bytes of payload that follow
    uint8_t  data[];      // chunk of the spec data
};
```

Captured RX heads (first 13 bytes, then `data[]`):

```
027: 00 020001bb 00010000 | 01000000 d08c9ddf 0115d111 ... (256 bytes)
                                ^^^^^^^^^^^^^^^^^^^^^
                                canonical DPAPI blob magic
028: 00 020001bb 44000000 | 99c23072 7581...           (68 bytes)
029: 00 010002bb 20000000 | cd28fb94 810a36df ...       (32 bytes hash)
```

### Mapping onto the existing Linux driver

The driver already has `goodix_gm168_encode_cmd(cmd, body, body_len, &out_len)`
in [`../goodix_gm168/goodix_proto.c`](../goodix_gm168/goodix_proto.c) and
`goodix_gm168_decode_ack(...)` which returns `extra` starting at A0 offset 8
(i.e. just after the 1-byte MCU status). So a sealed-PSK reader is ~30 LOC:

```c
guint8 sealed[324];
guint32 offset = 0;
while (offset < 324) {
    guint32 want = MIN(0x100, 324 - offset);
    guint8 body[16] = {0};
    GUINT32_TO_LE_STORE(want,        body + 0);
    GUINT32_TO_LE_STORE(offset,      body + 4);
    GUINT32_TO_LE_STORE(0xbb010002,  body + 8);
    // send body via existing pipeline, read back via existing pipeline
    // extra layout after decode_ack: [tag_echo:4][data_len:4][data:N]
    guint32 chunk = extra[4] | (extra[5]<<8) | (extra[6]<<16) | (extra[7]<<24);
    memcpy(sealed + offset, extra + 8, chunk);
    offset += chunk;
}
```

Ground-truth captures live in `C:\Windows\Temp\psk_probe\*_SendCmd_*_{TX,RX}_cmde4_*`
on the laptop — use them as parity tests for any new encoder/decoder code.

## What's still TODO before this ships

- **#1.** Decompile `sub_18007c60c` / `sub_1800783f0` to learn the exact
  byte layout of cmd `0xE4` (header bytes, body framing, response
  parsing). Without this the Linux side can't read the sealed blob.
- **#2.** Implement the read in `goodix_gm168.c` behind a config flag.
- **#3.** Write `gm168_unseal.ps1` with self-elevation + schtasks-as-SYSTEM.
- **#4.** Verify on a second device that the protocol works (and that
  `0xE4` is the same command across firmware revisions).

See also [NEXT_STEPS.md](NEXT_STEPS.md).

## Reference

- [`../frida_work/psk_probe.js`](../frida_work/psk_probe.js) — Frida hook
  that captured all evidence above. Forces SgxLost=1 on `Logic*::Start`
  entry to trigger `ProcessPsk` on a live service.
- [`../frida_work/run_psk_probe.bat`](../frida_work/run_psk_probe.bat) —
  one-click wrapper that elevates and attaches to WUDFHost.
- [`../frida_work/dpapi_unseal.ps1`](../frida_work/dpapi_unseal.ps1) —
  payload that decrypts a sealed blob via DPAPI. Run via
  `run_unseal_as_localservice.ps1 -RunAs SYSTEM`.
- Wbdi.dll RVAs:
  - `0x38c80` `GfUnsealData` — DPAPI wrapper
  - `0x38ea8` `PresetPskIsVaildG` — runtime validation orchestrator
  - `0x39b4c` `PresetPskReadSpecDataG` — TLV MCU read
  - `0x952d0` `ProcessPsk` — provisioning orchestrator (vtable +0x80)
  - `0x3a2e4` `PresetPskWriteKey` — provisioning writer
  - `0x83890` `LogicMilanFSeries::Start`, `0x897b0` `LogicMilanHVSeries::Start`
    — entry points; SgxLost flag at `arg1+0xe0`
