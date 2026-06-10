# RE Stack — Goodix GM168 Protocol Reverse Engineering

How we capture, dissect, and understand the full USB conversation between
Windows and the 27c6:589a sensor. Infrastructure as of 2026-06.

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  PC (dev box) — Windows 11                                          │
│                                                                     │
│  Claude Code ──MCP──► Binary Ninja (Wbdi.dll.bndb open)            │
│  │                    decompile / xref / hexdump / strings          │
│  │                                                                  │
│  └─── SSH ──────────────────────────────────────────────────────┐  │
└─────────────────────────────────────────────────────────────────│──┘
                                                                  │
          ┌───────────────────────────────────────────────────────▼──┐
          │  Laptop — Windows 11 (sensor attached)                   │
          │  IP: 192.168.1.14                                        │
          │                                                          │
          │  ┌─────────────────────────┐  ┌────────────────────────┐ │
          │  │ Windows (port 22)       │  │ WSL2 (port 2200)       │ │
          │  │                         │  │                        │ │
          │  │  WUDFHost.exe           │  │  libfprint (patched)   │ │
          │  │   └─ Wbdi.dll           │  │  fprintd               │ │
          │  │       └─ 27c6:589a      │  │  usbipd passthrough    │ │
          │  │                         │  │                        │ │
          │  │  Frida hooks:           │  │  usbmon  ──► .pcapng   │ │
          │  │   gx_hook.js            │  │  tshark / Wireshark    │ │
          │  │   psk_probe.js          │  │  goodix_message.lua    │ │
          │  └─────────────────────────┘  └────────────────────────┘ │
          └──────────────────────────────────────────────────────────┘
```

---

## Tools

### 1. Binary Ninja + MCP (static analysis hub)

**Role:** decompile `Wbdi.dll`, locate crypto/PSK functions, trace call graphs.

Binary Ninja runs on the PC with `raw/Wbdi.dll.bndb` open. Claude Code
reaches it through the `mcp__binary_ninja_mcp__*` tool family — no manual
copy-paste. All RE commands below are callable from within a conversation.

| MCP tool | What it does |
|---|---|
| `decompile_function` | HLIL decompile of any function by address or name |
| `get_xrefs_to` | Find every call site of a function |
| `list_strings` / `list_strings_filter` | Enumerate string literals (good for finding log prefixes) |
| `hexdump_address` | Dump raw bytes at any address |
| `search_functions_by_name` | Fuzzy-search function names in the binary |
| `get_il` | Get Low-Level IL for a function |
| `rename_function` / `rename_single_variable` | Annotate as we discover meaning |
| `set_comment` / `set_function_comment` | Leave breadcrumbs for future sessions |
| `fetch_disassembly` | Raw disassembly of an address range |

**Workflow — typical RE session:**

```
1. search_functions_by_name("psk")     → find PresetPskWriteKey, etc.
2. decompile_function(addr)            → read HLIL for the PSK write path
3. get_xrefs_to(addr)                  → find all callers
4. rename_function / set_comment       → annotate as we go
5. hexdump_address(data_addr, 64)      → inspect inline byte arrays
```

**Python scripting in Binary Ninja:**

Binary Ninja supports Python scripts via its API. We use them for bulk
annotation and batch analysis:

```python
# Example: find all functions that reference the PSK cipher constant
from binaryninja import *

bv = BinaryViewType.get_view_of_file("raw/Wbdi.dll.bndb")
TARGET = 0x00AE  # TLS_PSK_WITH_AES_128_CBC_SHA256

for func in bv.functions:
    for block in func.low_level_il:
        for insn in block:
            if any(op.value.value == TARGET for op in insn.operands
                   if hasattr(op, 'value')):
                print(f"0x{func.start:x}  {func.name}")
```

Run scripts via **Tools → Script Console** or the headless API:
```bash
binaryninja --headless -e "exec(open('scripts/find_cipher.py').read())"
```

---

### 2. usbmon + Wireshark (host-side capture)

**Role:** capture every USB URB between host and sensor, whether the driver
runs on Windows (KVM guest) or Linux (WSL/native).

**Why it works with KVM:** usbmon intercepts at the host controller level.
Even when 27c6:589a is passed to a Windows VM guest, all URBs flow through
the Linux host controller — usbmon sees them all.

```bash
# Load kernel module
sudo modprobe usbmon

# Find sensor bus
lsusb | grep 27c6
# Bus 003 Device 007: ID 27c6:589a

# Grant non-root access (add to ~/.bashrc or a udev rule)
sudo setfacl -m u:$USER:r /dev/usbmon3

# Capture to file
tshark -i usbmon3 -w capture_$(date +%Y%m%d_%H%M%S).pcapng

# Or live in Wireshark with display filter:
# usb.addr matches "^3\.7\."
```

**Goodix Lua dissector:**

Place `goodix_message.lua` in `~/.local/lib/wireshark/plugins/` (or the
platform-equivalent). Dissector source:
[tlambertz/goodix-fingerprint-reversing](https://github.com/tlambertz/goodix-fingerprint-reversing/blob/main/wireshark-dissector/goodix_message.lua)

With the dissector active, Wireshark decodes Goodix packet types inline:
- `0xA0` — command (plaintext, initialization)
- `0xB2` — TLS-encrypted payload

---

### 3. Frida (dynamic analysis — Windows side)

**Role:** hook `Wbdi.dll` at runtime to intercept PSK, TLS plaintext,
and decoded image buffers without modifying the binary.

**Setup:**

```bash
# On laptop (Windows), PowerShell as admin
pip install frida-tools
frida --version   # confirm ≥ 16.x
```

**Key scripts (live in `frida_work/`):**

| Script | Hooks | Output |
|---|---|---|
| `gx_hook.js` | TLS decrypt, ImageRestruct in/out, FRAME buffer | `C:\Windows\Temp\gx_dumps\` |
| `psk_probe.js` | `PresetPskWriteKey`, `CryptUnprotectData` | `C:\Windows\Temp\psk_probe\` |

**Launcher:**

```powershell
# One-click, self-elevates, waits for WUDFHost+Wbdi
.\frida_work\hook_finger.bat
# OR
.\frida_work\run_psk_probe.bat
```

**Goodix debug registry key** — makes driver pause at startup so you can
attach before PSK exchange:

```
HKLM\SOFTWARE\Goodix\FP\DebugMe  (DWORD = 1)
```

**PSK extraction via Frida:**

```javascript
// psk_probe.js — intercept PresetPskWriteKey
Interceptor.attach(Module.getExportByName("Wbdi.dll", "PresetPskWriteKey"), {
    onEnter(args) {
        const psk = args[0].readByteArray(32);
        send({ type: "psk", data: Array.from(new Uint8Array(psk)) });
    }
});
```

---

### 4. x64dbg (debugger — Windows side)

**Role:** attach to `WUDFHost.exe` for step-through debugging when Frida
hooks aren't sufficient (e.g. to overwrite PSK with a known value for
capture sessions).

**Workflow:**

```
1. Set HKLM\SOFTWARE\Goodix\FP\DebugMe = 1
2. Restart WBF service: sc stop WbioSrvc && sc start WbioSrvc
3. Attach x64dbg to WUDFHost.exe within the pause window
4. BP on PresetPskWriteKey
5. When hit: modify arg0 (RCX) to point to 32 zero bytes
   → sensor uses all-zero PSK → trivial to decrypt captures offline
```

---

### 5. goodix-fp-dump (Python RE harness)

**Role:** drive the sensor directly from Linux without the Windows driver.
Replay protocol sequences, observe responses, add support for new PIDs.

```bash
git clone https://github.com/goodix-fp-linux-dev/goodix-fp-dump
cd goodix-fp-dump
pip install pyusb

# No 589a script yet — adapt from closest model:
cp run_55a4.py run_589a.py
# Edit: chip_id query bytes, image dimensions, PSK if needed
python3 run_589a.py
```

The script opens the USB device directly (bypasses any driver), sends
init commands, and prints decoded responses. Compare output to usbmon
captures from the Windows driver session to find protocol differences.

---

## KVM/QEMU — Windows VM for driver capture

The VM is pre-configured on Fedora 46 at `192.168.1.23`:

```bash
# Start VM
virsh start win11-goodix

# Watch VNC/SPICE display
virt-viewer --connect qemu+ssh://mrcook1e@192.168.1.23/system win11-goodix

# Capture while VM runs
ssh mrcook1e@192.168.1.23 \
    "sudo tshark -i usbmon1 -w /tmp/goodix_$(date +%s).pcapng"
```

VM config: 4GB RAM, 4 vCPU, UEFI, 64GB SATA, USB passthrough `27c6:589a`,
SPICE port 5900. See `~/win11-vm.xml` on Fedora for full libvirt XML.

---

## Packet structure reference

### Outer USB wrapper (all traffic)

```
[flags: 1B] [length: 2B LE] [payload: N B] [checksum: 1B]
```

### Initialization sequence (plaintext)

| # | Type | Direction | Meaning |
|---|---|---|---|
| 1 | `0xB0` Wake | host→sensor | Wake from sleep |
| 2 | `0xF0` Chip ID | host→sensor | Query firmware version |
| 3 | `0xE0` PSK Exchange | bidirectional | Retrieve/write PSK |
| 4 | `0xB2` GTLS Init | bidirectional | TLS-PSK handshake begins |
| 5 | `0xD0` Config | host→sensor | Push sensor configuration |
| 6 | `0x20` FDT Calibrate | host→sensor | Finger detection baseline |
| 7 | `0x20` FDT Poll | bidirectional | Wait for finger, then capture |

### GTLS / TLS layer (after handshake)

Single hardcoded suite: `TLS_PSK_WITH_AES_128_CBC_SHA256` = `0x00AE`

Key derivation:
```
pre_master = uint16_be(32) || zeros(32) || uint16_be(32) || psk   [68 B]
master     = PRF(pre_master, "master secret", CR || SR, 48 B)
key_block  = PRF(master, "key expansion", SR || CR, 96 B)

client_MAC = key_block[0:32]
server_MAC = key_block[32:64]
client_key = key_block[64:80]
server_key = key_block[80:96]
```

See [`docs/TLS_REPLACEMENT_PLAN.md`](TLS_REPLACEMENT_PLAN.md) for the full
custom TLS state machine replacing OpenSSL.

---

## External references

| Resource | URL | Why |
|---|---|---|
| tlambertz reversing writeup | https://blog.th0m.as/misc/fingerprint-reversing/ | Best documented Goodix RE |
| Neodyme blog | https://neodyme.io/en/blog/fingerprint_reversing/ | mbedtls internals, x64dbg workflow |
| goodix-fp-dump | https://github.com/goodix-fp-linux-dev/goodix-fp-dump | Python scripts per model |
| goodix-fingerprint-reversing | https://github.com/tlambertz/goodix-fingerprint-reversing | Wireshark dissector + capture.py |
| KVM+usbmon post | https://www.earth.li/~noodles/blog/2012/10/kvm-usbmon-wireshark-win.html | KVM passthrough principle |
| CaptureSetup/USB | https://wiki.wireshark.org/CaptureSetup/USB | usbmon setup guide |
| RFC 4279 | https://www.rfc-editor.org/rfc/rfc4279 | TLS-PSK ciphersuites |
| RFC 5487 | https://www.rfc-editor.org/rfc/rfc5487 | 0x00AE definition |
