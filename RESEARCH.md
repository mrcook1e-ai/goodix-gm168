# Goodix GM168SEC Fingerprint Reverse Engineering

## TL;DR — Final Algorithm (verified pixel-perfect)

The sensor sends raw 12-bit-packed pixel data over TLS. **There is no descrambling.**
The transformation from TLS payload to the clean 64×80 uint16 image used by the
preprocessor is purely geometric:

```c
/* Input:  10564 bytes (4-byte header + 10560 bytes payload, laid out as
 *         80 rows × 132 bytes where each row = 96 data bytes + 36 zero pad)
 * Output: 64 × 80 uint16 image, row-major
 */
void gm168_decode_frame(const uint8_t *tls_payload, uint16_t out[64*80])
{
    uint8_t compact[80 * 96];

    /* Step 1: skip 4-byte header, de-pad each 132-byte wire row to 96 data bytes */
    const uint8_t *p = tls_payload + 4;
    for (int r = 0; r < 80; r++)
        memcpy(compact + r * 96, p + r * 132, 96);

    /* Step 2: decode 12-bit packed pixels + transpose in single pass.
     * 6 packed bytes -> 4 pixels; logical pixel k (0..5119) is placed at
     * output index (k % 64) * 80 + (k / 64), which is the transpose of an
     * 80-row × 64-col arrangement into a 64-row × 80-col output.
     */
    int k = 0;
    for (int i = 0; i < 80 * 96; i += 6) {
        uint8_t b0 = compact[i+0], b1 = compact[i+1], b2 = compact[i+2];
        uint8_t b3 = compact[i+3], b4 = compact[i+4], b5 = compact[i+5];
        uint16_t pix[4] = {
            ((b0 & 0xF) << 8) | b1,            /* P0 */
            (b3 << 4)         | (b0 >> 4),     /* P1 */
            ((b5 & 0xF) << 8) | b2,            /* P2 */
            (b4 << 4)         | (b5 >> 4),     /* P3 */
        };
        for (int j = 0; j < 4; j++)
            out[((k + j) % 64) * 80 + ((k + j) / 64)] = pix[j];
        k += 4;
    }
}
```

Verified pixel-perfect on 2/2 captured frames against the Windows preprocessor's
input buffer. Reference Python implementation: `scripts/solve_seed.py`.

---

## The Path To That Answer

The first two days of work were spent chasing an LFSR-based cipher that the
sensor does not actually use. This section records what was true, what was
wrong, and how we got to ground truth.

### What Was Wrong Initially

The original RESEARCH.md described a 32-bit LFSR (`sub_180077784` /
`sub_180077a84` in Wbdi.dll) and a seed living in the SGX enclave. Those
functions exist, but they are **dead code on this device**. Frida hooks
confirmed:

- `sub_180077a84` (LFSR descramble core in Wbdi.dll): 0 invocations across
  multiple finger-touch sessions.
- `FpParseImage` userland fields `*(dev+0x80)` (scramble flag) and
  `*(dev+0x84)` (seed): always 0.
- The "SGX path" via `SgxFpParseImage` enclave function is never taken — the
  production path stays inside Wbdi.dll via a local `sub_18003bc78` fallback,
  with the descramble step gated off by `flag == 0`.

The legacy LFSR description was correct *as code*. It just doesn't run.

### The Hook Pipeline That Cracked It

`frida_work/gx_hook.js` instruments the whole data path inside Wbdi.dll and
saves each intermediate buffer to `C:\Windows\Temp\gx_dumps\<SID>_<TAG>_<n>.bin`:

| Tag       | RVA       | What it captures                                                  |
|-----------|-----------|-------------------------------------------------------------------|
| `RECV`    | `0x0d4e0` | Raw bytes from `mbedtls_ssl_read` (TLS plaintext)                 |
| `STORED`  | `0x3ad6c` | `data_180255280` — TLS payload after stripping first 8 bytes      |
| `SGXIN`   | `0x3bc78` | Input to local `SgxFpParseImage` fallback (`flag`, `seed` args)   |
| `SGXOUT`  | `0x3bc78` | Output of the same                                                |
| `DESC`    | `0x77a84` | Every legacy LFSR descramble call (= 0 on this device)            |
| `RESTIN`  | `0x4e2dc` | Input to `ImageRestructInterface` (+ mode/w/h from config struct) |
| `RESTOUT` | `0x4e2dc` | Output of the same                                                |
| `FPPARSE` | `0x4b670` | Userland device struct flag/seed snapshot                         |
| `INPUT`   | `0xc87b0` | `preprocessor()` arg1 — pre-calibration uint16 frame              |
| `FRAME`   | `0xc87b0` | `preprocessor()` arg4 — post-calibration uint8 frame              |
| `CALIB`   | `0xc84b0` | `preprocess_save_calidata` blob                                   |
| `CFG`     | data      | Full 128-byte `data_180255290` config struct (hex in log)         |

WUDFHost.exe runs as LOCAL SERVICE, so dumps go to `C:\Windows\Temp\gx_dumps\`
(world-writable). The session id (`SID`) is timestamp-based so runs don't
clobber each other.

The deploy/fetch scripts in `scripts/`:

- `deploy_frida.ps1` — push `frida_work/` to the laptop's Windows side (port 22)
- `fetch_session.ps1` — pull `session.log` and `dumps/<SID>_*.bin` back to the PC
- `deploy_linux.ps1` — push driver sources to the laptop's WSL side (port 2200)

### Diagnostic Sequence

Once the hooks were comprehensive, one finger touch produced enough data to
solve everything in a single iteration:

1. `SGXIN.head` == `RESTIN.head` (byte-identical) → no descramble between them.
2. `RESTOUT.head` == `INPUT.head` (byte-identical) → `ImageRestructInterface`
   is the transformation that produces the clean image.
3. `RESTIN size = 10560` (= TLS minus 4-byte header), `RESTOUT size = 10240`
   (= 5120 uint16 = 64×80).
4. `CFG` struct first byte = `0x11` → mode 17 in the switch.
5. The Wbdi.dll switch in `sub_18004e2dc` (unlike the enclave's
   `sub_18003eb30`, which stops at case 0xe) has additional cases 0x10, 0x11,
   0x12. Case `0x11` dispatches to `sub_18004e030`.
6. `sub_18004e030` does the row de-pad: `memcpy(dst + r*0x60, src + r*0x84, 0x60)`
   in a loop of 0x50 iterations = 80 rows of 96 bytes each, source stride 132.
7. `sub_18004ef00` does decode + transpose: standard 12-bit unpack writing
   pixel `k` to `out[(k % 0x40) * 0x50 + (k / 0x40)]` = `out[(k%64)*80 + k/64]`.

That's the whole pipeline. Python implementation of those two steps matched
both captured frames pixel-perfectly.

---

## Wire Format Reference

### Packet
```
USB B2 packet → TLS record → mbedtls_ssl_read returns 10564 bytes of plaintext
```

### Layout of the 10564-byte plaintext
```
[0..3]                       4-byte image header (skipped before decode)
[4..10563]                   10560 bytes of payload, laid out as 80 wire rows
  each wire row (132 bytes):
    [0..95]                  96 bytes of 12-bit-packed pixel data
                             (16 groups × 6 bytes; each group encodes 4 pixels)
    [96..131]                36 bytes of zero padding
```

### 12-bit Pack Format
6 bytes `b0..b5` encode 4 pixels:
```
P0 = (b0 & 0x0F) << 8 | b1
P1 = b3        << 4 | (b0 >> 4)
P2 = (b5 & 0x0F) << 8 | b2
P3 = b4        << 4 | (b5 >> 4)
```

### Pixel Index Mapping
Logical pixel index `k` runs 0..5119 in order through the packed groups.
Each logical `k` is written to output index `(k % 64) * 80 + (k / 64)`. This
is equivalent to interpreting the logical stream as a row-major 80×64 image
(80 rows of 64 pixels each — matching the 80 wire rows × 64 data pixels per
row) and transposing it to row-major 64×80.

---

## Calibration Blob (`calib_windows.dat`)

Layout unchanged from before, captured via Frida from
`preprocess_save_calidata` (RVA `0xc84b0`). Total 140464 bytes.

| Offset    | Field                                       |
|-----------|---------------------------------------------|
| `0x0000`  | CRC of Cal1                                 |
| `0x0004`  | CRC of Cal2                                 |
| `0x0008`  | Cal1 (dark reference), 88×80 uint16 = 14080 |
| `0x9928`  | Cal2 (bright reference), 14080 bytes        |
| `0x18488` | int32 device parameter (= 77 here)          |
| `0x22490` | Version string "Preprocess_v_1.01.01"       |

Preprocessor formula (`sub_1800c87b0`):
```
signal = 0xFFF - raw_pixel + reference
```

Cal1 is the dark frame and is the reference the preprocessor subtracts. For
the Linux driver, parse Cal1 out of `calib_windows.dat` at offset `0x9928`
and use it instead of doing a runtime background capture.

Caveat: the calibration data may be device-specific. Whether `calib_windows.dat`
from one laptop works on another GM168 unit is **untested** — needs a second
sensor.

---

## Sensor Communication

### USB
- VID/PID: `27C6:589A`
- EP_OUT: `0x01`, EP_IN: `0x83` (16 KB)

### Packet Types
- `A0` plaintext command / ACK
- `B0` TLS handshake record
- `B2` TLS encrypted application record (10564-byte frame after decrypt)

### Protocol Commands (A0)

| cmd | Name                | Where reversed from               | Notes                                |
|-----|---------------------|-----------------------------------|--------------------------------------|
| `0x11` | WakeUp           | RESEARCH (no ACK)                 | first command after USB enumerate    |
| `0x20` | GetVersion / TriggerCapture | sendCmd path           | dual role — small payload = version; large payload = capture trigger |
| `0x32` | FDT Setup        | 35-byte capacitive threshold blob | written every capture cycle          |
| `0x34` | FDT Rearm        | sendCmd path                      | written **twice per cycle** + before each capture |
| `0x60` | Session Init     | RESEARCH                          | once at boot                         |
| `0xAE` | IRQ Arm          | sendCmd path                      | every cycle, before FDT rearm        |
| `0xD0` | TLS Start        | RESEARCH                          | once at boot                         |
| `0xD6` | MCU ReadRegister | `IoHubReadReg` → `MilanFSerSpiReadReg` | 2-byte payload = reg addr LE; 2-byte response = reg value. Observed reading reg 0 once per session. |
| `0x43` | PSK Read         | RESEARCH                          | returns nothing in normal mode (SGX) |
| `0xA8` | OTP Read         | RESEARCH                          | device-specific data                 |

### Init Sequence (cold boot, captured via Frida with disable/enable trick)
1. `0x11` WakeUp (no ACK)
2. `0x20` GetVersion → `"GF3206_GM168SEC_APP_10008"` (config struct also names
   it `"GF3258 WN2"`)
3. `0x60` Session Init
4. `0xD0` TLS Start → PSK handshake with 32-byte `REAL_PSK` (captured via Frida)
5. `0xAE` IRQ Arm
6. `0x32` FDT Setup (35-byte capacitive threshold blob)
7. `0x20` background capture (`INIT_BG_PROCESS`)
8. `0x34` ×2 FDT Rearm → ready for touch

### Touch & Capture

Touch event: `A0` packet, echo `0x32`, status `0x02`.

### Runtime Capture Loop (verified via _IoHubExec hook)

Each finger-touch cycle issues exactly these commands in order (one cycle ≈ 5
events, seen repeating ≥7× in one session):

```
0xAE  IRQ Arm                  (3-byte payload)
0x34  FDT Rearm                (35-byte payload)
0x34  FDT Rearm                (35-byte payload, second one)
0x32  FDT Setup                (35-byte payload, sometimes 2× back-to-back)
0x20  TriggerCapture           (10-byte payload, returns 10240 bytes processed frame)
```

The `got=10240` byte count on the `0x20` is **already-processed INPUT data**
(64×80 uint16) returned by the orchestrator's callback, not the raw 10564-byte
TLS payload. The raw frame is intercepted separately at the TLS layer
(mbedtls_ssl_read, RVA 0x0d4e0).

This pattern replaces the older RESEARCH.md note "0x34 ×2 FDT Rearm → ready for
touch" — the rearm pair fires **every** capture cycle, not just once after
background.

### Frida Protocol Instrumentation

`gx_hook.js` hooks `_IoHubExec` (RVA `0x794d8`) and emits one
`STEP N type=... cmd=0xXX outSz=... inSz=...` line per protocol event, plus a
`STEPRET N ret=... err=... got=...` line on return. Outgoing payloads are
saved to `C:\Windows\Temp\gx_dumps\<SID>_STEPOUT_<N>.bin` and readRaw
responses to `<SID>_STEPIN_<N>.bin`.

`scripts/protocol_checklist.py` parses the log and prints:
- TIMELINE (ordered list of all steps with cmd resolved to name)
- EVENT COUNTS (by type and by cmd)
- INIT SEQUENCE CHECK (validates against the documented init order)

**Catching full init:** WUDFHost.exe loads Wbdi.dll once when the device
starts. To catch the init commands (`0x11`, `0xD0`, `0x60`), Frida must be
attached BEFORE init runs. Workflow:
1. Start `frida_work/hook_finger.bat` (admin) — Frida waits for WUDFHost
2. In parallel: Device Manager → Biometric devices → ПКМ Goodix → **Disable**,
   wait 2-3 seconds → **Enable**
3. Wbdi.dll reloads from scratch; Frida attaches and catches init from
   `STEP 1 cmd=0x11` onward

Do **not** uninstall the driver — destructive and unnecessary.

---

## Linux Driver Status

### Working
- TLS handshake with `REAL_PSK`
- Background frame capture at init
- Touch detection (`A0` echo=0x32 status=0x02)
- Frame capture and TLS decryption

### Next
- Replace the current decode path with `gm168_decode_frame` above
- Replace runtime background capture with `Cal1` parsed from `calib_windows.dat`
- Apply `signal = 0xFFF - raw + Cal1` per the preprocessor formula
- Test through `fprintd` for enrollment/matching

### PSK / Cross-Device Portability
- `REAL_PSK` was captured via Frida from `Wbdi.dll`'s PSK callback
- Whether the PSK is device-specific or universal across GM168 units is
  **untested** — needs a second sensor to verify
- For factory-reset devices, IAP/bootloader (`SetIapModeGeneva`) is required
- Note that `calib_windows.dat` has the same uncertainty

---

## Repository Layout

```
goodix_gm168/                  Linux libfprint driver (in development)
raw/
  Wbdi.dll                     Windows driver
  Wbdi.dll.bndb                Binary Ninja database
  WbdiEnclave.signed.dll       SGX enclave (analyzed; mostly dead code on this device)
  WbdiEnclave.signed.dll.bndb
frida_work/
  gx_hook.js                   Comprehensive pipeline-instrumentation hook
  hook_finger.bat              Launch from cmd as admin
  dumps/                       Pulled-back binary captures (one set per SID)
scripts/
  deploy_frida.ps1             PC → laptop (Windows side, :22)
  deploy_linux.ps1             PC → laptop (Linux/WSL side, :2200)
  fetch_session.ps1            laptop → PC (session.log + matching dumps)
  solve_seed.py                The final working decoder (Python reference impl)
calib_windows.dat              Calibration blob captured via Frida
session.log                    Latest Frida session output
```

---

## Frida Setup (laptop, Windows)

- `frida-server.exe` runs as SYSTEM via Task Scheduler task `FridaServer`
- `frida` Python client at `C:\Users\mrcook1e\AppData\Local\Programs\Python\Python314\Scripts\frida.exe`
- Hook injection from an interactive admin shell (not via frida-server):
  double-click `frida_work\hook_finger.bat`, accept UAC, place finger.
  The bat waits for WUDFHost.exe loading Wbdi.dll, attaches, and writes
  `session.log` via Tee.
