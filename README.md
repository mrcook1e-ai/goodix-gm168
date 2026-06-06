# goodix-gm168 — Linux fingerprint driver

A [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) driver
for the **Goodix GM168SEC** capacitive fingerprint sensor
(USB VID:PID `27c6:589a`), found in several Lenovo / HP / ASUS laptops.

The sensor is not supported by mainline libfprint. This project reverse-
engineered the Windows protocol (`Wbdi.dll`), ported the per-pixel image
pipeline byte-for-byte, and hardened the transport layer for production
use with `fprintd` on Fedora 43+.

```
[scan]   → TLS-PSK over USB → de-pad → 12-bit unpack + transpose
         → background subtract → envelope-stretch → CLAHE? → fp_img → NBIS
```

Enroll + verify work end-to-end with the stock fprintd + PAM stack.

## Supported hardware

| Vendor:Product | Status   | Notes                                |
|----------------|----------|--------------------------------------|
| `27c6:589a`    | Works    | Tested on Lenovo laptop, Fedora 43   |
| Other Goodix   | Unknown  | Protocol is family-shared; YMMV      |

Probe yours: `lsusb | grep 27c6:589a`

## What's here

```
src/                  driver source (C, ~2400 LOC)
docs/                 architecture + reverse-engineering notes
  ├ DRIVER.md          driver internals, SSMs, hardening layer
  ├ HARDENING.md       transport-layer hardening campaign (10 items)
  ├ AUDIT.md           pre-hardening code audit
  ├ PIPELINE.md        image pipeline walkthrough
  └ PSK.md             how the TLS-PSK provisioning works
patches/              libfprint integration patch
udev/                 USB access rule
scripts/              build / deploy / release / grid-dumps
tools/windows/        gm168_unseal.ps1 (DPAPI unseal of sealed PSK)
tests/                static-assert tests for timeout constants
INSTALL.md            initial install steps
RESTORE.md            re-install from backup checklist
```

## Quick start

The build is a libfprint patch + a /opt prefix install, so it doesn't
touch system libfprint. The driver is loaded via a systemd drop-in that
points fprintd at `/opt/libfprint-gm168/lib64`.

```bash
# 1. one-time dev tools + libfprint clone
./scripts/bootstrap-fedora.sh

# 2. drop PSK (32 bytes, hardware-bound)
sudo install -m 600 your-psk.bin /etc/goodix-gm168/psk.bin

# 3. full release install (build, install, fprintd, polkit, systemd)
./scripts/release.sh all

# 4. enroll + verify
fprintd-enroll
fprintd-verify
```

If you don't have a PSK yet, see `docs/PSK.md`. There are three paths:

1. **Windows + Frida hook** (~20 min) — capture from a working Windows
   driver via `frida_work/gx_hook.js` (not bundled — was research-stage).
2. **Windows VM with USB passthrough** (~1 evening) — Linux host only,
   QEMU + Win10 guest. See "PSK lost — recovery" in [RESTORE.md](RESTORE.md).
3. **Boot to Windows + unseal** — driver auto-dumps `sealed.bin` from
   sensor memory; `tools/windows/gm168_unseal.ps1` decrypts via DPAPI.

The PSK is hardware-bound (DPAPI machine key during Windows
provisioning). Back up `/etc/goodix-gm168/psk.bin` to safe storage; losing
it means re-running one of the recovery paths above.

## Hardening campaign

`docs/HARDENING.md` documents 13 transport-layer items (G1..G13). 10
ship, 3 deferred. Coverage:

- 🔴 Critical: 2/2 (TLS thread leak, SSL_accept hang)
- 🟠 High: 9/12 (SSM watchdog, USB error classification, RECOVER SSM,
  cancellable wiring, capture resync, lifecycle cleanup, …)
- 🟡 Medium: 7/14

Verified under fprintd boot-load: 12-stage enroll + verify pass without
regressions. See `docs/DRIVER.md` § "Hardening layer" for the technical
overview.

## Calibration data

`src/gm168_cal.h` ships baseline cal1 / cal2 tables captured from one
specific sensor via Frida. Image quality may degrade on other physical
sensors of the same model — to regenerate per-device, see notes in
`docs/PIPELINE.md`.

Disable with `GM168_USE_CAL2=0` to fall back to the dynamic background
capture path (slightly noisier but per-sensor accurate).

## Status

Production-ready for personal use on the developer's machine. Not
upstream in libfprint (yet — see "Roadmap"). No automated CI; testing
is manual via the included scripts.

## Roadmap

- [ ] Upstream into libfprint (long path — mailing list, review cycle)
- [ ] IAP-mode provisioning so PSK can be generated on Linux without
      Windows at all (currently `docs/PSK.md` § "out of scope")
- [ ] Better matcher for tiny 80×64 sensor area (NBIS is rough on this
      sensor; verify rejection rate ~20% of touches)
- [ ] Hotplug auto-recovery (G5 in HARDENING.md, currently deferred)

## Acknowledgements

- libfprint authors and the existing Goodix drivers
  (`goodixmoc`, `goodix5xx`, `goodix6xx`) — protocol patterns
- The Binary Ninja and Frida tooling that made reverse engineering
  feasible
- OpenSSL for the PSK TLS server

## License

LGPL-2.1-or-later, matching libfprint. See [LICENSE](LICENSE).

## Disclaimer

This is reverse-engineering for personal interoperability and educational
purposes. The driver does not bypass Windows DPAPI sealing — it
co-exists with whatever Windows provisioned. PSK material is
hardware-bound and never leaves the device owner's machine.
