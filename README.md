# goodix-gm168 — Linux fingerprint driver

A [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) driver for the
**Goodix GM168SEC** capacitive fingerprint sensor (USB `27c6:589a`), found in
several Lenovo / HP / ASUS laptops where mainline libfprint reports
*"No driver found"*.

Production-tested on Fedora 46, integrates with `fprintd` + PAM unchanged.

```
sudo dnf copr enable mrcook1e-ai/goodix-gm168
sudo dnf install libfprint-goodix-gm168
# get a psk.bin (one-time, see "PSK bootstrap" below)
sudo install -m 600 psk.bin /etc/goodix-gm168/psk.bin
fprintd-enroll
```

## Status

| What                  | State                                         |
|-----------------------|-----------------------------------------------|
| Enroll (12 stages)    | ✅ ~22 s wall-clock on Fedora 46              |
| Verify                | ✅ ~1 s, gnome / KDE / PAM all work           |
| Identify              | ✅                                            |
| Quality (NBIS score)  | 84-92 / 100, dual-capture per touch           |
| Stability             | No watchdog timeouts under fprintd boot-load  |
| Suspend / resume      | ✅ (TLS session is re-established on wake)    |
| Hotplug               | ✅                                            |

## Supported hardware

| Vendor:Product | Status   | Notes                                         |
|----------------|----------|-----------------------------------------------|
| `27c6:589a`    | Works    | GM168SEC, tested on Lenovo laptops, Fedora 46 |
| Other Goodix   | Untested | Protocol shared across the family — please open an issue if you try one |

Check yours: `lsusb \| grep 27c6:589a`

## Install

### Fedora (recommended — COPR repo)

```bash
sudo dnf copr enable mrcook1e-ai/goodix-gm168
sudo dnf install libfprint-goodix-gm168
```

This swaps the system `libfprint` for one with our driver compiled in.
`fprintd` will pick it up on restart.

### Fedora / RHEL — bash installer

For systems without COPR, or if you want to install from `main`:

```bash
curl -fsSL https://raw.githubusercontent.com/mrcook1e-ai/goodix-gm168/main/install.sh | bash
```

Same end-state as the RPM, installs under `/opt/libfprint-goodix-gm168/`.

### Other distros / manual build

See [INSTALL.md](INSTALL.md) for the meson-based manual build.

## PSK bootstrap

The sensor speaks TLS-PSK; the PSK is **device-specific** (provisioned by the
Windows driver at factory or first Windows boot).  You need to extract it once
and drop it at `/etc/goodix-gm168/psk.bin`.

Two-step procedure:

**1. On Linux** — run anything that activates the driver (e.g.
`fprintd-enroll`).  It will fail with *"PSK not provisioned"* but writes a
324-byte sealed blob to `/etc/goodix-gm168/sealed.bin`.

**2. On Windows** — boot to the Windows install that originally provisioned
the sensor (Settings → Sign-in → Fingerprint at least once).  Copy
`sealed.bin` over and run, in an elevated PowerShell:

```powershell
.\gm168_unseal.ps1 -SealedBlob C:\path\to\sealed.bin -OutPsk C:\path\to\psk.bin
```

`gm168_unseal.ps1` ships with the package under
`/usr/share/doc/libfprint-goodix-gm168/tools/windows/`, or from
[tools/windows/](tools/windows/) in this repo.  It uses Windows DPAPI under a
SYSTEM-elevated scheduled task; no Frida, no Wbdi.dll, no SGX hooks.

**3. Back on Linux**:

```bash
sudo install -m 600 psk.bin /etc/goodix-gm168/psk.bin
sudo systemctl restart fprintd
fprintd-enroll
```

The PSK is hardware-bound — **back up your `psk.bin` to safe storage** because
re-running the unseal procedure requires the same Windows install (DPAPI master
keys are user + machine bound).

## Performance

Measured on Fedora 46, USB 3.0 host, Lenovo X1 Carbon Gen 9:

| Phase           | Wall-clock | Notes                                |
|-----------------|-----------:|--------------------------------------|
| Driver init     |      619 ms| 5-frame BG capture + FDT arm         |
| TLS handshake   |      132 ms| OpenSSL, PSK-AES128-CBC-SHA256       |
| Per-touch CAP   |      ~22 ms| ×2 captures per touch (dual-capture) |
| Per-touch REARM |     ~840 ms| FDT re-arm + wait-lift               |
| 12-stage enroll |     ~22 s  | Including user lift between touches  |

Recent timing improvements live in [`docs/DRIVER.md`](docs/DRIVER.md) §
"Optimisations" — short summary: REARM_DELAY 1500 → 150 ms (measured Windows
~115 ms in `patches/goodix.pcapng`), wait-lift poll 1000 → 300 ms, dual frame
capture per touch.

## Source layout

```
src/                  driver source (C, ~3 kLOC)
docs/                 architecture + protocol notes
patches/              the libfprint integration patch
packaging/
  ├ fedora/           RPM spec for COPR
  └ udev/             USB uaccess rule (27c6:589a)
tools/windows/        gm168_unseal.ps1 (DPAPI PSK extraction)
scripts/              build / enroll / debug helpers
install.sh            one-shot installer (Fedora)
```

Full reverse-engineering material — pcaps, RE Python scripts, original Goodix
SDK leak, WhiteBox AES key derivation — lives on the
[`archive/reverse-engineering`](https://github.com/mrcook1e-ai/goodix-gm168/tree/archive/reverse-engineering)
branch.

## Troubleshooting

**`fprintd-enroll` says "No devices detected"** — kernel sees the device but
libfprint doesn't.  Check that our `libfprint-2.so.2` is the active one:

```bash
sudo lsof /usr/lib64/libfprint-2.so.2 2>/dev/null | head
ldconfig -p | grep libfprint-2
```

**"PSK not provisioned"** — see the *PSK bootstrap* section above.  After
dropping `psk.bin`, restart `fprintd`.

**Permission denied on `/dev/bus/usb/…`** — udev rule didn't take.  Verify:

```bash
getfacl /dev/bus/usb/$(lsusb | awk '/27c6:589a/{sub(":","",$4); print $2"/"$4}')
# should list "user:<your-uid>:rw-"
```

If not, `sudo udevadm control --reload && sudo udevadm trigger`, then
re-plug the device or reboot.

**Driver appears to hang** — open an issue with the structured log at
`~/.goodix-gm168/sessions/gm168-*.log` from the failing session.

## Acknowledgements

- libfprint authors and the existing Goodix drivers (`goodixmoc`,
  `goodix5xx`) — protocol patterns and SSM structure.
- Binary Ninja + Frida — reverse engineering Wbdi.dll.
- OpenSSL 3.x — PSK TLS server with the `NO_RENEGOTIATION + NO_TICKET`
  trick that made the legacy GM168 handshake work without rewriting
  the TLS layer.

## License

[LGPL-2.1-or-later](LICENSE), matching libfprint.

## Disclaimer

This is reverse engineering for personal interoperability — recovering the
ability to use hardware you already own with the operating system of your
choice.  The driver does not bypass Windows DPAPI sealing; it co-exists with
whatever Windows provisioned and asks the user to re-extract their own PSK on
their own machine.  No PSK material leaves the device owner's hands.
