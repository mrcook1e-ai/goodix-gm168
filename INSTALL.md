# Installing the goodix-gm168 driver

Three install paths in order of "easiest → most manual":

1. [Fedora COPR repo](#1-fedora-copr-repo) — `dnf install`.
2. [Bash installer](#2-bash-installer) — works on any Fedora 41+.
3. [Manual build](#3-manual-build) — meson, applies to any distro that
   can build libfprint from source.

After install, do the [PSK bootstrap](#psk-bootstrap) one-time setup and
you can `fprintd-enroll`.

---

## 1. Fedora COPR repo

```bash
sudo dnf copr enable mrcook1e-ai/goodix-gm168
sudo dnf install libfprint-goodix-gm168
```

This package **replaces** the system `libfprint` with a build that has our
driver compiled in.  `Conflicts: libfprint` is set, `dnf` will swap them
cleanly.  `fprintd` is restarted automatically by the `%post` scriptlet.

To uninstall:

```bash
sudo dnf swap libfprint-goodix-gm168 libfprint
```

---

## 2. Bash installer

For distros without COPR access, or to install straight from `main`:

```bash
curl -fsSL https://raw.githubusercontent.com/mrcook1e-ai/goodix-gm168/main/install.sh | bash
```

What it does (read [`install.sh`](install.sh) for the full script):

1. Verifies Fedora 41+.
2. `dnf install`s build prerequisites.
3. Clones libfprint 1.94.10 and our driver into `~/.cache/goodix-gm168/`.
4. Applies the patch and meson-builds to `/opt/libfprint-goodix-gm168/`.
5. Adds `/opt/libfprint-goodix-gm168/lib64` to `/etc/ld.so.conf.d/` so
   `fprintd` finds our libfprint instead of the stock one.
6. Installs the udev rule and creates `/etc/goodix-gm168/`.
7. Restarts `fprintd`.

This path is non-destructive — your distro `libfprint` is untouched, the
new build lives under `/opt`.

To uninstall:

```bash
sudo rm -rf /opt/libfprint-goodix-gm168 \
            /etc/ld.so.conf.d/goodix-gm168.conf \
            /etc/udev/rules.d/70-goodix-gm168.rules
sudo ldconfig
sudo systemctl restart fprintd
```

---

## 3. Manual build

For distros other than Fedora, or if you want to control the prefix.

### Prerequisites

You need build tools and libfprint's build-deps.  On Debian / Ubuntu:

```bash
sudo apt install git meson ninja-build pkg-config \
    libglib2.0-dev libgusb-dev libssl-dev \
    libcairo2-dev libpixman-1-dev \
    libsystemd-dev libgudev-1.0-dev \
    libgirepository1.0-dev fprintd
```

On Fedora:

```bash
sudo dnf install git meson ninja-build gcc \
    glib2-devel libgusb-devel openssl-devel \
    cairo-devel pixman-devel \
    systemd-devel libgudev-devel \
    gobject-introspection-devel fprintd
```

### Build

```bash
# 1. Get the sources
git clone https://github.com/mrcook1e-ai/goodix-gm168.git
git clone --branch v1.94.10 \
    https://gitlab.freedesktop.org/libfprint/libfprint.git

# 2. Drop the driver into the libfprint tree
mkdir -p libfprint/libfprint/drivers/goodix_gm168
cp goodix-gm168/src/*.{c,h} libfprint/libfprint/drivers/goodix_gm168/
rm libfprint/libfprint/drivers/goodix_gm168/meson.build  # in-tree one comes from the patch

# 3. Apply the patch that wires us into libfprint's build
(cd libfprint && git apply ../goodix-gm168/patches/libfprint-add-gm168.patch)

# 4. Configure and build
meson setup build libfprint \
    --prefix=/usr/local \
    --libdir=lib \
    -Ddrivers=default \
    -Dudev_rules=disabled \
    -Dgtk-examples=false \
    -Ddoc=false \
    -Dintrospection=false
meson compile -C build
sudo meson install -C build

# 5. udev rule + state directory
sudo install -D -m 0644 \
    goodix-gm168/packaging/udev/70-goodix-gm168.rules \
    /etc/udev/rules.d/70-goodix-gm168.rules
sudo install -d -m 0755 /etc/goodix-gm168
sudo udevadm control --reload
sudo udevadm trigger

# 6. Restart fprintd to pick up the new libfprint
sudo systemctl restart fprintd
```

`fprintd` loads `libfprint-2.so.2` from whatever `ld.so` resolves
first — if your distro `libfprint` is in `/usr/lib/`, install with
`--prefix=/usr` so we override it.  Backup the system one first if you
want a fallback.

---

## PSK bootstrap

The sensor uses TLS-PSK with a **device-specific** 32-byte key provisioned by
the Windows driver.  You have to extract it once.  This is the only step that
requires Windows.

### Step 1 — extract the sealed blob from your sensor

On Linux, run anything that activates the driver:

```bash
fprintd-enroll
```

It will fail with *"PSK not provisioned"* and the driver writes a
324-byte sealed blob to `/etc/goodix-gm168/sealed.bin`.  Copy it to a
USB stick.

### Step 2 — unseal on Windows

Boot to the Windows install that was used when the laptop was set up.
You don't need to run Windows fingerprint enrollment — just need DPAPI
access on the install whose user provisioned the device.

Copy `sealed.bin` plus `gm168_unseal.ps1` to that Windows machine.

`gm168_unseal.ps1` is shipped by the package at
`/usr/share/doc/libfprint-goodix-gm168/tools/windows/` (RPM install) or
`/opt/libfprint-goodix-gm168/share/doc/.../` (bash install), or grab it
from [`tools/windows/`](tools/windows/) in this repo.

In an elevated PowerShell (right-click → "Run as administrator"):

```powershell
.\gm168_unseal.ps1 -SealedBlob C:\path\to\sealed.bin -OutPsk C:\path\to\psk.bin
```

The script:
1. UAC-elevates to admin.
2. Stages the blob into `C:\Windows\Temp\` so SYSTEM can read it.
3. Spawns a one-shot scheduled task running as `NT AUTHORITY\SYSTEM`
   that calls `CryptUnprotectData`.  Only SYSTEM can decrypt the
   DPAPI master key for the user that the Windows driver ran as.
4. Reads back the 32-byte PSK, writes it to `-OutPsk`, prints the hex
   so you can sanity-check.

### Step 3 — drop the PSK on Linux

```bash
sudo install -m 600 psk.bin /etc/goodix-gm168/psk.bin
sudo systemctl restart fprintd
fprintd-enroll
```

If everything is set up, enrollment should complete in ~22 seconds
(12 stages × ~1.8 s per touch).

### Backing up

`psk.bin` is hardware-bound — re-extracting requires the same Windows
install (DPAPI master keys are user + machine bound).  If you lose the
Windows install (reinstall, disk failure) without backing up the PSK,
your only option is to re-provision via Windows (works on a fresh
Windows install but rotates the PSK to whatever the new install
generates).

Back it up to a password manager or encrypted USB:

```bash
sudo cp /etc/goodix-gm168/psk.bin ~/secure-backup/gm168-psk-$(hostname).bin
```

---

## Verifying the install

After the PSK is in place:

```bash
# Driver registers the USB device
lsusb | grep 27c6:589a

# libfprint sees a driver for it
python3 -c "
import gi; gi.require_version('FPrint','2.0')
from gi.repository import FPrint
for d in FPrint.Context().get_devices():
    print('found:', d.get_driver())
"
# expected: found: goodix_gm168

# End-to-end test
fprintd-enroll
fprintd-verify
```

Per-session structured logs land in `~/.goodix-gm168/sessions/gm168-*.log` —
attach one of these to any bug report.
