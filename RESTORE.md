# Restoring goodix_gm168 driver on a fresh Linux install

After wiping Windows / reinstalling Linux on the laptop, follow these
steps to get the fingerprint reader working again. The source tree on
your Windows PC (where this repo lives) survives — you only need to
re-deploy + re-build on the new Linux.

## Prerequisites — files on the Windows PC

These must exist before you start. They were saved before the wipe:

- `goodix-gm168/` (this repo) — full source tree
- `goodix-gm168/logs/psk-backup-20260606-034138.bin` — **the PSK**
  (32 bytes, hardware-bound to this sensor; without it the driver
  cannot start a TLS session — see PSK.md if lost)
- SHA256 of the backup must match what's stored in the sensor — was
  verified the day of the backup: `cd28fb94...521770`

If the PSK file is gone — see "PSK lost" at the bottom.

## On the new Linux install

Assumes Fedora. For other distros, adjust package names in
`scripts/bootstrap-fedora.sh`.

### 1. Get SSH access from the Windows PC

The deploy/release scripts SSH from your Windows PC to the laptop.
Set up the SSH server on the new Linux, install your public key,
expose the port you used before (default 2200):

```bash
sudo dnf install -y openssh-server
sudo systemctl enable --now sshd
# Edit /etc/ssh/sshd_config: Port 2200 (or whatever GM168_HOST/PORT
# variables in scripts/_lib.sh expect)
sudo systemctl restart sshd
```

Verify from Windows PC:
```bash
ssh -p 2200 mrcook1e@<laptop-ip> "uname -a"
```

### 2. Deploy the source tree

From Windows PC:
```bash
cd /c/Users/mrcook1e/goodix-gm168
./scripts/deploy.sh
```

This rsyncs the repo to `~/dev/goodix-gm168/` on the laptop.

### 3. Bootstrap Fedora dev tools + libfprint

On the laptop (one-time):
```bash
cd ~/dev/goodix-gm168
./scripts/bootstrap-fedora.sh
```

Installs: meson, ninja, gcc, glib/gusb/openssl-devel, clones libfprint
at the pinned tag (v1.94.9), creates dirs, installs udev rule, adds
you to plugdev.

### 4. Restore PSK

From Windows PC:
```bash
scp -P 2200 logs/psk-backup-20260606-034138.bin \
    mrcook1e@<laptop-ip>:/tmp/psk.bin
ssh -p 2200 mrcook1e@<laptop-ip> "
    sudo mkdir -p /etc/goodix-gm168
    sudo install -m 600 /tmp/psk.bin /etc/goodix-gm168/psk.bin
    rm /tmp/psk.bin
    sha256sum /etc/goodix-gm168/psk.bin"
```

Expected sha256: `cd28fb94810a36dfab17c717ea6d6711ca89d1ed2f1adf6a88518afceab21770`

### 5. Run the full release install

From Windows PC:
```bash
./scripts/release.sh all
```

This does (idempotent, safe to re-run):
- Sync src/ into libfprint tree
- Build release (no GM168_DEBUG, -O2)
- Install fprintd + polkit
- Systemd override → LD_LIBRARY_PATH=/opt/libfprint-gm168/lib64
- Polkit rule allowing `wheel` to enroll/verify without password prompt
- Restart fprintd

### 6. Enroll + verify

On the laptop:
```bash
fprintd-enroll      # 12 stages, place finger at slightly different angles
fprintd-verify      # touch in roughly the same position
```

### 7. (Optional) Enable for login/sudo

```bash
sudo authselect select sssd with-fingerprint --force
```

Or via gnome-control-center → Users → Fingerprint Login.

## PSK lost — recovery without the backup

If `psk-backup-*.bin` is gone AND `/etc/goodix-gm168/psk.bin` isn't on
the laptop, you have two options:

### Option A: Windows VM with Frida

Detailed plan: see chat / README, but in short:
1. Install QEMU + virt-manager on Fedora
2. Win10 VM (no TPM needed)
3. USB-passthrough the sensor to the VM
4. Inside VM: install Goodix WBDI driver (Windows Update), Frida-tools
5. Run `frida_work/gx_hook.js` while Windows enrolls a fingerprint
6. Frida logs the PSK to console — copy out as psk.bin
7. Done with VM, never need it again

This re-provisions the sensor with a fresh PSK. ~1 evening of work.

### Option B: dual-boot Windows once

1. Boot a Windows install (any, even Windows-To-Go USB)
2. Windows installs Goodix driver, sets up fingerprint
3. Reboot to Linux, our driver dumps sealed.bin from sensor memory
4. Boot Windows again, run `tools/windows/gm168_unseal.ps1`
5. Reboot to Linux, copy psk.bin to `/etc/goodix-gm168/`

Same end result. Requires real Windows install + dual-boot.

## What's preserved across reinstalls

- **PSK** (sensor flash) — survives Linux reinstall. Only wiped by
  another OS provisioning fingerprint OR factory-reset via IAP mode.
- **Enrolled fingerprint templates** (`/var/lib/fprint/`) — wiped.
  Re-enroll on first login.
- **udev rule, fprintd config, systemd overrides** — wiped. The
  `release.sh all` rebuilds them.

## Reference: file inventory

| File | Where | Purpose |
|------|-------|---------|
| `src/` | repo | driver source |
| `patches/libfprint-add-gm168.patch` | repo | integrate into libfprint tree |
| `udev/60-goodix-gm168.rules` | repo | usb access for plugdev |
| `tools/windows/gm168_unseal.ps1` | repo | Windows unseal of sealed.bin |
| `frida_work/gx_hook.js` | not in repo (was in original RE) | Frida PSK capture |
| `scripts/release.sh` | repo | full production install |
| `scripts/bootstrap-fedora.sh` | repo | one-time dev setup |
| `logs/psk-backup-*.bin` | repo (gitignored — keep in cloud) | THE psk |
| `/etc/goodix-gm168/psk.bin` | Linux (root:root 600) | runtime location |
