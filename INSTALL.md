# Installing the GM168SEC driver

## 1. Build

```bash
sudo apt install meson ninja-build pkg-config \
    libglib2.0-dev libgusb-dev libssl-dev libfprint-2-dev
meson setup build goodix_gm168
ninja -C build
sudo ninja -C build install
```

This installs `libfprint-goodix-gm168.so` under `$(libdir)/libfprint-2/drivers/`,
where libfprint picks it up automatically.

## 2. udev rule

```bash
sudo cp packaging/60-goodix-gm168.rules /etc/udev/rules.d/
sudo udevadm control --reload
sudo udevadm trigger
```

Make sure your user is in the `plugdev` group:

```bash
sudo usermod -aG plugdev "$USER"
# log out / back in
```

## 3. PSK bootstrap

On first run the driver will report a missing `/etc/goodix-gm168/psk.bin`
and dump a 324-byte sealed blob into `/etc/goodix-gm168/sealed.bin`. To
unseal it:

1. Boot the Windows install where the sensor was originally provisioned
   (Settings → Sign-in options → Fingerprint at least once).
2. Copy `sealed.bin` to that Windows machine.
3. Run, in an elevated PowerShell:

   ```powershell
   tools\windows\gm168_unseal.ps1 `
       -SealedBlob sealed.bin `
       -OutPsk     psk.bin
   ```

4. Copy `psk.bin` back to Linux as `/etc/goodix-gm168/psk.bin`:

   ```bash
   sudo install -m 600 psk.bin /etc/goodix-gm168/psk.bin
   ```

Detailed troubleshooting: [`docs/PIPELINE.md`](docs/PIPELINE.md).

## 4. Verify

```bash
fprintd-enroll
fprintd-verify
```

Enroll currently reaches **stage 4/5** reliably. The remaining gap is a
preprocessor calibration step that has not yet been reverse-engineered;
see [`docs/NEXT_STEPS.md`](docs/NEXT_STEPS.md).
