#!/usr/bin/env python3
"""
Pre-TLS PSK hash probe for Goodix GM168SEC (USB 27c6:589a).

Sends cmd 0xE4 with tag 0xbb020001 to read the SHA-256 of the PSK
currently stored in the sensor's flash. Compares it to the sha256 of
/etc/goodix-gm168/psk.bin (or a path passed as argv[1]).

If the hashes match, our captured PSK is still the one the sensor knows,
and the SSL_accept failure is a code/OpenSSL issue. If they differ,
Windows re-provisioned the PSK at some point and we need to recapture.

Run as root:
    sudo systemctl stop fprintd
    sudo python3 scripts/check_psk.py
"""

import hashlib
import os
import struct
import sys

try:
    import usb.core
    import usb.util
except ImportError:
    print("pyusb missing — install with: sudo dnf install -y python3-pyusb")
    sys.exit(2)

VID, PID = 0x27C6, 0x589A
EP_OUT, EP_IN = 0x01, 0x83
TIMEOUT_MS = 3000

PSK_HASH_TAG = 0xBB020001  # 32-byte SHA-256 of PSK


def hdr_checksum(pkt_type: int, length: int) -> int:
    return (pkt_type + (length & 0xFF) + ((length >> 8) & 0xFF)) & 0xFF


def body_checksum(cmd: int, plen: int, payload: bytes) -> int:
    s = cmd + (plen & 0xFF) + ((plen >> 8) & 0xFF) + sum(payload)
    return (0xAA - s) & 0xFF


def encode_a0_cmd(cmd: int, payload: bytes) -> bytes:
    plen = len(payload) + 1
    inner_sz = 3 + len(payload) + 1
    out = bytearray(4 + inner_sz)
    out[0] = 0xA0
    out[1] = inner_sz & 0xFF
    out[2] = (inner_sz >> 8) & 0xFF
    out[3] = hdr_checksum(0xA0, inner_sz)
    out[4] = cmd
    out[5] = plen & 0xFF
    out[6] = (plen >> 8) & 0xFF
    out[7:7 + len(payload)] = payload
    out[7 + len(payload)] = body_checksum(cmd, plen, payload)
    return bytes(out)


def build_e4_body(chunk_size: int, offset: int, tag: int) -> bytes:
    return struct.pack("<IIII", chunk_size, offset, tag, 0)


def hexdump_short(b: bytes, n: int = 32) -> str:
    return " ".join(f"{x:02x}" for x in b[:n]) + (" …" if len(b) > n else "")


def main():
    psk_path = sys.argv[1] if len(sys.argv) > 1 else "/etc/goodix-gm168/psk.bin"

    print(f"[probe] reading captured PSK from {psk_path}")
    if not os.path.exists(psk_path):
        print(f"[probe] ERROR: {psk_path} not found.")
        sys.exit(1)
    with open(psk_path, "rb") as f:
        captured_psk = f.read()
    if len(captured_psk) != 32:
        print(f"[probe] ERROR: expected 32 bytes, got {len(captured_psk)}")
        sys.exit(1)
    captured_sha = hashlib.sha256(captured_psk).hexdigest()
    print(f"[probe]   captured PSK sha256 = {captured_sha}")

    print(f"[probe] looking for USB {VID:04x}:{PID:04x}")
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("[probe] ERROR: sensor not found (lsusb?)")
        sys.exit(1)

    # Detach kernel driver if any (fprintd must be stopped first or it will
    # re-grab the device after we release).
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
            print("[probe]   detached kernel driver")
    except (NotImplementedError, usb.core.USBError):
        pass

    try:
        dev.set_configuration()
    except usb.core.USBError as e:
        print(f"[probe] WARN set_configuration: {e}")

    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]
    usb.util.claim_interface(dev, intf.bInterfaceNumber)
    print(f"[probe]   claimed interface {intf.bInterfaceNumber}")

    def tx(label, pkt, drain_rx=True):
        print(f"[probe] TX {label} ({len(pkt)} bytes): {hexdump_short(pkt)}")
        dev.write(EP_OUT, pkt, TIMEOUT_MS)
        if drain_rx:
            try:
                r = bytes(dev.read(EP_IN, 16 * 1024, TIMEOUT_MS))
                print(f"        RX {len(r)} bytes: {hexdump_short(r)}")
                return r
            except usb.core.USBError as e:
                print(f"        RX timeout: {e}")
                return None
        return None

    try:
        # Sensor needs the same init prologue our driver runs in dev_activate
        # before it will respond to cmd 0xE4. Without these, EP_IN stays silent.
        # See INIT_WAKEUP → INIT_RESET → INIT_VERSION in goodix_gm168.c.
        import time

        tx("WAKEUP (cmd 0x11)", encode_a0_cmd(0x11, b""), drain_rx=False)
        time.sleep(0.1)

        # 0x60 with body [0x01, 0x00] clears any stale TLS state in the MCU
        tx("SESSION_INIT (cmd 0x60)", encode_a0_cmd(0x60, bytes([0x01, 0x00])))

        # 0x20 with empty body asks the MCU version — kicks the state machine
        tx("VERSION (cmd 0x20)", encode_a0_cmd(0x20, b""))

        body = build_e4_body(0x20, 0, PSK_HASH_TAG)
        pkt = encode_a0_cmd(0xE4, body)
        print(f"[probe] TX cmd=0xE4 tag=0xbb020001 ({len(pkt)} bytes)")
        print(f"        {hexdump_short(pkt)}")

        n = dev.write(EP_OUT, pkt, TIMEOUT_MS)
        print(f"[probe]   wrote {n} bytes")

        # Drain RX — first packet may be an ack (status=0x60-ish), then the
        # real 0xE4 reply, then possibly trailing async events. Read up to
        # a few times until we see echo_cmd=0xE4 with payload >= 32B.
        for attempt in range(5):
            try:
                resp = bytes(dev.read(EP_IN, 16 * 1024, TIMEOUT_MS))
            except usb.core.USBError as e:
                print(f"[probe]   RX#{attempt} timeout/error: {e}")
                break
            print(f"[probe]   RX#{attempt} {len(resp)} bytes: {hexdump_short(resp)}")
            if len(resp) < 9 or resp[0] != 0xA0:
                continue
            echo_cmd = resp[4]
            status = resp[7]
            if echo_cmd != 0xE4:
                print(f"        echo_cmd=0x{echo_cmd:02x} status=0x{status:02x} — not the reply, keep reading")
                continue

            # Parse extra payload — layout after the 1-byte status:
            #   [tag_echo:4][data_len:4][data:N]
            inner_len = resp[1] | (resp[2] << 8)
            ex_len = max(0, inner_len - 5)  # echo+plenL+plenH+status + bodysum
            extra = resp[8:8 + ex_len]
            if len(extra) < 8:
                print(f"        extra too short ({len(extra)}B)")
                continue
            tag_echo, data_len = struct.unpack("<II", extra[:8])
            data = extra[8:8 + data_len]
            print(f"        tag_echo=0x{tag_echo:08x} data_len={data_len} data={hexdump_short(data)}")
            if tag_echo != PSK_HASH_TAG:
                print(f"        tag_echo mismatch — expected {PSK_HASH_TAG:08x}")
                continue
            if data_len != 32 or len(data) < 32:
                print(f"        data_len wrong — expected 32, got {data_len}")
                continue

            sensor_sha = data[:32].hex()
            print()
            print(f"[probe] sensor PSK sha256 = {sensor_sha}")
            print(f"[probe] our PSK sha256    = {captured_sha}")
            print()
            if sensor_sha == captured_sha:
                print("[probe] ✓ MATCH — captured PSK is still in the sensor.")
                print("        TLS failure is NOT a PSK mismatch — investigate the code/OpenSSL path.")
            else:
                print("[probe] ✗ MISMATCH — sensor was re-provisioned with a different PSK.")
                print("        Recapture via Windows + Frida required (or IAP rewrite).")
            return
        print("[probe] gave up after 5 RX attempts without seeing 0xE4 reply")

    finally:
        usb.util.release_interface(dev, intf.bInterfaceNumber)
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    main()
