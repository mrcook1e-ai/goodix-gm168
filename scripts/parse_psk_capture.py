"""
Extract PSK blobs from goodix_full.pcapng and attempt WB decryption.

Looks for E0 WRITE commands containing tag 0xbb010002 (DPAPI) and
tag 0xbb010003 (WhiteBox), extracts the blobs, then tries to decrypt
the WB blob using SHA-256("123GOODIX")[:16] as AES-128-CBC key.
"""

import subprocess
import struct
import hashlib
import sys

PCAP = r"C:\Users\mrcook1e\Documents\goodix-gm168\captures\goodix_full.pcapng"
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES


# ── 1. Pull raw capdata from tshark ──────────────────────────────────────────

def get_frames():
    result = subprocess.run(
        [TSHARK, "-r", PCAP, "-T", "fields",
         "-e", "frame.number",
         "-e", "usb.endpoint_address.direction",
         "-e", "usb.capdata"],
        capture_output=True, text=True
    )
    frames = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 3 and parts[2]:
            fnum = int(parts[0])
            direction = parts[1]  # 0=OUT (host→sensor), 1=IN
            data = bytes.fromhex(parts[2])
            frames[fnum] = (direction, data)
    return frames


# ── 2. Reassemble multi-packet USB transfers ──────────────────────────────────
# Each 64-byte USB packet is one frame. Reassemble consecutive OUT frames
# that belong to the same A0 command by reading the outer length field.

def reassemble_commands(frames):
    """
    Yields (frame_numbers, direction, full_payload) for each complete
    Goodix A0 outer command.
    """
    frame_nums = sorted(frames.keys())
    i = 0
    while i < len(frame_nums):
        fnum = frame_nums[i]
        direction, data = frames[fnum]

        # Only care about host→sensor (OUT, direction=0) commands
        if direction != "0" or not data or data[0] != 0xa0:
            i += 1
            continue

        if len(data) < 3:
            i += 1
            continue

        total_len = struct.unpack_from("<H", data, 1)[0]  # payload length LE
        # outer frame = [a0:1][len:2][checksum:1] + payload
        # But the checksum comes AFTER the payload: [a0][len:2][payload...][csum:1]
        # Actually from PSK.md: [flags:1B][len:2B LE][payload:N][checksum:1B]
        need_bytes = 1 + 2 + total_len + 1  # flags + len + payload + checksum

        # Collect consecutive frames until we have enough bytes
        collected = bytearray(data)
        used_frames = [fnum]
        j = i + 1
        while len(collected) < need_bytes and j < len(frame_nums):
            next_fnum = frame_nums[j]
            next_dir, next_data = frames[next_fnum]
            if next_dir == "0" and next_data:
                collected.extend(next_data)
                used_frames.append(next_fnum)
            j += 1

        # Extract payload (strip padding zeros at end)
        payload = bytes(collected[3:3 + total_len])
        yield used_frames, direction, payload
        i = j if j > i + 1 else i + 1


# ── 3. Parse Goodix E0/E4 commands ───────────────────────────────────────────

def parse_e0_write(payload):
    """
    E0 WRITE payload structure (from PresetPskWriteG):
      [cmd:1=0xe0][inner_hdr:2][total_len:4][chunk_len:4][offset:4][data...]

    The data contains:
      [magic:10][tag:4 LE][data_len:4 LE][blob_data...]
    """
    if not payload or payload[0] != 0xe0:
        return None
    # skip cmd(1) + inner_hdr(2)
    if len(payload) < 3 + 12:
        return None
    body = payload[3:]
    total_len = struct.unpack_from("<I", body, 0)[0]
    chunk_len = struct.unpack_from("<I", body, 4)[0]
    offset    = struct.unpack_from("<I", body, 8)[0]
    data      = body[12:12 + chunk_len]
    return total_len, chunk_len, offset, data


# ── 4. Accumulate chunks → reconstruct blobs ─────────────────────────────────

MAGIC = bytes([0x56, 0xa5, 0xbb, 0x95, 0x6b, 0x7c, 0x8d, 0x9e, 0x00, 0x00])

TAG_DPAPI = 0xBB010002
TAG_WB    = 0xBB010003
TAG_HASH  = 0xBB020001

def extract_blobs_from_chunks(chunks):
    """
    chunks: list of (offset, data) sorted by offset
    The concatenated stream after the 10-byte magic is:
      [tag:4 LE][data_len:4 LE][blob...]
    possibly multiple TLVs back to back.
    """
    stream = b"".join(d for _, d in sorted(chunks))
    # Find and skip magic
    magic_pos = stream.find(MAGIC)
    if magic_pos == -1:
        return {}
    pos = magic_pos + len(MAGIC)

    blobs = {}
    while pos + 8 <= len(stream):
        tag = struct.unpack_from("<I", stream, pos)[0]
        length = struct.unpack_from("<I", stream, pos + 4)[0]
        pos += 8
        if length == 0 or pos + length > len(stream):
            break
        blobs[tag] = stream[pos:pos + length]
        pos += length
    return blobs


# ── 5. WB decrypt ────────────────────────────────────────────────────────────

def wb_decrypt(blob, salt=b"123GOODIX"):
    """Decrypt WB blob: AES-128-CBC, key=SHA-256(salt)[:16], IV=0x00*16."""
    key = hashlib.sha256(salt).digest()[:16]
    iv  = bytes(16)
    print(f"  WB key (SHA-256('{salt.decode()}')[:16]): {key.hex()}")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(blob)
    # remove PKCS7 pad
    pad = decrypted[-1]
    if 1 <= pad <= 16:
        return decrypted[:-pad], key
    return decrypted[:32], key  # fallback: just first 32 bytes


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"[*] Reading {PCAP}")
    frames = get_frames()
    print(f"[*] Got {len(frames)} frames with data")

    # Accumulate E0 write chunks (may span multiple A0 commands)
    e0_chunks = []  # list of (offset, data)

    print("\n[*] Scanning for E0 write commands...")
    for fnums, direction, payload in reassemble_commands(frames):
        if not payload or payload[0] != 0xe0:
            continue
        result = parse_e0_write(payload)
        if result is None:
            continue
        total_len, chunk_len, offset, data = result
        print(f"  frames {fnums}: E0 WRITE total={total_len} chunk={chunk_len} offset={offset}")
        e0_chunks.append((offset, data))

    if not e0_chunks:
        print("[!] No E0 WRITE commands found - trying raw frame scan...")
        # fallback: scan raw frame data for tag bytes
        for fnum in sorted(frames.keys()):
            _, data = frames[fnum]
            if b'\x03\x00\x01\xbb' in data:
                print(f"  Frame {fnum} contains WB tag 0xbb010003")
            if b'\x02\x00\x01\xbb' in data:
                print(f"  Frame {fnum} contains DPAPI tag 0xbb010002")
        return

    blobs = extract_blobs_from_chunks(e0_chunks)

    print(f"\n[*] Extracted TLV blobs: {[hex(t) for t in blobs]}")

    if TAG_DPAPI in blobs:
        dpapi = blobs[TAG_DPAPI]
        print(f"\n[+] DPAPI blob (0xbb010002): {len(dpapi)} bytes")
        print(f"    head: {dpapi[:16].hex()}")
        with open("dpapi_blob.bin", "wb") as f:
            f.write(dpapi)
        print(f"    saved: dpapi_blob.bin")

    if TAG_WB in blobs:
        wb = blobs[TAG_WB]
        print(f"\n[+] WB blob (0xbb010003): {len(wb)} bytes")
        print(f"    hex: {wb.hex()}")
        with open("wb_blob_from_capture.bin", "wb") as f:
            f.write(wb)
        print(f"    saved: wb_blob_from_capture.bin")

        print(f"\n[*] Attempting WB decrypt...")
        psk, key = wb_decrypt(wb)
        print(f"  Decrypted ({len(psk)} bytes): {psk.hex()}")
        psk32 = psk[:32]
        psk_hash = hashlib.sha256(psk32).digest()
        print(f"  SHA-256(PSK[:32]): {psk_hash.hex()}")

        if TAG_HASH in blobs:
            mcu_hash = blobs[TAG_HASH]
            print(f"\n[+] MCU hash (0xbb020001): {mcu_hash.hex()}")
            if psk_hash == mcu_hash:
                print(f"[✓✓✓] MATCH! WB decrypt correct. PSK = {psk32.hex()}")
                with open("psk_from_wb.bin", "wb") as f:
                    f.write(psk32)
                print(f"    saved: psk_from_wb.bin")
            else:
                print(f"[✗] No match. Key derivation or IV differs.")
                print(f"    expected: {mcu_hash.hex()}")
                print(f"    got:      {psk_hash.hex()}")

    if TAG_HASH in blobs and TAG_WB not in blobs:
        print(f"\n[+] MCU hash (0xbb020001): {blobs[TAG_HASH].hex()}")


if __name__ == "__main__":
    main()
