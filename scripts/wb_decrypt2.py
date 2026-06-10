"""
WB decrypt attempt #2 — based on decompile of sub_180001000 (SecWhiteEncrypt).

Key observations from HLIL decompile:
  1. First SHA-256 feeds: [arg2_as_LE32] || "123GOODIX"
     (arg2 = input length = 32 = 0x20)
  2. IV = first_sha256[:16] with IV[15] = (IV[15] & 0xf0) | (arg2 & 0x0f)
     (arg2 & 0x0f = 32 & 0xf = 0, so IV[15] gets lower nibble zeroed)
  3. Second SHA-256 feeds: first_sha256[:32] || zeros_16bytes
     → gives 32-byte AES key; AES-128 uses key[:16]
  4. Output appends 32 bytes after ciphertext (var_4c8.o || var_4b8.o)
     → WB blob = AES_ciphertext || 32_bytes_extra

So for PSK=32 bytes:
  plaintext = PSK (PKCS7 padded: 32 → 48 bytes)
  ciphertext = 48 bytes
  + 32 bytes appended
  = 80 bytes total

BUT our blob is 96 bytes... possibly:
  - The code appends 0x30=48 bytes?
  - Or PKCS7 pad is 32 bytes (value 0x20)? Making plaintext 32+32=64 → 64 bytes cipher + 32 = 96!

Trying multiple hypotheses.
"""

import hashlib
import subprocess
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

PCAP  = r"C:\Users\mrcook1e\Documents\goodix-gm168\captures\goodix_full.pcapng"
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

# ── Pull WB blob from pcap ────────────────────────────────────────────────────
result = subprocess.run(
    [TSHARK, "-r", PCAP, "-T", "fields", "-e", "frame.number", "-e", "usb.capdata"],
    capture_output=True, text=True
)
raw = {}
for line in result.stdout.splitlines():
    parts = line.strip().split("\t")
    if len(parts) == 2 and parts[1]:
        raw[int(parts[0])] = parts[1]

stream = "".join(raw[f] for f in sorted(raw))
MARKER = "030001bb60000000"
pos = stream.find(MARKER)
assert pos != -1, "WB marker not found"
wb_hex = stream[pos + len(MARKER) : pos + len(MARKER) + 192]
WB = bytes.fromhex(wb_hex)
print(f"[+] WB blob ({len(WB)}B): {WB.hex()}")

# Also pull MCU hash from IN direction frames
result2 = subprocess.run(
    [TSHARK, "-r", PCAP, "-T", "fields",
     "-e", "frame.number", "-e", "usb.endpoint_address.direction", "-e", "usb.capdata"],
    capture_output=True, text=True
)
in_stream = ""
for line in result2.stdout.splitlines():
    parts = line.strip().split("\t")
    if len(parts) == 3 and parts[1] == "1" and parts[2]:
        in_stream += parts[2]

# MCU hash tag: 010002bb20000000
HASH_MARKER = "010002bb20000000"
hpos = in_stream.find(HASH_MARKER)
mcu_hash = None
if hpos != -1:
    mcu_hash = bytes.fromhex(in_stream[hpos + len(HASH_MARKER) : hpos + len(HASH_MARKER) + 64])
    print(f"[+] MCU hash: {mcu_hash.hex()}")
else:
    print("[!] MCU hash not found in IN stream")

# ── Key derivation from decompile ─────────────────────────────────────────────

INPUT_LEN = 32  # arg2 = 32 bytes PSK

# First SHA-256: [arg2 as 4-byte LE] || "123GOODIX"
prefix = INPUT_LEN.to_bytes(4, "little")  # = b'\x20\x00\x00\x00'
first_sha = hashlib.sha256(prefix + b"123GOODIX").digest()
print(f"\n[*] first_sha256({prefix.hex()} || '123GOODIX') = {first_sha.hex()}")

# IV = first_sha[:16] with last byte lower nibble = (arg2 & 0x0f)
iv = bytearray(first_sha[:16])
iv[15] = (iv[15] & 0xf0) | (INPUT_LEN & 0x0f)  # arg2 & 0xf = 32 & 0xf = 0
IV = bytes(iv)
print(f"[*] IV = {IV.hex()}")

# Second SHA-256: first_sha (32B) || zeros (16B) — guessing the 16 zeros for var_488
# (var_488 was zeroed at 1800013b3, but may have contained something before)
second_sha = hashlib.sha256(first_sha + bytes(16)).digest()
AES_KEY = second_sha[:16]
print(f"[*] second_sha256(first_sha || 0*16) = {second_sha.hex()}")
print(f"[*] AES key = {AES_KEY.hex()}")

# ── Decrypt hypotheses ────────────────────────────────────────────────────────

def try_decrypt(name, key, iv_bytes, blob, extra_bytes=0):
    """Try AES-CBC decrypt. extra_bytes = bytes to skip at end of blob (appended tag/hmac)."""
    ciphertext = blob[:len(blob) - extra_bytes]
    if len(ciphertext) % 16 != 0:
        print(f"  [{name}] ciphertext length {len(ciphertext)} not multiple of 16, skip")
        return None
    cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
    dec = cipher.decrypt(ciphertext)
    pad = dec[-1]
    print(f"  [{name}] pad byte = 0x{pad:02x}", end="")
    if 1 <= pad <= 16 and all(b == pad for b in dec[-pad:]):
        psk = dec[:-pad]
        print(f" ✓  PSK ({len(psk)}B) = {psk.hex()}")
        if mcu_hash:
            got = hashlib.sha256(psk[:32]).digest()
            match = "✓✓✓ MATCH" if got == mcu_hash else "✗ no match"
            print(f"       SHA256(PSK) = {got.hex()} [{match}]")
        return psk
    else:
        print(f" ✗  (bad pad)")
        print(f"       dec[:32] = {dec[:32].hex()}")
        return None

print("\n--- Hypothesis A: correct derivation, no appended bytes ---")
try_decrypt("A1", AES_KEY, IV, WB, extra_bytes=0)

print("\n--- Hypothesis B: skip last 32 bytes (appended HMAC/tag) ---")
try_decrypt("B1", AES_KEY, IV, WB, extra_bytes=32)

print("\n--- Hypothesis C: skip last 48 bytes ---")
try_decrypt("C1", AES_KEY, IV, WB, extra_bytes=48)

# Also try simple SHA256("123GOODIX")[:16] with the new IV
simple_key = hashlib.sha256(b"123GOODIX").digest()[:16]
print(f"\n--- Hypothesis D: simple SHA256('123GOODIX')[:16] key, new IV ---")
try_decrypt("D1", simple_key, IV, WB, extra_bytes=0)
try_decrypt("D2", simple_key, IV, WB, extra_bytes=32)

# Try old IV (zeros) with new key
print(f"\n--- Hypothesis E: new key, IV=zeros ---")
try_decrypt("E1", AES_KEY, bytes(16), WB, extra_bytes=0)
try_decrypt("E2", AES_KEY, bytes(16), WB, extra_bytes=32)

# Try AES-256 (32-byte key) with IV=zeros
print(f"\n--- Hypothesis F: AES-256 with full second_sha as key, IV=zeros ---")
cipher = AES.new(second_sha, AES.MODE_CBC, bytes(16))
dec = cipher.decrypt(WB[:64])  # 64 bytes
print(f"  [F1] 64B dec: {dec.hex()}")
if 1 <= dec[-1] <= 16:
    print(f"       pad OK, PSK = {dec[:32].hex()}")

# Try: first_sha used directly as AES-256 key
print(f"\n--- Hypothesis G: first_sha as AES-256 key, IV=zeros, skip last 32B ---")
cipher = AES.new(first_sha, AES.MODE_CBC, bytes(16))
dec = cipher.decrypt(WB[:64])
pad = dec[-1]
print(f"  [G1] pad = 0x{pad:02x}, dec[:32] = {dec[:32].hex()}")
if 1 <= pad <= 16:
    psk = dec[:32]
    if mcu_hash:
        got = hashlib.sha256(psk).digest()
        print(f"  SHA256(psk) = {got.hex()}")
        if got == mcu_hash:
            print("  ✓✓✓ G1 MATCH!")

# Hexdump WB blob for manual inspection
print(f"\n--- WB blob hexdump ---")
for i in range(0, len(WB), 16):
    chunk = WB[i:i+16]
    hex_part = ' '.join(f'{b:02x}' for b in chunk)
    print(f"  {i:3d}: {hex_part}")
