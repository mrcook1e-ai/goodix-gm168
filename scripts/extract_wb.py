"""
Direct extraction of WB blob from known frame positions in goodix_full.pcapng.

From raw frame analysis:
  Frame 536: ...030001bb60000000ec35ae3abb45ed3f12c4751f1e5c2c
  Frame 538: c018e97cc54fb96637...b6de5
  Frame 540: 6a47238ce1329d5e22b401634e58c208e1...

WB blob (96 bytes, tag 0xbb010003, len 0x60) starts after 030001bb60000000.
"""

import subprocess, hashlib, sys

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
PCAP   = r"C:\Users\mrcook1e\Documents\goodix-gm168\captures\goodix_full.pcapng"

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

# Pull raw capdata indexed by frame number
result = subprocess.run(
    [TSHARK, "-r", PCAP, "-T", "fields",
     "-e", "frame.number", "-e", "usb.capdata"],
    capture_output=True, text=True
)
raw = {}
for line in result.stdout.splitlines():
    parts = line.strip().split("\t")
    if len(parts) == 2 and parts[1]:
        raw[int(parts[0])] = parts[1]  # hex string

# Concatenate frames containing the WB blob and find the blob
# WB blob marker: tag 0xbb010003 + len 0x60 = "030001bb60000000"
MARKER = "030001bb60000000"

# Build stream from all frames (they are 64-byte USB packets)
stream = ""
for fnum in sorted(raw.keys()):
    stream += raw[fnum]

# Find WB blob
pos = stream.find(MARKER)
if pos == -1:
    print("[!] WB marker not found in stream")
    sys.exit(1)

print(f"[+] Found WB marker at hex stream offset {pos}")
wb_start = pos + len(MARKER)
wb_hex = stream[wb_start : wb_start + 192]  # 96 bytes = 192 hex chars
wb_blob = bytes.fromhex(wb_hex)
print(f"[+] WB blob ({len(wb_blob)} bytes): {wb_blob.hex()}")

# Also find DPAPI blob marker: 020001bb44010000 or 020001bb00010000
DPAPI_TAG = "020001bb"
pos2 = stream.find(DPAPI_TAG)
if pos2 != -1:
    # The DPAPI blob length is 0x144 = 324 bytes
    dpapi_len_hex = stream[pos2+8 : pos2+16]
    dpapi_len = int.from_bytes(bytes.fromhex(dpapi_len_hex), 'little')
    print(f"\n[+] DPAPI tag found at stream offset {pos2}, declared len = {dpapi_len}")

# Find MCU hash (tag 0xbb020001)
HASH_TAG = "010002bb20000000"
pos3 = stream.find(HASH_TAG)
mcu_hash = None
if pos3 != -1:
    hash_hex = stream[pos3+16 : pos3+16+64]  # 32 bytes = 64 hex chars
    mcu_hash = bytes.fromhex(hash_hex)
    print(f"[+] MCU PSK hash (0xbb020001): {mcu_hash.hex()}")

# --- WB decrypt ---
print(f"\n[*] Attempting WB decrypt with SHA-256('123GOODIX')[:16]...")
wb_key_full = hashlib.sha256(b"123GOODIX").digest()
aes_key = wb_key_full[:16]
iv = bytes(16)
print(f"    SHA-256('123GOODIX')      = {wb_key_full.hex()}")
print(f"    AES-128 key (first 16B)   = {aes_key.hex()}")

cipher = AES.new(aes_key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(wb_blob)
print(f"    Decrypted raw ({len(decrypted)}B)  = {decrypted.hex()}")

# Check PKCS7 pad
pad = decrypted[-1]
print(f"    PKCS7 pad byte = 0x{pad:02x}")
if 1 <= pad <= 16 and all(b == pad for b in decrypted[-pad:]):
    psk = decrypted[:-pad]
    print(f"    After PKCS7 strip: {psk.hex()} ({len(psk)} bytes)")
else:
    psk = decrypted[:32]
    print(f"    Bad pad — taking first 32 bytes: {psk.hex()}")

psk32 = psk[:32]
psk_hash = hashlib.sha256(psk32).digest()
print(f"\n    SHA-256(decrypted PSK) = {psk_hash.hex()}")

if mcu_hash:
    if psk_hash == mcu_hash:
        print(f"\n[✓✓✓] MATCH! WB key derivation correct!")
        print(f"      PSK = {psk32.hex()}")
        with open("psk_from_wb.bin", "wb") as f:
            f.write(psk32)
        print(f"      Saved: psk_from_wb.bin")
    else:
        print(f"\n[✗] SHA-256 mismatch — key derivation or IV is wrong")
        print(f"    Expected (MCU hash): {mcu_hash.hex()}")
        print(f"    Got:                 {psk_hash.hex()}")
        print(f"\n    Trying HMAC-SHA256 key derivation...")
        # Alternative: HMAC-SHA256(key=SHA256_H0, msg="123GOODIX")
        SHA256_IV = bytes.fromhex(
            "6a09e667bb67ae853c6ef372a54ff53a"
            "510e527f9b05688c1f83d9ab5be0cd19"
        )
        import hmac
        hmac_key = hmac.new(SHA256_IV, b"123GOODIX", hashlib.sha256).digest()
        print(f"    HMAC key = {hmac_key.hex()}")
        cipher2 = AES.new(hmac_key[:16], AES.MODE_CBC, iv)
        dec2 = cipher2.decrypt(wb_blob)
        psk2 = dec2[:32]
        hash2 = hashlib.sha256(psk2).digest()
        print(f"    HMAC decrypt: {psk2.hex()}")
        print(f"    SHA-256:      {hash2.hex()}")
        if hash2 == mcu_hash:
            print(f"\n[✓✓✓] HMAC variant MATCHES!")
            print(f"      PSK = {psk2.hex()}")
        else:
            print(f"[✗] HMAC variant also wrong")
            print(f"\n    Dumping raw decrypted bytes for manual analysis:")
            print(f"    SHA-256 decrypt: {decrypted.hex()}")
            print(f"    HMAC decrypt:    {dec2.hex()}")
