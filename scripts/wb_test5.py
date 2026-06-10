"""
After first SHA-256 finalize, the IV derivation modifies var_4c8[0:16]:
  var_4c8.o = zmm2 (IV, stored back)  ← line 180001373

So at second SHA-256 time, var_4c8 = [IV:16 || first_sha[16:32]:16 || zeros:32]

Second SHA-256 feeds:
  - 64 bytes: var_4c8 = IV || first_sha[16:32] || zeros_32
  - 16 bytes: var_488
→ second_sha = SHA256(IV || first_sha[16:32] || zeros_32 || var_488)
AES key = second_sha[:16]
"""
import hashlib
try:
    from Crypto.Cipher import AES
except:
    from Cryptodome.Cipher import AES

WB = bytes.fromhex(
    'ec35ae3abb45ed3f12c4751f1e5c2cc0'
    '18e97cc54fb96637a09dbde6bb87efc8'
    '73287db6593c428c01affa68935ee973'
    '686702617397334392cb3c194550d7cb'
    'b22655c67a57d9bfddee98554b6de56a'
    '47238ce1329d5e22b401634e58c208e1'
)
KNOWN = bytes.fromhex(
    'ec35ae3abb45ed3f12c4751f1e5c2cc0'
    '5b3c5452e9104d9f2a3118644f37a04b'
    '6fd66b1d97cf80f1345f76c84f03ff30'
    'bb51bf308f2a9875c41e6592cd2a2f9e'
    '60809b17b5316037b69bb2fa5d4c8ac3'
    '1edb3394046ec06bbdacc57da6a756c5'
)

prefix = (32).to_bytes(4, 'little')
first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()
IV = first_sha[:15] + bytes([first_sha[15] & 0xf0])

print(f'first_sha:    {first_sha.hex()}')
print(f'IV:           {IV.hex()}')
print(f'WB[:16]:      {WB[:16].hex()}  match={IV == WB[:16]}')

# The 64-byte var_4c8 at second SHA-256 time:
# var_4c8[0:16] = IV (overwritten)
# var_4c8[16:32] = first_sha[16:32] (original, not overwritten)
# var_4c8[32:64] = zeros
var_4c8_64 = IV + first_sha[16:32] + bytes(32)
print(f'\nvar_4c8_64: {var_4c8_64.hex()}')

# Try different var_488 values
def try_decrypt(label, var_488_16, blob_label, blob):
    second_sha_input = var_4c8_64 + var_488_16
    second_sha = hashlib.sha256(second_sha_input).digest()
    key = second_sha[:16]
    ct = blob[16:64]
    dec = AES.new(key, AES.MODE_CBC, IV).decrypt(ct)
    pad = dec[-1]
    ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
    if ok:
        psk = dec[:-pad]
        zeros = all(b == 0 for b in psk)
        print(f'  *** OK [{blob_label}] {label}: key={key.hex()} PSK={psk.hex()} zeros={zeros}')
        return psk
    else:
        if blob_label == 'KNOWN':
            print(f'  [{blob_label}] {label}: key={key.hex()} pad=0x{pad:02x} bad')
    return None

# Try var_488 = zeros (most likely if sub_1800036c0 CRC is misunderstood)
try_decrypt('var_488=zeros', bytes(16), 'KNOWN', KNOWN)
try_decrypt('var_488=zeros', bytes(16), 'WB', WB)

# Try var_488 = CRC of obfuscated Goodix bytes (from previous analysis)
chars = [0x47, 0x6f, 0x6f, 0x64, 0x69, 0x78]
buf = []
r10, i = 1, 7
while i >= 0:
    for c in chars:
        buf.append(((c >> r10) | (c << i)) & 0xff)
    r10 += 2; i -= 2

var_488_sha = b''.join(hashlib.sha256(bytes(buf[j:j+3])).digest()[:2] for j in range(0, 24, 3))
try_decrypt('var_488=SHA2_groups', var_488_sha, 'KNOWN', KNOWN)
try_decrypt('var_488=SHA2_groups', var_488_sha, 'WB', WB)

# Try var_488 = first 16 bytes of SHA256 of all 24 obfuscated bytes
var_488_fullhash = hashlib.sha256(bytes(buf)).digest()[:16]
try_decrypt('var_488=SHA256(24B)[:16]', var_488_fullhash, 'KNOWN', KNOWN)

# Try var_488 = CRC32 of the 24 bytes (big endian, then LE, various combinations)
import struct
crc_poly = 0x4c11db7

def crc32_mpeg2(data):
    crc = 0xffffffff
    for b in data:
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) & 0xffffffff) ^ crc_poly
            else:
                crc = (crc << 1) & 0xffffffff
            crc ^= (1 if (b & 0x80) else 0)
            b = (b << 1) & 0xff
    return crc & 0xffffffff

crc_val = crc32_mpeg2(bytes(buf))
print(f'\nCRC32/MPEG-2 of {bytes(buf).hex()} = {crc_val:08x}')
# Store at var_488[12:14] as big-endian 2 bytes (from decompile)
for fill in [bytes(12), hashlib.sha256(bytes(buf[:3])).digest()[:12]]:
    v488 = fill + struct.pack('>H', (crc_val >> 16) & 0xffff) + bytes(2)
    try_decrypt(f'var_488 CRC at [12:14]', v488, 'KNOWN', KNOWN)

# Try: what if var_488 = SHA256(first_sha || "123GOODIX")[:16]?
v488 = hashlib.sha256(first_sha + b'123GOODIX').digest()[:16]
try_decrypt('var_488=SHA256(fsha||123G)[:16]', v488, 'KNOWN', KNOWN)

# What if second SHA-256 doesn't include var_488 at all (only 64 bytes)?
print('\n--- Second SHA-256 with only 64-byte var_4c8 (no var_488) ---')
sh2_64 = hashlib.sha256(var_4c8_64).digest()
key = sh2_64[:16]
for blob, label in [(KNOWN, 'KNOWN'), (WB, 'WB')]:
    ct = blob[16:64]
    dec = AES.new(key, AES.MODE_CBC, IV).decrypt(ct)
    pad = dec[-1]
    ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
    if ok:
        psk = dec[:-pad]
        print(f'  *** OK [{label}] SHA256(64B): PSK={psk.hex()} zeros={all(b==0 for b in psk)}')
    else:
        print(f'  [{label}] SHA256(64B) only: pad=0x{pad:02x}')
