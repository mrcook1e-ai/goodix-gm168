"""
CRITICAL FIX:
Line 180001359: __builtin_memset(&var_4b8, 0, 0x30)
var_4b8 = &var_4c8[16]  → zeros var_4c8[16:64] (48 bytes)

So AFTER IV write and BEFORE second SHA-256:
  var_4c8[0:16] = IV
  var_4c8[16:64] = zeros  (NOT first_sha[16:32] - that was overwritten by memset!)

Second SHA-256 input:
  64 bytes: var_4c8 = [IV:16 || zeros:48]
  16 bytes: var_488 (from sub_1800036c0)

second_sha = SHA256(IV || zeros_48 || var_488)
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

# var_4c8 at second SHA-256:
var_4c8_at_second = IV + bytes(48)  # [IV:16 || zeros:48]
print(f'var_4c8 at 2nd SHA256: {var_4c8_at_second.hex()}')

def try_key(label, key, blob_label, blob):
    ct = blob[16:64]
    dec = AES.new(key, AES.MODE_CBC, IV).decrypt(ct)
    pad = dec[-1]
    ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
    if ok:
        psk = dec[:-pad]
        zeros = all(b == 0 for b in psk)
        print(f'  *** OK [{blob_label}] {label}: PSK={psk.hex()} zeros={zeros}')
        return psk
    else:
        if blob_label == 'KNOWN':
            print(f'  bad [{blob_label}] {label}: pad=0x{pad:02x} key={key.hex()}')
    return None

# Try var_488 = zeros → SHA256(IV || zeros_64)
for var_488 in [
    bytes(16),                                           # zeros
    hashlib.sha256(b'123GOODIX').digest()[:16],         # simple
    hashlib.sha256(IV).digest()[:16],                   # SHA256(IV)
    hashlib.sha256(first_sha).digest()[:16],            # SHA256(first_sha)
]:
    second_sha = hashlib.sha256(var_4c8_at_second + var_488).digest()
    key16 = second_sha[:16]
    label = f'SHA256(IV||z48||{var_488[:4].hex()}...)'
    try_key(label, key16, 'KNOWN', KNOWN)

# Also try var_488 = SHA256-based CRC of Goodix obfuscated bytes
chars = [0x47, 0x6f, 0x6f, 0x64, 0x69, 0x78]
buf = []
r10, i = 1, 7
while i >= 0:
    for c in chars:
        buf.append(((c >> r10) | (c << i)) & 0xff)
    r10 += 2; i -= 2

var_488_sha_groups = b''.join(hashlib.sha256(bytes(buf[j:j+3])).digest()[:2] for j in range(0, 24, 3))
second_sha = hashlib.sha256(var_4c8_at_second + var_488_sha_groups).digest()
try_key('SHA2_groups', second_sha[:16], 'KNOWN', KNOWN)

# Try: second SHA-256 uses only 64 bytes (no var_488)
second_sha_64only = hashlib.sha256(var_4c8_at_second).digest()
try_key('SHA256(64B only)', second_sha_64only[:16], 'KNOWN', KNOWN)

# Try AES-256 variants
for var_488 in [bytes(16), var_488_sha_groups]:
    second_sha = hashlib.sha256(var_4c8_at_second + var_488).digest()
    label = f'AES256 SHA256(IV||z48||{var_488[:4].hex()}...)'
    ct = KNOWN[16:64]
    dec = AES.new(second_sha, AES.MODE_CBC, IV).decrypt(ct)
    pad = dec[-1]
    ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
    if ok:
        print(f'  *** AES-256 OK: PSK={dec[:-pad].hex()}')
    else:
        print(f'  AES-256 bad: {label} pad=0x{pad:02x}')

# Known-plaintext: for KNOWN (PSK=zeros), derive what second_sha MUST be
# AES-CBC: CT[0] = AES(K, PT[0] XOR IV)
# For PSK=zeros: PT[0] = 0x00*16, so CT[0] = AES(K, IV)
# K[16B] unknown. But: WB_blob structure TAG = var_4c8.o || var_4b8.o
# If the 32-byte tag IS second_sha, then KNOWN[64:96] = KNOWN_second_sha
print(f'\nKNOWN[64:96] = {KNOWN[64:96].hex()}  (candidate second_sha)')
print(f'WB[64:96]    = {WB[64:96].hex()}  (candidate second_sha - different!)')
# They differ → 32-byte tag is NOT second_sha (it's PSK-dependent = HMAC)

# Try: HMAC-SHA256 output at end. key=KNOWN[64:96] as AES key?
known_tag = KNOWN[64:96]
try_key('KNOWN_tag[:16] as AES key', known_tag[:16], 'KNOWN', KNOWN)
