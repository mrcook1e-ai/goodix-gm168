"""
Brute-force WB key by verifying against goodix-fp-dump KNOWN blob.
For KNOWN blob (PSK=0x00*32):
  KNOWN[16:64] = AES-CBC ciphertext
  KNOWN[64:96] = HMAC tag (or other authentication)

If we find K such that:
  AES_decrypt(K, IV, CT) = 0x00*32 + PKCS7_pad
we know the AES key. Also try HMAC verification.

Also: check AES(K, IV) = KNOWN[16:32] (known-plaintext from block 0 when PSK=zeros).
"""
import hashlib, hmac
try:
    from Crypto.Cipher import AES
except:
    from Cryptodome.Cipher import AES

KNOWN = bytes.fromhex(
    'ec35ae3abb45ed3f12c4751f1e5c2cc0'
    '5b3c5452e9104d9f2a3118644f37a04b'
    '6fd66b1d97cf80f1345f76c84f03ff30'
    'bb51bf308f2a9875c41e6592cd2a2f9e'
    '60809b17b5316037b69bb2fa5d4c8ac3'
    '1edb3394046ec06bbdacc57da6a756c5'
)
WB = bytes.fromhex(
    'ec35ae3abb45ed3f12c4751f1e5c2cc0'
    '18e97cc54fb96637a09dbde6bb87efc8'
    '73287db6593c428c01affa68935ee973'
    '686702617397334392cb3c194550d7cb'
    'b22655c67a57d9bfddee98554b6de56a'
    '47238ce1329d5e22b401634e58c208e1'
)

IV = WB[:16]  # same for KNOWN and WB
KNOWN_CT  = KNOWN[16:64]
KNOWN_TAG = KNOWN[64:96]
WB_CT     = WB[16:64]
WB_TAG    = WB[64:96]

# Known-plaintext: AES_enc(K, IV) = KNOWN_CT[0:16]
KNOWN_CT0 = KNOWN_CT[:16]  # = 5b3c5452e9104d9f2a3118644f37a04b

prefix = (32).to_bytes(4, 'little')
first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()
# var_4c8 at second SHA-256 = [IV:16 || zeros:48]
var_4c8_base = IV + bytes(48)

# Build obfuscated "Goodix" bytes
chars = [0x47, 0x6f, 0x6f, 0x64, 0x69, 0x78]
buf = []
r10, i = 1, 7
while i >= 0:
    for c in chars:
        buf.append(((c >> r10) | (c << i)) & 0xff)
    r10 += 2; i -= 2

def make_var_488_sha256_groups(buf, n=7, zero_msg_byte1=False):
    """SHA256(3_bytes)[:2] for each 3-byte group."""
    parts = []
    for j in range(0, n*3, 3):
        group = buf[j:j+3]
        if zero_msg_byte1:
            group = [group[0], 0x00, group[2]]  # middle byte is 0 (from decompile)
        parts.append(hashlib.sha256(bytes(group)).digest()[:2])
    return b''.join(parts) + bytes(16 - n*2)

# Additional var_488 candidates
var_488_candidates = {
    'zeros': bytes(16),
    'sha_groups_7': make_var_488_sha256_groups(buf, 7),
    'sha_groups_7_zeromid': make_var_488_sha256_groups(buf, 7, True),
    'sha_groups_5': make_var_488_sha256_groups(buf, 5),
    'sha_groups_8': make_var_488_sha256_groups(buf, 8),
    'sha256_allbuf': hashlib.sha256(bytes(buf)).digest()[:16],
    'sha256_allbuf_trunc': hashlib.sha256(bytes(buf[:21])).digest()[:16],
    'crc32_mpeg2': None,  # computed below
    'first_sha_upper': first_sha[16:32],  # second half of first_sha
}

# CRC32/MPEG-2
def crc32_mpeg2(data):
    poly = 0x04c11db7
    crc = 0xffffffff
    for b in data:
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ poly) & 0xffffffff
            else:
                crc = (crc << 1) & 0xffffffff
            if b & 0x80:
                crc ^= 1
            b = (b << 1) & 0xff
    return crc

crc = crc32_mpeg2(bytes(buf))
import struct
# Try putting CRC at various positions in var_488
var_488_candidates['crc32_mpeg2'] = struct.pack('>I', crc) + bytes(12)
var_488_candidates['crc32_at_12'] = bytes(12) + struct.pack('>H', (crc >> 16) & 0xffff) + bytes(2)
var_488_candidates['crc32_le'] = struct.pack('<I', crc) + bytes(12)

print(f'Testing {len(var_488_candidates)} var_488 candidates...\n')

found_any = False
for v488_name, v488 in var_488_candidates.items():
    if v488 is None:
        continue
    v488 = v488[:16]
    sha2_input = var_4c8_base + v488
    second_sha = hashlib.sha256(sha2_input).digest()
    key16 = second_sha[:16]
    key32 = second_sha

    # Check 1: AES_decrypt known PSK
    for key, klen in [(key16, 16), (key32, 32)]:
        if klen == 16:
            dec = AES.new(key, AES.MODE_CBC, IV).decrypt(KNOWN_CT)
        else:
            dec = AES.new(key, AES.MODE_CBC, IV).decrypt(KNOWN_CT)
        pad = dec[-1]
        ok_pkcs7 = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
        if ok_pkcs7:
            psk = dec[:-pad]
            zeros = all(b == 0 for b in psk)
            print(f'  *** AES-{klen*8} [{v488_name}] PKCS7 OK! PSK zeros={zeros}: {psk.hex()}')
            found_any = True

    # Check 2: HMAC verification (try different HMAC data)
    for hmac_key in [key16, key32]:
        for data_name, data in [
            ('CT', KNOWN_CT),
            ('IV+CT', IV + KNOWN_CT),
            ('PSK_zeros', bytes(32)),
        ]:
            tag = hmac.new(hmac_key, data, hashlib.sha256).digest()
            if tag == KNOWN_TAG:
                print(f'  *** HMAC match! [{v488_name}] key={hmac_key.hex()} data={data_name}')
                found_any = True

if not found_any:
    print('No match found with any candidate.')

# Additional: check if TAG = SHA256(second_sha || PSK) or similar
print('\n--- SHA256-based tag check ---')
for v488_name, v488 in var_488_candidates.items():
    if v488 is None:
        continue
    v488 = v488[:16]
    sha2_input = var_4c8_base + v488
    second_sha = hashlib.sha256(sha2_input).digest()
    for tag_data, tag_name in [
        (second_sha + bytes(32), 'sha2+PSK_zeros'),
        (bytes(32) + second_sha, 'PSK_zeros+sha2'),
        (KNOWN_CT + second_sha[:16], 'CT+key16'),
    ]:
        t = hashlib.sha256(tag_data).digest()
        if t == KNOWN_TAG:
            print(f'  *** TAG match! [{v488_name}] SHA256({tag_name})')
