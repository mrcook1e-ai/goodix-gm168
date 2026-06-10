"""
Try AES-256 and various second-SHA inputs.
sub_180002500 takes 0x20=32 as length => possibly AES-256 (256-bit key = 32 bytes).
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

# goodix-fp-dump PSK_WHITE_BOX (PSK=0x00*32, chip 55a4)
# If this is a valid reference, decrypting it should give PSK=0x00*32
KNOWN = bytes.fromhex(
    'ec35ae3abb45ed3f12c4751f1e5c2cc0'
    '5b3c5452e9104d9f2a3118644f37a04b'
    '6fd66b1d97cf80f1345f76c84f03ff30'
    'bb51bf308f2a9875c41e6592cd2a2f9e'
    '60809b17b5316037b69bb2fa5d4c8ac3'
    '1edb3394046ec06bbdacc57da6a756c5'
)

IV = WB[:16]  # = KNOWN[:16], confirmed
prefix = (32).to_bytes(4, 'little')
first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()

def try_key(label, key_bytes, iv, blob):
    CT = blob[16:16 + (48 if len(blob) == 96 else 48)]
    try:
        if len(key_bytes) == 16:
            dec = AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(CT)
        elif len(key_bytes) == 32:
            dec = AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(CT)
        else:
            print(f'  [{label}] bad key len {len(key_bytes)}')
            return
    except Exception as e:
        print(f'  [{label}] error: {e}')
        return
    pad = dec[-1]
    ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
    psk = dec[:-pad] if ok else dec[:32]
    status = 'OK!' if ok else 'bad'
    print(f'  [{label}] key={key_bytes[:8].hex()}... pad=0x{pad:02x} {status} psk[:8]={psk[:8].hex()}')
    if ok and all(b == 0 for b in psk):
        print(f'    => PSK is ALL ZEROS (matches goodix-fp-dump)')
    return psk if ok else None

print('=== Testing with goodix-fp-dump blob (PSK should be 0x00*32) ===')
# Try AES-256 with second_sha (all 32 bytes)
for extra in [0, 16, 32, 48]:
    sh2 = hashlib.sha256(first_sha + bytes(extra)).digest()
    try_key(f'AES-256 SHA256(fsha||z{extra})', sh2, IV, KNOWN)

# Try AES-128
for extra in [0, 16, 32, 48]:
    sh2 = hashlib.sha256(first_sha + bytes(extra)).digest()[:16]
    try_key(f'AES-128 SHA256(fsha||z{extra})[:16]', sh2, IV, KNOWN)

print()
print('=== Testing with our captured blob ===')
for extra in [0, 16, 32, 48]:
    sh2 = hashlib.sha256(first_sha + bytes(extra)).digest()
    try_key(f'AES-256 SHA256(fsha||z{extra})', sh2, IV, WB)
    try_key(f'AES-128 SHA256(fsha||z{extra})[:16]', sh2[:16], IV, WB)

# Also try: what if second SHA-256 feeds only first_sha (32 bytes), no extra zeros?
print()
print('=== Extra: AES-256/128 with just first_sha as key ===')
try_key('AES-128 first_sha[:16]', first_sha[:16], IV, KNOWN)
try_key('AES-256 first_sha', first_sha, IV, KNOWN)
try_key('AES-128 first_sha[:16]', first_sha[:16], IV, WB)
try_key('AES-256 first_sha', first_sha, IV, WB)
