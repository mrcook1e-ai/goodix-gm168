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

IV  = WB[:16]   # embedded IV (= first_sha[:15] + (first_sha[15] & 0xf0))
CT  = WB[16:64] # 48 bytes ciphertext
TAG = WB[64:]   # 32 bytes appended HMAC/tag

prefix = (32).to_bytes(4, 'little')  # arg2=32 LE
first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()
expected_iv = first_sha[:15] + bytes([first_sha[15] & 0xf0])
print(f'first_sha:    {first_sha.hex()}')
print(f'expected_IV:  {expected_iv.hex()}')
print(f'WB IV:        {IV.hex()}')
print(f'IV match:     {IV == expected_iv}')

# Second SHA-256 feeds: var_4c8 (64B) || var_488 (16B)
# var_4c8 after first finalize: first_sha[0:32] || zeros[32]
# var_488 from sub_1800036c0: most likely zeros
# So second_sha = SHA256(first_sha || zeros[48])

for label, input_bytes in [
    ('first_sha || zeros_16', first_sha + bytes(16)),
    ('first_sha || zeros_32', first_sha + bytes(32)),
    ('first_sha || zeros_48', first_sha + bytes(48)),
    ('first_sha || zeros_64', first_sha + bytes(64)),
]:
    sh2 = hashlib.sha256(input_bytes).digest()
    key = sh2[:16]
    dec = AES.new(key, AES.MODE_CBC, IV).decrypt(CT)
    pad = dec[-1]
    ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
    psk = dec[:-pad] if ok else dec[:32]
    status = 'OK!' if ok else 'bad'
    print(f'  {label}: key={key.hex()} pad=0x{pad:02x} {status} psk[:8]={psk[:8].hex()}')

# Also try: goodix-fp-dump has PSK_WHITE_BOX for chip 55a4
# If the WB blob for PSK=0x00*32 starts the same, we can verify the scheme
# by encrypting zeros and checking
print()
print('Verify: encrypt PSK=0x00*32 with confirmed scheme and compare with goodix-fp-dump')
KNOWN = bytes.fromhex(
    'ec35ae3abb45ed3f12c4751f1e5c2cc0'
    '5b3c5452e9104d9f2a3118644f37a04b'
    '6fd66b1d97cf80f1345f76c84f03ff30'
    'bb51bf308f2a9875c41e6592cd2a2f9e'
    '60809b17b5316037b69bb2fa5d4c8ac3'
    '1edb3394046ec06bbdacc57da6a756c5'
)
print(f'goodix-fp-dump blob: {KNOWN.hex()}')
print(f'Our WB blob:         {WB.hex()}')
print(f'Same IV block:       {WB[:16] == KNOWN[:16]}')
print(f'Differ at bytes 16+: {WB[16:32].hex()} vs {KNOWN[16:32].hex()}')
