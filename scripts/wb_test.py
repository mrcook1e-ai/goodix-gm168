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

# WB blob format (hypothesis): [IV:16][ciphertext:48][HMAC:32]
IV   = WB[:16]
CT   = WB[16:64]
TAG  = WB[64:]
print(f'IV   ({len(IV)}B): {IV.hex()}')
print(f'CT   ({len(CT)}B): {CT.hex()}')
print(f'TAG  ({len(TAG)}B): {TAG.hex()}')

# Key derivation from decompile
prefix = (32).to_bytes(4, 'little')   # arg2=32 as LE32
first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()
print(f'\nfirst_sha: {first_sha.hex()}')
assert first_sha[:16] == IV, "IV mismatch!"
print("IV MATCH confirmed: first_sha[:16] == WB[:16]")

second_sha = hashlib.sha256(first_sha + bytes(16)).digest()
AES_KEY = second_sha[:16]
print(f'second_sha: {second_sha.hex()}')
print(f'AES_KEY: {AES_KEY.hex()}')

# Try all key/IV combos
tests = [
    ('AES_KEY + first_sha_IV', AES_KEY, IV),
    ('simple_SHA256[:16] + first_sha_IV', hashlib.sha256(b'123GOODIX').digest()[:16], IV),
    ('first_sha[:16] + IV=zeros', first_sha[:16], bytes(16)),
    ('second_sha[:16] + IV=zeros', second_sha[:16], bytes(16)),
    ('first_sha[:16] + first_sha_IV', first_sha[:16], IV),
]

print()
for label, key, iv in tests:
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(CT)
    pad = dec[-1]
    ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
    if ok:
        psk = dec[:-pad]
        h = hashlib.sha256(psk[:32]).hexdigest()
        print(f'[OK] {label}: pad=0x{pad:02x} PSK={psk.hex()} sha256={h}')
    else:
        print(f'[--] {label}: pad=0x{pad:02x} BAD  dec[:16]={dec[:16].hex()}')
