"""
Reconstruct var_488 from sub_1800036c0 decompile:
- sub_1800031f0/sub_1800032f0: SHA-256(3 bytes)[:2] for each 3-byte group of obfuscated "Goodix"
- sub_180003510: similar for last group
- Then CRC bytes at [12:14]
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
KNOWN = bytes.fromhex(  # goodix-fp-dump PSK_WHITE_BOX, PSK=0x00*32
    'ec35ae3abb45ed3f12c4751f1e5c2cc0'
    '5b3c5452e9104d9f2a3118644f37a04b'
    '6fd66b1d97cf80f1345f76c84f03ff30'
    'bb51bf308f2a9875c41e6592cd2a2f9e'
    '60809b17b5316037b69bb2fa5d4c8ac3'
    '1edb3394046ec06bbdacc57da6a756c5'
)

IV = WB[:16]
prefix = (32).to_bytes(4, 'little')
first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()

# Build obfuscated "Goodix" bytes (24 bytes, 4 rotations × 6 chars)
chars = [0x47, 0x6f, 0x6f, 0x64, 0x69, 0x78]  # G,o,o,d,i,x
buf = []
r10, i = 1, 7
while i >= 0:
    for c in chars:
        buf.append(((c >> r10) | (c << i)) & 0xff)
    r10 += 2; i -= 2
print(f'Obfuscated "Goodix" bytes ({len(buf)}B): {bytes(buf).hex()}')

# Group into 3-byte chunks:
# sub_1800031f0 does: SHA256(buf[0:3])[:2] → var_488[0:2]
# sub_1800032f0 ×4: SHA256(buf[i*3+3: i*3+6])[:2] → var_488[(i+1)*2: (i+1)*2+2]
# sub_180003510: SHA256(buf[18:21?])[:2] → var_488[10:12]
# Then CRC at [12:14]

# var_488 construction (best guess from decompile):
def sha2bytes(b3):
    return hashlib.sha256(bytes(b3)).digest()[:2]

# Groups: [0:3], [3:6], [6:9], [9:12], [12:15], [15:18], [18:21]
# sub_1800031f0: group 0 → var_488[0:2]
# sub_1800032f0 ×4: groups 1-4 → var_488[2:10]
# sub_180003510: group 5 → var_488[10:12]  (or 2 bytes of CRC)
# CRC: var_488[12:14]

# Try: var_488 = concat of SHA256(each 3-byte group)[:2] for groups 0..6
var_488_parts = [sha2bytes(buf[i:i+3]) for i in range(0, 24, 3)]
print('\n3-byte groups and their SHA256[:2]:')
for i, (g, p) in enumerate(zip([buf[j:j+3] for j in range(0, 24, 3)], var_488_parts)):
    print(f'  group {i}: {bytes(g).hex()} → SHA256[:2] = {p.hex()}')

# Try different lengths of var_488 (6, 7, 8 groups)
for n_groups in [5, 6, 7, 8]:
    var_488 = b''.join(var_488_parts[:n_groups]) + bytes(16 - n_groups*2)
    var_488 = var_488[:16]
    print(f'\n[n={n_groups}] var_488 = {var_488.hex()}')

    for extra in [0, 16, 32, 48]:
        second_sha = hashlib.sha256(first_sha + bytes(extra - 16 if extra >= 16 else 0) + var_488[:16 if extra == 0 else extra]).digest()
        # Actually: feed first_sha (32B) || zeros (32B from var_4c8[32:64]) || var_488 (16B)
        second_sha = hashlib.sha256(first_sha + bytes(32) + var_488).digest()
        key16 = second_sha[:16]
        key32 = second_sha

        for blob, label in [(KNOWN, 'KNOWN'), (WB, 'WB')]:
            ct = blob[16:64]
            for k, kl in [(key16, '128'), (key32, '256')]:
                dec = AES.new(k, AES.MODE_CBC, IV).decrypt(ct)
                pad = dec[-1]
                ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
                if ok:
                    psk = dec[:-pad]
                    is_zeros = all(b == 0 for b in psk)
                    print(f'  *** AES-{kl} n={n_groups} extra_zeros=32 BLOB={label}: pad OK psk={psk.hex()} zeros={is_zeros}')

# Most likely formula: second_sha = SHA256(first_sha || zeros_32B || var_488_16B)
print('\n=== Systematic search: first_sha || zeros_32B || var_488 ===')
for n_groups in range(1, 9):
    var_488 = b''.join(var_488_parts[:n_groups]) + bytes(16 - n_groups*2)
    var_488 = var_488[:16]
    second_sha = hashlib.sha256(first_sha + bytes(32) + var_488).digest()
    key16 = second_sha[:16]

    for blob, label in [(KNOWN, 'KNOWN'), (WB, 'WB')]:
        ct = blob[16:64]
        dec = AES.new(key16, AES.MODE_CBC, IV).decrypt(ct)
        pad = dec[-1]
        ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
        psk = dec[:-pad] if ok else dec
        zeros = label == 'KNOWN' and ok and all(b == 0 for b in psk)
        if ok:
            print(f'  n={n_groups} {label}: pad={pad:02x} OK psk[:8]={psk[:8].hex()} zeros={zeros}')
        elif label == 'KNOWN':
            print(f'  n={n_groups} {label}: pad=0x{pad:02x} bad')
