"""
Декодирование PSK write фреймов из pcapng.
Собирает multi-chunk Goodix transfers и декодирует TLV.
"""
import struct, hashlib
from Crypto.Cipher import AES

PCAP = r"C:\Users\mrcook1e\Documents\goodix-gm168\captures\goodix_full.pcapng"
HDR = 64

TLV_TAGS = {
    0xBB010001:'PSK_plain',  0xBB010002:'PSK_DPAPI',
    0xBB010003:'PSK_WB',     0xBB020001:'PSK_SHA256',
}

def read_pcapng(path):
    with open(path,'rb') as f: data=f.read()
    pos,n=0,0
    while pos+8<=len(data):
        bt=struct.unpack_from('<I',data,pos)[0]
        bl=struct.unpack_from('<I',data,pos+4)[0]
        if bl<12 or pos+bl>len(data): break
        body=data[pos+8:pos+bl-4]
        if bt==0x00000006:
            caplen=struct.unpack_from('<I',body,12)[0]
            n+=1
            yield n,body[20:20+caplen]
        pos+=bl

def collect_out(frames, start, end):
    result = b''
    for n,raw in frames:
        if n < start or n > end: continue
        if len(raw) < HDR: continue
        if raw[8] != 0x53: continue   # Submit
        if raw[9] != 0x03: continue   # bulk
        if raw[10] & 0x80: continue   # OUT
        if raw[15] != 0: continue     # has data
        cap = struct.unpack_from('<I', raw, 36)[0]
        if cap > 0:
            result += raw[HDR:HDR+cap]
    return result

def find_tlv_le(data):
    results = []
    for offset in range(len(data)-8):
        raw_tag = struct.unpack_from('<I', data, offset)[0]
        if raw_tag in TLV_TAGS:
            length = struct.unpack_from('<I', data, offset+4)[0]
            if 0 < length < 8192 and offset+8+length <= len(data):
                val = data[offset+8:offset+8+length]
                results.append((offset, raw_tag, TLV_TAGS[raw_tag], length, val))
    return results

frames = list(read_pcapng(PCAP))

g1 = collect_out(frames, 520, 529)
g2 = collect_out(frames, 534, 541)

print("=" * 70)
print(f"G1 (frames 520-528): {len(g1)}B")
hdr1 = struct.unpack_from('<H', g1, 1)[0]
print(f"  flags=0x{g1[0]:02x}  len={hdr1}  cmd=0x{g1[3]:02x}  data[0]=0x{g1[4]:02x}")

print(f"\nG2 (frames 534-540): {len(g2)}B")
hdr2 = struct.unpack_from('<H', g2, 1)[0]
print(f"  flags=0x{g2[0]:02x}  len={hdr2}  cmd=0x{g2[3]:02x}  data[0]=0x{g2[4]:02x}")

print("\n=== TLV в G1 (DPAPI blob) ===")
for off,tag,name,length,val in find_tlv_le(g1):
    print(f"  @{off:3d}: {name} ({tag:#010x})[{length}B]")
    if name == 'PSK_DPAPI':
        # Ищем DPAPI magic
        dpapi_magic = bytes.fromhex('d08c9ddf0115d1118c7a00c04fc297eb')
        mi = val.find(dpapi_magic)
        if mi >= 0:
            print(f"         DPAPI magic @ val+{mi}")
        # Ищем UTF-16 строку
        try:
            s = val.decode('utf-16-le', errors='ignore').split('\x00')[0]
            if s: print(f"         description: '{s}'")
        except: pass

print("\n=== TLV в G2 (WB blob) ===")
for off,tag,name,length,val in find_tlv_le(g2):
    print(f"  @{off:3d}: {name} ({tag:#010x})[{length}B]")
    if name == 'PSK_WB' and length == 96:
        blob_iv = val[:16]
        blob_ct = val[16:64]
        blob_mac= val[64:96]
        print(f"    WB_IV  = {blob_iv.hex()}")
        print(f"    WB_CT  = {blob_ct.hex()}")
        print(f"    WB_MAC = {blob_mac.hex()}")

# Верификация PSK
print("\n=== Верификация PSK ===")
var_488 = bytes.fromhex('5cba6e25819518de2d53e96dc0347ab0')
prefix = (32).to_bytes(4,'little')
fs = hashlib.sha256(prefix + b'123GOODIX').digest()
iv  = fs[:15] + bytes([fs[15] & 0xf0])
ss  = hashlib.sha256(iv + bytes(48) + var_488).digest()
AES_KEY = ss[:16]
print(f"  AES_KEY = {AES_KEY.hex()}")

for off,tag,name,length,val in find_tlv_le(g2):
    if name == 'PSK_WB' and length == 96:
        try:
            dec = AES.new(AES_KEY, AES.MODE_CBC, val[:16]).decrypt(val[16:64])
            pad = dec[-1]
            psk = dec[:-pad]
            print(f"  PSK     = {psk.hex()}  ({len(psk)}B) [DECRYPTED OK]")
            expected = 'a12ba179ea7f00f6c70105b1d91dfe2e92d389053cb08603b63c4afba24a4c99'
            print(f"  match   = {'OK' if psk.hex() == expected else 'FAIL'}")
        except Exception as e:
            print(f"  DECRYPT FAIL: {e}")

print("\n=== Cmd коды (новые данные) ===")
print(f"  cmd 0xb1 -> PSK write DPAPI  (BB010002, {len(g1)}B transfer)")
print(f"  cmd 0x6e -> PSK write WB     (BB010003, {len(g2)}B transfer)")
print(f"  cmd 0xb4 -> McuGetPsk (ранее определен)")
