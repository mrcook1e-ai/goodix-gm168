#!/usr/bin/env python3
"""Test sensor response after TLS - with 3s wait and plaintext fallback test."""
import usb.core, usb.util, struct, hmac, hashlib, os, time, sys
from Crypto.Cipher import AES

VID, PID = 0x27c6, 0x589a
EP_OUT, EP_IN = 0x01, 0x83
PSK = bytes.fromhex('a12ba179ea7f00f6c70105b1d91dfe2e92d389053cb08603b63c4afba24a4c99')

def hmac_sha256(k, m): return hmac.new(k, m, hashlib.sha256).digest()
def prf(secret, label, seed, n):
    s = label + seed; out, A = b'', s
    while len(out) < n: A = hmac_sha256(secret, A); out += hmac_sha256(secret, A + s)
    return out[:n]
def tls_mac(mk, rt, seq, pt):
    return hmac_sha256(mk, struct.pack('>Q', seq) + bytes([rt, 3, 3]) + struct.pack('>H', len(pt)) + pt)
def tls_encrypt(wk, mk, seq, rt, pt):
    mac = tls_mac(mk, rt, seq, pt); body = pt + mac
    pad = 16 - (len(body) % 16); body += bytes([pad-1])*pad
    iv = os.urandom(16); ct = AES.new(wk, AES.MODE_CBC, iv).encrypt(body)
    payload = iv + ct; return bytes([rt, 3, 3]) + struct.pack('>H', len(payload)) + payload
def encode_cmd(cmd, payload=b''):
    plen = len(payload)+1; inner_sz = 3+len(payload)+1
    hs = (0xA0+(inner_sz&0xFF)+((inner_sz>>8)&0xFF))&0xFF
    s = cmd+(plen&0xFF)+((plen>>8)&0xFF)+sum(payload); bs = (0xAA-s)&0xFF
    return bytes([0xA0,inner_sz&0xFF,(inner_sz>>8)&0xFF,hs,cmd,plen&0xFF,(plen>>8)&0xFF])+bytes(payload)+bytes([bs])
def wrap_b0(d):
    n=len(d); hs=(0xB0+(n&0xFF)+((n>>8)&0xFF))&0xFF; return bytes([0xB0,n&0xFF,(n>>8)&0xFF,hs])+d

dev = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None: sys.exit("[!] device not found")
for iface in range(2):
    try:
        if dev.is_kernel_driver_active(iface): dev.detach_kernel_driver(iface)
    except: pass
try: dev.set_configuration()
except: pass
for _ in range(5):
    try: dev.read(EP_IN, 16384, 200)
    except: break

dev.write(EP_OUT, encode_cmd(0x60, b'\x01\x00'), 3000)
try: dev.read(EP_IN, 16384, 500)
except: pass
dev.write(EP_OUT, encode_cmd(0x20), 3000)
try: dev.read(EP_IN, 16384, 500)
except: pass
dev.write(EP_OUT, encode_cmd(0xD0, b'\x00\x00'), 3000)
try: dev.read(EP_IN, 16384, 500)
except: pass

# Collect CH
buf=b''
for _ in range(10):
    try: d=bytes(dev.read(EP_IN,16384,3000))
    except: break
    if d[0]==0xB0: buf+=d[4:4+(d[1]|(d[2]<<8))]
    if len(buf)>=5 and len(buf)>=5+((buf[3]<<8)|buf[4]): break
cr=buf[11:43]; transcript=buf[5:5+((buf[3]<<8)|buf[4])]
print(f'CR: {cr.hex()}')

# SH+SHD
sr=os.urandom(32)
sh_hs=bytes([0x02,0x00,0x00,38,0x03,0x03])+sr+b'\x00\x00\xae\x00'
shd_hs=bytes([0x0e,0x00,0x00,0x00])
transcript+=sh_hs+shd_hs
dev.write(EP_OUT, wrap_b0(bytes([0x16,0x03,0x03,0x00,42])+sh_hs+bytes([0x16,0x03,0x03,0x00,4])+shd_hs), 3000)

# CKE+CCS+CF
buf2=b''
for _ in range(15):
    try: d=bytes(dev.read(EP_IN,16384,2000))
    except: break
    if d[0]==0xB0: buf2+=d[4:4+(d[1]|(d[2]<<8))]
    if 0x14 in buf2: break

p=0; rl=(buf2[p+3]<<8)|buf2[p+4]; cke_hs=buf2[5:5+rl]; transcript+=cke_hs; p+=5+rl
rl2=(buf2[p+3]<<8)|buf2[p+4]; p+=5+rl2  # CCS
psk_len=32; pms=struct.pack('>H',psk_len)+b'\x00'*psk_len+struct.pack('>H',psk_len)+PSK
ms=prf(pms,b'master secret',cr+sr,48); kb=prf(ms,b'key expansion',sr+cr,96)
cwmk,swmk,cwk,swk=kb[:32],kb[32:64],kb[64:80],kb[80:96]
rl3=(buf2[p+3]<<8)|buf2[p+4]; fin_pay=buf2[p+5:p+5+rl3]
plain=AES.new(cwk,AES.MODE_CBC,fin_pay[:16]).decrypt(fin_pay[16:])
pad=plain[-1]; plain=plain[:-(pad+1)]; plain=plain[:-32]
transcript+=plain

# SF
dg=hashlib.sha256(transcript).digest(); sf_vd=prf(ms,b'server finished',dg,12)
sf_enc=tls_encrypt(swk,swmk,0,0x16,bytes([0x14,0x00,0x00,0x0c])+sf_vd)
ccs_bytes=bytes([0x14,0x03,0x03,0x00,0x01,0x01])

print(f'SF vd: {sf_vd.hex()}')
print(f'server_write_key: {swk.hex()}')
print(f'server_write_mac_key: {swmk.hex()}')

# Send CCS separately, then wait, then Finished
dev.write(EP_OUT, wrap_b0(ccs_bytes), 3000)
time.sleep(0.2)
dev.write(EP_OUT, wrap_b0(sf_enc), 3000)
print('Waiting 3s for ANYTHING from sensor after SF...')
for _ in range(6):
    try:
        d=bytes(dev.read(EP_IN,16384,500))
        print(f'  GOT: {len(d)}B {d[:24].hex()}')
    except: print('  [timeout 500ms]')

# Try plaintext 0x60 to see if sensor still responds to plaintext
print('Trying PLAINTEXT 0x60 after TLS handshake...')
dev.write(EP_OUT, encode_cmd(0x60, b'\x01\x00'), 3000)
for _ in range(3):
    try: d=bytes(dev.read(EP_IN,16384,1000)); print(f'  RESP: {d[:16].hex()}')
    except: print('  [timeout]')

# Try sending wrong MAC (corrupted) TLS app data - see if we get an alert
print('Sending CORRUPTED TLS app data (to provoke alert)...')
corrupted = tls_encrypt(swk,swmk,1,0x17,encode_cmd(0x60, b'\x01\x00'))
corrupted = corrupted[:20] + bytes([corrupted[20] ^ 0xFF]) + corrupted[21:]
dev.write(EP_OUT, wrap_b0(corrupted), 3000)
for _ in range(3):
    try: d=bytes(dev.read(EP_IN,16384,1000)); print(f'  CORRUPT_RESP: {d[:24].hex()}')
    except: print('  [timeout]')

usb.util.dispose_resources(dev)
print("Done.")
