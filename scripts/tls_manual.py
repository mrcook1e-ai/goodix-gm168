#!/usr/bin/env python3
"""
Manual TLS-PSK handshake with Goodix GM168SEC sensor.
Sends CCS and Finished SEPARATELY (not concatenated) to test if that fixes
the sensor non-response issue.
"""
import usb.core, usb.util, struct, hmac, hashlib, os, time, sys

VID, PID = 0x27c6, 0x589a
EP_OUT, EP_IN = 0x01, 0x83
PSK = bytes.fromhex('a12ba179ea7f00f6c70105b1d91dfe2e92d389053cb08603b63c4afba24a4c99')

def hmac_sha256(k, m):
    return hmac.new(k, m, hashlib.sha256).digest()

def prf(secret, label, seed, n):
    s = label + seed
    out, A = b'', s
    while len(out) < n:
        A = hmac_sha256(secret, A)
        out += hmac_sha256(secret, A + s)
    return out[:n]

from Crypto.Cipher import AES

def tls_mac(mac_key, rtype, seq, plaintext):
    hdr = struct.pack('>Q', seq) + bytes([rtype, 3, 3]) + struct.pack('>H', len(plaintext))
    return hmac.new(mac_key, hdr + plaintext, hashlib.sha256).digest()

def tls_encrypt(write_key, mac_key, seq, rtype, plaintext):
    mac = tls_mac(mac_key, rtype, seq, plaintext)
    body = plaintext + mac
    pad_len = 16 - (len(body) % 16)
    body += bytes([pad_len - 1]) * pad_len
    iv = os.urandom(16)
    ct = AES.new(write_key, AES.MODE_CBC, iv).encrypt(body)
    payload = iv + ct
    return bytes([rtype, 3, 3]) + struct.pack('>H', len(payload)) + payload

def tls_decrypt(write_key, mac_key, seq, rtype, record_payload):
    iv, ct = record_payload[:16], record_payload[16:]
    plain = AES.new(write_key, AES.MODE_CBC, iv).decrypt(ct)
    pad = plain[-1]
    plain = plain[:-(pad+1)]
    body, got_mac = plain[:-32], plain[-32:]
    exp_mac = tls_mac(mac_key, rtype, seq, body)
    if got_mac != exp_mac:
        raise ValueError(f"MAC fail: got {got_mac.hex()} exp {exp_mac.hex()}")
    return body

def encode_cmd(cmd, payload=b''):
    plen = len(payload) + 1
    inner_sz = 3 + len(payload) + 1
    hdr_sum = (0xA0 + (inner_sz & 0xFF) + ((inner_sz >> 8) & 0xFF)) & 0xFF
    s = cmd + (plen & 0xFF) + ((plen >> 8) & 0xFF) + sum(payload)
    body_sum = (0xAA - s) & 0xFF
    return bytes([0xA0, inner_sz & 0xFF, (inner_sz >> 8) & 0xFF, hdr_sum,
                  cmd, plen & 0xFF, (plen >> 8) & 0xFF]) + bytes(payload) + bytes([body_sum])

def wrap_b0(tls_data):
    n = len(tls_data)
    hdr_sum = (0xB0 + (n & 0xFF) + ((n >> 8) & 0xFF)) & 0xFF
    return bytes([0xB0, n & 0xFF, (n >> 8) & 0xFF, hdr_sum]) + tls_data

def usb_send(dev, data, label='TX'):
    n = dev.write(EP_OUT, data, 3000)
    print(f"  {label} {n}B: {data[:24].hex()}")

def usb_recv(dev, label='RX', timeout=3000):
    try:
        data = bytes(dev.read(EP_IN, 16*1024, timeout))
        print(f"  {label} {len(data)}B: {data[:32].hex()}")
        return data
    except usb.core.USBTimeoutError:
        print(f"  {label} TIMEOUT")
        return None

def flush(dev):
    for _ in range(10):
        try: dev.read(EP_IN, 16*1024, 200)
        except: break

dev = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None:
    sys.exit("[!] device not found")
for iface in range(2):
    try:
        if dev.is_kernel_driver_active(iface):
            dev.detach_kernel_driver(iface)
    except: pass
try: dev.set_configuration()
except: pass
flush(dev)

print("=== STEP 1: RESET + VERSION + TLS_START ===")
usb_send(dev, encode_cmd(0x60, b'\x01\x00'), 'RESET')
usb_recv(dev, 'RESET_ACK')
usb_send(dev, encode_cmd(0x20), 'VERSION')
usb_recv(dev, 'VERSION_ACK')
usb_send(dev, encode_cmd(0xD0, b'\x00\x00'), 'TLS_START')
usb_recv(dev, 'TLS_START_ACK')

print("\n=== STEP 2: Receive ClientHello ===")
tls_buf = b''
for _ in range(10):
    d = usb_recv(dev, 'DATA', timeout=3000)
    if d is None: break
    if d[0] == 0xB0:
        b0_len = d[1] | (d[2] << 8)
        tls_buf += d[4:4+b0_len]
    if len(tls_buf) >= 5:
        rec_len = (tls_buf[3] << 8) | tls_buf[4]
        if len(tls_buf) >= 5 + rec_len:
            break

print(f"  CH TLS record ({len(tls_buf)}B): {tls_buf[:20].hex()}")
if not tls_buf or tls_buf[0] != 0x16 or tls_buf[5] != 0x01:
    sys.exit("[!] no ClientHello")

rec_len = (tls_buf[3] << 8) | tls_buf[4]
ch_body = tls_buf[5:5+rec_len]
client_random = ch_body[6:38]
print(f"  client_random: {client_random.hex()}")
transcript = bytes(ch_body)

print("\n=== STEP 3: Send ServerHello + ServerHelloDone ===")
server_random = os.urandom(32)
print(f"  server_random: {server_random.hex()}")

sh_body = bytes([0x03, 0x03]) + server_random + b'\x00\x00\xae\x00'
sh_hs   = bytes([0x02, 0x00, 0x00, len(sh_body)]) + sh_body
sh_rec  = bytes([0x16, 0x03, 0x03]) + struct.pack('>H', len(sh_hs)) + sh_hs
transcript += sh_hs

shd_hs  = bytes([0x0e, 0x00, 0x00, 0x00])
shd_rec = bytes([0x16, 0x03, 0x03, 0x00, 0x04]) + shd_hs
transcript += shd_hs

usb_send(dev, wrap_b0(sh_rec + shd_rec), 'SH+SHD')

print("\n=== STEP 4: Receive CKE + CCS + ClientFinished ===")
tls_buf2 = b''
for _ in range(15):
    d = usb_recv(dev, 'HANDSHAKE', timeout=3000)
    if d is None: break
    if d[0] == 0xB0:
        b0_len = d[1] | (d[2] << 8)
        tls_buf2 += d[4:4+b0_len]
    elif d[0] == 0xA0:
        continue
    # Try to have CKE (0x10) + CCS (0x14) + Finished (0x16)
    if len(tls_buf2) > 60:
        # Parse to check if we have all three
        pos2 = 0
        records = []
        while pos2 + 5 <= len(tls_buf2):
            rtype = tls_buf2[pos2]
            rlen = (tls_buf2[pos2+3] << 8) | tls_buf2[pos2+4]
            if pos2 + 5 + rlen > len(tls_buf2):
                break
            records.append(rtype)
            pos2 += 5 + rlen
        # CKE=0x16, CCS=0x14, Finished=0x16 (encrypted)
        if 0x14 in records:
            break

print(f"  received {len(tls_buf2)}B: {tls_buf2[:16].hex()}")

# Parse CKE
pos = 0
cke_rec_len = (tls_buf2[pos+3] << 8) | tls_buf2[pos+4]
cke_hs = tls_buf2[5:5+cke_rec_len]
transcript += cke_hs
print(f"  CKE hs ({len(cke_hs)}B): {cke_hs[:8].hex()}")
pos = 5 + cke_rec_len

# Parse CCS
ccs_len = (tls_buf2[pos+3] << 8) | tls_buf2[pos+4]
print(f"  CCS: {tls_buf2[pos:pos+6].hex()}")
pos += 5 + ccs_len

# Derive keys
psk_len = len(PSK)
pms = struct.pack('>H', psk_len) + b'\x00'*psk_len + struct.pack('>H', psk_len) + PSK
ms = prf(pms, b'master secret', client_random + server_random, 48)
kb = prf(ms, b'key expansion', server_random + client_random, 96)
cwmk, swmk = kb[0:32], kb[32:64]
cwk, swk   = kb[64:80], kb[80:96]
print(f"  master_secret[:8]: {ms[:8].hex()}")
print(f"  client_write_key: {cwk.hex()}")
print(f"  server_write_key: {swk.hex()}")

# Parse ClientFinished
fin_rec_len = (tls_buf2[pos+3] << 8) | tls_buf2[pos+4]
fin_payload = tls_buf2[pos+5:pos+5+fin_rec_len]
print(f"  ClientFinished encrypted ({len(fin_payload)}B): {fin_payload[:16].hex()}")
try:
    fin_plain = tls_decrypt(cwk, cwmk, 0, 0x16, fin_payload)
    print(f"  ClientFinished decrypted: {fin_plain.hex()}")
    digest = hashlib.sha256(transcript).digest()
    expected_cf = prf(ms, b'client finished', digest, 12)
    got_cf = fin_plain[4:]
    print(f"  CF expected: {expected_cf.hex()}")
    print(f"  CF got:      {got_cf.hex()}")
    print(f"  CF MATCH: {'YES' if expected_cf == got_cf else 'NO'}")
except Exception as e:
    print(f"  ClientFinished decrypt FAILED: {e}")
    sys.exit(1)

transcript += fin_plain

print("\n=== STEP 5: Send ServerCCS SEPARATELY, then ServerFinished ===")
digest_sv = hashlib.sha256(transcript).digest()
sf_vd = prf(ms, b'server finished', digest_sv, 12)
print(f"  SF verify_data: {sf_vd.hex()}")

sf_plain = bytes([0x14, 0x00, 0x00, 0x0c]) + sf_vd
sf_enc = tls_encrypt(swk, swmk, 0, 0x16, sf_plain)

ccs_out = bytes([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])

# Send CCS alone first
usb_send(dev, wrap_b0(ccs_out), 'SERVER_CCS')
time.sleep(0.1)

# Then send Finished separately
usb_send(dev, wrap_b0(sf_enc), 'SERVER_FINISHED')
time.sleep(0.3)

print("\n=== STEP 6: Check for any sensor response ===")
for i in range(5):
    d = usb_recv(dev, f'POST_HS_{i}', timeout=1000)
    if d is None: break

print("\n=== STEP 7: Send TLS-encrypted SESSION_INIT (0x60) ===")
session_a0 = encode_cmd(0x60, b'\x01\x00')
session_tls = tls_encrypt(swk, swmk, 1, 0x17, session_a0)
print(f"  SESSION_INIT A0: {session_a0.hex()}")
usb_send(dev, wrap_b0(session_tls), 'SESSION_INIT')

print("\n=== STEP 8: Wait for TLS-encrypted ACK ===")
server_recv_seq = 0
for i in range(10):
    d = usb_recv(dev, f'RESP_{i}', timeout=2000)
    if d is None:
        print("  [TIMEOUT - sensor not responding]")
        break
    if d[0] == 0xB0:
        b0_len = d[1] | (d[2] << 8)
        tls_data = d[4:4+b0_len]
        print(f"  [B0 TLS {len(tls_data)}B type=0x{tls_data[0]:02x}]: {tls_data[:16].hex()}")
        if tls_data[0] == 0x17:  # AppData
            try:
                plain = tls_decrypt(cwk, cwmk, server_recv_seq, 0x17, tls_data[5:])
                print(f"  [DECRYPTED AppData]: {plain.hex()}")
                server_recv_seq += 1
            except Exception as e:
                print(f"  [decrypt fail]: {e}")
        elif tls_data[0] == 0x15:  # Alert
            print(f"  [TLS ALERT]: level={tls_data[5]} desc={tls_data[6]}")
    elif d[0] == 0xA0:
        print(f"  [A0 ACK]: {d[:10].hex()}")

usb.util.dispose_resources(dev)
print("\nDone.")
