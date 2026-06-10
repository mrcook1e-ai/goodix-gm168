#!/usr/bin/env python3
"""
Анализ USB-дампа Windows Goodix сессии (USBPcap linktype=249).
Разбирает IN+OUT bulk пакеты, декодирует Goodix A0/B0 фреймы,
расшифровывает TLS используя известный PSK.

USBPcap header (27 bytes, little-endian, no padding):
  0:  USHORT  headerLen    (обычно 27 для bulk)
  2:  UINT64  irpId
  10: UINT32  status
  14: USHORT  function
  16: UCHAR   info         (bit0: 0=OUT/request, 1=IN/response)
  17: USHORT  bus
  19: USHORT  device
  21: UCHAR   endpoint     (bit7: 0=OUT, 1=IN)
  22: UCHAR   transfer     (3=bulk)
  23: UINT32  dataLength
  27: [data]
"""
import struct, hmac, hashlib, sys, os
from Crypto.Cipher import AES

PCAP = r"C:\Users\mrcook1e\Documents\goodix-gm168\captures\goodix_win.pcapng"
PSK  = bytes.fromhex('a12ba179ea7f00f6c70105b1d91dfe2e92d389053cb08603b63c4afba24a4c99')

# ── pcapng reader ─────────────────────────────────────────────────────────────

def read_pcapng(path):
    """Читает pcapng, возвращает (linktype, [raw_packet_bytes])."""
    with open(path, 'rb') as f:
        data = f.read()
    linktype = None
    packets = []
    pos = 0
    while pos + 8 <= len(data):
        bt = struct.unpack_from('<I', data, pos)[0]
        bl = struct.unpack_from('<I', data, pos + 4)[0]
        if bl < 12 or pos + bl > len(data):
            break
        body = data[pos + 8: pos + bl - 4]

        if bt == 0x00000001:   # IDB — Interface Description Block
            lt = struct.unpack_from('<H', body, 0)[0]
            if linktype is None:
                linktype = lt
        elif bt == 0x00000006: # EPB — Enhanced Packet Block
            caplen  = struct.unpack_from('<I', body, 12)[0]
            packets.append(body[20: 20 + caplen])

        pos += bl
    return linktype, packets

# ── USBPcap packet parser (linktype 249) ──────────────────────────────────────

def parse_usbpcap(raw):
    if len(raw) < 27:
        return None
    hdr_len    = struct.unpack_from('<H', raw, 0)[0]
    status     = struct.unpack_from('<I', raw, 10)[0]
    info       = raw[16]
    endpoint   = raw[21]
    transfer   = raw[22]
    data_len   = struct.unpack_from('<I', raw, 23)[0]
    direction  = 'IN' if (endpoint & 0x80) else 'OUT'
    payload    = raw[hdr_len: hdr_len + data_len]
    return {
        'dir': direction,
        'transfer': transfer,
        'status': status,
        'endpoint': endpoint,
        'data': payload,
    }

# ── Linux usbmon packet parser (linktype 220) ─────────────────────────────────

def parse_usbmon(raw):
    HDR = 64
    if len(raw) < HDR:
        return None
    ep      = raw[10]
    xfer    = raw[9]
    ptype   = chr(raw[8])
    status  = struct.unpack_from('<i', raw, 28)[0]
    caplen  = struct.unpack_from('<I', raw, 36)[0]
    data    = raw[HDR: HDR + caplen] if caplen > 0 else b''
    direction = 'IN' if (ep & 0x80) else 'OUT'
    # только данные из submit (OUT) или complete (IN)
    if direction == 'OUT' and ptype != 'S':
        return None
    if direction == 'IN' and ptype != 'C':
        return None
    return {
        'dir': direction,
        'transfer': xfer,
        'status': status,
        'endpoint': ep,
        'data': data,
    }

# ── Goodix frame reassembly ───────────────────────────────────────────────────

def reassemble(packets):
    """Собирает Goodix-фреймы из потока USB bulk пакетов."""
    bufs = {'IN': b'', 'OUT': b''}
    frames = []

    def try_extract(d):
        while len(bufs[d]) >= 4:
            h = bufs[d]
            if h[0] not in (0xA0, 0xB0):
                bufs[d] = h[1:]
                continue
            inner = h[1] | (h[2] << 8)
            need  = 4 + inner
            if len(h) < need:
                break
            frames.append((d, bytes(h[:need])))
            bufs[d] = h[need:]

    for p in packets:
        if p is None or p['transfer'] != 3 or not p['data']:
            continue
        if p['status'] != 0:
            continue
        d = p['dir']
        bufs[d] += p['data']
        try_extract(d)

    return frames

# ── TLS crypto ────────────────────────────────────────────────────────────────

def hmac_sha256(k, m):
    return hmac.new(k, m, hashlib.sha256).digest()

def prf(secret, label, seed, n):
    s = label + seed
    out, A = b'', s
    while len(out) < n:
        A = hmac_sha256(secret, A)
        out += hmac_sha256(secret, A + s)
    return out[:n]

def derive_keys(cr, sr):
    psk_len = len(PSK)
    pms = struct.pack('>H', psk_len) + b'\x00'*psk_len + struct.pack('>H', psk_len) + PSK
    ms  = prf(pms, b'master secret', cr + sr, 48)
    kb  = prf(ms,  b'key expansion', sr + cr, 96)
    return ms, kb[:32], kb[32:64], kb[64:80], kb[80:96]  # ms,cwmk,swmk,cwk,swk

def tls_decrypt(write_key, mac_key, seq, rtype, payload):
    if len(payload) < 32:
        return None, "short"
    iv, ct = payload[:16], payload[16:]
    try:
        plain = AES.new(write_key, AES.MODE_CBC, iv).decrypt(ct)
    except Exception as e:
        return None, str(e)
    pad = plain[-1]
    if pad >= len(plain):
        return None, f"bad_pad={pad}"
    plain = plain[:-(pad + 1)]
    if len(plain) < 32:
        return None, "short_unpad"
    body, got_mac = plain[:-32], plain[-32:]
    exp_mac = hmac_sha256(mac_key,
        struct.pack('>Q', seq) + bytes([rtype, 3, 3]) +
        struct.pack('>H', len(body)) + body)
    ok = "OK" if got_mac == exp_mac else f"MAC_FAIL"
    return body, ok

def parse_tls(data):
    recs, p = [], 0
    while p + 5 <= len(data):
        rt   = data[p]
        rlen = (data[p+3] << 8) | data[p+4]
        if p + 5 + rlen > len(data):
            break
        recs.append((rt, data[p+5: p+5+rlen]))
        p += 5 + rlen
    return recs

# ── Goodix A0 decoder ─────────────────────────────────────────────────────────

CMDS = {
    0x11:"WAKEUP",    0x20:"VERSION",   0x60:"SESSION_INIT",
    0xAE:"ARM",       0xD0:"TLS_START", 0xE4:"PSK_READ",
    0xC4:"DEL_TMPL",  0x82:"CHIP_INFO", 0x84:"FW_INFO",
    0x90:"SET_PARAM", 0xA6:"SET_CFG",   0xA8:"SET_DRV",
    0xD2:"STORE_PSK", 0x36:"UNK_36",    0x70:"UNK_70",
    0xAC:"UNK_AC",
}

def decode_a0(data, is_in=False):
    if len(data) < 8:
        return "short"
    cmd  = data[4]
    plen = data[5] | (data[6] << 8)
    pay  = data[7: 7 + plen - 1] if plen > 1 else b''
    name = CMDS.get(cmd, f"0x{cmd:02X}")
    if is_in:
        status = data[7] if len(data) > 7 else 0
        return f"ACK({name}) status={status:#04x}"
    return f"{name}  [{len(pay)}B] {pay.hex()[:40]}"

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not os.path.exists(PCAP):
        print(f"[!] Файл не найден: {PCAP}")
        print("    Измени переменную PCAP в начале скрипта")
        sys.exit(1)

    print(f"Читаем: {PCAP}")
    linktype, raw_packets = read_pcapng(PCAP)
    print(f"Linktype: {linktype}  ({'USBPcap' if linktype==249 else 'usbmon(Linux)' if linktype==220 else 'unknown'})")
    print(f"Всего EPB: {len(raw_packets)}")

    if linktype == 249:
        parser = parse_usbpcap
    elif linktype == 220:
        parser = parse_usbmon
    else:
        print(f"[!] Неизвестный linktype {linktype}")
        sys.exit(1)

    packets = [p for r in raw_packets if (p := parser(r)) is not None]
    out_bulk = [p for p in packets if p['dir']=='OUT' and p['transfer']==3 and p['data']]
    in_bulk  = [p for p in packets if p['dir']=='IN'  and p['transfer']==3 and p['data']]
    print(f"OUT bulk с данными: {len(out_bulk)}")
    print(f"IN  bulk с данными: {len(in_bulk)}")
    print()

    frames = reassemble(packets)
    print(f"Goodix фреймов: {len(frames)}")
    print()

    # ── TLS state ────────────────────────────────────────────────────────────
    tls = dict(cr=None, sr=None, ms=None,
               cwk=None, cwmk=None, swk=None, swmk=None,
               c_seq=0, s_seq=0, established=False,
               c_ccs=False, s_ccs=False)

    HS_NAMES = {1:'ClientHello', 2:'ServerHello', 11:'Certificate',
                12:'ServerKeyExchange', 14:'ServerHelloDone',
                16:'ClientKeyExchange', 20:'Finished'}

    print("=" * 76)
    for direction, frame in frames:
        arrow = "→" if direction == 'OUT' else "←"

        if frame[0] == 0xA0:
            print(f"  {arrow} A0  {decode_a0(frame, is_in=(direction=='IN'))}")

        elif frame[0] == 0xB0:
            inner = frame[1] | (frame[2] << 8)
            tls_data = frame[4: 4 + inner]

            for rt, payload in parse_tls(tls_data):
                rt_name = {0x14:'CCS', 0x15:'Alert', 0x16:'HS', 0x17:'AppData'}.get(rt, f'{rt:#04x}')

                if rt == 0x14:  # CCS
                    who = "client" if direction=='IN' else "server"
                    print(f"  {arrow} CCS ({who})")
                    if direction == 'OUT':
                        tls['s_seq'] = 0
                        tls['s_ccs'] = True
                    else:
                        tls['c_ccs'] = True

                elif rt == 0x15:  # Alert
                    level = {1:'warn',2:'fatal'}.get(payload[0] if payload else 0, '?')
                    desc  = payload[1] if len(payload) > 1 else 0
                    ALERTS = {0:'close_notify',10:'unexpected_msg',20:'bad_record_mac',
                               40:'handshake_failure',51:'decrypt_error',80:'internal_error'}
                    print(f"  {arrow} ALERT {level}: {ALERTS.get(desc, desc)}")

                elif rt == 0x16:  # Handshake
                    if not payload:
                        continue
                    # После CCS — содержимое зашифровано, это Finished
                    ccs_active = tls['c_ccs'] if direction=='IN' else tls['s_ccs']
                    if ccs_active and tls['cwk']:
                        if direction == 'IN':
                            body, st = tls_decrypt(tls['cwk'], tls['cwmk'], tls['c_seq'], 0x16, payload)
                            if st == "OK" and body and body[0] == 0x14:
                                vd = body[4:16]
                                # Verify CF
                                from hashlib import sha256
                                exp_vd = prf(tls['ms'], b'client finished', sha256(tls.get('transcript', b'')).digest(), 12) if tls.get('transcript') else None
                                print(f"  {arrow} HS  ClientFinished  vd={vd.hex()}  mac={st}")
                                tls['c_seq'] += 1
                            else:
                                print(f"  {arrow} HS  ClientFinished(enc)  FAIL({st})")
                        else:
                            body, st = tls_decrypt(tls['swk'], tls['swmk'], tls['s_seq'], 0x16, payload)
                            if st == "OK" and body and body[0] == 0x14:
                                vd = body[4:16]
                                print(f"  {arrow} HS  ServerFinished  vd={vd.hex()}  mac={st}")
                                tls['s_seq'] += 1
                                tls['established'] = True
                                print(f"        → ✓ TLS ESTABLISHED")
                            else:
                                print(f"  {arrow} HS  ServerFinished(enc)  FAIL({st})")
                        continue
                    ht = payload[0]
                    hn = HS_NAMES.get(ht, f"hs_{ht:#04x}")

                    if ht == 1:   # ClientHello
                        if len(payload) >= 38:
                            tls['cr'] = payload[6:38]
                        print(f"  {arrow} HS  ClientHello  cr={tls['cr'].hex()[:20] if tls['cr'] else '?'}...")

                    elif ht == 2: # ServerHello
                        if len(payload) >= 38:
                            tls['sr'] = payload[6:38]
                        # cipher suite: skip session_id
                        sid_len = payload[38] if len(payload) > 38 else 0
                        cs_off  = 39 + sid_len
                        cs = ((payload[cs_off] << 8) | payload[cs_off+1]) if len(payload) >= cs_off+2 else 0
                        print(f"  {arrow} HS  ServerHello  cs={cs:#06x}  sr={tls['sr'].hex()[:20] if tls['sr'] else '?'}...")
                        if tls['cr'] and tls['sr']:
                            tls['ms'],tls['cwmk'],tls['swmk'],tls['cwk'],tls['swk'] = \
                                derive_keys(tls['cr'], tls['sr'])
                            print(f"        → Keys derived: cwk={tls['cwk'].hex()}")

                    elif ht == 16: # ClientKeyExchange
                        id_len = (payload[4]<<8)|payload[5] if len(payload)>5 else 0
                        psk_id = payload[6:6+id_len] if len(payload)>=6+id_len else b''
                        print(f"  {arrow} HS  ClientKeyExchange  id='{psk_id.decode('utf-8','replace')}'")

                    elif ht == 20: # Finished (cleartext — shouldn't happen post-CCS)
                        vd = payload[4:16]
                        print(f"  {arrow} HS  Finished  vd={vd.hex()}")

                    else:
                        print(f"  {arrow} HS  {hn}  [{len(payload)}B]")

                elif rt == 0x17:  # AppData
                    if tls['cwk']:
                        if direction == 'IN':
                            body, st = tls_decrypt(tls['cwk'], tls['cwmk'], tls['c_seq'], 0x17, payload)
                            seq = tls['c_seq']
                            if st == "OK":
                                tls['c_seq'] += 1
                        else:
                            body, st = tls_decrypt(tls['swk'], tls['swmk'], tls['s_seq'], 0x17, payload)
                            seq = tls['s_seq']
                            if st == "OK":
                                tls['s_seq'] += 1
                        if st == "OK":
                            inner_desc = decode_a0(body, is_in=(direction=='IN')) if body and body[0]==0xA0 else body.hex()[:48]
                            print(f"  {arrow} AppData seq={seq}  [{len(body)}B]  {inner_desc}")
                        else:
                            print(f"  {arrow} AppData seq={seq}  FAIL({st})  raw={payload[:8].hex()}")
                    else:
                        print(f"  {arrow} AppData (no keys)  [{len(payload)}B]  raw={payload[:8].hex()}")

                else:
                    # Encrypted Finished (type=0x16 post-CCS, содержимое зашифровано)
                    if tls['cwk'] and not tls['established']:
                        if direction == 'IN':
                            body, st = tls_decrypt(tls['cwk'], tls['cwmk'], tls['c_seq'], rt, payload)
                        else:
                            body, st = tls_decrypt(tls['swk'], tls['swmk'], tls['s_seq'], rt, payload)
                        if st == "OK" and body and body[0] == 0x14:
                            vd = body[4:16]
                            who = "ClientFinished" if direction=='IN' else "ServerFinished"
                            print(f"  {arrow} HS  {who}  vd={vd.hex()}")
                            if direction == 'IN':
                                tls['c_seq'] += 1
                            else:
                                tls['s_seq'] += 1
                                tls['established'] = True
                                print(f"        → ✓ TLS ESTABLISHED")
                        else:
                            print(f"  {arrow} {rt_name}  [{len(payload)}B]  raw={payload[:8].hex()}")
                    else:
                        print(f"  {arrow} {rt_name}  [{len(payload)}B]  raw={payload[:8].hex()}")

    print("=" * 76)
    print(f"\nTLS ключи:       {'✓ получены' if tls['cwk'] else '✗ нет'}")
    print(f"TLS established: {'✓' if tls['established'] else '✗'}")
    if tls['cwk']:
        print(f"  client_write_key = {tls['cwk'].hex()}")
        print(f"  server_write_key = {tls['swk'].hex()}")
    print(f"Расшифровано AppData: IN seq={tls['c_seq']}  OUT seq={tls['s_seq']}")

if __name__ == '__main__':
    main()
