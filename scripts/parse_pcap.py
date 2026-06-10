"""
Полный анализ pcapng (только OUT bulk, linktype=220, usbmon 64B header).
Собирает multi-chunk Goodix transfers и декодирует команды.
"""
import struct
from collections import Counter

PCAP = r"C:\Users\mrcook1e\Documents\goodix-gm168\captures\goodix_full.pcapng"

CMDS = {
    0x01:"NOP",              0x02:"GetVersion",       0x03:"ResetSensor",
    0x04:"GetPmk",           0x05:"SetConfigParams",  0x06:"GetConfigParams",
    0x07:"SetPowerMode",     0x08:"GetPowerMode",
    0x20:"StartCapture",     0x21:"GetImage",          0x22:"StopCapture",
    0x25:"GetFeatureMap",
    0x40:"IdentifyStart",    0x41:"IdentifyResult",
    0x50:"EnrollStart",      0x51:"EnrollCapture",     0x52:"EnrollResult",
    0x60:"TlsConnect",       0x61:"TlsConnectAck",
    0x62:"TlsData",          0x64:"TlsDisconnect",
    0x6E:"PskWriteWB",       # Запись WB-зашифрованного PSK (TLV BB010003)
    0x80:"GetChipId",        0x82:"GetChipInfo",
    0x84:"GetFwInfo",        0x86:"GetPmkInfo",
    0x90:"SetParam",         0x96:"SetRegister",       0x98:"GetRegister",
    0x9A:"FirmwareVersion",
    0xA0:"WriteCalib",       0xA2:"SetAutoWakeup",
    0xA4:"GetConfig",        0xA6:"SetConfig",
    0xA8:"SetDrvState2",     0xAA:"SwitchMode",        0xAE:"Calibrate",
    0xB0:"SetDrvState",      0xB1:"PskWriteDPAPI",     # Запись DPAPI PSK (TLV BB010002)
    0xB2:"GetDrvState",      0xB4:"McuGetPsk",
    0xC0:"GetPmkHash",       0xC4:"DelAllTemplate",    0xC8:"GetTemplateCount",
    0xD0:"GetPskHash",       0xD2:"StorePsk",          0xD4:"LoadPsk",
    0xE0:"PresetPskWriteR",  0xE2:"PresetPskReadR",
    0xE4:"PresetPskRead",    0xE6:"PresetPskWrite",
    0xF0:"Ioctl",            0xF2:"Reset",
}

TLV_TAGS = {
    0xBB010001:"PSK_plain",  0xBB010002:"PSK_DPAPI",
    0xBB010003:"PSK_WB",     0xBB020001:"PSK_SHA256",
}

HDR = 64  # Linux usbmon binary header size

def read_pcapng(path):
    with open(path,'rb') as f: data=f.read()
    pos,n,ifaces=0,0,[]
    while pos+8<=len(data):
        bt=struct.unpack_from('<I',data,pos)[0]
        bl=struct.unpack_from('<I',data,pos+4)[0]
        if bl<12 or pos+bl>len(data): break
        body=data[pos+8:pos+bl-4]
        if bt==0x00000001:
            ifaces.append(1_000_000)
        elif bt==0x00000006:
            caplen=struct.unpack_from('<I',body,12)[0]
            n+=1
            yield n,body[20:20+caplen]
        pos+=bl

def is_out_submit(raw):
    if len(raw) < HDR: return False
    if raw[8] != 0x53: return False   # только Submit
    if raw[9] != 0x03: return False   # bulk
    if raw[10] & 0x80: return False   # OUT
    if raw[15] != 0: return False     # has data flag
    cap = struct.unpack_from('<I', raw, 36)[0]
    return cap > 0

def get_payload(raw):
    cap = struct.unpack_from('<I', raw, 36)[0]
    return raw[HDR:HDR+cap]

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

def hx(b, n=24):
    h = b.hex()
    return h if len(h) <= n*2 else h[:n*2]+'...'

TLS_T  = {0x14:'CCS',0x15:'Alert',0x16:'Handshake',0x17:'AppData'}
TLS_H  = {1:'ClientHello',2:'ServerHello',11:'Certificate',12:'ServerKeyExchange',
          14:'ServerHelloDone',16:'ClientKeyExchange',20:'Finished'}

def tls_desc(b):
    if not b: return ''
    t = TLS_T.get(b[0], f'0x{b[0]:02x}')
    if b[0] == 0x16 and len(b) >= 6:
        return f"{t}/{TLS_H.get(b[5], f'hs_{b[5]:02x}')}"
    return t

# ── Reassembler ────────────────────────────────────────────────────────────────

def reassemble_frames(all_packets):
    """
    Собирает multi-chunk Goodix transfers.
    Возвращает список (first_frame_num, goodix_payload).
    """
    result = []
    buf = b''
    start_n = None
    expected = 0  # ожидаем ещё байт

    for n, raw in all_packets:
        if not is_out_submit(raw):
            continue
        pay = get_payload(raw)
        if not pay:
            continue

        if not buf:
            # Начало нового фрейма
            if len(pay) < 3:
                continue
            length = struct.unpack_from('<H', pay, 1)[0]
            total = 3 + length  # header + body + cksum (cksum входит в length)
            buf = pay
            start_n = n
            expected = total
        else:
            buf += pay

        if len(buf) >= expected:
            result.append((start_n, buf[:expected]))
            buf = b''
            expected = 0

    return result

def parse_goodix(frame_bytes):
    if len(frame_bytes) < 4:
        return None
    flags = frame_bytes[0]
    length = struct.unpack_from('<H', frame_bytes, 1)[0]
    if length < 1 or 3 + length > len(frame_bytes) + 1:
        return None
    body = frame_bytes[3:3+length]   # включая checksum (TLV может доходить до конца)
    if not body:
        return None
    cmd = body[0]
    return {
        'flags': flags, 'length': length,
        'cmd': cmd, 'name': CMDS.get(cmd, f'UNK_{cmd:02X}'),
        'body': body[1:]  # данные после cmd
    }

# ── MAIN ───────────────────────────────────────────────────────────────────────
print(f"Parsing {PCAP}")
all_pkts = list(read_pcapng(PCAP))
print(f"Total EPB: {len(all_pkts)}\n")

frames = reassemble_frames(all_pkts)
print(f"Reassembled Goodix frames: {len(frames)}\n")

events = []
tls_start = None
psk_ops = []

print(f"{'#':>4}  {'[frm]':>5}  {'Команда':<22}  Детали")
print("─" * 100)

for idx, (n, fbytes) in enumerate(frames):
    gf = parse_goodix(fbytes)
    if gf is None:
        continue

    cmd, name = gf['cmd'], gf['name']
    body = gf['body']

    # Timestamp из первого пакета этого фрейма
    prev_ts = events[-1][3] if events else 0

    details = ""
    if cmd == 0x62:  # TLS
        if tls_start is None: tls_start = n
        details = f"[{len(body)}B] {tls_desc(body)}"
    elif cmd in (0xE0, 0xE2, 0xE4, 0xE6, 0xB4, 0xB1, 0x6E):
        # McuWrite/PSK-related: определяем sub-cmd
        sub = body[0] if body else 0
        if cmd == 0xB1 and sub == 0xF0:
            # калибровка — показываем только индекс
            idx = struct.unpack_from('<I', body, 4)[0] if len(body) > 7 else 0
            details = f"Calib[{idx:03d}]"
        else:
            all_tlvs = find_tlv_le(body)
            if all_tlvs:
                parts = [f"{t}[{l}B]" for _, _, t, l, v in all_tlvs]
                details = f"sub=0x{sub:02X} TLV: " + "  ".join(parts)
                for _, tag, tname, tlen, tval in all_tlvs:
                    psk_ops.append((n, cmd, name, tname, tlen, tval))
            else:
                details = f"sub=0x{sub:02X} raw: {hx(body[1:], 14)}"
    elif cmd == 0xA6:
        details = f"cfg: {hx(body, 12)}"
    elif cmd == 0xA8:
        details = f"state: {hx(body, 8)}"
    elif body:
        details = hx(body, 18)

    events.append((n, cmd, name, 0))
    print(f"{idx+1:>4}  [{n:>4}]  {name:<22}  {details}")

# ── Итоги ────────────────────────────────────────────────────────────────────
print("\n" + "═" * 100)
print("\nPSK операции:")
for n, cmd, name, tname, tlen, tval in psk_ops:
    print(f"  [{n:>4}] {name:<20}  {tname}[{tlen}B]  = {tval[:32].hex()}...")

print("\nКоманды итого:")
counts = Counter(name for _, _, name, _ in events)
for name, cnt in counts.most_common():
    print(f"  {cnt:3}x  {name}")
