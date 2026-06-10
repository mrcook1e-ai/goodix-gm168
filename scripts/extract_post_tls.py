#!/usr/bin/env python3
"""
Извлекает все A0 OUT-команды ПОСЛЕ TLS handshake из all.pcapng.
Выводит полные payloads в виде C-массивов для вставки в драйвер.
"""
import struct, sys, os

PCAP = r"C:\Users\mrcook1e\Documents\goodix-gm168\patches\all.pcapng"

CMDS = {
    0x11:"WAKEUP",    0x20:"VERSION",   0x60:"SESSION_INIT",
    0xAE:"ARM",       0xD0:"TLS_START", 0xE4:"PSK_READ",
    0xC4:"DEL_TMPL",  0x82:"CHIP_INFO", 0x84:"FW_INFO",
    0x90:"SET_PARAM", 0xA6:"SET_CFG",   0xA8:"SET_DRV",
    0xD2:"STORE_PSK", 0x36:"UNK_36",    0x70:"UNK_70",
    0xAC:"UNK_AC",    0x34:"FDT_REARM", 0x32:"FDT_SETUP",
    0xD6:"POWER",     0xA2:"UNK_A2",
}

def read_pcapng(path):
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
        if bt == 0x00000001:
            lt = struct.unpack_from('<H', body, 0)[0]
            if linktype is None:
                linktype = lt
        elif bt == 0x00000006:
            caplen = struct.unpack_from('<I', body, 12)[0]
            packets.append(body[20: 20 + caplen])
        pos += bl
    return linktype, packets

def parse_usbpcap(raw):
    if len(raw) < 27:
        return None
    hdr_len  = struct.unpack_from('<H', raw, 0)[0]
    status   = struct.unpack_from('<I', raw, 10)[0]
    endpoint = raw[21]
    transfer = raw[22]
    data_len = struct.unpack_from('<I', raw, 23)[0]
    direction = 'IN' if (endpoint & 0x80) else 'OUT'
    payload = raw[hdr_len: hdr_len + data_len]
    return {'dir': direction, 'transfer': transfer, 'status': status, 'data': payload}

def reassemble(packets):
    """Reassemble A0, B0 и B2 Goodix-фреймы."""
    bufs = {'IN': b'', 'OUT': b''}
    frames = []

    def try_extract(d):
        while len(bufs[d]) >= 4:
            h = bufs[d]
            if h[0] not in (0xA0, 0xB0, 0xB2):
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

def parse_tls_records(data):
    recs, p = [], 0
    while p + 5 <= len(data):
        rt = data[p]
        rlen = (data[p+3] << 8) | data[p+4]
        if p + 5 + rlen > len(data):
            break
        recs.append((rt, data[p+5: p+5+rlen]))
        p += 5 + rlen
    return recs

def c_array(name, data):
    hex_vals = ', '.join(f'0x{b:02x}' for b in data)
    lines = []
    row = []
    for i, b in enumerate(data):
        row.append(f'0x{b:02x}')
        if len(row) == 16 or i == len(data)-1:
            lines.append('    ' + ', '.join(row) + ',')
            row = []
    inner = '\n'.join(lines)
    return f"static const guint8 {name}[] = {{\n{inner}\n}};\n/* length: {len(data)} */"

def main():
    linktype, raw_packets = read_pcapng(PCAP)
    print(f"Linktype: {linktype}, packets: {len(raw_packets)}")

    if linktype != 249:
        print("ERROR: expected USBPcap (249)")
        sys.exit(1)

    packets = [p for r in raw_packets if (p := parse_usbpcap(r)) is not None]
    frames = reassemble(packets)
    print(f"Goodix frames: {len(frames)}")
    print()

    # Найдём момент TLS ESTABLISHED (после ServerFinished)
    tls_done = False
    server_ccs_seen = False
    c_ccs_seen = False

    print("=== ВСЕ ФРЕЙМЫ ===")
    post_tls_cmds = []

    for direction, frame in frames:
        arrow = "→" if direction == 'OUT' else "←"

        if frame[0] == 0xB0:
            inner = frame[1] | (frame[2] << 8)
            tls_data = frame[4: 4 + inner]
            for rt, payload in parse_tls_records(tls_data):
                if rt == 0x14:  # CCS
                    if direction == 'OUT':
                        server_ccs_seen = True
                        print(f"  {arrow} CCS (server)")
                    else:
                        c_ccs_seen = True
                        print(f"  {arrow} CCS (client)")
                elif rt == 0x16:
                    if server_ccs_seen and direction == 'OUT' and not tls_done:
                        print(f"  {arrow} HS  ServerFinished(enc)")
                        tls_done = True
                        print(f"        → ✓ TLS ESTABLISHED")
                    elif c_ccs_seen and direction == 'IN' and tls_done == False:
                        print(f"  {arrow} HS  ClientFinished(enc)")
                    else:
                        print(f"  {arrow} HS  [{len(payload)}B]")
                else:
                    print(f"  {arrow} B0 rt={rt:#04x} [{len(payload)}B]")

        elif frame[0] == 0xA0:
            if len(frame) < 8:
                continue
            cmd  = frame[4]
            plen = frame[5] | (frame[6] << 8)
            pay  = bytes(frame[7: 7 + plen - 1]) if plen > 1 else b''
            name = CMDS.get(cmd, f"0x{cmd:02X}")

            if direction == 'IN':
                status = frame[7] if len(frame) > 7 else 0
                print(f"  {arrow} ACK({name}) status={status:#04x}")
            else:
                print(f"  {arrow} {name}  [{len(pay)}B] {pay.hex()}")
                if tls_done:
                    post_tls_cmds.append((cmd, name, pay))

        elif frame[0] == 0xB2:
            b2_len = frame[1] | (frame[2] << 8)
            print(f"  {arrow} B2  [{b2_len}B] (fingerprint image)")

    print()
    print("=" * 60)
    print("=== POST-TLS КОМАНДЫ (OUT) ===")
    print("=" * 60)
    print()

    for cmd, name, pay in post_tls_cmds:
        print(f"CMD 0x{cmd:02X} {name}  [{len(pay)}B]:")
        print(f"  hex: {pay.hex()}")
        if len(pay) > 0:
            var = f"gm168_{name.lower()}_payload"
            print(f"  C:  {c_array(var, pay)}")
        print()

if __name__ == '__main__':
    main()
