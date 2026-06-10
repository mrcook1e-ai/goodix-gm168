#!/usr/bin/env python3
"""
analyze_enroll_timing.py — extract REARM/FDT/capture timings from a Windows
enrollment pcap.  Builds the host→sensor command timeline with relative
millisecond deltas, focusing on the inter-capture gap (REARM_DELAY).

Usage:
    python analyze_enroll_timing.py [pcap_path]
"""
import struct, sys, os

PCAP = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:\Users\mrcook1e\Documents\goodix-gm168\patches\goodix.pcapng"

CMDS = {
    0x11: "WAKEUP",    0x20: "SCAN_TRIG", 0x32: "FDT_SETUP",
    0x34: "FDT_REARM", 0x60: "SESSION",   0x90: "SET_PARAM",
    0xA6: "SET_CFG",   0xA8: "SET_DRV",   0xAE: "IRQ_ARM",
    0xC4: "DEL_TMPL",  0xD0: "TLS_START", 0xD2: "STORE_PSK",
    0xD6: "POWER",     0xE4: "PSK_READ",  0xB1: "MCU_WRITE",
    0xB4: "MCU_GETPSK", 0x6E: "WB_WRITE",
}

# ── pcapng reader with timestamps ──────────────────────────────────────────
def read_pcapng(path):
    """Yield (timestamp_us, raw_packet_bytes, linktype)."""
    with open(path, 'rb') as f:
        data = f.read()
    linktype = None
    pos = 0
    while pos + 8 <= len(data):
        bt = struct.unpack_from('<I', data, pos)[0]
        bl = struct.unpack_from('<I', data, pos + 4)[0]
        if bl < 12 or pos + bl > len(data):
            break
        body = data[pos + 8: pos + bl - 4]
        if bt == 0x00000001 and linktype is None:
            linktype = struct.unpack_from('<H', body, 0)[0]
        elif bt == 0x00000006: # EPB
            ts_hi  = struct.unpack_from('<I', body, 4)[0]
            ts_lo  = struct.unpack_from('<I', body, 8)[0]
            ts     = (ts_hi << 32) | ts_lo
            caplen = struct.unpack_from('<I', body, 12)[0]
            yield ts, body[20: 20 + caplen], linktype
        pos += bl

def parse_usbpcap(raw):
    if len(raw) < 27: return None
    hdr_len  = struct.unpack_from('<H', raw, 0)[0]
    endpoint = raw[21]
    transfer = raw[22]
    data_len = struct.unpack_from('<I', raw, 23)[0]
    direction = 'IN' if (endpoint & 0x80) else 'OUT'
    payload = raw[hdr_len: hdr_len + data_len]
    return {'dir': direction, 'transfer': transfer,
            'data': payload, 'endpoint': endpoint}

# ── Goodix frame reassembly per direction, preserving ts of first byte ──
def reassemble_timed(packets):
    """packets: [(ts_us, parsed_pkt)]; returns [(ts_us, dir, frame)]."""
    bufs   = {'IN': bytearray(), 'OUT': bytearray()}
    buf_ts = {'IN': 0, 'OUT': 0}
    frames = []
    def flush(d):
        while len(bufs[d]) >= 4:
            h = bufs[d]
            if h[0] not in (0xA0, 0xB0):
                bufs[d] = h[1:]
                continue
            inner = h[1] | (h[2] << 8)
            need  = 4 + inner
            if len(h) < need:
                break
            frames.append((buf_ts[d], d, bytes(h[:need])))
            bufs[d] = h[need:]
        # Strip trailing zero padding (each URB is 64-byte aligned in Windows)
        while bufs[d] and bufs[d][0] == 0:
            bufs[d] = bufs[d][1:]
    for ts, p in packets:
        # bulk transfer = 0x03 in USBPcap (NOT 3); also filter empty SUBMIT
        if p is None or p['transfer'] != 0x03: continue
        if not p['data']: continue
        d = p['dir']
        if not bufs[d]:
            buf_ts[d] = ts
        bufs[d] += p['data']
        flush(d)
    return frames

# ── Main ───────────────────────────────────────────────────────────────────
def main():
    if not os.path.exists(PCAP):
        print(f"[!] not found: {PCAP}"); sys.exit(1)

    print(f"Reading: {PCAP}")
    packets, linktype = [], None
    for ts, raw, lt in read_pcapng(PCAP):
        if linktype is None: linktype = lt
        p = parse_usbpcap(raw)
        if p is not None:
            packets.append((ts, p))
    print(f"Linktype: {linktype}  packets: {len(packets)}")

    frames = reassemble_timed(packets)
    print(f"Goodix frames: {len(frames)}")
    print()

    if not frames: return

    t0 = frames[0][0]
    last_ts = t0
    capture_ts = []  # OUT SCAN_TRIG = 0x20 timestamps
    rearm_ts   = []  # First 0x34 after each capture
    touch_ts   = []  # IN FDT_SETUP status=0x02
    lift_ts    = []  # IN FDT_SETUP status!=0x02

    print(f"{'time_s':>9} {'Δms':>8}  {'dir':3}  {'cmd':<10}  detail")
    print("-" * 80)
    for ts, d, frame in frames:
        rel_s = (ts - t0) / 1e6
        delta_ms = (ts - last_ts) / 1000

        if frame[0] != 0xA0:
            inner = frame[1] | (frame[2] << 8)
            print(f"{rel_s:>9.3f} {delta_ms:>8.1f}  {d:3}  B0/TLS     [{inner} bytes]")
            last_ts = ts
            continue

        if len(frame) < 8: continue
        cmd  = frame[4]
        plen = frame[5] | (frame[6] << 8)
        name = CMDS.get(cmd, f"0x{cmd:02X}")

        tag = ""
        extra = ""
        if d == 'OUT':
            if cmd == 0x20:
                capture_ts.append(ts); tag = "  ◄── CAPTURE"
            elif cmd == 0x34:
                rearm_ts.append(ts);   tag = "  ◄── REARM-34"
            elif cmd == 0x32:          tag = "  ◄── FDT-arm"
        elif d == 'IN' and cmd == 0x32 and len(frame) >= 8:
            status = frame[7]
            if status == 0x02:
                touch_ts.append(ts); extra = f"  status=0x{status:02X} ⚡TOUCH"
            else:
                lift_ts.append(ts); extra = f"  status=0x{status:02X}  LIFT"

        print(f"{rel_s:>9.3f} {delta_ms:>8.1f}  {d:3}  {name:<10}  plen={plen}{extra}{tag}")
        last_ts = ts

    print()
    print("=" * 80)
    print("Inter-capture gaps (touch → next touch, Windows enrollment):")
    print("=" * 80)
    for i in range(1, len(capture_ts)):
        gap_ms = (capture_ts[i] - capture_ts[i-1]) / 1000
        print(f"  capture #{i} → #{i+1}:  {gap_ms:>9.1f} ms")

    print()
    print("=" * 80)
    print("REARM duration per capture (capture → first 0x34 → next FDT touch):")
    print("=" * 80)
    # Pair each rearm_ts with the immediately preceding capture
    for cap_ts in capture_ts:
        rearms = [r for r in rearm_ts if r > cap_ts]
        if not rearms: continue
        first_rearm = rearms[0]
        next_caps = [c for c in capture_ts if c > first_rearm]
        rearm_to_capture = (next_caps[0] - first_rearm) / 1000 if next_caps else None
        cap_to_rearm = (first_rearm - cap_ts) / 1000
        s = f"  capture@{(cap_ts-t0)/1e6:6.3f}s → rearm @ +{cap_to_rearm:.1f}ms"
        if rearm_to_capture is not None:
            s += f" → next capture @ +{rearm_to_capture:.1f}ms"
        print(s)

if __name__ == "__main__":
    main()
