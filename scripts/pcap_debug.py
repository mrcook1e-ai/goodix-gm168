"""Debug: печатаем сырые байты первых 20 пакетов pcapng"""
import struct

PCAP = r"C:\Users\mrcook1e\Documents\goodix-gm168\captures\goodix_full.pcapng"

def read_pcapng(path):
    with open(path, 'rb') as f:
        data = f.read()
    pos = 0
    ifaces = []
    pkt_num = 0
    while pos + 8 <= len(data):
        bt = struct.unpack_from('<I', data, pos)[0]
        bl = struct.unpack_from('<I', data, pos + 4)[0]
        if bl < 12 or pos + bl > len(data):
            break
        body = data[pos + 8: pos + bl - 4]

        if bt == 0x0A0D0D0A:
            print(f"[SHB] @ {pos}")
        elif bt == 0x00000001:
            lt = struct.unpack_from('<H', body, 0)[0]
            snap = struct.unpack_from('<I', body, 4)[0]
            print(f"[IDB] @ {pos}  link_type={lt}  snaplen={snap}")
            ifaces.append(lt)
        elif bt == 0x00000006:
            caplen = struct.unpack_from('<I', body, 12)[0]
            pkt = body[20: 20 + caplen]
            pkt_num += 1
            if pkt_num <= 20:
                print(f"\n[EPB #{pkt_num}] caplen={caplen}  raw[0:64]={pkt[:64].hex()}")
                # Если это usbmon (lt=220) — header 48 bytes
                if ifaces and ifaces[-1] == 220:
                    if len(pkt) >= 48:
                        urb_id   = struct.unpack_from('<Q', pkt, 0)[0]
                        urb_type = chr(pkt[8]) if pkt[8] in (0x53,0x43,0x45) else f'0x{pkt[8]:02x}'
                        xfer     = pkt[9]
                        epnum    = pkt[10]
                        devnum   = pkt[11]
                        busnum   = struct.unpack_from('<H', pkt, 12)[0]
                        flag_s   = pkt[14]
                        flag_d   = pkt[15]
                        status   = struct.unpack_from('<i', pkt, 28)[0]
                        length   = struct.unpack_from('<I', pkt, 32)[0]
                        caplen2  = struct.unpack_from('<I', pkt, 36)[0]
                        ep_dir   = 'IN' if (epnum & 0x80) else 'OUT'
                        print(f"  type={urb_type} xfer={xfer} ep={epnum&0x7f}({ep_dir}) dev={devnum} bus={busnum}")
                        print(f"  flag_setup=0x{flag_s:02x} flag_data=0x{flag_d:02x} status={status} len={length} caplen={caplen2}")
                        if flag_d == 0 and caplen2 > 0:
                            payload = pkt[48: 48 + caplen2]
                            print(f"  payload[{caplen2}B]: {payload[:48].hex()}")
            yield pkt_num, pkt
        pos += bl

list(read_pcapng(PCAP))
print(f"\nDone")
