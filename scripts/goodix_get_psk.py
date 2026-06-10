"""
goodix_get_psk.py — читает WB blob напрямую из Goodix GM168SEC сенсора и
расшифровывает PSK без Windows.

Протокол: libfprint goodix_gm168.c + goodix_proto.c
Формат OUT-фрейма: [A0][LenL][LenH][HdrSum][Cmd][PLenL][PLenH][Payload...][BodySum]
Формат IN-ответа:  [A0][LenL][LenH][HdrSum][EchoCmd][PLenL][PLenH][Status][Extra...][BodySum]

Использование:
    sudo python3 goodix_get_psk.py
"""
import sys
import time
import struct
import hashlib
import usb.core
import usb.util

# ── Параметры устройства ──────────────────────────────────────────────────────
VID, PID   = 0x27c6, 0x589a
EP_OUT     = 0x01
EP_IN      = 0x83
TIMEOUT_MS = 3000

# ── TLV теги ─────────────────────────────────────────────────────────────────
WB_TAG    = 0xBB010003  # WB-зашифрованный PSK (то что нам нужно)
DPAPI_TAG = 0xBB010002  # DPAPI PSK (только Windows)

# ── WB расшифровка ────────────────────────────────────────────────────────────
VAR_488 = bytes.fromhex('5cba6e25819518de2d53e96dc0347ab0')

def wb_derive_key():
    """Вычисляет AES ключ через var_488 метод (верифицирован из WB блоба pcap)."""
    prefix = (32).to_bytes(4, 'little')
    fs = hashlib.sha256(prefix + b'123GOODIX').digest()
    iv = fs[:15] + bytes([fs[15] & 0xf0])
    ss = hashlib.sha256(iv + bytes(48) + VAR_488).digest()
    return ss[:16]

def wb_decrypt(blob96):
    """Расшифровывает 96-байтный WB блоб → PSK (32B). Алгоритм: AES-128-CBC."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("  [!] pip install pycryptodome")
        return None
    key = wb_derive_key()
    iv  = blob96[:16]
    ct  = blob96[16:64]
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pad = dec[-1]
    if not (1 <= pad <= 16 and all(b == pad for b in dec[-pad:])):
        print(f"  [!] Плохой PKCS7 padding: 0x{pad:02x}")
        return None
    return dec[:-pad]

# ── Goodix frame builder ──────────────────────────────────────────────────────

def encode_cmd(cmd, payload=b''):
    """
    Кодирует A0-команду в libfprint формате:
    [A0][LenL][LenH][HdrSum][Cmd][PLenL][PLenH][Payload...][BodySum]
    """
    payload_len = len(payload)
    plen = payload_len + 1          # plen включает BodySum
    inner_sz = 3 + payload_len + 1  # Cmd(1)+PLenL(1)+PLenH(1)+payload+BodySum(1)

    # HdrSum = (0xA0 + lenL + lenH) & 0xFF
    hdr_sum = (0xA0 + (inner_sz & 0xFF) + ((inner_sz >> 8) & 0xFF)) & 0xFF

    # BodySum = (0xAA - (cmd + plenL + plenH + sum(payload))) & 0xFF
    s = cmd + (plen & 0xFF) + ((plen >> 8) & 0xFF) + sum(payload)
    body_sum = (0xAA - s) & 0xFF

    frame  = bytes([0xA0, inner_sz & 0xFF, (inner_sz >> 8) & 0xFF, hdr_sum])
    frame += bytes([cmd, plen & 0xFF, (plen >> 8) & 0xFF])
    frame += bytes(payload)
    frame += bytes([body_sum])
    return frame

# ── Заготовленные команды ─────────────────────────────────────────────────────

CMD_WAKEUP = encode_cmd(0x11)
CMD_RESET  = encode_cmd(0x60, bytes([0x01, 0x00]))
CMD_VERSION = encode_cmd(0x20)

def make_psk_read(tag, size, offset=0):
    """
    16-байтное тело для cmd 0xE4 (SPEC_DATA):
    body[0:2]  = chunk_size (LE u16)
    body[2:4]  = 0 (reserved)
    body[4:8]  = offset (LE u32)
    body[8:12] = tag (LE u32)
    body[12:16]= 0 (reserved)
    """
    body = bytearray(16)
    struct.pack_into('<H', body, 0, size)
    struct.pack_into('<I', body, 4, offset)
    struct.pack_into('<I', body, 8, tag)
    return encode_cmd(0xE4, bytes(body))

CMD_READ_WB    = make_psk_read(WB_TAG, 96, 0)
CMD_READ_DPAPI = make_psk_read(DPAPI_TAG, 256, 0)  # первый чанк 256B

# ── ACK парсер ────────────────────────────────────────────────────────────────

def decode_ack(data):
    """
    Разбирает A0-ответ MCU.
    Возвращает (echo_cmd, status, extra_bytes) или None.

    Формат: [A0][LenL][LenH][HdrSum][EchoCmd][PLenL][PLenH][Status][Extra...][BodySum]
            idx:  0    1     2       3         4       5      6       7        8+
    """
    if len(data) < 9:
        return None
    if data[0] != 0xA0:
        return None
    inner_len = data[1] | (data[2] << 8)
    echo_cmd  = data[4]
    status    = data[7]
    # extra = data[8 : 8+ex_len], ex_len = inner_len - 5 (echo+plenL+plenH+status+bodysum)
    ex_len = inner_len - 5 if inner_len > 5 else 0
    extra = data[8:8+ex_len] if ex_len > 0 else b''
    return (echo_cmd, status, extra)

def find_a0_ack(buf, want_cmd):
    """
    Сканирует буфер в поисках A0-пакета с echo_cmd == want_cmd.
    MCU может присылать стale B0/TLS пакеты, которые нужно пропустить.
    """
    offset = 0
    while offset + 4 <= len(buf):
        pkt_type = buf[offset]
        ilen     = buf[offset+1] | (buf[offset+2] << 8)
        pkt_len  = 4 + ilen
        if offset + pkt_len > len(buf):
            break
        if pkt_type == 0xA0:
            result = decode_ack(buf[offset:offset+pkt_len])
            if result and result[0] == want_cmd:
                return result
        offset += pkt_len
    return None

# ── USB хелперы ───────────────────────────────────────────────────────────────

def flush_input(dev):
    """Очищает EP_IN от stale ответов (например от VM-сессии)."""
    count = 0
    while True:
        try:
            chunk = bytes(dev.read(EP_IN, 16*1024, 200))
            print(f"  [flush] {len(chunk)}B: {chunk[:12].hex()}")
            count += 1
        except usb.core.USBTimeoutError:
            break
        except Exception:
            break
    if count:
        print(f"  [flush] Сброшено {count} пакетов")

def send(dev, frame, label):
    """Отправляет фрейм по 64B чанкам (EP_OUT_SIZE = 0x40)."""
    EP_OUT_SZ = 64
    total = 0
    for i in range(0, len(frame), EP_OUT_SZ):
        chunk = frame[i:i+EP_OUT_SZ]
        total += dev.write(EP_OUT, chunk, TIMEOUT_MS)
    print(f"  → {label} ({len(frame)}B): {frame.hex()}")
    return total

def recv(dev, label, max_read=8, want_cmd=None):
    """
    Читает ответ из EP_IN (до max_read чтений по 16KB).
    Если want_cmd задан — ищет A0 ACK с этим echo_cmd через find_a0_ack.
    Возвращает (raw_buf, ack_result_or_None).
    """
    buf = b''
    for i in range(max_read):
        try:
            chunk = bytes(dev.read(EP_IN, 16*1024, TIMEOUT_MS))
            buf += chunk
            print(f"  ← {label} chunk[{i}] ({len(chunk)}B): {chunk[:24].hex()}")
        except usb.core.USBTimeoutError:
            if buf:
                break
            print(f"  [!] Timeout ожидая {label}")
            break
        except Exception as e:
            print(f"  [!] Ошибка чтения: {e}")
            break

        if want_cmd is not None:
            result = find_a0_ack(buf, want_cmd)
            if result:
                return (buf, result)

    if want_cmd is not None:
        return (buf, find_a0_ack(buf, want_cmd))
    return (buf, None)

# ── Основная логика ───────────────────────────────────────────────────────────

def main():
    print("=" * 64)
    print("Goodix GM168SEC — прямое чтение PSK с сенсора")
    print("Алгоритм: WAKEUP → SESSION_INIT → VERSION → PSK_READ(WB)")
    print("=" * 64)

    # Найти устройство
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("[!] Сенсор 27c6:589a не найден")
        sys.exit(1)
    print(f"[+] Сенсор: Bus {dev.bus:03d} Device {dev.address:03d}")

    # Отцепить kernel driver
    for iface in range(2):
        try:
            if dev.is_kernel_driver_active(iface):
                print(f"[+] Detach kernel driver (iface {iface})")
                dev.detach_kernel_driver(iface)
        except Exception as e:
            print(f"[~] iface {iface}: {e}")

    try:
        dev.set_configuration()
        print("[+] set_configuration OK")
    except usb.core.USBError as e:
        print(f"[~] set_configuration: {e}")

    # Очистка stale IN-буфера (от предыдущих VM-сессий)
    print("\n[0] Flush EP_IN")
    flush_input(dev)

    # ── 1. WAKEUP (0x11) — MCU не шлёт ACK, просто ждём ──────────────────────
    print(f"\n[1] WAKEUP (cmd=0x11) — no ACK expected")
    send(dev, CMD_WAKEUP, "WAKEUP")
    time.sleep(0.05)
    # Читаем на случай если что-то пришло, но не ждём конкретного ACK
    flush_input(dev)

    # ── 2. SESSION_INIT/RESET (0x60 {01 00}) — сбросить stale TLS ──────────
    print(f"\n[2] SESSION_INIT (cmd=0x60) — reset MCU state")
    send(dev, CMD_RESET, "SESSION_INIT")
    _, ack = recv(dev, "SESSION_INIT", want_cmd=0x60)
    if ack:
        echo, status, extra = ack
        print(f"  ACK: echo=0x{echo:02X} status=0x{status:02X} extra={extra[:8].hex()}")
        if status != 0:
            print(f"  [!] Status ненулевой: 0x{status:02X}")
    else:
        print("  [!] ACK не получен — продолжаем")

    # ── 3. VERSION (0x20) ────────────────────────────────────────────────────
    print(f"\n[3] VERSION (cmd=0x20)")
    send(dev, CMD_VERSION, "VERSION")
    raw, ack = recv(dev, "VERSION", want_cmd=0x20)
    if ack:
        echo, status, extra = ack
        print(f"  ACK: echo=0x{echo:02X} status=0x{status:02X}")
        if extra:
            try:
                ver = extra.decode('ascii', errors='replace').rstrip('\x00')
                print(f"  Firmware: {ver}")
            except Exception:
                print(f"  extra[{len(extra)}B]: {extra[:32].hex()}")
    else:
        print("  [!] VERSION ACK не получен")

    # ── 4. PSK READ (0xE4) — WB blob (tag=BB010003, 96B) ────────────────────
    print(f"\n[4] PSK_READ WB (cmd=0xE4, tag=0xBB010003, size=96)")
    print(f"    Frame: {CMD_READ_WB.hex()}")
    send(dev, CMD_READ_WB, "PSK_READ_WB")

    # Ответ: A0 ACK с extra = [tag:4 LE][chunk_len:4 LE][data:96B]
    raw, ack = recv(dev, "PSK_READ_WB", max_read=16, want_cmd=0xE4)

    wb_blob = None
    if ack:
        echo, status, extra = ack
        print(f"\n  ACK: echo=0x{echo:02X} status=0x{status:02X} extra_len={len(extra)}")
        if status == 0 and len(extra) >= 8:
            tag_echo  = struct.unpack_from('<I', extra, 0)[0]
            chunk_len = struct.unpack_from('<I', extra, 4)[0]
            print(f"  tag_echo=0x{tag_echo:08X}  chunk_len={chunk_len}")
            if chunk_len > 0 and len(extra) >= 8 + chunk_len:
                wb_blob = extra[8:8+chunk_len]
                print(f"  WB blob ({len(wb_blob)}B): {wb_blob.hex()}")
            else:
                print(f"  [!] extra слишком короткий: {len(extra)} < {8+chunk_len}")
        elif status != 0:
            print(f"  [!] MCU вернул ошибку status=0x{status:02X}")
    else:
        print("  [!] ACK на cmd 0xE4 не найден в ответе")
        if raw:
            print(f"  Сырые данные [{len(raw)}B]: {raw.hex()}")

    # Если WB не получен — пробуем DPAPI (для диагностики)
    if wb_blob is None:
        print(f"\n[4b] Пробуем DPAPI blob (tag=0xBB010002) для диагностики")
        send(dev, CMD_READ_DPAPI, "PSK_READ_DPAPI")
        raw2, ack2 = recv(dev, "PSK_READ_DPAPI", max_read=16, want_cmd=0xE4)
        if ack2:
            echo, status, extra = ack2
            print(f"  ACK DPAPI: echo=0x{echo:02X} status=0x{status:02X} extra_len={len(extra)}")
            if status == 0 and len(extra) >= 8:
                tag_echo  = struct.unpack_from('<I', extra, 0)[0]
                chunk_len = struct.unpack_from('<I', extra, 4)[0]
                print(f"  tag_echo=0x{tag_echo:08X}  chunk_len={chunk_len}")
                # DPAPI не можем расшифровать без Windows
                print("  (DPAPI blob — нужен Windows для расшифровки)")

    # ── 5. Расшифровка ───────────────────────────────────────────────────────
    print("\n[5] Расшифровка")
    if wb_blob and len(wb_blob) == 96:
        psk = wb_decrypt(wb_blob)
        if psk:
            sha = hashlib.sha256(psk).hexdigest()
            print(f"\n  ✓ PSK = {psk.hex()}")
            print(f"  SHA256  = {sha}")

            out = f"PSK={psk.hex()}\nSHA256={sha}\n"
            with open('/tmp/goodix_psk.txt', 'w') as f:
                f.write(out)
            print("\n  Сохранено: /tmp/goodix_psk.txt")
        else:
            print("  [!] Расшифровка не удалась")
    else:
        print("  [!] WB blob не получен")
        print()
        print("  Возможные причины:")
        print("  1. WB blob не был записан (нужен provisioning через Windows)")
        print("  2. Неверная последовательность init команд")
        print("  3. Сенсор занят (kernel driver не отцеплен)")

    usb.util.dispose_resources(dev)

if __name__ == '__main__':
    main()
