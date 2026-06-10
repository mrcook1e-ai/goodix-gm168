# TLS трафик GM168SEC — анализ all.pcapng

Файл: `patches/all.pcapng`  
Захват: **USBPcap** (linktype=249) внутри Windows 11 KVM  
Направления: OUT bulk = 49 пакетов, IN bulk = 68 пакетов  
Скрипт анализа: `scripts/analyze_win_tls.py`

---

## TLS параметры (верифицированы ✓)

| Параметр | Значение |
|----------|---------|
| Cipher suite | `PSK-AES128-CBC-SHA256` (0x00AE) |
| PSK identity | `Client_identity` (mbedTLS default, 15 байт) |
| Client Random | из ClientHello |
| Server Random | из ServerHello |
| client_write_key | `c983080c526f528b38db7efb6966863d` |
| server_write_key | `3c970c15876fe82c63f1739b899fe71e` |
| ClientFinished vd | `e9917a645fb9ba5037e0cfc3` MAC=**OK** |
| ServerFinished vd | `63b03ff203666a3e2564a353` MAC=**OK** |

TLS роли: **сенсор = TLS client**, хост (Windows/libfprint) = TLS server.

---

## КРИТИЧЕСКОЕ ОТКРЫТИЕ: TLS — однонаправленный

**После установки TLS сессии Windows НЕ шифрует команды.**

```
→ ✓ TLS ESTABLISHED
→ A0  SET_PARAM   [256B]   ← PLAINTEXT! Обычный A0-фрейм, не B0/TLS AppData
← A0  ACK
→ A0  DEL_TMPL   [2B]      ← PLAINTEXT!
← A0  ACK
→ A0  STORE_PSK  [2B]      ← PLAINTEXT!
← A0  ACK
...
→ A0  SESSION_INIT [2B]    ← PLAINTEXT!
→ A0  ARM         [2B]     ← PLAINTEXT!
```

### TLS используется ТОЛЬКО для:

| Направление | Использование |
|-------------|---------------|
| **Сенсор → Хост** | Шифрование fingerprint image в B2-фреймах (`cwk` = client_write_key) |
| **Хост → Сенсор** | **PLAINTEXT** A0-команды (TLS не применяется) |

### Вывод для libfprint

**Ошибка в нашей реализации**: мы оборачивали команды в TLS AppData (B0-фрейм),  
а сенсор ожидает обычные A0-команды после handshake.

**Исправление**: после TLS handshake отправлять команды как обычный A0.  
Расшифровку входящих B2-фреймов делать с `cwk` (client_write_key сенсора).

---

## Полная последовательность Windows (normal session)

```
→ 0x00  [4B] 00000000                  ← probe
← ACK

→ SET_DRV (0xA8)  [2B] 0000            ← ×2
→ SET_DRV (0xA8)  [2B] 0000

→ PSK_READ (0xE4) [16B] ...            ← ×3 (reads: WB blob, SHA256 hash, DPAPI tag)

→ SET_DRV (0xA8)  [2B] 0000            ← ×2
→ 0xA2            [2B] 0514
→ CHIP_INFO (0x82)[5B] 0000000400
→ SET_CFG (0xA6)  [2B] 4000
→ 0xD6            [2B] 0000
→ TLS_START (0xD0)[2B] 0000

[TLS HANDSHAKE — B0 фреймы]
  → B0  ClientHello
  ← B0  ServerHello + Certificate + ServerHelloDone
  → B0  ClientKeyExchange + ChangeCipherSpec + Finished
  ← B0  ChangeCipherSpec + Finished
✓ TLS ESTABLISHED

[POST-TLS — всё plaintext A0]
→ SET_PARAM (0x90) [256B] b01160712c9d2cc91ce518fd...  ← параметры распознавания
→ DEL_TMPL (0xC4)  [2B] 0100                           ← ×2
→ STORE_PSK (0xD2) [2B] 0000
→ 0x36             [35B] ...
→ VERSION (0x20)   [10B] ...
→ 0x36, 0x70, CHIP_INFO (0x82), VERSION (0x20)
→ 0x36, DEL_TMPL, 0xAC
→ SESSION_INIT (0x60) [2B] 0100

[Сканирование]
→ 0xD6, ARM (0xAE) [2B] 0000
→ 0x34, VERSION ×2, 0x32, VERSION
→ 0x34, ARM, 0x34
→ SESSION_INIT (0x60), ARM (0xAE) [3B] 010001
```

---

## B2 фрейм — структура зашифрованного изображения

Встречается в `patches/goodix.pcapng` и `patches/lockscreen.pcapng` (IN-direction, от сенсора).

```
[B2][LenL][LenH][HdrSum]         ← 4 байта заголовок
[00 20 XX XX 00 00 00 00 00]     ← 9 байт sub-header
[17 03 03][LenL][LenH][...]      ← TLS AppData record (fingerprint image)
```

Пример: `b2 8e 29 69  00 20 8a 29 00 00 00 00 00  17 03 03 29 80 [encrypted]`  
- B2 len = 0x298e = 10638 байт  
- TLS record len = 0x2980 = 10624 байт (размер зашифрованного fingerprint image)

**Расшифровка**: TLS AppData внутри B2 зашифрована **client_write_key** (сенсор = TLS client).  
После расшифровки и удаления AES-CBC padding (16B) + MAC (32B): ~10576B сырых данных изображения.

---

## Неизвестные команды (обнаружены в этой сессии)

| Код | Длина payload | Назначение |
|-----|--------------|-----------|
| `0x00` | 4B (0000 0000) | Probe / wake-up |
| `0xA2` | 2B (0514) | Неизвестно |
| `0xD6` | 2B (0000) | Неизвестно (pre-TLS и post-TLS) |
| `0x36` | 35B | Неизвестно |
| `0x70` | ? | Неизвестно |
| `0x34` | ? | Неизвестно (в цикле сканирования) |
| `0x32` | ? | Неизвестно (в цикле сканирования) |
| `0xAC` | ? | Неизвестно |
| `0xD2` | 2B (0000) | STORE_PSK (хранение PSK в сенсоре?) |

---

## Захваченные pcap файлы

| Файл | Тип | Содержит TLS handshake | Содержит B2 (image) |
|------|-----|----------------------|---------------------|
| `patches/all.pcapng` | USBPcap | **Да** — полный handshake | Нет |
| `patches/goodix.pcapng` | USBPcap | Нет (уже установлен) | **Да** — несколько B2 |
| `patches/lockscreen.pcapng` | USBPcap | Нет (уже установлен) | **Да** — несколько B2 |
| `captures/goodix_win_tls.pcapng` | usbmon | Частично (OUT only, cap=0 для IN) | Нет |

---

## Ограничение usbmon при KVM USB passthrough

**Проблема**: `usbmon` захватывает IN-URB как пустые (caplen=0).  
**Причина**: QEMU получает IN-данные напрямую в userspace DMA-буфер, минуя ядро.  
**Решение**: USBPcap внутри Windows VM — захват на уровне Windows USB-стека, оба направления.

Установка USBPcap в VM: скачать с сайта производителя, установить, перезагрузить VM.  
Захват: Wireshark → интерфейс `USBPcap1`, фильтр `usb.transfer_type == 2` (bulk only).
