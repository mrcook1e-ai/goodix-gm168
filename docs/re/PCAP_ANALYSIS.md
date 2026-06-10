# PCAP анализ: goodix_full.pcapng

Файл: `captures/goodix_full.pcapng`  
Тип захвата: **Linux usbmon** (linktype=220), только OUT direction  
IN-направление: не захвачено (cap=0 во всех C+IN пакетах)

---

## Тип сессии: Factory Provisioning

Это НЕ нормальная рабочая сессия. Это единоразовая provisioning-сессия:
- Запись PSK в MCU (DPAPI + WB блобы)
- Запись ~26KB калибровочных данных (102 блока × 256B)
- Очистка тестовых шаблонов

**После provisioning PSK хранится в MCU NVRAM** (Сценарий A подтверждён).

---

## Структура фреймов

Фреймы 1–412: USB enumeration (control transfers, не Goodix bulk)  
Фреймы 413+: Goodix bulk (ep=1 OUT, ep=3 IN)

Всего Goodix OUT команд (reassembled): **128**

---

## Последовательность команд

```
[414]  SetDrvState2 (0xA8)        — init: driver state = 5
[419]  SetConfig    (0xA6)        — cfg a8030000
[425]  SetConfig    (0xA6)        — cfg a8030000
[433–514] McuGetPsk (0xB4) ×15   — опрос состояния PSK (sub=0xE4)
[472,478] SetConfig (0xA6) ×2    — смена конфигурации
[520]  PskWriteDPAPI (0xB1 sub=E0) — запись DPAPI-блоба (5 chunks × 64B)
[534]  PskWriteWB    (0x6E sub=E0) — запись WB-блоба    (4 chunks × 64B) ← PSK здесь
[546–558] McuGetPsk (0xB4) ×3    — верификация записи
[564]  SetConfig    (0xA6)
[570–1984] McuWrite Calib ×102   — запись калибровки (sub=0xF0, индексы 0–101)
[1998] GetPowerMode (0x08)
[2006] DelAllTemplate (0xC4)      — очистка
[2012] SetConfig    (0xA6)
```

---

## PSK данные (верифицированы ✓)

### WB blob (frame 534, TLV BB010003, 96B)
```
IV  = ec35ae3abb45ed3f12c4751f1e5c2cc0
CT  = 18e97cc54fb96637a09dbde6bb87efc873287db6593c428c01affa68935ee9736867026173973
MAC = b22655c67a57d9bfddee98554b6de56a47238ce1329d5e22b401634e58c208e1
```

### Расшифрованный PSK (AES-128-CBC, ключ из wb_keygen)
```
PSK = a12ba179ea7f00f6c70105b1d91dfe2e92d389053cb08603b63c4afba24a4c99
```
**Этот PSK используется как TLS-PSK для ciphersuite PSK-AES128-CBC-SHA256 (0x00AE).**

### DPAPI blob (frame 520, TLV BB010002, 324B)
Содержит тот же PSK, зашифрованный Windows DPAPI.
- DPAPI magic: `d08c9ddf0115d1118c7a00c04fc297eb`
- Description: "This is the description string." (UTF-16 LE)

---

## Формат Goodix фрейма

```
[flags:1][length:2 LE][cmd:1][data:...][checksum:1]
```
- `length` = total bytes after 3-byte header (включает cmd и checksum)
- Большие фреймы: split по 64B USB bulk packets, нужна сборка

### Multi-chunk reassembly
Goodix frame с `length > 60` (не влезает в 1 USB packet) разбивается на N пакетов:
- Каждый OUT Submit содержит 64B данных
- Ack (C+OUT) между каждыми двумя чанками
- Полный фрейм = конкатенация payload всех S+OUT до накопления `3+length` байт

---

## McuWrite (0xB1) — универсальная запись в MCU

| Sub-cmd | Назначение                |
|---------|---------------------------|
| `0xE0`  | Запись PSK (DPAPI блоб)  |
| `0xF0`  | Запись калибровки (102 блока, индекс 0–101 по 4B LE @ body+4) |

## McuWrite (0x6E) — запись WB блоба

Body: `[0xE0][data...]` с TLV BB010003 @ offset 101 в body.

---

## Калибровочные данные

102 блока × ~256B активных данных = **~26KB**

Каждый блок:
```
cmd=0xB1 sub=0xF0 | ?? | index[4B LE] | 01 00 00 02 00 00 00 | [data...]
```

Эти данные нужны для корректной работы сенсора (настройка АЦП, пороговые значения).  
Вероятно уже записаны в MCU NVRAM при первичной provisioning — на Linux не нужно повторять.

---

## Что НЕ видно в этом pcap

- IN-direction ответы от сенсора (cap=0)
- TLS handshake (это provisioning, не рабочая сессия)
- PSK_SHA256 (TLV BB020001) — response от устройства
- Нормальная сессия (GetChipInfo + TLS + scan) — нужен другой pcap
