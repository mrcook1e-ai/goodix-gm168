# Goodix GM168SEC — USB протокол

VID:PID `27c6:589a`

## Фрейм (outer layer)

```
[flags: 1B][len: 2B LE][payload: N B][checksum: 1B]
```

## Команды MCU (GM168SEC-специфичные)

| Команда      | Код    | Sub-cmd | Описание |
|--------------|--------|---------|----------|
| `McuWrite`   | `0xB1` | `0xE0`  | Запись PSK DPAPI-блоба (TLV 0xBB010002), 5×64B |
| `McuWrite`   | `0xB1` | `0xF0`  | Запись калибровки (102 блока, индексы 0–101) |
| `McuWrite`   | `0x6E` | `0xE0`  | Запись PSK WB-блоба (TLV 0xBB010003), 4×64B |
| `McuGetPsk`  | `0xB4` | —       | Чтение/верификация PSK с MCU |
| `PresetPskWriteR` | `0xE0` | — | Sub-cmd в теле McuWrite (первый байт data) |

## TLV теги хранилища PSK на MCU

| Тег | Содержимое |
|-----|-----------|
| `0xBB010001` | Открытый PSK (незащищённый) |
| `0xBB010002` | DPAPI-зашифрованный PSK (Windows CryptProtectData) |
| `0xBB010003` | WB-зашифрованный PSK (WhiteBox AES, Wbdi.dll) |
| `0xBB020001` | SHA-256(PSK) — хеш для верификации |

## TLS

Протокол: `PSK-AES128-CBC-SHA256` (TLS ciphersuite `0x00AE`)  
Длина PSK: 32 байта  
Хранится как TLV 0xBB010003 в WB-блобе (96B).

TLS роли: **сенсор = TLS client**, хост (Windows/libfprint) = TLS server.

### Важно: TLS — однонаправленный

После TLS handshake хост **НЕ** шифрует команды — они идут как обычные A0 plaintext.  
TLS применяется только в одном направлении: **сенсор шифрует fingerprint image** в B2-фреймах  
используя `client_write_key` (cwk).

Подробнее: `docs/re/TLS_TRAFFIC.md`.

### P0 проблема TLS (РЕШЕНА)

OpenSSL при ответе сервера (ServerHello) добавляет расширение `renegotiation_info` (RFC 5746).  
Прошивка GM168SEC использует mbedTLS старой версии — не ожидает это расширение.  
Из-за этого хеш TLS handshake расходится → MAC fail → сессия обрывается.

**Решение:** кастомная state machine, ServerHello **без** `renegotiation_info`.  
Handshake проверен на `patches/all.pcapng`: ClientFinished MAC=OK, ServerFinished MAC=OK.

## Структура pcap (captures/goodix_full.pcapng)

**Тип захвата**: единоразовая provisioning-сессия (запись PSK), НЕ нормальная работа.

### Init последовательность (provisioning = единоразово)
| Фреймы     | Команда              | Что происходит                               |
|------------|----------------------|----------------------------------------------|
| 413–417    | SetDrvState2 (0xA8)  | Инициализация драйвера                       |
| 418–519    | McuGetPsk (0xB4) ×15 | Чтение текущего состояния PSK (проверка)     |
| 520–528    | McuWrite PSK (0xB1)  | Запись PSK в DPAPI-блобе, sub=0xE0, 5×64B   |
| 534–540    | McuWrite WB (0x6E)   | Запись WB-блоба, 4×64B = 256B               |
| 546–558    | McuGetPsk (0xB4) ×3  | Верификация записи PSK                       |
| 564        | SetConfig (0xA6)     | Конфигурация                                 |
| 570–1984   | McuWrite Calib (0xB1)| 102 блока калибровки, sub=0xF0, индексы 0–101|
| 1998       | GetPowerMode (0x08)  | Проверка питания                             |
| 2006       | DelAllTemplate (0xC4)| Очистка тестовых шаблонов                   |
| 2012       | SetConfig (0xA6)     | Финализация                                  |

### TLV в PSK write фреймах
- `0xBB010002` (PSK_DPAPI): @g1[29] длина=324B (Windows DPAPI blob)
  - DPAPI magic: `d08c9ddf0115d1118c7a00c04fc297eb`
  - UTF-16 description: "This is the description string."
- `0xBB010003` (PSK_WB): @g2[105] длина=96B (**ПОДТВЕРЖДЁН**)
  - IV = `ec35ae3abb45ed3f12c4751f1e5c2cc0`
  - CT = `18e97cc54fb96637a09dbde6bb87efc873287db6593c428c01affa68935ee9736867026173973...`
  - MAC (HMAC-SHA256) = `b22655c67a57d9bfddee98554b6de56a47238ce1329d5e22b401634e58c208e1`

### PSK (расшифрован из WB блоба, верифицирован ✓)
```
PSK = a12ba179ea7f00f6c70105b1d91dfe2e92d389053cb08603b63c4afba24a4c99
```

### Вывод: Сценарий A подтверждён
PSK записывается один раз при первичной provisioning-сессии.  
После этого хранится в MCU NVRAM и переживает перезагрузки.  
На Linux драйвер должен: прочитать WB-блоб → расшифровать → использовать как TLS PSK.
