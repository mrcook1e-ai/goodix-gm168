# Goodix GM168SEC — результаты 42 часов работы

## Статус: TLS handshake ✓ | Post-TLS init fix ✓ (deployed, awaiting test)

---

## Что сделано

### 1. PSK извлечён ✓

**Проблема:** libfprint не работает без PSK. PSK хранится в MCU как WB-зашифрованный блоб.

**Решение:**
- Декодирован алгоритм WhiteBox из `Wbdi.dll` (метод `var_488`)
- PSK извлечён из provisioning pcap (`captures/goodix_full.pcapng`)
- Верифицирован: AES-128-CBC с ключом из `sha256(32LE + "123GOODIX")` → SHA256-seed → truncate
- Записан в `/etc/goodix-gm168/psk.bin` на Fedora-машине

```
PSK = a12ba179ea7f00f6c70105b1d91dfe2e92d389053cb08603b63c4afba24a4c99
```

Скрипт: [`scripts/goodix_get_psk.py`](../scripts/goodix_get_psk.py) — чтение PSK напрямую с сенсора (для сенсоров с WB-блобом).

---

### 2. Goodix frame format разобран ✓

**Внешний фрейм (из `goodix_proto.c`):**
```
[A0][LenL][LenH][HdrSum][Cmd][PLenL][PLenH][Payload...][BodySum]
```
- `HdrSum = (0xA0 + LenL + LenH) & 0xFF`
- `BodySum = (0xAA - (Cmd + PLenL + PLenH + sum(Payload))) & 0xFF`
- `plen = payload_len + 1` (включает BodySum)
- `inner_sz = 3 + payload_len + 1`

**B0 TLS-wrapper:**
```
[B0][LenL][LenH][HdrSum][TLS-record...]
```
- `HdrSum = (0xB0 + LenL + LenH) & 0xFF`

**A0 ACK-ответ:**
```
[A0][LenL][LenH][HdrSum][B0][PlenL][PlenH][EchoCmd][Status][BodySum]
                          4    5     6       7         8
```

---

### 3. Кастомный TLS state machine написан ✓

OpenSSL ломал handshake из-за расширения `renegotiation_info` в ServerHello, которое старый mbedTLS в MCU не ожидает.

**Файлы:**
- `goodix_tls.c` — основной state machine (TLS_S_AWAITING_CLIENT_HELLO → TLS_S_ESTABLISHED)
- `goodix_tls_handshake.c` — парсеры/генераторы HS-сообщений
- `goodix_tls_prf.c` — TLS 1.2 PRF (P_SHA256, HMAC-SHA256)
- `goodix_tls_record.c` — AES-128-CBC + HMAC-SHA256, MAC-then-Encrypt

**Схема:**
```
Sensor (TLS client)          Driver (TLS server, наш код)
───────────────────          ────────────────────────────
ClientHello          →
                     ←  ServerHello (NO renegotiation_info)
                     ←  ServerHelloDone
ClientKeyExchange    →       (PSK identity = "Client_identity", 15 bytes)
ChangeCipherSpec     →
ClientFinished       →       verify_data проверен ✓
                     ←  ChangeCipherSpec
                     ←  ServerFinished (verify_data вычислен)
```

**Cipher suite:** `PSK-AES128-CBC-SHA256` (`0x00AE`)

**PRF для master secret:**
```
PMS = uint16_be(32) || zeros(32) || uint16_be(32) || PSK   (68 байт)
MS  = PRF(PMS, "master secret", ClientRandom || ServerRandom, 48)
KB  = PRF(MS,  "key expansion", ServerRandom || ClientRandom, 96)
```

Key block layout: `cwmk[32] | swmk[32] | cwk[16] | swk[16]`

**Результат:** `goodix-gm168: TLS handshake complete ✓` — стабильно воспроизводится.

---

### 4. Инит-последовательность исправлена ✓

**Рабочая последовательность:**
```
WAKEUP (0x11) — no ACK
DELAY 50ms
SESSION_INIT (0x60 {01 00}) — echo=0x60, status=0x01
VERSION (0x20) — echo=0x20, status=0x01
TLS_START (0xD0 {00 00}) — echo=0xD0, status=0x01
[TLS handshake loop]
CCS + ServerFinished →
```

Удалено: POST-TLS `SESSION_INIT` (дубликат pre-TLS команды, вызывал таймаут).

---

---

## Сессия 2 — Post-TLS root cause найдена и исправлена

### 5. Root cause post-TLS silence: SET_PARAM не отправлялся ✓

**Анализ `patches/all.pcapng`** показал, что Windows перед SESSION_INIT отправляет
256-байтный пакет `SET_PARAM (0x90)` — карта регистров сенсора. Наш драйвер пропускал его.

**Дополнительно:** FDT_REARM пороги в коде были полностью неверными (0x24=36 вместо 0xb2=178).

**Что сделано:**
- Добавлены 8 новых состояний в state machine: `INIT_SET_PARAM`, `INIT_DEL_TMPL_1/2`, `INIT_D6_POST`
- Добавлен 256-байтный payload `goodix_gm168_set_param[]` из Windows pcap
- Исправлены пороги `fdt_setup[]` (3 байта) и `fdt_rearm[]` (6 байт)
- Исправлены все 3 `fpi_ssm_jump_to_state(INIT_SESSION)` → `INIT_SET_PARAM`
- Изменения задеплоены на `mrcook1e@192.168.1.23:~/dev/goodix-gm168/src/`
- Собрано через `scripts/build.sh` — 0 ошибок, установлено в `/opt/libfprint-gm168/`

**Новый init flow:**
```
TLS ESTABLISHED → SET_PARAM → DEL_TMPL×2 → SESSION_INIT → D6_POST → ARM → FDT_SETUP → BG scan…
```

**Подробности:** [`docs/re/POST_TLS_INIT.md`](re/POST_TLS_INIT.md)

**Тест:** `bash ~/goodix-gm168/scripts/run.sh` на Fedora — ищи `INIT_SET_PARAM` / `INIT_DEL_TMPL_1` в логах.

---

## Бывшая нерешённая проблема: сенсор молчит после TLS

**Симптом:** После успешного TLS handshake сенсор не отвечает ни на одну TLS-зашифрованную команду. Transfer timeout 2000ms без единого байта.

**Что проверено:**
| Проверка | Результат |
|---|---|
| CF verify_data | ✓ совпадает (PRF/ключи верные) |
| master_secret | ✓ совпадает с логом (`889439ed2d96726d...`) |
| client_write_key | ✓ совпадает с логом (`f9ba056d828601b2...`) |
| B0 checksum | ✓ корректен |
| CCS отдельно, Finished отдельно | ✗ всё равно нет ответа |
| Ожидание 3 секунды после Finished | ✗ нет ответа |
| Plaintext 0x60 после TLS | ✗ нет ответа |
| Encrypted SESSION_INIT (0x60) | ✗ нет ответа |
| Encrypted ARM (0xAE) | ✗ нет ответа |
| Python manual TLS (независимая реализация) | ✗ тот же результат |

**Гипотезы (не проверены):**
1. **Server Finished verify_data неверный** — маловероятно (ключи верные, CF проходит), но точно проверить невозможно без расшифровки трафика с Windows-машины с рабочим сенсором
2. **MCU обрабатывает ServerFinished, но ждёт конкретную первую команду** — неизвестна правильная первая постhandshake-команда
3. **Сенсор требует доп. команду перед TLS** — например, cmd `0x43` (удалён как "legacy")
4. **Баг в transcript** — крайне маловероятно (CF проходит)

**Следующий шаг (наиболее перспективный):**  
Нужен USB-дамп рабочей Windows-сессии (Frida или WireShark/USBPcap) с полным TLS — IN + OUT. Без него нельзя знать какая первая команда ожидается после ServerFinished.

---

## Файловая структура

```
goodix-gm168/
├── captures/
│   └── goodix_full.pcapng          # provisioning pcap (OUT only)
├── docs/
│   ├── re/
│   │   ├── PCAP_ANALYSIS.md        # анализ pcap
│   │   ├── USB_PROTOCOL.md         # Goodix USB протокол
│   │   └── POST_TLS_INIT.md        # Windows post-TLS sequence + изменения
│   ├── RE_STACK.md
│   └── SESSION_RESULTS.md          # этот файл
├── scripts/
│   ├── goodix_get_psk.py           # читает PSK с сенсора напрямую
│   ├── decode_psk_frames.py        # декодирует PSK-фреймы из pcap
│   ├── parse_pcap.py               # полный анализ pcapng
│   ├── tls_manual.py               # ручной TLS-handshake для отладки
│   ├── tls_test2.py                # extended TLS тест с 3s wait
│   └── wb_*.py                     # WhiteBox AES исследование
└── src/
    └── goodix_gm168/               # (локальная копия, мод на Fedora)
        ├── goodix_gm168.c
        ├── goodix_tls.c
        ├── goodix_tls_handshake.c
        ├── goodix_tls_prf.c
        └── goodix_tls_record.c
```

## Тестовая среда

- **Fedora** `192.168.1.23` — сенсор подключён, dev-сборка libfprint
- **libfprint dev**: `/home/mrcook1e/dev/libfprint`
- **Build**: `cd /home/mrcook1e/dev/libfprint/build && ninja`
- **Запуск**:
  ```bash
  printf '6\nn\n' | sudo LD_LIBRARY_PATH=/home/mrcook1e/dev/libfprint/build/libfprint \
    GOODIX_GM168_DIR=/etc/goodix-gm168 G_MESSAGES_DEBUG=all \
    /home/mrcook1e/dev/libfprint/build/examples/enroll
  ```
- **PSK**: `/etc/goodix-gm168/psk.bin` (32 байта)

## Состояние кода на Fedora

**Текущий dev-путь:** `~/dev/goodix-gm168/src/` (собирается через `scripts/build.sh`)

**`goodix_gm168.c`:**
- 8 новых состояний в `enum init_states`: `INIT_SET_PARAM`, `INIT_SET_PARAM_ACK`, `INIT_DEL_TMPL_1/2`, `INIT_DEL_TMPL_1/2_ACK`, `INIT_D6_POST`, `INIT_D6_POST_ACK`
- 3 jump target изменены: `INIT_SESSION` → `INIT_SET_PARAM` (после TLS)
- 8 новых `case` в `init_run_state()`

**`goodix_proto.h`:**
- `#define GOODIX_GM168_CMD_SET_PARAM 0x90`
- `#define GOODIX_GM168_CMD_DEL_TMPL  0xC4`
- `extern goodix_gm168_set_param[]`, `extern goodix_gm168_del_tmpl[]`

**`goodix_proto.c`:**
- `goodix_gm168_set_param[256]` — из Windows pcap
- `goodix_gm168_del_tmpl[] = {0x01, 0x00}`
- FDT пороги исправлены (fdt_setup 3B, fdt_rearm 6B)

**Файлы добавлены ранее:** `goodix_tls.c`, `goodix_tls_handshake.c`, `goodix_tls_prf.c`, `goodix_tls_record.c`

**Установлено:** `/opt/libfprint-gm168/lib64/libfprint-2.so` (сборка 2026-06-09)
