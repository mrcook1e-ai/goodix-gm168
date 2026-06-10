# POST-TLS Init последовательность — GM168SEC

Источник: `patches/all.pcapng` (USBPcap внутри Windows 11 KVM)  
Скрипт анализа: `scripts/extract_post_tls.py`

---

## Контекст

После успешного TLS handshake (сенсор = TLS client, хост = TLS server) Windows
отправляет ряд plaintext A0-команд **до** SESSION_INIT. Наш драйвер пропускал
этот блок и прыгал прямо в SESSION_INIT — сенсор молчал в ответ.

---

## Полная Windows-последовательность после TLS (all.pcapng)

```
✓ TLS ESTABLISHED

→ SET_PARAM  (0x90)  [256B]   ← конфигурация регистров сенсора
← ACK(0xB0) status=0x90       ← IMMEDIATE ACK
← ACK(SET_PARAM) status=0x01  ← FINAL ACK

→ DEL_TMPL   (0xC4)  [2B] 0100   ← удалить шаблон слот 1
← ACK(0xB0) status=0xc4
→ DEL_TMPL   (0xC4)  [2B] 0100   ← второй раз
← ACK(0xB0) status=0xc4

→ STORE_PSK  (0xD2)  [2B] 0000   ← сохранить PSK в NVM сенсора
← ACK(0xB0) status=0xd2
← ACK(STORE_PSK) status=0xff     ← сенсор возвращает BAD_CMD, Windows игнорирует

→ UNK_36     (0x36)  [35B] ...   (пропущено в нашей реализации)
→ VERSION    (0x20)  [10B] 0100... → B2 fingerprint image
→ UNK_36     (0x36)  [35B] ...
→ UNK_70     (0x70)  [2B] 1400   (пропущено)
→ CHIP_INFO  (0x82)  [5B] ...
→ VERSION    (0x20)  [10B] ...   → B2
→ UNK_36     (0x36)  [35B] ...
→ DEL_TMPL   (0xC4)  [2B] 0100
→ UNK_AC     (0xAC)  [40B] ...   (пропущено)

→ SESSION_INIT (0x60) [2B] 0100
← ACK(0xB0) status=0x60

→ POWER (0xD6) [2B] 0000
← ACK(0xB0) status=0xd6
← ACK(POWER) status=0xff         ← сенсор возвращает BAD_CMD, Windows игнорирует

→ ARM  (0xAE)  [3B] 000100
→ FDT_REARM (0x34) [35B] ...     ← с правильными ADC-порогами
→ VERSION scan ×2  → B2 (тёмный фон)
→ FDT_SETUP (0x32) [35B] ...
→ VERSION scan     → B2
→ FDT_REARM (адаптивный) [35B]   ← пороги вычислены по тёмному фону
→ ARM, FDT_REARM, SESSION_INIT, ARM [3B] 010001
```

---

## Ключевые выводы

### 1. SET_PARAM (0x90) — обязательно

256-байтный блок параметров регистров сенсора. Отсутствует в нашей прежней
реализации. Без него сенсор, по всей видимости, отвергает SESSION_INIT.

Payload (256B) извлечён из `all.pcapng` → сохранён в `goodix_proto.c` как
`goodix_gm168_set_param[]`.

### 2. DEL_TMPL (0xC4) × 2 — очистка перед сессией

Отправляется дважды, payload `{0x01, 0x00}`. Возможно, очищает буферы шаблонов
перед начом новой записи.

### 3. STORE_PSK (0xD2) — сенсор возвращает 0xFF

Windows отправляет STORE_PSK и игнорирует ответ 0xFF (BAD_CMD). Означает, что
сенсор не поддерживает эту операцию в данном контексте. **Не реализуем** — риск
сбоя ack_cb при 0xFF в buffer[8] IMMEDIATE ACK (статус неизвестен).

### 4. POWER (0xD6) между SESSION_INIT и ARM — игнорируемый 0xFF

Windows отправляет `0xD6 {0x00, 0x00}` после SESSION_INIT и также получает 0xFF.
Скорее всего это "power mode query" или заглушка. Реализовано — безопасно, т.к.
ack_cb проверяет buffer[8] (IMMEDIATE status), а не buffer[7] (FINAL status).

### 5. FDT пороги — были неверными

| Байты        | Старое значение | Правильное (Windows) |
|-------------|----------------|----------------------|
| fdt_setup[14] | `0xa3`       | `0xa2`               |
| fdt_setup[16] | `0xb6`       | `0xb5`               |
| fdt_setup[20] | `0xb6`       | `0xb5`               |
| fdt_rearm[10] | `0xa1`       | `0xb2`               |
| fdt_rearm[12] | `0x24`       | `0xc4`               |
| fdt_rearm[14] | `0x24`       | `0xa2`               |
| fdt_rearm[16] | `0x97`       | `0xb5`               |
| fdt_rearm[18] | `0xa0`       | `0xa2`               |
| fdt_rearm[20] | `0x9c`       | `0xb5`               |

FDT_REARM определяет ADC-пороги детектора касания пальца. Старые значения
(например `0x24` = 36) были явно некорректны.

---

## Пропущенные команды (deferred)

| Команда | Почему пропущено |
|---------|-----------------|
| STORE_PSK (0xD2) | Возвращает 0xFF — непредсказуемое поведение IMMEDIATE ACK |
| UNK_36 (0x36) | Неизвестное назначение; похоже на FDT-подобный блок |
| UNK_70 (0x70) `{0x14,0x00}` | Неизвестно |
| UNK_AC (0xAC) [40B] | Содержит FDT-пороги — возможно, альтернативный FDT_SETUP |
| Adaptive FDT_REARM | Пороги вычисляются по тёмному фону; мы используем initial |

---

## Особенность протокола: IMMEDIATE vs FINAL ACK

Каждая команда генерирует два ответа:

```
IMMEDIATE ACK: [A0][len][hsum][0xB0][plenL][plenH][echo_cmd][imm_status][bsum]
FINAL ACK:     [A0][len][hsum][echo_cmd][plenL][plenH][status][bsum]
```

Наш `ack_cb` проверяет `buffer[8]`:
- Для IMMEDIATE ACK: `buffer[8]` = `imm_status` (обычно `0x00`)
- Для FINAL ACK: `buffer[8]` = `bsum` (никогда не равен `0xFF` в реальных случаях)

Это значит, что ack_cb корректно продвигается вперёд и не падает на FINAL ACK
с `status=0xFF` (команды POWER, STORE_PSK). Windows в отличие от нас ждёт FINAL
ACK перед отправкой следующей команды.

---

## Что изменено в коде

### `src/goodix_proto.h`
- Добавлены `#define GOODIX_GM168_CMD_SET_PARAM 0x90`
- Добавлены `#define GOODIX_GM168_CMD_DEL_TMPL 0xC4`
- Добавлены `#define GOODIX_GM168_CMD_STORE_PSK 0xD2`
- Добавлены `extern` декларации для `goodix_gm168_set_param[]` и `goodix_gm168_del_tmpl[]`

### `src/goodix_proto.c`
- Добавлен `goodix_gm168_set_param[256]` — 256 байт из Windows pcap
- Добавлен `goodix_gm168_del_tmpl[] = {0x01, 0x00}`
- Исправлены пороги `goodix_gm168_fdt_setup[]` (3 байта)
- Исправлены пороги `goodix_gm168_fdt_rearm[]` (6 байт — радикальное исправление)

### `src/goodix_gm168.c`
Добавлено 8 новых состояний в `enum init_states`:

| Состояние | Что делает |
|-----------|-----------|
| `INIT_SET_PARAM` | отправить SET_PARAM (0x90) [256B] |
| `INIT_SET_PARAM_ACK` | ждать ACK |
| `INIT_DEL_TMPL_1` | отправить DEL_TMPL (0xC4) [2B] |
| `INIT_DEL_TMPL_1_ACK` | ждать ACK |
| `INIT_DEL_TMPL_2` | повторить DEL_TMPL |
| `INIT_DEL_TMPL_2_ACK` | ждать ACK |
| `INIT_D6_POST` | отправить POWER (0xD6) [2B] после SESSION_INIT |
| `INIT_D6_POST_ACK` | ждать ACK |

Все три `fpi_ssm_jump_to_state(INIT_SESSION)` после завершения TLS заменены
на `fpi_ssm_jump_to_state(INIT_SET_PARAM)`.

---

## Итоговый init flow (после изменений)

```
WAKEUP → RESET → VERSION → PSK_GATE → TLS_START → TLS handshake
  └─(TLS done)─→ SET_PARAM → DEL_TMPL×2
                           → SESSION_INIT → D6_POST → ARM
                                                    → FDT_SETUP
                                                    → BG_TRIG×5 → ...
```
