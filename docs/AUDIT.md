# Transport/HW Layer — Code Audit

Дата: 2026-06-05. Сделано по содержимому
[src/goodix_gm168.c](../src/goodix_gm168.c) (2433 строки),
[src/goodix_tls.c](../src/goodix_tls.c) (312 строк),
[src/goodix_proto.c](../src/goodix_proto.c) (270 строк).

Цель — построчно зафиксировать **что сейчас есть и где течёт**, чтобы из этого
вырастить план в [HARDENING.md](HARDENING.md). Это не "что делать", это "что
плохо лежит". Find-only.

Каждая находка имеет тяжесть:

- **🔴 C (critical)** — реально стреляет в проде: hang, краш, утечка, UB.
- **🟠 H (high)** — деградация надёжности или скрытый баг в редких путях.
- **🟡 M (medium)** — пахнет, может стрельнуть после рефакторинга.
- **🔵 L (low)** — стиль / техдолг, мешает читать.

---

## 1. Карта файла

```
goodix_gm168.c (2433 LOC)
  1–164     constants, FpDeviceGoodixGm168 struct
  165–181   quality-gate tunables
  183–280   PSK file I/O
  281–820   image pipeline (CLAHE, envelope-stretch, BG, decode_frame)
  821–950   ACK plumbing (ack_cb, ack_resubmit_or_fail, transfer_cb,
            async_send_cmd, async_recv_ack)
  951–985   DEINIT SSM
  988–1031  init TLS rx/tx callbacks
  1041–1163 PSK 0xE4 walk
  1167–1549 INIT SSM (run_state + init_completed)
  1552–1747 CAPTURE SSM
  1749–2015 capture_completed (decode + quality-gate)
  2017–2102 polling loop
  2104–2146 quality metric
  2148–2285 REARM SSM (+ retry variant)
  2287–2404 libfprint glue (open/close/activate/deactivate/change_state)
  2406–2432 driver registration

goodix_tls.c (312 LOC)
  1–138     OpenSSL PSK server, accept thread
  142–196   init
  198–227   feed / pull
  229–282   recv / send (with WANT_READ retry loop)
  284–312   deinit
```

Из этой карты сразу видно: 2433 строки в одном файле, в т.ч. весь image
pipeline + транспорт + state-machines + libfprint glue. **Это самая большая
проблема в обзорности**, см. §6.

---

## 2. Транспорт — что есть

### 2.1 USB submit-точки и их таймауты

| Где                                              | Direction | Timeout (ms) | Cancellable | Callback         |
|--------------------------------------------------|-----------|--------------|-------------|------------------|
| [:853] `ack_resubmit_or_fail` re-listen         | RX        | 2000         | **NULL**    | `ack_cb`         |
| [:938] `async_send_cmd` standard TX             | TX        | 2000         | **NULL**    | `transfer_cb`    |
| [:949] `async_recv_ack` standard RX             | RX        | param        | **NULL**    | `ack_cb`         |
| [:1115] PSK `0xE4` re-listen                    | RX        | 2000         | **NULL**    | `psk_read_rx_cb` |
| [:1242] PSK `0xE4` first read                   | RX        | 2000         | **NULL**    | `psk_read_rx_cb` |
| [:1270] init TLS RX                             | RX        | 1000         | **NULL**    | `init_tls_rx_cb` |
| [:1288] init TLS TX-pull pump                   | TX        | 2000         | **NULL**    | `init_tls_tx_cb` |
| [:1348] BG first read                           | RX        | 2000         | **NULL**    | `bg_rx_cb`       |
| [:1625] BG re-listen                            | RX        | 2000         | **NULL**    | `bg_rx_cb`       |
| [:1650] CAP_RX                                  | RX        | 1000         | **NULL**    | `capture_rx_cb`  |
| [:2100] polling                                 | RX        | 1000         | `poll_cancellable` | `poll_cb`  |

Наблюдения:

- **🟠 H1.** Только **одна** submit-точка (`start_polling`) использует
  `GCancellable`. Все остальные (~10 штук) передают `NULL`. Это значит, что
  `dev_deactivate` (см. [:2335]) рассчитывает только на гонку
  `self->deactivating = TRUE` против already-in-flight transfers. Поскольку
  libfprint не может отменить такие transfers, они просто **дорабатывают свой
  таймаут** (1–2 секунды) после deactivate. Это видно в callback'ах: все они
  проверяют `deactivating` руками. Работает, но deactivate стоит до 2 секунд
  висящего состояния.

- **🟡 M1.** Магические числа таймаутов — `2000`/`1000`/`1500` повторены
  десятки раз. Если решим уменьшить REARM_DELAY до 1200ms — придётся искать
  все вхождения вручную. Нет таблицы `state → timeout`.

- **🟠 H2.** Несовпадение `CAP_RX timeout (1000ms)` и `BUDGET_MS (600ms)`
  ([:1650] vs [:180]). Если capture стартует и сенсор молчит, мы потеряем
  400 ms до того, как quality-gate проверит budget на следующей итерации.

### 2.2 Классификация ошибок USB

Распознаются только два кода:

- `G_USB_DEVICE_ERROR_TIMED_OUT` — [:1001, :1565, :2040]: re-listen / retry.
- `G_IO_ERROR_CANCELLED` — [:866, :921, :1587, :2047]: silent abort.

Всё остальное (`NO_DEVICE`, `IO`, `PROTOCOL_ERROR`, `NOT_SUPPORTED`) идёт
через универсальный `fpi_ssm_mark_failed(error)`. То есть **device removal
неотличим от sensor wedge неотличим от libusb internal error**.

- **🟠 H3.** Нет различия `NO_DEVICE` vs `IO`. Hotplug → один error, recover()
  не может выбрать стратегию (повторить vs закрыть сессию).
- **🟡 M2.** `psk_read_rx_cb` [:1086] вообще НЕ обрабатывает таймаут отдельно
  — любая ошибка `→ mark_failed`. Если сенсор тормознёт на 2001 ms — провал
  инициализации; человек думает «PSK не читается», на деле просто долгий
  ответ.

### 2.3 Retry counters

| Counter             | Cap   | Where reset                                  |
|---------------------|-------|----------------------------------------------|
| `ack_retry`         | 60    | каждый успешный advance в `ack_cb` [:896,:904]; psk [:1141]; bg [:1603] |
| `tls_retry`         | 60    | при первом успешном TLS_RX [:1260]; при handshake done [:1295] |
| `capture_attempt`   | 6     | в `poll_cb` на touch [:2071] и после submit [:1996] |
| `sealed_offset`     | 324 B | в `dev_activate` [:2299]                     |

Анализ:

- **🟡 M3.** `ack_retry` — **единственный** счётчик ретраев для всех ACK
  путей, и он *сбрасывается* при advance. То есть «застрял в одном state»
  ловится, но «сенсор отвечает на каждый 30-й cmd с задержкой 2с» (~2 минуты
  на init) — нет.
- **🟠 H4.** Между этими тремя счётчиками нет **общего** wall-clock
  watchdog'а. Init может суммарно работать произвольно долго.

### 2.4 Состояние объекта при error/abort

`FpDeviceGoodixGm168` имеет:
- `img_buf`, `stitch_buf`, `background`, `background_sum`, `best_img`,
  `sealed_psk[offset]`, `tls`, `poll_transfer`.

Проверки очистки:

| Поле               | `dev_activate` reset | `dev_deactivate` reset | mid-session error |
|--------------------|----------------------|------------------------|-------------------|
| `best_img`         | clear [:2305]        | clear [:2342]          | clear [:1771]     |
| `img_buf`          | **НЕТ**              | **НЕТ**                | implicit via img_len=0 |
| `stitch_buf`       | size→0 [:2329 lazy]  | **НЕТ free**           | size→0 [:2022]    |
| `background_sum`   | clear [:2301]        | **НЕТ**                | —                 |
| `tls.ssl`          | re-init [:2312]      | **НЕТ**                | —                 |

- **🔴 C1.** `dev_deactivate` НЕ тушит TLS. Если fprintd делает
  activate → deactivate → activate (типичный pattern перед enroll), второй
  activate натыкается на живой `self->tls.ssl` и `goodix_gm168_tls_deinit`
  ([:2312]) — это спасает, но: между двумя activate'ами поток TLS живёт,
  держит fd'ы и socketpair'у. Если deactivate был из-за сбоя, поток мог
  застрять в `SSL_accept` на blocking sock_fd до закрытия в `dev_open`.
  Реально замечалось как «init не стартует второй раз без unplug».
- **🟠 H5.** `img_buf` никогда не освобождается до `dev_close`. Это не leak в
  смысле libc, но если drvr реactivate'ится, мы переиспользуем буфер с
  `img_len=0` — данные старой сессии лежат в памяти до перезаписи. Не
  security-issue (один и тот же пользователь), но смущает.
- **🟡 M4.** `stitch_buf` в `dev_deactivate` не freed, освобождается только
  в `dev_close` [:2395]. То же что H5.

---

## 3. State machines — что есть

### 3.1 INIT SSM (30 states, [:67–:107])

Поток: WAKEUP→RESET→VERSION→PSK_GATE→TLS→SESSION→ARM→FDT→BG×5→REARM-once.

- **🟡 M5.** `INIT_TLS_RX` имеет специальный таймаут-handler [:1001] который
  переходит в `INIT_SESSION` если `tls_done`. Это завязано на флаг,
  выставляемый из *другого* потока (`on_tls_done` callback из TLS thread).
  Race: между проверкой `if (self->tls_done)` и установкой флага нет
  синхронизации. На практике сериализуется через GLib main loop, но в
  коде это не видно — комментария нет.
- **🟠 H6.** Если init упал на любом этапе после TLS — `init_completed`
  не делает explicit cleanup TLS thread'а. Он живёт до следующего
  activate (где `goodix_gm168_tls_deinit` всё чистит). См. C1.
- **🟡 M6.** BG_LOOP_CHECK [:95-96] — нестандартный паттерн "крутить до
  N итераций, потом fall-through". Читается тяжело, поломать легко.

### 3.2 CAPTURE SSM ([:1553])

3 state'а: TRIG / RX / PROCESS. PROCESS парсит B0/B2/A0 пакеты, при
неизвестном type **дропает весь stitch_buf** [:1735].

- **🟠 H7.** Любой мусор в потоке → потеря всех буферизованных байт. Если
  сенсор отправил `[B2-half1][garbage 4B][B2-half2]`, мы дропнем half1 +
  half2. На практике это не наблюдалось, но **тест на corruption
  отсутствует**.
- **🟡 M7.** `CAP_PROCESS` после обработки всех пакетов в буфере делает
  `fpi_ssm_jump_to_state(ssm, CAP_RX)` [:1740] — даже если буфер пуст и
  фрейм собран. Лишний RX → блокируется на 1000 ms → попадает в timeout
  retry [:1565] → ещё один RX. Видно как «лишние 1–2 секунды после
  успешного capture». Должен быть `if (img_len >= FRAME_SIZE) → mark_completed`
  на верхнем уровне, а не закопанный внутрь B2 branch [:1714].
- **🟠 H8.** `capture_rx_cb` [:1567] на timeout **прыгает в CAP_RX а не в
  CAP_PROCESS**. То есть если TRIG прошёл, но сенсор молчит — мы перезаход
  в RX без отправки нового TRIG. Если сенсор «забыл» о TRIG (что бывает после
  reset) — зависнем в RX-loop до budget.

### 3.3 REARM SSM ([:2150])

9 state'ов. Используется **двумя** entry-функциями: `start_rearm_ssm` (после
submit) и `start_rearm_retry_ssm` (внутри quality-gate). Различие — `rd->retry`
флаг, ветвящий `REARM_DELAY` [:2197].

- **🟡 M8.** `rearm_completed` [:2230] **игнорирует ошибку**: `g_error_free + продолжить`.
  Это значит, что если REARM упал (sensor wedged), мы всё равно вызовем
  `fpi_image_device_image_captured`. libfprint счастлив, но следующий touch
  встретит мёртвый сенсор.
- **🟠 H9.** Все ACK-стейты используют `async_recv_ack(ssm, dev, 1000)` либо
  `2000`. При ошибке (не таймауте) — `mark_failed → rearm_completed`. Но
  `rearm_completed` ошибку игнорирует. Двойная ошибка: ACK fail логируется,
  но сенсор остаётся в неизвестном state.

### 3.4 POLL loop ([:2032])

- **🟡 M9.** `start_polling` идемпотентно [:2092] — хорошо. Но
  `poll_transfer = NULL` ставится **сразу** в начале `poll_cb` [:2037], до
  всей обработки. Если внутри обработки происходит re-entry через
  `start_capture_ssm → ... → start_polling`, второй submit пройдёт.
  Сценарий очень маловероятен (GLib serializes), но защита не явная.

### 3.5 DEINIT SSM ([:953])

Одно состояние: отправить `power off`. Не ждёт ACK'а.

- **🟡 M10.** `deinit_completed` [:974] игнорирует ошибки. Если power-off
  пакет не ушёл, сенсор может остаться в TLS-сессии. Следующий activate
  делает 0x60 RESET, который это лечит, но «грязная» деактивация
  оставляет сенсор есть ток.

---

## 4. TLS layer — что есть

Файл [src/goodix_tls.c](../src/goodix_tls.c) — отдельный поток + socketpair.

- **🔴 C2.** [:114] `SSL_accept` блокируется на blocking sock_fd. Если
  handshake застрял (MCU не отвечает на ServerHello) — поток висит
  **навсегда**, потому что в TLS layer нет таймаутов. `dev_deactivate`
  не закрывает sock_fd. Только `goodix_gm168_tls_deinit` (вызывается в
  следующем `dev_activate` или `dev_close`) закроет fd и разбудит accept.
  То есть **между deactivate и close мы держим залипший поток**.
- **🟠 H10.** [:245] `SSL_read` имеет **внутренний retry loop** на
  WANT_READ: 50 итераций × 5ms = 250 ms блокирующего ожидания в **main
  thread**. Это вызывается из `CAP_PROCESS` [:1700]. То есть на каждый B2
  пакет мы можем подвесить main loop на 250 ms. На enroll это
  замечается как «капча подёргивается».
- **🟠 H11.** [:201] `tls_feed` пишет через `write()` без проверки
  partial-write. Лог пишет о short_write [:208], но никто его не ловит.
  Если буфер socketpair заполнится — потеряем байты.
- **🟡 M11.** [:142] `goodix_gm168_tls_init` вызывает глобальные
  `SSL_load_error_strings()` / `OpenSSL_add_ssl_algorithms()` на каждый
  activate. Это идемпотентно в современном OpenSSL, но в OpenSSL 1.0 даёт
  warning'и в логах.
- **🟡 M12.** Нет API `gm168_tls_reset()` — на TLS error единственный путь
  это полный teardown + новый `goodix_gm168_tls_init`, что включает создание
  нового потока. Слишком тяжело для in-session recovery.

---

## 5. Libfprint glue — что есть

- **🟡 M13.** [:2375] `dev_open`/`dev_close` синхронны и НЕ держат cancellable.
  Если interface claim упал — libfprint получит error, но кто-то всё ещё мог
  держать ссылку на device. Очень редкий путь.
- **🟠 H12.** [:2356] `dev_change_state` обрабатывает только два state:
  `AWAIT_FINGER_ON` и `AWAIT_FINGER_OFF`. Остальные (CAPTURE,
  ENROLL_*, ANALYZE_DATA) молча игнорируются — `active_state = FALSE`.
  Это может привести к **остановке polling** в момент, когда libfprint
  ожидает что мы capture-ready. На текущей версии libfprint работает,
  на новой может сломаться.
- **🟡 M14.** Нет `dev_probe`, `dev_suspend`, `dev_resume`. Suspend/resume
  laptop ⇒ libfprint вызовет deactivate+activate (если повезёт). Но
  явной обработки suspend нет.

---

## 6. Структурные

- **🔵 L1.** 2433 LOC в одном `.c` — pipeline и transport смешаны. Любая
  правка transport требует пересборки всего файла.
- **🔵 L2.** Двуязычные комментарии (русский в `goodix_tls.c`, английский
  в `goodix_gm168.c`). Не баг, но при росте команды → kostyl.
- **🔵 L3.** `fp_dbg`/`fp_warn`/`g_printerr`/`g_debug` смешаны. Часть TLS
  пишет в stderr напрямую — обходит libfprint logging.
- **🔵 L4.** `#ifdef GM168_DEBUG` дампит файлы в `/tmp` — нет cleanup'а,
  забивает диск при долгом сеансе.

---

## 7. Сводка по тяжести

### 🔴 Critical (2)
- **C1** [:2335] deactivate не убирает TLS thread → застрявший поток после
  failed activate.
- **C2** [tls.c:114] SSL_accept blocking без таймаута → handshake hang =
  вечная нить.

### 🟠 High (12)
- **H1** Submit'ы без `GCancellable` → deactivate висит до 2c.
- **H2** CAP_RX timeout (1000ms) > BUDGET_MS (600ms).
- **H3** Нет различения `NO_DEVICE` vs `IO`.
- **H4** Нет общего wall-clock watchdog'а.
- **H5** `img_buf` живёт между сессиями.
- **H6** Init fail после TLS не чистит TLS thread.
- **H7** `CAP_PROCESS` дропает stitch_buf на unknown type.
- **H8** `capture_rx_cb` на timeout → CAP_RX вместо CAP_TRIG (повторный
  trigger потерян).
- **H9** REARM ACK fail → `rearm_completed` игнорирует, сенсор остаётся
  в неизвестном state.
- **H10** `SSL_read` 250ms blocking retry в main thread.
- **H11** `tls_feed` partial-write не обрабатывается.
- **H12** `dev_change_state` обрабатывает 2 из ~6 libfprint state'ов.

### 🟡 Medium (14)
- M1 Магические таймауты разбросаны.
- M2 `psk_read_rx_cb` не отличает timeout.
- M3 `ack_retry` сбрасывается на advance.
- M4 `stitch_buf` free только в close.
- M5 `tls_done` гонка комментариев нет.
- M6 `INIT_BG_LOOP_CHECK` хрупкий fall-through.
- M7 `CAP_PROCESS` всегда → CAP_RX.
- M8 `rearm_completed` глотает ошибку.
- M9 `poll_transfer = NULL` ставится до обработки.
- M10 `deinit_completed` глотает ошибку.
- M11 OpenSSL globals в init.
- M12 Нет `tls_reset()` API.
- M13 `dev_open`/`close` без cancellable.
- M14 Нет `suspend`/`resume`.

### 🔵 Low (4) — стиль
L1 моно-файл, L2 двуязычие, L3 mixed logging, L4 debug dumps без cleanup.

---

## 8. Что НЕ нашли (важно для honesty)

- Реальных утечек памяти в горячих путях не видно — `g_free`/`g_object_unref`
  парные. Quality-gate `best_img` имеет три точки сброса.
- Buffer overflow не виден — `goodix_gm168_decode_*` валидируют длины.
- Race condition между ACK и POLL не виден — все идут через GLib main loop.
- PSK file race (TOCTOU) — есть, но scope = `/etc`, не считаем.

---

## 9. Куда это ведёт

Шесть пунктов из [HARDENING.md](HARDENING.md) §2 покрывают эти находки:

| Hardening item | Покрываемые находки |
|----------------|---------------------|
| G1 SSM deadline | H4, M3                          |
| G2 budget sync  | H2                              |
| G3 USB classification | H3, M2                    |
| G4 recover SSM  | H8, H9, M8                      |
| G5 hotplug      | H3 (partial), M14               |
| G6 TLS reset    | C1, C2, H6, H10, M12            |
| G7 tracing      | M1 (foundation for table)       |

Непокрытые (нужно добавить в HARDENING.md):

- **H1** — global `GCancellable` для всех submit'ов.
- **H5** — `img_buf` truncate в deactivate.
- **H7** — `CAP_PROCESS` ресинхронизация на потерянный байт.
- **H11** — `tls_feed` partial-write handling.
- **H12** — расширить `dev_change_state` под все states.
- **M5** — explicit barrier на `tls_done`.
- **M6** — рефакторинг BG_LOOP_CHECK в честный счётчик.
- **M9** — `poll_transfer = NULL` после обработки.
- **M10** — `deinit_completed` пропагирует ошибку.
- **M13** — `dev_open` async (если libfprint позволяет).

Следующий шаг: обновить [HARDENING.md](HARDENING.md) на основе этого
списка (добавить G8..G15 или растворить в существующие пункты), и
**только после этого** браться за код.
