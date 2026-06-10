# Expert Review — goodix-gm168

**Дата:** 2026-06-09
**Метод:** полное прочтение кодовой базы (6277 строк C) + 6-мерный аудит с состязательной верификацией (29 агентов).
**Скоуп:** `src/*.c`, `src/*.h`, `meson.build`, сверка с `docs/`.
**Статус:** actionable — пункты P1/P2 готовы к работе; формулировки выверены, ложные срабатывания помечены.

> Этот документ **заменяет** устаревший `docs/CODE_REVIEW.md` (там 3 «критических» бага уже исправлены — см. §«Уже исправлено»).

---

## TL;DR — вердикт

Инженерно зрелый драйвер, а не прототип. Упёрся в **одну стратегическую проблему** (восстановление сигнала / калибровка) для функции и в **набор косметики + один реальный resource-leak** для upstream.

**Главное:** post-TLS init, который чинили последним, — **не** причина verify-miss. Verify промахивается из-за пер-девайсной калибровки (Cal1/Cal2), а не из-за протокола/TLS.

---

## Доска приоритетов

| ID | Приор. | Тема | Файл:строка | Статус верификации |
|----|--------|------|-------------|--------------------|
| F0 | **P0** | verify-miss = пер-девайсная калибровка Cal1/Cal2 | `gm168_cal.h`, `goodix_gm168.c:484` | confirmed (high) |
| F1 | **P1** | Нет finalize/dispose → leak TLS-потока/SSL/fd/буферов | `goodix_gm168.c:3129`, `:3104` | confirmed (high) |
| F2 | **P1** | Мёртвый рукописный TLS ~716 строк (компилится, не вызывается) | `meson.build:17`, `goodix_tls_*.c` | confirmed (high) |
| F3 | **P1** | 16 КБ-буферы на стеке в 5 местах SSM | `goodix_gm168.c:1471,1601,1623,1968,1995` | partial (medium) |
| F4 | **P1** | `process_rx_buffer_for_tls` молча теряет усечённый хвост | `goodix_gm168.c:858-879` | partial (medium) |
| F5 | **P1** | `tls_pull` маскирует фатальные ошибки сокета | `goodix_tls.c:325-344` | confirmed (low/medium) |
| F6 | **P2** | Device-specific данные как код + мёртвые provisioning-константы | `goodix_proto.c:22-64`, `gm168_cal.h` | partial (high) |
| F7 | **P2** | Комментарии RU/EN вперемешку, в т.ч. в публичных `.h` | `goodix_proto.h`, `goodix_tls.c` … | confirmed (medium) |
| F8 | **P2** | 7 env-флагов препроцессора; часть ломает enroll | `goodix_gm168.c:790-799,2140,2204` | confirmed (medium) |
| F9 | **P2** | Doc↔code: `TLS_REPLACEMENT_PLAN` описывает уже написанный мёртвый код | `docs/TLS_REPLACEMENT_PLAN.md` | confirmed |
| F10| P3 | Мелочи: NULL-guard в `rearm_completed`, log-ротация, DEBUG-fopen | разн. | confirmed (low) |
| ⚠️ FP1 | — | **ЛОЖНОЕ срабатывание:** «`ack_cb` читает не те смещения» | `goodix_gm168.c:979` | **refuted (см. ниже)** |

---

## P0 — функциональный блокер

### F0. verify-miss — это калибровка, а не код

**Где:** `GM168_CAL1/CAL2` в [gm168_cal.h](../src/gm168_cal.h); применяются в `gm168_cal2_stage` [goodix_gm168.c:484](../src/goodix_gm168.c#L484).

**Суть:** таблицы сняты с **одного** сенсора (SID 20260605023917). Сырой декод — визуальный шум; Windows вытягивает гребни через `sub_18010f650` + `calib_windows.dat` (~197 КБ FPN/gain-коррекции). Любая пост-обработка (CLAHE/envelope) упирается в ~56% и не закрывает verify. Подтверждено и кодом, и `docs/NEXT_STEPS.md`.

**Фикс (выбрать путь):**
- **(а)** Реверс `sub_18010f650` в `Wbdi.dll.bndb` → runtime-преобразование `calib_windows.dat` → Cal1/Cal2. Cal1 @0x0008, Cal2 @0x9928 (88×80 u16), индексация через config-блок `data_18025f070`.
- **(б)** On-device захват Cal1 (dark) + Cal2 (bright) на init, замена статических таблиц.

**Критерий приёмки:** `gm168_envelope_stretch(raw)` совпадает байт-в-байт с Frida `FRAME_*.bin` на ≥2 устройствах; enroll 12/12; verify same-finger PASS, different-finger FAIL.

---

## P1 — реальные баги кода

### F1. Нет finalize/dispose — течёт всё при уничтожении устройства  `[HIGH]`

**Где:** класс [goodix_gm168.c:3129](../src/goodix_gm168.c#L3129) не ставит `finalize`; `dev_close` [:3104](../src/goodix_gm168.c#L3104) намеренно ничего не освобождает; `dev_deactivate` чистит только `io_cancellable`.

**Течёт:** TLS-поток (никогда не `pthread_join`), `SSL_CTX`/`SSL`, fd сокетпары, `img_buf`, `stitch_buf`, `background*`. При hotplug-remove без выхода процесса — на время жизни процесса.

**Доп.:** коммент в `dev_deactivate` [:3044](../src/goodix_gm168.c#L3044) **врёт** — «tls_cancel still runs from dev_close», хотя `dev_close` его не вызывает. Исправить коммент.

**Фикс:**
```c
static void
fpi_device_goodix_gm168_finalize (GObject *obj)
{
  FpDeviceGoodixGm168 *self = FPI_DEVICE_GOODIX_GM168 (obj);
  if (self->tls.ssl) goodix_gm168_tls_deinit (&self->tls);
  g_clear_pointer (&self->stitch_buf, g_byte_array_unref);
  g_clear_pointer (&self->img_buf, g_free);
  g_clear_pointer (&self->background, g_free);
  g_clear_pointer (&self->background_sum, g_free);
  g_clear_object (&self->io_cancellable);
  G_OBJECT_CLASS (fpi_device_goodix_gm168_parent_class)->finalize (obj);
}
/* в class_init: G_OBJECT_CLASS(klass)->finalize = fpi_device_goodix_gm168_finalize; */
```
**Критерий приёмки:** valgrind/ASan на open→enroll→close→hotplug-remove — 0 leaked threads/fds; `helgrind` не ругается на join.

### F2. Мёртвый рукописный TLS (~716 строк)  `[HIGH]`

**Где:** `goodix_tls_handshake.c` (377), `goodix_tls_record.c` (225), `goodix_tls_prf.c` (114) в [meson.build:17](../src/meson.build#L17). Grep: вызовов из `goodix_gm168.c` **нет** — активен OpenSSL из [goodix_tls.c](../src/goodix_tls.c).

**Решение — см. §«Развилка по TLS».** Код крипто-корректен, просто не подключён.

### F3. 16 КБ-буферы на стеке в SSM  `[MEDIUM]`

**Где:** `guint8 dec[GOODIX_GM168_EP_IN_SIZE]` / `tls_out[...]` (=16384 Б) в [goodix_gm168.c:1471](../src/goodix_gm168.c#L1471), [:1601](../src/goodix_gm168.c#L1601), [:1623](../src/goodix_gm168.c#L1623), [:1968](../src/goodix_gm168.c#L1968), [:1995](../src/goodix_gm168.c#L1995).

**Поправка к авто-ревью:** исполняются **с main loop, не глубоко вложенно** → риск умеренный, не high. Но на small-stack окружениях нежелательно.

**Фикс:** один переиспользуемый `self->tls_dec_buf` (alloc в open, free в finalize) либо `g_malloc`/`g_free` по месту.

### F4. `process_rx_buffer_for_tls` теряет усечённый хвост  `[MEDIUM]`

**Где:** [goodix_gm168.c:858-879](../src/goodix_gm168.c#L858). При `offset+4+len > len` feed пропускается, но `offset += 4+len` выполняется всё равно → разрезанный TLS-record в init-пути теряется (тут нет stitch-сборки, в отличие от `CAP_PROCESS`).

**Поправка к авто-ревью:** это **не** зацикливание (offset монотонно растёт), а тихая потеря данных.

**Фикс:** при недостатке байт — `break` без сдвига offset (как в `CAP_PROCESS`/`INIT_BG_PROCESS`); обработать `pkt_len==0`.

### F5. `tls_pull` маскирует фатальные ошибки сокета  `[LOW/MEDIUM]`

**Где:** [goodix_tls.c:325-344](../src/goodix_tls.c#L325). Не-EAGAIN ошибка возвращается отрицательным `(int)n`; вызывающий [goodix_gm168.c:1472](../src/goodix_gm168.c#L1472) трактует `<0` как «нет данных» → handshake крутится до watchdog.

**Фикс:** `if (n < 0 && errno != EAGAIN) { fp_warn(...); return 0; }` (или вернуть distinct-код и поднять GError).

---

## ⚠️ FP1 — ЛОЖНОЕ срабатывание (не чинить!)

Авто-ревьюер пометил **HIGH**: «`ack_cb` читает echo/status с `buffer[7]/[8]` вместо `data[4]/[7]` как `decode_ack`» ([goodix_gm168.c:979](../src/goodix_gm168.c#L979)).

**Это НЕ баг.** В протоколе **два разных формата A0**:
- *IMMEDIATE* `[A0..][B0][pL][pH][echo][status][bsum]` → echo=7, status=8 — ровно как в `SESSION_RESULTS.md`. Эту ветку и обрабатывает `ack_cb` (после слива FINAL при `buffer[4]!=0xB0`).
- *standard* `[A0][LenL][LenH][HdrSum][echo][pL][pH][status]` → echo=4, status=7 — это разбирает `goodix_gm168_decode_ack`.

Смещения корректны для своей ветки. **Реальная (меньшая) проблема:** хрупкость — два формата + ручные смещения. *Опционально:* унифицировать через один декодер. Не дефект.

---

## P2 — путь к upstream

### F6. Device-specific данные как код  `[HIGH для переносимости]`
- Cal1/Cal2 ([gm168_cal.h](../src/gm168_cal.h)), `SET_PARAM` 256 Б из одного pcap, `DEL_TMPL` ([goodix_proto.c:46](../src/goodix_proto.c#L46)) — вынести калибровку в runtime-файл рядом с `psk.bin`.
- **Мёртвые** provisioning-константы (нигде не используются): `goodix_gm168_zero_psk`, `zero_psk_wb`, `sgx_empty_header`, `wb_header`, `wb_magic_prefix` ([goodix_proto.c:22-42](../src/goodix_proto.c#L22)) — удалить. Также мёртвая `goodix_gm168_irq_arm` [:96](../src/goodix_proto.c#L96).

### F7. Комментарии RU/EN вперемешку  `[MEDIUM]`
В т.ч. в публичных `.h` ([goodix_proto.h:24](../src/goodix_proto.h#L24), [goodix_tls.c:156](../src/goodix_tls.c#L156)). Upstream завернёт. Перевести в EN: сначала `.h`, потом `.c`.

### F8. Env-флаг sprawl  `[MEDIUM]`
7 флагов: `GM168_USE_CAL2/USE_MEDIAN/NO_WALLIS/USE_WALLIS` ([:790-799](../src/goodix_gm168.c#L790)), `USE_CLAHE` [:2140](../src/goodix_gm168.c#L2140), `NO_CLAHE` [:2204](../src/goodix_gm168.c#L2204). Часть комбинаций **заведомо ломает enroll** (Wallis, коммент [:563](../src/goodix_gm168.c#L563)). Выбрать один канонический пайплайн; остальное за `#ifdef GM168_DEBUG` или в отдельную ветку. `GOODIX_GM168_DIR` оставить (это конфиг, не research).

### F9. Doc↔code disconnect (TLS)
`docs/TLS_REPLACEMENT_PLAN.md` описывает рукописный TLS как «planned», хотя он уже написан и мёртв. Привести в соответствие после решения развилки.

### Прочее для upstream
- Интеграция через `libfprint-add-gm168.patch` ок для дев-сборки; для мержа в дерево — drivers.json/meson-интеграция libfprint, udev, тест декодера против ground-truth.

---

## Развилка по TLS (решить явно)

OpenSSL + `SSL_OP_NO_RENEGOTIATION | NO_TICKET | NO_EXTENDED_MASTER_SECRET | NO_ENCRYPT_THEN_MAC` + `SECLEVEL=0` **уже** решает renegotiation_info — handshake работает.

- **libfprint принимает зависимость OpenSSL** → удалить рукописный TLS (F2), обновить docs (F9).
- **libfprint не хочет OpenSSL** (предпочитает GnuTLS/свою крипту) → доделать рукописный TLS (почти готов, крипто-корректен) и выкинуть OpenSSL.

Сейчас худший вариант: две реализации, активна одна, docs описывают другую.

---

## Чеклист для следующей сессии

**Функция (разблокировать verify):**
- [ ] F0: реверс `sub_18010f650` / `calib_windows.dat` → runtime Cal1/Cal2 (или on-device захват)
- [ ] F0: верификация байт-в-байт против `FRAME_*.bin` на ≥2 устройствах
- [ ] F0: end-to-end enroll 12/12 + verify same/different

**Надёжность кода:**
- [ ] F1: добавить `finalize`-хэндлер + честный teardown; исправить врущий коммент [:3044](../src/goodix_gm168.c#L3044)
- [ ] F3: 16 КБ-буферы → heap/struct
- [ ] F4: `process_rx_buffer_for_tls` — `break` без сдвига offset при недоборе
- [ ] F5: `tls_pull` — логировать не-EAGAIN, не маскировать

**Решение + чистка:**
- [ ] Развилка по TLS → удалить ИЛИ доделать рукописный TLS (F2, F9)
- [ ] F6: калибровку в runtime-файл; удалить мёртвые provisioning-константы + `irq_arm`
- [ ] F8: схлопнуть env-флаги до одного канонического пайплайна

**Upstream-полировка:**
- [ ] F7: комментарии RU → EN (сначала `.h`)
- [ ] drivers.json/meson-интеграция libfprint, udev, тест декодера

---

## Уже исправлено (не трогать)

Из устаревшего `CODE_REVIEW.md` — проверено в текущем коде:
- ✅ `gm168_quality_metric` границы корректны (x0=16,x1=64,y0=8,y1=56) [goodix_gm168.c:2466](../src/goodix_gm168.c#L2466)
- ✅ bounds-check B2 присутствует [goodix_gm168.c:872](../src/goodix_gm168.c#L872)
- ✅ владение GError в `wait_lift_cb` корректно [goodix_gm168.c:2556](../src/goodix_gm168.c#L2556)
- ✅ O(n²) selection-sort заменён на `qsort` [goodix_gm168.c:2185](../src/goodix_gm168.c#L2185)

## Сильные стороны (для контекста)

- Крипто корректно: PRF P_SHA256, MAC-then-Encrypt, constant-time MAC/padding ([goodix_tls_record.c:182](../src/goodix_tls_record.c#L182), [goodix_tls_prf.c:46](../src/goodix_tls_prf.c#L46)).
- Потокобезопасность OpenSSL-сервера обоснована верно (socketpair, без мьютекса).
- Декод/транспонирование кадра корректны [goodix_gm168.c:818](../src/goodix_gm168.c#L818); envelope-пайплайн верифицирован побайтно.
- Зрелые SSM: дедлайны-watchdog, классификация USB-ошибок, fast-path переиспользования TLS+BG, idempotent polling.

---

*Полный машинно-читаемый отчёт с verdict'ами по каждой находке: `tasks/wbxfo25pe.output` (если доступен в сессии).*
