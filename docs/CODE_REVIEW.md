# Code Review — goodix-gm168

**Дата:** 2026-06-09  
**Ревьюер:** Claude Sonnet 4.6  
**Статус:** работает, баги не фатальные, но #1 и #2 — memory safety

---

## 🔴 Критические (memory safety / UB)

### 1. Out-of-bounds чтение в `gm168_quality_metric`

**Файл:** `src/goodix_gm168.c:2415`

Изображение аллоцируется как `fp_image_new(W=80, H=64)` → 5120 байт.
Метрика написана с перепутанными W/H:

```c
const int x0 = 8, x1 = 56;   /* "out of 64" — но W=80 */
const int y0 = 8, y1 = 72;   /* "out of 80" — но H=64 */
// img[y * 80 + x], y до 71 → индекс 71*80+55 = 5735 > 5120 ← OOB
```

**Фикс:**
```c
const int x0 = 16, x1 = 64;  /* central 48 cols out of 80 */
const int y0 = 8,  y1 = 56;  /* central 48 rows out of 64 */
```

---

### 2. Out-of-bounds чтение в `process_rx_buffer_for_tls` (B2 ветка)

**Файл:** `src/goodix_gm168.c:860`

```c
} else if (type == GOODIX_GM168_PKT_IMG) {
    // decode_img проверяет len, но дальше:
    guint16 total_len = (guint16)buf[offset+1] | ((guint16)buf[offset+2] << 8);
    // ← нет проверки offset+2 < len, OOB если хвост пакета обрезан
```

**Фикс:** добавить `if (offset + 4 > len) break;` перед чтением `buf[offset+1]`.

---

### 3. Утечка GError в `wait_lift_cb`

**Файл:** `src/goodix_gm168.c:2484`

```c
if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
    g_error_free (error);                          // освобождаем
    fpi_ssm_mark_failed (transfer->ssm,
        g_error_new (..., "wait_lift: cancelled")); // создаём новый — лишнее
```

**Фикс:** передать `error` напрямую (fpi_ssm_mark_failed берёт ownership):
```c
fpi_ssm_mark_failed (transfer->ssm, error);
return;
```

---

## 🟡 Логические баги

### 4. Ложный `fp_err` при WANT_READ (dec_n == 0)

**Файл:** `src/goodix_gm168.c:1937` и `1963`

```c
} else {
    fp_err("CAP_PROCESS B0: TLS decryption error: %s",
           err ? err->message : "unknown (dec_n<=0)");
```

`tls_recv` возвращает `0` при SSL_ERROR_WANT_READ timeout — это нормально.
`fp_err` при `dec_n==0, err==NULL` — ложная тревога, засоряет лог.

**Фикс:**
```c
if (err) {
    fp_err("CAP_PROCESS B0: TLS decrypt error: %s", err->message);
    g_error_free(err);
}
```

---

### 5. Hardcoded offsets в `ack_cb` IMMEDIATE-формат

**Файл:** `src/goodix_gm168.c:964`

```c
guint8 echo   = transfer->buffer[7];
guint8 status = transfer->buffer[8];
```

Сырые смещения, не используется `goodix_gm168_decode_ack()`. При неожиданной длине
пакета — тихое чтение неверных байт. Нет проверки длины перед `STATUS_BAD_CMD`.

**Фикс:** добавить `if (transfer->actual_length < 9) { /* re-listen */ return; }` перед чтением.

---

## 🟠 Производительность

### 6. O(n²) selection sort в CLAHE-пути

**Файл:** `src/goodix_gm168.c:2135`

```c
for (int a = 0; a < GM168_FRAME_PIXELS - 1; a++) {  // 5119 итераций
    for (int b = a + 1; b < GM168_FRAME_PIXELS; b++) // ещё до 5119 каждый
```

~13 млн сравнений на каждый кадр. Путь включён при `GM168_USE_CLAHE=1`.

**Фикс:** заменить на `qsort`.

---

## 🟢 Чистота / minor

### 7. `goodix_gm168_irq_arm` объявлена но нигде не используется

**Файл:** `src/goodix_proto.c:96`, `src/goodix_proto.h:126`

Везде в коде payload для IRQ_ARM задаётся inline `{0x00, 0x01, 0x00}`.
Использовать константу или удалить.

---

### 8. Дублирование Gaussian blur в CLAHE-пути

**Файл:** `src/goodix_gm168.c:2167`

Инлайн 3×3 биномиальный блюр после CLAHE — идентичен `gm168_binomial3x3()` (строка 599).
Стоит вызвать общую функцию.

---

### 9. Отладочные `fp_warn` в hot path TLS активны в production

**Файл:** `src/goodix_tls.c:302` (TLS_FEED), `src/goodix_tls.c:342` (TLS_PULL)

Каждый TLS-пакет (включая image data) логируется через `fp_warn` с hex-дампом.
Перевести на `fp_dbg` или убрать за `#ifdef GM168_DEBUG`.

---

### 10. `fp_warn` вместо `fp_dbg` для информационных сообщений

**Файл:** `src/goodix_gm168.c:1685`

```c
fp_warn ("BG averaged %d frames: hash=0x%08X sum=%u min=%u max=%u", ...);
```

BG-хэш — диагностика, не предупреждение. Аналогично `fp_warn("RECOVER OK...")` на 2797.

---

## Сводная таблица

| # | Приоритет | Суть | Файл:строка |
|---|-----------|------|-------------|
| 1 | 🔴 | OOB чтение: quality_metric y1=72 > H=64 | gm168.c:2415 |
| 2 | 🔴 | OOB чтение: B2 без bounds check | gm168.c:860 |
| 3 | 🔴 | GError leak в wait_lift_cb | gm168.c:2484 |
| 4 | 🟡 | Ложный fp_err при WANT_READ | gm168.c:1937,1963 |
| 5 | 🟡 | Hardcoded offsets в ack_cb IMMEDIATE | gm168.c:964 |
| 6 | 🟠 | O(n²) sort в CLAHE | gm168.c:2135 |
| 7 | 🟢 | Неиспользуемая константа irq_arm | proto.c:96 |
| 8 | 🟢 | Дублирование Gaussian blur | gm168.c:2167 |
| 9 | 🟢 | fp_warn в hot path TLS | tls.c:302,342 |
| 10 | 🟢 | fp_warn для info-сообщений | gm168.c:1685,2797 |
