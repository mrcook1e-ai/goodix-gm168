# Как работает драйвер отпечатка Goodix GM168 — простым языком

> Схема для тех, кто хочет понять что происходит, когда ты прикладываешь палец к сенсору на ноутбуке.

---

## 🗺️ Общая картина

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'primaryColor': '#1e3a5f', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#4a9eff', 'lineColor': '#888', 'secondaryColor': '#2d2d2d', 'tertiaryColor': '#1a1a2e'}}}%%
flowchart TD
    FINGER["👆 Ты прикладываешь палец"]
    SENSOR["📡 Сенсор GM168SEC\n(чип в ноутбуке)"]
    USB["🔌 USB провод\n(данные едут по проводу)"]
    DRIVER["🐧 Наш драйвер\n(программа на Linux)"]
    LINUX["🔐 Linux решает:\nпустить тебя или нет?"]

    FINGER --> SENSOR
    SENSOR -->|"зашифрованные данные"| USB
    USB --> DRIVER
    DRIVER -->|"обработанное изображение"| LINUX

    style FINGER fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
    style SENSOR fill:#1a2d4a,stroke:#4a9eff,color:#90c8ff
    style USB fill:#3d2e00,stroke:#f0a030,color:#ffd580
    style DRIVER fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style LINUX fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
```

**Коротко:** сенсор снимает отпечаток → шифрует → отправляет по USB → драйвер расшифровывает и обрабатывает → Linux сравнивает и пускает тебя.

---

## 🔑 Шаг 0: Секретный ключ (делается один раз)

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    subgraph WIN["💻 Windows — один раз при настройке"]
        W1["Goodix читает зашифрованный\nключ из памяти сенсора"]
        W2["Windows расшифровывает\nчерез DPAPI\n(системный сейф Windows)"]
        W3["Получаем psk.bin\n32 байта — секрет"]
        W1 --> W2 --> W3
    end

    subgraph LINUX["🐧 Linux — каждый раз"]
        L1["/etc/goodix-gm168/psk.bin\nлежит на диске"]
        L2["Драйвер читает ключ\nпри старте"]
        L1 --> L2
    end

    W3 -->|"копируешь файл вручную"| L1
```

> ⚠️ **Почему так сложно?** Ключ намертво привязан к Windows-установке через DPAPI (это как сейф, открыть который может только та самая Windows). Поэтому надо один раз загрузиться в Windows, вытащить ключ и скопировать на Linux.

---

## 🚀 Шаг 1: Инициализация (драйвер запускается)

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    START(["🟢 Драйвер запускается"])

    S1["📨 **Wakeup** — cmd 0x11\nПробуждаем сенсор\n«Эй, ты тут?»"]
    S2["🔄 **Reset** — cmd 0x60\nСбрасываем в начальное состояние\n«Забудь всё предыдущее»"]
    S3["📋 **Version** — cmd 0x20\nСпрашиваем версию прошивки\n«Кто ты такой?»"]
    S4["🔑 **Загрузка ключа**\nЧитаем psk.bin с диска\n«Достаём секрет из сейфа»"]
    S5["🤝 **TLS Handshake**\nУстанавливаем зашифрованный канал\nкак HTTPS но по USB\nТуда-сюда несколько пакетов"]
    S6["🔒 **Сессия установлена**\nТеперь всё зашифровано\n«Туннель готов»"]
    S7["⚙️ **Настройка сенсора**\nArm 0xAE + FDT 0x32\n«Начни следить за пальцем»"]
    S8["🌑 **Тёмные кадры ×5**\nСнимаем 5 кадров БЕЗ пальца\nУсредняем → фон для вычитания\n«Калибровка нуля»"]
    S9(["✅ Готов к работе — ждём пальца"])

    START --> S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9

    style START fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
    style S4 fill:#3d2e00,stroke:#f0a030,color:#ffd580
    style S5 fill:#2d1a4a,stroke:#b77fff,color:#d4b3ff
    style S6 fill:#2d1a4a,stroke:#b77fff,color:#d4b3ff
    style S8 fill:#1a2d4a,stroke:#4a9eff,color:#90c8ff
    style S9 fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
```

> 💡 **Тёмные кадры** — это как фотоаппарат, который сначала снимает с закрытым объективом, чтобы знать какой «шум» есть у матрицы. Потом это вычитается из реального снимка.

---

## 👁️ Шаг 2: Ожидание пальца

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    WAIT(["⏳ Непрерывный цикл ожидания\nДрайвер слушает USB EP_IN 0x83"])

    P1["Пакет A0 — echo=0x32, status=**0x01**\n«Пальца нет» → ждём дальше"]
    P2["Пакет A0 — echo=0x32, status=**0x02**\n🟢 ПАЛЕЦ ОБНАРУЖЕН!"]

    WAIT --> P1
    P1 -->|"снова"| WAIT
    WAIT --> P2
    P2 --> CAPTURE(["🚀 Запускаем захват кадра"])

    style WAIT fill:#1a2d4a,stroke:#4a9eff,color:#90c8ff
    style P1 fill:#2a2a2a,stroke:#666,color:#aaa
    style P2 fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
    style CAPTURE fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
```

> 💡 Сенсор сам следит за касанием (ёмкостный датчик). Когда палец касается — электрическое поле меняется → сенсор кричит «ЕСТЬ!»

---

## 📸 Шаг 3: Захват изображения

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    TRIG["📤 **CAP_TRIG**\nОтправляем команду 0x20\n«Сделай снимок!» + 10 байт настроек"]

    RX["📥 **CAP_RX**\nЧитаем ответ по USB\nТаймаут = мин(остаток_бюджета, 1 сек)\nПакеты складываем в буфер"]

    PROC["⚙️ **CAP_PROCESS**\nРазбираем пакеты:\n🔵 B0 → отдаём в TLS для расшифровки\n🔴 B2 → тоже расшифровываем\n⚫ A0 → пропускаем (подтверждения)\nСкладываем расшифрованное в img_buf"]

    CHECK{{"Накопили ≥ 10 560 байт?\n(один полный кадр)"}}

    MORE["Читаем ещё пакеты"]
    DONE(["✅ Кадр получен!\nПередаём на обработку"])

    TRIG --> RX --> PROC --> CHECK
    CHECK -->|"нет, ещё"| MORE --> RX
    CHECK -->|"да!"| DONE

    style TRIG fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style RX fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style PROC fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style DONE fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
```

> 💡 **Почему 10 560 байт?** 80 строк × 132 байта = 10 560. Данные приходят кусками по USB, поэтому мы их склеиваем пока не получим полный кадр.

---

## 🔐 Как работает шифрование

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    subgraph SENSOR["📡 Сенсор"]
        direction TB
        RAW["Сырое изображение\n10 560 байт"]
        ENC["Шифруем\nAES-128-CBC"]
        RAW --> ENC
    end

    subgraph WIRE["🔌 USB провод"]
        PKT["B2 пакеты\n(зашифровано — нечитаемо)"]
    end

    subgraph DRIVER["🐧 Драйвер"]
        direction TB
        PSK["🔑 psk.bin\n32 байта ключа"]
        TLS["TLS слой\ngoodix_tls.c\npthread + socketpair"]
        PLAIN["✅ Расшифрованные данные\n10 560 байт — готово!"]
        PSK --> TLS
        TLS --> PLAIN
    end

    ENC --> PKT --> TLS
```

> 💡 **TLS** — тот же протокол что защищает HTTPS в браузере. Только здесь он работает по USB, а не по сети. **PSK** (Pre-Shared Key) — общий секрет, который знают и сенсор и драйвер.

---

## 🖼️ Шаг 4: Обработка изображения — 6 этапов

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    RAW(["📊 Сырые данные\n10 560 байт — 80×132"])

    D1["1️⃣ **decode_frame()**\nРаспаковка 12-бит → 16-бит\nУбираем служебные байты (36 на строку)\nТранспонируем → **64×80** пикселей\nРезультат: raw16 — 5 120 чисел"]

    D2["2️⃣ **bg_subtract()**\nВычитаем тёмный фон (снятый при старте)\nПотом **median 3×3** — убираем одиночные\nбитые пиксели (мусорные точки)"]

    D3["3️⃣ **binomial3x3()**\nГауссово размытие 3×3\nМатрица: 1 2 1 / 2 4 2 / 1 2 1 ÷ 16\nСглаживаем мелкий шум сенсора"]

    D4["4️⃣ **envelope_h() + envelope_v()**\nДля каждого пикселя — окно **11×11**\nНаходим самый тёмный (low) и светлый (high)\nсосед — «огибающая» локального контраста"]

    D5["5️⃣ **morph_close_x5()**\nМорфологическое закрытие X-формой\nЗаполняем дырки в папиллярных линиях\n5 проходов для надёжности"]

    D6["6️⃣ **local_stretch()**\nout = **255 − (px − low) × 255 / (high − low)**\nКаждый пиксель растягивается на 0..255\nИнвертируем полярность (NBIS требует)"]

    DONE(["✅ uint8[5120] — 64×80 пикселей\nГотово для распознавания"])

    RAW --> D1 --> D2 --> D3 --> D4 --> D5 --> D6 --> DONE

    style RAW fill:#2a2a2a,stroke:#666,color:#ccc
    style D1 fill:#1a2040,stroke:#5c7cfa,color:#a0b4ff
    style D2 fill:#1a2040,stroke:#5c7cfa,color:#a0b4ff
    style D3 fill:#1a2040,stroke:#5c7cfa,color:#a0b4ff
    style D4 fill:#1a2040,stroke:#5c7cfa,color:#a0b4ff
    style D5 fill:#1a2040,stroke:#5c7cfa,color:#a0b4ff
    style D6 fill:#1a2040,stroke:#5c7cfa,color:#a0b4ff
    style DONE fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
```

> 💡 **Зачем столько шагов?** Сенсор ёмкостный, не оптический — он снимает не фото, а электрическое поле. Сигнал слабый и зашумлённый, поэтому нужна вся эта цепочка фильтров чтобы получить чёткие линии отпечатка.

---

## 🎯 Шаг 5: Контроль качества и повторы

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    IMG(["🖼️ Обработанное изображение"])

    SCORE["📏 **Считаем качество**\nСтандартное отклонение центральной зоны 48×64\nНормальный палец → ~45–70\nПустой кадр или смазан → ~5–10"]

    CHECK{{"Качество ≥ **25.0**?"}}

    GOOD(["✅ Хороший кадр!\nОтправляем в NBIS"])

    BAD{{"Попыток < 6\nИ бюджет < 600 мс?"}}

    RETRY["⏱️ Ждём **200 мс**\nПросим новый кадр"]

    BEST(["😐 Берём лучший из всех\n(даже если не идеал)"])

    NBIS(["🔍 NBIS — распознаватель минуций\nСравнивает с сохранёнными шаблонами"])

    IMG --> SCORE --> CHECK
    CHECK -->|"да"| GOOD --> NBIS
    CHECK -->|"нет"| BAD
    BAD -->|"да — повторяем"| RETRY --> SCORE
    BAD -->|"нет — сдаёмся"| BEST --> NBIS

    style GOOD fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
    style RETRY fill:#3d2e00,stroke:#f0a030,color:#ffd580
    style BEST fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style NBIS fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
```

> 💡 **Зачем повторы?** Если ты приложил палец криво или влажный — первый кадр будет плохим. Система делает до 6 попыток за 600 мс чтобы поймать хороший момент. Так улучшается точность на ~20%.

---

## 🔄 Шаг 6: Перезарядка сенсора

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    DONE(["Кадр обработан"])
    R1["**0x34** × 2\nСброс детектора пальца\n«Забудь что было касание»"]
    R2["⏳ Задержка **1 500 мс**\nСенсор перезагружается"]
    R3["**0xAE** — Arm\nВключаем прерывания снова"]
    R4["**0x32** — FDT\nЗапускаем детектор пальца"]
    R5(["⏳ Ждём следующего пальца"])

    DONE --> R1 --> R2 --> R3 --> R4 --> R5

    style DONE fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
    style R5 fill:#1a2d4a,stroke:#4a9eff,color:#90c8ff
```

> 💡 Без этого шага сенсор думает что палец всё ещё лежит и не отреагирует на следующее касание.

---

## 🔐 Финал: Распознавание отпечатка

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    IMG(["🖼️ Чистое изображение 64×80"])

    NBIS["🔬 **NBIS** — алгоритм NIST\nИщет минуции:\n• точки где линия раздваивается\n• точки где линия заканчивается\nЭто уникальные маркеры отпечатка"]

    subgraph ENROLL["📝 Режим сохранения — enroll"]
        E1["Собираем 5 кадров с разных углов"]
        E2["Строим шаблон — template"]
        E3["Сохраняем в базу fprintd"]
        E1 --> E2 --> E3
    end

    subgraph VERIFY["✅ Режим проверки — verify"]
        V1["Сравниваем с сохранёнными шаблонами"]
        V2{{"Совпадение\nвыше порога?"}}
        V3(["✅ ДОСТУП РАЗРЕШЁН\nfprintd → PAM → Linux"])
        V4(["❌ ОТКАЗ\nПопробуй снова"])
        V1 --> V2
        V2 -->|"да"| V3
        V2 -->|"нет"| V4
    end

    IMG --> NBIS
    NBIS --> ENROLL
    NBIS --> VERIFY

    style V3 fill:#1a3d2b,stroke:#40c057,color:#a6e3b2
    style V4 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
```

---

## 🛡️ Защита от сбоев (10 механизмов)

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    subgraph G["🛡️ Механизмы надёжности"]
        G1["**G1** — Сторожевой таймер\nINIT: макс 10 сек\nCAP: макс 2 сек\nЕсли завис — принудительно убиваем"]

        G2["**G2** — Умный таймаут чтения\nТаймаут = мин(остаток_бюджета, 1с)\nНе ждём вечно"]

        G3["**G3** — Умные USB ошибки\nОтличаем «устройство вынули»\nот «временный сбой»\nПравильная реакция на каждый случай"]

        G4["**G4** — Режим восстановления\nЕсли REARM упал → делаем полный\nцикл SESSION→ARM→FDT\nбез перезапуска TLS"]

        G8["**G8** — Главный выключатель\nio_cancellable — все USB операции\nотменяются мгновенно при выключении"]

        G9["**G9** — Таймаут TLS\n5 секунд на рукопожатие\nSO_RCVTIMEO на сокете\nНе зависаем навсегда"]

        G11["**G11** — Ресинхронизация\nПришёл мусор → убираем 1 байт и пробуем\nПосле 2 таймаутов → новый триггер"]

        G13["**G13** — Таблица таймаутов\nВсе константы в одном месте\ngm168_timeouts.h\nС ассертами на этапе компиляции"]
    end

    style G1 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style G2 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style G3 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style G4 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style G8 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style G9 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style G11 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style G13 fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
```

---

## 📁 Файлы проекта

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    MAIN["**goodix_gm168.c**\n🧠 Главный файл\n1 390 строк\nВсе 4 стейт-машины\n+ image pipeline"]

    PROTO["**goodix_proto.c/h**\n📦 USB кодек\nФормирует пакеты A0\nПарсит входящие"]

    TLS_F["**goodix_tls.c/h**\n🔐 TLS сервер\nmbedtls + pthread\n+ socketpair"]

    CAL["**gm168_cal.h**\n📐 Калибровочные таблицы\nСтатические (опционально)"]

    TMO["**gm168_timeouts.h**\n⏱️ Все таймауты\nВ одном месте"]

    ERR["**gm168_usb_errors.h**\n❌ USB ошибки\nКлассификация"]

    TRC["**gm168_trace.h**\n🔍 Трассировка\nGM168_TRACE=1"]

    MAIN --> PROTO
    MAIN --> TLS_F
    MAIN --> CAL
    MAIN --> TMO
    MAIN --> ERR
    MAIN --> TRC

    style MAIN fill:#3d1a1a,stroke:#ff6b6b,color:#ffb3b3
    style PROTO fill:#1a2d4a,stroke:#4a9eff,color:#90c8ff
    style TLS_F fill:#2d1a4a,stroke:#b77fff,color:#d4b3ff
    style CAL fill:#3d2e00,stroke:#f0a030,color:#ffd580
    style TMO fill:#3d2e00,stroke:#f0a030,color:#ffd580
    style ERR fill:#2a2a2a,stroke:#888,color:#ccc
    style TRC fill:#2a2a2a,stroke:#888,color:#ccc
```

---

## 🌊 Полный поток — вся жизнь одного касания

```mermaid
%%{init: {'theme': 'dark'}}%%
sequenceDiagram
    actor U as 👆 Ты
    participant S as 📡 Сенсор
    participant D as 🐧 Драйвер
    participant L as 🔐 Linux/PAM

    Note over D,S: ── Инициализация ──
    D->>S: Wakeup (0x11)
    D->>S: Reset (0x60)
    D->>S: Version (0x20)
    S-->>D: v2.3.x
    D->>S: TLS ClientHello
    S-->>D: TLS ServerHello
    D->>S: TLS Finished
    Note over D,S: 🔒 Зашифрованный канал готов
    D->>S: Session + Arm + FDT
    D->>S: Trigger ×5 — тёмные кадры
    S-->>D: 5 пустых кадров (фон)
    Note over D: Вычисляем background[5120]

    Note over U,S: ── Ожидание ──
    loop Каждые ~100 мс
        S-->>D: A0 status=0x01 — пальца нет
    end

    U->>S: 👆 Касание!
    S-->>D: A0 status=0x02 — TOUCH!

    Note over D,S: ── Захват ──
    D->>S: CAP_TRIG (0x20)
    S-->>D: B2 пакеты (AES зашифровано)
    Note over D: TLS расшифровка → 10 560 байт

    Note over D: decode → bg_subtract → blur
    Note over D: envelope → morph → stretch
    Note over D: Качество = 58.4 ✅ (≥25.0)

    D->>L: Изображение uint8[5120] 64×80
    Note over L: NBIS ищет минуции — развилки и концы линий
    L-->>U: ✅ Добро пожаловать!

    Note over D,S: ── Перезарядка ──
    D->>S: 0x34 × 2 (сброс FDT)
    Note over D: Пауза 1 500 мс
    D->>S: 0xAE + 0x32 (re-arm)
    Note over D,S: Готов к следующему касанию
```

---

## 📊 Ключевые числа

| Параметр | Значение | Пояснение |
|---|---|---|
| Размер сенсора | **64 × 80 пикселей** | Маленький, но достаточный для минуций |
| Размер кадра по USB | **10 560 байт** | 80 строк × 132 байта |
| Глубина пикселя | **12 бит** (0–4095) | Высокая точность измерения |
| Тёмных кадров для калибровки | **×5** | Усредняем для точного фона |
| Порог качества | **≥ 25.0** | Нормальный палец даёт ~45–70 |
| Макс. попыток на касание | **6** | Даём шанс плохому кадру исправиться |
| Бюджет времени на касание | **600 мс** | После — берём лучшее из имеющегося |
| Задержка между повторами | **200 мс** | Палец успевает стабилизироваться |
| Размер PSK ключа | **32 байта = 256 бит** | Военный уровень шифрования |
| Таймаут TLS рукопожатия | **5 секунд** | Дольше — считаем сенсор мёртвым |
| Таймаут INIT SSM | **10 секунд** | Вся инициализация должна уложиться |
| Таймаут REARM SSM | **4 секунды** | Перезарядка сенсора |
