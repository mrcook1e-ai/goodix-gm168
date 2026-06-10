# Wbdi.dll — Карта функций (RE результаты)

Файл: `C:\Users\mrcook1e\Fingerprint\raw\Wbdi.dll`  
ImageBase: `0x180000000`  
Архитектура: x86-64, Windows PE

## Основные функции (переименованы в .bndb)

### PSK шифрование

| Адрес | Имя | Описание |
|-------|-----|----------|
| `0x180001000` | `SecWhiteEncrypt` | Точка входа WB-шифрования. PSK (32B) → WB-блоб (96B). Принимает указатели на PSK, выходной буфер, длину. |
| `0x180002500` | `hmac_sha256_setup` | Инициализация HMAC-SHA256 (ipad=0x36, opad=0x5c). Генерирует 32-байтный TAG в конце WB-блоба. |

### WhiteBox AES константа

| Адрес | Имя | Описание |
|-------|-----|----------|
| `0x1800036c0` | `wb_get_aes_constant` | Вычисляет 16-байтную WB-константу (var_488). Результат: `5cba6e25819518de2d53e96dc0347ab0`. Не зависит от PSK/устройства. |
| `0x1800031f0` | `sha256_3b_to_2b` | SHA-256(3 байта) → записывает первые 2 байта в *out. Используется для групп 0 и 6. |
| `0x1800032f0` | `wb_aes_3b_to_2b` | WhiteBox AES: 3 байта → 2 байта. Используется 4 раза (группы 1–4). Содержит cfgcookie. |
| `0x180003510` | `wb_aes_group5_to_2b` | Аналог wb_aes_3b_to_2b для группы 5. |

### WhiteBox AES внутренности

| Адрес | Имя | Описание |
|-------|-----|----------|
| `0x1800071a0` | `wb_aes_key_schedule` | Расписание ключей AES (key expansion). Вызывается из wb_aes_3b_to_2b. |
| `0x180007a40` | `wb_aes_encrypt_round` | AES раунд (encrypt). |
| `0x180007cf0` | `wb_aes_encrypt_round2` | AES раунд (encrypt, вариант 2). |
| `0x180008300` | `wb_aes_decrypt_round` | AES раунд (decrypt). |

### Данные

| Адрес | Имя | Описание |
|-------|-----|----------|
| `0x18030d2e0` | `crc32_mpeg2_table` | Таблица CRC-32/MPEG-2 (poly=0x4c11db7). Инициализируется при первом вызове wb_get_aes_constant. 256 × 4B = 1024B. |

## Схема вызовов

```
SecWhiteEncrypt
├── [key derivation]
│   └── wb_get_aes_constant        ← вычисляет var_488 (16B WB-константа)
│       ├── sha256_3b_to_2b        (группы 0, 6)
│       ├── wb_aes_3b_to_2b ×4    (группы 1–4)
│       │   ├── wb_aes_key_schedule
│       │   ├── wb_aes_encrypt_round / wb_aes_encrypt_round2
│       │   └── wb_aes_decrypt_round
│       ├── wb_aes_group5_to_2b   (группа 5)
│       └── CRC32/MPEG-2 → out[12:14]  (таблица crc32_mpeg2_table)
├── AES-128-CBC encrypt (PSK → CT)
└── hmac_sha256_setup + finalize   (CT → TAG)
```

## Экспортированные функции

Из DLL экспортируются только:
- `identifyUpdate` @ `0x180037c50`
- `GetTptOverlapRate` @ `0x180031ab0`
- Jump-thunks: `j_sub_180007a40`, `j_sub_1800071a0`, `j_sub_180006b10`, `j_sub_180005da0`

`SecWhiteEncrypt` и `wb_get_aes_constant` — **не экспортируются**, вызываются по адресу.

## Как вызвать wb_get_aes_constant из Python

См. `scripts/wb_keygen.py` и `docs/re/WB_KEY_DERIVATION.md`.

Ключевое: `ctypes.windll.kernel32.LoadLibraryA.restype = ctypes.c_void_p`
