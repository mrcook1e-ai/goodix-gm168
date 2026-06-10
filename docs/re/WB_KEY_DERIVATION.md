# WhiteBox PSK Key Derivation — Goodix GM168SEC

Источник: RE `Wbdi.dll` (Windows driver), функция `SecWhiteEncrypt` @ `0x180001000`.

## Формат WB-блоба (96 байт)

```
offset  size  поле
  0      16   IV
 16      48   AES-128-CBC ciphertext (PSK 32B + PKCS7 pad 16B)
 64      32   HMAC-SHA256 tag
```

TLV-тег в протоколе MCU: `0xBB010003`

## Алгоритм шифрования PSK → WB-блоб

```python
import hashlib, hmac
from Crypto.Cipher import AES

PSK_LEN = 32  # всегда 32 байта для GM168SEC

# 1. Первый SHA-256 (IV derivation)
prefix    = PSK_LEN.to_bytes(4, 'little')          # b'\x20\x00\x00\x00'
first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()

# 2. IV (универсальный — одинаков для всех сенсоров)
IV = first_sha[:15] + bytes([first_sha[15] & 0xf0])
#  = ec35ae3abb45ed3f12c4751f1e5c2cc0

# 3. Константа WhiteBox AES (из Wbdi.dll, wb_get_aes_constant @ 0x36c0)
VAR_488 = bytes.fromhex('5cba6e25819518de2d53e96dc0347ab0')

# 4. Второй SHA-256 (ключ AES)
var_4c8   = IV + bytes(48)                         # IV || нули 48B
second_sha = hashlib.sha256(var_4c8 + VAR_488).digest()
AES_KEY   = second_sha[:16]
#  = b7e7f234c4e98b9eef95bfe665bacad2

# 5. Шифрование PSK
pt  = PSK + (16 - len(PSK) % 16) * bytes([16 - len(PSK) % 16])  # PKCS7
CT  = AES.new(AES_KEY, AES.MODE_CBC, IV).encrypt(pt)

# 6. HMAC тег
TAG = hmac.new(AES_KEY, CT, hashlib.sha256).digest()

blob = IV + CT + TAG  # 96 байт
```

## Алгоритм расшифровки WB-блоба → PSK

```python
IV      = blob[0:16]
CT      = blob[16:64]
TAG     = blob[64:96]

dec = AES.new(AES_KEY, AES.MODE_CBC, IV).decrypt(CT)
pad = dec[-1]
PSK = dec[:-pad]  # убрать PKCS7
```

## Как получить VAR_488 (wb_get_aes_constant)

```python
import ctypes

DLL_PATH = r"C:\...\Wbdi.dll"
FUNC_OFFSET = 0x36c0  # от ImageBase 0x180000000

kernel32 = ctypes.windll.kernel32
kernel32.LoadLibraryA.restype  = ctypes.c_void_p   # CRITICAL: 64-bit!
kernel32.LoadLibraryA.argtypes = [ctypes.c_char_p]

hmod = kernel32.LoadLibraryA(DLL_PATH.encode())
func = ctypes.WINFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8))(hmod + FUNC_OFFSET)
out  = (ctypes.c_uint8 * 16)()
func(out)
VAR_488 = bytes(out)
```

> **Важно:** `.restype = c_void_p` обязателен — без него ctypes обрезает 64-битный HMODULE до 32 бит, функция вызывается по мусорному адресу и падает.

## Известные значения

| Параметр | Значение |
|----------|----------|
| `IV` | `ec35ae3abb45ed3f12c4751f1e5c2cc0` |
| `VAR_488` | `5cba6e25819518de2d53e96dc0347ab0` |
| `AES_KEY` | `b7e7f234c4e98b9eef95bfe665bacad2` |
| **PSK** (из captures/goodix_full.pcapng) | `a12ba179ea7f00f6c70105b1d91dfe2e92d389053cb08603b63c4afba24a4c99` |

## Верификация

Тестовый вектор из goodix-fp-dump (chip 55a4, PSK = `0x00 * 32`):
```
KNOWN_BLOB = ec35ae3abb45ed3f12c4751f1e5c2cc0
             5b3c5452e9104d9f2a3118644f37a04b
             6fd66b1d97cf80f1345f76c84f03ff30
             bb51bf308f2a9875c41e6592cd2a2f9e
             60809b17b5316037b69bb2fa5d4c8ac3
             1edb3394046ec06bbdacc57da6a756c5
```
Расшифровывается в `0x00 * 32` ✓
