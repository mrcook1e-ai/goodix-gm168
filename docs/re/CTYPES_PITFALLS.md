# ctypes на 64-битном Windows — подводные камни

## Проблема: обрезание 64-битных указателей

### Симптом
```
hmod = 0x60e10000          # выглядит правдоподобно
func_addr = 0x60e136c0     # вроде бы правильно
# → вызов падает: "access violation writing 0x60e136c0"
```

### Причина
`ctypes.windll.*` по умолчанию возвращает `c_int` (знаковый 32-бит).  
На 64-битном Windows `HMODULE`, `HANDLE`, любые указатели — 64-битные.  
Реальный адрес загрузки DLL: `0x00007ffb61050000` — обрезается до `0x61050000` или `0x60e10000`.  
Функция вызывается по мусорному адресу → crash.

### Исправление (обязательно для всех Win32 API возвращающих указатель)

```python
import ctypes

kernel32 = ctypes.windll.kernel32

# ДО (неправильно):
hmod = kernel32.LoadLibraryA(path)          # возвращает c_int → обрезан!

# ПОСЛЕ (правильно):
kernel32.LoadLibraryA.restype  = ctypes.c_void_p
kernel32.LoadLibraryA.argtypes = [ctypes.c_char_p]
hmod = kernel32.LoadLibraryA(path)          # полные 64 бита
```

### Полный шаблон для вызова произвольной функции по адресу

```python
import ctypes

kernel32 = ctypes.windll.kernel32

# 1. Загрузка DLL с правильным restype
kernel32.LoadLibraryA.restype  = ctypes.c_void_p
kernel32.LoadLibraryA.argtypes = [ctypes.c_char_p]
hmod = kernel32.LoadLibraryA(b"C:\\path\\to\\lib.dll")
if not hmod:
    raise RuntimeError(f"LoadLibraryA failed: {kernel32.GetLastError()}")

# 2. Вычисление адреса функции (IMAGE_BASE берём из PE-заголовка или Binary Ninja)
IMAGE_BASE  = 0x180000000
FUNC_OFFSET = 0x36c0
func_addr   = hmod + FUNC_OFFSET

# 3. Объявление сигнатуры (WINFUNCTYPE = __stdcall / Microsoft x64 на 64-бит)
#    void func(uint8_t* out)
FuncType = ctypes.WINFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8))
func = FuncType(func_addr)

# 4. Вызов
out = (ctypes.c_uint8 * 16)()
func(out)
result = bytes(out)
```

### Другие функции с той же проблемой

| Win32 API | Правильный restype |
|-----------|-------------------|
| `LoadLibraryA` / `LoadLibraryW` | `c_void_p` |
| `GetProcAddress` | `c_void_p` |
| `VirtualAlloc` | `c_void_p` |
| `OpenProcess` / `OpenThread` | `c_void_p` |
| `CreateFileA` | `c_void_p` |
| `HeapAlloc` | `c_void_p` |
| Любой HANDLE / HMODULE | `c_void_p` |

## Проблема: CFUNCTYPE vs WINFUNCTYPE

На 64-битном Windows оба ведут себя одинаково (единое соглашение вызовов Microsoft x64).  
На 32-битном Windows:
- `CFUNCTYPE` = `__cdecl` (caller очищает стек)
- `WINFUNCTYPE` = `__stdcall` (callee очищает стек)

Для DLL из Windows (WinAPI, драйверы) всегда используй `WINFUNCTYPE`.
