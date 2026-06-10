"""
WB (WhiteBox) key derivation and PSK extraction for Goodix GM168SEC.

Key derivation (confirmed):
  first_sha = SHA256(b'\x20\x00\x00\x00' + b'123GOODIX')
  IV        = first_sha[:15] + bytes([first_sha[15] & 0xf0])
  var_488   = sub_1800036c0(Wbdi.dll)  -- WhiteBox AES constant (device-independent)
  var_4c8   = IV + bytes(48)
  second_sha = SHA256(var_4c8 + var_488)
  AES_KEY   = second_sha[:16]

WB blob format: [IV:16][AES-CBC-CT:48][HMAC-SHA256:32] = 96 bytes
"""
import ctypes, hashlib, sys

DLL_PATH = r"C:\Users\mrcook1e\Fingerprint\raw\Wbdi.dll"
IMAGE_BASE = 0x180000000
FUNC_OFFSET = 0x1800036c0 - IMAGE_BASE  # 0x36c0

# Cached result — call get_var488() only once per session
_VAR488_CACHE = None

def get_var488():
    global _VAR488_CACHE
    if _VAR488_CACHE:
        return _VAR488_CACHE
    kernel32 = ctypes.windll.kernel32
    kernel32.LoadLibraryA.restype = ctypes.c_void_p
    kernel32.LoadLibraryA.argtypes = [ctypes.c_char_p]
    hmod = kernel32.LoadLibraryA(DLL_PATH.encode())
    if not hmod:
        raise RuntimeError(f'LoadLibraryA failed, error={kernel32.GetLastError()}')
    func_addr = hmod + FUNC_OFFSET
    FuncType = ctypes.WINFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8))
    func = FuncType(func_addr)
    out = (ctypes.c_uint8 * 16)()
    func(out)
    _VAR488_CACHE = bytes(out)
    return _VAR488_CACHE

def derive_key(var_488: bytes):
    prefix = (32).to_bytes(4, 'little')
    first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()
    iv = first_sha[:15] + bytes([first_sha[15] & 0xf0])
    var_4c8 = iv + bytes(48)
    second_sha = hashlib.sha256(var_4c8 + var_488).digest()
    return iv, second_sha[:16]

def decrypt_wb(blob: bytes, aes_key: bytes, iv: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
    except ImportError:
        from Cryptodome.Cipher import AES
    ct = blob[16:64]
    dec = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct)
    pad = dec[-1]
    if not (1 <= pad <= 16 and all(b == pad for b in dec[-pad:])):
        raise ValueError(f'Bad PKCS7 padding: 0x{pad:02x}')
    return dec[:-pad]

if __name__ == '__main__':
    print('Getting var_488 from Wbdi.dll sub_1800036c0...')
    var_488 = get_var488()
    print(f'var_488   = {var_488.hex()}')

    iv, aes_key = derive_key(var_488)
    print(f'IV        = {iv.hex()}')
    print(f'AES_KEY   = {aes_key.hex()}')

    # Captured WB blob from goodix_full.pcapng
    WB = bytes.fromhex(
        'ec35ae3abb45ed3f12c4751f1e5c2cc0'
        '18e97cc54fb96637a09dbde6bb87efc8'
        '73287db6593c428c01affa68935ee973'
        '686702617397334392cb3c194550d7cb'
        'b22655c67a57d9bfddee98554b6de56a'
        '47238ce1329d5e22b401634e58c208e1'
    )

    psk = decrypt_wb(WB, aes_key, iv)
    print(f'\nPSK       = {psk.hex()}  ({len(psk)}B)')
    print(f'SHA256    = {hashlib.sha256(psk).hexdigest()}')
