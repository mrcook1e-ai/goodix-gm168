"""
Get var_488 by calling sub_1800036c0 directly via ctypes.
sub_1800036c0 is a WhiteBox AES computation — can't compute it analytically.
Load Wbdi.dll, find the function by offset, call it to get the 16-byte output.

Also: hook mbedtls_aes_setkey_enc to capture the actual AES key used.
"""
import ctypes, ctypes.wintypes, hashlib, sys

DLL_PATH = r"C:\Users\mrcook1e\Fingerprint\raw\Wbdi.dll"

# Image base in bndb is 0x180000000 (common for 64-bit DLLs)
IMAGE_BASE = 0x180000000
FUNC_OFFSET = 0x1800036c0 - IMAGE_BASE  # = 0x36c0

print(f'Loading {DLL_PATH}...')
try:
    hmod = ctypes.windll.kernel32.LoadLibraryExA(
        DLL_PATH.encode(), None, 0x00000020  # LOAD_LIBRARY_AS_IMAGE_RESOURCE
    )
    if hmod:
        print(f'Loaded (image resource) at 0x{hmod:016x}')
    else:
        hmod = ctypes.cdll.LoadLibrary(DLL_PATH)._handle
        print(f'Loaded at 0x{hmod:016x}')
except Exception as e:
    print(f'LoadLibraryEx error: {e}')
    hmod = None

if not hmod:
    # Try plain LoadLibrary
    try:
        hmod = ctypes.cdll.LoadLibrary(DLL_PATH)._handle
        print(f'Loaded via cdll at 0x{hmod:016x}')
    except Exception as e:
        print(f'cdll.LoadLibrary error: {e}')
        sys.exit(1)

func_addr = hmod + FUNC_OFFSET
print(f'sub_1800036c0 at: 0x{func_addr:016x} (offset=0x{FUNC_OFFSET:x})')

# Prototype: void sub_1800036c0(uint8_t* out_16bytes)
FuncType = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8))
func = FuncType(func_addr)

out = (ctypes.c_uint8 * 16)()
print('Calling sub_1800036c0...')
try:
    func(out)
    var_488 = bytes(out)
    print(f'var_488 = {var_488.hex()}')
except Exception as e:
    print(f'Call error: {e}')
    var_488 = None

if var_488:
    # Now compute the full AES key
    prefix = (32).to_bytes(4, 'little')
    first_sha = hashlib.sha256(prefix + b'123GOODIX').digest()
    IV = first_sha[:15] + bytes([first_sha[15] & 0xf0])
    var_4c8_base = IV + bytes(48)
    second_sha = hashlib.sha256(var_4c8_base + var_488).digest()
    AES_KEY = second_sha[:16]

    print(f'\nfirst_sha:  {first_sha.hex()}')
    print(f'IV:         {IV.hex()}')
    print(f'var_488:    {var_488.hex()}')
    print(f'second_sha: {second_sha.hex()}')
    print(f'AES_KEY:    {AES_KEY.hex()}')

    try:
        from Crypto.Cipher import AES
    except:
        from Cryptodome.Cipher import AES

    WB = bytes.fromhex(
        'ec35ae3abb45ed3f12c4751f1e5c2cc0'
        '18e97cc54fb96637a09dbde6bb87efc8'
        '73287db6593c428c01affa68935ee973'
        '686702617397334392cb3c194550d7cb'
        'b22655c67a57d9bfddee98554b6de56a'
        '47238ce1329d5e22b401634e58c208e1'
    )
    KNOWN = bytes.fromhex(
        'ec35ae3abb45ed3f12c4751f1e5c2cc0'
        '5b3c5452e9104d9f2a3118644f37a04b'
        '6fd66b1d97cf80f1345f76c84f03ff30'
        'bb51bf308f2a9875c41e6592cd2a2f9e'
        '60809b17b5316037b69bb2fa5d4c8ac3'
        '1edb3394046ec06bbdacc57da6a756c5'
    )

    for blob, label in [(KNOWN, 'KNOWN(PSK=zeros)'), (WB, 'captured blob')]:
        CT = blob[16:64]
        dec = AES.new(AES_KEY, AES.MODE_CBC, IV).decrypt(CT)
        pad = dec[-1]
        ok = 1 <= pad <= 16 and all(b == pad for b in dec[-pad:])
        if ok:
            psk = dec[:-pad]
            print(f'\n[OK] {label}: PSK = {psk.hex()} ({len(psk)}B)')
            psk_hash = hashlib.sha256(psk).hexdigest()
            print(f'     SHA256(PSK) = {psk_hash}')
        else:
            print(f'\n[X] {label}: pad=0x{pad:02x} bad, dec[:16]={dec[:16].hex()}')
