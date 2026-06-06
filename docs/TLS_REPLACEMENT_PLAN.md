# Plan: replace OpenSSL TLS-PSK with a custom implementation

**Status:** planned, not started — pick up next session.
**Estimated effort:** 3–4 hours coding + 30–60 min hardware test.

## Why we have to do this

The GM168 firmware speaks TLS-1.0-era PSK retrofitted to claim TLS 1.2.
Its ClientHello carries **no extensions block** and uses the SCSV
pseudo-cipher `0x00FF` to signal secure renegotiation support per
RFC 5746.

Per RFC 5746 OpenSSL is then **required** to echo an empty
`renegotiation_info` extension in the ServerHello. There is **no
public API in OpenSSL 3.x to suppress this**. Captured wire dump
(see `docs/PSK.md` and the journal traces from 2026-06-06):

```
TLS_FEED 52 bytes ClientHello:
  16 03 01 00 2f 01 00 00 2b 03 03
  <32B random>
  00                                ← session_id = empty
  00 04 00 ae 00 ff                 ← cipher_suites: PSK-AES128-CBC-SHA256 + SCSV
  01 00                             ← compression null
  <no extensions block>             ← length stops at compression

TLS_PULL 95 bytes ServerHello (what OpenSSL emits):
  16 03 03 00 51 02 00 00 4d 03 03
  <32B random>
  20 <32B session_id>               ← we send a 32-byte session id
  00 ae 00                          ← cipher + compression
  00 05 ff 01 00 01 00              ← renegotiation_info extension ★
```

The sensor firmware was clearly written before RFC 5746 became a hard
requirement. It parses ServerHello up to and including
`compression_method` and treats whatever follows as belonging to the
next record. So:

* **Our** transcript hash includes the full 81-byte ServerHello (with
  the 5-byte `renegotiation_info` extension).
* **Sensor's** transcript hash includes only the first 76 bytes
  (up to compression_method).

The hashes diverge → the master secret derived from each side's
transcript-influenced state differs → AES-CBC + HMAC-SHA256 keys
differ → the sensor's encrypted `Finished` decrypts to garbage on our
side. OpenSSL surfaces this as the exact 3-line queue we keep seeing:

```
error:1C800066:Provider routines::cipher operation failed
error:0A000119:SSL routines::decryption failed or bad record mac
error:0A000139:SSL routines::record layer failure
```

EMS disable, EtM disable, NO_RENEGOTIATION, NO_TICKET, SECLEVEL=0,
OPENSSL_CONF=/dev/null — none of these prevent OpenSSL from adding
the extension when the client used SCSV. The behaviour is hard-wired
into `tls_construct_stoc_renegotiate`.

The PSK itself is verified correct via `scripts/check_psk.py`
(sensor's flash sha256 == our `/etc/goodix-gm168/psk.bin` sha256).
Hardware is fine; OpenSSL just refuses to interop with a firmware
that pre-dates RFC 5746.

## What we keep

* Everything above `goodix_tls.c` — `goodix_gm168.c`, `goodix_proto.c`,
  B0/B2 wrapping, USB pipeline, hardening layer (G1–G13)
* `libcrypto` for primitives (AES, HMAC, SHA, `CRYPTO_memcmp`) — the
  problem is `libssl` handshake construction, not the crypto provider
* Public API of `goodix_tls.h` — `feed/pull/send/recv/cancel/deinit`
  signatures unchanged so `goodix_gm168.c` doesn't need to change

## What goes

* `SSL_CTX`, `SSL`, `SSL_accept`, `SSL_CTX_set_psk_server_callback`,
  the BIO setup
* `tls_serve_thread`, `pthread_create`, `pthread_join`
* `socketpair` between driver and SSL thread
* Result: ~150 LOC out of `goodix_tls.c`

## What we add

* TLS 1.2 record layer (encrypt + decrypt, AES-128-CBC + HMAC-SHA256
  in Mac-then-Encrypt order) — ~120 LOC
* `PRF_SHA256` (P_SHA256 + label/seed concat) — ~30 LOC
* Synchronous handshake state machine inside `tls_feed` — ~250 LOC
* Unit tests with RFC 5246 § known-answer vectors — ~80 LOC
* Total **~480 LOC added, ~150 LOC removed, net ~330 LOC**

## Cipher suite

Single hardcoded suite: `TLS_PSK_WITH_AES_128_CBC_SHA256` = `0x00AE`
(RFC 5487). We don't support any other suites; we reject ClientHello
if `0x00AE` is not in its cipher list.

## Handshake sequence

| # | From | Message | Action |
|---|---|---|---|
| 1 | sensor | ClientHello | parse, verify `0x00AE` present, save `client_random`, append handshake body to transcript |
| 2 | us | ServerHello | construct WITHOUT extensions, append to transcript, queue in `out_pending` |
| 3 | us | ServerHelloDone | (SKE omitted — PSK with no identity hint), append to transcript, queue |
| 4 | sensor | ClientKeyExchange | parse PSK identity (ignored — we always use our `psk.bin`), append to transcript |
| 5 | — | compute keys | `master_secret` + `key_block` from `psk` + randoms |
| 6 | sensor | ChangeCipherSpec | flip `read_encrypted = true` |
| 7 | sensor | encrypted Finished | decrypt, verify `verify_data`, append PLAINTEXT to transcript |
| 8 | us | ChangeCipherSpec | queue, flip `write_encrypted = true` |
| 9 | us | Finished | compute `verify_data` over current transcript, encrypt, queue |
| 10 | — | TLS_S_ESTABLISHED | application data flows through `tls_send`/`tls_recv` |

## Key derivation (RFC 5246 §8.1 + RFC 4279 §2)

```
pre_master_secret = uint16_be(32) || zeros(32) || uint16_be(32) || psk   /* 68 B */

master_secret = PRF(pre_master_secret, "master secret",
                    client_random || server_random, 48 B)

key_block     = PRF(master_secret, "key expansion",
                    server_random || client_random, 96 B)

client_write_MAC_key = key_block[0:32]
server_write_MAC_key = key_block[32:64]
client_write_key     = key_block[64:80]
server_write_key     = key_block[80:96]
/* No fixed IV — TLS 1.2 uses an explicit per-record IV */
```

## PRF (TLS 1.2, SHA-256-based)

```
P_SHA256(secret, seed):
    A(0) = seed
    A(i) = HMAC-SHA256(secret, A(i-1))
    output_i = HMAC-SHA256(secret, A(i) || seed)
    output = concat(output_i...) truncated to requested length

PRF(secret, label, seed, len) = P_SHA256(secret, label || seed) [:len]
```

## Verify data

```
verify_data = PRF(master_secret,
                  "client finished" or "server finished",
                  SHA256(transcript_so_far),
                  12 B)
```

`transcript_so_far` is the concatenation of handshake message bodies
(NOT TLS record headers, NOT ChangeCipherSpec) from ClientHello up to
the point of computing.

## Record layer (MAC-then-Encrypt, RFC 5246 §6.2.3.2)

### Encrypt

```
mac_input = uint64_be(seq) || type || version || uint16_be(len(plain)) || plain
mac       = HMAC-SHA256(write_mac_key, mac_input)              /* 32 B */
padded    = plain || mac || padding
            /* padding: N+1 bytes all equal to N, smallest N >= 0 such that
               (len(plain) + 32 + N + 1) % 16 == 0 */
iv        = random(16)
cipher    = AES-128-CBC-encrypt(write_key, iv, padded)
record    = type || version || uint16_be(len(iv) + len(cipher)) || iv || cipher
```

### Decrypt

```
iv         = bytes[0:16]
cipher     = bytes[16:]
padded     = AES-128-CBC-decrypt(read_key, iv, cipher)
pad_len    = padded[-1]
            /* verify last (pad_len+1) bytes == pad_len, constant-time */
mac        = padded[-(32 + pad_len + 1) : -(pad_len + 1)]
plain      = padded[: -(32 + pad_len + 1)]
expected   = HMAC-SHA256(read_mac_key,
                         uint64_be(seq) || type || version
                         || uint16_be(len(plain)) || plain)
require    CRYPTO_memcmp(mac, expected, 32) == 0
```

Sequence numbers reset to 0 on each ChangeCipherSpec; incremented
per record per direction. No anti-replay needed (USB transport).

## New `GoodixGM168TlsServer` struct

```c
typedef enum {
    TLS_S_IDLE,
    TLS_S_AWAITING_CLIENT_HELLO,
    TLS_S_AWAITING_CLIENT_KEY_EXCHANGE,
    TLS_S_AWAITING_CLIENT_CCS,
    TLS_S_AWAITING_CLIENT_FINISHED,
    TLS_S_ESTABLISHED,
    TLS_S_FAILED,
} GoodixTlsState;

struct GoodixGM168TlsServer {
    GoodixTlsState state;

    GByteArray *transcript;             /* concatenated handshake bodies */

    guint8 client_random[32];
    guint8 server_random[32];

    const guint8 *psk;                  /* points into goodix_gm168_psk */
    gsize         psk_len;              /* == 32 */

    guint8 master_secret[48];
    guint8 client_write_mac_key[32];
    guint8 server_write_mac_key[32];
    guint8 client_write_key[16];
    guint8 server_write_key[16];

    guint64 client_seq;
    guint64 server_seq;

    gboolean read_encrypted;
    gboolean write_encrypted;

    GByteArray *in_pending;             /* raw bytes from sensor, mid-parse */
    GByteArray *out_pending;             /* bytes queued for the driver to pull */
    GByteArray *app_recv;                /* decrypted app data ready for tls_recv */

    volatile gboolean cancel_requested;
};
```

`socketpair`, `pthread_t`, `sock_fd`, `client_fd`, `ssl`, `ctx` all
go away.

## Implementation order (one commit per step)

| # | Step | LOC | Test |
|---|------|-----|------|
| 1 | Add `prf_sha256()` helper + RFC test vectors | 30 + 60 | `test_tls_prf` |
| 2 | Add `compute_master_secret` + `compute_key_block` | 40 | RFC KAT |
| 3 | Add `encrypt_record` / `decrypt_record` (no state machine) | 120 | self-roundtrip + KAT |
| 4 | Add `parse_client_hello`, `parse_client_key_exchange` | 80 | replay captured bytes |
| 5 | Add `emit_server_hello` (no extensions) + `emit_server_hello_done` | 50 | byte-perfect output |
| 6 | Stitch everything in new `tls_feed` state machine | 80 | replay full handshake |
| 7 | `parse_client_finished` + `emit_change_cipher_spec` + `emit_server_finished` | 40 | replay full |
| 8 | `tls_send`/`tls_recv` via `encrypt_record`/`decrypt_record` | 30 | roundtrip |
| 9 | Delete OpenSSL `SSL_CTX`/`SSL`/`SSL_accept` + socketpair + thread | −150 | build |
| 10 | Update `meson.build` — drop `libssl` dep, keep `libcrypto` | 5 | build |
| 11 | Remove TLS_FEED / TLS_PULL debug dumps from `goodix_tls.c` | −30 | clean release |
| 12 | Hardware test → `fprintd-enroll` end-to-end | — | manual |

Step 6 is where we first see end-to-end behaviour on the wire — even
if Finished verification isn't wired yet, the sensor should at least
accept our ServerHello (no SSL_accept error queue, no INIT watchdog
trip).

## Testing strategy

### Unit (`tests/test_tls_prf.c`)

* `prf_sha256` against RFC 5246 known-answer vectors and at least one
  third-party implementation's vector
* `compute_master_secret` against a vector derived by hand using a
  fixed PSK + fixed randoms
* `encrypt_record` round-trip: `encrypt_record(plain) → decrypt_record
  → plain` for a few `plain` lengths spanning block boundaries
* `parse_client_hello` on the captured 52-byte ClientHello (committed
  as a fixture binary) — verify it extracts the expected random,
  detects `0x00AE`, ignores SCSV

### Integration

* Boot fprintd, run `fprintd-enroll`
* Expected progression in journal:
  ```
  goodix-gm168: TLS handshake started
  goodix-gm168: TLS handshake complete
  goodix-gm168: <... encrypted command flow ...>
  ```
* Touch the sensor → enroll stages progress

## Risks and edge cases

| Risk | Mitigation |
|---|---|
| Padding oracle | `CRYPTO_memcmp` for MAC, constant-time padding check |
| Endianness on length / seq fields | Always `GUINT16_TO_BE` / `GUINT64_TO_BE` explicitly |
| ClientHello fragmentation across USB reads | USB read returns whole transfer; sensor always sends ClientHello atomically. Worst-case: keep `in_pending` so multi-byte feeds reassemble |
| Alert handling | Minimal — log alert payload (type `0x15`), set `TLS_S_FAILED` on fatal alerts |
| `g_byte_array` lifecycle | Standard `g_byte_array_*` with explicit `g_byte_array_free`; struct-owned arrays freed in `tls_deinit` |

## Fallback if this approach fails

* **mbedTLS migration** — embedded-friendly library, behaviours
  closer to GM168 firmware (it almost certainly uses mbedTLS itself).
  ~1–2 days work. Gives future-proof TLS support if we ever need
  session resumption or rekeying.
* **Patch OpenSSL** — compile a private libssl with RFC 5746 server
  response disabled. Dirty but minimal LOC.

## Pre-session checklist

* `scripts/check_psk.py` confirms `MATCH` (sensor's PSK == our backup)
* `/etc/goodix-gm168/psk.bin` exists, sha256 ==
  `cd28fb94810a36dfab17c717ea6d6711ca89d1ed2f1adf6a88518afceab21770`
* `lsusb | grep 27c6:589a` shows the sensor
* `./scripts/release.sh status` shows the patched libfprint at `/opt`
  is current and fprintd points there

## Reference

* RFC 5246 — TLS 1.2 (record layer, PRF, key derivation, Finished)
* RFC 4279 — TLS-PSK ciphersuites
* RFC 5487 — PSK ciphersuites with SHA-256 (defines `0x00AE`)
* RFC 5746 — secure renegotiation (the source of our problem)
* `docs/PSK.md` — capture format and Frida workflow
* Wire dumps from 2026-06-06 session — see chat history /
  `~/.claude/projects/.../*.jsonl` if needed
