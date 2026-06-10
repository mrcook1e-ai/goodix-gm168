/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * TLS 1.2 record layer: AES-128-CBC + HMAC-SHA256, MAC-then-Encrypt.
 *
 * RFC 5246 §6.2.3.2 (GenericBlockCipher):
 *   content = plaintext
 *   mac     = HMAC_SHA256(write_mac_key,
 *               seq_num(8) || type(1) || version(2) || length(2) || content)
 *   padded  = content || mac || PKCS7-padding
 *   cipher  = AES-128-CBC(IV, padded)
 *   record  = hdr(5) || IV(16) || cipher
 */

#define FP_COMPONENT "goodix_gm168"

#include "goodix_tls_record.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>

#define AES_BLOCK  16
#define SHA256_LEN 32
#define TLS_HDR     5   /* type(1) + version(2) + length(2) */
#define TLS_VER_HI  0x03
#define TLS_VER_LO  0x03

/* ── helpers ─────────────────────────────────────────────────────────────── */

/* HMAC-SHA256 over 5-part AAD + plaintext (no heap alloc). */
static void
compute_mac (const guint8 *mac_key,
             guint8        type,
             guint64       seq,
             const guint8 *plain, gsize plain_len,
             guint8        mac_out[SHA256_LEN])
{
    guint8 hdr[13];  /* seq(8) + type(1) + ver(2) + len(2) */
    hdr[0] = (guint8)(seq >> 56); hdr[1] = (guint8)(seq >> 48);
    hdr[2] = (guint8)(seq >> 40); hdr[3] = (guint8)(seq >> 32);
    hdr[4] = (guint8)(seq >> 24); hdr[5] = (guint8)(seq >> 16);
    hdr[6] = (guint8)(seq >>  8); hdr[7] = (guint8)(seq);
    hdr[8]  = type;
    hdr[9]  = TLS_VER_HI;
    hdr[10] = TLS_VER_LO;
    hdr[11] = (guint8)(plain_len >> 8);
    hdr[12] = (guint8)(plain_len);

    HMAC_CTX *ctx = HMAC_CTX_new ();
    unsigned int out_len = SHA256_LEN;
    HMAC_Init_ex (ctx, mac_key, SHA256_LEN, EVP_sha256 (), NULL);
    HMAC_Update (ctx, hdr, sizeof (hdr));
    HMAC_Update (ctx, plain, plain_len);
    HMAC_Final (ctx, mac_out, &out_len);
    HMAC_CTX_free (ctx);
}

/* ── public API ──────────────────────────────────────────────────────────── */

gsize
tls_record_encrypted_size (gsize plain_len)
{
    /* plaintext + MAC, then PKCS7 padding to AES block boundary */
    gsize after_mac = plain_len + SHA256_LEN;
    gsize pad_len   = AES_BLOCK - (after_mac % AES_BLOCK);  /* 1..16 */
    return TLS_HDR + AES_BLOCK /* IV */ + after_mac + pad_len;
}

int
tls_encrypt_record (guint8        type,
                     guint64       seq,
                     const guint8 *write_key,
                     const guint8 *mac_key,
                     const guint8 *iv,
                     const guint8 *plain,    gsize plain_len,
                     guint8       *out,       gsize out_sz)
{
    gsize need = tls_record_encrypted_size (plain_len);
    if (out_sz < need)
        return -1;

    /* ── 1. Compute MAC ── */
    guint8 mac[SHA256_LEN];
    compute_mac (mac_key, type, seq, plain, plain_len, mac);

    /* ── 2. Build plaintext block: plain || mac || PKCS7 pad ── */
    gsize after_mac = plain_len + SHA256_LEN;
    /* TLS padding (RFC 5246 §6.2.3.2): pad_total bytes all with value
     * (pad_total - 1).  The last byte IS the padding_length field and
     * its value N means "N more identical bytes precede me", so total
     * padding = N + 1.  This differs from PKCS#7 where byte value = count.
     * pad_total = AES_BLOCK - (after_mac % AES_BLOCK), range [1..16]. */
    gsize pad_len   = AES_BLOCK - (after_mac % AES_BLOCK);  /* total pad bytes */
    gsize block_len = after_mac + pad_len;

    guint8 *block = g_malloc (block_len);
    memcpy (block,             plain, plain_len);
    memcpy (block + plain_len, mac,   SHA256_LEN);
    memset (block + after_mac, (guint8)(pad_len - 1), pad_len);  /* value = N-1 */

    /* ── 3. Generate IV ── */
    guint8 iv_buf[AES_BLOCK];
    if (iv) {
        memcpy (iv_buf, iv, AES_BLOCK);
    } else {
        if (RAND_bytes (iv_buf, AES_BLOCK) != 1) {
            g_free (block);
            return -1;
        }
    }

    /* ── 4. AES-128-CBC encrypt (manual: no padding, we padded already) ── */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
    EVP_EncryptInit_ex (ctx, EVP_aes_128_cbc (), NULL, write_key, iv_buf);
    EVP_CIPHER_CTX_set_padding (ctx, 0);  /* we handle PKCS7 ourselves */

    guint8 *cipher_dst = out + TLS_HDR + AES_BLOCK;
    int out1 = 0, out2 = 0;
    EVP_EncryptUpdate (ctx, cipher_dst, &out1, block, (int)block_len);
    EVP_EncryptFinal_ex (ctx, cipher_dst + out1, &out2);
    EVP_CIPHER_CTX_free (ctx);
    g_free (block);

    gsize cipher_len = (gsize)(out1 + out2);
    gsize payload_len = AES_BLOCK + cipher_len;

    /* ── 5. Write TLS record header ── */
    out[0] = type;
    out[1] = TLS_VER_HI;
    out[2] = TLS_VER_LO;
    out[3] = (guint8)(payload_len >> 8);
    out[4] = (guint8)(payload_len);

    /* ── 6. Write IV ── */
    memcpy (out + TLS_HDR, iv_buf, AES_BLOCK);

    return (int)(TLS_HDR + payload_len);
}

int
tls_decrypt_record (guint8        type,
                     guint64       seq,
                     const guint8 *write_key,
                     const guint8 *mac_key,
                     const guint8 *payload,     gsize payload_len,
                     guint8       *out,          gsize out_sz)
{
    /* payload = IV(16) || ciphertext */
    if (payload_len < (gsize)(AES_BLOCK + AES_BLOCK))
        return -1;
    if ((payload_len - AES_BLOCK) % AES_BLOCK != 0)
        return -1;

    const guint8 *iv_in     = payload;
    const guint8 *cipher_in = payload + AES_BLOCK;
    gsize         cipher_len = payload_len - AES_BLOCK;

    /* ── 1. AES-128-CBC decrypt ── */
    guint8 *plain_padded = g_malloc (cipher_len);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
    EVP_DecryptInit_ex (ctx, EVP_aes_128_cbc (), NULL, write_key, iv_in);
    EVP_CIPHER_CTX_set_padding (ctx, 0);
    int out1 = 0, out2 = 0;
    EVP_DecryptUpdate (ctx, plain_padded, &out1, cipher_in, (int)cipher_len);
    EVP_DecryptFinal_ex (ctx, plain_padded + out1, &out2);
    EVP_CIPHER_CTX_free (ctx);
    gsize padded_len = (gsize)(out1 + out2);

    /* ── 2. Remove TLS padding (RFC 5246 §6.2.3.2) ── */
    /* Last byte = padding_length N; total padding = N+1 bytes, all value N. */
    if (padded_len == 0) {
        g_free (plain_padded);
        return -1;
    }
    guint8 pad_byte  = plain_padded[padded_len - 1];   /* N */
    gsize  pad_total = (gsize)pad_byte + 1;             /* N+1 */
    if (pad_total > AES_BLOCK || pad_total > padded_len) {
        g_free (plain_padded);
        return -1;
    }
    /* Constant-time: all N+1 trailing bytes must equal N */
    int pad_ok = 1;
    for (gsize i = 0; i < pad_total; i++)
        if (plain_padded[padded_len - 1 - i] != pad_byte)
            pad_ok = 0;
    if (!pad_ok) {
        g_warning ("tls_dec: BAD PADDING pad_byte=0x%02x pad_total=%zu padded_len=%zu",
                   (unsigned)pad_byte, pad_total, padded_len);
        g_free (plain_padded);
        return -1;
    }
    gsize unpadded_len = padded_len - pad_total;   /* plain + MAC */

    if (unpadded_len < SHA256_LEN) {
        g_free (plain_padded);
        return -1;
    }
    gsize plain_len = unpadded_len - SHA256_LEN;

    /* ── 3. Verify MAC ── */
    guint8 expected_mac[SHA256_LEN];
    compute_mac (mac_key, type, seq, plain_padded, plain_len, expected_mac);

    /* Constant-time MAC compare */
    const guint8 *got_mac = plain_padded + plain_len;
    int mac_ok = 1;
    for (int i = 0; i < SHA256_LEN; i++)
        if (got_mac[i] != expected_mac[i])
            mac_ok = 0;

    if (!mac_ok) {
        g_free (plain_padded);
        return -1;
    }

    /* ── 4. Copy plaintext to output ── */
    if (plain_len > out_sz) {
        g_free (plain_padded);
        return -1;
    }
    memcpy (out, plain_padded, plain_len);
    g_free (plain_padded);
    return (int)plain_len;
}
