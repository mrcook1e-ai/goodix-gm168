/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * TLS 1.2 PRF (P_SHA256) for the GM168 PSK handshake.
 *
 * RFC 5246 §5:
 *   PRF(secret, label, seed) = P_SHA256(secret, label || seed)
 *   P_SHA256(secret, A_seed) = HMAC_SHA256(secret, A(1) || A_seed) || ...
 *   A(0) = A_seed
 *   A(i) = HMAC_SHA256(secret, A(i-1))
 */

#define FP_COMPONENT "goodix_gm168"

#include "goodix_tls_prf.h"
#include <openssl/hmac.h>
#include <string.h>

#define SHA256_LEN 32

/* One HMAC-SHA256 round. */
static void
hmac_sha256 (const guint8 *key, gsize key_len,
             const guint8 *data, gsize data_len,
             guint8 *out)
{
    unsigned int out_len = SHA256_LEN;
    HMAC (EVP_sha256 (), key, (int)key_len, data, data_len, out, &out_len);
}

/* Concatenate two byte strings for HMAC input without heap alloc. */
static void
hmac_sha256_2 (const guint8 *key, gsize key_len,
               const guint8 *d1, gsize d1_len,
               const guint8 *d2, gsize d2_len,
               guint8 *out)
{
    HMAC_CTX *ctx = HMAC_CTX_new ();
    unsigned int out_len = SHA256_LEN;
    HMAC_Init_ex (ctx, key, (int)key_len, EVP_sha256 (), NULL);
    HMAC_Update (ctx, d1, d1_len);
    HMAC_Update (ctx, d2, d2_len);
    HMAC_Final (ctx, out, &out_len);
    HMAC_CTX_free (ctx);
}

void
prf_sha256 (const guint8 *secret, gsize secret_len,
            const guint8 *label,  gsize label_len,
            const guint8 *seed,   gsize seed_len,
            guint8       *out,    gsize out_len)
{
    /* A_seed = label || seed  (we keep them separate and pass as two pieces) */
    /* A(0) = label || seed */
    guint8 A[SHA256_LEN];

    /* A(1) = HMAC(secret, label || seed) */
    hmac_sha256_2 (secret, secret_len, label, label_len, seed, seed_len, A);

    gsize produced = 0;
    while (produced < out_len) {
        /* output chunk = HMAC(secret, A(i) || label || seed) */
        HMAC_CTX *ctx = HMAC_CTX_new ();
        guint8    chunk[SHA256_LEN];
        unsigned int chunk_len = SHA256_LEN;
        HMAC_Init_ex (ctx, secret, (int)secret_len, EVP_sha256 (), NULL);
        HMAC_Update (ctx, A, SHA256_LEN);
        HMAC_Update (ctx, label, label_len);
        HMAC_Update (ctx, seed, seed_len);
        HMAC_Final (ctx, chunk, &chunk_len);
        HMAC_CTX_free (ctx);

        gsize copy_n = MIN (out_len - produced, (gsize)SHA256_LEN);
        memcpy (out + produced, chunk, copy_n);
        produced += copy_n;

        /* A(i+1) = HMAC(secret, A(i)) */
        if (produced < out_len)
            hmac_sha256 (secret, secret_len, A, SHA256_LEN, A);
    }
}

void
tls_compute_master_secret (const guint8 *pms,           gsize pms_len,
                            const guint8 *client_random,
                            const guint8 *server_random,
                            guint8        master_secret[48])
{
    /* seed = client_random || server_random */
    guint8 cr_sr[64];
    memcpy (cr_sr,      client_random, 32);
    memcpy (cr_sr + 32, server_random, 32);

    prf_sha256 (pms, pms_len,
                (const guint8 *)"master secret", 13,
                cr_sr, 64,
                master_secret, 48);
}

void
tls_compute_key_block (const guint8 *master_secret,
                        const guint8 *client_random,
                        const guint8 *server_random,
                        guint8        key_block[96])
{
    /* seed = server_random || client_random  (note: reversed vs master!) */
    guint8 sr_cr[64];
    memcpy (sr_cr,      server_random, 32);
    memcpy (sr_cr + 32, client_random, 32);

    prf_sha256 (master_secret, 48,
                (const guint8 *)"key expansion", 13,
                sr_cr, 64,
                key_block, 96);
}
