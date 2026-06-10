/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * TLS 1.2 handshake message parsers and emitters for the GM168 PSK handshake.
 * No libssl; all bytes are built / consumed manually.
 *
 * Nomenclature:
 *   record   = TLS record: type(1) + version(2) + length(2) + payload
 *   hs_msg   = handshake message: type(1) + length(3) + body
 *   transcript = concat of hs_msgs (NO record headers, NO CCS)
 */

#define FP_COMPONENT "goodix_gm168"

#include "goodix_tls_handshake.h"
#include "goodix_tls_prf.h"
#include "goodix_tls_record.h"
#include "drivers_api.h"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>

/* ── constants ───────────────────────────────────────────────────────────── */

#define TLS_RT_CHANGE_CIPHER_SPEC  0x14
#define TLS_RT_HANDSHAKE           0x16
#define TLS_HT_CLIENT_HELLO        0x01
#define TLS_HT_SERVER_HELLO        0x02
#define TLS_HT_SERVER_HELLO_DONE   0x0e
#define TLS_HT_CLIENT_KEY_EXCHANGE 0x10
#define TLS_HT_FINISHED            0x14
#define TLS_VER_HI                 0x03
#define TLS_VER_LO                 0x03
#define CIPHER_PSK_AES128_SHA256   0x00ae
#define CIPHER_SCSV                0x00ff
#define TLS_RECORD_HDR             5
#define TLS_HS_HDR                 4   /* type(1) + length(3) */
#define VERIFY_DATA_LEN            12

/* ── tiny reader ─────────────────────────────────────────────────────────── */

typedef struct { const guint8 *d; gsize len; gsize pos; } R;

static gboolean r_ok    (R *r, gsize n) { return r->pos + n <= r->len; }
static guint8   r_u8    (R *r)          { return r->d[r->pos++]; }
static guint16  r_u16   (R *r)          { guint16 v = (guint16)(r->d[r->pos] << 8 | r->d[r->pos+1]); r->pos += 2; return v; }
static guint32  r_u24   (R *r)          { guint32 v = ((guint32)r->d[r->pos] << 16) | ((guint32)r->d[r->pos+1] << 8) | r->d[r->pos+2]; r->pos += 3; return v; }
static void     r_skip  (R *r, gsize n) { r->pos += n; }

/* ── tiny writer ─────────────────────────────────────────────────────────── */

typedef struct { guint8 *d; gsize size; gsize pos; } W;

static void     w_u8   (W *w, guint8  v)  { w->d[w->pos++] = v; }
static void     w_u16  (W *w, guint16 v)  { w->d[w->pos++] = v >> 8; w->d[w->pos++] = v & 0xff; }
static void     w_u24  (W *w, guint32 v)  { w->d[w->pos++] = (v >> 16) & 0xff; w->d[w->pos++] = (v >> 8) & 0xff; w->d[w->pos++] = v & 0xff; }
static void     w_bytes(W *w, const guint8 *src, gsize n) { memcpy (w->d + w->pos, src, n); w->pos += n; }

/* ── helpers ─────────────────────────────────────────────────────────────── */

/* Append handshake message (type+len3+body) at r->d+5 to transcript. */
static void
transcript_append_hs (GByteArray *t, const guint8 *record)
{
    /* hs_msg starts at record[5]; length is record[6..8] (uint24_be) + 4 */
    guint32 body_len = ((guint32)record[6] << 16) | ((guint32)record[7] << 8) | record[8];
    g_byte_array_append (t, record + 5, TLS_HS_HDR + body_len);
}

/* Check outer record envelope; return FALSE and warn on mismatch. */
static gboolean
check_record (const guint8 *rec, gsize rec_len,
              guint8 expected_rt, guint8 expected_ht)
{
    if (rec_len < TLS_RECORD_HDR + TLS_HS_HDR) {
        fp_warn ("goodix-gm168: record too short (%zu)", rec_len);
        return FALSE;
    }
    if (rec[0] != expected_rt) {
        fp_warn ("goodix-gm168: unexpected record type 0x%02x (want 0x%02x)",
                 rec[0], expected_rt);
        return FALSE;
    }
    guint16 payload_len = (guint16)(rec[3] << 8 | rec[4]);
    if ((gsize)payload_len + TLS_RECORD_HDR != rec_len) {
        fp_warn ("goodix-gm168: record length mismatch: header says %u, got %zu",
                 payload_len, rec_len - TLS_RECORD_HDR);
        return FALSE;
    }
    if (expected_ht && rec[5] != expected_ht) {
        fp_warn ("goodix-gm168: unexpected handshake type 0x%02x (want 0x%02x)",
                 rec[5], expected_ht);
        return FALSE;
    }
    return TRUE;
}

/* ── parsers ─────────────────────────────────────────────────────────────── */

gboolean
tls_parse_client_hello (const guint8 *record, gsize record_len,
                         guint8       *client_random_out,
                         GByteArray   *transcript)
{
    if (!check_record (record, record_len, TLS_RT_HANDSHAKE, TLS_HT_CLIENT_HELLO))
        return FALSE;

    R r = { record, record_len, TLS_RECORD_HDR };

    guint8  ht       = r_u8  (&r);  /* 0x01 — already checked */
    guint32 hs_len   = r_u24 (&r);  /* handshake body length  */
    (void)ht;

    if (!r_ok (&r, hs_len)) {
        fp_warn ("goodix-gm168: ClientHello body truncated");
        return FALSE;
    }

    /* client_hello_version — accept any (sensor claims 0x0303) */
    if (!r_ok (&r, 2 + 32)) { fp_warn ("goodix-gm168: ClientHello too short"); return FALSE; }
    r_skip (&r, 2);                   /* version */
    memcpy (client_random_out, r.d + r.pos, 32);
    r_skip (&r, 32);                  /* random  */

    /* session_id */
    if (!r_ok (&r, 1)) return FALSE;
    guint8 sid_len = r_u8 (&r);
    if (!r_ok (&r, sid_len)) return FALSE;
    r_skip (&r, sid_len);

    /* cipher_suites */
    if (!r_ok (&r, 2)) return FALSE;
    guint16 cs_len = r_u16 (&r);
    if (cs_len % 2 != 0 || !r_ok (&r, cs_len)) return FALSE;

    gboolean has_psk = FALSE;
    for (guint16 i = 0; i < cs_len; i += 2) {
        guint16 cs = r_u16 (&r);
        if (cs == CIPHER_PSK_AES128_SHA256) has_psk = TRUE;
        /* SCSV 0x00FF is expected — silently accepted */
    }

    if (!has_psk) {
        fp_warn ("goodix-gm168: ClientHello missing 0x00AE cipher suite");
        return FALSE;
    }

    fp_dbg ("goodix-gm168: ClientHello OK — PSK cipher present");
    transcript_append_hs (transcript, record);
    return TRUE;
}

gboolean
tls_parse_client_key_exchange (const guint8 *record, gsize record_len,
                                GByteArray   *transcript)
{
    if (!check_record (record, record_len, TLS_RT_HANDSHAKE, TLS_HT_CLIENT_KEY_EXCHANGE))
        return FALSE;

    R r = { record, record_len, TLS_RECORD_HDR };
    r_skip (&r, 1);                   /* handshake type (already checked) */
    guint32 hs_len = r_u24 (&r);
    if (!r_ok (&r, hs_len)) {
        fp_warn ("goodix-gm168: ClientKeyExchange body truncated");
        return FALSE;
    }

    /* PSK identity: uint16_be length + identity bytes */
    if (!r_ok (&r, 2)) return FALSE;
    guint16 id_len = r_u16 (&r);
    if (!r_ok (&r, id_len)) return FALSE;

    fp_dbg ("goodix-gm168: ClientKeyExchange PSK identity length=%u (ignored)", id_len);
    /* identity content is ignored — we always use /etc/goodix-gm168/psk.bin */

    transcript_append_hs (transcript, record);
    return TRUE;
}

gboolean
tls_parse_change_cipher_spec (const guint8 *record, gsize record_len)
{
    if (record_len < 6) {
        fp_warn ("goodix-gm168: ChangeCipherSpec too short");
        return FALSE;
    }
    if (record[0] != TLS_RT_CHANGE_CIPHER_SPEC) {
        fp_warn ("goodix-gm168: expected CCS record (0x14), got 0x%02x", record[0]);
        return FALSE;
    }
    if (record[5] != 0x01) {
        fp_warn ("goodix-gm168: CCS payload != 0x01");
        return FALSE;
    }
    fp_dbg ("goodix-gm168: ChangeCipherSpec OK");
    return TRUE;
}

gboolean
tls_parse_finished (const guint8 *record, gsize record_len,
                     guint64       seq,
                     const guint8 *read_key,
                     const guint8 *read_mac_key,
                     const guint8 *master_secret,
                     GByteArray   *transcript)
{
    if (record_len < TLS_RECORD_HDR) {
        fp_warn ("goodix-gm168: Finished record too short");
        return FALSE;
    }
    if (record[0] != TLS_RT_HANDSHAKE) {
        fp_warn ("goodix-gm168: Finished: wrong record type 0x%02x", record[0]);
        return FALSE;
    }

    /* Decrypt payload (everything after the 5-byte record header) */
    guint8  plain[256];
    int plain_len = tls_decrypt_record (TLS_RT_HANDSHAKE, seq,
                                         read_key, read_mac_key,
                                         record + TLS_RECORD_HDR,
                                         record_len - TLS_RECORD_HDR,
                                         plain, sizeof (plain));
    if (plain_len < 0) {
        fp_warn ("goodix-gm168: Finished decrypt failed (bad MAC or padding)");
        return FALSE;
    }

    /* Plaintext = hs_type(1) + hs_len(3) + verify_data(12) = 16 bytes */
    if (plain_len < TLS_HS_HDR + VERIFY_DATA_LEN) {
        fp_warn ("goodix-gm168: Finished plaintext too short (%d)", plain_len);
        return FALSE;
    }
    if (plain[0] != TLS_HT_FINISHED) {
        fp_warn ("goodix-gm168: Finished: wrong hs type 0x%02x", plain[0]);
        return FALSE;
    }

    /* Compute expected verify_data = PRF(master_secret, "client finished",
     *                                    SHA256(transcript), 12) */
    guint8 digest[32];
    SHA256 (transcript->data, transcript->len, digest);

    guint8 expected[VERIFY_DATA_LEN];
    prf_sha256 (master_secret, 48,
                (const guint8 *)"client finished", 15,
                digest, 32,
                expected, VERIFY_DATA_LEN);

    if (memcmp (plain + TLS_HS_HDR, expected, VERIFY_DATA_LEN) != 0) {
        fp_warn ("goodix-gm168: Finished verify_data mismatch");
        return FALSE;
    }

    fp_dbg ("goodix-gm168: client Finished verified OK");
    /* Append plaintext hs_msg to transcript */
    g_byte_array_append (transcript, plain, (guint)(TLS_HS_HDR + VERIFY_DATA_LEN));
    return TRUE;
}

/* ── emitters ────────────────────────────────────────────────────────────── */

int
tls_emit_server_hello (const guint8 *server_random,
                        guint8 *out, gsize out_size,
                        GByteArray *transcript)
{
    /*
     * ServerHello body (no extensions — this is the whole point):
     *   version(2) + random(32) + session_id_len(1)=0
     *   + cipher(2)=0x00AE + compression(1)=0x00
     *   = 38 bytes body
     * hs_msg = type(1) + len(3) + body(38) = 42 bytes
     * record = header(5) + hs_msg(42) = 47 bytes
     *
     * OpenSSL adds a 5-byte renegotiation_info extension here —
     * that is exactly what breaks the GM168 firmware.  We emit 0 extensions.
     */
    const gsize body_len = 38;
    const gsize total    = TLS_RECORD_HDR + TLS_HS_HDR + body_len;  /* 47 */

    if (out_size < total) return -1;

    W w = { out, out_size, 0 };

    /* Record header */
    w_u8  (&w, TLS_RT_HANDSHAKE);
    w_u8  (&w, TLS_VER_HI);
    w_u8  (&w, TLS_VER_LO);
    w_u16 (&w, (guint16)(TLS_HS_HDR + body_len));

    /* Handshake header */
    w_u8  (&w, TLS_HT_SERVER_HELLO);
    w_u24 (&w, (guint32)body_len);

    /* Body */
    w_u8  (&w, TLS_VER_HI);          /* version */
    w_u8  (&w, TLS_VER_LO);
    w_bytes (&w, server_random, 32); /* random */
    w_u8  (&w, 0x00);               /* session_id_length = 0 */
    w_u16 (&w, CIPHER_PSK_AES128_SHA256); /* cipher_suite */
    w_u8  (&w, 0x00);               /* compression_method = null */
    /* NO extensions length field — matches the sensor's expectations */

    g_assert (w.pos == total);
    transcript_append_hs (transcript, out);
    return (int)total;
}

int
tls_emit_server_hello_done (guint8 *out, gsize out_size, GByteArray *transcript)
{
    /*
     * ServerHelloDone: empty body (PSK has no identity hint → no SKE).
     * hs_msg = type(1) + len(3) + body(0) = 4 bytes
     * record = header(5) + 4 = 9 bytes
     */
    const gsize total = TLS_RECORD_HDR + TLS_HS_HDR;  /* 9 */
    if (out_size < total) return -1;

    W w = { out, out_size, 0 };
    w_u8  (&w, TLS_RT_HANDSHAKE);
    w_u8  (&w, TLS_VER_HI);
    w_u8  (&w, TLS_VER_LO);
    w_u16 (&w, TLS_HS_HDR);            /* payload = just the hs header */
    w_u8  (&w, TLS_HT_SERVER_HELLO_DONE);
    w_u24 (&w, 0);                     /* body length = 0 */

    g_assert (w.pos == total);
    transcript_append_hs (transcript, out);
    return (int)total;
}

int
tls_emit_change_cipher_spec (guint8 *out, gsize out_size)
{
    if (out_size < 6) return -1;
    out[0] = TLS_RT_CHANGE_CIPHER_SPEC;
    out[1] = TLS_VER_HI;
    out[2] = TLS_VER_LO;
    out[3] = 0x00;
    out[4] = 0x01;
    out[5] = 0x01;
    return 6;
}

int
tls_emit_finished (guint64       seq,
                    const guint8 *write_key,
                    const guint8 *write_mac_key,
                    const guint8 *master_secret,
                    GByteArray   *transcript,
                    guint8       *out, gsize out_size)
{
    /* verify_data = PRF(master_secret, "server finished", SHA256(transcript), 12) */
    guint8 digest[32];
    SHA256 (transcript->data, transcript->len, digest);

    guint8 verify_data[VERIFY_DATA_LEN];
    prf_sha256 (master_secret, 48,
                (const guint8 *)"server finished", 15,
                digest, 32,
                verify_data, VERIFY_DATA_LEN);

    /* Build plaintext hs_msg: type(1) + len(3) + verify_data(12) = 16 bytes */
    guint8 plain[TLS_HS_HDR + VERIFY_DATA_LEN];
    plain[0] = TLS_HT_FINISHED;
    plain[1] = 0x00;
    plain[2] = 0x00;
    plain[3] = VERIFY_DATA_LEN;
    memcpy (plain + TLS_HS_HDR, verify_data, VERIFY_DATA_LEN);

    return tls_encrypt_record (TLS_RT_HANDSHAKE, seq,
                                write_key, write_mac_key,
                                NULL,   /* random IV */
                                plain, sizeof (plain),
                                out, out_size);
}
