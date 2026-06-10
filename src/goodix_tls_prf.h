/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glib.h>

/* ── TLS 1.2 PRF (P_SHA256, RFC 5246 §5) ────────────────────────────────── */

/* Core TLS 1.2 PRF: out_len bytes of keying material.
 *   PRF(secret, label, seed) = P_SHA256(secret, label || seed)
 * Concatenates as many HMAC-SHA256 A-chain rounds as needed. */
void prf_sha256 (const guint8 *secret, gsize secret_len,
                 const guint8 *label,  gsize label_len,
                 const guint8 *seed,   gsize seed_len,
                 guint8       *out,    gsize out_len);

/* master_secret = PRF(pms, "master secret", client_random || server_random, 48)
 * GM168 note: build_pre_master_secret() passes zeros_psk_struct as pms.     */
void tls_compute_master_secret (const guint8 *pms,           gsize pms_len,
                                 const guint8 *client_random,
                                 const guint8 *server_random,
                                 guint8        master_secret[48]);

/* key_block (96 B) = PRF(master_secret, "key expansion",
 *                        server_random || client_random, 96)
 * Layout: client_write_mac(32) | server_write_mac(32) |
 *         client_write_key(16) | server_write_key(16)            */
void tls_compute_key_block (const guint8 *master_secret,
                             const guint8 *client_random,
                             const guint8 *server_random,
                             guint8        key_block[96]);
