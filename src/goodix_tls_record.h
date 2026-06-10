/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <glib.h>

/* ── TLS 1.2 record layer, AES-128-CBC + HMAC-SHA256 (MAC-then-Encrypt) ─── */

/* Total size of the full TLS record including 5-byte header, 16-byte IV,
 * ciphertext (plaintext + 32-byte MAC, PKCS#7-padded to AES block). */
gsize tls_record_encrypted_size (gsize plain_len);

/* Encrypt plaintext to a TLS application-data record.
 *   type      : TLS record type (e.g. 0x16 handshake, 0x17 app_data)
 *   seq       : 64-bit sequence number (big-endian in MAC AAD)
 *   write_key : 16-byte AES-128 key
 *   mac_key   : 32-byte HMAC-SHA256 key
 *   iv        : 16-byte explicit IV; pass NULL to use RAND_bytes
 *   plain     : plaintext bytes
 *   out / out_sz : destination buffer (must be >= tls_record_encrypted_size)
 *
 * Returns total bytes written (5-hdr + 16-IV + ciphertext), or -1 on error.
 */
int tls_encrypt_record (guint8        type,
                         guint64       seq,
                         const guint8 *write_key,
                         const guint8 *mac_key,
                         const guint8 *iv,
                         const guint8 *plain,    gsize plain_len,
                         guint8       *out,       gsize out_sz);

/* Decrypt a TLS record payload (the bytes AFTER the 5-byte record header).
 *   payload / payload_len : ciphertext (IV + cipher blocks)
 *   out / out_sz          : destination for plaintext
 *
 * Returns plaintext length, or -1 if MAC or padding check fails.
 */
int tls_decrypt_record (guint8        type,
                         guint64       seq,
                         const guint8 *write_key,
                         const guint8 *mac_key,
                         const guint8 *payload,     gsize payload_len,
                         guint8       *out,          gsize out_sz);
