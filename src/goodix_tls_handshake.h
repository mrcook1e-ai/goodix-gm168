/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include <glib.h>

/*
 * TLS 1.2 handshake message parsers and emitters for the GM168 PSK handshake.
 * No libssl; all bytes are built / consumed manually.
 *
 * Transcript rules (RFC 5246 §7.4):
 *   - Append the entire handshake message: type(1) + length(3) + body
 *   - NOT the TLS record header (type + version + length)
 *   - NOT ChangeCipherSpec records
 */

/* ── Parsing ─────────────────────────────────────────────────────────────── */

/*
 * tls_parse_client_hello
 *
 * record / record_len  — full TLS record starting at 0x16
 * client_random_out    — 32-byte buffer filled with ClientHello.random
 * transcript           — handshake message (type+len+body) appended here
 *
 * Returns TRUE if:
 *   - record_type == 0x16 (handshake)
 *   - handshake_type == 0x01 (ClientHello)
 *   - TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00AE) is in cipher_suites
 *   - lengths are internally consistent
 * Returns FALSE and logs a warning otherwise.
 */
gboolean tls_parse_client_hello       (const guint8 *record, gsize record_len,
                                        guint8       *client_random_out,
                                        GByteArray   *transcript);

/*
 * tls_parse_client_key_exchange
 *
 * record / record_len  — full TLS record
 * transcript           — handshake message appended
 *
 * PSK identity in the payload is parsed and logged but ignored; we always
 * use the key from /etc/goodix-gm168/psk.bin.
 *
 * Returns TRUE on successful parse, FALSE on structural error.
 */
gboolean tls_parse_client_key_exchange (const guint8 *record, gsize record_len,
                                         GByteArray   *transcript);

/*
 * tls_parse_change_cipher_spec
 *
 * Validates that the record is a well-formed ChangeCipherSpec (type 0x14,
 * single byte 0x01).  Does NOT append to transcript (CCS is excluded by spec).
 *
 * Returns TRUE on success.
 */
gboolean tls_parse_change_cipher_spec  (const guint8 *record, gsize record_len);

/*
 * tls_parse_finished
 *
 * Decrypts and verifies the client Finished message.
 *
 * record / record_len  — full encrypted TLS record (type 0x16)
 * seq                  — client sequence number for this record
 * read_key             — 16-byte AES key
 * read_mac_key         — 32-byte HMAC key
 * master_secret        — 48 bytes, for verify_data computation
 * transcript           — transcript BEFORE this Finished (used to compute
 *                        expected verify_data); plaintext Finished body
 *                        is appended AFTER successful verification
 *
 * Returns TRUE if decryption succeeds and verify_data matches.
 */
gboolean tls_parse_finished            (const guint8 *record, gsize record_len,
                                         guint64       seq,
                                         const guint8 *read_key,
                                         const guint8 *read_mac_key,
                                         const guint8 *master_secret,
                                         GByteArray   *transcript);

/* ── Emitting ─────────────────────────────────────────────────────────────── */

/*
 * tls_emit_server_hello
 *
 * Builds a ServerHello record with NO extensions block.
 * server_random must be 32 bytes (caller fills with RAND_bytes).
 * cipher = 0x00AE, compression = 0x00, session_id = empty.
 *
 * out / out_size — output buffer; must be >= 76 bytes.
 * transcript     — handshake message appended.
 *
 * Returns number of bytes written, or -1 on error.
 */
int      tls_emit_server_hello         (const guint8 *server_random,
                                         guint8       *out, gsize out_size,
                                         GByteArray   *transcript);

/*
 * tls_emit_server_hello_done
 *
 * Builds an empty ServerHelloDone record (no SKE — PSK has no identity hint).
 * out / out_size — must be >= 9 bytes.
 * transcript     — handshake message appended.
 *
 * Returns number of bytes written, or -1 on error.
 */
int      tls_emit_server_hello_done    (guint8 *out, gsize out_size,
                                         GByteArray *transcript);

/*
 * tls_emit_change_cipher_spec
 *
 * Builds a ChangeCipherSpec record (not appended to transcript).
 * out / out_size — must be >= 6 bytes.
 *
 * Returns number of bytes written.
 */
int      tls_emit_change_cipher_spec   (guint8 *out, gsize out_size);

/*
 * tls_emit_finished
 *
 * Computes verify_data = PRF(master_secret, "server finished",
 *                             SHA256(transcript), 12)
 * then encrypts the Finished handshake message.
 *
 * seq            — server sequence number for this record
 * write_key      — 16-byte AES key
 * write_mac_key  — 32-byte HMAC key
 * master_secret  — 48 bytes
 * transcript     — current transcript (up to and including client Finished)
 * out / out_size — must be >= tls_record_encrypted_size(16)
 *
 * Returns number of bytes written, or -1 on error.
 */
int      tls_emit_finished             (guint64       seq,
                                         const guint8 *write_key,
                                         const guint8 *write_mac_key,
                                         const guint8 *master_secret,
                                         GByteArray   *transcript,
                                         guint8       *out, gsize out_size);
