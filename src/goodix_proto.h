// SPDX-License-Identifier: LGPL-2.1-or-later
// Goodix GM168 (27c6:589A) Linux driver
//
// Forked from TheWeirdDev/libfprint (55b4-experimental)
// Adapted for Geneva/Milan protocol (GM168, Xiaomi A55)
//
// Key differences from 55b4:
//   - TLS cipher: CBC-SHA256 (not GCM)
//   - EP_IN: 0x83 (not 0x82)
//   - A0 packet format: [A0][LenL][LenH][HdrSum][Cmd][PLenL][PLenH][Payload][BodySum]
//   - Touch event: A0 echo=0x32, status=0x02 (24 bytes)

#pragma once

#include <glib.h>
#include <stdint.h>

// ─── USB ──────────────────────────────────────────────────────────────────────
#define GOODIX_GM168_VID           0x27c6
#define GOODIX_GM168_PID           0x589a
#define GOODIX_GM168_INTERFACE     0
#define GOODIX_GM168_EP_OUT        0x01
#define GOODIX_GM168_EP_IN         0x83   // NOTE: 0x83, NOT 0x82 like 55b4!
// EP_IN_SIZE: 16 KB — enough for one B2 packet (~10642 B per libusb_bulk_transfer).
// libusb returns exactly as many bytes as arrived; it does not block.
#define GOODIX_GM168_EP_IN_SIZE    (16 * 1024)
#define GOODIX_GM168_EP_OUT_SIZE   0x40   // 64 bytes per chunk
#define GOODIX_GM168_TIMEOUT_MS    2000

// ─── Firmware ─────────────────────────────────────────────────────────────────
// Verified from Binary Ninja: string "GF3206_GM168SEC_APP_10008"
#define GOODIX_GM168_FIRMWARE_VER  "GF3206_GM168SEC_APP_10008"

// ─── A0 Packet format (Geneva/Milan) ─────────────────────────────────────────
// [A0][LenL][LenH][HdrSum]  [Cmd][PLenL][PLenH][Payload...][BodySum]
//  0    1     2     3         4     5      6       7...        last
//
// HdrSum  = (0xA0 + LenL + LenH) & 0xFF
// BodySum = (0xAA - (Cmd + PLenL + PLenH + SUM(payload))) & 0xFF
// PLenL/H = len(payload) + 1  (включает байт BodySum)
#define GOODIX_GM168_PKT_CMD  0xA0
#define GOODIX_GM168_PKT_TLS  0xB0
#define GOODIX_GM168_PKT_IMG  0xB2

/* Commands (verified from Frida + Binary Ninja) */
#define GOODIX_GM168_CMD_WAKEUP        0x11
/*
 * 0x20 is dual-purpose: MCU distinguishes by payload length.
 *   - No payload (4 bytes total)  -> firmware version query
 *   - 10-byte payload             -> image scan trigger
 * Both usages are legitimate; a single opcode value is intentional.
 */
#define GOODIX_GM168_CMD_VERSION       0x20
#define GOODIX_GM168_CMD_SCAN_TRIGGER  GOODIX_GM168_CMD_VERSION  /* same opcode, different payload */
#define GOODIX_GM168_CMD_SESSION_INIT  0x60  /* reset/init session */
#define GOODIX_GM168_CMD_POWER         0xD6  /* power state */
#define GOODIX_GM168_CMD_IRQ_ARM       0xAE  /* interrupt arm */
#define GOODIX_GM168_CMD_FDT_SETUP     0x32  /* FDT (finger detection) params */
#define GOODIX_GM168_CMD_FDT_REARM     0x34  /* FDT re-arm after capture */
#define GOODIX_GM168_CMD_TLS_START     0xD0  /* trigger TLS handshake on MCU */
#define GOODIX_GM168_CMD_PSK_READ      0x43  /* read PSK from sensor */
#define GOODIX_GM168_CMD_PSK_WRITE     0x44  /* write PSK to sensor */
#define GOODIX_GM168_CMD_SPEC_DATA     0xE4  /* MCU spec-data RW (sealed PSK lives here) */
#define GOODIX_GM168_CMD_SET_PARAM     0x90  /* sensor register map (sent after TLS) */
#define GOODIX_GM168_CMD_DEL_TMPL      0xC4  /* delete fingerprint template */
#define GOODIX_GM168_CMD_STORE_PSK     0xD2  /* store PSK in sensor NVM */

/* Sealed PSK blob: DPAPI-encrypted, tag 0xbb010002, total 324 bytes,
 * read via cmd 0xE4 in 256 + 68 byte chunks. See docs/PSK.md. */
#define GOODIX_GM168_SEALED_PSK_TAG    0xbb010002u
#define GOODIX_GM168_SEALED_PSK_LEN    324
#define GOODIX_GM168_SEALED_PSK_CHUNK  0x100

// ─── Status codes ─────────────────────────────────────────────────────────────
#define GOODIX_GM168_STATUS_OK        0x00
#define GOODIX_GM168_STATUS_BUSY      0x01
#define GOODIX_GM168_STATUS_TOUCH     0x02  // finger detected (in FDT echo)
#define GOODIX_GM168_STATUS_BAD_CMD   0xFF

// ─── Touch event detection ────────────────────────────────────────────────────
// MCU шлёт A0 (24B) когда палец обнаружен:
// a0 14 00 b4 32 11 00 02 00 3f 00 b9 00 c0 00 91 00 9d 00 86 00 b7 00 42
// data[4]=0x32 (echo_cmd), data[7]=0x02 (TOUCH status)
#define GOODIX_GM168_TOUCH_PKT_LEN    24
#define GOODIX_GM168_TOUCH_ECHO_OFF   4
#define GOODIX_GM168_TOUCH_STATUS_OFF 7

// ─── PSK (32 bytes) — runtime-loaded from <dir>/psk.bin ──────────────────────
// Populated by gm168_load_psk_from_file() at dev_activate. Zero-initialised at
// startup; TLS handshake will fail until the file is loaded.
extern guint8 goodix_gm168_psk[32];
// PSK identity string (верифицирован из Binary Ninja: 32 вхождения)
extern const char goodix_gm168_psk_identity[];

// ─── TLS ──────────────────────────────────────────────────────────────────────
// Cipher suite from Binary Ninja: "TLS-PSK-WITH-AES-128-CBC-SHA256"
// NOTE: GM168 uses CBC, NOT GCM (unlike 55b4)!
#define GOODIX_GM168_TLS_CIPHER  "PSK-AES128-CBC-SHA256"
#define GOODIX_GM168_TLS_PORT    4433

// ─── Post-TLS setup payloads (extracted from Windows all.pcapng capture) ────
extern const guint8 goodix_gm168_set_param[];
extern const guint16 goodix_gm168_set_param_len;
extern const guint8 goodix_gm168_del_tmpl[];
extern const guint16 goodix_gm168_del_tmpl_len;

// ─── FDT payloads (updated to match Windows all.pcapng values) ───────────────
extern const guint8 goodix_gm168_fdt_setup[];
extern const guint16 goodix_gm168_fdt_setup_len;

extern const guint8 goodix_gm168_fdt_rearm[];
extern const guint16 goodix_gm168_fdt_rearm_len;

// Capture trigger payload (0x20)
extern const guint8 goodix_gm168_capture_payload[];
extern const guint16 goodix_gm168_capture_payload_len;

// Session init payload (0x60)
extern const guint8 goodix_gm168_session_init[];

// ─── Packet structures ────────────────────────────────────────────────────────

// A0 outer header
typedef struct __attribute__((__packed__)) {
    guint8  type;    // 0xA0
    guint16 length;  // LE, total inner length
    guint8  hdrsum;  // (type + lenL + lenH) & 0xFF
} GoodixGM168OuterHdr;

// Inner command body
typedef struct __attribute__((__packed__)) {
    guint8  cmd;
    guint16 plen;    // LE, payload_len + 1 (for checksum byte)
} GoodixGM168InnerHdr;

// Full ACK response from MCU
// data[4] = echo_cmd, data[7] = status, data[7+] = optional data
typedef struct __attribute__((__packed__)) {
    guint8  type;    // 0xA0
    guint16 length;
    guint8  hdrsum;
    guint8  marker;  // 0xB0 in response
    guint16 inner_len;
    guint8  echo_cmd;
    guint8  status;
} GoodixGM168AckHdr;

// ─── Function declarations ────────────────────────────────────────────────────

// Encode: создать корректный A0-пакет
// Returns allocated buffer (caller must g_free), sets out_len
guint8 *goodix_gm168_encode_cmd(guint8 cmd, const guint8 *payload,
                                 guint16 payload_len, guint32 *out_len);

// Decode: разобрать A0-ответ от MCU
gboolean goodix_gm168_decode_ack(const guint8 *data, guint32 data_len,
                                   guint8 *echo_cmd, guint8 *status,
                                   guint8 **extra, guint16 *extra_len);

// Check if it's a touch event
gboolean goodix_gm168_is_touch_event(const guint8 *data, guint32 data_len);

// Wrap TLS data in B0 header
guint8 *goodix_gm168_encode_tls(const guint8 *tls_data, guint16 tls_len,
                                  guint32 *out_len);

// Strip B0 header, return pointer to TLS payload inside buffer
const guint8 *goodix_gm168_decode_tls(const guint8 *data, guint32 data_len,
                                        guint16 *tls_len);

// Strip B2 header, return pointer to TLS payload inside buffer
const guint8 *goodix_gm168_decode_img(const guint8 *data, guint32 data_len,
                                        guint16 *tls_len);
