// SPDX-License-Identifier: LGPL-2.1-or-later
// Goodix GM168 — Geneva/Milan A0/B0 protocol implementation
//
// Verified against:
//   - Binary Ninja (Wbdi.dll pack_milan / sub_18009ff44)
//   - fedora_3.log TX traces
//   - Frida SendCmd hooks

#include "goodix_proto.h"
#include <glib.h>
#include <string.h>
#include <fpi-log.h>

// ─── PSK and static data definitions ──────────────────────────────────────────
// PSK is per-device and bound to the Windows install that provisioned the MCU.
// The driver loads it at runtime from <dir>/psk.bin; if missing, the driver
// reads the sealed blob from the MCU (cmd 0xE4 / tag 0xbb010002), saves it to
// <dir>/sealed.bin and asks the user to unseal it on Windows via DPAPI.
guint8 goodix_gm168_psk[32] = {0};
const char goodix_gm168_psk_identity[] = "Client_identity";

/* SET_PARAM (0x90): 256-byte sensor register map sent immediately after TLS.
 * Extracted verbatim from patches/all.pcapng (Windows driver OUT frames post-TLS). */
const guint8 goodix_gm168_set_param[] = {
    0xb0, 0x11, 0x60, 0x71, 0x2c, 0x9d, 0x2c, 0xc9, 0x1c, 0xe5, 0x18, 0xfd, 0x00, 0xfd, 0x00, 0xfd,
    0x03, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x04, 0x00, 0x84, 0x00, 0x15, 0xb3, 0x86, 0x00, 0x00,
    0xc4, 0x88, 0x00, 0x00, 0xba, 0x8a, 0x00, 0x00, 0xb2, 0x8c, 0x00, 0x00, 0xaa, 0x8e, 0x00, 0x00,
    0xc1, 0x90, 0x00, 0xbb, 0xbb, 0x92, 0x00, 0xb1, 0xb1, 0x94, 0x00, 0x00, 0xa8, 0x96, 0x00, 0x00,
    0xb6, 0x98, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x00, 0x00, 0xd2, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00,
    0x00, 0xd6, 0x00, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x00, 0x50, 0x00, 0x01, 0x05, 0xd0, 0x00, 0x00,
    0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78, 0x56, 0x74, 0x00, 0x34, 0x12, 0x20, 0x00, 0x10,
    0x40, 0x2a, 0x01, 0x02, 0x04, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x32, 0x00, 0x80, 0x00, 0x01,
    0x00, 0x5c, 0x00, 0x80, 0x00, 0x56, 0x00, 0x24, 0x20, 0x58, 0x00, 0x03, 0x02, 0x32, 0x00, 0x0c,
    0x02, 0x66, 0x00, 0x03, 0x00, 0x7c, 0x00, 0x00, 0x58, 0x82, 0x00, 0x80, 0x15, 0x2a, 0x01, 0x82,
    0x03, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14, 0x00, 0x80, 0x00, 0x01, 0x00, 0x5c, 0x00, 0x00,
    0x01, 0x56, 0x00, 0x04, 0x20, 0x58, 0x00, 0x03, 0x02, 0x32, 0x00, 0x0c, 0x02, 0x66, 0x00, 0x03,
    0x00, 0x7c, 0x00, 0x00, 0x58, 0x82, 0x00, 0x80, 0x26, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0x80,
    0x00, 0x54, 0x00, 0x10, 0x01, 0x62, 0x00, 0x04, 0x03, 0x64, 0x00, 0x19, 0x00, 0x66, 0x00, 0x03,
    0x00, 0x7c, 0x00, 0x01, 0x58, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0xd0, 0x00, 0x52, 0x00, 0x08,
    0x00, 0x54, 0x00, 0x00, 0x01, 0x66, 0x00, 0x03, 0x00, 0x7c, 0x00, 0x01, 0x58, 0x00, 0x43, 0x3e,
};
const guint16 goodix_gm168_set_param_len = sizeof(goodix_gm168_set_param);

/* DEL_TMPL (0xC4): delete fingerprint template slot 1. */
const guint8 goodix_gm168_del_tmpl[] = {0x01, 0x00};
const guint16 goodix_gm168_del_tmpl_len = sizeof(goodix_gm168_del_tmpl);

/* FDT_SETUP (0x32): finger detection thresholds — verified from Windows all.pcapng. */
const guint8 goodix_gm168_fdt_setup[] = {
    0x1c, 0x01, 0xa4, 0x00, 0xa6, 0x00, 0xa4, 0x00,
    0xa5, 0x00, 0x80, 0xb3, 0x80, 0xc5, 0x80, 0xa2,
    0x80, 0xb5, 0x80, 0xa2, 0x80, 0xb5, 0x00, 0x00,
    0x00, 0x00, 0xa4, 0x00, 0xa6, 0x00, 0xa4, 0x00,
    0xa5, 0x00, 0x00
};
const guint16 goodix_gm168_fdt_setup_len = sizeof(goodix_gm168_fdt_setup);

/* FDT_REARM (0x34): initial finger-detect thresholds — from Windows all.pcapng.
 * Windows adapts these after the dark-background scan; we use the initial values. */
const guint8 goodix_gm168_fdt_rearm[] = {
    0x0e, 0x01, 0xa4, 0x00, 0xa6, 0x00, 0xa4, 0x00,
    0xa5, 0x00, 0x80, 0xb2, 0x80, 0xc4, 0x80, 0xa2,
    0x80, 0xb5, 0x80, 0xa2, 0x80, 0xb5, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00
};
const guint16 goodix_gm168_fdt_rearm_len = sizeof(goodix_gm168_fdt_rearm);

const guint8 goodix_gm168_capture_payload[] = {
    0x05, 0x00, 0xa4, 0x00, 0xa6, 0x00, 0xa4, 0x00, 0xa5, 0x00
};
const guint16 goodix_gm168_capture_payload_len = sizeof(goodix_gm168_capture_payload);

const guint8 goodix_gm168_session_init[] = {0x01, 0x00};

// ─── Helpers ─────────────────────────────────────────────────────────────────

static guint8
body_checksum (guint8 cmd, guint16 plen, const guint8 *payload, guint16 payload_len)
{
    // BodySum = (0xAA - (cmd + plenL + plenH + SUM(payload))) & 0xFF
    guint32 s = cmd + (plen & 0xFF) + ((plen >> 8) & 0xFF);
    for (guint16 i = 0; i < payload_len; i++)
        s += payload[i];
    return (guint8)((0xAA - s) & 0xFF);
}

static guint8
hdr_checksum (guint8 type, guint16 length)
{
    return (guint8)((type + (length & 0xFF) + ((length >> 8) & 0xFF)) & 0xFF);
}

// ─── Encode A0 command ────────────────────────────────────────────────────────
//
// Result layout:
//   [A0][LenL][LenH][HdrSum]  [Cmd][PLenL][PLenH][Payload...][BodySum]
//    0    1     2     3         4     5      6       7...
//
// Length (outer) = sizeof(Cmd + PLenL + PLenH + Payload + BodySum)
//                = 3 + payload_len + 1
guint8 *
goodix_gm168_encode_cmd (guint8 cmd, const guint8 *payload,
                          guint16 payload_len, guint32 *out_len)
{
    // inner = [Cmd][PLenL][PLenH] + payload + [BodySum]
    guint16 plen     = payload_len + 1;  // plen includes BodySum byte
    guint16 inner_sz = 3 + payload_len + 1; // Cmd(1) + plen(2) + payload + chk(1)

    // outer = [A0][LenL][LenH][HdrSum] + inner
    *out_len = 4 + inner_sz;
    guint8 *buf = g_malloc0 (*out_len);

    // Outer header
    buf[0] = GOODIX_GM168_PKT_CMD;                      // 0xA0
    buf[1] = inner_sz & 0xFF;
    buf[2] = (inner_sz >> 8) & 0xFF;
    buf[3] = hdr_checksum (buf[0], inner_sz);

    // Inner body
    buf[4] = cmd;
    buf[5] = plen & 0xFF;
    buf[6] = (plen >> 8) & 0xFF;
    if (payload && payload_len)
        memcpy (buf + 7, payload, payload_len);
    buf[7 + payload_len] = body_checksum (cmd, plen, payload, payload_len);

    return buf;
}

// ─── Decode A0 ACK from MCU ──────────────────────────────────────────────────
//
// Verified A0 MCU response layout:
//   [A0][LenL][LenH][HdrSum]  [EchoCmd][PLenL][PLenH][Status][Extra...][BodySum]
//    0    1     2     3           4       5      6       7       8...
//
// Earlier code used wrong offsets (echo_cmd=data[7], status=data[8]).
// Correct (matches goodix_gm168_is_touch_event and Frida traces):
//   echo_cmd = data[4]  (GOODIX_GM168_TOUCH_ECHO_OFF)
//   status   = data[7]  (GOODIX_GM168_TOUCH_STATUS_OFF)
gboolean
goodix_gm168_decode_ack (const guint8 *data, guint32 data_len,
                          guint8 *echo_cmd, guint8 *status,
                          guint8 **extra, guint16 *extra_len)
{
    if (data_len < 9)
        return FALSE;
    if (data[0] != GOODIX_GM168_PKT_CMD)
        return FALSE;

    /* Verified offsets: echo=data[4], status=data[7] */
    *echo_cmd = data[GOODIX_GM168_TOUCH_ECHO_OFF];    /* data[4] */
    *status   = data[GOODIX_GM168_TOUCH_STATUS_OFF];  /* data[7] */

    if (extra && extra_len) {
        guint16 inner_len = (guint16)data[1] | ((guint16)data[2] << 8);
        /* Extra starts at data[8] (after EchoCmd+PLenL+PLenH+Status).
         * inner_len covers all bytes after outer 4B header, including BodySum.
         * ex_len = inner_len - 4 (echo+plenL+plenH+status) - 1 (BodySum)  */
        guint16 ex_len = (inner_len > 5) ? (inner_len - 5) : 0;
        if (ex_len > 0 && (guint32)(8 + ex_len) <= data_len) {
            *extra     = (guint8 *)(data + 8);
            *extra_len = ex_len;
        } else {
            *extra     = NULL;
            *extra_len = 0;
        }
    }

    return TRUE;
}

// ─── Touch event detection ────────────────────────────────────────────────────
// Touch event: A0 (24B), data[4]=0x32, data[7]=0x02
gboolean
goodix_gm168_is_touch_event (const guint8 *data, guint32 data_len)
{
    if (data_len < GOODIX_GM168_TOUCH_PKT_LEN)
        return FALSE;
    if (data[0] != GOODIX_GM168_PKT_CMD)
        return FALSE;
    if (data[GOODIX_GM168_TOUCH_ECHO_OFF] != GOODIX_GM168_CMD_FDT_SETUP)
        return FALSE;
    return data[GOODIX_GM168_TOUCH_STATUS_OFF] == GOODIX_GM168_STATUS_TOUCH;
}

// ─── Encode B0 TLS wrapper ────────────────────────────────────────────────────
//
// B0 layout: [B0][LenL][LenH][HdrSum][TLS data...]
guint8 *
goodix_gm168_encode_tls (const guint8 *tls_data, guint16 tls_len,
                           guint32 *out_len)
{
    *out_len    = 4 + tls_len;
    guint8 *buf = g_malloc0 (*out_len);

    buf[0] = GOODIX_GM168_PKT_TLS;   // 0xB0
    buf[1] = tls_len & 0xFF;
    buf[2] = (tls_len >> 8) & 0xFF;
    buf[3] = hdr_checksum (buf[0], tls_len);
    memcpy (buf + 4, tls_data, tls_len);

    return buf;
}

// ─── Decode B0 TLS wrapper ───────────────────────────────────────────────────
const guint8 *
goodix_gm168_decode_tls (const guint8 *data, guint32 data_len,
                           guint16 *tls_len)
{
    if (data_len < 4 || data[0] != GOODIX_GM168_PKT_TLS)
        return NULL;

    *tls_len = (guint16)data[1] | ((guint16)data[2] << 8);
    if ((guint32)(4 + *tls_len) > data_len)
        return NULL;

    return data + 4;
}

/* Decode B2 TLS Image wrapper
 *
 * B2 layout: [B2][InnerLenL][InnerLenH][HdrSum][...sub-header...][TLS data...]
 *
 * inner_len (bytes [1:2], LE) is the authoritative payload length as reported
 * by the MCU. We dynamically search for the TLS Application Data header (17 03 03)
 * to bypass the variable-length sub-header.
 */
const guint8 *
goodix_gm168_decode_img (const guint8 *data, guint32 data_len,
                           guint16 *tls_len)
{
    guint16 inner_len;

    if (data_len < 4 || data[0] != GOODIX_GM168_PKT_IMG) {
        return NULL;
    }

    inner_len = (guint16)data[1] | ((guint16)data[2] << 8);

    if ((guint32)(4 + inner_len) > data_len) {
        return NULL;
    }

    /* Scan the first 32 bytes for the TLS record header (0x17 0x03 0x03). */
    guint32 search_limit = (inner_len > 32) ? 32 : inner_len;
    guint32 tls_offset = 0;
    
    for (guint32 i = 0; i + 2 < search_limit; i++) {
        if (data[4 + i] == 0x17 && data[4 + i + 1] == 0x03 && data[4 + i + 2] == 0x03) {
            tls_offset = 4 + i;
            break;
        }
    }

    if (tls_offset == 0) {
        fp_err("decode_img: TLS Application Data header (17 03 03) not found in B2 sub-header! Fallback to +13");
        tls_offset = 13; /* Fallback to original hardcoded offset */
    } else {
        fp_dbg("decode_img: Found TLS header at offset %u (sub-header size %u bytes)", tls_offset, tls_offset - 4);
    }

    if (inner_len >= (tls_offset - 4)) {
        *tls_len = inner_len - (tls_offset - 4);
    } else {
        *tls_len = 0;
    }

    const guint8 *tls_ptr = data + tls_offset;
    if (*tls_len >= 5) {
        fp_dbg("decode_img: TLS header = %02X %02X %02X %02X %02X (len=%u)", 
               tls_ptr[0], tls_ptr[1], tls_ptr[2], tls_ptr[3], tls_ptr[4],
               (tls_ptr[3] << 8) | tls_ptr[4]);
    }
    return tls_ptr;
}
