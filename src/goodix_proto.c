// SPDX-License-Identifier: LGPL-2.1-or-later
// Goodix GM168 — Geneva/Milan A0/B0 protocol implementation
//
// Верифицирован через:
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

const guint8 goodix_gm168_zero_psk[32] = {0};

const guint8 goodix_gm168_zero_psk_wb[96] = {
    0xec, 0x35, 0xae, 0x3a, 0xbb, 0x45, 0xed, 0x3f, 0x12, 0xc4, 0x75, 0x1f, 0x1e, 0x5c, 0x2c, 0xc0,
    0x5b, 0x3c, 0x54, 0x52, 0xe9, 0x10, 0x4d, 0x9f, 0x2a, 0x31, 0x18, 0x64, 0x4f, 0x37, 0xa0, 0x4b,
    0x6f, 0xd6, 0x6b, 0x1d, 0x97, 0xcf, 0x80, 0xf1, 0x34, 0x5f, 0x76, 0xc8, 0x4f, 0x03, 0xff, 0x30,
    0xbb, 0x51, 0xbf, 0x30, 0x8f, 0x2a, 0x98, 0x75, 0xc4, 0x1e, 0x65, 0x92, 0xcd, 0x2a, 0x2f, 0x9e,
    0x60, 0x80, 0x9b, 0x17, 0xb5, 0x31, 0x60, 0x37, 0xb6, 0x9b, 0xb2, 0xfa, 0x5d, 0x4c, 0x8a, 0xc3,
    0x1e, 0xdb, 0x33, 0x94, 0x04, 0x6e, 0xc0, 0x6b, 0xbd, 0xac, 0xc5, 0x7d, 0xa6, 0xa7, 0x56, 0xc5
};

const guint8 goodix_gm168_sgx_empty_header[8] = {
    0x02, 0x00, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x00
};

const guint8 goodix_gm168_wb_header[8] = {
    0x03, 0x00, 0x01, 0xBB, 0x60, 0x00, 0x00, 0x00
};
const guint8 goodix_gm168_wb_magic_prefix[10] = {
    0x56, 0xa5, 0xbb, 0x95, 0x6b, 0x7c, 0x8d, 0x9e, 0x00, 0x00
};

const guint8 goodix_gm168_fdt_setup[] = {
    0x1c, 0x01, 0xa4, 0x00, 0xa6, 0x00, 0xa4, 0x00,
    0xa5, 0x00, 0x80, 0xb3, 0x80, 0xc5, 0x80, 0xa3,
    0x80, 0xb6, 0x80, 0xa2, 0x80, 0xb6, 0x00, 0x00,
    0x00, 0x00, 0xa4, 0x00, 0xa6, 0x00, 0xa4, 0x00,
    0xa5, 0x00, 0x00
};
const guint16 goodix_gm168_fdt_setup_len = sizeof(goodix_gm168_fdt_setup);

const guint8 goodix_gm168_fdt_rearm[] = {
    0x0e, 0x01, 0xa4, 0x00, 0xa6, 0x00, 0xa4, 0x00,
    0xa5, 0x00, 0x80, 0xa1, 0x80, 0x24, 0x80, 0x24,
    0x80, 0x97, 0x80, 0xa0, 0x80, 0x9c, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00
};
const guint16 goodix_gm168_fdt_rearm_len = sizeof(goodix_gm168_fdt_rearm);

const guint8 goodix_gm168_capture_payload[] = {
    0x05, 0x00, 0xa4, 0x00, 0xa6, 0x00, 0xa4, 0x00, 0xa5, 0x00
};
const guint16 goodix_gm168_capture_payload_len = sizeof(goodix_gm168_capture_payload);

const guint8 goodix_gm168_irq_arm[] = {0x00, 0x01, 0x00};
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
// [FIX-B2] Верифицированный формат A0 ответа MCU:
//   [A0][LenL][LenH][HdrSum]  [EchoCmd][PLenL][PLenH][Status][Extra...][BodySum]
//    0    1     2     3           4       5      6       7       8...
//
// Ранее были неверные смещения: echo_cmd=data[7], status=data[8].
// Правильно (совпадает с goodix_gm168_is_touch_event и Frida traces):
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

    /* [FIX-B2] Правильные offset'ы: echo=data[4], status=data[7] */
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

    /* Динамический поиск TLS заголовка (0x17 0x03 0x03) в пределах первых 32 байт */
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
