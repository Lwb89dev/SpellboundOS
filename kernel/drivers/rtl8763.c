/* Independently authored RTL8763 Bluetooth HCI framing (CRC16/MODBUS, H4, H5 SLIP). */
#include "rtl8763.h"
#include <stddef.h>

uint16_t rtl8763_crc16_modbus(uint16_t crc, const uint8_t *data, uint32_t len) {
    if (!data && len > 0) return crc;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i];
        for (unsigned bit = 0; bit < 8u; bit++) {
            if ((crc & 1u) != 0) {
                crc = (uint16_t)((crc >> 1) ^ 0xA001u);
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

int rtl8763_h4_build_cmd(uint8_t *out, uint32_t cap, uint16_t opcode,
                         const uint8_t *params, uint8_t param_len) {
    if (!out || (param_len > 0 && !params)) return -1;
    uint32_t total = 4u + (uint32_t)param_len;
    if (cap < total) return -1;
    out[0] = HCI_H4_CMD;
    out[1] = (uint8_t)(opcode & 0xFFu);
    out[2] = (uint8_t)(opcode >> 8);
    out[3] = param_len;
    for (uint8_t i = 0; i < param_len; i++) {
        out[4u + i] = params[i];
    }
    return (int)total;
}

int rtl8763_h4_build_vendor_crc_cmd(uint8_t *out, uint32_t cap, uint16_t opcode,
                                    const uint8_t *params, uint8_t param_len) {
    if (!out || (param_len > 0 && !params) || param_len > 253u) return -1;
    uint32_t total = 4u + (uint32_t)param_len + 2u;
    if (cap < total) return -1;
    out[0] = HCI_H4_CMD;
    out[1] = (uint8_t)(opcode & 0xFFu);
    out[2] = (uint8_t)(opcode >> 8);
    out[3] = (uint8_t)(param_len + 2u);
    for (uint8_t i = 0; i < param_len; i++) {
        out[4u + i] = params[i];
    }
    uint16_t crc = rtl8763_crc16_modbus(0xFFFFu, &out[1], 2u);
    if (param_len > 0) {
        crc = rtl8763_crc16_modbus(crc, params, param_len);
    }
    out[4u + param_len] = (uint8_t)(crc & 0xFFu);
    out[5u + param_len] = (uint8_t)(crc >> 8);
    return (int)total;
}

int rtl8763_slip_encode(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t out_cap) {
    if (!out || (in_len > 0 && !in) || out_cap < 2u) return -1;
    uint32_t p = 0;
    out[p++] = SLIP_END;
    for (uint32_t i = 0; i < in_len; i++) {
        uint8_t b = in[i];
        if (b == SLIP_END) {
            if (p + 2u >= out_cap) return -1;
            out[p++] = SLIP_ESC;
            out[p++] = SLIP_ESC_END;
        } else if (b == SLIP_ESC) {
            if (p + 2u >= out_cap) return -1;
            out[p++] = SLIP_ESC;
            out[p++] = SLIP_ESC_ESC;
        } else {
            if (p + 1u >= out_cap) return -1;
            out[p++] = b;
        }
    }
    if (p >= out_cap) return -1;
    out[p++] = SLIP_END;
    return (int)p;
}

void rtl8763_slip_init(struct rtl8763_slip_decoder *dec) {
    if (!dec) return;
    dec->in_frame = false;
    dec->escaped = false;
    dec->pos = 0;
    dec->frames_ok = 0;
    dec->errors = 0;
}

int rtl8763_slip_feed(struct rtl8763_slip_decoder *dec, uint8_t byte,
                      uint8_t *out, uint32_t out_cap) {
    if (!dec || !out) return -1;
    if (byte == SLIP_END) {
        if (!dec->in_frame) {
            dec->in_frame = true;
            dec->escaped = false;
            dec->pos = 0;
            return 0;
        }
        if (dec->pos == 0) {
            return 0; /* back-to-back 0xC0 sync bytes */
        }
        uint32_t len = dec->pos;
        dec->pos = 0;
        dec->escaped = false;
        dec->in_frame = false;
        if (len > out_cap) {
            dec->errors++;
            return -1;
        }
        for (uint32_t i = 0; i < len; i++) out[i] = dec->buf[i];
        dec->frames_ok++;
        return (int)len;
    }
    if (!dec->in_frame) {
        return 0;
    }
    if (dec->escaped) {
        dec->escaped = false;
        if (byte == SLIP_ESC_END) {
            byte = SLIP_END;
        } else if (byte == SLIP_ESC_ESC) {
            byte = SLIP_ESC;
        } else {
            dec->in_frame = false;
            dec->pos = 0;
            dec->errors++;
            return -1;
        }
    } else if (byte == SLIP_ESC) {
        dec->escaped = true;
        return 0;
    }
    if (dec->pos >= RTL8763_MAX_FRAME) {
        dec->in_frame = false;
        dec->pos = 0;
        dec->errors++;
        return -1;
    }
    dec->buf[dec->pos++] = byte;
    return 0;
}
