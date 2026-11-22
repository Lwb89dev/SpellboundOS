/* Portable RTL8763 Bluetooth HCI framing: CRC16/MODBUS, H4 packets and H5 SLIP. */
#ifndef SPELLBOUND_RTL8763_H
#define SPELLBOUND_RTL8763_H

#include <stdbool.h>
#include <stdint.h>

#define HCI_H4_CMD  0x01u
#define HCI_H4_ACL  0x02u
#define HCI_H4_SCO  0x03u
#define HCI_H4_EVT  0x04u

#define SLIP_END     0xC0u
#define SLIP_ESC     0xDBu
#define SLIP_ESC_END 0xDCu
#define SLIP_ESC_ESC 0xDDu

#define RTL8763_MAX_FRAME 280u

/* Reflected CRC16/MODBUS (poly 0xA001). Seed with 0xFFFF for full-frame CRC;
 * check value for "123456789" is 0x4B37. */
uint16_t rtl8763_crc16_modbus(uint16_t crc, const uint8_t *data, uint32_t len);

/* Build standard HCI H4 command packet: [0x01, op_lo, op_hi, param_len, params...].
 * Returns packet length or -1 on error. */
int rtl8763_h4_build_cmd(uint8_t *out, uint32_t cap, uint16_t opcode,
                         const uint8_t *params, uint8_t param_len);

/* Build RTL8763 vendor HCI command carrying trailing CRC16/MODBUS over [op_lo, op_hi, params...]. */
int rtl8763_h4_build_vendor_crc_cmd(uint8_t *out, uint32_t cap, uint16_t opcode,
                                    const uint8_t *params, uint8_t param_len);

/* SLIP framing (used by H5 three-wire UART transport on uart2). */
int rtl8763_slip_encode(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t out_cap);

struct rtl8763_slip_decoder {
    bool in_frame;
    bool escaped;
    uint32_t pos;
    uint8_t buf[RTL8763_MAX_FRAME];
    uint32_t frames_ok;
    uint32_t errors;
};

void rtl8763_slip_init(struct rtl8763_slip_decoder *dec);

/* Feed one UART byte. Returns >0 (decoded frame length copied to out) on complete frame,
 * 0 if incomplete, -1 on framing/overflow error. */
int rtl8763_slip_feed(struct rtl8763_slip_decoder *dec, uint8_t byte,
                      uint8_t *out, uint32_t out_cap);

#endif /* SPELLBOUND_RTL8763_H */
