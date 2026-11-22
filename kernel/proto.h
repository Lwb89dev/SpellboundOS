/* Independently authored SpellboundFit binary framed link protocol (v1).
 * Transport-agnostic over BLE GATT, UART or host pipes. */
#ifndef SPELLBOUND_PROTO_H
#define SPELLBOUND_PROTO_H

#include <stdbool.h>
#include <stdint.h>

#define PROTO_MAGIC_0       0x53u /* 'S' */
#define PROTO_MAGIC_1       0x42u /* 'B' */
#define PROTO_VERSION       1u
#define PROTO_HEADER_LEN    8u
#define PROTO_CRC_LEN       4u
#define PROTO_MAX_PAYLOAD   256u
#define PROTO_MAX_FRAME     (PROTO_HEADER_LEN + PROTO_MAX_PAYLOAD + PROTO_CRC_LEN)

enum proto_msg_type {
    PROTO_PING           = 0x01,
    PROTO_PONG           = 0x02,
    PROTO_ACK            = 0x03,
    PROTO_NACK           = 0x04,
    PROTO_TIME_SYNC      = 0x10,
    PROTO_NOTIFY_POST    = 0x20,
    PROTO_NOTIFY_DISMISS = 0x21,
    PROTO_NOTIFY_ACTION  = 0x22,
    PROTO_NAV_UPDATE     = 0x30,
    PROTO_NAV_CLEAR      = 0x31,
    PROTO_CALL_STATE     = 0x40,
    PROTO_TELEMETRY      = 0x50,
};

struct proto_frame {
    uint8_t version;
    uint8_t type;
    uint16_t seq;
    uint16_t len;
    uint8_t payload[PROTO_MAX_PAYLOAD];
};

struct proto_decoder {
    uint8_t state;
    uint8_t header[PROTO_HEADER_LEN];
    uint8_t crc_buf[PROTO_CRC_LEN];
    uint16_t pos;
    struct proto_frame cur;
    uint32_t frames_ok;
    uint32_t crc_errors;
    uint32_t framing_errors;
};

struct proto_tx {
    int (*send)(const uint8_t *data, uint32_t len, void *ctx);
    void *ctx;
};

/* Reflected IEEE 802.3 CRC-32 (polynomial 0xEDB88320). */
uint32_t proto_crc32(const uint8_t *data, uint32_t len);

/* Encode a complete wire frame into out[0..out_cap). Returns encoded length or -1. */
int proto_encode(uint8_t *out, uint32_t out_cap, uint8_t type, uint16_t seq,
                 const uint8_t *payload, uint16_t payload_len);

/* Convenience watch -> phone encoders. */
int proto_encode_notify_action(uint8_t *out, uint32_t out_cap, uint16_t seq,
                               uint32_t notif_id, uint8_t action_index);
int proto_encode_telemetry(uint8_t *out, uint32_t out_cap, uint16_t seq,
                           uint8_t battery_pct, bool charging,
                           uint32_t steps, uint16_t hr_bpm, uint32_t uptime_sec);

void proto_decoder_init(struct proto_decoder *dec);

/* Feed one byte into the streaming frame decoder.
 * Returns 1 when a valid frame was copied into out, 0 if incomplete, -1 on error. */
int proto_decoder_feed(struct proto_decoder *dec, uint8_t byte, struct proto_frame *out);

/* Dispatch a decoded companion frame into notify/nav/call services and send
 * PONG/ACK/NACK over tx (if non-NULL). Optional out params receive TIME_SYNC values. */
int proto_dispatch(const struct proto_frame *frame, const struct proto_tx *tx,
                   int64_t *synced_unix_sec_out, int16_t *synced_tz_min_out);

#endif /* SPELLBOUND_PROTO_H */
