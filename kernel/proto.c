/* Independently authored SpellboundFit binary framed link protocol (v1). */
#include "proto.h"
#include "notify.h"
#include <stddef.h>

enum {
    DEC_MAGIC0 = 0,
    DEC_MAGIC1 = 1,
    DEC_HEADER = 2,
    DEC_PAYLOAD = 3,
    DEC_CRC = 4,
};

static uint16_t rd_le16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)(v >> 8);
}

static void wr_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8u; bit++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc;
}

uint32_t proto_crc32(const uint8_t *data, uint32_t len) {
    if (!data && len > 0) return 0;
    return ~crc32_update(0xFFFFFFFFu, data, len);
}

int proto_encode(uint8_t *out, uint32_t out_cap, uint8_t type, uint16_t seq,
                 const uint8_t *payload, uint16_t payload_len) {
    if (!out || payload_len > PROTO_MAX_PAYLOAD || (payload_len > 0 && !payload)) {
        return -1;
    }
    uint32_t total = PROTO_HEADER_LEN + (uint32_t)payload_len + PROTO_CRC_LEN;
    if (out_cap < total) {
        return -1;
    }
    out[0] = PROTO_MAGIC_0;
    out[1] = PROTO_MAGIC_1;
    out[2] = PROTO_VERSION;
    out[3] = type;
    wr_le16(&out[4], seq);
    wr_le16(&out[6], payload_len);
    for (uint16_t i = 0; i < payload_len; i++) {
        out[PROTO_HEADER_LEN + i] = payload[i];
    }
    uint32_t crc = proto_crc32(out, PROTO_HEADER_LEN + (uint32_t)payload_len);
    wr_le32(&out[PROTO_HEADER_LEN + payload_len], crc);
    return (int)total;
}

int proto_encode_notify_action(uint8_t *out, uint32_t out_cap, uint16_t seq,
                               uint32_t notif_id, uint8_t action_index) {
    uint8_t payload[5];
    wr_le32(&payload[0], notif_id);
    payload[4] = action_index;
    return proto_encode(out, out_cap, PROTO_NOTIFY_ACTION, seq, payload, sizeof payload);
}

int proto_encode_telemetry(uint8_t *out, uint32_t out_cap, uint16_t seq,
                           uint8_t battery_pct, bool charging,
                           uint32_t steps, uint16_t hr_bpm, uint32_t uptime_sec) {
    uint8_t payload[12];
    payload[0] = battery_pct;
    payload[1] = charging ? 1u : 0u;
    wr_le32(&payload[2], steps);
    wr_le16(&payload[6], hr_bpm);
    wr_le32(&payload[8], uptime_sec);
    return proto_encode(out, out_cap, PROTO_TELEMETRY, seq, payload, sizeof payload);
}

void proto_decoder_init(struct proto_decoder *dec) {
    if (!dec) return;
    dec->state = DEC_MAGIC0;
    dec->pos = 0;
    dec->frames_ok = 0;
    dec->crc_errors = 0;
    dec->framing_errors = 0;
}

int proto_decoder_feed(struct proto_decoder *dec, uint8_t byte, struct proto_frame *out) {
    if (!dec || !out) return -1;

    switch (dec->state) {
    case DEC_MAGIC0:
        if (byte == PROTO_MAGIC_0) {
            dec->header[0] = byte;
            dec->state = DEC_MAGIC1;
        }
        return 0;

    case DEC_MAGIC1:
        if (byte == PROTO_MAGIC_1) {
            dec->header[1] = byte;
            dec->pos = 2;
            dec->state = DEC_HEADER;
        } else if (byte == PROTO_MAGIC_0) {
            dec->header[0] = byte;
        } else {
            dec->state = DEC_MAGIC0;
        }
        return 0;

    case DEC_HEADER:
        dec->header[dec->pos++] = byte;
        if (dec->pos < PROTO_HEADER_LEN) {
            return 0;
        }
        dec->cur.version = dec->header[2];
        dec->cur.type = dec->header[3];
        dec->cur.seq = rd_le16(&dec->header[4]);
        dec->cur.len = rd_le16(&dec->header[6]);
        if (dec->cur.version != PROTO_VERSION || dec->cur.len > PROTO_MAX_PAYLOAD) {
            dec->framing_errors++;
            dec->state = DEC_MAGIC0;
            return -1;
        }
        dec->pos = 0;
        dec->state = dec->cur.len > 0 ? DEC_PAYLOAD : DEC_CRC;
        return 0;

    case DEC_PAYLOAD:
        dec->cur.payload[dec->pos++] = byte;
        if (dec->pos == dec->cur.len) {
            dec->pos = 0;
            dec->state = DEC_CRC;
        }
        return 0;

    case DEC_CRC:
        dec->crc_buf[dec->pos++] = byte;
        if (dec->pos < PROTO_CRC_LEN) {
            return 0;
        }
        dec->state = DEC_MAGIC0;
        uint32_t expected = rd_le32(dec->crc_buf);
        uint32_t calc = 0xFFFFFFFFu;
        calc = crc32_update(calc, dec->header, PROTO_HEADER_LEN);
        calc = crc32_update(calc, dec->cur.payload, dec->cur.len);
        calc = ~calc;
        if (calc != expected) {
            dec->crc_errors++;
            return -1;
        }
        *out = dec->cur;
        dec->frames_ok++;
        return 1;
    }

    dec->state = DEC_MAGIC0;
    return -1;
}

static bool read_len_str(const uint8_t *buf, uint16_t buf_len, uint16_t *off,
                         char *dst, uint32_t dst_cap) {
    if (*off >= buf_len) return false;
    uint8_t slen = buf[(*off)++];
    if ((uint32_t)(*off) + slen > buf_len) return false;
    uint32_t copy = slen;
    if (copy + 1u > dst_cap) copy = dst_cap - 1u;
    for (uint32_t i = 0; i < copy; i++) {
        dst[i] = (char)buf[*off + i];
    }
    dst[copy] = '\0';
    *off = (uint16_t)(*off + slen);
    return true;
}

static void send_reply(const struct proto_tx *tx, uint8_t type, uint16_t seq,
                       const uint8_t *payload, uint16_t len) {
    if (!tx || !tx->send) return;
    uint8_t frame[PROTO_HEADER_LEN + 16u + PROTO_CRC_LEN];
    if (len > 16u) return;
    int n = proto_encode(frame, sizeof frame, type, seq, payload, len);
    if (n > 0) {
        (void)tx->send(frame, (uint32_t)n, tx->ctx);
    }
}

int proto_dispatch(const struct proto_frame *frame, const struct proto_tx *tx,
                   int64_t *synced_unix_sec_out, int16_t *synced_tz_min_out) {
    if (!frame) return -1;
    const uint8_t *p = frame->payload;
    uint16_t len = frame->len;

    switch (frame->type) {
    case PROTO_PING:
        send_reply(tx, PROTO_PONG, frame->seq, NULL, 0);
        return 0;

    case PROTO_TIME_SYNC: {
        if (len < 10u) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        uint64_t lo = rd_le32(&p[0]);
        uint64_t hi = rd_le32(&p[4]);
        int64_t unix_sec = (int64_t)(lo | (hi << 32));
        int16_t tz_min = (int16_t)rd_le16(&p[8]);
        if (synced_unix_sec_out) *synced_unix_sec_out = unix_sec;
        if (synced_tz_min_out) *synced_tz_min_out = tz_min;
        send_reply(tx, PROTO_ACK, frame->seq, NULL, 0);
        return 0;
    }

    case PROTO_NOTIFY_POST: {
        if (len < 12u) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        struct notification n = {0};
        n.id = rd_le32(&p[0]);
        n.timestamp_sec = rd_le32(&p[4]);
        n.unread = true;
        uint16_t off = 8;
        if (!read_len_str(p, len, &off, n.app, NOTIFY_APP_MAX) ||
            !read_len_str(p, len, &off, n.title, NOTIFY_TITLE_MAX) ||
            !read_len_str(p, len, &off, n.body, NOTIFY_BODY_MAX) ||
            off >= len) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        uint8_t act_cnt = p[off++];
        if (act_cnt > NOTIFY_MAX_ACTIONS) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        n.action_count = act_cnt;
        for (uint8_t i = 0; i < act_cnt; i++) {
            if (!read_len_str(p, len, &off, n.actions[i], NOTIFY_ACTION_MAX)) {
                send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
                return -1;
            }
        }
        if (notify_post(&n) != 0) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        send_reply(tx, PROTO_ACK, frame->seq, NULL, 0);
        return 0;
    }

    case PROTO_NOTIFY_DISMISS: {
        if (len < 4u) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        uint32_t id = rd_le32(&p[0]);
        (void)notify_dismiss(id);
        send_reply(tx, PROTO_ACK, frame->seq, NULL, 0);
        return 0;
    }

    case PROTO_NAV_UPDATE: {
        if (len < 10u) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        struct nav_state nav = {0};
        nav.active = true;
        nav.maneuver = p[0];
        nav.roundabout_exit = p[1];
        nav.distance_m = rd_le32(&p[2]);
        nav.eta_min = rd_le16(&p[6]);
        uint16_t off = 8;
        if (!read_len_str(p, len, &off, nav.street, NAV_STREET_MAX) ||
            !read_len_str(p, len, &off, nav.next_street, NAV_NEXT_MAX)) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        nav_update(&nav);
        send_reply(tx, PROTO_ACK, frame->seq, NULL, 0);
        return 0;
    }

    case PROTO_NAV_CLEAR:
        nav_clear();
        send_reply(tx, PROTO_ACK, frame->seq, NULL, 0);
        return 0;

    case PROTO_CALL_STATE: {
        if (len < 3u) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        struct call_info ci = {0};
        ci.state = p[0];
        uint16_t off = 1;
        if (!read_len_str(p, len, &off, ci.caller, CALL_CALLER_MAX) ||
            !read_len_str(p, len, &off, ci.number, CALL_NUMBER_MAX)) {
            send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
            return -1;
        }
        call_update(&ci);
        send_reply(tx, PROTO_ACK, frame->seq, NULL, 0);
        return 0;
    }

    default:
        send_reply(tx, PROTO_NACK, frame->seq, NULL, 0);
        return -1;
    }
}
