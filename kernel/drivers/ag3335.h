/* Portable Airoha AG3335M GNSS driver: PAIR command framing, ACK and NMEA parser. */
#ifndef SPELLBOUND_AG3335_H
#define SPELLBOUND_AG3335_H

#include <stdbool.h>
#include <stdint.h>

#define AG3335_MAX_SENTENCE 128u

/* Verified PAIR command codes */
#define AG3335_PAIR_ACK           1u
#define AG3335_PAIR_POWER_ON      2u
#define AG3335_PAIR_POWER_OFF     3u
#define AG3335_PAIR_SEARCH_MODE   66u
#define AG3335_PAIR_DUAL_BAND     104u
#define AG3335_PAIR_BAND_QUERY    105u
#define AG3335_PAIR_GLP_MODE      680u

struct ag3335_transport {
    int (*write)(const uint8_t *data, uint32_t len, void *ctx);
    void *ctx;
};

struct ag3335_fix {
    bool valid;
    int32_t lat_e6;       /* latitude in microdegrees (N positive, S negative) */
    int32_t lon_e6;       /* longitude in microdegrees (E positive, W negative) */
    uint8_t satellites;
    uint16_t speed_kx10;  /* speed over ground in 0.1 knots */
    int32_t alt_dm;       /* altitude in decimeters (0.1 m) */
};

struct ag3335_ack {
    bool received;
    uint16_t cmd_code;
    uint8_t result; /* 0 = OK */
};

struct ag3335_dev {
    struct ag3335_transport tx;
    char line[AG3335_MAX_SENTENCE];
    uint32_t line_len;
    bool in_sentence;
    struct ag3335_fix fix;
    struct ag3335_ack last_ack;
    uint32_t sentences_ok;
    uint32_t checksum_errors;
};

/* Compute NMEA/PAIR XOR checksum over body (characters between '$' and '*'). */
uint8_t ag3335_xor_checksum(const char *body, uint32_t len);

/* Build "$PAIR<code>[,<params>]*HH\r\n" into out[0..cap). Returns length or -1. */
int ag3335_format_pair(char *out, uint32_t cap, const char *code, const char *params);

void ag3335_init(struct ag3335_dev *dev, const struct ag3335_transport *tx);

int ag3335_send_pair(struct ag3335_dev *dev, const char *code, const char *params);
int ag3335_power_on(struct ag3335_dev *dev);
int ag3335_power_off(struct ag3335_dev *dev);
int ag3335_set_search_mode(struct ag3335_dev *dev, bool gps, bool glonass, bool galileo,
                           bool beidou, bool qzss, bool navic);
int ag3335_set_dual_band(struct ag3335_dev *dev, bool enable);

/* Feed one UART RX byte from the GNSS receiver.
 * Returns 1 when a valid sentence was parsed, 0 if incomplete, -1 on checksum error. */
int ag3335_feed_byte(struct ag3335_dev *dev, uint8_t byte);

#endif /* SPELLBOUND_AG3335_H */
