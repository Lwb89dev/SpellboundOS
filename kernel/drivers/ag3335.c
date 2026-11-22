/* Independently authored Airoha AG3335M GNSS PAIR/NMEA driver (no FPU/stdio). */
#include "ag3335.h"
#include <stddef.h>

static const char hex_upper[] = "0123456789ABCDEF";

uint8_t ag3335_xor_checksum(const char *body, uint32_t len) {
    uint8_t sum = 0;
    for (uint32_t i = 0; i < len; i++) {
        sum ^= (uint8_t)body[i];
    }
    return sum;
}

static uint32_t str_len_n(const char *s) {
    uint32_t n = 0;
    while (s && s[n] != '\0') n++;
    return n;
}

int ag3335_format_pair(char *out, uint32_t cap, const char *code, const char *params) {
    if (!out || !code || code[0] == '\0') {
        return -1;
    }
    uint32_t clen = str_len_n(code);
    uint32_t plen = (params && params[0] != '\0') ? str_len_n(params) : 0;
    uint32_t body_len = 4u + clen + (plen > 0 ? 1u + plen : 0u);
    /* '$' + body + '*HH\r\n' + '\0' */
    uint32_t total = 1u + body_len + 5u;
    if (total + 1u > cap) {
        return -1;
    }
    uint32_t p = 0;
    out[p++] = '$';
    uint32_t body_start = p;
    out[p++] = 'P'; out[p++] = 'A'; out[p++] = 'I'; out[p++] = 'R';
    for (uint32_t i = 0; i < clen; i++) out[p++] = code[i];
    if (plen > 0) {
        out[p++] = ',';
        for (uint32_t i = 0; i < plen; i++) out[p++] = params[i];
    }
    uint8_t cksum = ag3335_xor_checksum(&out[body_start], p - body_start);
    out[p++] = '*';
    out[p++] = hex_upper[(cksum >> 4) & 0x0Fu];
    out[p++] = hex_upper[cksum & 0x0Fu];
    out[p++] = '\r';
    out[p++] = '\n';
    out[p] = '\0';
    return (int)p;
}

void ag3335_init(struct ag3335_dev *dev, const struct ag3335_transport *tx) {
    if (!dev) return;
    dev->tx = tx ? *tx : (struct ag3335_transport){0};
    dev->line_len = 0;
    dev->in_sentence = false;
    dev->fix = (struct ag3335_fix){0};
    dev->last_ack = (struct ag3335_ack){0};
    dev->sentences_ok = 0;
    dev->checksum_errors = 0;
}

int ag3335_send_pair(struct ag3335_dev *dev, const char *code, const char *params) {
    if (!dev || !dev->tx.write) return -1;
    char frame[AG3335_MAX_SENTENCE];
    int n = ag3335_format_pair(frame, sizeof frame, code, params);
    if (n <= 0) return -1;
    return dev->tx.write((const uint8_t *)frame, (uint32_t)n, dev->tx.ctx) == 0 ? 0 : -2;
}

int ag3335_power_on(struct ag3335_dev *dev) {
    return ag3335_send_pair(dev, "002", NULL);
}

int ag3335_power_off(struct ag3335_dev *dev) {
    return ag3335_send_pair(dev, "003", NULL);
}

int ag3335_set_search_mode(struct ag3335_dev *dev, bool gps, bool glonass, bool galileo,
                           bool beidou, bool qzss, bool navic) {
    char p[12] = {
        gps ? '1' : '0', ',',
        glonass ? '1' : '0', ',',
        galileo ? '1' : '0', ',',
        beidou ? '1' : '0', ',',
        qzss ? '1' : '0', ',',
        navic ? '1' : '0', '\0',
    };
    return ag3335_send_pair(dev, "066", p);
}

int ag3335_set_dual_band(struct ag3335_dev *dev, bool enable) {
    return ag3335_send_pair(dev, "104", enable ? "1" : "0");
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return -1;
}

static bool starts_with(const char *s, const char *prefix) {
    while (*prefix) {
        if (*s != *prefix) return false;
        s++; prefix++;
    }
    return true;
}

static uint32_t parse_u32_field(const char *s) {
    uint32_t v = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10u + (uint32_t)(*s - '0');
        s++;
    }
    return v;
}

/* Parse NMEA ddmm.mmmm (lat) or dddmm.mmmm (lon) into signed microdegrees. */
static bool parse_nmea_coord(const char *field, char hemi, bool is_lon, int32_t *out_e6) {
    if (!field || !*field) return false;
    uint32_t deg_digits = is_lon ? 3u : 2u;
    uint32_t deg = 0;
    for (uint32_t i = 0; i < deg_digits; i++) {
        if (field[i] < '0' || field[i] > '9') return false;
        deg = deg * 10u + (uint32_t)(field[i] - '0');
    }
    const char *p = &field[deg_digits];
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') return false;
    uint32_t min_int = (uint32_t)(p[0] - '0') * 10u + (uint32_t)(p[1] - '0');
    p += 2;
    uint32_t min_frac = 0; /* scaled to 1e4 */
    uint32_t scale = 1000u;
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9' && scale > 0) {
            min_frac += (uint32_t)(*p - '0') * scale;
            scale /= 10u;
            p++;
        }
    }
    /* total minutes * 1e4 -> microdegrees = (min_e4 * 100) / 60 = (min_e4 * 5) / 3 */
    uint32_t min_e4 = min_int * 10000u + min_frac;
    int32_t micro = (int32_t)(deg * 1000000u + (min_e4 * 5u + 1u) / 3u);
    if (hemi == 'S' || hemi == 'W') micro = -micro;
    *out_e6 = micro;
    return true;
}

/* Parse signed decimal with 1 decimal place (e.g. "123.4" -> 1234, "-5.2" -> -52). */
static int32_t parse_dec_x10(const char *s) {
    if (!s || !*s) return 0;
    bool neg = false;
    if (*s == '-') { neg = true; s++; }
    int32_t whole = 0;
    while (*s >= '0' && *s <= '9') {
        whole = whole * 10 + (*s - '0');
        s++;
    }
    int32_t frac = 0;
    if (*s == '.' && s[1] >= '0' && s[1] <= '9') {
        frac = s[1] - '0';
    }
    int32_t res = whole * 10 + frac;
    return neg ? -res : res;
}

static void handle_sentence(struct ag3335_dev *dev, char *body) {
    char *fields[16];
    uint32_t nf = 0;
    char *p = body;
    fields[nf++] = p;
    while (*p && nf < 16u) {
        if (*p == ',') {
            *p = '\0';
            fields[nf++] = p + 1;
        }
        p++;
    }

    if (starts_with(fields[0], "PAIR001") && nf >= 3u) {
        dev->last_ack.received = true;
        dev->last_ack.cmd_code = (uint16_t)parse_u32_field(fields[1]);
        dev->last_ack.result = (uint8_t)parse_u32_field(fields[2]);
        return;
    }

    /* $GxRMC: 1=time, 2=status(A/V), 3=lat, 4=N/S, 5=lon, 6=E/W, 7=speed(knots) */
    if (str_len_n(fields[0]) == 5u && starts_with(&fields[0][2], "RMC") && nf >= 8u) {
        bool ok = (fields[2][0] == 'A');
        dev->fix.valid = ok;
        if (ok) {
            int32_t lat = 0, lon = 0;
            if (parse_nmea_coord(fields[3], fields[4][0], false, &lat) &&
                parse_nmea_coord(fields[5], fields[6][0], true, &lon)) {
                dev->fix.lat_e6 = lat;
                dev->fix.lon_e6 = lon;
            }
            int32_t spd = parse_dec_x10(fields[7]);
            dev->fix.speed_kx10 = spd > 0 ? (uint16_t)spd : 0u;
        }
        return;
    }

    /* $GxGGA: 6=fix_qual, 7=sats, 9=alt(m) */
    if (str_len_n(fields[0]) == 5u && starts_with(&fields[0][2], "GGA") && nf >= 10u) {
        uint32_t qual = parse_u32_field(fields[6]);
        dev->fix.valid = (qual > 0);
        dev->fix.satellites = (uint8_t)parse_u32_field(fields[7]);
        dev->fix.alt_dm = parse_dec_x10(fields[9]);
    }
}

int ag3335_feed_byte(struct ag3335_dev *dev, uint8_t byte) {
    if (!dev) return -1;
    char c = (char)byte;
    if (c == '$') {
        dev->in_sentence = true;
        dev->line_len = 0;
        return 0;
    }
    if (!dev->in_sentence) {
        return 0;
    }
    if (c == '\r' || c == '\n') {
        dev->in_sentence = false;
        if (dev->line_len < 4u) return 0;
        dev->line[dev->line_len] = '\0';

        /* Locate '*' checksum separator */
        int star = -1;
        for (uint32_t i = 0; i < dev->line_len; i++) {
            if (dev->line[i] == '*') { star = (int)i; break; }
        }
        if (star <= 0 || (uint32_t)star + 3u > dev->line_len) {
            dev->checksum_errors++;
            return -1;
        }
        int hi = hex_val(dev->line[star + 1]);
        int lo = hex_val(dev->line[star + 2]);
        if (hi < 0 || lo < 0) {
            dev->checksum_errors++;
            return -1;
        }
        uint8_t expected = (uint8_t)((hi << 4) | lo);
        uint8_t calc = ag3335_xor_checksum(dev->line, (uint32_t)star);
        if (calc != expected) {
            dev->checksum_errors++;
            return -1;
        }
        dev->line[star] = '\0';
        handle_sentence(dev, dev->line);
        dev->sentences_ok++;
        return 1;
    }
    if (dev->line_len + 1u < AG3335_MAX_SENTENCE) {
        dev->line[dev->line_len++] = c;
    } else {
        dev->in_sentence = false;
        dev->checksum_errors++;
        return -1;
    }
    return 0;
}
