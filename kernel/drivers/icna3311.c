/* Independently authored Chipone ICNA3311 AMOLED MIPI DCS panel driver. */
#include "icna3311.h"
#include <stddef.h>

static const uint32_t icna3311_known_ids[9] = {
    0x250905u, 0x5A0905u, 0x250906u,
    0x1B0909u, 0x4B090Du, 0x5C0913u,
    0x5B0913u, 0x250914u, 0x2C0914u,
};

static void icna_delay_ms(const struct icna3311_dev *dev, uint32_t ms) {
    if (dev->cfg.delay_ms) {
        dev->cfg.delay_ms(ms, dev->cfg.delay_ctx);
    }
}

static int dcs_write(const struct icna3311_dev *dev, const uint8_t *data, uint32_t len) {
    if (!dev || !dev->cfg.bus || !dev->cfg.bus->ops || !dev->cfg.bus->ops->write_cmd) {
        return -1;
    }
    return dev->cfg.bus->ops->write_cmd(dev->cfg.bus, data, len) == 0 ? 0 : -2;
}

static int dcs_read(const struct icna3311_dev *dev, uint8_t cmd, uint8_t *out, uint32_t len) {
    if (!dev || !dev->cfg.bus || !dev->cfg.bus->ops || !dev->cfg.bus->ops->read_cmd) {
        return -1;
    }
    return dev->cfg.bus->ops->read_cmd(dev->cfg.bus, cmd, out, len) == 0 ? 0 : -2;
}

static int icna_page0_unlock(const struct icna3311_dev *dev) {
    static const uint8_t seq[4][2] = {
        {0xFEu, 0x80u}, {0xF4u, 0x00u}, {0xF5u, 0x00u}, {0xFEu, 0x00u},
    };
    for (unsigned i = 0; i < 4u; i++) {
        if (dcs_write(dev, seq[i], 2) != 0) return -2;
    }
    return 0;
}

static int icna_page0_lock(const struct icna3311_dev *dev) {
    static const uint8_t seq[4][2] = {
        {0xFEu, 0x80u}, {0xF4u, 0xACu}, {0xF5u, 0xE1u}, {0xFEu, 0x00u},
    };
    for (unsigned i = 0; i < 4u; i++) {
        if (dcs_write(dev, seq[i], 2) != 0) return -2;
    }
    return 0;
}

bool icna3311_is_known_variant(uint32_t panel_id) {
    for (unsigned i = 0; i < 9u; i++) {
        if (icna3311_known_ids[i] == panel_id) {
            return true;
        }
    }
    return false;
}

uint32_t icna3311_read_id(struct icna3311_dev *dev) {
    if (!dev || !dev->cfg.bus) {
        return 0;
    }
    uint8_t b0 = 0, b1 = 0, b2 = 0;
    if (dcs_read(dev, DCS_CMD_READ_ID1, &b0, 1) != 0 ||
        dcs_read(dev, DCS_CMD_READ_ID2, &b1, 1) != 0 ||
        dcs_read(dev, DCS_CMD_READ_ID3, &b2, 1) != 0) {
        return 0;
    }
    return ((uint32_t)b0 << 16) | ((uint32_t)b1 << 8) | (uint32_t)b2;
}

int icna3311_play_table(struct icna3311_dev *dev, const uint8_t *table, uint32_t len) {
    if (!dev || !table || len < 2u) {
        return -1;
    }
    uint32_t pos = 0;
    while (pos < len) {
        if (pos + 2u > len) {
            return -1;
        }
        uint8_t op = table[pos];
        uint8_t nargs = table[pos + 1u];
        if (pos + 2u + nargs > len) {
            return -1;
        }
        const uint8_t *payload = &table[pos + 2u];
        if (op == ICNA3311_OP_WRITE) {
            if (nargs == 0 || dcs_write(dev, payload, nargs) != 0) {
                return -2;
            }
        } else if (op == ICNA3311_OP_DELAY) {
            if (nargs >= 1u) {
                icna_delay_ms(dev, payload[0]);
            }
        } else {
            return -1;
        }
        pos += 2u + nargs;
    }
    return 0;
}

int icna3311_init(struct icna3311_dev *dev, const struct icna3311_config *cfg) {
    if (!dev || !cfg || !cfg->bus || !cfg->bus->ops ||
        cfg->width == 0 || cfg->height == 0) {
        return -1;
    }
    dev->cfg = *cfg;
    dev->panel_id = 0;
    dev->probed = false;
    dev->power_on = false;
    dev->dimming = false;
    dev->hbm = false;
    dev->brightness = 0;
    dev->flush_count = 0;

    uint32_t id = icna3311_read_id(dev);
    dev->panel_id = id;
    if (!icna3311_is_known_variant(id)) {
        return -3;
    }

    /* Clean-room bring-up sequence: RGB565 (0x55), TE on, sleep out, 120 ms, display on. */
    static const uint8_t bringup_seq[] = {
        ICNA3311_OP_WRITE, 2, DCS_CMD_SET_PIXEL_FMT, 0x55u,
        ICNA3311_OP_WRITE, 2, DCS_CMD_SET_TEAR_ON,   0x00u,
        ICNA3311_OP_WRITE, 2, DCS_CMD_SET_CTRL_DISP, 0x20u,
        ICNA3311_OP_WRITE, 2, DCS_CMD_SET_BRIGHTNESS, 0x80u,
        ICNA3311_OP_WRITE, 1, DCS_CMD_SLEEP_OUT,
        ICNA3311_OP_DELAY, 1, 120u,
        ICNA3311_OP_WRITE, 1, DCS_CMD_DISPLAY_ON,
    };
    if (icna3311_play_table(dev, bringup_seq, sizeof bringup_seq) != 0) {
        return -2;
    }
    dev->probed = true;
    dev->power_on = true;
    dev->brightness = 0x80u;
    return 0;
}

int icna3311_set_power(struct icna3311_dev *dev, bool on) {
    if (!dev || !dev->probed) {
        return -1;
    }
    if (on) {
        static const uint8_t on_seq[] = {
            ICNA3311_OP_WRITE, 1, DCS_CMD_SLEEP_OUT,
            ICNA3311_OP_DELAY, 1, 120u,
            ICNA3311_OP_WRITE, 1, DCS_CMD_DISPLAY_ON,
        };
        if (icna3311_play_table(dev, on_seq, sizeof on_seq) != 0) {
            return -2;
        }
        dev->power_on = true;
    } else {
        static const uint8_t off_seq[] = {
            ICNA3311_OP_WRITE, 1, DCS_CMD_DISPLAY_OFF,
            ICNA3311_OP_DELAY, 1, 20u,
            ICNA3311_OP_WRITE, 1, DCS_CMD_SLEEP_IN,
            ICNA3311_OP_DELAY, 1, 100u,
        };
        if (icna3311_play_table(dev, off_seq, sizeof off_seq) != 0) {
            return -2;
        }
        dev->power_on = false;
    }
    return 0;
}

int icna3311_set_brightness(struct icna3311_dev *dev, uint8_t level) {
    if (!dev || !dev->probed) {
        return -1;
    }
    uint8_t cmd[2] = {DCS_CMD_SET_BRIGHTNESS, level};
    if (icna_page0_unlock(dev) != 0 || dcs_write(dev, cmd, 2) != 0 ||
        icna_page0_lock(dev) != 0) {
        return -2;
    }
    dev->brightness = level;
    return 0;
}

int icna3311_set_dimming(struct icna3311_dev *dev, bool enable) {
    if (!dev || !dev->probed) {
        return -1;
    }
    uint8_t cmd[2] = {DCS_CMD_SET_CTRL_DISP, enable ? 0x28u : 0x20u};
    if (icna_page0_unlock(dev) != 0 || dcs_write(dev, cmd, 2) != 0 ||
        icna_page0_lock(dev) != 0) {
        return -2;
    }
    dev->dimming = enable;
    return 0;
}

int icna3311_set_hbm(struct icna3311_dev *dev, bool enable) {
    if (!dev || !dev->probed) {
        return -1;
    }
    uint8_t cmd[2] = {DCS_CMD_SET_HBM, enable ? 0x02u : 0x00u};
    if (icna_page0_unlock(dev) != 0 || dcs_write(dev, cmd, 2) != 0 ||
        icna_page0_lock(dev) != 0) {
        return -2;
    }
    dev->hbm = enable;
    return 0;
}

int icna3311_set_window(struct icna3311_dev *dev,
                        uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1) {
    if (!dev || !dev->probed || x0 > x1 || y0 > y1 ||
        x1 >= dev->cfg.width || y1 >= dev->cfg.height) {
        return -1;
    }
    uint8_t caset[5] = {
        DCS_CMD_SET_COL_ADDR,
        (uint8_t)(x0 >> 8), (uint8_t)(x0 & 0xFFu),
        (uint8_t)(x1 >> 8), (uint8_t)(x1 & 0xFFu),
    };
    uint8_t raset[5] = {
        DCS_CMD_SET_ROW_ADDR,
        (uint8_t)(y0 >> 8), (uint8_t)(y0 & 0xFFu),
        (uint8_t)(y1 >> 8), (uint8_t)(y1 & 0xFFu),
    };
    if (dcs_write(dev, caset, 5) != 0 || dcs_write(dev, raset, 5) != 0) {
        return -2;
    }
    return 0;
}

int icna3311_flush_fb(struct icna3311_dev *dev, struct fb *fb) {
    if (!dev || !dev->probed || !fb || !fb->pixels ||
        fb->width > dev->cfg.width || fb->height > dev->cfg.height) {
        return -1;
    }
    struct fb_rect r;
    if (!fb_get_dirty(fb, &r)) {
        return 0;
    }
    if (dev->cfg.even_align_window) {
        r.x0 &= (uint16_t)(~1u);
        r.y0 &= (uint16_t)(~1u);
        if ((r.x1 & 1u) == 0 && (uint16_t)(r.x1 + 1u) < fb->width) r.x1++;
        if ((r.y1 & 1u) == 0 && (uint16_t)(r.y1 + 1u) < fb->height) r.y1++;
    }
    if (icna3311_set_window(dev, r.x0, r.y0, r.x1, r.y1) != 0) {
        return -2;
    }
    uint8_t ramwr = DCS_CMD_WRITE_MEM;
    if (dcs_write(dev, &ramwr, 1) != 0) {
        return -2;
    }
    if (dev->cfg.bus->ops->write_pixels) {
        uint16_t w = (uint16_t)(r.x1 - r.x0 + 1u);
        uint16_t h = (uint16_t)(r.y1 - r.y0 + 1u);
        if (dev->cfg.bus->ops->write_pixels(dev->cfg.bus, fb->pixels, fb->width,
                                            r.x0, r.y0, w, h) != 0) {
            return -2;
        }
    }
    fb_clear_dirty(fb);
    dev->flush_count++;
    return 1;
}
