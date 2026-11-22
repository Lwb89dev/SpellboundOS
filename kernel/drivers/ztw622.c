/* Independently authored ZTW622 capacitive touch controller driver over I2C. */
#include "ztw622.h"
#include "../input.h"
#include <stddef.h>

static void ztw622_delay_ms(const struct ztw622_dev *dev, uint32_t ms) {
    if (dev->cfg.delay_ms) {
        dev->cfg.delay_ms(ms, dev->cfg.delay_ctx);
    }
}

static uint16_t le16_u(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static void put_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)(v >> 8);
}

static int i2c_write_retry(struct ztw622_dev *dev, const uint8_t *buf, uint32_t len) {
    if (i2c_write(dev->cfg.bus, dev->cfg.addr, buf, len) == 0) {
        return 0;
    }
    if (i2c_reset(dev->cfg.bus) != 0) {
        return -2;
    }
    return i2c_write(dev->cfg.bus, dev->cfg.addr, buf, len) == 0 ? 0 : -2;
}

static int i2c_read_retry(struct ztw622_dev *dev, uint8_t *buf, uint32_t len) {
    if (i2c_read(dev->cfg.bus, dev->cfg.addr, buf, len) == 0) {
        return 0;
    }
    if (i2c_reset(dev->cfg.bus) != 0) {
        return -2;
    }
    return i2c_read(dev->cfg.bus, dev->cfg.addr, buf, len) == 0 ? 0 : -2;
}

int ztw622_write_cmd(struct ztw622_dev *dev, uint16_t cmd) {
    if (!dev || !dev->cfg.bus) {
        return -1;
    }
    uint8_t buf[2];
    put_le16(buf, cmd);
    return i2c_write_retry(dev, buf, 2);
}

int ztw622_write_reg(struct ztw622_dev *dev, uint16_t reg, uint16_t value) {
    if (!dev || !dev->cfg.bus) {
        return -1;
    }
    uint8_t buf[4];
    put_le16(&buf[0], reg);
    put_le16(&buf[2], value);
    return i2c_write_retry(dev, buf, 4);
}

int ztw622_read_block(struct ztw622_dev *dev, uint16_t reg, uint8_t *out, uint32_t len) {
    if (!dev || !dev->cfg.bus || !out || len == 0) {
        return -1;
    }
    int rc = ztw622_write_cmd(dev, reg);
    if (rc != 0) {
        return rc;
    }
    return i2c_read_retry(dev, out, len);
}

int ztw622_read_reg(struct ztw622_dev *dev, uint16_t reg, uint16_t *out) {
    if (!out) {
        return -1;
    }
    uint8_t buf[2] = {0, 0};
    int rc = ztw622_read_block(dev, reg, buf, 2);
    if (rc != 0) {
        return rc;
    }
    *out = le16_u(buf);
    return 0;
}

int ztw622_clear_int(struct ztw622_dev *dev) {
    if (!dev || !dev->cfg.bus) {
        return -1;
    }
    for (unsigned attempt = 0; attempt < 3u; attempt++) {
        if (ztw622_write_cmd(dev, ZTW622_CMD_CLEAR_INT) == 0) {
            return 0;
        }
    }
    return -2;
}

static void ztw622_hw_reset(struct ztw622_dev *dev) {
    if (!dev->cfg.gpio || dev->cfg.reset_pin < 0) {
        return;
    }
    uint32_t pin = (uint32_t)dev->cfg.reset_pin;
    (void)gpio_configure(dev->cfg.gpio, pin, GPIO_OUTPUT);
    (void)gpio_write(dev->cfg.gpio, pin, false);
    ztw622_delay_ms(dev, 1);
    (void)gpio_write(dev->cfg.gpio, pin, true);
    ztw622_delay_ms(dev, 10);
    (void)gpio_write(dev->cfg.gpio, pin, false);
    ztw622_delay_ms(dev, 100);
    (void)gpio_write(dev->cfg.gpio, pin, true);
    ztw622_delay_ms(dev, 200);
}

int ztw622_init(struct ztw622_dev *dev, const struct ztw622_config *cfg) {
    if (!dev || !cfg || !cfg->bus || cfg->rotation > 3u) {
        return -1;
    }
    dev->cfg = *cfg;
    if (dev->cfg.addr == 0) {
        dev->cfg.addr = ZTW622_I2C_ADDR;
    }
    if (dev->cfg.max_fingers == 0 || dev->cfg.max_fingers > ZTW622_MAX_SLOTS) {
        dev->cfg.max_fingers = ZTW622_MAX_SLOTS;
    }
    dev->info = (struct ztw622_info){0};
    dev->state = ZTW622_STATE_IDLE;
    dev->probed = false;
    dev->slot_down[0] = false;
    dev->slot_down[1] = false;
    dev->event_count = 0;

    if (dev->cfg.gpio && dev->cfg.irq_pin >= 0) {
        (void)gpio_configure(dev->cfg.gpio, (uint32_t)dev->cfg.irq_pin, GPIO_INPUT_PULLUP);
    }
    ztw622_hw_reset(dev);

    /* Probe sequence: 0x01F8, unlock 0xC000=1, read 22-byte info block, soft reset 0x0FF8. */
    uint8_t info_blk[22] = {0};
    bool info_ok = false;
    if (ztw622_write_cmd(dev, ZTW622_CMD_POWER_SEQ) == 0) {
        ztw622_delay_ms(dev, 100);
        if (ztw622_write_reg(dev, ZTW622_REG_VENDOR_UNLOCK, 1u) == 0 &&
            ztw622_read_block(dev, ZTW622_REG_INFO_BLOCK, info_blk, sizeof info_blk) == 0 &&
            ztw622_write_cmd(dev, ZTW622_CMD_SOFT_RESET) == 0) {
            ztw622_delay_ms(dev, 100);
            info_ok = true;
        }
    }

    uint16_t chip_id = 0;
    if (info_ok) {
        chip_id = le16_u(&info_blk[0x0A]);
        dev->info.ium_id = ((uint32_t)info_blk[8] << 16) |
                           ((uint32_t)info_blk[0x0D] << 8) |
                           (uint32_t)info_blk[0x0C];
    }
    if (chip_id != ZTW622_CHIP_ID) {
        /* Fallback direct chip ID register read (up to 2 attempts). */
        int last_rc = -3;
        for (unsigned attempt = 0; attempt < 2u; attempt++) {
            uint16_t id = 0;
            int rc = ztw622_read_reg(dev, ZTW622_REG_CHIP_ID, &id);
            if (rc == 0) {
                chip_id = id;
                if (chip_id == ZTW622_CHIP_ID) {
                    break;
                }
                last_rc = -3;
            } else {
                last_rc = -2;
            }
        }
        if (chip_id != ZTW622_CHIP_ID) {
            return last_rc;
        }
    }
    dev->info.chip_id = chip_id;

    /* Read firmware version and resolution. */
    (void)ztw622_write_cmd(dev, ZTW622_CMD_RESET_FAST);
    if (ztw622_read_reg(dev, ZTW622_REG_FW_MAJOR, &dev->info.fw_major) != 0 ||
        ztw622_read_reg(dev, ZTW622_REG_FW_MINOR, &dev->info.fw_minor) != 0 ||
        ztw622_read_reg(dev, ZTW622_REG_FW_RELEASE, &dev->info.fw_release) != 0 ||
        ztw622_read_reg(dev, ZTW622_REG_X_RES, &dev->info.x_res) != 0 ||
        ztw622_read_reg(dev, ZTW622_REG_Y_RES, &dev->info.y_res) != 0 ||
        ztw622_read_reg(dev, ZTW622_REG_X_CHANNELS, &dev->info.x_channels) != 0 ||
        ztw622_read_reg(dev, ZTW622_REG_Y_CHANNELS, &dev->info.y_channels) != 0) {
        return -2;
    }

    /* Enable touch reporting configuration and optional active nap delay. */
    if (ztw622_write_reg(dev, ZTW622_REG_ACTIVE_CFG, 0x003Cu) != 0 ||
        ztw622_write_cmd(dev, ZTW622_CMD_RESET_FAST) != 0 ||
        ztw622_clear_int(dev) != 0) {
        return -2;
    }
    if (dev->cfg.nap_delay > 0) {
        if (ztw622_write_reg(dev, ZTW622_REG_NAP_DELAY, dev->cfg.nap_delay) != 0) {
            return -2;
        }
    }

    dev->probed = true;
    dev->state = ZTW622_STATE_REPORT;
    return 0;
}

int ztw622_set_state(struct ztw622_dev *dev, enum ztw622_state state) {
    if (!dev || !dev->probed) {
        return -1;
    }
    if (state != ZTW622_STATE_IDLE && state != ZTW622_STATE_REPORT &&
        state != ZTW622_STATE_GESTURE) {
        return -1;
    }
    dev->state = state;
    if (state != ZTW622_STATE_REPORT) {
        dev->slot_down[0] = false;
        dev->slot_down[1] = false;
    }
    return 0;
}

static void transform_coords(const struct ztw622_dev *dev, uint16_t raw_x, uint16_t raw_y,
                             int16_t *out_x, int16_t *out_y) {
    int32_t xr = (int32_t)dev->info.x_res;
    int32_t yr = (int32_t)dev->info.y_res;
    int32_t x = (int32_t)raw_x;
    int32_t y = (int32_t)raw_y;
    int32_t rx = x;
    int32_t ry = y;

    switch (dev->cfg.rotation) {
    case 0:
        rx = x;
        ry = y;
        break;
    case 1:
        rx = y;
        ry = xr - x;
        break;
    case 2:
        rx = xr - x;
        ry = yr - y;
        break;
    case 3:
        rx = yr - y;
        ry = x;
        break;
    default:
        break;
    }
    if (dev->cfg.flip_180) {
        rx = xr - rx;
        ry = yr - ry;
    }
    if (rx < -32768) rx = -32768;
    if (rx > 32767) rx = 32767;
    if (ry < -32768) ry = -32768;
    if (ry > 32767) ry = 32767;
    *out_x = (int16_t)rx;
    *out_y = (int16_t)ry;
}

int ztw622_poll(struct ztw622_dev *dev) {
    if (!dev || !dev->probed) {
        return -1;
    }
    int posted = 0;

    if (dev->state == ZTW622_STATE_IDLE) {
        return ztw622_clear_int(dev) == 0 ? 0 : -2;
    }

    if (dev->state == ZTW622_STATE_GESTURE) {
        dev->event_count++;
        uint16_t gesture = 0;
        if (ztw622_read_reg(dev, ZTW622_REG_GESTURE_ID, &gesture) != 0) {
            return -2;
        }
        (void)ztw622_write_reg(dev, ZTW622_REG_GESTURE_ID, 0u);
        if (gesture != 0 && (gesture & dev->cfg.gesture_mask) != 0) {
            struct input_event ev = {
                .timestamp_ticks = 0,
                .type = INPUT_TOUCH,
                .action = INPUT_TOUCH_GESTURE,
                .code = gesture,
                .x = 0,
                .y = 0,
            };
            if (input_post(&ev)) {
                posted++;
            }
        }
        return ztw622_clear_int(dev) == 0 ? posted : -2;
    }

    /* ZTW622_STATE_REPORT: read 16-byte point status block from 0x0080. */
    dev->event_count++;
    uint8_t blk[16];
    if (ztw622_read_block(dev, ZTW622_REG_POINT_STATUS, blk, sizeof blk) != 0) {
        return -2;
    }
    uint16_t status = le16_u(&blk[0]);
    uint8_t count = blk[2];

    if ((status & ZTW622_STATUS_LARGE_OBJ) != 0 && dev->cfg.large_object_enable) {
        (void)ztw622_write_reg(dev, ZTW622_REG_GESTURE_ID, 0u);
        struct input_event ev = {
            .timestamp_ticks = 0,
            .type = INPUT_TOUCH,
            .action = INPUT_TOUCH_GESTURE,
            .code = ZTW622_STATUS_LARGE_OBJ,
            .x = 0,
            .y = 0,
        };
        if (input_post(&ev)) {
            posted++;
        }
    } else if ((status & ZTW622_STATUS_POINT_MASK) != 0) {
        uint8_t limit = count;
        if (limit > dev->cfg.max_fingers) {
            limit = dev->cfg.max_fingers;
        }
        for (uint8_t slot = 0; slot < limit; slot++) {
            const uint8_t *pt = &blk[4u + (uint32_t)slot * 6u];
            uint16_t raw_x = le16_u(&pt[0]);
            uint16_t raw_y = le16_u(&pt[2]);
            uint8_t sub_status = pt[5];
            if ((sub_status & 0x0Fu) == 0) {
                continue;
            }
            bool down = (sub_status & 0x08u) == 0;
            int16_t tx = 0;
            int16_t ty = 0;
            transform_coords(dev, raw_x, raw_y, &tx, &ty);

            uint8_t action = 0;
            if (down) {
                action = dev->slot_down[slot] ? INPUT_TOUCH_MOVE : INPUT_TOUCH_DOWN;
                dev->slot_down[slot] = true;
            } else {
                action = INPUT_TOUCH_UP;
                dev->slot_down[slot] = false;
            }
            struct input_event ev = {
                .timestamp_ticks = 0,
                .type = INPUT_TOUCH,
                .action = action,
                .code = slot,
                .x = tx,
                .y = ty,
            };
            if (input_post(&ev)) {
                posted++;
            }
        }
    }
    return ztw622_clear_int(dev) == 0 ? posted : -2;
}
