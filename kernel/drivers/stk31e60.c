/* Independently authored STK31E60 ambient light sensor driver over I2C. */
#include "stk31e60.h"
#include "../sensor.h"
#include <stddef.h>

static void stk_delay_ms(const struct stk31e60_dev *dev, uint32_t ms) {
    if (dev->cfg.delay_ms) {
        dev->cfg.delay_ms(ms, dev->cfg.delay_ctx);
    }
}

int stk31e60_read_reg(struct stk31e60_dev *dev, uint8_t reg, uint8_t *out) {
    if (!dev || !dev->cfg.bus || !out) {
        return -1;
    }
    for (unsigned attempt = 0; attempt < 3u; attempt++) {
        if (i2c_write_read(dev->cfg.bus, dev->cfg.addr, &reg, 1, out, 1) == 0) {
            return 0;
        }
        if (attempt + 1u < 3u) {
            stk_delay_ms(dev, 2);
        }
    }
    return -2;
}

int stk31e60_write_reg(struct stk31e60_dev *dev, uint8_t reg, uint8_t value) {
    if (!dev || !dev->cfg.bus) {
        return -1;
    }
    uint8_t buf[2] = {reg, value};
    for (unsigned attempt = 0; attempt < 3u; attempt++) {
        if (i2c_write(dev->cfg.bus, dev->cfg.addr, buf, 2) == 0) {
            return 0;
        }
        if (attempt + 1u < 3u) {
            stk_delay_ms(dev, 2);
        }
    }
    return -2;
}

uint16_t stk31e60_encode_it(uint16_t ms_x10) {
    if (ms_x10 == 0) {
        ms_x10 = STK31E60_DEFAULT_IT_MS_X10;
    }
    uint32_t ticks = ((uint32_t)ms_x10 * 100u) / 99u;
    if (ticks == 0) {
        return 0;
    }
    ticks -= 1u;
    return ticks > 0xFFFFu ? 0xFFFFu : (uint16_t)ticks;
}

static uint32_t stk_raw_to_lux(uint16_t raw, uint8_t gain_code) {
    /* Reference gain 0xB0 maps 1:1; higher nibble doubles sensitivity (halves lux/count),
     * lower nibble halves sensitivity (doubles lux/count). */
    int nibble = (int)((gain_code >> 4) & 0x0Fu);
    int diff = nibble - 0x0B;
    uint32_t lux = raw;
    if (diff > 0) {
        lux >>= (unsigned)diff;
    } else if (diff < 0) {
        unsigned shift = (unsigned)(-diff);
        if (shift > 15u) {
            shift = 15u;
        }
        lux <<= shift;
    }
    return lux;
}

int stk31e60_set_gain(struct stk31e60_dev *dev, uint8_t gain_code) {
    if (!dev || !dev->cfg.bus || (gain_code & 0x0Fu) != 0) {
        return -1;
    }
    int rc = stk31e60_write_reg(dev, STK31E60_REG_GAIN, gain_code);
    if (rc == 0) {
        dev->gain_code = gain_code;
    }
    return rc;
}

int stk31e60_init(struct stk31e60_dev *dev, const struct stk31e60_config *cfg) {
    if (!dev || !cfg || !cfg->bus) {
        return -1;
    }
    dev->cfg = *cfg;
    if (dev->cfg.addr == 0) {
        dev->cfg.addr = STK31E60_I2C_ADDR;
    }
    if (dev->cfg.integration_ms_x10 == 0) {
        dev->cfg.integration_ms_x10 = STK31E60_DEFAULT_IT_MS_X10;
    }
    if (dev->cfg.gain_code == 0) {
        dev->cfg.gain_code = STK31E60_GAIN_REF_CODE;
    }
    dev->probed = false;
    dev->chip_id = 0;
    dev->last_raw = 0;
    dev->has_cached = false;

    /* Verify chip ID at 0x3E == 0xE0. */
    uint8_t id = 0;
    int rc = stk31e60_read_reg(dev, STK31E60_REG_CHIP_ID, &id);
    if (rc != 0) {
        return -2;
    }
    dev->chip_id = id;
    if (id != STK31E60_CHIP_ID) {
        return -3;
    }

    /* Ensure vendor trim registers 0xE3/0xE5/0xEA/0xEC are 0x80 (write only on mismatch). */
    static const uint8_t trim_regs[4] = {0xE3u, 0xE5u, 0xEAu, 0xECu};
    for (unsigned i = 0; i < 4u; i++) {
        uint8_t cur = 0;
        if (stk31e60_read_reg(dev, trim_regs[i], &cur) != 0) {
            return -2;
        }
        if (cur != 0x80u && stk31e60_write_reg(dev, trim_regs[i], 0x80u) != 0) {
            return -2;
        }
    }

    /* Core configuration sequence. */
    if (stk31e60_write_reg(dev, STK31E60_REG_CFG_07, 0x03u) != 0 ||
        stk31e60_write_reg(dev, STK31E60_REG_CFG_08, 0xE7u) != 0 ||
        stk31e60_write_reg(dev, STK31E60_REG_CFG_3D, 0x00u) != 0) {
        return -2;
    }

    uint8_t r6a = 0;
    if (stk31e60_read_reg(dev, STK31E60_REG_CFG_6A, &r6a) != 0 ||
        stk31e60_write_reg(dev, STK31E60_REG_CFG_6A, (uint8_t)(r6a & (uint8_t)(~0x10u))) != 0 ||
        stk31e60_write_reg(dev, STK31E60_REG_CFG_6B, 0x01u) != 0 ||
        stk31e60_set_gain(dev, dev->cfg.gain_code) != 0) {
        return -2;
    }

    uint16_t it_code = stk31e60_encode_it(dev->cfg.integration_ms_x10);
    if (stk31e60_write_reg(dev, STK31E60_REG_IT_H, (uint8_t)(it_code >> 8)) != 0 ||
        stk31e60_write_reg(dev, STK31E60_REG_IT_L, (uint8_t)(it_code & 0xFFu)) != 0) {
        return -2;
    }
    dev->it_code = it_code;
    dev->probed = true;
    return 0;
}

int stk31e60_read_als(struct stk31e60_dev *dev, uint16_t *raw_out,
                      uint32_t *lux_out, bool *cached_out) {
    if (!dev || !dev->probed) {
        return -1;
    }
    bool ready = false;
    for (unsigned attempt = 0; attempt < 3u; attempt++) {
        uint8_t flag = 0;
        if (stk31e60_read_reg(dev, STK31E60_REG_FLAG, &flag) == 0 && (flag & 0x80u) != 0) {
            ready = true;
            break;
        }
        if (attempt + 1u < 3u) {
            stk_delay_ms(dev, 200);
        }
    }
    if (!ready) {
        return -2;
    }

    uint8_t hi = 0;
    uint8_t lo = 0;
    bool used_cache = false;
    uint16_t raw = 0;
    if (stk31e60_read_reg(dev, STK31E60_REG_DATA_H, &hi) == 0 &&
        stk31e60_read_reg(dev, STK31E60_REG_DATA_L, &lo) == 0) {
        raw = (uint16_t)(((uint16_t)hi << 8) | lo);
        dev->last_raw = raw;
        dev->has_cached = true;
    } else if (dev->has_cached) {
        raw = dev->last_raw;
        used_cache = true;
    } else {
        return -2;
    }

    uint32_t lux = stk_raw_to_lux(raw, dev->gain_code);
    if (raw_out) {
        *raw_out = raw;
    }
    if (lux_out) {
        *lux_out = lux;
    }
    if (cached_out) {
        *cached_out = used_cache;
    }
    if (dev->cfg.publish_sensor) {
        struct sensor_sample sample = {
            .timestamp_ticks = 0,
            .type = SENSOR_ALS,
            .flags = used_cache ? SENSOR_FLAG_CACHED : 0u,
            .sensitivity = dev->gain_code,
            .x = (int32_t)lux,
            .y = (int32_t)raw,
            .z = 0,
        };
        (void)sensor_post(&sample);
    }
    return 0;
}
