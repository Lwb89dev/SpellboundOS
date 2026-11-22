/* Portable STK31E60 ambient light sensor (ALS) driver over I2C (bus.h -> sensor.h). */
#ifndef SPELLBOUND_STK31E60_H
#define SPELLBOUND_STK31E60_H

#include <stdbool.h>
#include <stdint.h>
#include "../bus.h"

#define STK31E60_I2C_ADDR         0x48u
#define STK31E60_CHIP_ID          0xE0u

#define STK31E60_REG_CFG_07       0x07u
#define STK31E60_REG_CFG_08       0x08u
#define STK31E60_REG_FLAG         0x10u
#define STK31E60_REG_DATA_H       0x13u
#define STK31E60_REG_DATA_L       0x14u
#define STK31E60_REG_GAIN         0x17u
#define STK31E60_REG_CFG_3D       0x3Du
#define STK31E60_REG_CHIP_ID      0x3Eu
#define STK31E60_REG_CFG_6A       0x6Au
#define STK31E60_REG_CFG_6B       0x6Bu
#define STK31E60_REG_IT_H         0x6Eu
#define STK31E60_REG_IT_L         0x6Fu

#define STK31E60_GAIN_REF_CODE    0xB0u /* reference gain (1x) */
#define STK31E60_DEFAULT_IT_MS_X10 166u /* 16.6 ms -> reg code 0x00A6 */

struct stk31e60_config {
    struct i2c_bus *bus;
    uint16_t addr; /* 0 defaults to STK31E60_I2C_ADDR (0x48) */
    uint16_t integration_ms_x10; /* 0 defaults to 166 (16.6 ms) */
    uint8_t gain_code; /* 0 defaults to 0xB0 */
    bool publish_sensor;
    void (*delay_ms)(uint32_t ms, void *ctx);
    void *delay_ctx;
};

struct stk31e60_dev {
    struct stk31e60_config cfg;
    bool probed;
    uint8_t chip_id;
    uint8_t gain_code;
    uint16_t it_code;
    uint16_t last_raw;
    bool has_cached;
};

int stk31e60_read_reg(struct stk31e60_dev *dev, uint8_t reg, uint8_t *out);
int stk31e60_write_reg(struct stk31e60_dev *dev, uint8_t reg, uint8_t value);

/* Compute integration time register code from tenths of milliseconds. */
uint16_t stk31e60_encode_it(uint16_t ms_x10);

/* Probe chip ID (0xE0) and apply init sequence. Returns 0, -1 args, -2 bus, -3 bad ID. */
int stk31e60_init(struct stk31e60_dev *dev, const struct stk31e60_config *cfg);

/* Update gain code (0x00..0xF0 step 0x10). */
int stk31e60_set_gain(struct stk31e60_dev *dev, uint8_t gain_code);

/* Wait for data ready (0x10 bit 7), read 16-bit ALS count, compute integer lux
 * and optionally post SENSOR_ALS. Returns 0 on fresh/cached read, -2 on DRDY timeout. */
int stk31e60_read_als(struct stk31e60_dev *dev, uint16_t *raw_out,
                      uint32_t *lux_out, bool *cached_out);

#endif /* SPELLBOUND_STK31E60_H */
