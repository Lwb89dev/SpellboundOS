/* Portable LSM6DSO 6-axis IMU driver over SPI (bus.h -> sensor.h). */
#ifndef SPELLBOUND_LSM6DSO_H
#define SPELLBOUND_LSM6DSO_H

#include <stdbool.h>
#include <stdint.h>
#include "../bus.h"

#define LSM6DSO_WHO_AM_I_VAL       0x6Cu

#define LSM6DSO_REG_FUNC_CFG       0x01u
#define LSM6DSO_REG_FIFO_CTRL3     0x09u
#define LSM6DSO_REG_FIFO_CTRL4     0x0Au
#define LSM6DSO_REG_WHO_AM_I       0x0Fu
#define LSM6DSO_REG_CTRL1_XL       0x10u
#define LSM6DSO_REG_CTRL2_G        0x11u
#define LSM6DSO_REG_CTRL3_C        0x12u
#define LSM6DSO_REG_CTRL4_C        0x13u
#define LSM6DSO_REG_CTRL5_C        0x14u
#define LSM6DSO_REG_CTRL6_C        0x15u
#define LSM6DSO_REG_CTRL7_G        0x16u
#define LSM6DSO_REG_CTRL9_XL       0x18u
#define LSM6DSO_REG_STATUS_REG     0x1Eu
#define LSM6DSO_REG_OUTX_L_G       0x22u
#define LSM6DSO_REG_OUTX_L_A       0x28u
#define LSM6DSO_REG_FIFO_STATUS1   0x3Au
#define LSM6DSO_REG_FIFO_STATUS2   0x3Bu
#define LSM6DSO_REG_I3C_BUS_AVB    0x62u
#define LSM6DSO_REG_FREQ_FINE      0x63u
#define LSM6DSO_REG_FIFO_DATA_TAG  0x78u

#define LSM6DSO_FIFO_TAG_GYRO_NC   0x01u
#define LSM6DSO_FIFO_TAG_XL_NC     0x02u

enum lsm6dso_odr {
    LSM6DSO_ODR_OFF   = 0,
    LSM6DSO_ODR_12_5  = 1,
    LSM6DSO_ODR_26    = 2,
    LSM6DSO_ODR_52    = 3,
    LSM6DSO_ODR_104   = 4,
    LSM6DSO_ODR_208   = 5,
    LSM6DSO_ODR_417   = 6,
    LSM6DSO_ODR_833   = 7,
};

enum lsm6dso_xl_fs {
    LSM6DSO_XL_2G  = 0, /* 16384 LSB/g */
    LSM6DSO_XL_16G = 1, /* 2048 LSB/g  */
    LSM6DSO_XL_4G  = 2, /* 8192 LSB/g  */
    LSM6DSO_XL_8G  = 3, /* 4096 LSB/g  */
};

/* CTRL2_G bits 3:1 encoding. */
enum lsm6dso_gy_fs {
    LSM6DSO_GY_250DPS  = 0,
    LSM6DSO_GY_125DPS  = 1,
    LSM6DSO_GY_500DPS  = 2,
    LSM6DSO_GY_1000DPS = 4,
    LSM6DSO_GY_2000DPS = 6,
};

enum lsm6dso_power_mode {
    LSM6DSO_PWR_HIGH_PERF = 0,
    LSM6DSO_PWR_LOW_NORMAL = 1,
    LSM6DSO_PWR_ULTRA_LOW = 2,
};

struct lsm6dso_config {
    struct spi_bus *bus;
    struct spi_config spi_cfg;
    void (*delay_ms)(uint32_t ms, void *ctx);
    void *delay_ctx;
    uint8_t orientation; /* 0..7 */
    bool wrist_flipped;
    int16_t xl_offset[3];
    int16_t gy_offset[3];
};

struct lsm6dso_dev {
    struct lsm6dso_config cfg;
    bool probed;
    bool active;
    bool gyro_enabled;
    uint8_t chip_id;
    enum lsm6dso_odr odr;
    enum lsm6dso_xl_fs xl_fs;
    enum lsm6dso_gy_fs gy_fs;
    uint32_t overrun_count;
    uint32_t samples_delivered;
};

/* Low-level 4-wire SPI register helpers. */
int lsm6dso_read_regs(struct lsm6dso_dev *dev, uint8_t reg, uint8_t *out, uint32_t len);
int lsm6dso_write_reg(struct lsm6dso_dev *dev, uint8_t reg, uint8_t value);

/* Software-reset and probe WHO_AM_I (up to 3 attempts, expects 0x6C).
 * Returns 0 on success, -1 bad args, -2 SPI error, -3 unexpected WHO_AM_I. */
int lsm6dso_init(struct lsm6dso_dev *dev, const struct lsm6dso_config *cfg);

/* Configure accelerometer (and optional gyroscope) plus continuous FIFO mode. */
int lsm6dso_enable(struct lsm6dso_dev *dev, enum lsm6dso_odr odr,
                   enum lsm6dso_xl_fs xl_fs, bool enable_gyro,
                   enum lsm6dso_gy_fs gy_fs, enum lsm6dso_power_mode xl_power);

/* Power down accelerometer, gyroscope and FIFO (bypass mode). */
int lsm6dso_disable(struct lsm6dso_dev *dev);

/* Direct 6-byte raw axis reads (offsets and orientation applied). */
int lsm6dso_read_accel_raw(struct lsm6dso_dev *dev, int16_t xyz[3]);
int lsm6dso_read_gyro_raw(struct lsm6dso_dev *dev, int16_t xyz[3]);

/* Query FIFO word level (10-bit) and overrun flag. */
int lsm6dso_fifo_status(struct lsm6dso_dev *dev, uint16_t *level, bool *overrun);

/* Drain up to max_words 7-byte tagged words from the FIFO, decode XL_NC and
 * GYRO_NC frames, apply offsets and orientation remap, and post them to
 * sensor_post(). Returns decoded sample count or negative error. */
int lsm6dso_fifo_drain(struct lsm6dso_dev *dev, uint16_t max_words,
                       uint16_t *remaining_out);

#endif /* SPELLBOUND_LSM6DSO_H */
