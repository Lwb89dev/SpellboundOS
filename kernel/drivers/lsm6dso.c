/* Independently authored LSM6DSO 6-axis IMU driver over SPI. */
#include "lsm6dso.h"
#include "../sensor.h"
#include <stddef.h>

#define LSM6DSO_SPI_READ_BIT   0x80u
#define LSM6DSO_CTRL3_SW_RESET 0x01u
#define LSM6DSO_CTRL3_IF_INC   0x04u
#define LSM6DSO_CTRL3_BDU      0x40u
#define LSM6DSO_FIFO_BYPASS    0x00u
#define LSM6DSO_FIFO_CONT      0x06u
#define LSM6DSO_FIFO_WORD_LEN  7u
#define LSM6DSO_CHUNK_WORDS    16u

static void lsm6dso_delay_ms(const struct lsm6dso_dev *dev, uint32_t ms) {
    if (dev->cfg.delay_ms) {
        dev->cfg.delay_ms(ms, dev->cfg.delay_ctx);
    }
}

static int16_t clamp_add_i16(int16_t a, int16_t b) {
    int32_t sum = (int32_t)a + (int32_t)b;
    if (sum > 32767) {
        return 32767;
    }
    if (sum < -32768) {
        return -32768;
    }
    return (int16_t)sum;
}

static int16_t le16_signed(uint8_t lo, uint8_t hi) {
    uint16_t u = (uint16_t)lo | ((uint16_t)hi << 8);
    return (int16_t)u;
}

static uint16_t xl_sensitivity(enum lsm6dso_xl_fs fs) {
    switch (fs) {
    case LSM6DSO_XL_2G:  return 16384u;
    case LSM6DSO_XL_4G:  return 8192u;
    case LSM6DSO_XL_8G:  return 4096u;
    case LSM6DSO_XL_16G: return 2048u;
    }
    return 4096u;
}

static uint16_t gy_sensitivity_x10(enum lsm6dso_gy_fs fs) {
    /* Sensitivity in 0.1 * (LSB / dps) units: 2000dps -> 14.28 => 143, etc. */
    switch (fs) {
    case LSM6DSO_GY_125DPS:  return 2286u;
    case LSM6DSO_GY_250DPS:  return 1143u;
    case LSM6DSO_GY_500DPS:  return 571u;
    case LSM6DSO_GY_1000DPS: return 286u;
    case LSM6DSO_GY_2000DPS: return 143u;
    }
    return 143u;
}

int lsm6dso_read_regs(struct lsm6dso_dev *dev, uint8_t reg, uint8_t *out, uint32_t len) {
    if (!dev || !dev->cfg.bus || !out || len == 0 ||
        len > LSM6DSO_CHUNK_WORDS * LSM6DSO_FIFO_WORD_LEN) {
        return -1;
    }
    uint8_t tx[1 + LSM6DSO_CHUNK_WORDS * LSM6DSO_FIFO_WORD_LEN];
    uint8_t rx[1 + LSM6DSO_CHUNK_WORDS * LSM6DSO_FIFO_WORD_LEN];
    tx[0] = (uint8_t)(reg | LSM6DSO_SPI_READ_BIT);
    for (uint32_t i = 0; i < len; i++) {
        tx[1u + i] = 0;
        rx[1u + i] = 0;
    }
    rx[0] = 0;
    struct spi_transfer xfer = {
        .tx = tx,
        .rx = rx,
        .len = len + 1u,
    };
    if (spi_transfer(dev->cfg.bus, &dev->cfg.spi_cfg, &xfer, 1) != 0) {
        return -2;
    }
    for (uint32_t i = 0; i < len; i++) {
        out[i] = rx[1u + i];
    }
    return 0;
}

int lsm6dso_write_reg(struct lsm6dso_dev *dev, uint8_t reg, uint8_t value) {
    if (!dev || !dev->cfg.bus) {
        return -1;
    }
    uint8_t tx[2] = {(uint8_t)(reg & 0x7Fu), value};
    struct spi_transfer xfer = {
        .tx = tx,
        .rx = NULL,
        .len = 2,
    };
    return spi_transfer(dev->cfg.bus, &dev->cfg.spi_cfg, &xfer, 1) == 0 ? 0 : -2;
}

static int lsm6dso_update_bits(struct lsm6dso_dev *dev, uint8_t reg,
                               uint8_t mask, uint8_t value) {
    uint8_t cur = 0;
    int rc = lsm6dso_read_regs(dev, reg, &cur, 1);
    if (rc != 0) {
        return rc;
    }
    uint8_t next = (uint8_t)((cur & (uint8_t)(~mask)) | (value & mask));
    return lsm6dso_write_reg(dev, reg, next);
}

static int lsm6dso_soft_reset(struct lsm6dso_dev *dev) {
    int rc = lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL3_C,
                                 LSM6DSO_CTRL3_SW_RESET, LSM6DSO_CTRL3_SW_RESET);
    if (rc != 0) {
        return rc;
    }
    for (unsigned attempt = 0; attempt < 10u; attempt++) {
        lsm6dso_delay_ms(dev, 1);
        uint8_t val = LSM6DSO_CTRL3_SW_RESET;
        rc = lsm6dso_read_regs(dev, LSM6DSO_REG_CTRL3_C, &val, 1);
        if (rc == 0 && (val & LSM6DSO_CTRL3_SW_RESET) == 0) {
            return 0;
        }
    }
    return -2;
}

int lsm6dso_init(struct lsm6dso_dev *dev, const struct lsm6dso_config *cfg) {
    if (!dev || !cfg || !cfg->bus || cfg->orientation >= 8u) {
        return -1;
    }
    dev->cfg = *cfg;
    dev->probed = false;
    dev->active = false;
    dev->gyro_enabled = false;
    dev->chip_id = 0;
    dev->odr = LSM6DSO_ODR_OFF;
    dev->xl_fs = LSM6DSO_XL_8G;
    dev->gy_fs = LSM6DSO_GY_2000DPS;
    dev->overrun_count = 0;
    dev->samples_delivered = 0;

    /* Best-effort software reset before probing identity. */
    (void)lsm6dso_soft_reset(dev);

    int last_err = -3;
    for (unsigned attempt = 0; attempt < 3u; attempt++) {
        uint8_t id = 0;
        int rc = lsm6dso_read_regs(dev, LSM6DSO_REG_WHO_AM_I, &id, 1);
        if (rc == 0) {
            dev->chip_id = id;
            if (id == LSM6DSO_WHO_AM_I_VAL) {
                dev->probed = true;
                return 0;
            }
            last_err = -3;
        } else {
            last_err = -2;
        }
        if (attempt + 1u < 3u) {
            lsm6dso_delay_ms(dev, 10);
        }
    }
    return last_err;
}

int lsm6dso_enable(struct lsm6dso_dev *dev, enum lsm6dso_odr odr,
                   enum lsm6dso_xl_fs xl_fs, bool enable_gyro,
                   enum lsm6dso_gy_fs gy_fs, enum lsm6dso_power_mode xl_power) {
    if (!dev || !dev->probed || odr == LSM6DSO_ODR_OFF || (unsigned)odr > 7u ||
        (unsigned)xl_fs > 3u || (unsigned)xl_power > 2u) {
        return -1;
    }
    if (lsm6dso_soft_reset(dev) != 0) {
        return -2;
    }
    /* Disable I3C interface per verified bring-up contract. */
    if (lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL9_XL, 0x02u, 0x00u) != 0 ||
        lsm6dso_update_bits(dev, LSM6DSO_REG_I3C_BUS_AVB, 0x18u, 0x00u) != 0) {
        return -2;
    }
    /* Enable block data update and address auto-increment. */
    if (lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL3_C,
                            LSM6DSO_CTRL3_BDU | LSM6DSO_CTRL3_IF_INC,
                            LSM6DSO_CTRL3_BDU | LSM6DSO_CTRL3_IF_INC) != 0) {
        return -2;
    }
    /* Accelerometer power mode: CTRL5_C bit 7 = mode>>1, CTRL6_C bit 4 = mode&1. */
    uint8_t pwr = enable_gyro ? (uint8_t)LSM6DSO_PWR_HIGH_PERF : (uint8_t)xl_power;
    if (lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL5_C, 0x80u, (uint8_t)((pwr >> 1) << 7)) != 0 ||
        lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL6_C, 0x10u, (uint8_t)((pwr & 1u) << 4)) != 0) {
        return -2;
    }
    /* Accelerometer full scale + ODR. */
    uint8_t ctrl1 = (uint8_t)(((uint8_t)odr << 4) | ((uint8_t)xl_fs << 2));
    if (lsm6dso_write_reg(dev, LSM6DSO_REG_CTRL1_XL, ctrl1) != 0) {
        return -2;
    }
    /* Gyroscope configuration or power-down. */
    uint8_t fifo_batch = (uint8_t)odr;
    if (enable_gyro) {
        if (lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL6_C, 0x07u, 0x07u) != 0 ||
            lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL4_C, 0x02u, 0x02u) != 0 ||
            lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL7_G, 0x80u, 0x00u) != 0) {
            return -2;
        }
        uint8_t ctrl2 = (uint8_t)(((uint8_t)odr << 4) | (((uint8_t)gy_fs & 0x07u) << 1));
        if (lsm6dso_write_reg(dev, LSM6DSO_REG_CTRL2_G, ctrl2) != 0) {
            return -2;
        }
        fifo_batch |= (uint8_t)((uint8_t)odr << 4);
    } else {
        if (lsm6dso_write_reg(dev, LSM6DSO_REG_CTRL2_G, 0x00u) != 0) {
            return -2;
        }
    }
    /* Batch rates and continuous FIFO mode. */
    if (lsm6dso_write_reg(dev, LSM6DSO_REG_FIFO_CTRL3, fifo_batch) != 0 ||
        lsm6dso_update_bits(dev, LSM6DSO_REG_FIFO_CTRL4, 0x07u, LSM6DSO_FIFO_CONT) != 0) {
        return -2;
    }

    dev->active = true;
    dev->gyro_enabled = enable_gyro;
    dev->odr = odr;
    dev->xl_fs = xl_fs;
    dev->gy_fs = gy_fs;
    return 0;
}

int lsm6dso_disable(struct lsm6dso_dev *dev) {
    if (!dev || !dev->probed) {
        return -1;
    }
    if (lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL1_XL, 0xF0u, 0x00u) != 0 ||
        lsm6dso_update_bits(dev, LSM6DSO_REG_CTRL2_G, 0xF0u, 0x00u) != 0 ||
        lsm6dso_update_bits(dev, LSM6DSO_REG_FIFO_CTRL4, 0x07u, LSM6DSO_FIFO_BYPASS) != 0) {
        return -2;
    }
    dev->active = false;
    dev->gyro_enabled = false;
    dev->odr = LSM6DSO_ODR_OFF;
    return 0;
}

static void transform_sample(const struct lsm6dso_dev *dev, const int16_t offset[3],
                             const uint8_t raw[6], int16_t out[3]) {
    int16_t x = clamp_add_i16(le16_signed(raw[0], raw[1]), offset[0]);
    int16_t y = clamp_add_i16(le16_signed(raw[2], raw[3]), offset[1]);
    int16_t z = clamp_add_i16(le16_signed(raw[4], raw[5]), offset[2]);
    (void)sensor_remap_xyz(dev->cfg.orientation, dev->cfg.wrist_flipped, &x, &y, &z);
    out[0] = x;
    out[1] = y;
    out[2] = z;
}

int lsm6dso_read_accel_raw(struct lsm6dso_dev *dev, int16_t xyz[3]) {
    if (!dev || !dev->probed || !xyz) {
        return -1;
    }
    uint8_t raw[6];
    int rc = lsm6dso_read_regs(dev, LSM6DSO_REG_OUTX_L_A, raw, 6);
    if (rc != 0) {
        return rc;
    }
    transform_sample(dev, dev->cfg.xl_offset, raw, xyz);
    return 0;
}

int lsm6dso_read_gyro_raw(struct lsm6dso_dev *dev, int16_t xyz[3]) {
    if (!dev || !dev->probed || !xyz) {
        return -1;
    }
    uint8_t raw[6];
    int rc = lsm6dso_read_regs(dev, LSM6DSO_REG_OUTX_L_G, raw, 6);
    if (rc != 0) {
        return rc;
    }
    transform_sample(dev, dev->cfg.gy_offset, raw, xyz);
    return 0;
}

int lsm6dso_fifo_status(struct lsm6dso_dev *dev, uint16_t *level, bool *overrun) {
    if (!dev || !dev->probed || !level || !overrun) {
        return -1;
    }
    uint8_t st[2];
    int rc = lsm6dso_read_regs(dev, LSM6DSO_REG_FIFO_STATUS1, st, 2);
    if (rc != 0) {
        return rc;
    }
    *level = (uint16_t)st[0] | (uint16_t)(((uint16_t)(st[1] & 0x03u)) << 8);
    *overrun = (st[1] & 0x40u) != 0;
    return 0;
}

int lsm6dso_fifo_drain(struct lsm6dso_dev *dev, uint16_t max_words,
                       uint16_t *remaining_out) {
    if (!dev || !dev->probed || !dev->active) {
        return -1;
    }
    uint16_t level = 0;
    bool overrun = false;
    int rc = lsm6dso_fifo_status(dev, &level, &overrun);
    if (rc != 0) {
        return rc;
    }
    if (overrun) {
        dev->overrun_count++;
    }

    uint16_t to_read = level;
    if (max_words > 0 && to_read > max_words) {
        to_read = max_words;
    }
    if (dev->gyro_enabled && (to_read & 1u) != 0) {
        to_read--;
    }
    if (remaining_out) {
        *remaining_out = (uint16_t)(level - to_read);
    }

    int decoded = 0;
    uint16_t left = to_read;
    while (left > 0) {
        uint16_t chunk = left > LSM6DSO_CHUNK_WORDS ? LSM6DSO_CHUNK_WORDS : left;
        uint8_t buf[LSM6DSO_CHUNK_WORDS * LSM6DSO_FIFO_WORD_LEN];
        rc = lsm6dso_read_regs(dev, LSM6DSO_REG_FIFO_DATA_TAG, buf,
                               (uint32_t)chunk * LSM6DSO_FIFO_WORD_LEN);
        if (rc != 0) {
            return rc;
        }
        for (uint16_t i = 0; i < chunk; i++) {
            const uint8_t *word = &buf[(uint32_t)i * LSM6DSO_FIFO_WORD_LEN];
            uint8_t tag = (uint8_t)(word[0] >> 3);
            struct sensor_sample sample = {0};
            sample.flags = overrun ? SENSOR_FLAG_OVERFLOW : 0;

            if (tag == LSM6DSO_FIFO_TAG_XL_NC) {
                int16_t xyz[3];
                transform_sample(dev, dev->cfg.xl_offset, &word[1], xyz);
                sample.type = SENSOR_ACCEL;
                sample.sensitivity = xl_sensitivity(dev->xl_fs);
                sample.x = xyz[0];
                sample.y = xyz[1];
                sample.z = xyz[2];
                if (sensor_post(&sample)) {
                    dev->samples_delivered++;
                }
                decoded++;
            } else if (tag == LSM6DSO_FIFO_TAG_GYRO_NC && dev->gyro_enabled) {
                int16_t xyz[3];
                transform_sample(dev, dev->cfg.gy_offset, &word[1], xyz);
                sample.type = SENSOR_GYRO;
                sample.sensitivity = gy_sensitivity_x10(dev->gy_fs);
                sample.x = xyz[0];
                sample.y = xyz[1];
                sample.z = xyz[2];
                if (sensor_post(&sample)) {
                    dev->samples_delivered++;
                }
                decoded++;
            }
        }
        left = (uint16_t)(left - chunk);
    }

    if (overrun) {
        /* Clear overrun state by toggling FIFO bypass -> continuous. */
        (void)lsm6dso_update_bits(dev, LSM6DSO_REG_FIFO_CTRL4, 0x07u, LSM6DSO_FIFO_BYPASS);
        (void)lsm6dso_update_bits(dev, LSM6DSO_REG_FIFO_CTRL4, 0x07u, LSM6DSO_FIFO_CONT);
    }
    return decoded;
}
