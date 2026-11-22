/* Independently authored MAX8617X optical PPG/SpO2 sensor driver over SPI. */
#include "max8617x.h"
#include <stddef.h>

void max8617x_decode_word(uint32_t raw_word, struct max8617x_sample *out) {
    if (!out) return;
    out->channel = (uint8_t)((raw_word >> 29) & 0x03u);
    out->meas_id = (uint8_t)((raw_word >> 24) & 0x1Fu);
    int32_t v = (int32_t)(raw_word & 0x000FFFFFu);
    if ((v & 0x00080000) != 0) {
        v |= (int32_t)0xFFF00000u; /* sign-extend 20-bit two's complement */
    }
    out->value = v;
}

int max8617x_read_reg(struct max8617x_dev *dev, uint8_t reg, uint8_t *out) {
    if (!dev || !dev->cfg.bus || !out) return -1;
    uint8_t tx[3] = {reg, MAX8617X_SPI_READ_OP, 0x00u};
    uint8_t rx[3] = {0, 0, 0};
    struct spi_transfer xfer = {.tx = tx, .rx = rx, .len = 3};
    if (spi_transfer(dev->cfg.bus, &dev->cfg.spi_cfg, &xfer, 1) != 0) {
        return -2;
    }
    *out = rx[2];
    return 0;
}

int max8617x_write_reg(struct max8617x_dev *dev, uint8_t reg, uint8_t value) {
    if (!dev || !dev->cfg.bus) return -1;
    uint8_t tx[3] = {reg, MAX8617X_SPI_WRITE_OP, value};
    struct spi_transfer xfer = {.tx = tx, .rx = NULL, .len = 3};
    return spi_transfer(dev->cfg.bus, &dev->cfg.spi_cfg, &xfer, 1) == 0 ? 0 : -2;
}

int max8617x_recover(struct max8617x_dev *dev) {
    if (!dev || !dev->cfg.bus) return -1;
    /* Touch FIFO_CFG1 (0x09) and SYS_CFG1 (0x0D) to flush FIFO and clear faults. */
    int rc1 = max8617x_write_reg(dev, MAX8617X_REG_FIFO_CFG1, 0x00u);
    int rc2 = max8617x_write_reg(dev, MAX8617X_REG_FIFO_CFG2, 0x10u); /* flush FIFO */
    int rc3 = max8617x_write_reg(dev, MAX8617X_REG_SYS_CFG1, 0x01u);  /* soft reset */
    dev->recovery_count++;
    return (rc1 == 0 && rc2 == 0 && rc3 == 0) ? 0 : -2;
}

int max8617x_init(struct max8617x_dev *dev, const struct max8617x_config *cfg) {
    if (!dev || !cfg || !cfg->bus) return -1;
    dev->cfg = *cfg;
    if (dev->cfg.frame_words == 0) {
        dev->cfg.frame_words = 1u;
    }
    dev->probed = false;
    dev->active = false;
    dev->part_id = 0;
    dev->samples_read = 0;
    dev->recovery_count = 0;

    uint8_t id = 0;
    if (max8617x_read_reg(dev, MAX8617X_REG_PART_ID, &id) != 0) {
        return -2;
    }
    dev->part_id = id;
    if (id == 0x00u || id == 0xFFu ||
        (dev->cfg.expected_part_id != 0 && id != dev->cfg.expected_part_id)) {
        return -3;
    }
    if (max8617x_write_reg(dev, MAX8617X_REG_SYS_CFG1, 0x01u) != 0 ||
        max8617x_write_reg(dev, MAX8617X_REG_FIFO_CFG2, 0x10u) != 0) {
        return -2;
    }
    dev->probed = true;
    return 0;
}

int max8617x_enable(struct max8617x_dev *dev, bool enable) {
    if (!dev || !dev->probed) return -1;
    /* SYS_CFG1 bit 1 = SHDN (1 = shutdown, 0 = active). */
    uint8_t val = enable ? 0x00u : 0x02u;
    if (max8617x_write_reg(dev, MAX8617X_REG_SYS_CFG1, val) != 0) {
        return -2;
    }
    dev->active = enable;
    return 0;
}

int max8617x_fifo_count(struct max8617x_dev *dev, uint16_t *count_out) {
    if (!dev || !dev->probed || !count_out) return -1;
    uint8_t r3 = 0, r4 = 0;
    if (max8617x_read_reg(dev, MAX8617X_REG_FIFO_OVF_CNT, &r3) != 0 ||
        max8617x_read_reg(dev, MAX8617X_REG_FIFO_DATA_CNT, &r4) != 0) {
        return -2;
    }
    *count_out = (uint16_t)((((uint16_t)(r3 & 0xC0u)) << 2) | (uint16_t)r4);
    return 0;
}

int max8617x_fifo_drain(struct max8617x_dev *dev, uint16_t max_words) {
    if (!dev || !dev->probed || !dev->active) return -1;
    uint16_t count = 0;
    int rc = max8617x_fifo_count(dev, &count);
    if (rc != 0) return rc;

    if (count >= MAX8617X_MAX_FIFO_WORDS) {
        (void)max8617x_recover(dev);
        return -4; /* overflow / invalid FIFO count */
    }
    uint16_t to_read = count;
    if (max_words > 0 && to_read > max_words) {
        to_read = max_words;
    }
    /* Round down to a whole multiple of configured frame_words. */
    to_read = (uint16_t)((to_read / dev->cfg.frame_words) * dev->cfg.frame_words);
    if (to_read == 0) {
        return 0;
    }

    int decoded = 0;
    uint16_t left = to_read;
    while (left > 0) {
        uint16_t chunk = left > MAX8617X_CHUNK_WORDS ? MAX8617X_CHUNK_WORDS : left;
        uint8_t tx[2 + MAX8617X_CHUNK_WORDS * 4u];
        uint8_t rx[2 + MAX8617X_CHUNK_WORDS * 4u];
        uint32_t xfer_len = 2u + (uint32_t)chunk * 4u;
        tx[0] = MAX8617X_REG_FIFO_DATA;
        tx[1] = MAX8617X_SPI_READ_OP;
        for (uint32_t i = 2; i < xfer_len; i++) tx[i] = 0;
        for (uint32_t i = 0; i < xfer_len; i++) rx[i] = 0;

        struct spi_transfer xfer = {.tx = tx, .rx = rx, .len = xfer_len};
        if (spi_transfer(dev->cfg.bus, &dev->cfg.spi_cfg, &xfer, 1) != 0) {
            return -2;
        }
        for (uint16_t w = 0; w < chunk; w++) {
            const uint8_t *p = &rx[2u + (uint32_t)w * 4u];
            uint32_t raw = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
            struct max8617x_sample s;
            max8617x_decode_word(raw, &s);
            if (dev->cfg.on_sample) {
                dev->cfg.on_sample(&s, dev->cfg.cb_ctx);
            }
            dev->samples_read++;
            decoded++;
        }
        left = (uint16_t)(left - chunk);
    }
    return decoded;
}
