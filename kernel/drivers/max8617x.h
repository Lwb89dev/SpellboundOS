/* Portable MAX8617X optical PPG/SpO2 sensor driver over SPI (bus.h -> hr.h). */
#ifndef SPELLBOUND_MAX8617X_H
#define SPELLBOUND_MAX8617X_H

#include <stdbool.h>
#include <stdint.h>
#include "../bus.h"

#define MAX8617X_REG_FIFO_OVF_CNT  0x03u
#define MAX8617X_REG_FIFO_DATA_CNT 0x04u
#define MAX8617X_REG_FIFO_DATA     0x08u
#define MAX8617X_REG_FIFO_CFG1     0x09u
#define MAX8617X_REG_FIFO_CFG2     0x0Au
#define MAX8617X_REG_SYS_CFG1      0x0Du
#define MAX8617X_REG_PART_ID       0xFFu

#define MAX8617X_SPI_READ_OP       0x80u
#define MAX8617X_SPI_WRITE_OP      0x00u
#define MAX8617X_MAX_FIFO_WORDS    512u
#define MAX8617X_CHUNK_WORDS       16u

struct max8617x_sample {
    uint8_t channel;     /* bits 30:29 (0..3) */
    uint8_t meas_id;     /* bits 28:24 (0..31) */
    int32_t value;       /* sign-extended 20-bit sample (-524288..+524287) */
};

typedef void (*max8617x_sample_cb)(const struct max8617x_sample *sample, void *ctx);

struct max8617x_config {
    struct spi_bus *bus;
    struct spi_config spi_cfg;
    uint8_t frame_words; /* words per optical frame (e.g. 1..4); 0 defaults to 1 */
    uint8_t expected_part_id; /* 0 accepts any nonzero/non-0xFF part ID */
    max8617x_sample_cb on_sample;
    void *cb_ctx;
};

struct max8617x_dev {
    struct max8617x_config cfg;
    bool probed;
    bool active;
    uint8_t part_id;
    uint32_t samples_read;
    uint32_t recovery_count;
};

/* Decode one big-endian 32-bit MAX8617X FIFO word into channel, meas_id and signed 20-bit value. */
void max8617x_decode_word(uint32_t raw_word, struct max8617x_sample *out);

int max8617x_read_reg(struct max8617x_dev *dev, uint8_t reg, uint8_t *out);
int max8617x_write_reg(struct max8617x_dev *dev, uint8_t reg, uint8_t value);

int max8617x_init(struct max8617x_dev *dev, const struct max8617x_config *cfg);
int max8617x_enable(struct max8617x_dev *dev, bool enable);
int max8617x_recover(struct max8617x_dev *dev);

/* Query 10-bit FIFO word count: ((reg3 & 0xC0) << 2) | reg4. */
int max8617x_fifo_count(struct max8617x_dev *dev, uint16_t *count_out);

/* Drain aligned frames from FIFO via prefix [0x08, 0x80] + 4*words bytes.
 * Returns number of decoded samples or negative error (triggers recovery on count >= 512). */
int max8617x_fifo_drain(struct max8617x_dev *dev, uint16_t max_words);

#endif /* SPELLBOUND_MAX8617X_H */
