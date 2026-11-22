/* Portable Chipone ICNA3311 AMOLED MIPI DCS panel driver. */
#ifndef SPELLBOUND_ICNA3311_H
#define SPELLBOUND_ICNA3311_H

#include <stdbool.h>
#include <stdint.h>
#include "../fb.h"

/* Standard MIPI DCS commands used by ICNA3311 */
#define DCS_CMD_SLEEP_IN       0x10u
#define DCS_CMD_SLEEP_OUT      0x11u
#define DCS_CMD_DISPLAY_OFF    0x28u
#define DCS_CMD_DISPLAY_ON     0x29u
#define DCS_CMD_SET_COL_ADDR   0x2Au
#define DCS_CMD_SET_ROW_ADDR   0x2Bu
#define DCS_CMD_WRITE_MEM      0x2Cu
#define DCS_CMD_SET_TEAR_ON    0x35u
#define DCS_CMD_SET_PIXEL_FMT  0x3Au
#define DCS_CMD_SET_BRIGHTNESS 0x51u
#define DCS_CMD_SET_CTRL_DISP  0x53u
#define DCS_CMD_SET_HBM        0x66u
#define DCS_CMD_READ_ID1       0xDAu
#define DCS_CMD_READ_ID2       0xDBu
#define DCS_CMD_READ_ID3       0xDCu

/* DCS command-table entry types */
#define ICNA3311_OP_WRITE      0u
#define ICNA3311_OP_DELAY      1u

struct dcs_bus;

struct dcs_ops {
    int (*write_cmd)(struct dcs_bus *bus, const uint8_t *data, uint32_t len);
    int (*read_cmd)(struct dcs_bus *bus, uint8_t cmd, uint8_t *out, uint32_t len);
    /* Transfer a rectangular RGB565 sub-image after 0x2A/0x2B/0x2C window setup. */
    int (*write_pixels)(struct dcs_bus *bus, const uint16_t *pixels,
                        uint16_t stride, uint16_t x0, uint16_t y0,
                        uint16_t w, uint16_t h);
};

struct dcs_bus {
    const char *name;
    const struct dcs_ops *ops;
    void *priv;
};

struct icna3311_config {
    struct dcs_bus *bus;
    uint16_t width;
    uint16_t height;
    bool even_align_window; /* AMOLED controllers commonly require even x/y window bounds */
    void (*delay_ms)(uint32_t ms, void *ctx);
    void *delay_ctx;
};

struct icna3311_dev {
    struct icna3311_config cfg;
    uint32_t panel_id;
    bool probed;
    bool power_on;
    bool dimming;
    bool hbm;
    uint8_t brightness;
    uint32_t flush_count;
};

/* Check if a 24-bit RDID matches one of the 9 verified ICNA3311 variants. */
bool icna3311_is_known_variant(uint32_t panel_id);

/* Issue DCS 0xDA/0xDB/0xDC and return (b0 << 16 | b1 << 8 | b2), or 0 on error. */
uint32_t icna3311_read_id(struct icna3311_dev *dev);

/* Execute a packed {type, nargs, payload...} DCS command table. */
int icna3311_play_table(struct icna3311_dev *dev, const uint8_t *table, uint32_t len);

/* Probe ID, run RGB565 + TE + sleep-out + display-on sequence. */
int icna3311_init(struct icna3311_dev *dev, const struct icna3311_config *cfg);

int icna3311_set_power(struct icna3311_dev *dev, bool on);
int icna3311_set_brightness(struct icna3311_dev *dev, uint8_t level);
int icna3311_set_dimming(struct icna3311_dev *dev, bool enable);
int icna3311_set_hbm(struct icna3311_dev *dev, bool enable);
int icna3311_set_window(struct icna3311_dev *dev,
                        uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1);

/* Flush only the dirty rectangle of fb to the panel and clear dirty state.
 * Returns 1 if pixels were flushed, 0 if fb was clean, negative on error. */
int icna3311_flush_fb(struct icna3311_dev *dev, struct fb *fb);

#endif /* SPELLBOUND_ICNA3311_H */
