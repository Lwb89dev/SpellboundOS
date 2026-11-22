/* Portable ZTW622 capacitive touch controller driver over I2C (bus.h -> input.h). */
#ifndef SPELLBOUND_ZTW622_H
#define SPELLBOUND_ZTW622_H

#include <stdbool.h>
#include <stdint.h>
#include "../bus.h"

#define ZTW622_I2C_ADDR           0x20u
#define ZTW622_CHIP_ID            0xE622u
#define ZTW622_MAX_SLOTS          2u

#define ZTW622_CMD_RESET_FAST     0x0000u
#define ZTW622_CMD_CLEAR_INT      0x0003u
#define ZTW622_REG_TOUCH_MODE     0x0010u
#define ZTW622_REG_FW_MAJOR       0x0012u
#define ZTW622_REG_FW_RELEASE     0x0013u
#define ZTW622_REG_X_CHANNELS     0x0060u
#define ZTW622_REG_Y_CHANNELS     0x0061u
#define ZTW622_REG_POINT_STATUS   0x0080u
#define ZTW622_REG_X_RES          0x00C0u
#define ZTW622_REG_Y_RES          0x00C1u
#define ZTW622_REG_ACTIVE_CFG     0x00D4u
#define ZTW622_REG_NAP_DELAY      0x00E3u
#define ZTW622_REG_CHIP_ID        0x0120u
#define ZTW622_REG_FW_MINOR       0x0121u
#define ZTW622_REG_GESTURE_ID     0x0126u
#define ZTW622_CMD_POWER_SEQ      0x01F8u
#define ZTW622_REG_INFO_BLOCK     0x09D2u
#define ZTW622_CMD_SOFT_RESET     0x0FF8u
#define ZTW622_REG_VENDOR_UNLOCK  0xC000u

#define ZTW622_STATUS_LARGE_OBJ   0x0010u
#define ZTW622_STATUS_POINT_MASK  0x080Eu
#define ZTW622_STATUS_NO_CHANGE   0x1000u

enum ztw622_state {
    ZTW622_STATE_IDLE = 0,
    ZTW622_STATE_REPORT = 1,
    ZTW622_STATE_GESTURE = 3,
};

struct ztw622_config {
    struct i2c_bus *bus;
    uint16_t addr;            /* 0 defaults to ZTW622_I2C_ADDR (0x20) */
    struct gpio_chip *gpio;   /* optional; NULL skips GPIO control */
    int32_t reset_pin;        /* < 0 if unused */
    int32_t irq_pin;          /* < 0 if unused */
    uint8_t rotation;         /* 0, 1 (90), 2 (180), 3 (270) */
    bool flip_180;
    uint8_t max_fingers;      /* 1..2; 0 defaults to 2 */
    bool large_object_enable;
    uint16_t gesture_mask;
    uint16_t nap_delay;
    void (*delay_ms)(uint32_t ms, void *ctx);
    void *delay_ctx;
};

struct ztw622_info {
    uint16_t chip_id;
    uint32_t ium_id;
    uint16_t fw_major;
    uint16_t fw_minor;
    uint16_t fw_release;
    uint16_t x_res;
    uint16_t y_res;
    uint16_t x_channels;
    uint16_t y_channels;
};

struct ztw622_dev {
    struct ztw622_config cfg;
    struct ztw622_info info;
    enum ztw622_state state;
    bool probed;
    bool slot_down[ZTW622_MAX_SLOTS];
    uint32_t event_count;
};

/* 16-bit LE register helpers with automatic bus-reset retry on failure. */
int ztw622_write_cmd(struct ztw622_dev *dev, uint16_t cmd);
int ztw622_write_reg(struct ztw622_dev *dev, uint16_t reg, uint16_t value);
int ztw622_read_reg(struct ztw622_dev *dev, uint16_t reg, uint16_t *out);
int ztw622_read_block(struct ztw622_dev *dev, uint16_t reg, uint8_t *out, uint32_t len);
int ztw622_clear_int(struct ztw622_dev *dev);

/* Probe hardware, verify 0xE622 identity, read version/resolution and enable
 * report mode. Returns 0 on success, -1 bad args, -2 bus error, -3 bad ID. */
int ztw622_init(struct ztw622_dev *dev, const struct ztw622_config *cfg);

int ztw622_set_state(struct ztw622_dev *dev, enum ztw622_state state);

/* Poll touch/gesture status and emit INPUT_TOUCH_* events via input_post().
 * Returns number of input events posted (>= 0) or negative error. */
int ztw622_poll(struct ztw622_dev *dev);

#endif /* SPELLBOUND_ZTW622_H */
