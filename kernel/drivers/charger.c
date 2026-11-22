/* Independently authored CW6305 and AW32012 I2C battery charger drivers. */
#include "charger.h"
#include <stddef.h>

/* CW6305 registers */
#define CW_REG_ID      0x00u
#define CW_REG_CFG1    0x01u
#define CW_REG_ICHG    0x04u
#define CW_REG_TIMER   0x06u
#define CW_REG_PWROFF  0x07u
#define CW_REG_WDT     0x08u
#define CW_REG_IRQ     0x0Bu
#define CW_REG_STAT1   0x0Du
#define CW_REG_STAT2   0x0Eu

/* AW32012 registers */
#define AW_REG_CTRL    0x01u
#define AW_REG_ICHG    0x02u
#define AW_REG_IPRE    0x03u
#define AW_REG_PWROFF  0x06u
#define AW_REG_STAT    0x08u
#define AW_REG_FAULT   0x09u
#define AW_REG_ID      0x0Au
#define AW_REG_VBUS    0x21u
#define AW_REG_LOCK    0x69u

static int chg_read_reg(const struct charger_dev *dev, uint8_t reg, uint8_t *out) {
    if (!dev || !dev->bus || !out) {
        return -1;
    }
    return i2c_write_read(dev->bus, dev->addr, &reg, 1, out, 1) == 0 ? 0 : -2;
}

static int chg_write_reg(const struct charger_dev *dev, uint8_t reg, uint8_t val) {
    if (!dev || !dev->bus) {
        return -1;
    }
    uint8_t buf[2] = {reg, val};
    return i2c_write(dev->bus, dev->addr, buf, 2) == 0 ? 0 : -2;
}

static int chg_update_if_changed(const struct charger_dev *dev, uint8_t reg,
                                 uint8_t mask, uint8_t value) {
    uint8_t cur = 0;
    int rc = chg_read_reg(dev, reg, &cur);
    if (rc != 0) {
        return rc;
    }
    uint8_t next = (uint8_t)((cur & (uint8_t)(~mask)) | (value & mask));
    if (next == cur) {
        return 0;
    }
    return chg_write_reg(dev, reg, next);
}

int cw6305_encode_current_ma(uint16_t ma) {
    if (ma < 10u || ma > 470u) {
        return -1;
    }
    if (ma <= 20u) {
        /* 1.25 mA steps: (ma - 10) / 1.25 == ((ma - 10) * 4) / 5 */
        return (int)(((uint32_t)(ma - 10u) * 4u) / 5u);
    }
    if (ma <= 40u) {
        /* 2.5 mA steps starting at code 8 */
        return 8 + (int)(((uint32_t)(ma - 20u) * 2u) / 5u);
    }
    if (ma <= 80u) {
        /* 5 mA steps starting at code 16 */
        return 16 + (int)((ma - 40u) / 5u);
    }
    /* 10 mA steps starting at code 24 */
    return 24 + (int)((ma - 80u) / 10u);
}

int aw32012_encode_fast_ma(uint16_t ma) {
    if (ma < 8u) {
        return -1;
    }
    if (ma > 519u) {
        return 0x3F;
    }
    return (int)((ma - 8u) / 8u);
}

int aw32012_encode_pre_ma(uint16_t ma) {
    if (ma < 1u) {
        return -1;
    }
    if (ma > 32u) {
        return 0x0F;
    }
    return (int)((ma - 1u) / 2u);
}

int charger_init_cw6305(struct charger_dev *dev, struct i2c_bus *bus) {
    if (!dev || !bus) {
        return -1;
    }
    dev->bus = bus;
    dev->kind = CHARGER_CW6305;
    dev->addr = CW6305_I2C_ADDR;
    dev->chip_id = 0;
    dev->initialized = false;

    uint8_t id = 0;
    if (chg_read_reg(dev, CW_REG_ID, &id) != 0 || id == 0 || id == 0xFFu) {
        dev->kind = CHARGER_NONE;
        return -2;
    }
    dev->chip_id = id;
    dev->initialized = true;
    return 0;
}

int charger_init_aw32012(struct charger_dev *dev, struct i2c_bus *bus) {
    if (!dev || !bus) {
        return -1;
    }
    dev->bus = bus;
    dev->kind = CHARGER_AW32012;
    dev->addr = AW32012_I2C_ADDR;
    dev->chip_id = 0;
    dev->initialized = false;

    uint8_t id = 0;
    if (chg_read_reg(dev, AW_REG_ID, &id) != 0 || id == 0 || id == 0xFFu) {
        dev->kind = CHARGER_NONE;
        return -2;
    }
    dev->chip_id = id;
    dev->initialized = true;
    return 0;
}

int charger_probe(struct charger_dev *dev, struct i2c_bus *bus) {
    if (charger_init_cw6305(dev, bus) == 0) {
        return 0;
    }
    return charger_init_aw32012(dev, bus);
}

int charger_set_enable(struct charger_dev *dev, bool enable) {
    if (!dev || !dev->initialized) {
        return -1;
    }
    if (dev->kind == CHARGER_CW6305) {
        return chg_update_if_changed(dev, CW_REG_CFG1, 0x40u, enable ? 0x40u : 0x00u);
    }
    if (dev->kind == CHARGER_AW32012) {
        /* AW32012 bit 3 is active-high charge DISABLE. */
        return chg_update_if_changed(dev, AW_REG_CTRL, 0x08u, enable ? 0x00u : 0x08u);
    }
    return -1;
}

int charger_set_fast_current_ma(struct charger_dev *dev, uint16_t ma) {
    if (!dev || !dev->initialized) {
        return -1;
    }
    if (dev->kind == CHARGER_CW6305) {
        int code = cw6305_encode_current_ma(ma);
        if (code < 0) {
            return -1;
        }
        return chg_update_if_changed(dev, CW_REG_ICHG, 0x3Fu, (uint8_t)code);
    }
    if (dev->kind == CHARGER_AW32012) {
        int code = aw32012_encode_fast_ma(ma);
        if (code < 0) {
            return -1;
        }
        return chg_update_if_changed(dev, AW_REG_ICHG, 0x3Fu, (uint8_t)code);
    }
    return -1;
}

int charger_read_status(struct charger_dev *dev, struct charger_status *out) {
    if (!dev || !dev->initialized || !out) {
        return -1;
    }
    out->state = CHARGER_STATE_NOT_CHARGING;
    out->vbus_present = false;
    out->raw_status = 0;
    out->raw_status2_or_fault = 0;

    if (dev->kind == CHARGER_CW6305) {
        uint8_t s1 = 0, s2 = 0;
        if (chg_read_reg(dev, CW_REG_STAT1, &s1) != 0 ||
            chg_read_reg(dev, CW_REG_STAT2, &s2) != 0) {
            return -2;
        }
        out->raw_status = s1;
        out->raw_status2_or_fault = s2;
        out->vbus_present = (s1 & 0x01u) != 0;
        out->state = (enum charger_state)((s1 >> 1) & 0x03u);
        return 0;
    }
    if (dev->kind == CHARGER_AW32012) {
        uint8_t st = 0, flt = 0;
        if (chg_read_reg(dev, AW_REG_STAT, &st) != 0 ||
            chg_read_reg(dev, AW_REG_FAULT, &flt) != 0) {
            return -2;
        }
        out->raw_status = st;
        out->raw_status2_or_fault = flt;
        out->state = (enum charger_state)((st >> 3) & 0x03u);
        out->vbus_present = (st & 0x04u) != 0 || out->state != CHARGER_STATE_NOT_CHARGING;
        return 0;
    }
    return -1;
}

int charger_clear_irq(struct charger_dev *dev) {
    if (!dev || !dev->initialized) {
        return -1;
    }
    if (dev->kind == CHARGER_CW6305) {
        return chg_write_reg(dev, CW_REG_IRQ, 0x00u);
    }
    if (dev->kind == CHARGER_AW32012) {
        uint8_t flt = 0;
        return chg_read_reg(dev, AW_REG_FAULT, &flt);
    }
    return -1;
}

int aw32012_set_vbus_reset(struct charger_dev *dev, bool disable_vbus_reset) {
    if (!dev || !dev->initialized || dev->kind != CHARGER_AW32012) {
        return -1;
    }
    int rc = chg_write_reg(dev, AW_REG_LOCK, 0xC2u);
    if (rc == 0) {
        rc = chg_update_if_changed(dev, AW_REG_VBUS, 0x80u,
                                   disable_vbus_reset ? 0x80u : 0x00u);
    }
    int lock_rc = chg_write_reg(dev, AW_REG_LOCK, 0x00u);
    if (lock_rc != 0) {
        return -2;
    }
    return rc;
}

int charger_poweroff(struct charger_dev *dev) {
    if (!dev || !dev->initialized) {
        return -1;
    }
    if (dev->kind == CHARGER_CW6305) {
        /* Clear charge WDT (bit 7), clear discharge WDT (bit 6), then set 0x07 bit 7. */
        (void)chg_update_if_changed(dev, CW_REG_WDT, 0x80u, 0x00u);
        (void)chg_update_if_changed(dev, CW_REG_WDT, 0x40u, 0x00u);
        return chg_update_if_changed(dev, CW_REG_PWROFF, 0x80u, 0x80u);
    }
    if (dev->kind == CHARGER_AW32012) {
        return chg_update_if_changed(dev, AW_REG_PWROFF, 0x20u, 0x20u);
    }
    return -1;
}
