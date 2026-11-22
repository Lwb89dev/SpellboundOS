/* Portable battery charger drivers for CW6305 (0x0B) and AW32012 (0x49) over I2C. */
#ifndef SPELLBOUND_CHARGER_H
#define SPELLBOUND_CHARGER_H

#include <stdbool.h>
#include <stdint.h>
#include "../bus.h"

#define CW6305_I2C_ADDR   0x0Bu
#define AW32012_I2C_ADDR  0x49u

enum charger_kind {
    CHARGER_NONE = 0,
    CHARGER_CW6305 = 1,
    CHARGER_AW32012 = 2,
};

enum charger_state {
    CHARGER_STATE_NOT_CHARGING = 0,
    CHARGER_STATE_PRECHARGE = 1,
    CHARGER_STATE_FAST_CHARGE = 2,
    CHARGER_STATE_DONE = 3,
};

struct charger_status {
    enum charger_state state;
    bool vbus_present;
    uint8_t raw_status;
    uint8_t raw_status2_or_fault;
};

struct charger_dev {
    struct i2c_bus *bus;
    enum charger_kind kind;
    uint16_t addr;
    uint8_t chip_id;
    bool initialized;
};

/* Piecewise 6-bit fast-charge current encoders. Return negative on out-of-range. */
int cw6305_encode_current_ma(uint16_t ma);
int aw32012_encode_fast_ma(uint16_t ma);
int aw32012_encode_pre_ma(uint16_t ma);

/* Explicit driver initializers or runtime auto-probe (CW6305 then AW32012). */
int charger_init_cw6305(struct charger_dev *dev, struct i2c_bus *bus);
int charger_init_aw32012(struct charger_dev *dev, struct i2c_bus *bus);
int charger_probe(struct charger_dev *dev, struct i2c_bus *bus);

int charger_set_enable(struct charger_dev *dev, bool enable);
int charger_set_fast_current_ma(struct charger_dev *dev, uint16_t ma);
int charger_read_status(struct charger_dev *dev, struct charger_status *out);
int charger_clear_irq(struct charger_dev *dev);
int charger_poweroff(struct charger_dev *dev);

/* AW32012-specific VBUS reset configuration (unlock 0x69=0xC2, RMW 0x21, relock 0x69=0). */
int aw32012_set_vbus_reset(struct charger_dev *dev, bool disable_vbus_reset);

#endif /* SPELLBOUND_CHARGER_H */
