/* Watch power, screen-timeout and ALS auto-brightness manager. */
#ifndef SPELLBOUND_POWER_H
#define SPELLBOUND_POWER_H

#include <stdbool.h>
#include <stdint.h>
#include "drivers/icna3311.h"

enum power_screen_state {
    POWER_ACTIVE = 0,
    POWER_DIM = 1,
    POWER_AOD = 2,
    POWER_SLEEP = 3,
};

struct power_config {
    uint32_t dim_timeout_ticks;
    uint32_t sleep_timeout_ticks;
    bool aod_enabled;
    bool auto_brightness;
    uint8_t manual_brightness;
    uint8_t dim_brightness;
    uint8_t aod_brightness;
};

struct power_state {
    struct power_config cfg;
    enum power_screen_state screen;
    uint64_t last_activity_ticks;
    uint8_t target_brightness;
    uint8_t applied_brightness;
    bool brightness_synced;
    bool panel_awake;
    uint8_t battery_pct;
    bool charging;
    bool dnd_enabled;
    bool haptics_enabled;
    uint32_t last_lux;
};

/* Map ambient lux reading to panel brightness (24..255) using integer piecewise curve. */
uint8_t power_lux_to_brightness(uint32_t lux);

void power_init(struct power_state *st, const struct power_config *cfg, uint64_t now_ticks);
bool power_wake(struct power_state *st, uint64_t now_ticks);
bool power_sleep(struct power_state *st);
bool power_update_als(struct power_state *st, uint32_t lux);
void power_set_battery(struct power_state *st, uint8_t pct, bool charging);
bool power_set_auto_brightness(struct power_state *st, bool enable);
bool power_set_manual_brightness(struct power_state *st, uint8_t level);

/* Evaluate dim/AOD/sleep timeouts at now_ticks. Returns true if screen or brightness changed. */
bool power_tick(struct power_state *st, uint64_t now_ticks);

/* Push current screen power/dimming/HBM/brightness state to an ICNA3311 panel. */
int power_apply_panel(struct power_state *st, struct icna3311_dev *panel);

#endif /* SPELLBOUND_POWER_H */
