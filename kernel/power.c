/* Watch power, screen-timeout and ALS auto-brightness manager. */
#include "power.h"
#include <stddef.h>

uint8_t power_lux_to_brightness(uint32_t lux) {
    if (lux <= 10u) {
        return (uint8_t)(24u + (lux * 16u) / 10u); /* 24..40 */
    }
    if (lux <= 100u) {
        return (uint8_t)(40u + ((lux - 10u) * 56u) / 90u); /* 40..96 */
    }
    if (lux <= 500u) {
        return (uint8_t)(96u + ((lux - 100u) * 64u) / 400u); /* 96..160 */
    }
    if (lux <= 2000u) {
        return (uint8_t)(160u + ((lux - 500u) * 60u) / 1500u); /* 160..220 */
    }
    if (lux >= 5000u) {
        return 255u;
    }
    return (uint8_t)(220u + ((lux - 2000u) * 35u) / 3000u); /* 220..255 */
}

static uint8_t compute_target_brightness(const struct power_state *st) {
    switch (st->screen) {
    case POWER_ACTIVE:
        return st->cfg.auto_brightness
            ? power_lux_to_brightness(st->last_lux)
            : st->cfg.manual_brightness;
    case POWER_DIM:
        return st->cfg.dim_brightness;
    case POWER_AOD:
        return st->cfg.aod_brightness;
    case POWER_SLEEP:
        return 0u;
    }
    return st->cfg.manual_brightness;
}

void power_init(struct power_state *st, const struct power_config *cfg, uint64_t now_ticks) {
    if (!st) return;
    if (cfg) {
        st->cfg = *cfg;
    } else {
        st->cfg = (struct power_config){
            .dim_timeout_ticks = 800u,
            .sleep_timeout_ticks = 1500u,
            .aod_enabled = false,
            .auto_brightness = true,
            .manual_brightness = 160u,
            .dim_brightness = 32u,
            .aod_brightness = 20u,
        };
    }
    st->screen = POWER_ACTIVE;
    st->last_activity_ticks = now_ticks;
    st->last_lux = 150u;
    st->target_brightness = compute_target_brightness(st);
    st->applied_brightness = 0u;
    st->brightness_synced = false;
    st->panel_awake = true;
    st->battery_pct = 100u;
    st->charging = false;
    st->dnd_enabled = false;
    st->haptics_enabled = true;
}

bool power_wake(struct power_state *st, uint64_t now_ticks) {
    if (!st) return false;
    bool changed = (st->screen != POWER_ACTIVE);
    st->screen = POWER_ACTIVE;
    st->last_activity_ticks = now_ticks;
    uint8_t b = compute_target_brightness(st);
    if (b != st->target_brightness) {
        st->target_brightness = b;
        changed = true;
    }
    return changed;
}

bool power_sleep(struct power_state *st) {
    if (!st) return false;
    enum power_screen_state next = st->cfg.aod_enabled ? POWER_AOD : POWER_SLEEP;
    bool changed = (st->screen != next);
    st->screen = next;
    uint8_t b = compute_target_brightness(st);
    if (b != st->target_brightness) {
        st->target_brightness = b;
        changed = true;
    }
    return changed;
}

bool power_update_als(struct power_state *st, uint32_t lux) {
    if (!st) return false;
    st->last_lux = lux;
    if (!st->cfg.auto_brightness || st->screen != POWER_ACTIVE) {
        return false;
    }
    uint8_t b = compute_target_brightness(st);
    if (b != st->target_brightness) {
        st->target_brightness = b;
        return true;
    }
    return false;
}

void power_set_battery(struct power_state *st, uint8_t pct, bool charging) {
    if (!st) return;
    st->battery_pct = pct > 100u ? 100u : pct;
    st->charging = charging;
}

bool power_set_auto_brightness(struct power_state *st, bool enable) {
    if (!st) return false;
    st->cfg.auto_brightness = enable;
    uint8_t b = compute_target_brightness(st);
    if (b != st->target_brightness) {
        st->target_brightness = b;
        return true;
    }
    return false;
}

bool power_set_manual_brightness(struct power_state *st, uint8_t level) {
    if (!st) return false;
    st->cfg.manual_brightness = level;
    if (st->cfg.auto_brightness || st->screen != POWER_ACTIVE) {
        return false;
    }
    uint8_t b = compute_target_brightness(st);
    if (b != st->target_brightness) {
        st->target_brightness = b;
        return true;
    }
    return false;
}

bool power_tick(struct power_state *st, uint64_t now_ticks) {
    if (!st || st->screen == POWER_SLEEP || st->screen == POWER_AOD) {
        return false;
    }
    uint64_t idle = now_ticks - st->last_activity_ticks;
    enum power_screen_state prev = st->screen;

    if (st->cfg.sleep_timeout_ticks > 0 && idle >= st->cfg.sleep_timeout_ticks) {
        st->screen = st->cfg.aod_enabled ? POWER_AOD : POWER_SLEEP;
    } else if (st->cfg.dim_timeout_ticks > 0 && idle >= st->cfg.dim_timeout_ticks) {
        st->screen = POWER_DIM;
    }
    if (st->screen != prev) {
        st->target_brightness = compute_target_brightness(st);
        return true;
    }
    return false;
}

int power_apply_panel(struct power_state *st, struct icna3311_dev *panel) {
    if (!st || !panel || !panel->probed) {
        return -1;
    }
    bool want_awake = (st->screen != POWER_SLEEP);
    if (want_awake != panel->power_on) {
        int rc = icna3311_set_power(panel, want_awake);
        if (rc != 0) return rc;
    }
    st->panel_awake = want_awake;
    if (!want_awake) {
        st->applied_brightness = 0;
        st->brightness_synced = false;
        return 0;
    }
    bool want_hbm = (st->screen == POWER_ACTIVE && st->target_brightness >= 245u);
    if (want_hbm != panel->hbm) {
        int rc = icna3311_set_hbm(panel, want_hbm);
        if (rc != 0) return rc;
    }
    bool want_dim = (st->screen == POWER_DIM);
    if (want_dim != panel->dimming) {
        int rc = icna3311_set_dimming(panel, want_dim);
        if (rc != 0) return rc;
    }
    if (!st->brightness_synced || st->applied_brightness != st->target_brightness) {
        int rc = icna3311_set_brightness(panel, st->target_brightness);
        if (rc != 0) return rc;
        st->applied_brightness = st->target_brightness;
        st->brightness_synced = true;
    }
    return 0;
}
