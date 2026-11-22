/* Pure-integer IMU activity pipeline: pedometer step counter & wrist-raise wake detector. */
#include "activity.h"
#include <stddef.h>

/* Integer square root for 32-bit unsigned values (no libgcc/FPU). */
static uint32_t isqrt_u32(uint32_t n) {
    uint32_t res = 0;
    uint32_t bit = 1u << 30;
    while (bit > n) bit >>= 2;
    while (bit != 0) {
        if (n >= res + bit) {
            n -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    return res;
}

static int32_t abs_i32(int32_t v) {
    return v < 0 ? -v : v;
}

void activity_init(struct activity_state *st, const struct activity_config *cfg) {
    if (!st) return;
    if (cfg) {
        st->cfg = *cfg;
    } else {
        st->cfg = (struct activity_config){
            .tick_hz = 100u,
            .stride_cm = 72u,
            .min_step_ticks = 25u,
            .max_step_ticks = 150u,
            .wrist_cooldown_ticks = 150u,
        };
    }
    if (st->cfg.tick_hz == 0) st->cfg.tick_hz = 100u;
    if (st->cfg.stride_cm == 0) st->cfg.stride_cm = 72u;
    if (st->cfg.min_step_ticks == 0) st->cfg.min_step_ticks = st->cfg.tick_hz / 4u;
    if (st->cfg.max_step_ticks == 0) st->cfg.max_step_ticks = (st->cfg.tick_hz * 3u) / 2u;
    if (st->cfg.wrist_cooldown_ticks == 0) st->cfg.wrist_cooldown_ticks = (st->cfg.tick_hz * 3u) / 2u;

    st->steps = 0;
    st->baseline_mg = 1000;
    st->peak_armed = false;
    st->has_last_step = false;
    st->last_step_ticks = 0;
    st->cadence_streak = 0;
    st->wrist_down = true;
    st->has_last_wake = false;
    st->last_wake_ticks = 0;
}

void activity_reset_daily(struct activity_state *st) {
    if (!st) return;
    st->steps = 0;
    st->cadence_streak = 0;
    st->has_last_step = false;
}

uint8_t activity_feed_accel(struct activity_state *st, const struct sensor_sample *sample) {
    if (!st || !sample || sample->type != SENSOR_ACCEL) {
        return ACTIVITY_EVT_NONE;
    }
    uint32_t sens = sample->sensitivity > 0 ? sample->sensitivity : 4096u;
    /* Convert raw axes to milli-g safely (|axis| <= 32768 -> *1000 fits in int32). */
    int32_t gx = (sample->x * 1000) / (int32_t)sens;
    int32_t gy = (sample->y * 1000) / (int32_t)sens;
    int32_t gz = (sample->z * 1000) / (int32_t)sens;

    uint32_t ax = (uint32_t)abs_i32(gx);
    uint32_t ay = (uint32_t)abs_i32(gy);
    uint32_t az = (uint32_t)abs_i32(gz);
    if (ax > 16000u) ax = 16000u;
    if (ay > 16000u) ay = 16000u;
    if (az > 16000u) az = 16000u;

    uint32_t mag_mg = isqrt_u32(ax * ax + ay * ay + az * az);
    /* Slow exponential moving baseline (7/8 old + 1/8 new). */
    st->baseline_mg = (st->baseline_mg * 7 + (int32_t)mag_mg) / 8;
    int32_t delta = (int32_t)mag_mg - st->baseline_mg;

    uint8_t events = ACTIVITY_EVT_NONE;

    /* Hysteresis peak detector: arm above +180 mg, commit step crossing below +40 mg. */
    if (!st->peak_armed) {
        if (delta >= 180) {
            st->peak_armed = true;
        }
    } else if (delta <= 40) {
        st->peak_armed = false;
        uint64_t now = sample->timestamp_ticks;
        if (!st->has_last_step) {
            st->has_last_step = true;
            st->last_step_ticks = now;
            st->cadence_streak = 1;
        } else {
            uint64_t dt = now - st->last_step_ticks;
            if (dt >= st->cfg.min_step_ticks && dt <= st->cfg.max_step_ticks) {
                st->last_step_ticks = now;
                if (st->cadence_streak < 255u) st->cadence_streak++;
                if (st->cadence_streak == 3u) {
                    /* Commit the 3 initial rhythmic steps once walking is confirmed. */
                    st->steps += 3u;
                    events |= ACTIVITY_EVT_STEP;
                } else if (st->cadence_streak > 3u) {
                    st->steps++;
                    events |= ACTIVITY_EVT_STEP;
                }
            } else if (dt > st->cfg.max_step_ticks) {
                /* Cadence broke; start a fresh streak. */
                st->last_step_ticks = now;
                st->cadence_streak = 1;
            }
            /* dt < min_step_ticks: bounce/noise ignored without resetting streak. */
        }
    }

    /* Wrist-raise wake detector:
     * Arm-down posture: gz < 350 mg (watch tilted away/down).
     * Viewing posture: gz >= 750 mg and |gx| < 450 mg and |gy| < 450 mg. */
    if (gz < 350) {
        st->wrist_down = true;
    } else if (st->wrist_down && gz >= 750 && ax < 450u && ay < 450u) {
        uint64_t now = sample->timestamp_ticks;
        if (!st->has_last_wake || (now - st->last_wake_ticks) >= st->cfg.wrist_cooldown_ticks) {
            st->wrist_down = false;
            st->has_last_wake = true;
            st->last_wake_ticks = now;
            events |= ACTIVITY_EVT_WRIST_WAKE;
        }
    }

    return events;
}

uint32_t activity_steps(const struct activity_state *st) {
    return st ? st->steps : 0;
}

uint32_t activity_distance_m(const struct activity_state *st) {
    if (!st) return 0;
    return (st->steps * (uint32_t)st->cfg.stride_cm) / 100u;
}

uint32_t activity_calories_kcal(const struct activity_state *st) {
    if (!st) return 0;
    /* ~0.04 kcal/step = steps / 25 */
    return st->steps / 25u;
}
