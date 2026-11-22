/* Pure-integer IMU activity pipeline: pedometer step counter & wrist-raise wake detector. */
#ifndef SPELLBOUND_ACTIVITY_H
#define SPELLBOUND_ACTIVITY_H

#include <stdbool.h>
#include <stdint.h>
#include "sensor.h"

#define ACTIVITY_EVT_NONE       0x00u
#define ACTIVITY_EVT_STEP       0x01u
#define ACTIVITY_EVT_WRIST_WAKE 0x02u

struct activity_config {
    uint32_t tick_hz;             /* timer ticks per second (e.g. 100) */
    uint16_t stride_cm;           /* average stride length in cm (default 72) */
    uint32_t min_step_ticks;      /* min ticks between steps (~250 ms) */
    uint32_t max_step_ticks;      /* max ticks between consecutive steps (~1500 ms) */
    uint32_t wrist_cooldown_ticks;/* min ticks between wrist-wake events (~1500 ms) */
};

struct activity_state {
    struct activity_config cfg;
    uint32_t steps;
    int32_t baseline_mg;      /* filtered magnitude in milli-g */
    bool peak_armed;
    bool has_last_step;
    uint64_t last_step_ticks;
    uint8_t cadence_streak;   /* requires consecutive rhythmic steps to reject single jolts */
    bool wrist_down;
    bool has_last_wake;
    uint64_t last_wake_ticks;
};

void activity_init(struct activity_state *st, const struct activity_config *cfg);
void activity_reset_daily(struct activity_state *st);

/* Feed one SENSOR_ACCEL sample. Returns bitmask of ACTIVITY_EVT_* flags. */
uint8_t activity_feed_accel(struct activity_state *st, const struct sensor_sample *sample);

uint32_t activity_steps(const struct activity_state *st);
uint32_t activity_distance_m(const struct activity_state *st);
uint32_t activity_calories_kcal(const struct activity_state *st);

#endif /* SPELLBOUND_ACTIVITY_H */
