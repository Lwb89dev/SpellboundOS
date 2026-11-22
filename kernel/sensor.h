/* Hardware-independent sensor sample delivery queue and 3D orientation remap. */
#ifndef SPELLBOUND_SENSOR_H
#define SPELLBOUND_SENSOR_H

#include <stdbool.h>
#include <stdint.h>

enum sensor_type {
    SENSOR_ACCEL = 1,
    SENSOR_GYRO = 2,
    SENSOR_ALS = 3,
    SENSOR_STEP = 4,
    SENSOR_HEART_RATE = 5,
    SENSOR_BATTERY = 6,
};

#define SENSOR_FLAG_OVERFLOW 0x01u
#define SENSOR_FLAG_CACHED   0x02u

struct sensor_sample {
    uint64_t timestamp_ticks;
    uint8_t type;
    uint8_t flags;
    uint16_t sensitivity; /* LSB/g for accel, LSB/dps*10 or unit-specific scale */
    int32_t x;            /* primary value for 1D sensors (lux, steps, bpm, mV) */
    int32_t y;
    int32_t z;
};

/* Bind caller-owned sample queue storage. Returns 0 on success, -1 on error. */
int sensor_init(struct sensor_sample *storage, uint32_t capacity);

/* Post a sample (ISR-safe). Auto-stamps timestamp_ticks if zero. Returns false
 * and increments the dropped counter if uninitialized or full. */
bool sensor_post(const struct sensor_sample *sample);

bool sensor_poll(struct sensor_sample *out);
bool sensor_wait(struct sensor_sample *out);
bool sensor_wait_for(struct sensor_sample *out, uint32_t ticks);

uint32_t sensor_pending(void);
uint32_t sensor_dropped(void);

/* Apply one of the 8 orthogonal 3D board orientation transforms (0..7) and
 * optional wrist flip (negates remapped X and Y). Returns false if pointers
 * are NULL or orientation >= 8, leaving coordinates unmodified. */
bool sensor_remap_xyz(uint8_t orientation, bool wrist_flipped,
                      int16_t *x, int16_t *y, int16_t *z);

#endif /* SPELLBOUND_SENSOR_H */
