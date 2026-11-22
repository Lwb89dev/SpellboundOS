/* Hardware-independent sensor sample delivery queue and orientation remap. */
#include "sensor.h"
#include "sync.h"
#include <stddef.h>

#ifndef SPELLBOUND_HOST_TEST
#include "arch/riscv/riscv.h"
#include "arch/riscv/timer.h"
#endif

static struct msgq sensor_queue;
static bool sensor_ready;
static uint32_t dropped_samples;

int sensor_init(struct sensor_sample *storage, uint32_t capacity) {
    uint32_t previous = irq_save();
    sensor_ready = false;
    dropped_samples = 0;
    int rc = msgq_init(&sensor_queue, storage, sizeof(struct sensor_sample), capacity);
    if (rc == 0) {
        sensor_ready = true;
    }
    irq_restore(previous);
    return rc;
}

bool sensor_post(const struct sensor_sample *sample) {
    if (!sample) {
        return false;
    }
    uint32_t previous = irq_save();
    if (!sensor_ready) {
        irq_restore(previous);
        return false;
    }
    struct sensor_sample stamped = *sample;
    if (stamped.timestamp_ticks == 0) {
        stamped.timestamp_ticks = timer_ticks();
    }
    bool ok = msgq_try_send(&sensor_queue, &stamped);
    if (!ok) {
        dropped_samples++;
    }
    irq_restore(previous);
    return ok;
}

bool sensor_poll(struct sensor_sample *out) {
    return sensor_ready && msgq_try_recv(&sensor_queue, out);
}

bool sensor_wait(struct sensor_sample *out) {
    return sensor_ready && msgq_recv(&sensor_queue, out);
}

bool sensor_wait_for(struct sensor_sample *out, uint32_t ticks) {
    return sensor_ready && msgq_recv_for(&sensor_queue, out, ticks);
}

uint32_t sensor_pending(void) {
    return sensor_ready ? msgq_count(&sensor_queue) : 0;
}

uint32_t sensor_dropped(void) {
    uint32_t previous = irq_save();
    uint32_t count = dropped_samples;
    irq_restore(previous);
    return count;
}

static int16_t clamp_i16(int32_t v) {
    if (v > 32767) {
        return 32767;
    }
    if (v < -32768) {
        return -32768;
    }
    return (int16_t)v;
}

/* Eight orthogonal board-to-watch axis matrices (m00, m01, m10, m11, mz). */
static const int8_t orient_table[8][5] = {
    { 1,  0,  0,  1,  1},
    { 1,  0,  0, -1, -1},
    {-1,  0,  0,  1, -1},
    {-1,  0,  0, -1,  1},
    { 0,  1,  1,  0, -1},
    { 0,  1, -1,  0,  1},
    { 0, -1,  1,  0,  1},
    { 0, -1, -1,  0, -1},
};

bool sensor_remap_xyz(uint8_t orientation, bool wrist_flipped,
                      int16_t *x, int16_t *y, int16_t *z) {
    if (!x || !y || !z || orientation >= 8u) {
        return false;
    }
    const int8_t *m = orient_table[orientation];
    int32_t rx = (int32_t)m[0] * (int32_t)(*x) + (int32_t)m[1] * (int32_t)(*y);
    int32_t ry = (int32_t)m[2] * (int32_t)(*x) + (int32_t)m[3] * (int32_t)(*y);
    int32_t rz = (int32_t)m[4] * (int32_t)(*z);
    if (wrist_flipped) {
        rx = -rx;
        ry = -ry;
    }
    *x = clamp_i16(rx);
    *y = clamp_i16(ry);
    *z = clamp_i16(rz);
    return true;
}
