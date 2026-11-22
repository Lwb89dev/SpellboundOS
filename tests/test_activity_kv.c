/* Host unit tests for power-fail-safe KV store and IMU activity/pedometer pipeline. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"

static unsigned mock_irq_depth = 0;
static inline uint32_t irq_save(void) {
    mock_irq_depth++;
    return mock_irq_depth == 1 ? 8u : 0u;
}
static inline void irq_restore(uint32_t previous) {
    assert(mock_irq_depth > 0);
    if (previous & 8u) assert(mock_irq_depth == 1);
    mock_irq_depth--;
}

#include "../kernel/notify.c"
#include "../kernel/proto.c"
#include "../kernel/kv.c"
#include "../kernel/activity.c"

/* ---- Mock Flash/NOR KV backend (erased = 0xFF) ---- */

struct mock_flash {
    uint8_t mem[512];
    uint32_t erases;
};

static int flash_read(uint32_t off, uint8_t *out, uint32_t len, void *ctx) {
    struct mock_flash *f = ctx;
    assert(off + len <= sizeof f->mem);
    memcpy(out, &f->mem[off], len);
    return 0;
}

static int flash_write(uint32_t off, const uint8_t *data, uint32_t len, void *ctx) {
    struct mock_flash *f = ctx;
    assert(off + len <= sizeof f->mem);
    memcpy(&f->mem[off], data, len);
    return 0;
}

static int flash_erase(void *ctx) {
    struct mock_flash *f = ctx;
    memset(f->mem, 0xFF, sizeof f->mem);
    f->erases++;
    return 0;
}

static void test_kv_store(void) {
    struct mock_flash fl = {0};
    memset(fl.mem, 0xFF, sizeof fl.mem);
    struct kv_backend be = {
        .capacity = sizeof fl.mem,
        .read = flash_read,
        .write = flash_write,
        .erase = flash_erase,
        .ctx = &fl,
    };

    struct kv_store kv;
    assert(kv_mount(&kv, &be) == 0);
    assert(kv_count(&kv) == 0 && kv_free_bytes(&kv) == sizeof fl.mem);

    /* Set, get, overwrite, u32 helper, delete */
    assert(kv_set(&kv, "tz_name", "CET", 3) == 0);
    assert(kv_set_u32(&kv, "brightness", 180u) == 0);
    assert(kv_set_u32(&kv, "brightness", 210u) == 0); /* overwrite */
    assert(kv_set(&kv, "temp", "xyz", 3) == 0);
    assert(kv_count(&kv) == 3);
    assert(kv_delete(&kv, "temp") == 0);
    assert(kv_count(&kv) == 2 && !kv_exists(&kv, "temp"));

    uint32_t brt = 0;
    assert(kv_get_u32(&kv, "brightness", &brt) && brt == 210u);
    char tz[8] = {0};
    uint8_t len = 0;
    assert(kv_get(&kv, "tz_name", tz, sizeof tz, &len) == 0 && len == 3 && memcmp(tz, "CET", 3) == 0);

    /* Simulate torn write (power loss mid-record) at the tail of the log */
    uint32_t cursor_before = kv.write_cursor;
    fl.mem[cursor_before + 0] = 'S';
    fl.mem[cursor_before + 1] = 'K';
    fl.mem[cursor_before + 2] = 0x01;
    fl.mem[cursor_before + 3] = 4;
    fl.mem[cursor_before + 4] = 4;
    memcpy(&fl.mem[cursor_before + 5], "torn", 4);
    /* leave bad CRC bytes -> remount must ignore torn tail and preserve prior records */
    struct kv_store kv2;
    assert(kv_mount(&kv2, &be) == 0);
    assert(kv2.corrupt_tail_records == 1);
    assert(kv2.write_cursor == cursor_before);
    assert(kv_count(&kv2) == 2);
    assert(kv_get_u32(&kv2, "brightness", &brt) && brt == 210u);
    assert(!kv_exists(&kv2, "torn"));

    /* Compact removes obsolete brightness + tombstoned temp + corrupt tail */
    uint8_t scratch[512];
    uint32_t free_before = kv_free_bytes(&kv2);
    assert(kv_compact(&kv2, scratch, sizeof scratch) == 0);
    assert(fl.erases == 1 && kv2.corrupt_tail_records == 0);
    assert(kv_free_bytes(&kv2) > free_before);
    assert(kv_count(&kv2) == 2);
    assert(kv_get_u32(&kv2, "brightness", &brt) && brt == 210u);
    assert(kv_get(&kv2, "tz_name", tz, sizeof tz, &len) == 0 && len == 3);
}

static void feed_step_wave(struct activity_state *act, uint64_t t_peak, uint64_t t_valley,
                           uint8_t *events_or) {
    /* Peak at ~1.35g, then settle back to ~1.0g */
    struct sensor_sample hi = {
        .timestamp_ticks = t_peak, .type = SENSOR_ACCEL, .sensitivity = 4096u,
        .x = 0, .y = 0, .z = 5600,
    };
    struct sensor_sample lo = {
        .timestamp_ticks = t_valley, .type = SENSOR_ACCEL, .sensitivity = 4096u,
        .x = 0, .y = 0, .z = 4096,
    };
    *events_or |= activity_feed_accel(act, &hi);
    *events_or |= activity_feed_accel(act, &lo);
}

static void test_activity_pipeline(void) {
    struct activity_state act;
    activity_init(&act, NULL);

    /* Single isolated jolt must NOT increment step count */
    uint8_t ev = 0;
    feed_step_wave(&act, 100, 110, &ev);
    assert(activity_steps(&act) == 0);

    /* Rhythmic walking: 6 steps spaced 50 ticks (500 ms) apart after cooldown gap */
    ev = 0;
    uint64_t t = 500;
    for (int i = 0; i < 6; i++) {
        feed_step_wave(&act, t, t + 10, &ev);
        t += 50;
    }
    assert((ev & ACTIVITY_EVT_STEP) != 0);
    assert(activity_steps(&act) == 6u);
    assert(activity_distance_m(&act) == (6u * 72u) / 100u);

    /* Wrist-raise wake: arm down (z=100mg) -> raise to viewing angle (z=980mg, x/y small) */
    struct sensor_sample down = {
        .timestamp_ticks = 1000, .type = SENSOR_ACCEL, .sensitivity = 4096u,
        .x = 3900, .y = 1000, .z = 200,
    };
    struct sensor_sample up = {
        .timestamp_ticks = 1020, .type = SENSOR_ACCEL, .sensitivity = 4096u,
        .x = 200, .y = -100, .z = 4050,
    };
    assert((activity_feed_accel(&act, &down) & ACTIVITY_EVT_WRIST_WAKE) == 0);
    assert((activity_feed_accel(&act, &up) & ACTIVITY_EVT_WRIST_WAKE) != 0);

    /* Immediate repeat within cooldown does NOT re-trigger */
    down.timestamp_ticks = 1050;
    up.timestamp_ticks = 1070;
    assert((activity_feed_accel(&act, &down) & ACTIVITY_EVT_WRIST_WAKE) == 0);
    assert((activity_feed_accel(&act, &up) & ACTIVITY_EVT_WRIST_WAKE) == 0);

    /* After cooldown (>= 150 ticks), triggers again */
    down.timestamp_ticks = 1250;
    up.timestamp_ticks = 1270;
    assert((activity_feed_accel(&act, &down) & ACTIVITY_EVT_WRIST_WAKE) == 0);
    assert((activity_feed_accel(&act, &up) & ACTIVITY_EVT_WRIST_WAKE) != 0);

    activity_reset_daily(&act);
    assert(activity_steps(&act) == 0);
}

int main(void) {
    test_kv_store();
    test_activity_pipeline();
    assert(mock_irq_depth == 0);
    printf("PASS: power-fail-safe KV store and IMU activity/pedometer\n");
    return 0;
}
