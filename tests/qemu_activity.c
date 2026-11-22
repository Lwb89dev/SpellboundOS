/* Runtime check for KV store and IMU activity/pedometer on RV32 QEMU virt. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../kernel/activity.h"
#include "../kernel/board.h"
#include "../kernel/console.h"
#include "../kernel/kv.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"

static uint8_t ram_store[256];
static uint8_t scratch_buf[256];

static int ram_read(uint32_t off, uint8_t *out, uint32_t len, void *ctx) {
    (void)ctx;
    for (uint32_t i = 0; i < len; i++) out[i] = ram_store[off + i];
    return 0;
}
static int ram_write(uint32_t off, const uint8_t *in, uint32_t len, void *ctx) {
    (void)ctx;
    for (uint32_t i = 0; i < len; i++) ram_store[off + i] = in[i];
    return 0;
}
static int ram_erase(void *ctx) {
    (void)ctx;
    for (uint32_t i = 0; i < sizeof ram_store; i++) ram_store[i] = 0xFFu;
    return 0;
}

void kernel_main(void) {
    unsigned failures = 0;
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);

    ram_erase(NULL);
    struct kv_backend be = {.capacity = sizeof ram_store, .read = ram_read, .write = ram_write, .erase = ram_erase};
    struct kv_store kv;
    uint32_t v = 0;
    if (kv_mount(&kv, &be) != 0 || kv_set_u32(&kv, "goal", 8000u) != 0 ||
        kv_compact(&kv, scratch_buf, sizeof scratch_buf) != 0 ||
        !kv_get_u32(&kv, "goal", &v) || v != 8000u) {
        failures++;
    }

    struct activity_state act;
    activity_init(&act, NULL);
    for (uint64_t i = 0; i < 4; i++) {
        struct sensor_sample hi = {.timestamp_ticks = 200u + i * 50u, .type = SENSOR_ACCEL, .sensitivity = 4096u, .z = 5600};
        struct sensor_sample lo = {.timestamp_ticks = 210u + i * 50u, .type = SENSOR_ACCEL, .sensitivity = 4096u, .z = 4096};
        (void)activity_feed_accel(&act, &hi);
        (void)activity_feed_accel(&act, &lo);
    }
    if (activity_steps(&act) != 4u) {
        failures++;
    }

    console_puts(failures ? "FAIL: KV store and activity pipeline\n" :
                            "PASS: KV store and activity pipeline\n");
    board_poweroff();
}
