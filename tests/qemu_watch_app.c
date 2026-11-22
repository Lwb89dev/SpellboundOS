/* Runtime check for AG3335 GNSS driver and unified watch_app runtime on RV32 QEMU virt. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../kernel/board.h"
#include "../kernel/console.h"
#include "../kernel/fb.h"
#include "../kernel/input.h"
#include "../kernel/notify.h"
#include "../kernel/rtc.h"
#include "../kernel/sensor.h"
#include "../kernel/watch_app.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/drivers/ag3335.h"

static uint16_t fb_buf[120 * 140];
static struct input_event in_buf[8];
static struct sensor_sample sen_buf[8];
static uint32_t tx_frames;

static int tx_stub(const uint8_t *d, uint32_t l, void *c) {
    (void)d; (void)l; (void)c;
    tx_frames++;
    return 0;
}

void kernel_main(void) {
    unsigned failures = 0;
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);

    /* Verify AG3335 PAIR formatting checksums on RV32 */
    char pair[32];
    if (ag3335_format_pair(pair, sizeof pair, "002", NULL) != 13 ||
        pair[9] != '3' || pair[10] != '8') {
        failures++;
    }

    if (input_init(in_buf, 8) != 0 || sensor_init(sen_buf, 8) != 0) failures++;
    notify_reset();

    struct fb fb;
    if (fb_init(&fb, fb_buf, 120, 140) != 0) failures++;

    struct watch_app app;
    struct watch_app_config cfg = {
        .fb = &fb,
        .proto_tx = {.send = tx_stub},
        .tick_hz = 100u,
        .telemetry_period_ticks = 10u,
    };
    watch_app_init(&app, &cfg, 0);

    uint8_t ping[16];
    int n = proto_encode(ping, sizeof ping, PROTO_PING, 1, NULL, 0);
    if (watch_app_feed_proto(&app, ping, (uint32_t)n, 5) != 1) failures++;

    watch_app_step(&app, 15, rtc_is_bound() ? rtc_read_sec() : 1795255200ull);
    if (app.ui.frames_rendered != 1 || app.telemetry_sent != 1 || tx_frames != 2u) {
        failures++;
    }

    console_puts(failures ? "FAIL: GNSS and watch_app runtime\n" :
                            "PASS: GNSS and watch_app runtime\n");
    board_poweroff();
}
