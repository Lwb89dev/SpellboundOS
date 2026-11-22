/* End-to-end RV32 QEMU runtime check: proto -> notify/nav -> UI render -> ICNA3311 flush. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../kernel/board.h"
#include "../kernel/console.h"
#include "../kernel/fb.h"
#include "../kernel/input.h"
#include "../kernel/notify.h"
#include "../kernel/power.h"
#include "../kernel/proto.h"
#include "../kernel/rtc.h"
#include "../kernel/ui.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/drivers/icna3311.h"

static uint16_t fb_pixels[120 * 140];
static uint32_t panel_flushes;

static int q_dcs_w(struct dcs_bus *b, const uint8_t *d, uint32_t l) { (void)b; (void)d; (void)l; return 0; }
static int q_dcs_r(struct dcs_bus *b, uint8_t c, uint8_t *o, uint32_t l) {
    (void)b; if (l != 1) return -1;
    if (c == DCS_CMD_READ_ID1) { o[0] = 0x1B; return 0; }
    if (c == DCS_CMD_READ_ID2) { o[0] = 0x09; return 0; }
    if (c == DCS_CMD_READ_ID3) { o[0] = 0x09; return 0; }
    return -1;
}
static int q_dcs_px(struct dcs_bus *b, const uint16_t *p, uint16_t s,
                    uint16_t x0, uint16_t y0, uint16_t w, uint16_t h) {
    (void)b; (void)p; (void)s; (void)x0; (void)y0; (void)w; (void)h;
    panel_flushes++;
    return 0;
}
static const struct dcs_ops q_dcs_ops = {q_dcs_w, q_dcs_r, q_dcs_px};
static struct dcs_bus q_dcs = {.name = "virt_dsi", .ops = &q_dcs_ops};

void kernel_main(void) {
    unsigned failures = 0;
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);
    notify_reset();

    struct fb fb;
    struct icna3311_dev panel;
    struct icna3311_config pcfg = {.bus = &q_dcs, .width = 120, .height = 140, .even_align_window = true};
    if (fb_init(&fb, fb_pixels, 120, 140) != 0 || icna3311_init(&panel, &pcfg) != 0) {
        failures++;
    }

    struct power_state pwr;
    power_init(&pwr, NULL, timer_ticks());
    (void)power_update_als(&pwr, 600);
    if (power_apply_panel(&pwr, &panel) != 0) failures++;

    struct ui_state ui;
    ui_init(&ui);
    uint64_t now_sec = rtc_is_bound() ? rtc_read_sec() : 1795255200ull;

    /* Render watchface */
    if (!ui_render(&ui, &fb, &pwr, now_sec) || icna3311_flush_fb(&panel, &fb) != 1) {
        failures++;
    }

    /* Inject Roadstr navigation maneuver and verify auto-switch + flush */
    struct nav_state nav = {.active = true, .maneuver = NAV_LEFT, .distance_m = 180, .eta_min = 4, .street = "Via Roma"};
    nav_update(&nav);
    if (!ui_render(&ui, &fb, &pwr, now_sec) || ui.screen != UI_SCREEN_NAVIGATION ||
        icna3311_flush_fb(&panel, &fb) != 1 || panel_flushes != 2u) {
        failures++;
    }

    console_puts(failures ? "FAIL: watch UI and power manager\n" :
                            "PASS: watch UI and power manager\n");
    board_poweroff();
}
