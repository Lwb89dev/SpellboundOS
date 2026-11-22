/* Host unit tests for power manager, watch UI compositor and Bip 6 board descriptor. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"
#include "../kernel/boards/bip6/board_desc.h"

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

#include "../kernel/rtc.c"
#include "../kernel/fb.c"
#include "../kernel/notify.c"
#include "../kernel/drivers/icna3311.c"
#include "../kernel/power.c"
#include "../kernel/ui.c"

struct ui_mock_dcs {
    uint32_t flushes;
    uint32_t cmds;
};
static int u_dcs_w(struct dcs_bus *b, const uint8_t *d, uint32_t l) {
    (void)d; (void)l; ((struct ui_mock_dcs *)b->priv)->cmds++; return 0;
}
static int u_dcs_r(struct dcs_bus *b, uint8_t c, uint8_t *o, uint32_t l) {
    (void)b; assert(l == 1);
    if (c == DCS_CMD_READ_ID1) { o[0] = 0x1B; return 0; }
    if (c == DCS_CMD_READ_ID2) { o[0] = 0x09; return 0; }
    if (c == DCS_CMD_READ_ID3) { o[0] = 0x09; return 0; }
    return -1;
}
static int u_dcs_px(struct dcs_bus *b, const uint16_t *p, uint16_t s,
                    uint16_t x0, uint16_t y0, uint16_t w, uint16_t h) {
    (void)p; (void)s; (void)x0; (void)y0; (void)w; (void)h;
    ((struct ui_mock_dcs *)b->priv)->flushes++;
    return 0;
}
static const struct dcs_ops u_dcs_ops = {u_dcs_w, u_dcs_r, u_dcs_px};

static uint32_t count_nonblack(const struct fb *fb) {
    uint32_t n = 0;
    uint32_t total = (uint32_t)fb->width * (uint32_t)fb->height;
    for (uint32_t i = 0; i < total; i++) {
        if (fb->pixels[i] != FB_BLACK) n++;
    }
    return n;
}

static uint32_t action_fired_id = 0;
static void ui_action_cb(uint32_t id, uint8_t idx, const char *label, void *ctx) {
    (void)idx; (void)label; (void)ctx;
    action_fired_id = id;
}

static void test_power_manager(void) {
    /* Verify monotonic ALS -> brightness curve */
    assert(power_lux_to_brightness(0) == 24);
    assert(power_lux_to_brightness(10) == 40);
    assert(power_lux_to_brightness(100) == 96);
    assert(power_lux_to_brightness(500) == 160);
    assert(power_lux_to_brightness(2000) == 220);
    assert(power_lux_to_brightness(6000) == 255);

    struct ui_mock_dcs md = {0};
    struct dcs_bus bus = {.name = "dsi0", .ops = &u_dcs_ops, .priv = &md};
    struct icna3311_dev panel;
    struct icna3311_config pcfg = {.bus = &bus, .width = 160, .height = 180};
    assert(icna3311_init(&panel, &pcfg) == 0);

    struct power_state pwr;
    struct power_config cfg = {
        .dim_timeout_ticks = 100,
        .sleep_timeout_ticks = 200,
        .aod_enabled = false,
        .auto_brightness = true,
        .manual_brightness = 150,
        .dim_brightness = 30,
        .aod_brightness = 20,
    };
    power_init(&pwr, &cfg, 1000);
    assert(power_update_als(&pwr, 6000)); /* bright sun -> 255 -> HBM */
    assert(power_apply_panel(&pwr, &panel) == 0);
    assert(panel.brightness == 255 && panel.hbm && panel.power_on);

    /* Timeout to DIM -> brightness 30, dimming on, HBM off */
    assert(power_tick(&pwr, 1100) && pwr.screen == POWER_DIM);
    assert(power_apply_panel(&pwr, &panel) == 0);
    assert(panel.dimming && !panel.hbm && panel.brightness == 30);

    /* Timeout to SLEEP -> panel off */
    assert(power_tick(&pwr, 1200) && pwr.screen == POWER_SLEEP);
    assert(power_apply_panel(&pwr, &panel) == 0);
    assert(!panel.power_on);

    /* Wake back to ACTIVE */
    assert(power_wake(&pwr, 1250) && pwr.screen == POWER_ACTIVE);
    assert(power_apply_panel(&pwr, &panel) == 0 && panel.power_on);

    /* AOD mode keeps panel awake at low brightness */
    pwr.cfg.aod_enabled = true;
    assert(power_sleep(&pwr) && pwr.screen == POWER_AOD);
    assert(power_apply_panel(&pwr, &panel) == 0 && panel.power_on && panel.brightness == 20);
}

static void test_ui_compositor(void) {
    static uint16_t pixels[160 * 180];
    struct fb fb;
    assert(fb_init(&fb, pixels, 160, 180) == 0);

    struct ui_mock_dcs md = {0};
    struct dcs_bus bus = {.name = "dsi0", .ops = &u_dcs_ops, .priv = &md};
    struct icna3311_dev panel;
    struct icna3311_config pcfg = {.bus = &bus, .width = 160, .height = 180, .even_align_window = true};
    assert(icna3311_init(&panel, &pcfg) == 0);

    notify_reset();
    notify_set_action_cb(ui_action_cb, NULL);

    struct power_state pwr;
    power_init(&pwr, NULL, 0);
    power_set_battery(&pwr, 78, true);

    struct ui_state ui;
    ui_init(&ui);
    ui_set_activity(&ui, 4321, 68);
    ui_set_timezone(&ui, 60);

    /* 1. Watchface render */
    uint64_t now_sec = 1795255200ull; /* 2026-11-22 10:00:00 UTC */
    assert(ui_render(&ui, &fb, &pwr, now_sec));
    assert(count_nonblack(&fb) > 200);
    assert(icna3311_flush_fb(&panel, &fb) == 1);
    assert(!ui_render(&ui, &fb, &pwr, now_sec)); /* unchanged second -> no redraw */

    /* 2. Post notification, click button to Notifications screen, double-click to fire action */
    struct notification n = {
        .id = 99, .unread = true, .app = "Signal", .title = "Marco", .body = "Arrivo tra 5m",
        .action_count = 1,
    };
    strcpy(n.actions[0], "OK");
    assert(notify_post(&n) == 0);

    struct input_event click = {.type = INPUT_KEY, .action = INPUT_KEY_SHORT_CLICK, .code = 0};
    assert(ui_handle_input(&ui, &pwr, &click, 10));
    assert(ui.screen == UI_SCREEN_NOTIFICATIONS);
    assert(ui_render(&ui, &fb, &pwr, now_sec) && count_nonblack(&fb) > 500);

    struct input_event dbl = {.type = INPUT_KEY, .action = INPUT_KEY_DOUBLE_CLICK, .code = 0};
    assert(ui_handle_input(&ui, &pwr, &dbl, 20));
    assert(action_fired_id == 99);

    /* 3. Roadstr navigation auto-promotes and draws every maneuver cleanly */
    const enum nav_maneuver maneuvers[] = {
        NAV_STRAIGHT, NAV_LEFT, NAV_RIGHT, NAV_ROUNDABOUT, NAV_UTURN, NAV_ARRIVE
    };
    for (unsigned i = 0; i < sizeof maneuvers / sizeof maneuvers[0]; i++) {
        struct nav_state nav = {
            .active = true,
            .maneuver = (uint8_t)maneuvers[i],
            .roundabout_exit = 2,
            .distance_m = (i == 0) ? 1450u : 250u,
            .eta_min = 9,
            .street = "Via Emilia",
        };
        nav_update(&nav);
        assert(ui_render(&ui, &fb, &pwr, now_sec));
        assert(ui.screen == UI_SCREEN_NAVIGATION);
        assert(count_nonblack(&fb) > 400);
        assert(icna3311_flush_fb(&panel, &fb) == 1);
    }

    /* 4. Incoming call auto-promotes, then clears back to watchface */
    struct call_info ci = {.state = CALL_RINGING, .caller = "Elena", .number = "+39333"};
    call_update(&ci);
    assert(ui_render(&ui, &fb, &pwr, now_sec) && ui.screen == UI_SCREEN_CALL);
    assert(count_nonblack(&fb) > 300);

    ci.state = CALL_IDLE;
    call_update(&ci);
    assert(ui_render(&ui, &fb, &pwr, now_sec) && ui.screen == UI_SCREEN_WATCHFACE);

    /* 5. Quick settings toggle via button + touch */
    ui_set_screen(&ui, UI_SCREEN_QUICK_SETTINGS);
    assert(ui_render(&ui, &fb, &pwr, now_sec));
    bool prev_auto = pwr.cfg.auto_brightness;
    struct input_event tap = {.type = INPUT_TOUCH, .action = INPUT_TOUCH_DOWN, .x = 80, .y = 32};
    assert(ui_handle_input(&ui, &pwr, &tap, 30));
    assert(pwr.cfg.auto_brightness == !prev_auto);

    /* 6. Sleep suppresses render; wake consumes first key without changing screen */
    assert(power_sleep(&pwr));
    assert(!ui_render(&ui, &fb, &pwr, now_sec + 1));
    assert(ui_handle_input(&ui, &pwr, &click, 40));
    assert(pwr.screen == POWER_ACTIVE && ui.screen == UI_SCREEN_QUICK_SETTINGS);

    /* 7. Bip 6 hardware descriptor sanity constants */
    assert(BIP6_DISPLAY_WIDTH == 390u && BIP6_DISPLAY_HEIGHT == 450u);
    assert(BIP6_TOUCH_I2C_ADDR == 0x20u && BIP6_ALS_I2C_ADDR == 0x48u);
    assert(BIP6_MOTOR_GPIO == 95u && BIP6_IMU_WHO_AM_I == 0x6Cu);
}

int main(void) {
    test_power_manager();
    test_ui_compositor();
    assert(mock_irq_depth == 0);
    printf("PASS: power manager, watch UI compositor and Bip 6 descriptor\n");
    return 0;
}
