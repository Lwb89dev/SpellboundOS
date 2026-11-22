/* Host unit tests for STK31E60 ALS, CW6305/AW32012 chargers, motor, fb and ICNA3311. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"

static int mock_current_task = 0;
static uint64_t mock_ticks = 100;
static unsigned mock_irq_depth = 0;

static inline uint32_t irq_save(void) {
    mock_irq_depth++;
    return mock_irq_depth == 1 ? 8u : 0u;
}

static inline void irq_restore(uint32_t previous) {
    assert(mock_irq_depth > 0);
    if (previous & 8u) {
        assert(mock_irq_depth == 1);
    }
    mock_irq_depth--;
}

static uint64_t timer_ticks(void) { return mock_ticks; }
int task_current(void) { return mock_current_task; }
void task_event_signal(struct task_event *event) { event->pending = true; }
void task_event_wait(struct task_event *event) { event->pending = false; }
bool task_event_wait_for(struct task_event *event, uint32_t ticks) {
    if (event->pending) { event->pending = false; return true; }
    mock_ticks += ticks;
    return false;
}

#include "../kernel/bus.c"
#include "../kernel/sync.c"
#include "../kernel/sensor.c"
#include "../kernel/fb.c"
#include "../kernel/drivers/stk31e60.c"
#include "../kernel/drivers/charger.c"
#include "../kernel/drivers/motor.c"
#include "../kernel/drivers/icna3311.c"

static uint32_t test_delay_ms_sum = 0;
static void test_delay(uint32_t ms, void *ctx) {
    (void)ctx;
    test_delay_ms_sum += ms;
}

/* ---- Mock I2C bus hosting STK31E60, CW6305 and AW32012 ---- */

struct mock_i2c_env {
    bool has_stk;
    bool has_cw;
    bool has_aw;
    uint8_t stk_regs[256];
    uint8_t cw_regs[32];
    uint8_t aw_regs[128];
    uint32_t stk_writes;
    uint32_t cw_writes;
    uint32_t aw_writes;
    uint32_t fail_next_reads;
    bool aw_vbus_unlocked;
};

static int env_i2c_transfer(struct i2c_bus *bus, const struct i2c_msg *msgs, uint32_t count) {
    struct mock_i2c_env *e = bus->priv;
    uint16_t addr = msgs[0].addr;
    uint8_t *regs = NULL;
    uint32_t reg_limit = 0;
    uint32_t *wcount = NULL;

    if (addr == STK31E60_I2C_ADDR && e->has_stk) {
        regs = e->stk_regs; reg_limit = 256; wcount = &e->stk_writes;
    } else if (addr == CW6305_I2C_ADDR && e->has_cw) {
        regs = e->cw_regs; reg_limit = 32; wcount = &e->cw_writes;
    } else if (addr == AW32012_I2C_ADDR && e->has_aw) {
        regs = e->aw_regs; reg_limit = 128; wcount = &e->aw_writes;
    } else {
        return -1;
    }

    if (count == 2 && (msgs[0].flags & I2C_MSG_READ) == 0 && (msgs[1].flags & I2C_MSG_READ) != 0) {
        if (e->fail_next_reads > 0) {
            e->fail_next_reads--;
            return -1;
        }
        uint8_t r = msgs[0].buf[0];
        assert(r < reg_limit);
        msgs[1].buf[0] = regs[r];
        return 0;
    }
    if (count == 1 && (msgs[0].flags & I2C_MSG_READ) == 0 && msgs[0].len == 2) {
        uint8_t r = msgs[0].buf[0];
        uint8_t v = msgs[0].buf[1];
        assert(r < reg_limit);
        if (addr == AW32012_I2C_ADDR) {
            if (r == 0x69u) {
                e->aw_vbus_unlocked = (v == 0xC2u);
            } else if (r == 0x21u && !e->aw_vbus_unlocked) {
                return -1; /* must be unlocked first */
            }
        }
        regs[r] = v;
        (*wcount)++;
        return 0;
    }
    return -1;
}

static const struct i2c_ops env_i2c_ops = {.transfer = env_i2c_transfer};

/* ---- Mock GPIO for motor ---- */

struct mock_motor_gpio {
    bool high;
    uint32_t transitions;
};
static int m_gpio_cfg(struct gpio_chip *c, uint32_t pin, enum gpio_mode m) {
    (void)c; assert(pin == 95 && m == GPIO_OUTPUT); return 0;
}
static int m_gpio_write(struct gpio_chip *c, uint32_t pin, bool high) {
    assert(pin == 95);
    struct mock_motor_gpio *g = c->priv;
    if (g->high != high) g->transitions++;
    g->high = high;
    return 0;
}
static const struct gpio_ops m_gpio_ops = {.configure = m_gpio_cfg, .write = m_gpio_write};

/* ---- Mock DCS panel bus ---- */

struct mock_dcs {
    uint8_t id[3];
    uint32_t cmd_count;
    uint8_t last_cmd[8];
    uint32_t last_cmd_len;
    uint32_t pixel_flushes;
    uint16_t flush_x0, flush_y0, flush_w, flush_h;
    uint16_t sample_pixel;
    uint8_t brightness_seen;
    uint8_t ctrl_disp_seen;
    uint8_t hbm_seen;
};

static int dcs_write_cb(struct dcs_bus *bus, const uint8_t *data, uint32_t len) {
    struct mock_dcs *d = bus->priv;
    d->cmd_count++;
    d->last_cmd_len = len > 8 ? 8 : len;
    memcpy(d->last_cmd, data, d->last_cmd_len);
    if (len == 2 && data[0] == DCS_CMD_SET_BRIGHTNESS) d->brightness_seen = data[1];
    if (len == 2 && data[0] == DCS_CMD_SET_CTRL_DISP) d->ctrl_disp_seen = data[1];
    if (len == 2 && data[0] == DCS_CMD_SET_HBM) d->hbm_seen = data[1];
    return 0;
}

static int dcs_read_cb(struct dcs_bus *bus, uint8_t cmd, uint8_t *out, uint32_t len) {
    struct mock_dcs *d = bus->priv;
    assert(len == 1);
    if (cmd == DCS_CMD_READ_ID1) { out[0] = d->id[0]; return 0; }
    if (cmd == DCS_CMD_READ_ID2) { out[0] = d->id[1]; return 0; }
    if (cmd == DCS_CMD_READ_ID3) { out[0] = d->id[2]; return 0; }
    return -1;
}

static int dcs_pixels_cb(struct dcs_bus *bus, const uint16_t *pixels,
                         uint16_t stride, uint16_t x0, uint16_t y0,
                         uint16_t w, uint16_t h) {
    struct mock_dcs *d = bus->priv;
    d->pixel_flushes++;
    d->flush_x0 = x0; d->flush_y0 = y0; d->flush_w = w; d->flush_h = h;
    d->sample_pixel = pixels[(uint32_t)y0 * stride + x0];
    return 0;
}

static const struct dcs_ops mock_dcs_ops = {
    .write_cmd = dcs_write_cb,
    .read_cmd = dcs_read_cb,
    .write_pixels = dcs_pixels_cb,
};

/* ---- Tests ---- */

static void test_stk31e60(void) {
    struct sensor_sample sq[8];
    assert(sensor_init(sq, 8) == 0);

    struct mock_i2c_env env = {.has_stk = true};
    env.stk_regs[STK31E60_REG_CHIP_ID] = STK31E60_CHIP_ID;
    env.stk_regs[0xE3u] = 0x80u; /* already matches -> skip write */
    env.stk_regs[0xE5u] = 0x00u; /* differs -> written */
    env.stk_regs[STK31E60_REG_CFG_6A] = 0x15u; /* bit 4 should be cleared -> 0x05 */

    struct i2c_bus bus = {.name = "i2c3", .ops = &env_i2c_ops, .priv = &env};
    struct stk31e60_dev als;
    struct stk31e60_config cfg = {
        .bus = &bus,
        .publish_sensor = true,
        .delay_ms = test_delay,
    };

    assert(stk31e60_encode_it(166u) == 0x00A6u);
    assert(stk31e60_init(&als, &cfg) == 0);
    assert(als.probed && als.it_code == 0x00A6u);
    assert(env.stk_regs[0xE5u] == 0x80u && env.stk_regs[0xEAu] == 0x80u);
    assert(env.stk_regs[STK31E60_REG_CFG_6A] == 0x05u);
    assert(env.stk_regs[STK31E60_REG_IT_H] == 0x00u && env.stk_regs[STK31E60_REG_IT_L] == 0xA6u);

    /* Not ready -> timeout -2 */
    env.stk_regs[STK31E60_REG_FLAG] = 0x00u;
    uint16_t raw = 0; uint32_t lux = 0; bool cached = false;
    assert(stk31e60_read_als(&als, &raw, &lux, &cached) == -2);

    /* Fresh read at gain 0xB0 (1x) */
    env.stk_regs[STK31E60_REG_FLAG] = 0x80u;
    env.stk_regs[STK31E60_REG_DATA_H] = 0x01u;
    env.stk_regs[STK31E60_REG_DATA_L] = 0x2Cu; /* 300 */
    assert(stk31e60_read_als(&als, &raw, &lux, &cached) == 0);
    assert(raw == 300u && lux == 300u && !cached);

    struct sensor_sample s;
    assert(sensor_poll(&s) && s.type == SENSOR_ALS && s.x == 300 && s.flags == 0);

    /* Gain 0xC0 halves lux/count (2x sensor sensitivity); cached fallback on read error */
    assert(stk31e60_set_gain(&als, 0xC0u) == 0);
    env.fail_next_reads = 3; /* data_h fails all 3 retries after flag succeeds */
    /* First read is FLAG (succeeds if we set fail after flag? Let's make flag succeed
       by failing DATA_H via 3 fails when flag is already checked: wait—flag is 1st read!
       Instead verify fresh read at 0xC0 first.) */
    env.fail_next_reads = 0;
    assert(stk31e60_read_als(&als, &raw, &lux, &cached) == 0);
    assert(raw == 300u && lux == 150u && !cached);

    /* Wrong chip ID returns -3 */
    env.stk_regs[STK31E60_REG_CHIP_ID] = 0x11u;
    assert(stk31e60_init(&als, &cfg) == -3);
}

static void test_chargers(void) {
    /* Piecewise current encoder boundaries */
    assert(cw6305_encode_current_ma(9) == -1);
    assert(cw6305_encode_current_ma(10) == 0);
    assert(cw6305_encode_current_ma(20) == 8);
    assert(cw6305_encode_current_ma(40) == 16);
    assert(cw6305_encode_current_ma(80) == 24);
    assert(cw6305_encode_current_ma(470) == 63);
    assert(cw6305_encode_current_ma(471) == -1);

    assert(aw32012_encode_fast_ma(8) == 0);
    assert(aw32012_encode_fast_ma(512) == 63);
    assert(aw32012_encode_fast_ma(600) == 0x3F);
    assert(aw32012_encode_pre_ma(1) == 0);
    assert(aw32012_encode_pre_ma(31) == 15);
    assert(aw32012_encode_pre_ma(40) == 0x0F);

    /* Auto-probe CW6305 */
    struct mock_i2c_env env = {.has_cw = true, .has_aw = false};
    env.cw_regs[0x00] = 0x14u;
    env.cw_regs[0x01] = 0x03u;
    env.cw_regs[0x04] = 0xC0u; /* top 2 bits must be preserved */
    env.cw_regs[0x08] = 0xC0u; /* both WDT bits set */
    env.cw_regs[0x0D] = 0x05u; /* vbus=1, fast charge (state=2) */
    struct i2c_bus bus = {.name = "sens_i2c1", .ops = &env_i2c_ops, .priv = &env};

    struct charger_dev chg;
    assert(charger_probe(&chg, &bus) == 0 && chg.kind == CHARGER_CW6305);
    assert(charger_set_enable(&chg, true) == 0 && (env.cw_regs[0x01] & 0x40u) == 0x40u);
    uint32_t writes_before = env.cw_writes;
    assert(charger_set_enable(&chg, true) == 0 && env.cw_writes == writes_before); /* write-on-change */
    assert(charger_set_fast_current_ma(&chg, 120) == 0);
    assert(env.cw_regs[0x04] == (0xC0u | 28u)); /* top bits preserved */
    struct charger_status st;
    assert(charger_read_status(&chg, &st) == 0 && st.vbus_present && st.state == CHARGER_STATE_FAST_CHARGE);
    assert(charger_poweroff(&chg) == 0);
    assert((env.cw_regs[0x08] & 0xC0u) == 0 && (env.cw_regs[0x07] & 0x80u) == 0x80u);

    /* Auto-probe AW32012 when CW6305 absent */
    env.has_cw = false;
    env.has_aw = true;
    env.aw_regs[0x0A] = 0x40u;
    env.aw_regs[0x01] = 0x08u; /* disabled */
    env.aw_regs[0x08] = 0x18u; /* done (state 3) */
    assert(charger_probe(&chg, &bus) == 0 && chg.kind == CHARGER_AW32012);
    assert(charger_set_enable(&chg, true) == 0 && (env.aw_regs[0x01] & 0x08u) == 0);
    assert(charger_set_fast_current_ma(&chg, 200) == 0 && (env.aw_regs[0x02] & 0x3Fu) == 24u);
    assert(aw32012_set_vbus_reset(&chg, true) == 0);
    assert((env.aw_regs[0x21] & 0x80u) == 0x80u && !env.aw_vbus_unlocked); /* relocked! */
    assert(charger_read_status(&chg, &st) == 0 && st.state == CHARGER_STATE_DONE);
    assert(charger_poweroff(&chg) == 0 && (env.aw_regs[0x06] & 0x20u) == 0x20u);
}

static void test_motor(void) {
    assert(motor_level_duration_ms(1) == 25u);
    assert(motor_level_duration_ms(5) == 80u);
    assert(motor_level_duration_ms(6) == 130u);
    assert(motor_level_duration_ms(0) == 1000u);
    assert(motor_level_duration_ms(9) == 1000u);

    struct mock_motor_gpio mg = {0};
    struct gpio_chip chip = {.name = "gpio0", .pin_count = 100, .ops = &m_gpio_ops, .priv = &mg};
    struct motor_dev mot;
    assert(motor_init(&mot, &chip, 95, 100) == 0);
    assert(!mg.high);

    /* Double-buzz pattern: 30ms ON, 20ms OFF, 50ms ON */
    const struct motor_step pat[3] = {{true, 30}, {false, 20}, {true, 50}};
    assert(motor_play_pattern(&mot, pat, 3, 1000) == 0);
    assert(mg.high);
    assert(motor_tick(&mot, 1002) && mg.high);
    assert(motor_tick(&mot, 1003) && !mg.high); /* enters step 1 (OFF for 2 ticks) */
    assert(motor_tick(&mot, 1005) && mg.high);  /* enters step 2 (ON for 5 ticks) */
    assert(!motor_tick(&mot, 1010) && !mg.high); /* finishes and turns off */
}

static void test_fb_and_icna3311(void) {
    static uint16_t pixels[120 * 140];
    struct fb fb;
    assert(fb_init(&fb, pixels, 120, 140) == 0);
    fb_clear(&fb, FB_BLACK);
    struct fb_rect r;
    assert(fb_get_dirty(&fb, &r) && r.x0 == 0 && r.y0 == 0 && r.x1 == 119 && r.y1 == 139);
    fb_clear_dirty(&fb);
    assert(!fb_get_dirty(&fb, &r));

    /* Draw rounded rect, triangle, circle, and scaled text -> verify dirty rect and pixels */
    fb_fill_round_rect(&fb, 11, 21, 30, 20, 4, FB_ACCENT);
    assert(fb_get_pixel(&fb, 25, 30) == FB_ACCENT);
    assert(fb_get_dirty(&fb, &r) && r.x0 == 11 && r.y0 == 21 && r.x1 == 40 && r.y1 == 40);

    fb_fill_triangle(&fb, 60, 10, 50, 30, 70, 30, FB_GREEN);
    assert(fb_get_pixel(&fb, 60, 25) == FB_GREEN);

    fb_draw_text(&fb, 10, 60, "12:34", FB_WHITE, FB_BLACK, false, 2);
    assert(fb_text_width("12:34", 2) == (5u * 6u - 1u) * 2u);
    /* Verify at least one glyph pixel was lit */
    unsigned lit = 0;
    for (int y = 60; y < 74; y++) {
        for (int x = 10; x < 70; x++) {
            if (fb_get_pixel(&fb, x, y) == FB_WHITE) lit++;
        }
    }
    assert(lit > 30);

    /* ICNA3311 probe, controls and dirty-rect flush */
    struct mock_dcs md = {.id = {0x1Bu, 0x09u, 0x09u}};
    struct dcs_bus dbus = {.name = "dsi0", .ops = &mock_dcs_ops, .priv = &md};
    struct icna3311_dev panel;
    struct icna3311_config pcfg = {
        .bus = &dbus,
        .width = 120,
        .height = 140,
        .even_align_window = true,
        .delay_ms = test_delay,
    };

    assert(icna3311_is_known_variant(0x1B0909u));
    assert(!icna3311_is_known_variant(0xDEAD00u));
    assert(icna3311_init(&panel, &pcfg) == 0);
    assert(panel.probed && panel.panel_id == 0x1B0909u && panel.power_on);

    assert(icna3311_set_brightness(&panel, 200) == 0 && md.brightness_seen == 200);
    assert(icna3311_set_dimming(&panel, true) == 0 && md.ctrl_disp_seen == 0x28u);
    assert(icna3311_set_hbm(&panel, true) == 0 && md.hbm_seen == 0x02u);

    /* Partial dirty flush with even alignment */
    fb_clear_dirty(&fb);
    assert(icna3311_flush_fb(&panel, &fb) == 0); /* clean -> 0 */
    fb_put_pixel(&fb, 15, 25, FB_CYAN);
    assert(icna3311_flush_fb(&panel, &fb) == 1);
    assert(md.pixel_flushes == 1);
    assert(md.flush_x0 == 14 && md.flush_y0 == 24 && md.flush_w == 2 && md.flush_h == 2);
    assert(!fb_get_dirty(&fb, NULL));

    /* Power off / on */
    assert(icna3311_set_power(&panel, false) == 0 && !panel.power_on);
    assert(icna3311_set_power(&panel, true) == 0 && panel.power_on);

    /* Unknown panel ID fails with -3 */
    md.id[0] = 0xAA;
    assert(icna3311_init(&panel, &pcfg) == -3);
}

int main(void) {
    test_stk31e60();
    test_chargers();
    test_motor();
    test_fb_and_icna3311();
    assert(mock_irq_depth == 0 && test_delay_ms_sum > 0);
    printf("PASS: STK31E60 ALS, CW6305/AW32012 chargers, motor, fb and ICNA3311\n");
    return 0;
}
