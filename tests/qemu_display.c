/* Runtime check for framebuffer, ICNA3311 panel, motor, ALS and charger on RV32 QEMU virt. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../kernel/board.h"
#include "../kernel/bus.h"
#include "../kernel/console.h"
#include "../kernel/fb.h"
#include "../kernel/sched.h"
#include "../kernel/sensor.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/drivers/charger.h"
#include "../kernel/drivers/icna3311.h"
#include "../kernel/drivers/motor.h"
#include "../kernel/drivers/stk31e60.h"

static uint16_t fb_mem[64 * 64];
static uint32_t flushed_pixels;
static bool motor_pin_state;

static int virt_dcs_w(struct dcs_bus *b, const uint8_t *d, uint32_t l) { (void)b; (void)d; (void)l; return 0; }
static int virt_dcs_r(struct dcs_bus *b, uint8_t cmd, uint8_t *out, uint32_t l) {
    (void)b; if (l != 1) return -1;
    if (cmd == DCS_CMD_READ_ID1) { out[0] = 0x1B; return 0; }
    if (cmd == DCS_CMD_READ_ID2) { out[0] = 0x09; return 0; }
    if (cmd == DCS_CMD_READ_ID3) { out[0] = 0x09; return 0; }
    return -1;
}
static int virt_dcs_px(struct dcs_bus *b, const uint16_t *p, uint16_t s,
                       uint16_t x0, uint16_t y0, uint16_t w, uint16_t h) {
    (void)b; (void)p; (void)s; (void)x0; (void)y0;
    flushed_pixels += (uint32_t)w * (uint32_t)h;
    return 0;
}
static const struct dcs_ops virt_dcs_ops = {virt_dcs_w, virt_dcs_r, virt_dcs_px};
static struct dcs_bus virt_dcs = {.name = "virt_dsi", .ops = &virt_dcs_ops};

static int virt_gpio_cfg(struct gpio_chip *c, uint32_t p, enum gpio_mode m) { (void)c; (void)p; (void)m; return 0; }
static int virt_gpio_w(struct gpio_chip *c, uint32_t p, bool hi) { (void)c; (void)p; motor_pin_state = hi; return 0; }
static const struct gpio_ops virt_gpio_ops = {.configure = virt_gpio_cfg, .write = virt_gpio_w};
static struct gpio_chip virt_gpio = {.name = "virt_gpio", .pin_count = 100, .ops = &virt_gpio_ops};

void kernel_main(void) {
    unsigned failures = 0;
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);

    struct fb fb;
    if (fb_init(&fb, fb_mem, 64, 64) != 0) failures++;
    fb_clear(&fb, FB_BLACK);
    fb_draw_text(&fb, 4, 8, "SBOS", FB_CYAN, FB_BLACK, false, 2);

    struct icna3311_dev panel;
    struct icna3311_config pcfg = {.bus = &virt_dcs, .width = 64, .height = 64, .even_align_window = true};
    if (icna3311_init(&panel, &pcfg) != 0 || icna3311_flush_fb(&panel, &fb) != 1 || flushed_pixels != 4096u) {
        failures++;
    }

    struct motor_dev mot;
    if (motor_init(&mot, &virt_gpio, 95, 100) != 0 || motor_pulse(&mot, 1, timer_ticks()) != 0 || !motor_pin_state) {
        failures++;
    }
    if (motor_tick(&mot, timer_ticks() + 10) || motor_pin_state) {
        failures++;
    }
    if (cw6305_encode_current_ma(470) != 63 || stk31e60_encode_it(166) != 0x00A6u) {
        failures++;
    }

    console_puts(failures ? "FAIL: peripherals and display\n" :
                            "PASS: peripherals and display\n");
    board_poweroff();
}
