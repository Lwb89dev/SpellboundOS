/* Host desktop simulator C shim wrapping the real SpellboundOS C kernel stack
 * at Bip 6's native 390x450 RGB565 resolution for ctypes / Python companion driving. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "sched.h"
#include "boards/bip6/board_desc.h"

/* Minimal single-threaded host scheduler/IRQ/board stubs. */
static int sim_task_id = 0;
static uint64_t sim_ticks = 0;
static uint32_t sim_poweroff_count = 0;
static uint32_t sim_reboot_count = 0;

static inline uint32_t irq_save(void) { return 0; }
static inline void irq_restore(uint32_t previous) { (void)previous; }
static uint64_t timer_ticks(void) { return sim_ticks; }
static void board_poweroff(void) { sim_poweroff_count++; }
static void board_reboot(void) { sim_reboot_count++; }
int task_current(void) { return sim_task_id; }
void task_event_signal(struct task_event *event) { event->pending = true; }
void task_event_wait(struct task_event *event) { event->pending = false; }
bool task_event_wait_for(struct task_event *event, uint32_t ticks) {
    if (event->pending) { event->pending = false; return true; }
    sim_ticks += ticks;
    return false;
}

#include "driver.c"
#include "kmem.c"
#include "rtc.c"
#include "bus.c"
#include "sync.c"
#include "input.c"
#include "sensor.c"
#include "fb.c"
#include "notify.c"
#include "proto.c"
#include "kv.c"
#include "activity.c"
#include "hr.c"
#include "crypto.c"
#include "secure_link.c"
#include "drivers/icna3311.c"
#include "drivers/motor.c"
#include "power.c"
#include "ui.c"
#include "shell.c"
#include "watch_app.c"

/* ---- Simulator Backing State ---- */

#define SIM_W BIP6_DISPLAY_WIDTH
#define SIM_H BIP6_DISPLAY_HEIGHT

static uint16_t sim_pixels[SIM_W * SIM_H];
static uint8_t sim_heap[32 * 1024];
static uint8_t sim_kv_mem[2048];
static struct input_event sim_in_q[32];
static struct sensor_sample sim_sen_q[64];

static struct fb sim_fb;
static struct icna3311_dev sim_panel;
static struct motor_dev sim_motor;
static struct kv_store sim_kv;
static struct watch_app sim_app;
static struct secure_session sim_sec;
static struct hr_state sim_hr;
static struct shell_state sim_shell;

static uint64_t sim_rtc_sec = 1795255200ull; /* 2026-11-22 10:00:00 UTC */
static bool sim_motor_pin = false;
static uint32_t sim_panel_flushes = 0;

/* Outbound encrypted/plain packet queue to Python companion */
#define SIM_OUT_CAP 32u
#define SIM_PKT_MAX 512u
static uint8_t sim_out_pkts[SIM_OUT_CAP][SIM_PKT_MAX];
static uint32_t sim_out_lens[SIM_OUT_CAP];
static uint32_t sim_out_head, sim_out_tail, sim_out_count;

static char sim_shell_out[2048];
static uint32_t sim_shell_out_len;

static void sim_push_out_pkt(const uint8_t *data, uint32_t len) {
    if (sim_out_count >= SIM_OUT_CAP || len > SIM_PKT_MAX) return;
    memcpy(sim_out_pkts[sim_out_tail], data, len);
    sim_out_lens[sim_out_tail] = len;
    sim_out_tail = (sim_out_tail + 1u) % SIM_OUT_CAP;
    sim_out_count++;
}

static int sim_proto_send(const uint8_t *data, uint32_t len, void *ctx) {
    (void)ctx;
    if (sim_sec.established) {
        uint8_t enc[SIM_PKT_MAX];
        int n = secure_encrypt(&sim_sec, data, len, enc, sizeof enc);
        if (n <= 0) return -1;
        sim_push_out_pkt(enc, (uint32_t)n);
    } else {
        sim_push_out_pkt(data, len);
    }
    return 0;
}

static uint64_t sim_rtc_read_ns(uintptr_t ctx) {
    (void)ctx;
    return sim_rtc_sec * 1000000000ull;
}

static int sim_kv_r(uint32_t o, uint8_t *b, uint32_t l, void *c) {
    (void)c; memcpy(b, &sim_kv_mem[o], l); return 0;
}
static int sim_kv_w(uint32_t o, const uint8_t *b, uint32_t l, void *c) {
    (void)c; memcpy(&sim_kv_mem[o], b, l); return 0;
}
static int sim_kv_e(void *c) {
    (void)c; memset(sim_kv_mem, 0xFF, sizeof sim_kv_mem); return 0;
}

static int sim_gpio_cfg(struct gpio_chip *c, uint32_t p, enum gpio_mode m) {
    (void)c; (void)p; (void)m; return 0;
}
static int sim_gpio_w(struct gpio_chip *c, uint32_t p, bool hi) {
    (void)c; (void)p; sim_motor_pin = hi; return 0;
}
static const struct gpio_ops sim_gpio_ops = {.configure = sim_gpio_cfg, .write = sim_gpio_w};
static struct gpio_chip sim_gpio = {.name = "sim_gpio", .pin_count = 128, .ops = &sim_gpio_ops};

static int sim_dcs_w(struct dcs_bus *b, const uint8_t *d, uint32_t l) { (void)b; (void)d; (void)l; return 0; }
static int sim_dcs_r(struct dcs_bus *b, uint8_t c, uint8_t *o, uint32_t l) {
    (void)b; if (l != 1) return -1;
    if (c == DCS_CMD_READ_ID1) { o[0] = 0x1B; return 0; }
    if (c == DCS_CMD_READ_ID2) { o[0] = 0x09; return 0; }
    if (c == DCS_CMD_READ_ID3) { o[0] = 0x09; return 0; }
    return -1;
}
static int sim_dcs_px(struct dcs_bus *b, const uint16_t *p, uint16_t s,
                      uint16_t x0, uint16_t y0, uint16_t w, uint16_t h) {
    (void)b; (void)p; (void)s; (void)x0; (void)y0; (void)w; (void)h;
    sim_panel_flushes++;
    return 0;
}
static const struct dcs_ops sim_dcs_ops = {sim_dcs_w, sim_dcs_r, sim_dcs_px};
static struct dcs_bus sim_dcs = {.name = "sim_dsi", .ops = &sim_dcs_ops};

static void sim_shell_puts(const char *s, void *ctx) {
    (void)ctx;
    while (*s && sim_shell_out_len + 1u < sizeof sim_shell_out) {
        sim_shell_out[sim_shell_out_len++] = *s++;
    }
    sim_shell_out[sim_shell_out_len] = '\0';
}

/* ---- Exported ctypes API ---- */

int sim_init(const uint8_t psk[32], uint64_t start_unix_sec) {
    sim_ticks = 0;
    sim_rtc_sec = start_unix_sec > 0 ? start_unix_sec : 1795255200ull;
    sim_motor_pin = false;
    sim_panel_flushes = 0;
    sim_out_head = sim_out_tail = sim_out_count = 0;

    kmem_init(sim_heap, sizeof sim_heap);
    static const struct rtc_ops rops = {.read_ns = sim_rtc_read_ns};
    if (!rtc_is_bound()) {
        (void)rtc_bind(&rops, 0);
    }
    (void)input_init(sim_in_q, 32);
    (void)sensor_init(sim_sen_q, 64);
    notify_reset();
    (void)fb_init(&sim_fb, sim_pixels, SIM_W, SIM_H);

    struct icna3311_config pcfg = {
        .bus = &sim_dcs, .width = SIM_W, .height = SIM_H, .even_align_window = true,
    };
    if (icna3311_init(&sim_panel, &pcfg) != 0) return -1;
    if (motor_init(&sim_motor, &sim_gpio, BIP6_MOTOR_GPIO, 100u) != 0) return -2;

    sim_kv_e(NULL);
    struct kv_backend kbe = {
        .capacity = sizeof sim_kv_mem, .read = sim_kv_r, .write = sim_kv_w, .erase = sim_kv_e,
    };
    if (kv_mount(&sim_kv, &kbe) != 0) return -3;

    secure_session_init(&sim_sec, SECURE_ROLE_WATCH, psk);
    struct hr_config hrcfg = {.sample_rate_hz = 50u, .min_ac_amplitude = 250, .publish_sensor = true};
    hr_init(&sim_hr, &hrcfg);

    struct watch_app_config wcfg = {
        .fb = &sim_fb,
        .panel = &sim_panel,
        .motor = &sim_motor,
        .kv = &sim_kv,
        .proto_tx = {.send = sim_proto_send},
        .tick_hz = 100u,
        .telemetry_period_ticks = 500u,
    };
    watch_app_init(&sim_app, &wcfg, sim_ticks);

    struct shell_io shio = {.puts = sim_shell_puts};
    shell_init(&sim_shell, &shio, false);
    watch_app_step(&sim_app, sim_ticks, sim_rtc_sec);
    return 0;
}

int sim_width(void) { return (int)SIM_W; }
int sim_height(void) { return (int)SIM_H; }

int sim_handle_secure_hello(const uint8_t *hello, uint32_t hello_len,
                            const uint8_t watch_nonce[16], uint8_t *ack_out) {
    return secure_watch_accept_hello(&sim_sec, hello, hello_len, watch_nonce, ack_out);
}

int sim_feed_packet(const uint8_t *pkt, uint32_t len) {
    if (sim_sec.established) {
        uint8_t pt[SIM_PKT_MAX];
        int n = secure_decrypt(&sim_sec, pkt, len, pt, sizeof pt);
        if (n < 0) return n;
        return (int)watch_app_feed_proto(&sim_app, pt, (uint32_t)n, sim_ticks);
    }
    return (int)watch_app_feed_proto(&sim_app, pkt, len, sim_ticks);
}

int sim_pop_out_packet(uint8_t *out, uint32_t cap) {
    if (sim_out_count == 0) return 0;
    uint32_t len = sim_out_lens[sim_out_head];
    if (len > cap) return -1;
    memcpy(out, sim_out_pkts[sim_out_head], len);
    sim_out_head = (sim_out_head + 1u) % SIM_OUT_CAP;
    sim_out_count--;
    return (int)len;
}

void sim_inject_key(uint8_t action, uint16_t code) {
    struct input_event ev = {
        .timestamp_ticks = sim_ticks, .type = INPUT_KEY, .action = action, .code = code,
    };
    (void)input_post(&ev);
}

void sim_inject_touch(uint8_t action, int16_t x, int16_t y) {
    struct input_event ev = {
        .timestamp_ticks = sim_ticks, .type = INPUT_TOUCH, .action = action, .x = x, .y = y,
    };
    (void)input_post(&ev);
}

void sim_inject_accel(int16_t x, int16_t y, int16_t z) {
    struct sensor_sample s = {
        .timestamp_ticks = sim_ticks, .type = SENSOR_ACCEL, .sensitivity = 4096u,
        .x = x, .y = y, .z = z,
    };
    (void)sensor_post(&s);
}

void sim_inject_als(uint32_t lux) {
    struct sensor_sample s = {.timestamp_ticks = sim_ticks, .type = SENSOR_ALS, .x = (int32_t)lux};
    (void)sensor_post(&s);
}

void sim_inject_battery(uint8_t pct, bool charging) {
    struct sensor_sample s = {
        .timestamp_ticks = sim_ticks, .type = SENSOR_BATTERY, .x = pct, .y = charging ? 1 : 0,
    };
    (void)sensor_post(&s);
}

void sim_inject_hr(uint16_t bpm) {
    struct sensor_sample s = {.timestamp_ticks = sim_ticks, .type = SENSOR_HEART_RATE, .x = bpm};
    (void)sensor_post(&s);
}

void sim_set_screen(uint8_t screen) {
    ui_set_screen(&sim_app.ui, (enum ui_screen)screen);
}

void sim_set_aod(bool enable) {
    sim_app.power.cfg.aod_enabled = enable;
    if (enable) {
        (void)power_sleep(&sim_app.power);
        sim_app.ui.needs_redraw = true;
    } else {
        (void)power_wake(&sim_app.power, sim_ticks);
        sim_app.ui.needs_redraw = true;
    }
}

void sim_step(uint32_t delta_ticks) {
    sim_ticks += delta_ticks;
    sim_rtc_sec += delta_ticks / 100u;
    watch_app_step(&sim_app, sim_ticks, sim_rtc_sec);
}

void sim_get_rgb888(uint8_t *rgb_out) {
    for (uint32_t i = 0; i < (uint32_t)SIM_W * (uint32_t)SIM_H; i++) {
        uint16_t px = sim_pixels[i];
        uint8_t r = (uint8_t)((px >> 11) & 0x1Fu);
        uint8_t g = (uint8_t)((px >> 5) & 0x3Fu);
        uint8_t b = (uint8_t)(px & 0x1Fu);
        rgb_out[i * 3u + 0u] = (uint8_t)((r << 3) | (r >> 2));
        rgb_out[i * 3u + 1u] = (uint8_t)((g << 2) | (g >> 4));
        rgb_out[i * 3u + 2u] = (uint8_t)((b << 3) | (b >> 2));
    }
}

const char *sim_shell_exec(const char *cmd) {
    sim_shell_out_len = 0;
    sim_shell_out[0] = '\0';
    (void)shell_exec_line(&sim_shell, cmd);
    return sim_shell_out;
}

uint8_t sim_current_screen(void) { return (uint8_t)sim_app.ui.screen; }
uint8_t sim_brightness(void) { return sim_panel.brightness; }
uint32_t sim_steps(void) { return activity_steps(&sim_app.activity); }
uint32_t sim_flushes(void) { return sim_panel_flushes; }
bool sim_motor_active(void) { return sim_motor_pin; }
uint32_t sim_poweroff_count_get(void) { return sim_poweroff_count; }
uint32_t sim_reboot_count_get(void) { return sim_reboot_count; }
