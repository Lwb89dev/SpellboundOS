/* Host unit tests for AG3335 GNSS PAIR/NMEA driver and unified watch_app runtime. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"

static int mock_current_task = 0;
static uint64_t mock_ticks = 0;
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
#include "../kernel/rtc.c"
#include "../kernel/input.c"
#include "../kernel/sensor.c"
#include "../kernel/fb.c"
#include "../kernel/notify.c"
#include "../kernel/proto.c"
#include "../kernel/kv.c"
#include "../kernel/activity.c"
#include "../kernel/drivers/icna3311.c"
#include "../kernel/drivers/motor.c"
#include "../kernel/drivers/ag3335.c"
#include "../kernel/power.c"
#include "../kernel/ui.c"
#include "../kernel/watch_app.c"

/* ---- AG3335 mock transport ---- */

struct gnss_tx_cap {
    char last[128];
    uint32_t writes;
};

static int gnss_tx_write(const uint8_t *data, uint32_t len, void *ctx) {
    struct gnss_tx_cap *c = ctx;
    assert(len < sizeof c->last);
    memcpy(c->last, data, len);
    c->last[len] = '\0';
    c->writes++;
    return 0;
}

static void feed_str(struct ag3335_dev *dev, const char *s, int *last_rc) {
    *last_rc = 0;
    for (const char *p = s; *p; p++) {
        int r = ag3335_feed_byte(dev, (uint8_t)*p);
        if (r != 0) *last_rc = r;
    }
}

static void test_ag3335_gnss(void) {
    char buf[64];
    /* Verify exact match against documented PAIR checksums in analysis/MAIN_GNSS_PAIR.md */
    assert(ag3335_format_pair(buf, sizeof buf, "002", NULL) > 0);
    assert(strcmp(buf, "$PAIR002*38\r\n") == 0);
    assert(ag3335_format_pair(buf, sizeof buf, "104", "1") > 0);
    assert(strcmp(buf, "$PAIR104,1*22\r\n") == 0);
    assert(ag3335_format_pair(buf, sizeof buf, "066", "1,1,1,1,0,0") > 0);
    assert(strcmp(buf, "$PAIR066,1,1,1,1,0,0*3A\r\n") == 0);

    struct gnss_tx_cap cap = {0};
    struct ag3335_transport tx = {.write = gnss_tx_write, .ctx = &cap};
    struct ag3335_dev gnss;
    ag3335_init(&gnss, &tx);

    assert(ag3335_power_on(&gnss) == 0 && strcmp(cap.last, "$PAIR002*38\r\n") == 0);
    assert(ag3335_set_dual_band(&gnss, true) == 0 && strcmp(cap.last, "$PAIR104,1*22\r\n") == 0);
    assert(ag3335_set_search_mode(&gnss, true, true, true, true, false, false) == 0);
    assert(strcmp(cap.last, "$PAIR066,1,1,1,1,0,0*3A\r\n") == 0);

    /* Parse PAIR001 ACK */
    int rc = 0;
    const char *ack_body = "PAIR001,066,0";
    char ack_line[64];
    uint8_t cks = ag3335_xor_checksum(ack_body, (uint32_t)strlen(ack_body));
    snprintf(ack_line, sizeof ack_line, "$%s*%02X\r\n", ack_body, cks);
    feed_str(&gnss, ack_line, &rc);
    assert(rc == 1 && gnss.last_ack.received && gnss.last_ack.cmd_code == 66 && gnss.last_ack.result == 0);

    /* Parse $GNRMC (45°28.1234'N, 009°11.4000'E -> ~45.468723, 9.190000, speed 12.5 kn) */
    const char *rmc_body = "GNRMC,100000.00,A,4528.1234,N,00911.4000,E,12.5,90.0,221126,,,A";
    char rmc_line[128];
    cks = ag3335_xor_checksum(rmc_body, (uint32_t)strlen(rmc_body));
    snprintf(rmc_line, sizeof rmc_line, "$%s*%02X\r\n", rmc_body, cks);
    feed_str(&gnss, rmc_line, &rc);
    assert(rc == 1 && gnss.fix.valid);
    assert(gnss.fix.lat_e6 >= 45468720 && gnss.fix.lat_e6 <= 45468726);
    assert(gnss.fix.lon_e6 == 9190000);
    assert(gnss.fix.speed_kx10 == 125);

    /* Parse $GNGGA (11 sats, altitude 122.4 m -> 1224 dm) */
    const char *gga_body = "GNGGA,100000.00,4528.1234,N,00911.4000,E,1,11,0.9,122.4,M,45.0,M,,";
    char gga_line[128];
    cks = ag3335_xor_checksum(gga_body, (uint32_t)strlen(gga_body));
    snprintf(gga_line, sizeof gga_line, "$%s*%02X\r\n", gga_body, cks);
    feed_str(&gnss, gga_line, &rc);
    assert(rc == 1 && gnss.fix.satellites == 11 && gnss.fix.alt_dm == 1224);

    /* Bad checksum rejected */
    feed_str(&gnss, "$PAIR001,002,0*FF\r\n", &rc);
    assert(rc == -1 && gnss.checksum_errors == 1);
}

/* ---- Watch app vertical-slice mocks ---- */

static uint8_t kv_mem[512];
static int wa_kv_r(uint32_t o, uint8_t *b, uint32_t l, void *c) { (void)c; memcpy(b, &kv_mem[o], l); return 0; }
static int wa_kv_w(uint32_t o, const uint8_t *b, uint32_t l, void *c) { (void)c; memcpy(&kv_mem[o], b, l); return 0; }
static int wa_kv_e(void *c) { (void)c; memset(kv_mem, 0xFF, sizeof kv_mem); return 0; }

static bool motor_hi;
static int wa_gpio_cfg(struct gpio_chip *c, uint32_t p, enum gpio_mode m) { (void)c; (void)p; (void)m; return 0; }
static int wa_gpio_w(struct gpio_chip *c, uint32_t p, bool hi) { (void)c; (void)p; motor_hi = hi; return 0; }
static const struct gpio_ops wa_gpio_ops = {.configure = wa_gpio_cfg, .write = wa_gpio_w};

static uint32_t wa_flushes;
static int wa_dcs_w(struct dcs_bus *b, const uint8_t *d, uint32_t l) { (void)b; (void)d; (void)l; return 0; }
static int wa_dcs_r(struct dcs_bus *b, uint8_t c, uint8_t *o, uint32_t l) {
    (void)b; (void)l;
    if (c == DCS_CMD_READ_ID1) { o[0] = 0x1B; return 0; }
    if (c == DCS_CMD_READ_ID2) { o[0] = 0x09; return 0; }
    if (c == DCS_CMD_READ_ID3) { o[0] = 0x09; return 0; }
    return -1;
}
static int wa_dcs_px(struct dcs_bus *b, const uint16_t *p, uint16_t s,
                     uint16_t x0, uint16_t y0, uint16_t w, uint16_t h) {
    (void)b; (void)p; (void)s; (void)x0; (void)y0; (void)w; (void)h;
    wa_flushes++;
    return 0;
}
static const struct dcs_ops wa_dcs_ops = {wa_dcs_w, wa_dcs_r, wa_dcs_px};

struct proto_out_log {
    uint8_t types[16];
    uint32_t count;
};
static int wa_proto_tx(const uint8_t *data, uint32_t len, void *ctx) {
    struct proto_out_log *log = ctx;
    assert(len >= 12 && log->count < 16);
    log->types[log->count++] = data[3];
    return 0;
}

static void test_watch_app_vertical_slice(void) {
    static struct input_event in_q[16];
    static struct sensor_sample sen_q[16];
    static uint16_t fb_mem[160 * 180];
    assert(input_init(in_q, 16) == 0);
    assert(sensor_init(sen_q, 16) == 0);
    notify_reset();

    struct fb fb;
    assert(fb_init(&fb, fb_mem, 160, 180) == 0);
    struct dcs_bus dbus = {.name = "dsi0", .ops = &wa_dcs_ops};
    struct icna3311_dev panel;
    struct icna3311_config pcfg = {.bus = &dbus, .width = 160, .height = 180, .even_align_window = true};
    assert(icna3311_init(&panel, &pcfg) == 0);

    struct gpio_chip gpio = {.name = "gpio0", .pin_count = 100, .ops = &wa_gpio_ops};
    struct motor_dev motor;
    assert(motor_init(&motor, &gpio, 95, 100) == 0);

    wa_kv_e(NULL);
    struct kv_backend kbe = {.capacity = sizeof kv_mem, .read = wa_kv_r, .write = wa_kv_w, .erase = wa_kv_e};
    struct kv_store kv;
    assert(kv_mount(&kv, &kbe) == 0);

    struct proto_out_log tx_log = {0};
    struct watch_app app;
    struct watch_app_config wcfg = {
        .fb = &fb,
        .panel = &panel,
        .motor = &motor,
        .kv = &kv,
        .proto_tx = {.send = wa_proto_tx, .ctx = &tx_log},
        .tick_hz = 100u,
        .telemetry_period_ticks = 500u,
    };
    watch_app_init(&app, &wcfg, 100);

    /* Initial step renders watchface & flushes panel */
    watch_app_step(&app, 100, 1795255200ull);
    assert(wa_flushes == 1 && app.ui.frames_rendered == 1);

    /* Companion sends NOTIFY_POST -> buzzes motor, wakes screen, sends ACK */
    uint8_t np[48];
    uint32_t off = 0;
    uint32_t nid = 50; memcpy(&np[off], &nid, 4); off += 4;
    uint32_t nts = 10; memcpy(&np[off], &nts, 4); off += 4;
    np[off++] = 4; memcpy(&np[off], "Chat", 4); off += 4;
    np[off++] = 3; memcpy(&np[off], "Tom", 3); off += 3;
    np[off++] = 2; memcpy(&np[off], "Hi", 2); off += 2;
    np[off++] = 1; np[off++] = 2; memcpy(&np[off], "OK", 2); off += 2;
    uint8_t wire[128];
    int n = proto_encode(wire, sizeof wire, PROTO_NOTIFY_POST, 1, np, (uint16_t)off);
    assert(watch_app_feed_proto(&app, wire, (uint32_t)n, 120) == 1);
    assert(motor_hi); /* notification buzz started */
    assert(tx_log.count == 1 && tx_log.types[0] == PROTO_ACK);

    /* User clicks to Notifications screen, then double-clicks to trigger action -> sends PROTO_NOTIFY_ACTION */
    struct input_event click = {.timestamp_ticks = 130, .type = INPUT_KEY, .action = INPUT_KEY_SHORT_CLICK, .code = 0};
    struct input_event dbl = {.timestamp_ticks = 140, .type = INPUT_KEY, .action = INPUT_KEY_DOUBLE_CLICK, .code = 0};
    assert(input_post(&click));
    assert(input_post(&dbl));
    watch_app_step(&app, 145, 1795255201ull);
    assert(app.ui.screen == UI_SCREEN_NOTIFICATIONS);
    assert(tx_log.count == 2 && tx_log.types[1] == PROTO_NOTIFY_ACTION);

    /* Feed ALS + Battery + 4 walking steps via sensor queue */
    struct sensor_sample als = {.timestamp_ticks = 150, .type = SENSOR_ALS, .x = 3000};
    struct sensor_sample bat = {.timestamp_ticks = 150, .type = SENSOR_BATTERY, .x = 64, .y = 1};
    assert(sensor_post(&als) && sensor_post(&bat));
    for (uint64_t i = 0; i < 4; i++) {
        struct sensor_sample hi = {.timestamp_ticks = 200u + i * 50u, .type = SENSOR_ACCEL, .sensitivity = 4096u, .z = 5600};
        struct sensor_sample lo = {.timestamp_ticks = 210u + i * 50u, .type = SENSOR_ACCEL, .sensitivity = 4096u, .z = 4096};
        assert(sensor_post(&hi) && sensor_post(&lo));
    }
    watch_app_step(&app, 610, 1795255206ull); /* crosses 500-tick telemetry period! */
    assert(app.power.battery_pct == 64 && app.power.charging);
    assert(activity_steps(&app.activity) == 4u && app.ui.steps == 4u);
    assert(app.telemetry_sent == 1 && tx_log.types[tx_log.count - 1u] == PROTO_TELEMETRY);

    /* Persist settings to KV and verify reload on fresh watch_app_init */
    app.power.dnd_enabled = true;
    ui_set_timezone(&app.ui, 120);
    assert(watch_app_save_settings(&app) == 0);

    struct watch_app app2;
    watch_app_init(&app2, &wcfg, 700);
    assert(app2.power.dnd_enabled && app2.ui.tz_offset_min == 120);
}

int main(void) {
    test_ag3335_gnss();
    test_watch_app_vertical_slice();
    assert(mock_irq_depth == 0);
    printf("PASS: AG3335 GNSS PAIR/NMEA and unified watch_app runtime\n");
    return 0;
}
