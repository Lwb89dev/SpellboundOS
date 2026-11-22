/* Host unit tests for notify/nav/call services, SpellboundFit proto and interactive shell. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"

static int mock_current_task = 0;
static uint64_t mock_ticks = 1234;
static unsigned mock_irq_depth = 0;
static uint32_t mock_poweroff_calls = 0;
static uint32_t mock_reboot_calls = 0;

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
static void board_poweroff(void) { mock_poweroff_calls++; }
static void board_reboot(void) { mock_reboot_calls++; }
int task_current(void) { return mock_current_task; }
void task_event_signal(struct task_event *event) { event->pending = true; }
void task_event_wait(struct task_event *event) { event->pending = false; }
bool task_event_wait_for(struct task_event *event, uint32_t ticks) {
    if (event->pending) { event->pending = false; return true; }
    mock_ticks += ticks;
    return false;
}

#include "../kernel/driver.c"
#include "../kernel/kmem.c"
#include "../kernel/rtc.c"
#include "../kernel/sync.c"
#include "../kernel/input.c"
#include "../kernel/sensor.c"
#include "../kernel/notify.c"
#include "../kernel/proto.c"
#include "../kernel/shell.c"

/* ---- Action callback capture ---- */

static uint32_t last_action_id;
static uint8_t last_action_idx;
static char last_action_label[NOTIFY_ACTION_MAX];
static uint32_t action_count_seen;

static void on_notify_action(uint32_t id, uint8_t idx, const char *label, void *ctx) {
    (void)ctx;
    last_action_id = id;
    last_action_idx = idx;
    strncpy(last_action_label, label, sizeof last_action_label - 1u);
    last_action_label[sizeof last_action_label - 1u] = '\0';
    action_count_seen++;
}

/* ---- Proto TX capture ---- */

struct tx_capture {
    uint8_t buf[PROTO_MAX_FRAME];
    uint32_t len;
    uint32_t calls;
};

static int capture_tx_send(const uint8_t *data, uint32_t len, void *ctx) {
    struct tx_capture *cap = ctx;
    assert(len <= sizeof cap->buf);
    memcpy(cap->buf, data, len);
    cap->len = len;
    cap->calls++;
    return 0;
}

/* ---- Shell output capture ---- */

struct out_capture {
    char buf[2048];
    uint32_t len;
};

static void capture_puts(const char *s, void *ctx) {
    struct out_capture *o = ctx;
    size_t slen = strlen(s);
    assert(o->len + slen + 1u < sizeof o->buf);
    memcpy(&o->buf[o->len], s, slen);
    o->len += (uint32_t)slen;
    o->buf[o->len] = '\0';
}

static int custom_ping_cmd(int argc, char **argv, const struct shell_io *io) {
    (void)argc; (void)argv;
    io->puts("pong!\n", io->ctx);
    return 0;
}

/* ---- Tests ---- */

static void test_notify_nav_call(void) {
    notify_reset();
    notify_set_action_cb(on_notify_action, NULL);

    /* Reject id=0 */
    struct notification bad = {.id = 0};
    assert(notify_post(&bad) == -1);

    /* Post 20 notifications -> newest 16 retained, index 0 is #20 */
    for (uint32_t i = 1; i <= 20; i++) {
        struct notification n = {
            .id = i,
            .timestamp_sec = 1700000000u + i,
            .unread = true,
            .action_count = 2,
        };
        snprintf(n.app, sizeof n.app, "App%u", i);
        snprintf(n.title, sizeof n.title, "Title %u", i);
        snprintf(n.body, sizeof n.body, "Body %u", i);
        strcpy(n.actions[0], "Reply");
        strcpy(n.actions[1], "Mute");
        assert(notify_post(&n) == 0);
    }
    assert(notify_count() == NOTIFY_MAX_ITEMS);
    assert(notify_unread_count() == NOTIFY_MAX_ITEMS);

    struct notification top;
    assert(notify_get_at(0, &top) && top.id == 20);
    assert(!notify_find(1, &top)); /* evicted */
    assert(notify_find(5, &top) && top.id == 5);

    /* Trigger action marks read and invokes callback */
    assert(notify_trigger_action(20, 1));
    assert(action_count_seen == 1 && last_action_id == 20 && last_action_idx == 1);
    assert(strcmp(last_action_label, "Mute") == 0);
    assert(notify_unread_count() == NOTIFY_MAX_ITEMS - 1u);
    assert(!notify_trigger_action(20, 2)); /* out of range */

    /* Update existing ID moves it to index 0 */
    struct notification upd = {.id = 10, .unread = true, .app = "Chat", .title = "Updated", .body = "Hi"};
    assert(notify_post(&upd) == 0);
    assert(notify_count() == NOTIFY_MAX_ITEMS);
    assert(notify_get_at(0, &top) && top.id == 10 && strcmp(top.title, "Updated") == 0);

    assert(notify_dismiss(10));
    assert(notify_count() == NOTIFY_MAX_ITEMS - 1u);
    assert(!notify_dismiss(10));

    /* Navigation & call state */
    struct nav_state nav = {
        .active = true,
        .maneuver = NAV_ROUNDABOUT,
        .roundabout_exit = 2,
        .distance_m = 350,
        .eta_min = 12,
        .street = "Via Emilia",
        .next_street = "Corso Italia",
    };
    nav_update(&nav);
    struct nav_state nav_out;
    assert(nav_get(&nav_out) && nav_out.active && nav_out.maneuver == NAV_ROUNDABOUT);
    assert(nav_out.roundabout_exit == 2 && nav_out.distance_m == 350 && nav_out.revision == 1);
    assert(strcmp(nav_maneuver_name(NAV_ROUNDABOUT), "ROUNDABOUT") == 0);
    nav_clear();
    assert(!nav_get(&nav_out) && nav_out.revision == 2);

    struct call_info ci = {.state = CALL_RINGING, .caller = "Alice", .number = "+39000"};
    call_update(&ci);
    struct call_info ci_out;
    assert(call_get(&ci_out) && ci_out.state == CALL_RINGING && strcmp(ci_out.caller, "Alice") == 0);
}

static void feed_bytes(struct proto_decoder *dec, const uint8_t *buf, int len,
                       struct proto_frame *out, int *last_rc) {
    *last_rc = 0;
    for (int i = 0; i < len; i++) {
        *last_rc = proto_decoder_feed(dec, buf[i], out);
    }
}

static void test_proto(void) {
    /* Standard IEEE CRC-32 check value: "123456789" == 0xCBF43926 */
    const uint8_t check[9] = {'1','2','3','4','5','6','7','8','9'};
    assert(proto_crc32(check, 9) == 0xCBF43926u);

    notify_reset();
    struct proto_decoder dec;
    proto_decoder_init(&dec);
    struct proto_frame frame;
    struct tx_capture cap = {0};
    struct proto_tx tx = {.send = capture_tx_send, .ctx = &cap};

    /* Noise prefix + PING -> PONG */
    uint8_t wire[PROTO_MAX_FRAME];
    int n = proto_encode(wire, sizeof wire, PROTO_PING, 0x1234u, NULL, 0);
    assert(n == 12);
    assert(proto_decoder_feed(&dec, 0xFF, &frame) == 0);
    assert(proto_decoder_feed(&dec, PROTO_MAGIC_0, &frame) == 0);
    assert(proto_decoder_feed(&dec, 0x00, &frame) == 0);
    int rc = 0;
    feed_bytes(&dec, wire, n, &frame, &rc);
    assert(rc == 1 && frame.type == PROTO_PING && frame.seq == 0x1234u && frame.len == 0);
    assert(proto_dispatch(&frame, &tx, NULL, NULL) == 0);
    assert(cap.calls == 1 && cap.buf[3] == PROTO_PONG);

    /* Corrupt a byte -> CRC error, then next valid frame recovers */
    wire[5] ^= 0x01u;
    feed_bytes(&dec, wire, n, &frame, &rc);
    assert(rc == -1 && dec.crc_errors == 1);

    /* TIME_SYNC */
    uint8_t ts_payload[10] = {0};
    uint64_t tsec = 1795255200ull; /* 2026-11-22 */
    for (int i = 0; i < 8; i++) ts_payload[i] = (uint8_t)((tsec >> (8 * i)) & 0xFFu);
    int16_t tz = 60;
    ts_payload[8] = (uint8_t)((uint16_t)tz & 0xFFu);
    ts_payload[9] = (uint8_t)((uint16_t)tz >> 8);
    n = proto_encode(wire, sizeof wire, PROTO_TIME_SYNC, 2, ts_payload, 10);
    feed_bytes(&dec, wire, n, &frame, &rc);
    assert(rc == 1);
    int64_t synced_sec = 0; int16_t synced_tz = 0;
    assert(proto_dispatch(&frame, &tx, &synced_sec, &synced_tz) == 0);
    assert(synced_sec == (int64_t)tsec && synced_tz == 60);
    assert(cap.buf[3] == PROTO_ACK);

    /* NOTIFY_POST with 1 action */
    uint8_t np[64];
    uint32_t off = 0;
    uint32_t nid = 77;
    memcpy(&np[off], &nid, 4); off += 4;
    uint32_t nts = 1000;
    memcpy(&np[off], &nts, 4); off += 4;
    np[off++] = 4; memcpy(&np[off], "Mail", 4); off += 4;
    np[off++] = 5; memcpy(&np[off], "Hello", 5); off += 5;
    np[off++] = 4; memcpy(&np[off], "Body", 4); off += 4;
    np[off++] = 1; /* 1 action */
    np[off++] = 7; memcpy(&np[off], "Archive", 7); off += 7;
    n = proto_encode(wire, sizeof wire, PROTO_NOTIFY_POST, 3, np, (uint16_t)off);
    feed_bytes(&dec, wire, n, &frame, &rc);
    assert(rc == 1 && proto_dispatch(&frame, &tx, NULL, NULL) == 0);
    struct notification got_n;
    assert(notify_find(77, &got_n) && strcmp(got_n.app, "Mail") == 0 &&
           got_n.action_count == 1 && strcmp(got_n.actions[0], "Archive") == 0);

    /* NAV_UPDATE */
    uint8_t nv[64];
    off = 0;
    nv[off++] = NAV_RIGHT;
    nv[off++] = 0;
    uint32_t dist = 420; memcpy(&nv[off], &dist, 4); off += 4;
    uint16_t eta = 7;    memcpy(&nv[off], &eta, 2);  off += 2;
    nv[off++] = 7; memcpy(&nv[off], "SP 1234", 7); off += 7;
    nv[off++] = 4; memcpy(&nv[off], "SS 9", 4); off += 4;
    n = proto_encode(wire, sizeof wire, PROTO_NAV_UPDATE, 4, nv, (uint16_t)off);
    feed_bytes(&dec, wire, n, &frame, &rc);
    assert(rc == 1 && proto_dispatch(&frame, &tx, NULL, NULL) == 0);
    struct nav_state got_nav;
    assert(nav_get(&got_nav) && got_nav.maneuver == NAV_RIGHT &&
           got_nav.distance_m == 420 && strcmp(got_nav.street, "SP 1234") == 0);

    /* Watch -> phone encoders round-trip */
    n = proto_encode_notify_action(wire, sizeof wire, 5, 77, 0);
    feed_bytes(&dec, wire, n, &frame, &rc);
    assert(rc == 1 && frame.type == PROTO_NOTIFY_ACTION && frame.len == 5);

    n = proto_encode_telemetry(wire, sizeof wire, 6, 87, true, 5432, 72, 999);
    feed_bytes(&dec, wire, n, &frame, &rc);
    assert(rc == 1 && frame.type == PROTO_TELEMETRY && frame.len == 12 &&
           frame.payload[0] == 87 && frame.payload[1] == 1);
}

static uint64_t mock_rtc_ns(uintptr_t ctx) {
    (void)ctx;
    return 1700000000ull * 1000000000ull;
}

static void test_shell(void) {
    static uint8_t heap[4096];
    kmem_init(heap, sizeof heap);
    notify_reset();
    static const struct rtc_ops rops = {.read_ns = mock_rtc_ns};
    assert(rtc_bind(&rops, 0) == 0);

    struct out_capture out = {0};
    struct shell_io io = {.puts = capture_puts, .ctx = &out};
    struct shell_state sh;
    shell_init(&sh, &io, true);

    static const struct shell_cmd extra = {"ping", "reply pong", custom_ping_cmd};
    assert(shell_register_cmd(&sh, &extra) == 0);

    assert(shell_exec_line(&sh, "help") == 0 && strstr(out.buf, "notify") && strstr(out.buf, "ping"));
    out.len = 0; out.buf[0] = '\0';
    assert(shell_exec_line(&sh, "date") == 0 && strstr(out.buf, "2023-11-14 22:13:20 UTC"));
    assert(shell_exec_line(&sh, "uptime") == 0 && strstr(out.buf, "1234"));
    assert(shell_exec_line(&sh, "heap") == 0 && strstr(out.buf, "heap: free"));
    assert(shell_exec_line(&sh, "notify add 5 Signal \"Bob\" \"On my way\"") == 0);
    assert(notify_count() == 1);
    assert(shell_exec_line(&sh, "notify list") == 0 && strstr(out.buf, "On my way"));
    assert(shell_exec_line(&sh, "nav set 3 150 4 \"Via Garibaldi\"") == 0);
    assert(shell_exec_line(&sh, "nav status") == 0 && strstr(out.buf, "TURN LEFT") && strstr(out.buf, "Via Garibaldi"));

    /* Interactive char-by-char line editing with backspace */
    out.len = 0; out.buf[0] = '\0';
    const char *typed = "pinx\bg\n";
    for (const char *p = typed; *p; p++) {
        shell_feed_char(&sh, *p);
    }
    assert(strstr(out.buf, "pong!") != NULL);

    /* Poweroff & reboot hooks */
    assert(shell_exec_line(&sh, "poweroff") == 0 && mock_poweroff_calls == 1);
    assert(shell_exec_line(&sh, "reboot") == 0 && mock_reboot_calls == 1);
    assert(shell_exec_line(&sh, "nonexistent") == -1);
}

int main(void) {
    test_notify_nav_call();
    test_proto();
    test_shell();
    assert(mock_irq_depth == 0);
    printf("PASS: notify/nav/call, SpellboundFit proto and shell\n");
    return 0;
}
