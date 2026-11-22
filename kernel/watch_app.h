/* Unified SpellboundOS watch runtime orchestrator.
 * Connects input, sensors/activity, companion proto, KV settings, power, haptics and UI. */
#ifndef SPELLBOUND_WATCH_APP_H
#define SPELLBOUND_WATCH_APP_H

#include <stdbool.h>
#include <stdint.h>
#include "activity.h"
#include "fb.h"
#include "kv.h"
#include "power.h"
#include "proto.h"
#include "ui.h"
#include "drivers/icna3311.h"
#include "drivers/motor.h"

struct watch_app_config {
    struct fb *fb;
    struct icna3311_dev *panel; /* optional */
    struct motor_dev *motor;    /* optional */
    struct kv_store *kv;        /* optional persistent settings */
    struct proto_tx proto_tx;   /* optional companion link TX */
    uint32_t tick_hz;
    uint32_t telemetry_period_ticks; /* 0 disables periodic telemetry */
};

struct watch_app {
    struct watch_app_config cfg;
    struct power_state power;
    struct ui_state ui;
    struct activity_state activity;
    struct proto_decoder proto_dec;
    uint16_t tx_seq;
    int64_t clock_offset_sec; /* delta added to RTC/monotonic time after TIME_SYNC */
    uint64_t last_telemetry_ticks;
    uint32_t proto_frames_handled;
    uint32_t telemetry_sent;
};

void watch_app_init(struct watch_app *app, const struct watch_app_config *cfg, uint64_t now_ticks);

/* Persist current power/timezone settings into kv (if bound). */
int watch_app_save_settings(struct watch_app *app);

/* Feed companion link bytes (BLE/UART) into protocol decoder and dispatch. */
uint32_t watch_app_feed_proto(struct watch_app *app, const uint8_t *data, uint32_t len,
                              uint64_t now_ticks);

/* Run one periodic watch service tick: drains input + sensor queues, updates
 * power/motor/UI, flushes dirty framebuffer to panel and emits telemetry. */
void watch_app_step(struct watch_app *app, uint64_t now_ticks, uint64_t rtc_unix_sec);

#endif /* SPELLBOUND_WATCH_APP_H */
