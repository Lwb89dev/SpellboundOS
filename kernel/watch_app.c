/* Unified SpellboundOS watch runtime orchestrator. */
#include "watch_app.h"
#include "input.h"
#include "notify.h"
#include "sensor.h"
#include <stddef.h>

static const struct motor_step notif_buzz[3] = {
    {true, 50u}, {false, 40u}, {true, 80u},
};

static const struct motor_step call_buzz[4] = {
    {true, 130u}, {false, 80u}, {true, 130u}, {false, 80u},
};

static void on_ui_notify_action(uint32_t notif_id, uint8_t action_index,
                                const char *label, void *ctx) {
    (void)label;
    struct watch_app *app = ctx;
    if (!app || !app->cfg.proto_tx.send) return;
    uint8_t wire[32];
    int n = proto_encode_notify_action(wire, sizeof wire, ++app->tx_seq,
                                       notif_id, action_index);
    if (n > 0) {
        (void)app->cfg.proto_tx.send(wire, (uint32_t)n, app->cfg.proto_tx.ctx);
    }
}

static void load_settings_from_kv(struct watch_app *app) {
    struct kv_store *kv = app->cfg.kv;
    if (!kv || !kv->mounted) return;
    uint32_t v = 0;
    if (kv_get_u32(kv, "auto_brt", &v)) (void)power_set_auto_brightness(&app->power, v != 0);
    if (kv_get_u32(kv, "manual_brt", &v)) (void)power_set_manual_brightness(&app->power, (uint8_t)v);
    if (kv_get_u32(kv, "dnd", &v)) app->power.dnd_enabled = (v != 0);
    if (kv_get_u32(kv, "haptics", &v)) app->power.haptics_enabled = (v != 0);
    if (kv_get_u32(kv, "aod", &v)) app->power.cfg.aod_enabled = (v != 0);
    if (kv_get_u32(kv, "tz_min", &v)) ui_set_timezone(&app->ui, (int16_t)v);
}

int watch_app_save_settings(struct watch_app *app) {
    if (!app || !app->cfg.kv || !app->cfg.kv->mounted) return -1;
    struct kv_store *kv = app->cfg.kv;
    if (kv_set_u32(kv, "auto_brt", app->power.cfg.auto_brightness ? 1u : 0u) != 0 ||
        kv_set_u32(kv, "manual_brt", app->power.cfg.manual_brightness) != 0 ||
        kv_set_u32(kv, "dnd", app->power.dnd_enabled ? 1u : 0u) != 0 ||
        kv_set_u32(kv, "haptics", app->power.haptics_enabled ? 1u : 0u) != 0 ||
        kv_set_u32(kv, "aod", app->power.cfg.aod_enabled ? 1u : 0u) != 0 ||
        kv_set_u32(kv, "tz_min", (uint32_t)(uint16_t)app->ui.tz_offset_min) != 0) {
        return -2;
    }
    return 0;
}

void watch_app_init(struct watch_app *app, const struct watch_app_config *cfg, uint64_t now_ticks) {
    if (!app || !cfg) return;
    app->cfg = *cfg;
    if (app->cfg.tick_hz == 0) app->cfg.tick_hz = 100u;

    power_init(&app->power, NULL, now_ticks);
    ui_init(&app->ui);
    struct activity_config act_cfg = {.tick_hz = app->cfg.tick_hz, .stride_cm = 72u};
    activity_init(&app->activity, &act_cfg);
    proto_decoder_init(&app->proto_dec);

    app->tx_seq = 0;
    app->clock_offset_sec = 0;
    app->last_telemetry_ticks = now_ticks;
    app->proto_frames_handled = 0;
    app->telemetry_sent = 0;

    load_settings_from_kv(app);
    notify_set_action_cb(on_ui_notify_action, app);
}

uint32_t watch_app_feed_proto(struct watch_app *app, const uint8_t *data, uint32_t len,
                              uint64_t now_ticks) {
    if (!app || !data || len == 0) return 0;
    uint32_t handled = 0;
    struct proto_frame frame;

    for (uint32_t i = 0; i < len; i++) {
        if (proto_decoder_feed(&app->proto_dec, data[i], &frame) != 1) {
            continue;
        }
        int64_t synced_sec = -1;
        int16_t synced_tz = app->ui.tz_offset_min;
        if (proto_dispatch(&frame, &app->cfg.proto_tx, &synced_sec, &synced_tz) != 0) {
            continue;
        }
        handled++;
        app->proto_frames_handled++;

        if (frame.type == PROTO_TIME_SYNC) {
            ui_set_timezone(&app->ui, synced_tz);
        } else if (frame.type == PROTO_NOTIFY_POST) {
            app->ui.needs_redraw = true;
            if (!app->power.dnd_enabled) {
                (void)power_wake(&app->power, now_ticks);
                if (app->cfg.motor && app->power.haptics_enabled) {
                    (void)motor_play_pattern(app->cfg.motor, notif_buzz, 3, now_ticks);
                }
            }
        } else if (frame.type == PROTO_CALL_STATE) {
            struct call_info ci;
            if (call_get(&ci) && ci.state == CALL_RINGING) {
                (void)power_wake(&app->power, now_ticks);
                if (app->cfg.motor && app->power.haptics_enabled && !app->power.dnd_enabled) {
                    (void)motor_play_pattern(app->cfg.motor, call_buzz, 4, now_ticks);
                }
            }
            app->ui.needs_redraw = true;
        } else if (frame.type == PROTO_NAV_UPDATE || frame.type == PROTO_NAV_CLEAR) {
            (void)power_wake(&app->power, now_ticks);
            app->ui.needs_redraw = true;
        }
    }
    return handled;
}

void watch_app_step(struct watch_app *app, uint64_t now_ticks, uint64_t rtc_unix_sec) {
    if (!app) return;

    /* 1. Drain pending watch input events (buttons & touch). */
    struct input_event ev;
    while (input_poll(&ev)) {
        bool changed = ui_handle_input(&app->ui, &app->power, &ev, now_ticks);
        if (changed && app->cfg.motor && app->power.haptics_enabled && !app->power.dnd_enabled &&
            ev.type == INPUT_KEY &&
            (ev.action == INPUT_KEY_SHORT_CLICK || ev.action == INPUT_KEY_DOUBLE_CLICK)) {
            (void)motor_pulse(app->cfg.motor, 1u, now_ticks);
        }
    }

    /* 2. Drain pending sensor samples (IMU accel -> pedometer/wrist-wake, ALS -> auto-brightness). */
    struct sensor_sample sample;
    while (sensor_poll(&sample)) {
        if (sample.type == SENSOR_ACCEL) {
            uint8_t act_ev = activity_feed_accel(&app->activity, &sample);
            if ((act_ev & ACTIVITY_EVT_STEP) != 0) {
                ui_set_activity(&app->ui, activity_steps(&app->activity),
                                app->ui.heart_rate_bpm);
            }
            if ((act_ev & ACTIVITY_EVT_WRIST_WAKE) != 0) {
                if (power_wake(&app->power, now_ticks)) {
                    app->ui.needs_redraw = true;
                }
            }
        } else if (sample.type == SENSOR_ALS) {
            if (sample.x >= 0) {
                (void)power_update_als(&app->power, (uint32_t)sample.x);
            }
        } else if (sample.type == SENSOR_HEART_RATE) {
            if (sample.x > 0 && sample.x < 300) {
                ui_set_activity(&app->ui, app->ui.steps, (uint16_t)sample.x);
            }
        } else if (sample.type == SENSOR_BATTERY) {
            power_set_battery(&app->power, (uint8_t)sample.x, sample.y != 0);
            app->ui.needs_redraw = true;
        }
    }

    /* 3. Advance power timeouts and haptic motor sequencer. */
    if (power_tick(&app->power, now_ticks)) {
        app->ui.needs_redraw = true;
    }
    if (app->cfg.motor) {
        (void)motor_tick(app->cfg.motor, now_ticks);
    }
    if (app->cfg.panel) {
        (void)power_apply_panel(&app->power, app->cfg.panel);
    }

    /* 4. Render watch UI if needed and flush dirty rect to ICNA3311 panel. */
    int64_t effective_sec = (int64_t)rtc_unix_sec + app->clock_offset_sec;
    if (effective_sec < 0) effective_sec = 0;
    if (app->cfg.fb && ui_render(&app->ui, app->cfg.fb, &app->power, (uint64_t)effective_sec)) {
        if (app->cfg.panel) {
            (void)icna3311_flush_fb(app->cfg.panel, app->cfg.fb);
        }
    }

    /* 5. Periodic companion telemetry report. */
    if (app->cfg.telemetry_period_ticks > 0 && app->cfg.proto_tx.send &&
        (now_ticks - app->last_telemetry_ticks) >= app->cfg.telemetry_period_ticks) {
        app->last_telemetry_ticks = now_ticks;
        uint8_t wire[32];
        uint32_t up_sec = (uint32_t)now_ticks / app->cfg.tick_hz;
        int n = proto_encode_telemetry(wire, sizeof wire, ++app->tx_seq,
                                       app->power.battery_pct, app->power.charging,
                                       activity_steps(&app->activity),
                                       app->ui.heart_rate_bpm, up_sec);
        if (n > 0) {
            (void)app->cfg.proto_tx.send(wire, (uint32_t)n, app->cfg.proto_tx.ctx);
            app->telemetry_sent++;
        }
    }
}
