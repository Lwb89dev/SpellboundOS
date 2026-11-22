/* Watch UI compositor rendering watchface, notifications, Roadstr nav, calls and settings. */
#include "ui.h"
#include "notify.h"
#include "rtc.h"
#include <stddef.h>

static void fmt_u32(char *dst, uint32_t cap, uint32_t val) {
    if (cap == 0) return;
    char rev[12];
    unsigned n = 0;
    if (val == 0) {
        rev[n++] = '0';
    } else {
        while (val > 0 && n < 12u) {
            rev[n++] = (char)('0' + (val % 10u));
            val /= 10u;
        }
    }
    uint32_t out = 0;
    while (n > 0 && out + 1u < cap) {
        dst[out++] = rev[--n];
    }
    dst[out] = '\0';
}

static void fmt_2d(char *dst, uint8_t v) {
    dst[0] = (char)('0' + (v / 10u) % 10u);
    dst[1] = (char)('0' + (v % 10u));
}

static void draw_centered_text(struct fb *fb, int32_t y, const char *text,
                               uint16_t fg, uint8_t scale) {
    uint32_t w = fb_text_width(text, scale);
    int32_t x = ((int32_t)fb->width - (int32_t)w) / 2;
    if (x < 2) x = 2;
    fb_draw_text(fb, x, y, text, fg, FB_BLACK, false, scale);
}

void ui_init(struct ui_state *ui) {
    if (!ui) return;
    *ui = (struct ui_state){
        .screen = UI_SCREEN_WATCHFACE,
        .needs_redraw = true,
        .last_rendered_sec = UINT64_MAX,
    };
}

void ui_set_screen(struct ui_state *ui, enum ui_screen screen) {
    if (!ui) return;
    if (ui->screen != screen) {
        ui->screen = screen;
        ui->needs_redraw = true;
    }
}

void ui_set_activity(struct ui_state *ui, uint32_t steps, uint16_t heart_rate_bpm) {
    if (!ui) return;
    if (ui->steps != steps || ui->heart_rate_bpm != heart_rate_bpm) {
        ui->steps = steps;
        ui->heart_rate_bpm = heart_rate_bpm;
        ui->needs_redraw = true;
    }
}

void ui_set_timezone(struct ui_state *ui, int16_t tz_offset_min) {
    if (!ui) return;
    if (ui->tz_offset_min != tz_offset_min) {
        ui->tz_offset_min = tz_offset_min;
        ui->needs_redraw = true;
    }
}

bool ui_handle_input(struct ui_state *ui, struct power_state *power,
                     const struct input_event *ev, uint64_t now_ticks) {
    if (!ui || !ev) return false;

    if (power) {
        bool was_asleep = (power->screen == POWER_SLEEP || power->screen == POWER_AOD);
        if (power_wake(power, now_ticks)) {
            ui->needs_redraw = true;
        }
        if (was_asleep) {
            return true; /* first event wakes screen without triggering UI actions */
        }
    }

    if (ev->type == INPUT_KEY) {
        if (ev->action == INPUT_KEY_LONG_PRESS) {
            if (ui->screen == UI_SCREEN_NOTIFICATIONS && notify_count() > 0) {
                struct notification n;
                if (notify_get_at(ui->selected_notif, &n)) {
                    (void)notify_dismiss(n.id);
                    if (ui->selected_notif >= notify_count() && ui->selected_notif > 0) {
                        ui->selected_notif--;
                    }
                    ui->selected_action = 0;
                    ui->needs_redraw = true;
                    return true;
                }
            }
            ui->screen = UI_SCREEN_WATCHFACE;
            ui->needs_redraw = true;
            return true;
        }
        if (ev->action == INPUT_KEY_DOUBLE_CLICK) {
            if (ui->screen == UI_SCREEN_NOTIFICATIONS) {
                struct notification n;
                if (notify_get_at(ui->selected_notif, &n) && n.action_count > 0) {
                    uint8_t idx = ui->selected_action < n.action_count ? ui->selected_action : 0;
                    (void)notify_trigger_action(n.id, idx);
                    ui->needs_redraw = true;
                    return true;
                }
            }
            if (ui->screen == UI_SCREEN_QUICK_SETTINGS && power) {
                if (ui->quick_idx == 0) (void)power_set_auto_brightness(power, !power->cfg.auto_brightness);
                else if (ui->quick_idx == 1) power->dnd_enabled = !power->dnd_enabled;
                else if (ui->quick_idx == 2) power->haptics_enabled = !power->haptics_enabled;
                else if (ui->quick_idx == 3) power->cfg.aod_enabled = !power->cfg.aod_enabled;
                ui->needs_redraw = true;
                return true;
            }
            struct nav_state nav;
            if (nav_get(&nav)) {
                ui->screen = UI_SCREEN_NAVIGATION;
                ui->needs_redraw = true;
                return true;
            }
            return false;
        }
        if (ev->action == INPUT_KEY_SHORT_CLICK) {
            if (ev->code == 0) {
                /* Primary button cycles top-level screens: Watchface -> Alerts -> Nav -> Settings */
                if (ui->screen == UI_SCREEN_WATCHFACE) {
                    ui->screen = UI_SCREEN_NOTIFICATIONS;
                    ui->selected_notif = 0;
                    ui->selected_action = 0;
                } else if (ui->screen == UI_SCREEN_NOTIFICATIONS) {
                    struct nav_state nav;
                    ui->screen = nav_get(&nav) ? UI_SCREEN_NAVIGATION : UI_SCREEN_QUICK_SETTINGS;
                } else if (ui->screen == UI_SCREEN_NAVIGATION) {
                    ui->screen = UI_SCREEN_QUICK_SETTINGS;
                } else {
                    ui->screen = UI_SCREEN_WATCHFACE;
                }
                ui->needs_redraw = true;
                return true;
            } else {
                /* Secondary button steps selection inside current screen */
                if (ui->screen == UI_SCREEN_NOTIFICATIONS && notify_count() > 0) {
                    ui->selected_notif = (ui->selected_notif + 1u) % notify_count();
                    ui->selected_action = 0;
                    ui->needs_redraw = true;
                    return true;
                }
                if (ui->screen == UI_SCREEN_QUICK_SETTINGS) {
                    ui->quick_idx = (uint8_t)((ui->quick_idx + 1u) % 4u);
                    ui->needs_redraw = true;
                    return true;
                }
            }
        }
    }

    if (ev->type == INPUT_TOUCH && ev->action == INPUT_TOUCH_DOWN) {
        if (ui->screen == UI_SCREEN_QUICK_SETTINGS && power) {
            if (ui->quick_idx == 0) (void)power_set_auto_brightness(power, !power->cfg.auto_brightness);
            else if (ui->quick_idx == 1) power->dnd_enabled = !power->dnd_enabled;
            else if (ui->quick_idx == 2) power->haptics_enabled = !power->haptics_enabled;
            else if (ui->quick_idx == 3) power->cfg.aod_enabled = !power->cfg.aod_enabled;
            ui->needs_redraw = true;
            return true;
        }
        if (ui->screen == UI_SCREEN_NOTIFICATIONS) {
            struct notification n;
            if (notify_get_at(ui->selected_notif, &n) && n.action_count > 0) {
                (void)notify_trigger_action(n.id, ui->selected_action);
                ui->needs_redraw = true;
                return true;
            }
        }
    }

    return false;
}

/* ---- Screen renderers ---- */

static void render_watchface(const struct ui_state *ui, struct fb *fb,
                             const struct power_state *power, uint64_t unix_sec) {
    fb_clear(fb, FB_BLACK);

    int64_t local_sec = (int64_t)unix_sec + (int64_t)ui->tz_offset_min * 60;
    if (local_sec < 0) local_sec = 0;
    struct rtc_datetime dt;
    rtc_unix_to_datetime((uint64_t)local_sec, &dt);

    char hhmm[6];
    fmt_2d(&hhmm[0], dt.hour);
    hhmm[2] = ':';
    fmt_2d(&hhmm[3], dt.minute);
    hhmm[5] = '\0';

    uint8_t time_scale = fb->width >= 240u ? 4u : 2u;
    int32_t time_y = (int32_t)(fb->height / 2u) - (int32_t)(FB_FONT_H * time_scale) / 2 - 6;

    if (power && power->screen == POWER_AOD) {
        draw_centered_text(fb, time_y, hhmm, FB_GRAY, time_scale);
        return;
    }

    /* Top status bar: battery + unread badge */
    uint8_t bat = power ? power->battery_pct : 100u;
    bool chg = power && power->charging;
    uint16_t bat_col = bat <= 20u ? FB_RED : (chg ? FB_GREEN : FB_WHITE);
    fb_rect(fb, fb->width - 30, 6, 22, 10, bat_col);
    fb_fill_rect(fb, fb->width - 8, 9, 2, 4, bat_col);
    int32_t fill_w = ((int32_t)bat * 18) / 100;
    if (fill_w > 0) fb_fill_rect(fb, fb->width - 28, 8, fill_w, 6, bat_col);

    uint32_t unread = notify_unread_count();
    if (unread > 0) {
        fb_fill_round_rect(fb, 6, 4, 24, 14, 4, FB_ACCENT);
        char ubuf[8];
        fmt_u32(ubuf, sizeof ubuf, unread);
        fb_draw_text(fb, 11, 8, ubuf, FB_WHITE, FB_ACCENT, false, 1);
    }

    /* Main HH:MM clock */
    draw_centered_text(fb, time_y, hhmm, FB_WHITE, time_scale);

    /* Date YYYY-MM-DD */
    char date_str[12];
    fmt_u32(date_str, 5, (uint32_t)dt.year);
    date_str[4] = '-';
    fmt_2d(&date_str[5], dt.month);
    date_str[7] = '-';
    fmt_2d(&date_str[8], dt.day);
    date_str[10] = '\0';
    draw_centered_text(fb, time_y + (int32_t)(FB_FONT_H * time_scale) + 8, date_str, FB_CYAN, 1);

    /* Bottom activity strip */
    int32_t bot_y = (int32_t)fb->height - 20;
    fb_hline(fb, 8, bot_y - 4, (int32_t)fb->width - 16, FB_DARK_GRAY);
    char sbuf[16];
    sbuf[0] = 'S'; sbuf[1] = ':';
    fmt_u32(&sbuf[2], sizeof sbuf - 2u, ui->steps);
    fb_draw_text(fb, 8, bot_y, sbuf, FB_GREEN, FB_BLACK, false, 1);

    char hbuf[16];
    hbuf[0] = 'H'; hbuf[1] = ':';
    fmt_u32(&hbuf[2], sizeof hbuf - 2u, ui->heart_rate_bpm);
    int32_t hx = (int32_t)fb->width - (int32_t)fb_text_width(hbuf, 1) - 8;
    fb_draw_text(fb, hx, bot_y, hbuf, FB_ORANGE, FB_BLACK, false, 1);
}

static void render_notifications(const struct ui_state *ui, struct fb *fb) {
    fb_clear(fb, FB_BLACK);
    fb_fill_rect(fb, 0, 0, fb->width, 18, FB_DARK_GRAY);
    fb_draw_text(fb, 6, 5, "ALERTS", FB_ACCENT, FB_DARK_GRAY, false, 1);

    uint32_t total = notify_count();
    if (total == 0) {
        draw_centered_text(fb, fb->height / 2 - 4, "No notifications", FB_GRAY, 1);
        return;
    }
    uint32_t idx = ui->selected_notif < total ? ui->selected_notif : 0;
    struct notification n;
    if (!notify_get_at(idx, &n)) return;

    fb_fill_round_rect(fb, 6, 24, (int32_t)fb->width - 12, (int32_t)fb->height - 54, 6, FB_DARK_GRAY);
    fb_draw_text(fb, 12, 30, n.app, FB_CYAN, FB_DARK_GRAY, false, 1);
    fb_draw_text(fb, 12, 42, n.title, FB_WHITE, FB_DARK_GRAY, false, 1);
    fb_draw_text(fb, 12, 56, n.body, FB_GRAY, FB_DARK_GRAY, false, 1);

    if (n.action_count > 0) {
        int32_t pill_y = (int32_t)fb->height - 24;
        uint8_t act = ui->selected_action < n.action_count ? ui->selected_action : 0;
        fb_fill_round_rect(fb, 10, pill_y, (int32_t)fb->width - 20, 18, 5, FB_ACCENT);
        draw_centered_text(fb, pill_y + 5, n.actions[act], FB_WHITE, 1);
    }
}

static void draw_nav_arrow(struct fb *fb, enum nav_maneuver m, int32_t cx, int32_t cy, int32_t sz) {
    uint16_t col = (m == NAV_ARRIVE) ? FB_GREEN : FB_CYAN;
    switch (m) {
    case NAV_LEFT:
    case NAV_SLIGHT_LEFT:
    case NAV_SHARP_LEFT:
        fb_fill_rect(fb, cx - 2, cy - sz / 4, 6, sz, col);
        fb_fill_rect(fb, cx - sz / 2, cy - sz / 4, sz / 2 + 4, 6, col);
        fb_fill_triangle(fb, cx - sz, cy - sz / 4 + 3,
                         cx - sz / 2, cy - sz / 2 - 4,
                         cx - sz / 2, cy + 10, col);
        break;
    case NAV_RIGHT:
    case NAV_SLIGHT_RIGHT:
    case NAV_SHARP_RIGHT:
        fb_fill_rect(fb, cx - 4, cy - sz / 4, 6, sz, col);
        fb_fill_rect(fb, cx - 4, cy - sz / 4, sz / 2 + 4, 6, col);
        fb_fill_triangle(fb, cx + sz, cy - sz / 4 + 3,
                         cx + sz / 2, cy - sz / 2 - 4,
                         cx + sz / 2, cy + 10, col);
        break;
    case NAV_ROUNDABOUT:
        fb_circle(fb, cx, cy, sz / 2, col);
        fb_circle(fb, cx, cy, sz / 2 - 1, col);
        fb_fill_triangle(fb, cx, cy - sz, cx - 7, cy - sz / 2, cx + 7, cy - sz / 2, col);
        break;
    case NAV_UTURN:
        fb_fill_rect(fb, cx + 4, cy - sz / 2, 5, sz, col);
        fb_fill_rect(fb, cx - 9, cy - sz / 2, 18, 5, col);
        fb_fill_rect(fb, cx - 9, cy - sz / 2, 5, sz / 2, col);
        fb_fill_triangle(fb, cx - 7, cy + sz / 4, cx - 14, cy, cx, cy, col);
        break;
    case NAV_ARRIVE:
        fb_fill_circle(fb, cx, cy - 4, sz / 2, FB_GREEN);
        fb_fill_circle(fb, cx, cy - 4, sz / 4, FB_BLACK);
        break;
    case NAV_STRAIGHT:
    case NAV_NONE:
    default:
        fb_fill_rect(fb, cx - 3, cy - sz / 4, 6, sz, col);
        fb_fill_triangle(fb, cx, cy - sz, cx - sz / 2, cy - sz / 4, cx + sz / 2, cy - sz / 4, col);
        break;
    }
}

static void render_navigation(struct fb *fb) {
    fb_clear(fb, FB_BLACK);
    fb_fill_rect(fb, 0, 0, fb->width, 18, FB_DARK_GRAY);
    fb_draw_text(fb, 6, 5, "ROADSTR NAV", FB_GREEN, FB_DARK_GRAY, false, 1);

    struct nav_state nav;
    if (!nav_get(&nav)) {
        draw_centered_text(fb, fb->height / 2 - 4, "No active route", FB_GRAY, 1);
        return;
    }

    int32_t arrow_sz = fb->height >= 200u ? 32 : 16;
    draw_nav_arrow(fb, (enum nav_maneuver)nav.maneuver,
                   (int32_t)fb->width / 2, 24 + arrow_sz, arrow_sz);

    /* Distance formatting: <1000 -> "XXXm", >=1000 -> "X.Ykm" */
    char dist_buf[16];
    if (nav.distance_m < 1000u) {
        fmt_u32(dist_buf, 12, nav.distance_m);
        uint32_t l = 0; while (dist_buf[l]) l++;
        dist_buf[l] = 'm'; dist_buf[l + 1u] = '\0';
    } else {
        uint32_t km = nav.distance_m / 1000u;
        uint32_t tenths = (nav.distance_m % 1000u) / 100u;
        fmt_u32(dist_buf, 10, km);
        uint32_t l = 0; while (dist_buf[l]) l++;
        dist_buf[l++] = '.';
        dist_buf[l++] = (char)('0' + tenths);
        dist_buf[l++] = 'k';
        dist_buf[l++] = 'm';
        dist_buf[l] = '\0';
    }
    int32_t dist_y = 28 + arrow_sz * 2 + 4;
    draw_centered_text(fb, dist_y, dist_buf, FB_WHITE, fb->width >= 200u ? 3u : 2u);
    draw_centered_text(fb, dist_y + 22, nav.street, FB_YELLOW, 1);

    char eta_buf[16] = "ETA ";
    fmt_u32(&eta_buf[4], 10, nav.eta_min);
    uint32_t el = 4; while (eta_buf[el]) el++;
    eta_buf[el++] = 'm'; eta_buf[el] = '\0';
    draw_centered_text(fb, (int32_t)fb->height - 16, eta_buf, FB_GRAY, 1);
}

static void render_call(struct fb *fb) {
    fb_clear(fb, FB_BLACK);
    struct call_info ci;
    (void)call_get(&ci);
    draw_centered_text(fb, 14, ci.state == CALL_ACTIVE ? "IN CALL" : "INCOMING CALL", FB_GREEN, 1);
    draw_centered_text(fb, fb->height / 2 - 12, ci.caller[0] ? ci.caller : "Unknown", FB_WHITE, 2);
    draw_centered_text(fb, fb->height / 2 + 10, ci.number, FB_GRAY, 1);
    fb_fill_circle(fb, fb->width / 4, fb->height - 22, 10, FB_GREEN);
    fb_fill_circle(fb, (fb->width * 3) / 4, fb->height - 22, 10, FB_RED);
}

static void render_quick_settings(const struct ui_state *ui, struct fb *fb,
                                  const struct power_state *power) {
    fb_clear(fb, FB_BLACK);
    fb_fill_rect(fb, 0, 0, fb->width, 18, FB_DARK_GRAY);
    fb_draw_text(fb, 6, 5, "SETTINGS", FB_CYAN, FB_DARK_GRAY, false, 1);

    static const char *labels[4] = {"AUTO BRT", "DND", "HAPTICS", "AOD"};
    bool vals[4] = {
        power ? power->cfg.auto_brightness : false,
        power ? power->dnd_enabled : false,
        power ? power->haptics_enabled : false,
        power ? power->cfg.aod_enabled : false,
    };

    for (uint8_t i = 0; i < 4u; i++) {
        int32_t y = 24 + (int32_t)i * 24;
        uint16_t bg = (i == ui->quick_idx) ? FB_ACCENT : FB_DARK_GRAY;
        fb_fill_round_rect(fb, 6, y, (int32_t)fb->width - 12, 20, 4, bg);
        fb_draw_text(fb, 12, y + 6, labels[i], FB_WHITE, bg, false, 1);
        const char *st = vals[i] ? "ON" : "OFF";
        uint16_t sc = vals[i] ? FB_GREEN : FB_GRAY;
        int32_t sx = (int32_t)fb->width - (int32_t)fb_text_width(st, 1) - 12;
        fb_draw_text(fb, sx, y + 6, st, sc, bg, false, 1);
    }
}

bool ui_render(struct ui_state *ui, struct fb *fb, const struct power_state *power,
               uint64_t unix_sec) {
    if (!ui || !fb || !fb->pixels) return false;
    if (power && power->screen == POWER_SLEEP) {
        return false;
    }

    /* Auto-promote incoming call or fresh Roadstr navigation update. */
    struct call_info ci;
    if (call_get(&ci) && ci.state == CALL_RINGING && ui->screen != UI_SCREEN_CALL) {
        ui->screen = UI_SCREEN_CALL;
        ui->needs_redraw = true;
    } else if (ui->screen == UI_SCREEN_CALL && !call_get(&ci)) {
        ui->screen = UI_SCREEN_WATCHFACE;
        ui->needs_redraw = true;
    }

    struct nav_state nav;
    if (nav_get(&nav) && nav.revision != ui->last_nav_rev) {
        ui->last_nav_rev = nav.revision;
        if (ui->screen != UI_SCREEN_CALL) {
            ui->screen = UI_SCREEN_NAVIGATION;
        }
        ui->needs_redraw = true;
    }

    if (ui->screen == UI_SCREEN_WATCHFACE && unix_sec != ui->last_rendered_sec) {
        ui->needs_redraw = true;
    }
    if (!ui->needs_redraw) {
        return false;
    }

    switch (ui->screen) {
    case UI_SCREEN_WATCHFACE:
        render_watchface(ui, fb, power, unix_sec);
        break;
    case UI_SCREEN_NOTIFICATIONS:
        render_notifications(ui, fb);
        break;
    case UI_SCREEN_NAVIGATION:
        render_navigation(fb);
        break;
    case UI_SCREEN_CALL:
        render_call(fb);
        break;
    case UI_SCREEN_QUICK_SETTINGS:
        render_quick_settings(ui, fb, power);
        break;
    }

    ui->last_rendered_sec = unix_sec;
    ui->needs_redraw = false;
    ui->frames_rendered++;
    return true;
}
