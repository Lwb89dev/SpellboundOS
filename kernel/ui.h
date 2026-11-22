/* Watch UI compositor: watchface, notifications, Roadstr navigation, call & quick settings. */
#ifndef SPELLBOUND_UI_H
#define SPELLBOUND_UI_H

#include <stdbool.h>
#include <stdint.h>
#include "fb.h"
#include "input.h"
#include "power.h"

enum ui_screen {
    UI_SCREEN_WATCHFACE = 0,
    UI_SCREEN_NOTIFICATIONS = 1,
    UI_SCREEN_NAVIGATION = 2,
    UI_SCREEN_QUICK_SETTINGS = 3,
    UI_SCREEN_CALL = 4,
};

struct ui_state {
    enum ui_screen screen;
    bool needs_redraw;
    uint32_t selected_notif;
    uint8_t selected_action;
    uint8_t quick_idx; /* 0=auto-bright, 1=DND, 2=haptics, 3=AOD */
    uint32_t steps;
    uint16_t heart_rate_bpm;
    int16_t tz_offset_min;
    uint32_t last_nav_rev;
    uint64_t last_rendered_sec;
    uint32_t frames_rendered;
};

void ui_init(struct ui_state *ui);
void ui_set_screen(struct ui_state *ui, enum ui_screen screen);
void ui_set_activity(struct ui_state *ui, uint32_t steps, uint16_t heart_rate_bpm);
void ui_set_timezone(struct ui_state *ui, int16_t tz_offset_min);

/* Process a watch input event (buttons or touch). Returns true if UI state changed. */
bool ui_handle_input(struct ui_state *ui, struct power_state *power,
                     const struct input_event *ev, uint64_t now_ticks);

/* Synchronize with call/navigation updates and render the active screen into fb.
 * Returns true if a frame was drawn into fb. */
bool ui_render(struct ui_state *ui, struct fb *fb, const struct power_state *power,
               uint64_t unix_sec);

#endif /* SPELLBOUND_UI_H */
