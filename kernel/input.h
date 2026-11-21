/* Watch input event queue (buttons, touch points and wake gestures). */
#ifndef SPELLBOUND_INPUT_H
#define SPELLBOUND_INPUT_H

#include <stdbool.h>
#include <stdint.h>

enum input_type {
    INPUT_KEY = 1,
    INPUT_TOUCH = 2,
};

enum input_key_action {
    INPUT_KEY_PRESS = 1,
    INPUT_KEY_RELEASE = 2,
    INPUT_KEY_SHORT_CLICK = 3,
    INPUT_KEY_LONG_PRESS = 4,
    INPUT_KEY_DOUBLE_CLICK = 5,
    INPUT_KEY_COMBO = 6,
};

enum input_touch_action {
    INPUT_TOUCH_DOWN = 1,
    INPUT_TOUCH_MOVE = 2,
    INPUT_TOUCH_UP = 3,
    INPUT_TOUCH_GESTURE = 4,
};

struct input_event {
    uint64_t timestamp_ticks;
    uint8_t type;
    uint8_t action;
    uint16_t code; /* key index, key bitmask for combo, touch id or gesture */
    int16_t x;
    int16_t y;
};

/* Bind caller-owned event storage. Returns 0 on success, -1 on error. */
int input_init(struct input_event *storage, uint32_t capacity);

/* Post an event (ISR-safe). Auto-stamps timestamp_ticks if zero. Returns false
 * and increments the dropped counter if uninitialized or full. */
bool input_post(const struct input_event *ev);

bool input_poll(struct input_event *out);
bool input_wait(struct input_event *out);
bool input_wait_for(struct input_event *out, uint32_t ticks);

uint32_t input_pending(void);
uint32_t input_dropped(void);

#endif /* SPELLBOUND_INPUT_H */
