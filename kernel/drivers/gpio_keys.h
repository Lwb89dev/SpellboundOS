/* Portable GPIO button debouncer and gesture engine (click, long, double, combo).
 * Independently authored over kernel/bus.h and kernel/input.h. */
#ifndef SPELLBOUND_GPIO_KEYS_H
#define SPELLBOUND_GPIO_KEYS_H

#include <stdbool.h>
#include <stdint.h>
#include "../bus.h"

#define GPIO_KEYS_MAX 4u

struct gpio_key_desc {
    uint32_t pin;
    uint16_t code;    /* logical key code posted in struct input_event.code */
    bool active_low;  /* true when a pressed button reads logic 0 */
};

struct gpio_keys_config {
    struct gpio_chip *chip;
    const struct gpio_key_desc *keys;
    uint32_t key_count;
    uint32_t debounce_ticks;     /* stable ticks required before state change */
    uint32_t long_press_ticks;   /* hold duration for INPUT_KEY_LONG_PRESS (0 disables) */
    uint32_t double_click_ticks; /* window after release for double click (0 disables) */
    uint32_t combo_window_ticks; /* max skew between two presses for combo (0 disables) */
};

struct gpio_key_slot {
    struct gpio_key_desc desc;
    bool raw_pressed;
    bool stable_pressed;
    bool long_fired;
    bool combo_consumed;
    bool pending_click;
    uint64_t raw_since;
    uint64_t pressed_at;
    uint64_t released_at;
};

struct gpio_keys_state {
    struct gpio_chip *chip;
    uint32_t key_count;
    uint32_t debounce_ticks;
    uint32_t long_press_ticks;
    uint32_t double_click_ticks;
    uint32_t combo_window_ticks;
    bool combo_active;
    struct gpio_key_slot slots[GPIO_KEYS_MAX];
};

/* Configure GPIO pins and initialize key state. Returns 0 on success, -1 on error. */
int gpio_keys_init(struct gpio_keys_state *state, const struct gpio_keys_config *cfg);

/* Sample all buttons at timestamp now_ticks and post recognized events to input. */
void gpio_keys_poll(struct gpio_keys_state *state, uint64_t now_ticks);

#endif /* SPELLBOUND_GPIO_KEYS_H */
