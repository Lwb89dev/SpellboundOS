/* Independently authored GPIO button debouncer and gesture state machine. */
#include "gpio_keys.h"
#include "../input.h"
#include <stddef.h>

static void emit_key(uint64_t now, uint8_t action, uint16_t code) {
    struct input_event ev = {
        .timestamp_ticks = now,
        .type = INPUT_KEY,
        .action = action,
        .code = code,
        .x = 0,
        .y = 0,
    };
    (void)input_post(&ev);
}

static bool sample_pressed(struct gpio_chip *chip, const struct gpio_key_desc *desc) {
    int level = gpio_read(chip, desc->pin);
    if (level < 0) {
        return false;
    }
    return desc->active_low ? (level == 0) : (level != 0);
}

int gpio_keys_init(struct gpio_keys_state *state, const struct gpio_keys_config *cfg) {
    if (!state || !cfg || !cfg->chip || !cfg->keys ||
        cfg->key_count == 0 || cfg->key_count > GPIO_KEYS_MAX) {
        return -1;
    }
    state->chip = cfg->chip;
    state->key_count = cfg->key_count;
    state->debounce_ticks = cfg->debounce_ticks;
    state->long_press_ticks = cfg->long_press_ticks;
    state->double_click_ticks = cfg->double_click_ticks;
    state->combo_window_ticks = cfg->combo_window_ticks;
    state->combo_active = false;

    for (uint32_t i = 0; i < cfg->key_count; i++) {
        enum gpio_mode mode = cfg->keys[i].active_low ? GPIO_INPUT_PULLUP : GPIO_INPUT_PULLDOWN;
        if (gpio_configure(cfg->chip, cfg->keys[i].pin, mode) != 0) {
            return -1;
        }
        struct gpio_key_slot *s = &state->slots[i];
        s->desc = cfg->keys[i];
        s->raw_pressed = false;
        s->stable_pressed = false;
        s->long_fired = false;
        s->combo_consumed = false;
        s->pending_click = false;
        s->raw_since = 0;
        s->pressed_at = 0;
        s->released_at = 0;
    }
    return 0;
}

static uint64_t abs_diff(uint64_t a, uint64_t b) {
    return a >= b ? (a - b) : (b - a);
}

void gpio_keys_poll(struct gpio_keys_state *state, uint64_t now_ticks) {
    if (!state || !state->chip) {
        return;
    }

    /* Pass 1: debounce edges, handle press/release and pending single-click expiry. */
    uint32_t held_count = 0;
    for (uint32_t i = 0; i < state->key_count; i++) {
        struct gpio_key_slot *s = &state->slots[i];
        bool raw = sample_pressed(state->chip, &s->desc);
        if (raw != s->raw_pressed) {
            s->raw_pressed = raw;
            s->raw_since = now_ticks;
        }

        if (s->raw_pressed != s->stable_pressed &&
            (now_ticks - s->raw_since) >= state->debounce_ticks) {
            s->stable_pressed = s->raw_pressed;
            if (s->stable_pressed) {
                s->pressed_at = now_ticks;
                s->long_fired = false;
                s->combo_consumed = false;
                emit_key(now_ticks, INPUT_KEY_PRESS, s->desc.code);
            } else {
                emit_key(now_ticks, INPUT_KEY_RELEASE, s->desc.code);
                if (!s->long_fired && !s->combo_consumed) {
                    if (state->double_click_ticks == 0) {
                        emit_key(now_ticks, INPUT_KEY_SHORT_CLICK, s->desc.code);
                    } else if (s->pending_click &&
                               (now_ticks - s->released_at) <= state->double_click_ticks) {
                        s->pending_click = false;
                        emit_key(now_ticks, INPUT_KEY_DOUBLE_CLICK, s->desc.code);
                    } else {
                        s->pending_click = true;
                        s->released_at = now_ticks;
                    }
                } else {
                    s->pending_click = false;
                }
            }
        }

        if (s->stable_pressed) {
            held_count++;
        } else if (s->pending_click &&
                   (now_ticks - s->released_at) > state->double_click_ticks) {
            s->pending_click = false;
            emit_key(now_ticks, INPUT_KEY_SHORT_CLICK, s->desc.code);
        }
    }

    if (held_count == 0) {
        state->combo_active = false;
    }

    /* Pass 2: detect simultaneous two-key combo within combo_window_ticks. */
    if (!state->combo_active && state->combo_window_ticks > 0 && held_count >= 2) {
        for (uint32_t i = 0; i < state->key_count && !state->combo_active; i++) {
            struct gpio_key_slot *a = &state->slots[i];
            if (!a->stable_pressed || a->long_fired || a->combo_consumed) {
                continue;
            }
            for (uint32_t j = i + 1; j < state->key_count; j++) {
                struct gpio_key_slot *b = &state->slots[j];
                if (!b->stable_pressed || b->long_fired || b->combo_consumed) {
                    continue;
                }
                if (abs_diff(a->pressed_at, b->pressed_at) <= state->combo_window_ticks) {
                    a->combo_consumed = true;
                    b->combo_consumed = true;
                    a->pending_click = false;
                    b->pending_click = false;
                    state->combo_active = true;
                    uint16_t mask = (uint16_t)((1u << i) | (1u << j));
                    emit_key(now_ticks, INPUT_KEY_COMBO, mask);
                    break;
                }
            }
        }
    }

    /* Pass 3: fire long-press once for held keys that were not consumed by a combo. */
    if (state->long_press_ticks > 0) {
        for (uint32_t i = 0; i < state->key_count; i++) {
            struct gpio_key_slot *s = &state->slots[i];
            if (s->stable_pressed && !s->long_fired && !s->combo_consumed &&
                (now_ticks - s->pressed_at) >= state->long_press_ticks) {
                s->long_fired = true;
                s->pending_click = false;
                emit_key(now_ticks, INPUT_KEY_LONG_PRESS, s->desc.code);
            }
        }
    }
}
