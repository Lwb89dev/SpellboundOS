/* Independently authored GPIO haptic vibration motor driver. */
#include "motor.h"
#include <stddef.h>

static const uint16_t level_durations_ms[8] = {
    25u, 25u, 50u, 50u, 80u, 130u, 25u, 25u
};

uint16_t motor_level_duration_ms(uint8_t level) {
    if (level >= 1u && level <= 8u) {
        return level_durations_ms[level - 1u];
    }
    return 1000u;
}

static uint32_t ms_to_ticks(uint32_t tick_hz, uint16_t ms) {
    uint32_t ticks = ((uint32_t)ms * tick_hz + 999u) / 1000u;
    return ticks == 0 ? 1u : ticks;
}

int motor_init(struct motor_dev *dev, struct gpio_chip *chip, uint32_t pin, uint32_t tick_hz) {
    if (!dev || !chip || tick_hz == 0) {
        return -1;
    }
    if (gpio_configure(chip, pin, GPIO_OUTPUT) != 0 ||
        gpio_write(chip, pin, false) != 0) {
        return -1;
    }
    dev->chip = chip;
    dev->pin = pin;
    dev->tick_hz = tick_hz;
    dev->initialized = true;
    dev->active = false;
    dev->pattern_running = false;
    dev->step_count = 0;
    dev->step_index = 0;
    dev->step_deadline_ticks = 0;
    return 0;
}

int motor_on(struct motor_dev *dev) {
    if (!dev || !dev->initialized) {
        return -1;
    }
    if (gpio_write(dev->chip, dev->pin, true) != 0) {
        return -1;
    }
    dev->active = true;
    dev->pattern_running = false;
    return 0;
}

int motor_off(struct motor_dev *dev) {
    if (!dev || !dev->initialized) {
        return -1;
    }
    dev->pattern_running = false;
    dev->active = false;
    return gpio_write(dev->chip, dev->pin, false);
}

int motor_play_pattern(struct motor_dev *dev, const struct motor_step *steps,
                       uint32_t count, uint64_t now_ticks) {
    if (!dev || !dev->initialized || !steps || count == 0 || count > MOTOR_MAX_PATTERN_STEPS) {
        return -1;
    }
    for (uint32_t i = 0; i < count; i++) {
        dev->steps[i] = steps[i];
    }
    dev->step_count = count;
    dev->step_index = 0;
    dev->step_deadline_ticks = now_ticks + ms_to_ticks(dev->tick_hz, steps[0].duration_ms);
    if (gpio_write(dev->chip, dev->pin, steps[0].on) != 0) {
        return -1;
    }
    dev->active = steps[0].on;
    dev->pattern_running = true;
    return 0;
}

int motor_pulse(struct motor_dev *dev, uint8_t level, uint64_t now_ticks) {
    struct motor_step step = {
        .on = true,
        .duration_ms = motor_level_duration_ms(level),
    };
    return motor_play_pattern(dev, &step, 1, now_ticks);
}

bool motor_tick(struct motor_dev *dev, uint64_t now_ticks) {
    if (!dev || !dev->initialized || !dev->pattern_running) {
        return false;
    }
    if ((int64_t)(now_ticks - dev->step_deadline_ticks) < 0) {
        return true;
    }
    dev->step_index++;
    if (dev->step_index >= dev->step_count) {
        (void)motor_off(dev);
        return false;
    }
    const struct motor_step *s = &dev->steps[dev->step_index];
    dev->step_deadline_ticks = now_ticks + ms_to_ticks(dev->tick_hz, s->duration_ms);
    (void)gpio_write(dev->chip, dev->pin, s->on);
    dev->active = s->on;
    return true;
}
