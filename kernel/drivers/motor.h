/* Portable GPIO haptic vibration motor driver with level durations and patterns. */
#ifndef SPELLBOUND_MOTOR_H
#define SPELLBOUND_MOTOR_H

#include <stdbool.h>
#include <stdint.h>
#include "../bus.h"

#define MOTOR_MAX_PATTERN_STEPS 8u

struct motor_step {
    bool on;
    uint16_t duration_ms;
};

struct motor_dev {
    struct gpio_chip *chip;
    uint32_t pin;
    uint32_t tick_hz;
    bool initialized;
    bool active;
    bool pattern_running;
    struct motor_step steps[MOTOR_MAX_PATTERN_STEPS];
    uint32_t step_count;
    uint32_t step_index;
    uint64_t step_deadline_ticks;
};

/* Level-to-duration lookup (levels 1..8 -> 25,25,50,50,80,130,25,25 ms; else 1000 ms). */
uint16_t motor_level_duration_ms(uint8_t level);

int motor_init(struct motor_dev *dev, struct gpio_chip *chip, uint32_t pin, uint32_t tick_hz);
int motor_on(struct motor_dev *dev);
int motor_off(struct motor_dev *dev);

/* Start a one-shot timed pulse for the given intensity level. */
int motor_pulse(struct motor_dev *dev, uint8_t level, uint64_t now_ticks);

/* Start a multi-step haptic pattern (copied internally, up to MOTOR_MAX_PATTERN_STEPS). */
int motor_play_pattern(struct motor_dev *dev, const struct motor_step *steps,
                       uint32_t count, uint64_t now_ticks);

/* Advance active pulse/pattern at now_ticks. Returns true if still running. */
bool motor_tick(struct motor_dev *dev, uint64_t now_ticks);

#endif /* SPELLBOUND_MOTOR_H */
