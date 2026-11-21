/* Runtime check for input event delivery, gpio_keys and syscon binding on RV32 QEMU virt. */
#include <stdbool.h>
#include <stdint.h>
#include "../kernel/board.h"
#include "../kernel/bus.h"
#include "../kernel/console.h"
#include "../kernel/driver.h"
#include "../kernel/input.h"
#include "../kernel/sched.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/drivers/gpio_keys.h"

static _Alignas(16) uint32_t stacks[2][256];
static struct input_event event_storage[8];
static volatile bool pin_level = true; /* active-low idle */
static volatile unsigned failures;

static int virt_gpio_cfg(struct gpio_chip *chip, uint32_t pin, enum gpio_mode mode) {
    (void)chip;
    (void)pin;
    (void)mode;
    return 0;
}

static int virt_gpio_read(struct gpio_chip *chip, uint32_t pin) {
    (void)chip;
    return pin == 19 ? (pin_level ? 1 : 0) : 1;
}

static const struct gpio_ops virt_gpio_ops = {
    .configure = virt_gpio_cfg,
    .read = virt_gpio_read,
};

static struct gpio_chip virt_gpio = {
    .name = "virt_gpio",
    .pin_count = 32,
    .ops = &virt_gpio_ops,
};

static struct gpio_keys_state keys_state;

static void key_producer(void) {
    const struct gpio_key_desc desc = {.pin = 19, .code = 0, .active_low = true};
    struct gpio_keys_config cfg = {
        .chip = &virt_gpio,
        .keys = &desc,
        .key_count = 1,
        .debounce_ticks = 2,
        .long_press_ticks = 0,
        .double_click_ticks = 0,
        .combo_window_ticks = 0,
    };
    if (gpio_keys_init(&keys_state, &cfg) != 0) {
        failures++;
        return;
    }

    pin_level = false;
    for (unsigned i = 0; i < 4; i++) {
        gpio_keys_poll(&keys_state, timer_ticks());
        task_sleep(1);
    }
    pin_level = true;
    for (unsigned i = 0; i < 4; i++) {
        gpio_keys_poll(&keys_state, timer_ticks());
        task_sleep(1);
    }
}

static void key_consumer(void) {
    const uint8_t expected[3] = {INPUT_KEY_PRESS, INPUT_KEY_RELEASE, INPUT_KEY_SHORT_CLICK};
    for (unsigned i = 0; i < 3; i++) {
        struct input_event ev;
        if (!input_wait_for(&ev, 50) || ev.type != INPUT_KEY ||
            ev.action != expected[i] || ev.code != 0) {
            failures++;
            return;
        }
    }
    struct input_event unused;
    if (input_wait_for(&unused, 3)) {
        failures++;
    }
}

void kernel_main(void) {
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);

    struct device *syscon = device_find("syscon0");
    if (!syscon || !syscon->bound) {
        failures++;
    }
    if (gpio_register(&virt_gpio) != 0 || gpio_find("virt_gpio") != &virt_gpio ||
        input_init(event_storage, 8) != 0) {
        failures++;
    }
    if (task_create(key_producer, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(key_consumer, stacks[1], sizeof stacks[1]) < 0) {
        failures++;
    }
    sched_run();

    console_puts(failures ? "FAIL: bus, input and syscon\n" :
                            "PASS: bus, input and syscon\n");
    board_poweroff();
}
