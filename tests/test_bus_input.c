/* Host unit tests for sifive_test, bus (GPIO/I2C/SPI), input queue and gpio_keys. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"

/* Minimal mock scheduler/timer primitives for sync.c + input.c on host. */
static int mock_current_task = 0;
static uint64_t mock_ticks = 100;
static unsigned mock_irq_depth = 0;

static inline uint32_t irq_save(void) {
    mock_irq_depth++;
    return mock_irq_depth == 1 ? 8u : 0u;
}

static inline void irq_restore(uint32_t previous) {
    assert(mock_irq_depth > 0);
    if (previous & 8u) {
        assert(mock_irq_depth == 1);
    }
    mock_irq_depth--;
}

static uint64_t timer_ticks(void) {
    return mock_ticks;
}

int task_current(void) {
    return mock_current_task;
}

void task_event_signal(struct task_event *event) {
    event->pending = true;
}

void task_event_wait(struct task_event *event) {
    assert(mock_irq_depth == 0);
    event->pending = false;
}

bool task_event_wait_for(struct task_event *event, uint32_t ticks) {
    assert(mock_irq_depth == 0);
    if (event->pending) {
        event->pending = false;
        return true;
    }
    mock_ticks += ticks;
    return false;
}

#include "../kernel/driver.c"
#include "../kernel/drivers/sifive_test.c"
#include "../kernel/bus.c"
#include "../kernel/sync.c"
#include "../kernel/input.c"
#include "../kernel/drivers/gpio_keys.c"

/* ---- Mock GPIO / I2C / SPI backends ---- */

struct mock_gpio_state {
    enum gpio_mode modes[64];
    bool levels[64];
    enum gpio_irq_trigger triggers[64];
    gpio_irq_cb cbs[64];
    void *ctxs[64];
};

static int mock_gpio_configure(struct gpio_chip *chip, uint32_t pin, enum gpio_mode mode) {
    struct mock_gpio_state *st = chip->priv;
    st->modes[pin] = mode;
    return 0;
}

static int mock_gpio_read(struct gpio_chip *chip, uint32_t pin) {
    struct mock_gpio_state *st = chip->priv;
    return st->levels[pin] ? 1 : 0;
}

static int mock_gpio_write(struct gpio_chip *chip, uint32_t pin, bool high) {
    struct mock_gpio_state *st = chip->priv;
    st->levels[pin] = high;
    return 0;
}

static int mock_gpio_set_irq(struct gpio_chip *chip, uint32_t pin,
                             enum gpio_irq_trigger trigger, gpio_irq_cb cb, void *ctx) {
    struct mock_gpio_state *st = chip->priv;
    st->triggers[pin] = trigger;
    st->cbs[pin] = cb;
    st->ctxs[pin] = ctx;
    return 0;
}

static const struct gpio_ops mock_gpio_ops = {
    .configure = mock_gpio_configure,
    .read = mock_gpio_read,
    .write = mock_gpio_write,
    .set_irq = mock_gpio_set_irq,
};

struct mock_i2c_state {
    uint16_t last_addr;
    uint32_t last_count;
    uint8_t last_tx[8];
    uint32_t last_tx_len;
    unsigned resets;
};

static int mock_i2c_transfer(struct i2c_bus *bus, const struct i2c_msg *msgs, uint32_t count) {
    struct mock_i2c_state *st = bus->priv;
    st->last_addr = msgs[0].addr;
    st->last_count = count;
    for (uint32_t i = 0; i < count; i++) {
        if (msgs[i].flags == I2C_MSG_WRITE) {
            st->last_tx_len = msgs[i].len;
            if (msgs[i].len <= sizeof st->last_tx) {
                memcpy(st->last_tx, msgs[i].buf, msgs[i].len);
            }
        } else {
            for (uint32_t b = 0; b < msgs[i].len; b++) {
                msgs[i].buf[b] = (uint8_t)(0x40u + b);
            }
        }
    }
    return 0;
}

static int mock_i2c_reset(struct i2c_bus *bus) {
    struct mock_i2c_state *st = bus->priv;
    st->resets++;
    return 0;
}

static const struct i2c_ops mock_i2c_ops = {
    .transfer = mock_i2c_transfer,
    .reset = mock_i2c_reset,
};

struct mock_spi_state {
    uint32_t last_hz;
    uint8_t last_mode;
    uint8_t last_cs;
    uint8_t last_tx[8];
    uint32_t last_tx_len;
};

static int mock_spi_transfer(struct spi_bus *bus, const struct spi_config *cfg,
                             const struct spi_transfer *xfers, uint32_t count) {
    struct mock_spi_state *st = bus->priv;
    st->last_hz = cfg->hz;
    st->last_mode = cfg->mode;
    st->last_cs = cfg->cs;
    for (uint32_t i = 0; i < count; i++) {
        if (xfers[i].tx && xfers[i].len <= sizeof st->last_tx) {
            memcpy(st->last_tx, xfers[i].tx, xfers[i].len);
            st->last_tx_len = xfers[i].len;
        }
        if (xfers[i].rx) {
            for (uint32_t b = 0; b < xfers[i].len; b++) {
                xfers[i].rx[b] = (uint8_t)(0x6cu + b); /* e.g. LSM6DSO WHO_AM_I */
            }
        }
    }
    return 0;
}

static const struct spi_ops mock_spi_ops = {
    .transfer = mock_spi_transfer,
};

static void dummy_gpio_irq(uint32_t pin, void *ctx) {
    (void)pin;
    (void)ctx;
}

static void test_syscon(void) {
    uint32_t mock_finisher = 0;
    assert(sifive_test_poweroff() == -1);
    assert(sifive_test_reboot() == -1);
    assert(sifive_test_fail(1) == -1);

    driver_registry_reset();
    assert(driver_register(&sifive_test_driver) == 0);
    static struct device syscon = {
        .name = "syscon0",
        .driver = SIFIVE_TEST_DRIVER_NAME,
        .irq = -1,
    };
    syscon.base = (uintptr_t)&mock_finisher;
    assert(device_register(&syscon) == 0);
    assert(drivers_probe() == 1 && syscon.bound == &sifive_test_driver);

    assert(sifive_test_poweroff() == 0 && mock_finisher == SIFIVE_TEST_PASS);
    assert(sifive_test_reboot() == 0 && mock_finisher == SIFIVE_TEST_RESET);
    assert(sifive_test_fail(7) == 0 && mock_finisher == (SIFIVE_TEST_FAIL | (7u << 16)));
}

static void test_buses(void) {
    bus_registry_reset();

    struct mock_gpio_state gstate = {0};
    struct gpio_chip chip = {
        .name = "gpio0",
        .pin_count = 64,
        .ops = &mock_gpio_ops,
        .priv = &gstate,
    };
    assert(gpio_register(&chip) == 0);
    assert(gpio_register(&chip) == -1); /* duplicate */
    assert(gpio_find("gpio0") == &chip && gpio_find("nope") == NULL);

    assert(gpio_configure(&chip, 19, GPIO_INPUT_PULLUP) == 0);
    assert(gpio_configure(&chip, 64, GPIO_INPUT) == -1); /* out of bounds */
    assert(gpio_write(&chip, 19, true) == 0 && gpio_read(&chip, 19) == 1);
    assert(gpio_read(&chip, 64) == -1);
    assert(gpio_set_irq(&chip, 19, GPIO_IRQ_FALLING, NULL, NULL) == -1);
    assert(gpio_set_irq(&chip, 19, GPIO_IRQ_FALLING, dummy_gpio_irq, NULL) == 0);
    assert(gpio_set_irq(&chip, 19, GPIO_IRQ_NONE, NULL, NULL) == 0);

    struct mock_i2c_state istate = {0};
    struct i2c_bus i2c3 = {.name = "i2c3", .ops = &mock_i2c_ops, .priv = &istate};
    assert(i2c_register(&i2c3) == 0);
    assert(i2c_register(&i2c3) == -1);
    assert(i2c_find("i2c3") == &i2c3);

    const uint8_t reg_addr[2] = {0x80, 0x00};
    uint8_t rx[4] = {0};
    assert(i2c_write_read(&i2c3, 0x80, reg_addr, 2, rx, 4) == -1); /* > 7-bit addr */
    assert(i2c_write_read(&i2c3, 0x20, NULL, 2, rx, 4) == -1);
    assert(i2c_write_read(&i2c3, 0x20, reg_addr, 2, rx, 4) == 0);
    assert(istate.last_addr == 0x20 && istate.last_count == 2 && istate.last_tx_len == 2);
    assert(rx[0] == 0x40 && rx[3] == 0x43);
    assert(i2c_reset(&i2c3) == 0 && istate.resets == 1);

    struct mock_spi_state sstate = {0};
    struct spi_bus spi1 = {.name = "sens_spi1", .ops = &mock_spi_ops, .priv = &sstate};
    assert(spi_register(&spi1) == 0 && spi_find("sens_spi1") == &spi1);
    struct spi_config bad_cfg = {.hz = 0, .mode = 0, .cs = 0};
    struct spi_config cfg = {.hz = 8000000u, .mode = 3, .cs = 0};
    const uint8_t whoami_cmd = 0x8fu;
    uint8_t whoami = 0;
    assert(spi_write_then_read(&spi1, &bad_cfg, &whoami_cmd, 1, &whoami, 1) == -1);
    assert(spi_write_then_read(&spi1, &cfg, &whoami_cmd, 1, &whoami, 1) == 0);
    assert(sstate.last_hz == 8000000u && sstate.last_mode == 3 && whoami == 0x6cu);
}

static void expect_key(uint8_t action, uint16_t code) {
    struct input_event ev;
    assert(input_poll(&ev));
    assert(ev.type == INPUT_KEY && ev.action == action && ev.code == code);
}

static void test_input_and_gpio_keys(void) {
    struct input_event storage[8];
    assert(input_init(storage, 8) == 0);
    assert(input_pending() == 0 && input_dropped() == 0);

    /* Auto-timestamping and overflow drop accounting. */
    mock_ticks = 555;
    for (int i = 0; i < 8; i++) {
        struct input_event ev = {.type = INPUT_TOUCH, .action = INPUT_TOUCH_DOWN, .code = (uint16_t)i};
        assert(input_post(&ev));
    }
    struct input_event overflow_ev = {.type = INPUT_TOUCH, .action = INPUT_TOUCH_UP, .code = 9};
    assert(!input_post(&overflow_ev));
    assert(input_dropped() == 1 && input_pending() == 8);

    struct input_event out;
    assert(input_poll(&out) && out.timestamp_ticks == 555 && out.code == 0);
    for (int i = 1; i < 8; i++) {
        assert(input_poll(&out) && out.code == (uint16_t)i);
    }
    assert(input_pending() == 0);

    /* Configure two active-low buttons matching Bip 6 pins 19 and 54. */
    struct mock_gpio_state gstate = {0};
    gstate.levels[19] = true; /* idle high (active-low) */
    gstate.levels[54] = true;
    struct gpio_chip chip = {
        .name = "main_gpio",
        .pin_count = 64,
        .ops = &mock_gpio_ops,
        .priv = &gstate,
    };
    const struct gpio_key_desc keys[2] = {
        {.pin = 19, .code = 0, .active_low = true},
        {.pin = 54, .code = 1, .active_low = true},
    };
    struct gpio_keys_state ks;
    struct gpio_keys_config kcfg = {
        .chip = &chip,
        .keys = keys,
        .key_count = 2,
        .debounce_ticks = 3,
        .long_press_ticks = 50,
        .double_click_ticks = 20,
        .combo_window_ticks = 10,
    };
    assert(gpio_keys_init(&ks, &kcfg) == 0);
    assert(gstate.modes[19] == GPIO_INPUT_PULLUP && gstate.modes[54] == GPIO_INPUT_PULLUP);

    uint64_t t = 1000;
    /* 1) Glitch shorter than debounce_ticks (2 ticks) produces zero events. */
    gstate.levels[19] = false;
    gpio_keys_poll(&ks, t++);
    gpio_keys_poll(&ks, t++);
    gstate.levels[19] = true;
    gpio_keys_poll(&ks, t++);
    assert(input_pending() == 0);

    /* 2) Single short click -> PRESS, RELEASE, then SHORT_CLICK after window. */
    gstate.levels[19] = false;
    for (int i = 0; i < 5; i++) gpio_keys_poll(&ks, t++);
    expect_key(INPUT_KEY_PRESS, 0);
    assert(input_pending() == 0);

    gstate.levels[19] = true;
    for (int i = 0; i < 5; i++) gpio_keys_poll(&ks, t++);
    expect_key(INPUT_KEY_RELEASE, 0);
    assert(input_pending() == 0); /* waiting for double-click window */

    t += 21;
    gpio_keys_poll(&ks, t++);
    expect_key(INPUT_KEY_SHORT_CLICK, 0);
    assert(input_pending() == 0);

    /* 3) Double click -> PRESS, RELEASE, PRESS, RELEASE, DOUBLE_CLICK. */
    for (int click = 0; click < 2; click++) {
        gstate.levels[19] = false;
        for (int i = 0; i < 5; i++) gpio_keys_poll(&ks, t++);
        gstate.levels[19] = true;
        for (int i = 0; i < 5; i++) gpio_keys_poll(&ks, t++);
    }
    expect_key(INPUT_KEY_PRESS, 0);
    expect_key(INPUT_KEY_RELEASE, 0);
    expect_key(INPUT_KEY_PRESS, 0);
    expect_key(INPUT_KEY_RELEASE, 0);
    expect_key(INPUT_KEY_DOUBLE_CLICK, 0);
    t += 30;
    gpio_keys_poll(&ks, t++);
    assert(input_pending() == 0);

    /* 4) Long press -> PRESS, LONG_PRESS once, RELEASE (no SHORT_CLICK). */
    gstate.levels[54] = false;
    for (int i = 0; i < 4; i++) gpio_keys_poll(&ks, t++);
    expect_key(INPUT_KEY_PRESS, 1);
    t += 55;
    gpio_keys_poll(&ks, t++);
    gpio_keys_poll(&ks, t++); /* must not fire twice */
    expect_key(INPUT_KEY_LONG_PRESS, 1);
    assert(input_pending() == 0);
    gstate.levels[54] = true;
    for (int i = 0; i < 4; i++) gpio_keys_poll(&ks, t++);
    expect_key(INPUT_KEY_RELEASE, 1);
    t += 30;
    gpio_keys_poll(&ks, t++);
    assert(input_pending() == 0);

    /* 5) Two-key combo within combo_window_ticks -> COMBO(mask=0x3), suppresses clicks/long. */
    gstate.levels[19] = false;
    for (int i = 0; i < 4; i++) gpio_keys_poll(&ks, t++);
    gstate.levels[54] = false;
    for (int i = 0; i < 4; i++) gpio_keys_poll(&ks, t++);
    expect_key(INPUT_KEY_PRESS, 0);
    expect_key(INPUT_KEY_PRESS, 1);
    expect_key(INPUT_KEY_COMBO, 0x3u);
    t += 60;
    gpio_keys_poll(&ks, t++); /* combo suppresses long press */
    assert(input_pending() == 0);

    gstate.levels[19] = true;
    gstate.levels[54] = true;
    for (int i = 0; i < 4; i++) gpio_keys_poll(&ks, t++);
    expect_key(INPUT_KEY_RELEASE, 0);
    expect_key(INPUT_KEY_RELEASE, 1);
    t += 30;
    gpio_keys_poll(&ks, t++);
    assert(input_pending() == 0 && mock_irq_depth == 0);
}

int main(void) {
    test_syscon();
    test_buses();
    test_input_and_gpio_keys();
    printf("PASS: syscon, bus (GPIO/I2C/SPI), input queue and gpio_keys\n");
    return 0;
}
