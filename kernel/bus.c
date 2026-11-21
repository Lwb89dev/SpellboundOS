/* Named registries and validated dispatch wrappers for GPIO, I2C and SPI buses. */
#include "bus.h"
#include <stddef.h>

#define MAX_BUSES 8

static struct gpio_chip *gpio_chips[MAX_BUSES];
static int gpio_count;

static struct i2c_bus *i2c_buses[MAX_BUSES];
static int i2c_count;

static struct spi_bus *spi_buses[MAX_BUSES];
static int spi_count;

static bool bus_str_eq(const char *a, const char *b) {
    if (!a || !b) {
        return a == b;
    }
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return *a == *b;
}

/* ---- GPIO ---- */

int gpio_register(struct gpio_chip *chip) {
    if (gpio_count >= MAX_BUSES || !chip || !chip->name || !chip->name[0] ||
        chip->pin_count == 0 || !chip->ops) {
        return -1;
    }
    for (int i = 0; i < gpio_count; i++) {
        if (gpio_chips[i] == chip || bus_str_eq(gpio_chips[i]->name, chip->name)) {
            return -1;
        }
    }
    gpio_chips[gpio_count++] = chip;
    return 0;
}

struct gpio_chip *gpio_find(const char *name) {
    if (!name || !name[0]) {
        return NULL;
    }
    for (int i = 0; i < gpio_count; i++) {
        if (bus_str_eq(gpio_chips[i]->name, name)) {
            return gpio_chips[i];
        }
    }
    return NULL;
}

int gpio_configure(struct gpio_chip *chip, uint32_t pin, enum gpio_mode mode) {
    if (!chip || !chip->ops || !chip->ops->configure || pin >= chip->pin_count ||
        mode > GPIO_OUTPUT) {
        return -1;
    }
    return chip->ops->configure(chip, pin, mode);
}

int gpio_read(struct gpio_chip *chip, uint32_t pin) {
    if (!chip || !chip->ops || !chip->ops->read || pin >= chip->pin_count) {
        return -1;
    }
    return chip->ops->read(chip, pin);
}

int gpio_write(struct gpio_chip *chip, uint32_t pin, bool high) {
    if (!chip || !chip->ops || !chip->ops->write || pin >= chip->pin_count) {
        return -1;
    }
    return chip->ops->write(chip, pin, high);
}

int gpio_set_irq(struct gpio_chip *chip, uint32_t pin, enum gpio_irq_trigger trigger,
                 gpio_irq_cb cb, void *context) {
    if (!chip || !chip->ops || !chip->ops->set_irq || pin >= chip->pin_count ||
        trigger > GPIO_IRQ_BOTH) {
        return -1;
    }
    if (trigger != GPIO_IRQ_NONE && !cb) {
        return -1;
    }
    return chip->ops->set_irq(chip, pin, trigger, cb, context);
}

/* ---- I2C ---- */

int i2c_register(struct i2c_bus *bus) {
    if (i2c_count >= MAX_BUSES || !bus || !bus->name || !bus->name[0] ||
        !bus->ops || !bus->ops->transfer) {
        return -1;
    }
    for (int i = 0; i < i2c_count; i++) {
        if (i2c_buses[i] == bus || bus_str_eq(i2c_buses[i]->name, bus->name)) {
            return -1;
        }
    }
    i2c_buses[i2c_count++] = bus;
    return 0;
}

struct i2c_bus *i2c_find(const char *name) {
    if (!name || !name[0]) {
        return NULL;
    }
    for (int i = 0; i < i2c_count; i++) {
        if (bus_str_eq(i2c_buses[i]->name, name)) {
            return i2c_buses[i];
        }
    }
    return NULL;
}

int i2c_transfer(struct i2c_bus *bus, const struct i2c_msg *msgs, uint32_t count) {
    if (!bus || !bus->ops || !bus->ops->transfer || !msgs || count == 0) {
        return -1;
    }
    for (uint32_t i = 0; i < count; i++) {
        if (msgs[i].addr > 0x7fu || (msgs[i].flags & ~I2C_MSG_READ) != 0) {
            return -1;
        }
        if (msgs[i].len > 0 && !msgs[i].buf) {
            return -1;
        }
    }
    return bus->ops->transfer(bus, msgs, count);
}

int i2c_write(struct i2c_bus *bus, uint16_t addr, const uint8_t *data, uint32_t len) {
    struct i2c_msg msg = {
        .addr = addr,
        .flags = I2C_MSG_WRITE,
        .buf = (uint8_t *)(uintptr_t)data,
        .len = len,
    };
    return i2c_transfer(bus, &msg, 1);
}

int i2c_read(struct i2c_bus *bus, uint16_t addr, uint8_t *out, uint32_t len) {
    struct i2c_msg msg = {
        .addr = addr,
        .flags = I2C_MSG_READ,
        .buf = out,
        .len = len,
    };
    return i2c_transfer(bus, &msg, 1);
}

int i2c_write_read(struct i2c_bus *bus, uint16_t addr,
                   const uint8_t *tx, uint32_t tx_len,
                   uint8_t *rx, uint32_t rx_len) {
    struct i2c_msg msgs[2] = {
        {.addr = addr, .flags = I2C_MSG_WRITE, .buf = (uint8_t *)(uintptr_t)tx, .len = tx_len},
        {.addr = addr, .flags = I2C_MSG_READ, .buf = rx, .len = rx_len},
    };
    return i2c_transfer(bus, msgs, 2);
}

int i2c_reset(struct i2c_bus *bus) {
    if (!bus || !bus->ops || !bus->ops->reset) {
        return -1;
    }
    return bus->ops->reset(bus);
}

/* ---- SPI ---- */

int spi_register(struct spi_bus *bus) {
    if (spi_count >= MAX_BUSES || !bus || !bus->name || !bus->name[0] ||
        !bus->ops || !bus->ops->transfer) {
        return -1;
    }
    for (int i = 0; i < spi_count; i++) {
        if (spi_buses[i] == bus || bus_str_eq(spi_buses[i]->name, bus->name)) {
            return -1;
        }
    }
    spi_buses[spi_count++] = bus;
    return 0;
}

struct spi_bus *spi_find(const char *name) {
    if (!name || !name[0]) {
        return NULL;
    }
    for (int i = 0; i < spi_count; i++) {
        if (bus_str_eq(spi_buses[i]->name, name)) {
            return spi_buses[i];
        }
    }
    return NULL;
}

int spi_transfer(struct spi_bus *bus, const struct spi_config *cfg,
                 const struct spi_transfer *xfers, uint32_t count) {
    if (!bus || !bus->ops || !bus->ops->transfer || !cfg || cfg->hz == 0 ||
        cfg->mode > 3u || !xfers || count == 0) {
        return -1;
    }
    for (uint32_t i = 0; i < count; i++) {
        if (xfers[i].len > 0 && !xfers[i].tx && !xfers[i].rx) {
            return -1;
        }
    }
    return bus->ops->transfer(bus, cfg, xfers, count);
}

int spi_write_then_read(struct spi_bus *bus, const struct spi_config *cfg,
                        const uint8_t *tx, uint32_t tx_len,
                        uint8_t *rx, uint32_t rx_len) {
    struct spi_transfer xfers[2] = {
        {.tx = tx, .rx = NULL, .len = tx_len},
        {.tx = NULL, .rx = rx, .len = rx_len},
    };
    return spi_transfer(bus, cfg, xfers, 2);
}

void bus_registry_reset(void) {
    gpio_count = 0;
    i2c_count = 0;
    spi_count = 0;
}
