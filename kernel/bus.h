/* Hardware-independent GPIO, I2C and SPI bus abstractions. Portable and
 * freestanding so peripheral drivers can be tested on the host. */
#ifndef SPELLBOUND_BUS_H
#define SPELLBOUND_BUS_H

#include <stdbool.h>
#include <stdint.h>

/* ---- GPIO ---- */

enum gpio_mode {
    GPIO_INPUT = 0,
    GPIO_INPUT_PULLUP = 1,
    GPIO_INPUT_PULLDOWN = 2,
    GPIO_OUTPUT = 3,
};

enum gpio_irq_trigger {
    GPIO_IRQ_NONE = 0,
    GPIO_IRQ_RISING = 1,
    GPIO_IRQ_FALLING = 2,
    GPIO_IRQ_BOTH = 3,
};

typedef void (*gpio_irq_cb)(uint32_t pin, void *context);

struct gpio_chip;

struct gpio_ops {
    int (*configure)(struct gpio_chip *chip, uint32_t pin, enum gpio_mode mode);
    int (*read)(struct gpio_chip *chip, uint32_t pin);
    int (*write)(struct gpio_chip *chip, uint32_t pin, bool high);
    int (*set_irq)(struct gpio_chip *chip, uint32_t pin, enum gpio_irq_trigger trigger,
                   gpio_irq_cb cb, void *context);
};

struct gpio_chip {
    const char *name;
    uint32_t pin_count;
    const struct gpio_ops *ops;
    void *priv;
};

int gpio_register(struct gpio_chip *chip);
struct gpio_chip *gpio_find(const char *name);
int gpio_configure(struct gpio_chip *chip, uint32_t pin, enum gpio_mode mode);
int gpio_read(struct gpio_chip *chip, uint32_t pin);
int gpio_write(struct gpio_chip *chip, uint32_t pin, bool high);
int gpio_set_irq(struct gpio_chip *chip, uint32_t pin, enum gpio_irq_trigger trigger,
                 gpio_irq_cb cb, void *context);

/* ---- I2C ---- */

#define I2C_MSG_WRITE 0u
#define I2C_MSG_READ 1u

struct i2c_msg {
    uint16_t addr;  /* 7-bit target address (0x00..0x7f) */
    uint16_t flags; /* I2C_MSG_WRITE or I2C_MSG_READ */
    uint8_t *buf;
    uint32_t len;
};

struct i2c_bus;

struct i2c_ops {
    int (*transfer)(struct i2c_bus *bus, const struct i2c_msg *msgs, uint32_t count);
    int (*reset)(struct i2c_bus *bus);
};

struct i2c_bus {
    const char *name;
    const struct i2c_ops *ops;
    void *priv;
};

int i2c_register(struct i2c_bus *bus);
struct i2c_bus *i2c_find(const char *name);
int i2c_transfer(struct i2c_bus *bus, const struct i2c_msg *msgs, uint32_t count);
int i2c_write(struct i2c_bus *bus, uint16_t addr, const uint8_t *data, uint32_t len);
int i2c_read(struct i2c_bus *bus, uint16_t addr, uint8_t *out, uint32_t len);
int i2c_write_read(struct i2c_bus *bus, uint16_t addr,
                   const uint8_t *tx, uint32_t tx_len,
                   uint8_t *rx, uint32_t rx_len);
int i2c_reset(struct i2c_bus *bus);

/* ---- SPI ---- */

struct spi_config {
    uint32_t hz;
    uint8_t mode; /* SPI mode 0..3 (CPOL/CPHA) */
    uint8_t cs;   /* board-specific chip-select index */
};

struct spi_transfer {
    const uint8_t *tx;
    uint8_t *rx;
    uint32_t len;
};

struct spi_bus;

struct spi_ops {
    int (*transfer)(struct spi_bus *bus, const struct spi_config *cfg,
                    const struct spi_transfer *xfers, uint32_t count);
};

struct spi_bus {
    const char *name;
    const struct spi_ops *ops;
    void *priv;
};

int spi_register(struct spi_bus *bus);
struct spi_bus *spi_find(const char *name);
int spi_transfer(struct spi_bus *bus, const struct spi_config *cfg,
                 const struct spi_transfer *xfers, uint32_t count);
int spi_write_then_read(struct spi_bus *bus, const struct spi_config *cfg,
                        const uint8_t *tx, uint32_t tx_len,
                        uint8_t *rx, uint32_t rx_len);

/* Clears all bus registrations (intended for unit tests). */
void bus_registry_reset(void);

#endif /* SPELLBOUND_BUS_H */
