/* SiFive Test syscon MMIO driver for QEMU virt shutdown and reset. */
#include "sifive_test.h"
#include <stddef.h>

static volatile uint32_t *finisher;

static int sifive_test_probe(struct device *dev) {
    if (!dev || !dev->base || finisher) {
        return -1;
    }
    finisher = (volatile uint32_t *)dev->base;
    dev->drvdata = (void *)(uintptr_t)finisher;
    return 0;
}

int sifive_test_poweroff(void) {
    if (!finisher) {
        return -1;
    }
    *finisher = SIFIVE_TEST_PASS;
    return 0;
}

int sifive_test_reboot(void) {
    if (!finisher) {
        return -1;
    }
    *finisher = SIFIVE_TEST_RESET;
    return 0;
}

int sifive_test_fail(uint16_t code) {
    if (!finisher) {
        return -1;
    }
    *finisher = SIFIVE_TEST_FAIL | ((uint32_t)code << 16);
    return 0;
}

const struct driver sifive_test_driver = {
    .name = SIFIVE_TEST_DRIVER_NAME,
    .probe = sifive_test_probe,
};
