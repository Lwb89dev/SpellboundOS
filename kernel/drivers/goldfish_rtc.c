/* Goldfish RTC driver: 64-bit nanosecond wall clock and one-shot alarm IRQ. */
#include "goldfish_rtc.h"
#include "../rtc.h"
#include <stdbool.h>
#include <stddef.h>

#ifndef SPELLBOUND_HOST_TEST
#include "plic.h"
#include "../arch/riscv/riscv.h"
#endif

/* 32-bit word register offsets (byte offsets 0x00..0x1c). */
#define RTC_TIME_LOW 0u
#define RTC_TIME_HIGH 1u
#define RTC_ALARM_LOW 2u
#define RTC_ALARM_HIGH 3u
#define RTC_IRQ_ENABLED 4u
#define RTC_CLEAR_ALARM 5u
#define RTC_ALARM_STATUS 6u
#define RTC_CLEAR_INTERRUPT 7u

struct goldfish_rtc_dev {
    volatile uint32_t *regs;
    int irq;
    bool irq_registered;
    rtc_alarm_cb alarm_cb;
    void *alarm_ctx;
};

static struct goldfish_rtc_dev primary_dev;

static uint64_t goldfish_read_ns(uintptr_t context) {
    struct goldfish_rtc_dev *dev = (struct goldfish_rtc_dev *)context;
    /* Reading TIME_LOW latches TIME_HIGH in hardware; mask interrupts so a
     * concurrent ISR cannot disturb the latched upper half. */
    uint32_t previous = irq_save();
    uint32_t lo = dev->regs[RTC_TIME_LOW];
    uint32_t hi = dev->regs[RTC_TIME_HIGH];
    irq_restore(previous);
    return ((uint64_t)hi << 32) | lo;
}

static void goldfish_irq(void *context) {
    struct goldfish_rtc_dev *dev = (struct goldfish_rtc_dev *)context;
    dev->regs[RTC_CLEAR_INTERRUPT] = 1u;
    dev->regs[RTC_IRQ_ENABLED] = 0u;
    rtc_alarm_cb cb = dev->alarm_cb;
    void *cb_ctx = dev->alarm_ctx;
    dev->alarm_cb = NULL;
    dev->alarm_ctx = NULL;
    if (cb) {
        cb(cb_ctx);
    }
}

static int goldfish_set_alarm_ns(uintptr_t context, uint64_t time_ns,
                                 rtc_alarm_cb cb, void *cb_ctx) {
    struct goldfish_rtc_dev *dev = (struct goldfish_rtc_dev *)context;
    if (dev->irq <= 0) {
        return -1;
    }
    uint32_t previous = irq_save();
    if (!dev->irq_registered) {
        if (plic_register((unsigned)dev->irq, goldfish_irq, dev) != 0) {
            irq_restore(previous);
            return -1;
        }
        dev->irq_registered = true;
    }
    dev->regs[RTC_IRQ_ENABLED] = 0u;
    dev->regs[RTC_CLEAR_ALARM] = 1u;
    dev->regs[RTC_CLEAR_INTERRUPT] = 1u;
    dev->alarm_cb = cb;
    dev->alarm_ctx = cb_ctx;
    dev->regs[RTC_IRQ_ENABLED] = 1u;
    /* Write ALARM_HIGH first: writing ALARM_LOW arms the hardware timer. */
    dev->regs[RTC_ALARM_HIGH] = (uint32_t)(time_ns >> 32);
    dev->regs[RTC_ALARM_LOW] = (uint32_t)time_ns;
    irq_restore(previous);
    return 0;
}

static int goldfish_clear_alarm(uintptr_t context) {
    struct goldfish_rtc_dev *dev = (struct goldfish_rtc_dev *)context;
    uint32_t previous = irq_save();
    dev->regs[RTC_IRQ_ENABLED] = 0u;
    dev->regs[RTC_CLEAR_ALARM] = 1u;
    dev->regs[RTC_CLEAR_INTERRUPT] = 1u;
    dev->alarm_cb = NULL;
    dev->alarm_ctx = NULL;
    irq_restore(previous);
    return 0;
}

static const struct rtc_ops goldfish_ops = {
    .read_ns = goldfish_read_ns,
    .set_alarm_ns = goldfish_set_alarm_ns,
    .clear_alarm = goldfish_clear_alarm,
};

static int goldfish_probe(struct device *dev) {
    if (!dev || !dev->base || primary_dev.regs) {
        return -1;
    }
    volatile uint32_t *regs = (volatile uint32_t *)dev->base;
    regs[RTC_IRQ_ENABLED] = 0u;
    regs[RTC_CLEAR_ALARM] = 1u;
    regs[RTC_CLEAR_INTERRUPT] = 1u;
    if (rtc_bind(&goldfish_ops, (uintptr_t)&primary_dev) != 0) {
        return -1;
    }
    primary_dev.regs = regs;
    primary_dev.irq = dev->irq;
    primary_dev.irq_registered = false;
    primary_dev.alarm_cb = NULL;
    primary_dev.alarm_ctx = NULL;
    dev->drvdata = &primary_dev;
    return 0;
}

const struct driver goldfish_rtc_driver = {
    .name = GOLDFISH_RTC_DRIVER_NAME,
    .probe = goldfish_probe,
};
