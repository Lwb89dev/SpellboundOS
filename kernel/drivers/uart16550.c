/* Polled byte access to a preconfigured, byte-spaced 16550 UART. */
#include "uart16550.h"
#include "../console.h"

#define UART_THR 0u
#define UART_RBR 0u
#define UART_LSR 5u
#define LSR_DR 0x01u
#define LSR_THRE 0x20u

static void uart_putc(uintptr_t base, char c) {
    volatile uint8_t *registers = (volatile uint8_t *)base;
    while ((registers[UART_LSR] & LSR_THRE) == 0) {
    }
    registers[UART_THR] = (uint8_t)c;
}

static int uart_getc(uintptr_t base) {
    volatile uint8_t *registers = (volatile uint8_t *)base;
    if (registers[UART_LSR] & LSR_DR) {
        return registers[UART_RBR];
    }
    return -1;
}

static const struct console_io uart_io = {
    .putc = uart_putc,
    .getc = uart_getc,
};

static int uart_probe(struct device *dev) {
    if (dev->base == 0) {
        return -1;
    }
    return console_bind(&uart_io, dev->base);
}

const struct driver uart16550_driver = {
    .name = UART16550_DRIVER_NAME,
    .probe = uart_probe,
};
