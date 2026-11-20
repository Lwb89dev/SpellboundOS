/* Console I/O over a preconfigured, byte-spaced 16550 UART. */
#include "uart16550.h"
#include "plic.h"
#include "../arch/riscv/riscv.h"
#include "../console.h"
#include <stdbool.h>

#define UART_THR 0u
#define UART_RBR 0u
#define UART_IER 1u
#define UART_LSR 5u
#define IER_RX 0x01u
#define LSR_DR 0x01u
#define LSR_THRE 0x20u
#define RX_CAPACITY 64u

struct uart_port {
    volatile uint8_t *registers;
    bool rx_irq;
    unsigned head, tail;
    uint8_t rx[RX_CAPACITY];
};

static struct uart_port console_port;

static void uart_putc(uintptr_t context, char c) {
    struct uart_port *port = (struct uart_port *)context;
    volatile uint8_t *registers = port->registers;
    while ((registers[UART_LSR] & LSR_THRE) == 0) {
    }
    registers[UART_THR] = (uint8_t)c;
}

static int uart_getc(uintptr_t context) {
    struct uart_port *port = (struct uart_port *)context;
    if (port->rx_irq) {
        uint32_t previous = irq_save();
        int result = -1;
        if (port->head != port->tail) {
            result = port->rx[port->tail];
            port->tail = (port->tail + 1u) % RX_CAPACITY;
        }
        irq_restore(previous);
        return result;
    }
    volatile uint8_t *registers = port->registers;
    if (registers[UART_LSR] & LSR_DR) {
        return registers[UART_RBR];
    }
    return -1;
}

static void uart_receive(void *context) {
    struct uart_port *port = context;
    volatile uint8_t *registers = port->registers;
    for (unsigned i = 0; i < RX_CAPACITY && (registers[UART_LSR] & LSR_DR); i++) {
        uint8_t byte = registers[UART_RBR];
        unsigned next = (port->head + 1u) % RX_CAPACITY;
        if (next != port->tail) {
            port->rx[port->head] = byte;
            port->head = next;
        }
    }
}

static const struct console_io uart_io = {
    .putc = uart_putc,
    .getc = uart_getc,
};

static int uart_probe(struct device *dev) {
    if (!dev->base || console_port.registers) {
        return -1;
    }
    if (console_bind(&uart_io, (uintptr_t)&console_port) != 0) {
        return -1;
    }
    console_port.registers = (volatile uint8_t *)dev->base;
    dev->drvdata = &console_port;
    return 0;
}

int uart16550_enable_rx_irq(struct device *dev) {
    if (!dev || dev->bound != &uart16550_driver || dev->irq <= 0) {
        return -1;
    }
    struct uart_port *port = dev->drvdata;
    uint32_t previous = irq_save();
    if (!port->rx_irq) {
        if (plic_register((unsigned)dev->irq, uart_receive, port) != 0) {
            irq_restore(previous);
            return -1;
        }
        port->rx_irq = true;
        port->registers[UART_IER] = IER_RX;
    }
    irq_restore(previous);
    return 0;
}

const struct driver uart16550_driver = {
    .name = UART16550_DRIVER_NAME,
    .probe = uart_probe,
};
