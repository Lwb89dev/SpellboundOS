/* Console over the QEMU virt 16550 UART at 0x10000000. Board-specific; the
 * Bip 6 UART differs and will have its own driver. */
#include "console.h"

static volatile uint8_t *const uart = (volatile uint8_t *)0x10000000u;

#define UART_THR 0u /* transmit holding */
#define UART_RBR 0u /* receive buffer */
#define UART_LSR 5u /* line status */
#define LSR_DR 0x01u /* data ready */
#define LSR_THRE 0x20u /* transmit holding empty */

void console_putc(char c) {
    while ((uart[UART_LSR] & LSR_THRE) == 0) {
    }
    uart[UART_THR] = (uint8_t)c;
}

void console_puts(const char *s) {
    while (*s) {
        if (*s == '\n') {
            console_putc('\r');
        }
        console_putc(*s++);
    }
}

void console_puthex(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    console_putc('0');
    console_putc('x');
    for (int shift = 28; shift >= 0; shift -= 4) {
        console_putc(digits[(value >> shift) & 0xfu]);
    }
}

void console_putdec(uint32_t value) {
    char buf[10];
    int i = 0;
    if (value == 0) {
        console_putc('0');
        return;
    }
    while (value > 0 && i < (int)sizeof(buf)) {
        buf[i++] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    while (i > 0) {
        console_putc(buf[--i]);
    }
}

int console_getc(void) {
    if (uart[UART_LSR] & LSR_DR) {
        return (int)(uint8_t)uart[UART_RBR];
    }
    return -1;
}
