/* QEMU virt 16550 only; this MMIO mapping is not the Bip 6 UART. */
#include <stdint.h>

static volatile uint8_t *const uart = (volatile uint8_t *)0x10000000u;
static void putc_uart(char c) {
    while ((uart[5] & 0x20u) == 0) { }
    uart[0] = (uint8_t)c;
}
static void puts_uart(const char *s) {
    while (*s) putc_uart(*s++);
}

void kernel_main(void) {
    puts_uart("SpellboundFit RV32 prototype\r\n");
    puts_uart("QEMU virt only; Bluetooth unavailable\r\n");
    puts_uart("Type a character to echo: ");
    for (;;) {
        if (uart[5] & 1u) {
            char c = (char)uart[0];
            putc_uart(c);
        }
    }
}
