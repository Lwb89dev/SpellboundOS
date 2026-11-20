/* Minimal console over the QEMU virt 16550 UART (not the Bip 6 UART). */
#ifndef SPELLBOUND_CONSOLE_H
#define SPELLBOUND_CONSOLE_H

#include <stdint.h>

void console_putc(char c);
void console_puts(const char *s);
void console_puthex(uint32_t value); /* 0x-prefixed 8-digit hex */
void console_putdec(uint32_t value);
int console_getc(void); /* -1 if no byte ready */

#endif /* SPELLBOUND_CONSOLE_H */
