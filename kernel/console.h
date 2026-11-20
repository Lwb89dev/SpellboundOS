/* Minimal console over a board-provided byte stream. */
#ifndef SPELLBOUND_CONSOLE_H
#define SPELLBOUND_CONSOLE_H

#include <stdint.h>

struct console_io {
    void (*putc)(uintptr_t context, char c);
    int (*getc)(uintptr_t context);
};

/* Bind the primary console once during boot. The ops must remain valid. */
int console_bind(const struct console_io *io, uintptr_t context);

void console_putc(char c);
void console_puts(const char *s);
void console_puthex(uint32_t value); /* 0x-prefixed 8-digit hex */
void console_putdec(uint32_t value);
int console_getc(void); /* -1 if no byte ready */

#endif /* SPELLBOUND_CONSOLE_H */
