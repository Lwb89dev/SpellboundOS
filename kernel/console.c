/* Formatting and byte I/O over the primary console. */
#include "console.h"

static const struct console_io *console;
static uintptr_t context;

int console_bind(const struct console_io *io, uintptr_t cookie) {
    if (!io || !io->putc || !io->getc || console) {
        return -1;
    }
    context = cookie;
    console = io;
    return 0;
}

void console_putc(char c) {
    if (console) {
        console->putc(context, c);
    }
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
    return console ? console->getc(context) : -1;
}
