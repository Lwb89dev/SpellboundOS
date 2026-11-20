/* SpellboundOS RV32 bring-up: console, machine-mode traps and a periodic timer
 * tick. QEMU virt only; the Bip 6 board support is separate. */
#include <stdint.h>

#include "console.h"
#include "arch/riscv/riscv.h"
#include "arch/riscv/timer.h"
#include "arch/riscv/trap.h"

#define TICK_HZ 100u /* timer interrupts per second */

void kernel_main(void) {
    console_puts("SpellboundOS RV32 foundation\n");
    console_puts("QEMU virt only; Bluetooth unavailable\n");

    trap_init();

    /* Deterministic echo first (polled, interrupts still off). */
    console_puts("Type a character to echo: ");
    int c;
    do {
        c = console_getc();
    } while (c < 0);
    console_putc((char)c);

    /* Bring the periodic tick online. */
    console_puts("\ntimer: 100 Hz tick online\n");
    timer_init(TICK_HZ);
    set_csr(mstatus, MSTATUS_MIE);

    uint64_t last_second = 0;
    for (;;) {
        uint64_t t = timer_ticks();
        uint64_t second = t / TICK_HZ;
        if (second != last_second) {
            last_second = second;
            console_puts("tick ");
            console_putdec((uint32_t)second);
            console_putc('\n');
        }
        int k = console_getc();
        if (k >= 0) {
            console_putc((char)k);
        }
        __asm__ volatile("wfi"); /* wake on the next timer interrupt */
    }
}
