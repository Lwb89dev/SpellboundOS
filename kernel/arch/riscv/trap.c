/* Trap dispatch: machine timer interrupts drive the tick; any exception is
 * reported and the hart is parked (no recovery yet). */
#include "riscv.h"
#include "timer.h"
#include "../../console.h"

extern void trap_vector(void);

void trap_init(void) {
    write_csr(mtvec, (uint32_t)trap_vector); /* direct mode (low bits 0) */
}

void trap_handler(uint32_t mcause, uint32_t mepc, struct trap_frame *frame) {
    (void)frame;
    if (mcause & MCAUSE_INTERRUPT) {
        switch (MCAUSE_CODE(mcause)) {
        case IRQ_MACHINE_TIMER:
            timer_on_tick();
            return;
        default:
            return; /* ignore other interrupt sources for now */
        }
    }
    /* Synchronous exception: report and park. */
    console_puts("\n*** trap: mcause=");
    console_puthex(mcause);
    console_puts(" mepc=");
    console_puthex(mepc);
    console_puts(" ***\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}
