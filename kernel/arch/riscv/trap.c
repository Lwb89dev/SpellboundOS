/* Machine timer interrupts advance the clock. Unhandled traps stop the hart. */
#include "riscv.h"
#include "timer.h"
#include "../../console.h"

extern void trap_vector(void);

void trap_init(void) {
    write_csr(mtvec, (uint32_t)trap_vector); /* direct mode (low bits 0) */
}

void trap_handler(uint32_t mcause, uint32_t mepc, struct trap_frame *frame) {
    (void)frame;
    if (mcause == (MCAUSE_INTERRUPT | IRQ_MACHINE_TIMER)) {
        timer_on_tick();
        return;
    }

    uint32_t mtval = read_csr(mtval);
    /* Leave pending sources masked so a parked hart stays idle. */
    write_csr(mie, 0u);
    console_puts("\n*** trap: mcause=");
    console_puthex(mcause);
    console_puts(" mepc=");
    console_puthex(mepc);
    console_puts(" mtval=");
    console_puthex(mtval);
    console_puts(" ***\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}
