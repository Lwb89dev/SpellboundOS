/* Machine timer interrupts advance the clock. Unhandled traps stop the hart. */
#include "riscv.h"
#include "timer.h"
#include "../../console.h"
#include "../../drivers/plic.h"
#include "../../sched_internal.h"

extern void trap_vector(void);
extern const char sched_trap_ecall[];

void trap_init(void) {
    write_csr(mtvec, (uint32_t)trap_vector); /* direct mode (low bits 0) */
}

struct trap_frame *trap_handler(uint32_t mcause, struct trap_frame *frame) {
    if (mcause == (MCAUSE_INTERRUPT | IRQ_MACHINE_TIMER)) {
        return timer_handle_irq() ? sched_on_tick(frame) : frame;
    }
    if (mcause == (MCAUSE_INTERRUPT | IRQ_MACHINE_EXTERNAL)) {
        plic_dispatch();
        return frame;
    }
    if (mcause == EXCEPTION_MACHINE_ECALL && frame->pc == (uintptr_t)sched_trap_ecall) {
        struct trap_frame *next = sched_on_request(frame);
        if (next) {
            frame->pc += 4; /* ECALL is a 32-bit instruction. */
            return next;
        }
    }

    uint32_t mtval = read_csr(mtval);
    /* Leave pending sources masked so a parked hart stays idle. */
    write_csr(mie, 0u);
    console_puts("\n*** trap: mcause=");
    console_puthex(mcause);
    console_puts(" mepc=");
    console_puthex(frame->pc);
    console_puts(" mtval=");
    console_puthex(mtval);
    console_puts(" ***\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}
