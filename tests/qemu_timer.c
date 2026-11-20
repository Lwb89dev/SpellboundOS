/* Exercise real timer interrupts and the RV32 counter read on QEMU virt. */
#include "../kernel/console.h"
#include "../kernel/arch/riscv/trap.h"
/* Included to set the counter near rollover and inspect the interval. */
#include "../kernel/arch/riscv/timer.c"

void kernel_main(void) {
    int failed = 0;
    trap_init();
    timer_init(UINT32_MAX);
    if (interval != 1 || timer_ticks() != 0 ||
        (read_csr(mstatus) & MSTATUS_MIE)) failed = 1;
    timer_init(100);
    ticks = 0xffffffffu;
    set_csr(mstatus, MSTATUS_MIE);
    while (timer_ticks() <= 0xffffffffu) { }
    if (!(read_csr(mstatus) & MSTATUS_MIE)) failed = 1;
    clear_csr(mstatus, MSTATUS_MIE);
    uint64_t stopped = timer_ticks();
    if ((read_csr(mstatus) & MSTATUS_MIE) || stopped < 0x100000000ull)
        failed = 1;
    console_puts(failed ? "FAIL: timer rollover\n" : "PASS: timer rollover\n");
    for (;;) __asm__ volatile("wfi");
}
