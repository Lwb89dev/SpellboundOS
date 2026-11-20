/* Exercise real timer interrupts and the RV32 counter read on QEMU virt. */
#include "../kernel/console.h"
#include "../kernel/sched.h"
#include "../kernel/arch/riscv/trap.h"
/* Included to set the counter near rollover and inspect the interval. */
#include "../kernel/arch/riscv/timer.c"

static _Alignas(16) uint32_t stack[256];
static int slept_across_wrap;

static void sleep_across_wrap(void) {
    clear_csr(mstatus, MSTATUS_MIE);
    const uint64_t start = UINT64_MAX - 2;
    ticks = start;
    set_csr(mstatus, MSTATUS_MIE);
    task_sleep(4);
    uint64_t now = timer_ticks();
    slept_across_wrap = now < start && now - start >= 4;
}

static bool deadline_policy_ok(void) {
    interval = 100;
    deadline = 1000;
    ticks = 0;
    if (service_deadline(999) || ticks != 0 || deadline != 1000) {
        return false;
    }
    if (!service_deadline(1040) || ticks != 1 || deadline != 1100) {
        return false;
    }
    return service_deadline(1305) && ticks == 2 && deadline == 1405;
}

void kernel_main(void) {
    int failed = 0;
    trap_init();
    if (!deadline_policy_ok()) failed = 1;
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
    if (task_create(sleep_across_wrap, stack, sizeof stack) < 0) failed = 1;
    set_csr(mstatus, MSTATUS_MIE);
    sched_run();
    if (!slept_across_wrap) failed = 1;
    console_puts(failed ? "FAIL: timer rollover\n" : "PASS: timer rollover\n");
    for (;;) __asm__ volatile("wfi");
}
