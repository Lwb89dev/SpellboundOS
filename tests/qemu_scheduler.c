/* Runtime scheduler checks on RV32 QEMU virt, independently of the demo. */
#include <stdint.h>
#include "../kernel/console.h"
#include "../kernel/sched.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"

static uint32_t stacks[8][256];
static _Alignas(16) unsigned char misaligned_stack[96];
static unsigned calls;
static unsigned failures;

static void worker(void) {
    calls++;
    /* Nested scheduling must not replace the saved boot context. */
    int before = sched_runnable();
    sched_run();
    if (sched_runnable() != before) failures++;
    for (unsigned i = 0; i < 2000; i++) task_yield();
}

void kernel_main(void) {
    trap_init();
    timer_init(10000);
    set_csr(mstatus, MSTATUS_MIE);
    task_yield();
    sched_run();
    if (sched_runnable() != 0) failures++;
    if (task_create(0, stacks[0], sizeof stacks[0]) != -1 ||
        task_create(worker, 0, 1024) != -1 ||
        task_create(worker, (void *)0xfffffff0u, 128) != -1 ||
        task_create(worker, stacks[0], 16) != -1 ||
        task_create(worker, misaligned_stack + 1, 80) != -1) failures++;

    uint64_t started = timer_ticks();
    for (unsigned round = 0; round < 3; round++) {
        for (unsigned i = 0; i < 8; i++) {
            if (task_create(worker, stacks[i], sizeof stacks[i]) < 0) failures++;
        }
        if (task_create(worker, stacks[0], sizeof stacks[0]) != -1 ||
            sched_runnable() != 8) failures++;
        sched_run();
        if (sched_runnable() != 0 || calls != (round + 1) * 8) failures++;
        task_yield();
    }
    if (timer_ticks() == started) failures++;
    console_puts(failures ? "FAIL: scheduler lifecycle\n" :
                            "PASS: scheduler lifecycle\n");
    for (;;) __asm__ volatile("wfi");
}
