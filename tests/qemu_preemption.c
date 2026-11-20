/* Two CPU-bound workers must both finish, even though the second never yields. */
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/console.h"
#include "../kernel/sched.h"

static _Alignas(16) uint32_t stacks[2][256];
static volatile uint32_t first_started, second_started, first_finished;
static bool first_ok, second_ok;

static bool exchange(volatile uint32_t *announce, volatile uint32_t *wait_for, uint32_t marker) {
    uint32_t seen, saved;
    /* Hold distinct values in the same caller-saved register across switches. */
    __asm__ volatile(
        "mv t3, %[marker]\n"
        "li %[seen], 1\n"
        "sw %[seen], 0(%[announce])\n"
        "1: lw %[seen], 0(%[wait_for])\n"
        "beqz %[seen], 1b\n"
        "mv %[saved], t3\n"
        : [seen] "=&r"(seen), [saved] "=r"(saved)
        : [marker] "r"(marker), [announce] "r"(announce), [wait_for] "r"(wait_for)
        : "t3", "memory");
    return saved == marker;
}

static void first_worker(void) {
    bool registers_ok = exchange(&first_started, &second_started, 0x12345678u);
    uint32_t previous = irq_save();
    task_yield();
    bool irq_state_ok = (previous & MSTATUS_MIE) && !(read_csr(mstatus) & MSTATUS_MIE);
    irq_restore(previous);

    /* The tick must wake this task while its peer is still busy spinning. */
    uint64_t start = timer_ticks();
    task_sleep(3);
    first_ok = registers_ok && irq_state_ok && timer_ticks() - start >= 3;
    first_finished = 1;
}

static void second_worker(void) {
    bool irq_on = (read_csr(mstatus) & MSTATUS_MIE) != 0;
    bool registers_ok = exchange(&second_started, &first_finished, 0x87654321u);
    second_ok = irq_on && registers_ok && first_started != 0;
}

void kernel_main(void) {
    trap_init();
    timer_init(1000);
    set_csr(mstatus, MSTATUS_MIE);
    sched_set_preemption(true);

    bool created = task_create(first_worker, stacks[0], sizeof stacks[0]) >= 0 &&
                   task_create(second_worker, stacks[1], sizeof stacks[1]) >= 0;
    if (created) {
        sched_run();
    }

    sched_set_preemption(false);
    bool ok = created && first_ok && second_ok && sched_runnable() == 0 &&
              (read_csr(mstatus) & MSTATUS_MIE);
    console_puts(ok ? "PASS: timer preemption\n" : "FAIL: timer preemption\n");
    for (;;) __asm__ volatile("wfi");
}
