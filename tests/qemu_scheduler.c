/* Runtime scheduler checks on RV32 QEMU virt, independently of the demo. */
#include <stdint.h>
#include "../kernel/console.h"
#include "../kernel/sched.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/arch/riscv/trap_frame.h"

static uint32_t stacks[8][256];
static _Alignas(16) unsigned char misaligned_stack[TRAP_FRAME_SIZE + 144];
static unsigned calls;
static unsigned failures;
static unsigned sleep_stage;
static unsigned yield_stage;
static struct task_event input_event, other_event;
static unsigned event_stage;
static struct task_event timed_event;

static void worker(void) {
    calls++;
    /* Nested scheduling must not replace the saved boot context. */
    int before = sched_runnable();
    sched_run();
    if (sched_runnable() != before) failures++;
    for (unsigned i = 0; i < 2000; i++) task_yield();
}

static void first_sleeper(void) {
    yield_stage = 1;
    task_sleep(0);
    if (yield_stage != 2) failures++;
    uint64_t start = timer_ticks();
    sleep_stage = 1;
    task_sleep(8);
    if (timer_ticks() - start < 8 || sleep_stage < 2) failures++;
    sleep_stage |= 4;
}

static void second_sleeper(void) {
    if (yield_stage != 1) failures++;
    yield_stage = 2;
    task_yield();
    if (sleep_stage != 1 || sched_runnable() != 1) failures++;
    sleep_stage = 2;
    uint64_t start = timer_ticks();
    task_sleep(3);
    if (timer_ticks() - start < 3) failures++;
    sleep_stage |= 8;
}

static void first_waiter(void) {
    task_event_wait(&input_event);
    event_stage |= 1;
    task_event_wait(&input_event);
    event_stage |= 2;
}

static void second_waiter(void) {
    task_event_wait(&input_event);
    event_stage |= 4;
}

static void signal_waiters(void) {
    if (event_stage != 1 || sched_runnable() != 1) failures++;
    task_event_signal(&other_event);
    if (sched_runnable() != 1) failures++;
    task_event_signal(&input_event);
    if (sched_runnable() != 2) failures++;
    task_yield();
    if (event_stage != 3 || sched_runnable() != 1) failures++;
    task_event_signal(&input_event);
    task_event_wait(&other_event);
}

static void timed_waiter(void) {
    if (task_event_wait_for(&timed_event, 0)) failures++;
    if (!task_event_wait_for(&timed_event, 100)) failures++;
    uint64_t start = timer_ticks();
    if (task_event_wait_for(&timed_event, 3) || timer_ticks() - start < 3) failures++;
}

static void signal_timed_waiter(void) {
    task_event_signal(&timed_event);
}

static void late_waiter(void) {
    if (task_event_wait_for(&timed_event, 4)) failures++;
    if (!task_event_wait_for(&timed_event, 0)) failures++;
}

static void signal_after_expiry(void) {
    /* Keep running cooperatively past the deadline before signaling. This
     * reaches signal() while the expired task is still marked waiting. */
    uint64_t start = timer_ticks();
    while (timer_ticks() - start < 6) {
    }
    task_event_signal(&timed_event);
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
        task_create(worker, misaligned_stack + 1, TRAP_FRAME_SIZE + 128) != -1) failures++;

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

    /* Both tasks block, so the scheduler must idle and dispatch them again. */
    clear_csr(mstatus, MSTATUS_MIE);
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);
    task_sleep(UINT32_MAX); /* no task is active */
    if (task_create(first_sleeper, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(second_sleeper, stacks[1], sizeof stacks[1]) < 0) failures++;
    sched_run();
    if (sleep_stage != (2 | 4 | 8) || sched_runnable() != 0) failures++;

    task_event_signal(&input_event);
    task_event_signal(&input_event);
    task_event_wait(&input_event); /* boot does not consume the signal */
    if (task_create(first_waiter, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(second_waiter, stacks[1], sizeof stacks[1]) < 0 ||
        task_create(signal_waiters, stacks[2], sizeof stacks[2]) < 0) failures++;
    sched_run();
    if (event_stage != 7 || sched_runnable() != 0) failures++;

    if (task_create(timed_waiter, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(signal_timed_waiter, stacks[1], sizeof stacks[1]) < 0) failures++;
    sched_run();
    if (task_create(late_waiter, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(signal_after_expiry, stacks[1], sizeof stacks[1]) < 0) failures++;
    sched_run();
    if (sched_runnable() != 0) failures++;

    console_puts(failures ? "FAIL: scheduler lifecycle\n" :
                            "PASS: scheduler lifecycle\n");
    for (;;) __asm__ volatile("wfi");
}
