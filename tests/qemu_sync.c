/* Runtime checks for kmutex and msgq on RV32 QEMU virt under preemption. */
#include <stdbool.h>
#include <stdint.h>
#include "../kernel/console.h"
#include "../kernel/sched.h"
#include "../kernel/sync.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"

struct packet {
    uint32_t seq;
    uint32_t checksum;
};

static _Alignas(16) uint32_t stacks[3][256];
static struct kmutex shared_lock;
static volatile uint32_t in_critical;
static volatile uint32_t shared_counter;
static volatile uint32_t failures;

static struct msgq queue;
static struct packet queue_storage[4];
static volatile uint32_t received_count;

static void mutex_worker(void) {
    for (unsigned i = 0; i < 40; i++) {
        if (!kmutex_lock(&shared_lock)) {
            failures++;
            return;
        }
        /* Mutual exclusion invariant while preemption is active. */
        if (in_critical != 0) {
            failures++;
        }
        in_critical = 1;
        /* Non-recursive lock and non-owner checks. */
        if (kmutex_try_lock(&shared_lock)) {
            failures++;
        }
        uint32_t value = shared_counter;
        for (volatile unsigned spin = 0; spin < 500; spin++) {
        }
        shared_counter = value + 1;
        in_critical = 0;
        if (!kmutex_unlock(&shared_lock)) {
            failures++;
        }
    }
}

static void lock_holder(void) {
    if (!kmutex_lock(&shared_lock)) {
        failures++;
        return;
    }
    task_sleep(8);
    if (!kmutex_unlock(&shared_lock)) {
        failures++;
    }
}

static void lock_contender(void) {
    /* Let holder acquire first, then verify non-owner unlock and timeout. */
    while (kmutex_owner(&shared_lock) < 0) {
        task_yield();
    }
    if (kmutex_unlock(&shared_lock)) {
        failures++;
    }
    uint64_t start = timer_ticks();
    if (kmutex_lock_for(&shared_lock, 3) || timer_ticks() - start < 3) {
        failures++;
    }
    /* Now wait long enough to inherit the lock when holder releases it. */
    if (!kmutex_lock_for(&shared_lock, 20)) {
        failures++;
        return;
    }
    if (!kmutex_unlock(&shared_lock)) {
        failures++;
    }
}

static void producer(void) {
    for (uint32_t seq = 1; seq <= 16; seq++) {
        struct packet pkt = {.seq = seq, .checksum = seq ^ 0x5a5a5a5au};
        if (!msgq_send(&queue, &pkt)) {
            failures++;
            return;
        }
    }
}

static void consumer(void) {
    for (uint32_t expected = 1; expected <= 16; expected++) {
        struct packet pkt = {0, 0};
        if (!msgq_recv(&queue, &pkt)) {
            failures++;
            return;
        }
        if (pkt.seq != expected || pkt.checksum != (expected ^ 0x5a5a5a5au)) {
            failures++;
        }
        received_count++;
    }
    struct packet unused = {0, 0};
    uint64_t start = timer_ticks();
    if (msgq_recv_for(&queue, &unused, 3) || timer_ticks() - start < 3) {
        failures++;
    }
}

void kernel_main(void) {
    trap_init();
    timer_init(1000);
    set_csr(mstatus, MSTATUS_MIE);

    kmutex_init(&shared_lock);
    if (kmutex_try_lock(&shared_lock) || kmutex_owner(&shared_lock) != -1) {
        failures++;
    }

    /* Preemptive mutual exclusion across two competing workers. */
    sched_set_preemption(true);
    if (task_create(mutex_worker, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(mutex_worker, stacks[1], sizeof stacks[1]) < 0) {
        failures++;
    }
    sched_run();
    sched_set_preemption(false);
    if (shared_counter != 80 || kmutex_owner(&shared_lock) != -1) {
        failures++;
    }

    /* Mutex timeout and handoff. */
    timer_init(100);
    if (task_create(lock_holder, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(lock_contender, stacks[1], sizeof stacks[1]) < 0) {
        failures++;
    }
    sched_run();
    if (kmutex_owner(&shared_lock) != -1) {
        failures++;
    }

    /* Bounded message queue blocking send/recv across capacity wrap and timeout. */
    if (msgq_init(&queue, queue_storage, sizeof queue_storage[0], 4) != 0) {
        failures++;
    }
    if (task_create(producer, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(consumer, stacks[1], sizeof stacks[1]) < 0) {
        failures++;
    }
    sched_run();
    if (received_count != 16 || msgq_count(&queue) != 0) {
        failures++;
    }

    console_puts(failures ? "FAIL: sync mutex and msgq\n" :
                            "PASS: sync mutex and msgq\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}
