/* SpellboundOS RV32 bring-up: console, machine-mode traps, a periodic timer
 * tick and a cooperative scheduler. QEMU virt only; Bip 6 board support is
 * separate. */
#include <stdint.h>

#include "console.h"
#include "kmem.h"
#include "sched.h"
#include "arch/riscv/riscv.h"
#include "arch/riscv/timer.h"
#include "arch/riscv/trap.h"

#define TICK_HZ 100u /* timer interrupts per second */

static uint32_t stack_a[256];
static uint32_t stack_b[256];
static uint8_t heap[32 * 1024];

static void worker(char tag) {
    for (int i = 1; i <= 3; i++) {
        console_putc(tag);
        console_putdec((uint32_t)i);
        console_putc('\n');
        task_yield();
    }
}

static void task_a(void) { worker('A'); }
static void task_b(void) { worker('B'); }

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

    /* Periodic tick online. */
    console_puts("\ntimer: 100 Hz tick online\n");
    timer_init(TICK_HZ);
    set_csr(mstatus, MSTATUS_MIE);

    /* Kernel heap. */
    kmem_init(heap, sizeof heap);
    void *p = kmalloc(256);
    void *q = kmalloc(1024);
    struct kmem_stats ks;
    kmem_get_stats(&ks);
    console_puts("heap: free ");
    console_putdec(ks.free_bytes);
    console_puts(" bytes in ");
    console_putdec(ks.free_blocks);
    console_puts(" blocks\n");
    kfree(p);
    kfree(q);

    /* Cooperative scheduler: two tasks round-robin to completion. */
    console_puts("scheduler: running 2 tasks\n");
    task_create(task_a, stack_a, sizeof stack_a);
    task_create(task_b, stack_b, sizeof stack_b);
    sched_run();
    console_puts("scheduler: all tasks done\n");

    /* Idle: report one line per second, echo input, sleep on the tick. */
    uint64_t last_second = 0;
    for (;;) {
        uint64_t second = timer_ticks() / TICK_HZ;
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
        __asm__ volatile("wfi");
    }
}
