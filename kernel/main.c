/* SpellboundOS RV32 bring-up: console, machine-mode traps, a periodic timer
 * tick and a cooperative scheduler. QEMU virt only; Bip 6 board support is
 * separate. */
#include <stdint.h>

#include "board.h"
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
static struct task_event serial_input;
static bool serial_irq;

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

static void uart_ready(void *context) {
    task_event_signal(context);
}

static void echo_first_byte(void) {
    int byte;
    while ((byte = console_getc()) < 0) {
        task_event_wait(&serial_input);
    }
    console_putc((char)byte);
}

static void echo_console(void) {
    for (;;) {
        unsigned received = 0;
        for (; received < 64; received++) {
            int byte = console_getc();
            if (byte < 0) {
                break;
            }
            console_putc((char)byte);
        }
        if (received == 64) {
            task_yield();
        } else if (serial_irq) {
            task_event_wait(&serial_input);
        } else {
            task_sleep(1);
        }
    }
}

static void report_ticks(void) {
    uint64_t last_second = 0;
    for (;;) {
        uint64_t now = timer_ticks();
        uint64_t second = now / TICK_HZ;
        if (second != last_second) {
            last_second = second;
            console_puts("tick ");
            console_putdec((uint32_t)second);
            console_putc('\n');
        }
        task_sleep(TICK_HZ - (uint32_t)(now - second * TICK_HZ));
    }
}

void kernel_main(void) {
    console_puts("SpellboundOS RV32 foundation\n");
    console_puts("QEMU virt only; Bluetooth unavailable\n");

    trap_init();

    serial_irq = board_console_rx_irq(uart_ready, &serial_input) == 0;
    if (serial_irq) {
        set_csr(mstatus, MSTATUS_MIE);
        console_puts("console: RX interrupts enabled\n");
    }
    console_puts("Type a character to echo: ");
    if (serial_irq && task_create(echo_first_byte, stack_a, sizeof stack_a) >= 0) {
        sched_run();
    } else {
        int byte;
        do {
            byte = console_getc();
        } while (byte < 0);
        console_putc((char)byte);
    }

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

    if (task_create(echo_console, stack_a, sizeof stack_a) < 0 ||
        task_create(report_ticks, stack_b, sizeof stack_b) < 0) {
        console_puts("scheduler: console tasks unavailable\n");
        return;
    }
    sched_run();
}
