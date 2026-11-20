/* Check repeated claim and completion for the emulated UART's interrupt. */
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/console.h"
#include "../kernel/driver.h"
#include "../kernel/drivers/plic.h"
#include <stdbool.h>

enum { UART_IER = 1, UART_IIR = 2, UART_THRE_IRQ = 2 };
static volatile unsigned delivered;
static volatile bool bad_interrupt;

static void uart_transmit_ready(void *context) {
    volatile uint8_t *uart = context;
    if ((uart[UART_IIR] & 0x0fu) != UART_THRE_IRQ || (read_csr(mstatus) & MSTATUS_MIE)) {
        bad_interrupt = true;
    }
    uart[UART_IER] = 0;
    delivered++;
}

void kernel_main(void) {
    trap_init();
    struct device *device = device_find("uart0");
    bool ok = device && device->irq > 0;
    if (ok) {
        void *base = (void *)device->base;
        unsigned irq = (unsigned)device->irq;
        ok = plic_register(0, uart_transmit_ready, base) == -1 &&
             plic_register(irq, 0, base) == -1 &&
             plic_register(irq, uart_transmit_ready, base) == 0 &&
             plic_register(irq, uart_transmit_ready, base) == -1 &&
             !(read_csr(mstatus) & MSTATUS_MIE);

        if (ok) {
            volatile uint8_t *uart = base;
            set_csr(mstatus, MSTATUS_MIE);
            for (unsigned round = 1; round <= 2; round++) {
                uart[UART_IER] = UART_THRE_IRQ;
                while (delivered < round) {
                }
            }
            ok = delivered == 2 && !bad_interrupt;
        }
    }
    console_puts(ok ? "PASS: PLIC UART interrupts\n" : "FAIL: PLIC UART interrupts\n");
    for (;;) __asm__ volatile("wfi");
}
