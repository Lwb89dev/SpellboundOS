/* Trigger an illegal instruction through the normal machine trap vector. */
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/console.h"

void kernel_main(void) {
    trap_init();
    __asm__ volatile(".word 0");
    console_puts("FAIL: illegal instruction\n");
}
