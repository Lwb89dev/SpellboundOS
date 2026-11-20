#ifndef SPELLBOUND_BOARD_H
#define SPELLBOUND_BOARD_H

#include <stdint.h>

/* Hart 0 machine timer registers and input clock. */
struct board_timer_config {
    uintptr_t time;
    uintptr_t compare;
    uint32_t frequency;
};

extern const struct board_timer_config board_timer;

/* Called once after memory and the boot stack are available. */
int board_init(void);

/* Enable console input interrupts after installing the trap vector.
 * Notify on a transition from empty to readable, in interrupt context. */
int board_console_rx_irq(void (*notify)(void *), void *context);

#endif
