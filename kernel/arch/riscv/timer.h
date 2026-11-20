/* Machine timer tick interface. */
#ifndef SPELLBOUND_TIMER_H
#define SPELLBOUND_TIMER_H

#include <stdbool.h>
#include <stdint.h>

void timer_init(uint32_t hz);   /* start periodic machine-timer interrupts at hz */
bool timer_handle_irq(void);    /* true if an elapsed deadline advanced the tick */
uint64_t timer_ticks(void);     /* elapsed ticks since timer_init */

#endif /* SPELLBOUND_TIMER_H */
