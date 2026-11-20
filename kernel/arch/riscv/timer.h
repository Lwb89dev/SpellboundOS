/* Machine timer tick interface. */
#ifndef SPELLBOUND_TIMER_H
#define SPELLBOUND_TIMER_H

#include <stdint.h>

void timer_init(uint32_t hz);   /* start periodic machine-timer interrupts at hz */
void timer_on_tick(void);       /* called from the trap handler on each interrupt */
uint64_t timer_ticks(void);     /* elapsed ticks since timer_init */

#endif /* SPELLBOUND_TIMER_H */
