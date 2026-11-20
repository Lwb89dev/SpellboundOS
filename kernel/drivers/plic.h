#ifndef SPELLBOUND_PLIC_H
#define SPELLBOUND_PLIC_H

#include <stdint.h>

typedef void (*plic_handler)(void *context);

/* Select the hart 0 machine context before enabling external interrupts. */
int plic_init(uintptr_t base, unsigned context, unsigned source_count);
/* Register and enable a source. The handler acknowledges its device. */
int plic_register(unsigned source, plic_handler handler, void *context);
void plic_dispatch(void);

#endif
