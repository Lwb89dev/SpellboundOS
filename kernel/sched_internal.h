#ifndef SPELLBOUND_SCHED_INTERNAL_H
#define SPELLBOUND_SCHED_INTERNAL_H

#include "arch/riscv/trap_frame.h"

struct trap_frame *sched_on_tick(struct trap_frame *frame);
struct trap_frame *sched_on_request(struct trap_frame *frame);

#endif
