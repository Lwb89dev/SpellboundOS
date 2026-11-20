/* Round-robin scheduling on hart 0 in machine mode. */
#ifndef SPELLBOUND_SCHED_H
#define SPELLBOUND_SCHED_H

#include <stdbool.h>
#include <stdint.h>

typedef void (*task_fn)(void);

/* Switch tasks on timer interrupts while enabled. Defaults to cooperative. */
void sched_set_preemption(bool enabled);

/* Register a task with its own stack. Returns the task id, or -1 if invalid or
 * full. Finished task slots can be reused. The stack must remain valid until
 * the task exits; its size must also cover task calls and interrupt frames. */
int task_create(task_fn fn, void *stack, uint32_t stack_size);

/* Hand the CPU to the next ready task; outside a task this is a no-op. */
void task_yield(void);

/* Suspend the current task for at least this many timer interrupts.
 * Zero acts like task_yield. Outside a task this is a no-op.
 * A positive delay requires the periodic timer and interrupts to stay enabled. */
void task_sleep(uint32_t ticks);

/* End the current task (marks it finished and yields; never returns). */
_Noreturn void task_exit(void);

/* Run from boot after trap_init until every task exits. A nested call is a no-op.
 * Scheduler APIs are for boot and task contexts on hart 0. */
void sched_run(void);

/* Number of ready or running tasks, excluding tasks still asleep. */
int sched_runnable(void);

#endif /* SPELLBOUND_SCHED_H */
