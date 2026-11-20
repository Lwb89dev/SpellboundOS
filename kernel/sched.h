/* Cooperative round-robin scheduler. */
#ifndef SPELLBOUND_SCHED_H
#define SPELLBOUND_SCHED_H

#include <stdint.h>

typedef void (*task_fn)(void);

/* Register a task with its own stack. Returns the task id, or -1 if full. */
int task_create(task_fn fn, void *stack, uint32_t stack_size);

/* Hand the CPU to the next ready task. */
void task_yield(void);

/* End the current task (marks it finished and yields; never returns). */
void task_exit(void);

/* Run the scheduler from the boot context. Returns when every task has exited. */
void sched_run(void);

/* Number of tasks that have not yet exited. */
int sched_runnable(void);

#endif /* SPELLBOUND_SCHED_H */
