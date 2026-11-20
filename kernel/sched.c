/* Single-hart round-robin scheduler. Dispatch runs with interrupts masked. */
#include "sched.h"
#include "sched_internal.h"
#include "arch/riscv/riscv.h"
#include "arch/riscv/timer.h"

#define MAX_TASKS 8
#define MIN_STACK (TRAP_FRAME_SIZE + 128u)

enum task_state { TASK_UNUSED, TASK_READY, TASK_RUNNING, TASK_SLEEPING, TASK_DONE };
enum sched_request { SCHED_RUN, SCHED_YIELD, SCHED_SLEEP, SCHED_EXIT };

struct task {
    struct trap_frame *frame;
    enum task_state state;
    bool started;
    uint64_t sleep_start;
    uint32_t sleep_ticks;
};

extern void sched_trap_call(unsigned request, uint32_t argument);

static struct task tasks[MAX_TASKS];
static struct trap_frame *boot_frame;
static int current = -1;
static bool preempt;

static void task_start(task_fn fn) {
    fn();
    task_exit();
}

int task_create(task_fn fn, void *stack, uint32_t stack_size) {
    uintptr_t base = (uintptr_t)stack;
    if (!fn || !base || stack_size < MIN_STACK || base > UINTPTR_MAX - stack_size) {
        return -1;
    }
    uintptr_t top = (base + stack_size) & ~(uintptr_t)15;
    if (top - base < MIN_STACK) {
        return -1;
    }

    uint32_t previous = irq_save();
    for (int i = 0; i < MAX_TASKS; i++) {
        struct task *task = &tasks[i];
        if (task->state != TASK_UNUSED && task->state != TASK_DONE) {
            continue;
        }
        struct trap_frame *frame = (struct trap_frame *)(top - TRAP_FRAME_SIZE);
        for (unsigned reg = 0; reg < 32; reg++) {
            frame->x[reg] = 0;
        }
        frame->x[2] = top;
        __asm__ volatile("mv %0, gp" : "=r"(frame->x[3]));
        __asm__ volatile("mv %0, tp" : "=r"(frame->x[4]));
        frame->x[10] = (uintptr_t)fn;
        frame->pc = (uintptr_t)task_start;
        task->frame = frame;
        task->started = false;
        task->state = TASK_READY;
        irq_restore(previous);
        return i;
    }
    irq_restore(previous);
    return -1;
}

static int next_ready(int from) {
    for (int i = 1; i <= MAX_TASKS; i++) {
        int candidate = (from + i) % MAX_TASKS;
        if (tasks[candidate].state == TASK_READY) {
            return candidate;
        }
    }
    return -1;
}

static int wake_sleepers(void) {
    int waiting = 0;
    for (int i = 0; i < MAX_TASKS; i++) {
        struct task *task = &tasks[i];
        if (task->state != TASK_SLEEPING) {
            continue;
        }
        if (timer_ticks() - task->sleep_start >= task->sleep_ticks) {
            task->state = TASK_READY;
        } else {
            waiting++;
        }
    }
    return waiting;
}

static struct trap_frame *dispatch(struct trap_frame *frame) {
    int from = current;
    wake_sleepers();
    int next = next_ready(from >= 0 ? from : MAX_TASKS - 1);
    if (next < 0 && from < 0) {
        return frame;
    }
    if (from >= 0) {
        tasks[from].frame = frame;
    } else {
        boot_frame = frame;
    }
    current = next;
    if (next < 0) {
        return boot_frame;
    }

    struct task *task = &tasks[next];
    task->state = TASK_RUNNING;
    if (!task->started) {
        task->frame->status = MSTATUS_MPP_MACHINE | (boot_frame->status & MSTATUS_MPIE);
        task->started = true;
    }
    return task->frame;
}

struct trap_frame *sched_on_request(struct trap_frame *frame) {
    unsigned request = frame->x[10]; /* a0 */
    if (request > SCHED_EXIT) {
        return NULL;
    }
    if (current < 0) {
        return request == SCHED_RUN ? dispatch(frame) : frame;
    }
    if (request == SCHED_RUN) {
        return frame;
    }

    struct task *task = &tasks[current];
    uint32_t delay = frame->x[11]; /* a1 */
    if (request == SCHED_EXIT) {
        task->state = TASK_DONE;
    } else if (request == SCHED_SLEEP && delay != 0) {
        task->sleep_start = timer_ticks();
        task->sleep_ticks = delay;
        task->state = TASK_SLEEPING;
    } else {
        task->state = TASK_READY;
    }
    return dispatch(frame);
}

struct trap_frame *sched_on_tick(struct trap_frame *frame) {
    if (!preempt || current < 0) {
        return frame;
    }
    tasks[current].state = TASK_READY;
    return dispatch(frame);
}

void sched_set_preemption(bool enabled) {
    uint32_t previous = irq_save();
    preempt = enabled;
    irq_restore(previous);
}

void task_yield(void) {
    if (current >= 0) {
        sched_trap_call(SCHED_YIELD, 0);
    }
}

void task_sleep(uint32_t ticks) {
    if (current >= 0) {
        sched_trap_call(SCHED_SLEEP, ticks);
    }
}

_Noreturn void task_exit(void) {
    sched_trap_call(SCHED_EXIT, 0);
    for (;;) {
        __asm__ volatile("wfi");
    }
}

void sched_run(void) {
    if (current >= 0) {
        return;
    }
    for (;;) {
        sched_trap_call(SCHED_RUN, 0);
        int waiting = wake_sleepers();
        if (next_ready(MAX_TASKS - 1) >= 0) {
            continue;
        }
        if (!waiting) {
            return;
        }
        __asm__ volatile("wfi" ::: "memory");
    }
}

int sched_runnable(void) {
    uint32_t previous = irq_save();
    wake_sleepers();
    int count = 0;
    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].state == TASK_READY || tasks[i].state == TASK_RUNNING) {
            count++;
        }
    }
    irq_restore(previous);
    return count;
}
