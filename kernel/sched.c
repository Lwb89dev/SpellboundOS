/* Cooperative round-robin scheduler over the context_switch primitive. */
#include "sched.h"

#define MAX_TASKS 8
#define CONTEXT_WORDS 16 /* ra + s0..s11 and padding, 16-byte aligned */

enum task_state { TASK_UNUSED = 0, TASK_READY, TASK_RUNNING, TASK_DONE };

struct task {
    uint32_t *sp;
    enum task_state state;
};

extern void context_switch(uint32_t **old_sp, uint32_t *new_sp);
extern void task_trampoline(void);

static struct task tasks[MAX_TASKS];
static uint32_t *boot_sp;
static int current = -1;

int task_create(task_fn fn, void *stack, uint32_t stack_size) {
    int id = -1;
    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].state == TASK_UNUSED || tasks[i].state == TASK_DONE) {
            id = i;
            break;
        }
    }
    if (id < 0 || fn == 0 || stack == 0 ||
        stack_size < CONTEXT_WORDS * 4u + 16u ||
        (uint32_t)stack > UINT32_MAX - stack_size) {
        return -1;
    }
    uint32_t top = ((uint32_t)stack + stack_size) & ~15u;
    if (top - (uint32_t)stack < CONTEXT_WORDS * 4u + 16u) return -1;
    uint32_t *frame = (uint32_t *)(top - CONTEXT_WORDS * 4u);
    frame[0] = (uint32_t)task_trampoline; /* ra */
    frame[1] = (uint32_t)fn;              /* s0 -> called by the trampoline */
    frame[2] = (uint32_t)task_exit;       /* s1 -> called when fn returns */
    for (int i = 3; i < CONTEXT_WORDS; i++) {
        frame[i] = 0; /* s2..s11 */
    }
    tasks[id].sp = frame;
    tasks[id].state = TASK_READY;
    return id;
}

static int next_ready(int from) {
    for (int i = 1; i <= MAX_TASKS; i++) {
        int j = (from + i) % MAX_TASKS;
        if (tasks[j].state == TASK_READY) {
            return j;
        }
    }
    return -1;
}

void task_yield(void) {
    int cur = current;
    /* The boot context has no task to yield and may not have a saved stack. */
    if (cur < 0) return;
    if (cur >= 0 && tasks[cur].state == TASK_RUNNING) {
        tasks[cur].state = TASK_READY;
    }
    int nxt = next_ready(cur < 0 ? MAX_TASKS - 1 : cur);
    if (nxt < 0) {
        /* Nobody else ready: return to the boot context. */
        current = -1;
        context_switch(&tasks[cur].sp, boot_sp);
        return;
    }
    if (nxt == cur) {
        tasks[cur].state = TASK_RUNNING;
        return;
    }
    tasks[nxt].state = TASK_RUNNING;
    current = nxt;
    if (cur >= 0) {
        context_switch(&tasks[cur].sp, tasks[nxt].sp);
    } else {
        context_switch(&boot_sp, tasks[nxt].sp);
    }
}

void task_exit(void) {
    if (current >= 0) {
        tasks[current].state = TASK_DONE;
    }
    task_yield();
    for (;;) {
    } /* unreachable: a DONE task is never rescheduled */
}

void sched_run(void) {
    /* A nested run would overwrite the saved boot context. */
    if (current >= 0) return;
    int first = next_ready(MAX_TASKS - 1);
    if (first < 0) {
        return;
    }
    tasks[first].state = TASK_RUNNING;
    current = first;
    context_switch(&boot_sp, tasks[first].sp);
    current = -1;
}

int sched_runnable(void) {
    int n = 0;
    for (int i = 0; i < MAX_TASKS; i++) {
        if (tasks[i].state == TASK_READY || tasks[i].state == TASK_RUNNING) {
            n++;
        }
    }
    return n;
}
