/* Watch input event queue backed by msgq. */
#include "input.h"
#include "sync.h"
#include <stddef.h>

#ifndef SPELLBOUND_HOST_TEST
#include "arch/riscv/riscv.h"
#include "arch/riscv/timer.h"
#endif

static struct msgq input_queue;
static bool input_ready;
static uint32_t dropped_events;

int input_init(struct input_event *storage, uint32_t capacity) {
    uint32_t previous = irq_save();
    input_ready = false;
    dropped_events = 0;
    int rc = msgq_init(&input_queue, storage, sizeof(struct input_event), capacity);
    if (rc == 0) {
        input_ready = true;
    }
    irq_restore(previous);
    return rc;
}

bool input_post(const struct input_event *ev) {
    if (!ev) {
        return false;
    }
    uint32_t previous = irq_save();
    if (!input_ready) {
        irq_restore(previous);
        return false;
    }
    struct input_event stamped = *ev;
    if (stamped.timestamp_ticks == 0) {
        stamped.timestamp_ticks = timer_ticks();
    }
    bool ok = msgq_try_send(&input_queue, &stamped);
    if (!ok) {
        dropped_events++;
    }
    irq_restore(previous);
    return ok;
}

bool input_poll(struct input_event *out) {
    return input_ready && msgq_try_recv(&input_queue, out);
}

bool input_wait(struct input_event *out) {
    return input_ready && msgq_recv(&input_queue, out);
}

bool input_wait_for(struct input_event *out, uint32_t ticks) {
    return input_ready && msgq_recv_for(&input_queue, out, ticks);
}

uint32_t input_pending(void) {
    return input_ready ? msgq_count(&input_queue) : 0;
}

uint32_t input_dropped(void) {
    uint32_t previous = irq_save();
    uint32_t count = dropped_events;
    irq_restore(previous);
    return count;
}
