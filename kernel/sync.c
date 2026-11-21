/* Non-recursive mutex and bounded FIFO message queue built on scheduler events. */
#include "sync.h"
#include <stddef.h>

#ifndef SPELLBOUND_HOST_TEST
#include "arch/riscv/riscv.h"
#include "arch/riscv/timer.h"
#endif

static void copy_bytes(uint8_t *dst, const uint8_t *src, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

void kmutex_init(struct kmutex *mutex) {
    if (!mutex) {
        return;
    }
    mutex->owner = -1;
    mutex->released.pending = false;
}

int kmutex_owner(const struct kmutex *mutex) {
    if (!mutex) {
        return -1;
    }
    uint32_t previous = irq_save();
    int owner = mutex->owner;
    irq_restore(previous);
    return owner;
}

bool kmutex_try_lock(struct kmutex *mutex) {
    int me = task_current();
    if (!mutex || me < 0) {
        return false;
    }
    uint32_t previous = irq_save();
    bool acquired = false;
    if (mutex->owner < 0) {
        mutex->owner = me;
        acquired = true;
    }
    irq_restore(previous);
    return acquired;
}

bool kmutex_lock(struct kmutex *mutex) {
    int me = task_current();
    if (!mutex || me < 0) {
        return false;
    }
    for (;;) {
        uint32_t previous = irq_save();
        if (mutex->owner == me) {
            irq_restore(previous);
            return false;
        }
        if (mutex->owner < 0) {
            mutex->owner = me;
            irq_restore(previous);
            return true;
        }
        irq_restore(previous);
        task_event_wait(&mutex->released);
    }
}

bool kmutex_lock_for(struct kmutex *mutex, uint32_t ticks) {
    int me = task_current();
    if (!mutex || me < 0) {
        return false;
    }
    uint64_t start = timer_ticks();
    for (;;) {
        uint32_t previous = irq_save();
        if (mutex->owner == me) {
            irq_restore(previous);
            return false;
        }
        if (mutex->owner < 0) {
            mutex->owner = me;
            irq_restore(previous);
            return true;
        }
        irq_restore(previous);
        if (ticks == 0) {
            return false;
        }
        uint64_t elapsed = timer_ticks() - start;
        if (elapsed >= ticks) {
            return false;
        }
        uint32_t remaining = ticks - (uint32_t)elapsed;
        if (!task_event_wait_for(&mutex->released, remaining)) {
            return kmutex_try_lock(mutex);
        }
    }
}

bool kmutex_unlock(struct kmutex *mutex) {
    int me = task_current();
    if (!mutex || me < 0) {
        return false;
    }
    uint32_t previous = irq_save();
    if (mutex->owner != me) {
        irq_restore(previous);
        return false;
    }
    mutex->owner = -1;
    task_event_signal(&mutex->released);
    irq_restore(previous);
    return true;
}

int msgq_init(struct msgq *q, void *storage, uint32_t item_size, uint32_t capacity) {
    if (!q) {
        return -1;
    }
    q->storage = NULL;
    q->item_size = 0;
    q->capacity = 0;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->not_empty.pending = false;
    q->not_full.pending = false;
    if (!storage || item_size == 0 || capacity == 0 || item_size > UINT32_MAX / capacity) {
        return -1;
    }
    size_t total = (size_t)item_size * (size_t)capacity;
    if ((uintptr_t)storage > UINTPTR_MAX - total) {
        return -1;
    }
    q->storage = (uint8_t *)storage;
    q->item_size = item_size;
    q->capacity = capacity;
    return 0;
}

uint32_t msgq_count(const struct msgq *q) {
    if (!q) {
        return 0;
    }
    uint32_t previous = irq_save();
    uint32_t count = q->count;
    irq_restore(previous);
    return count;
}

uint32_t msgq_capacity(const struct msgq *q) {
    return q ? q->capacity : 0;
}

bool msgq_try_send(struct msgq *q, const void *item) {
    if (!q || !q->storage || !item) {
        return false;
    }
    uint32_t previous = irq_save();
    if (q->count >= q->capacity) {
        irq_restore(previous);
        return false;
    }
    uint8_t *slot = q->storage + (size_t)q->head * (size_t)q->item_size;
    copy_bytes(slot, (const uint8_t *)item, q->item_size);
    q->head++;
    if (q->head == q->capacity) {
        q->head = 0;
    }
    q->count++;
    task_event_signal(&q->not_empty);
    irq_restore(previous);
    return true;
}

bool msgq_try_recv(struct msgq *q, void *out) {
    if (!q || !q->storage || !out) {
        return false;
    }
    uint32_t previous = irq_save();
    if (q->count == 0) {
        irq_restore(previous);
        return false;
    }
    const uint8_t *slot = q->storage + (size_t)q->tail * (size_t)q->item_size;
    copy_bytes((uint8_t *)out, slot, q->item_size);
    q->tail++;
    if (q->tail == q->capacity) {
        q->tail = 0;
    }
    q->count--;
    task_event_signal(&q->not_full);
    irq_restore(previous);
    return true;
}

bool msgq_send(struct msgq *q, const void *item) {
    if (!q || !q->storage || !item || task_current() < 0) {
        return false;
    }
    for (;;) {
        if (msgq_try_send(q, item)) {
            return true;
        }
        task_event_wait(&q->not_full);
    }
}

bool msgq_send_for(struct msgq *q, const void *item, uint32_t ticks) {
    if (!q || !q->storage || !item || task_current() < 0) {
        return false;
    }
    uint64_t start = timer_ticks();
    for (;;) {
        if (msgq_try_send(q, item)) {
            return true;
        }
        if (ticks == 0) {
            return false;
        }
        uint64_t elapsed = timer_ticks() - start;
        if (elapsed >= ticks) {
            return false;
        }
        uint32_t remaining = ticks - (uint32_t)elapsed;
        if (!task_event_wait_for(&q->not_full, remaining)) {
            return msgq_try_send(q, item);
        }
    }
}

bool msgq_recv(struct msgq *q, void *out) {
    if (!q || !q->storage || !out || task_current() < 0) {
        return false;
    }
    for (;;) {
        if (msgq_try_recv(q, out)) {
            return true;
        }
        task_event_wait(&q->not_empty);
    }
}

bool msgq_recv_for(struct msgq *q, void *out, uint32_t ticks) {
    if (!q || !q->storage || !out || task_current() < 0) {
        return false;
    }
    uint64_t start = timer_ticks();
    for (;;) {
        if (msgq_try_recv(q, out)) {
            return true;
        }
        if (ticks == 0) {
            return false;
        }
        uint64_t elapsed = timer_ticks() - start;
        if (elapsed >= ticks) {
            return false;
        }
        uint32_t remaining = ticks - (uint32_t)elapsed;
        if (!task_event_wait_for(&q->not_empty, remaining)) {
            return msgq_try_recv(q, out);
        }
    }
}
