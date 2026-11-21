/* Task synchronization primitives: non-recursive mutex and bounded message queue. */
#ifndef SPELLBOUND_SYNC_H
#define SPELLBOUND_SYNC_H

#include <stdbool.h>
#include <stdint.h>
#include "sched.h"

/* Non-recursive mutex owned by a single task on hart 0. Call kmutex_init
 * before use and keep the mutex alive while tasks wait on it. */
struct kmutex {
    int owner;
    struct task_event released;
};

void kmutex_init(struct kmutex *mutex);
int kmutex_owner(const struct kmutex *mutex); /* owning task id, or -1 */
bool kmutex_try_lock(struct kmutex *mutex);
bool kmutex_lock(struct kmutex *mutex);
bool kmutex_lock_for(struct kmutex *mutex, uint32_t ticks);
bool kmutex_unlock(struct kmutex *mutex);

/* Fixed-size bounded FIFO message queue. Try-operations are ISR-safe on hart 0;
 * blocking operations require task context. */
struct msgq {
    uint8_t *storage;
    uint32_t item_size;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    struct task_event not_empty;
    struct task_event not_full;
};

/* Bind caller-owned storage of item_size * capacity bytes. Returns 0 or -1. */
int msgq_init(struct msgq *q, void *storage, uint32_t item_size, uint32_t capacity);
uint32_t msgq_count(const struct msgq *q);
uint32_t msgq_capacity(const struct msgq *q);

bool msgq_try_send(struct msgq *q, const void *item);
bool msgq_try_recv(struct msgq *q, void *out);

bool msgq_send(struct msgq *q, const void *item);
bool msgq_send_for(struct msgq *q, const void *item, uint32_t ticks);
bool msgq_recv(struct msgq *q, void *out);
bool msgq_recv_for(struct msgq *q, void *out, uint32_t ticks);

#endif /* SPELLBOUND_SYNC_H */
