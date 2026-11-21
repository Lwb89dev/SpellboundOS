/* Host unit test for kmutex and msgq (kernel/sync.c) over deterministic hooks. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"

/* Deterministic mock scheduler/timer environment for host testing. */
static int mock_current_task = -1;
static uint64_t mock_ticks = 0;
static unsigned mock_irq_depth = 0;
static unsigned mock_signal_calls = 0;
static unsigned mock_wait_calls = 0;
static unsigned mock_wait_for_calls = 0;
static uint32_t mock_last_timeout = 0;

typedef bool (*wait_hook_fn)(struct task_event *event, uint32_t ticks);
static wait_hook_fn mock_wait_hook = NULL;

static inline uint32_t irq_save(void) {
    mock_irq_depth++;
    return mock_irq_depth == 1 ? 8u : 0u;
}

static inline void irq_restore(uint32_t previous) {
    assert(mock_irq_depth > 0);
    if (previous & 8u) {
        assert(mock_irq_depth == 1);
    }
    mock_irq_depth--;
}

static uint64_t timer_ticks(void) {
    return mock_ticks;
}

int task_current(void) {
    return mock_current_task;
}

void task_event_signal(struct task_event *event) {
    assert(event != NULL);
    mock_signal_calls++;
    event->pending = true;
}

void task_event_wait(struct task_event *event) {
    assert(mock_irq_depth == 0); /* never block with interrupts masked */
    mock_wait_calls++;
    if (event->pending) {
        event->pending = false;
        return;
    }
    assert(mock_wait_hook != NULL);
    (void)mock_wait_hook(event, 0);
}

bool task_event_wait_for(struct task_event *event, uint32_t ticks) {
    assert(mock_irq_depth == 0); /* never block with interrupts masked */
    mock_wait_for_calls++;
    mock_last_timeout = ticks;
    if (event->pending) {
        event->pending = false;
        return true;
    }
    if (ticks == 0) {
        return false;
    }
    if (mock_wait_hook) {
        return mock_wait_hook(event, ticks);
    }
    mock_ticks += ticks;
    return false;
}

#include "../kernel/sync.c"

/* Hook state for simulating concurrent release, barging and timeouts. */
static struct kmutex *hook_mutex;
static struct msgq *hook_msgq;
static unsigned hook_step;

struct sample_msg {
    uint32_t seq;
    uint16_t tag;
    uint8_t flags;
};

static bool hook_unlock_on_first_wait(struct task_event *event, uint32_t ticks) {
    (void)event;
    (void)ticks;
    int saved = mock_current_task;
    mock_current_task = hook_mutex->owner;
    assert(kmutex_unlock(hook_mutex));
    mock_current_task = saved;
    hook_mutex->released.pending = false;
    return true;
}

static bool hook_barge_then_unlock(struct task_event *event, uint32_t ticks) {
    (void)event;
    hook_step++;
    if (hook_step == 1) {
        /* First wakeup after 3 ticks, but another task steals the lock. */
        assert(ticks == 10);
        mock_ticks += 3;
        hook_mutex->owner = 2;
        return true;
    }
    /* Second wait must only ask for the remaining 7 ticks. */
    assert(ticks == 7);
    mock_ticks += 2;
    hook_mutex->owner = -1;
    return true;
}

static bool hook_unlock_at_expiry(struct task_event *event, uint32_t ticks) {
    (void)event;
    mock_ticks += ticks;
    /* Unlocked right as timeout expired. */
    hook_mutex->owner = -1;
    return false;
}

static bool hook_msgq_pop_one(struct task_event *event, uint32_t ticks) {
    (void)event;
    (void)ticks;
    struct sample_msg dropped = {0};
    assert(msgq_try_recv(hook_msgq, &dropped));
    hook_msgq->not_full.pending = false;
    return true;
}

static bool hook_msgq_push_one(struct task_event *event, uint32_t ticks) {
    (void)event;
    (void)ticks;
    struct sample_msg m = {.seq = 999, .tag = 7, .flags = 1};
    assert(msgq_try_send(hook_msgq, &m));
    hook_msgq->not_empty.pending = false;
    return true;
}

static void test_mutex(void) {
    struct kmutex m;
    kmutex_init(&m);
    assert(kmutex_owner(&m) == -1);
    assert(kmutex_owner(NULL) == -1);

    /* Reject operations outside task context. */
    mock_current_task = -1;
    assert(!kmutex_try_lock(&m));
    assert(!kmutex_lock(&m));
    assert(!kmutex_lock_for(&m, 5));
    assert(!kmutex_unlock(&m));

    /* Basic lock/unlock, non-recursive and owner checks. */
    mock_current_task = 0;
    assert(kmutex_try_lock(&m));
    assert(kmutex_owner(&m) == 0);
    assert(!kmutex_try_lock(&m));
    assert(!kmutex_lock(&m));
    assert(!kmutex_lock_for(&m, 10));

    mock_current_task = 1;
    assert(!kmutex_unlock(&m));
    assert(!kmutex_try_lock(&m));
    assert(!kmutex_lock_for(&m, 0));

    /* Blocking kmutex_lock wakes when owner unlocks. */
    hook_mutex = &m;
    mock_wait_hook = hook_unlock_on_first_wait;
    unsigned waits_before = mock_wait_calls;
    unsigned signals_before = mock_signal_calls;
    assert(kmutex_lock(&m));
    assert(mock_wait_calls == waits_before + 1);
    assert(mock_signal_calls == signals_before + 1);
    assert(kmutex_owner(&m) == 1);
    assert(mock_irq_depth == 0);

    /* Bounded wait with barging recomputes remaining timeout across 64-bit wrap. */
    mock_ticks = UINT64_MAX - 1;
    mock_current_task = 0;
    hook_step = 0;
    unsigned timed_before = mock_wait_for_calls;
    mock_wait_hook = hook_barge_then_unlock;
    assert(kmutex_lock_for(&m, 10));
    assert(kmutex_owner(&m) == 0);
    assert(hook_step == 2 && mock_wait_for_calls == timed_before + 2 && mock_last_timeout == 7);

    /* Timeout expiry when still held returns false. */
    mock_current_task = 1;
    mock_wait_hook = NULL;
    uint64_t before = mock_ticks;
    assert(!kmutex_lock_for(&m, 4));
    assert(mock_ticks - before == 4);
    assert(kmutex_owner(&m) == 0);

    /* Concurrent unlock right at expiry still succeeds on final check. */
    mock_wait_hook = hook_unlock_at_expiry;
    assert(kmutex_lock_for(&m, 4));
    assert(kmutex_owner(&m) == 1);

    assert(kmutex_unlock(&m));
    assert(kmutex_owner(&m) == -1);
    assert(!kmutex_unlock(&m));
    assert(mock_irq_depth == 0);
}

static void test_msgq(void) {
    struct msgq q;
    struct sample_msg buf[4];

    /* Invalid init checks including multiplication and pointer wrap overflow. */
    assert(msgq_init(NULL, buf, sizeof buf[0], 4) == -1);
    assert(msgq_init(&q, NULL, sizeof buf[0], 4) == -1);
    assert(msgq_init(&q, buf, 0, 4) == -1);
    assert(msgq_init(&q, buf, sizeof buf[0], 0) == -1);
    assert(msgq_init(&q, buf, 0x80000000u, 2) == -1);
    assert(msgq_init(&q, (void *)(UINTPTR_MAX - 4), 8, 2) == -1);

    assert(msgq_init(&q, buf, sizeof buf[0], 4) == 0);
    assert(msgq_capacity(&q) == 4 && msgq_count(&q) == 0);

    /* ISR-safe try_send/try_recv work even outside task context (mock_current_task == -1). */
    mock_current_task = -1;
    struct sample_msg out = {0};
    assert(!msgq_try_recv(&q, &out));
    for (uint32_t i = 0; i < 4; i++) {
        struct sample_msg in = {.seq = 100 + i, .tag = (uint16_t)(i + 1), .flags = (uint8_t)i};
        assert(msgq_try_send(&q, &in));
    }
    assert(msgq_count(&q) == 4);
    struct sample_msg extra = {.seq = 500, .tag = 9, .flags = 1};
    assert(!msgq_try_send(&q, &extra));

    /* Blocking send/recv rejected outside task context. */
    assert(!msgq_send(&q, &extra));
    assert(!msgq_send_for(&q, &extra, 5));
    assert(!msgq_recv(&q, &out));
    assert(!msgq_recv_for(&q, &out, 5));

    /* Pop 2 and push 2 to exercise wrap-around and FIFO ordering. */
    for (uint32_t i = 0; i < 2; i++) {
        assert(msgq_try_recv(&q, &out));
        assert(out.seq == 100 + i && out.tag == i + 1 && out.flags == i);
    }
    for (uint32_t i = 4; i < 6; i++) {
        struct sample_msg in = {.seq = 100 + i, .tag = (uint16_t)(i + 1), .flags = (uint8_t)i};
        assert(msgq_try_send(&q, &in));
    }
    assert(msgq_count(&q) == 4);

    /* Blocking send on full queue waits until space opens. */
    mock_current_task = 0;
    hook_msgq = &q;
    q.not_full.pending = false;
    mock_wait_hook = hook_msgq_pop_one;
    struct sample_msg pushed = {.seq = 106, .tag = 7, .flags = 6};
    assert(msgq_send(&q, &pushed));
    assert(msgq_count(&q) == 4);

    /* Timeout on full queue returns false. */
    q.not_full.pending = false;
    mock_wait_hook = NULL;
    assert(!msgq_send_for(&q, &extra, 0));
    assert(!msgq_send_for(&q, &extra, 3));

    /* Drain remaining 4 items in exact FIFO order (103, 104, 105, 106). */
    for (uint32_t expected = 103; expected <= 106; expected++) {
        assert(msgq_recv(&q, &out));
        assert(out.seq == expected);
    }
    assert(msgq_count(&q) == 0);

    /* Timeout on empty queue returns false; wakeup delivers pushed item. */
    q.not_empty.pending = false;
    assert(!msgq_recv_for(&q, &out, 0));
    assert(!msgq_recv_for(&q, &out, 5));

    mock_wait_hook = hook_msgq_push_one;
    assert(msgq_recv_for(&q, &out, 5));
    assert(out.seq == 999 && out.tag == 7 && out.flags == 1);
    assert(msgq_count(&q) == 0 && mock_irq_depth == 0);
}

int main(void) {
    test_mutex();
    test_msgq();
    printf("PASS: sync kmutex/msgq contention/timeouts/wrap\n");
    return 0;
}
