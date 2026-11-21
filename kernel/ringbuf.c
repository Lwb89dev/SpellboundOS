/* Bounded byte ring buffer over caller-owned storage. */
#include "ringbuf.h"
#include <stddef.h>

int ringbuf_init(struct ringbuf *rb, uint8_t *storage, uint32_t capacity) {
    if (!rb) {
        return -1;
    }
    rb->data = NULL;
    rb->capacity = 0;
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
    if (!storage || capacity == 0 || (uintptr_t)storage > UINTPTR_MAX - capacity) {
        return -1;
    }
    rb->data = storage;
    rb->capacity = capacity;
    return 0;
}

void ringbuf_reset(struct ringbuf *rb) {
    if (!rb) {
        return;
    }
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
}

uint32_t ringbuf_len(const struct ringbuf *rb) {
    return rb ? rb->count : 0;
}

uint32_t ringbuf_free(const struct ringbuf *rb) {
    return (rb && rb->capacity >= rb->count) ? (rb->capacity - rb->count) : 0;
}

bool ringbuf_is_empty(const struct ringbuf *rb) {
    return !rb || rb->count == 0;
}

bool ringbuf_is_full(const struct ringbuf *rb) {
    return !rb || rb->capacity == 0 || rb->count >= rb->capacity;
}

bool ringbuf_push_byte(struct ringbuf *rb, uint8_t byte) {
    if (!rb || !rb->data || rb->count >= rb->capacity) {
        return false;
    }
    rb->data[rb->head] = byte;
    rb->head++;
    if (rb->head == rb->capacity) {
        rb->head = 0;
    }
    rb->count++;
    return true;
}

bool ringbuf_pop_byte(struct ringbuf *rb, uint8_t *out) {
    if (!rb || !rb->data || rb->count == 0) {
        return false;
    }
    uint8_t byte = rb->data[rb->tail];
    rb->tail++;
    if (rb->tail == rb->capacity) {
        rb->tail = 0;
    }
    rb->count--;
    if (out) {
        *out = byte;
    }
    return true;
}

bool ringbuf_peek_byte(const struct ringbuf *rb, uint8_t *out) {
    if (!rb || !rb->data || rb->count == 0 || !out) {
        return false;
    }
    *out = rb->data[rb->tail];
    return true;
}

uint32_t ringbuf_write(struct ringbuf *rb, const uint8_t *src, uint32_t len) {
    if (!rb || !rb->data || (!src && len > 0)) {
        return 0;
    }
    uint32_t written = 0;
    while (written < len && ringbuf_push_byte(rb, src[written])) {
        written++;
    }
    return written;
}

uint32_t ringbuf_read(struct ringbuf *rb, uint8_t *dst, uint32_t len) {
    if (!rb || !rb->data || (!dst && len > 0)) {
        return 0;
    }
    uint32_t read_count = 0;
    while (read_count < len && ringbuf_pop_byte(rb, &dst[read_count])) {
        read_count++;
    }
    return read_count;
}
