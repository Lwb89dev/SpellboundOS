/* Bounded byte ring buffer. Freestanding and portable for host unit testing. */
#ifndef SPELLBOUND_RINGBUF_H
#define SPELLBOUND_RINGBUF_H

#include <stdbool.h>
#include <stdint.h>

/* Caller-serialized (mask interrupts when shared with an IRQ handler). */
struct ringbuf {
    uint8_t *data;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t count;
};

/* Bind caller-owned storage of at least one byte. Returns 0 on success, -1 on error. */
int ringbuf_init(struct ringbuf *rb, uint8_t *storage, uint32_t capacity);
void ringbuf_reset(struct ringbuf *rb);

uint32_t ringbuf_len(const struct ringbuf *rb);
uint32_t ringbuf_free(const struct ringbuf *rb);
bool ringbuf_is_empty(const struct ringbuf *rb);
bool ringbuf_is_full(const struct ringbuf *rb);

bool ringbuf_push_byte(struct ringbuf *rb, uint8_t byte);
bool ringbuf_pop_byte(struct ringbuf *rb, uint8_t *out);
bool ringbuf_peek_byte(const struct ringbuf *rb, uint8_t *out);

uint32_t ringbuf_write(struct ringbuf *rb, const uint8_t *src, uint32_t len);
uint32_t ringbuf_read(struct ringbuf *rb, uint8_t *dst, uint32_t len);

#endif /* SPELLBOUND_RINGBUF_H */
