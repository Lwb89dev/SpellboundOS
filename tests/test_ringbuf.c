/* Host unit test for the byte ring buffer (kernel/ringbuf.c). */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/ringbuf.c"

int main(void) {
    struct ringbuf rb;
    uint8_t storage[8];
    uint8_t byte = 0;

    /* Reject invalid initialization arguments. */
    assert(ringbuf_init(NULL, storage, sizeof storage) == -1);
    assert(ringbuf_init(&rb, NULL, sizeof storage) == -1);
    assert(ringbuf_is_empty(&rb) && ringbuf_is_full(&rb) && ringbuf_free(&rb) == 0);
    assert(ringbuf_init(&rb, storage, 0) == -1);
    assert(ringbuf_init(&rb, (uint8_t *)(UINTPTR_MAX - 3), 8) == -1);

    /* Valid initialization uses the full capacity (no wasted slot). */
    assert(ringbuf_init(&rb, storage, sizeof storage) == 0);
    assert(ringbuf_is_empty(&rb) && !ringbuf_is_full(&rb));
    assert(ringbuf_len(&rb) == 0 && ringbuf_free(&rb) == 8);
    assert(!ringbuf_pop_byte(&rb, &byte));
    assert(!ringbuf_peek_byte(&rb, &byte));

    /* Fill to full capacity, verify FIFO and overflow drop. */
    for (uint8_t i = 0; i < 8; i++) {
        assert(ringbuf_push_byte(&rb, (uint8_t)(0x10u + i)));
    }
    assert(ringbuf_is_full(&rb) && ringbuf_len(&rb) == 8 && ringbuf_free(&rb) == 0);
    assert(!ringbuf_push_byte(&rb, 0xff));

    assert(ringbuf_peek_byte(&rb, &byte) && byte == 0x10u);
    assert(ringbuf_len(&rb) == 8); /* peek does not consume */

    /* Pop 3 bytes, then push 3 more to cross the storage wrap boundary. */
    for (uint8_t i = 0; i < 3; i++) {
        assert(ringbuf_pop_byte(&rb, &byte) && byte == (uint8_t)(0x10u + i));
    }
    assert(ringbuf_len(&rb) == 5 && ringbuf_free(&rb) == 3);

    const uint8_t tail_bytes[4] = {0xa1, 0xa2, 0xa3, 0xa4};
    assert(ringbuf_write(&rb, tail_bytes, 4) == 3); /* 4th byte dropped */
    assert(ringbuf_is_full(&rb));

    uint8_t out[8] = {0};
    assert(ringbuf_read(&rb, out, 8) == 8);
    const uint8_t expected[8] = {0x13, 0x14, 0x15, 0x16, 0x17, 0xa1, 0xa2, 0xa3};
    assert(memcmp(out, expected, sizeof expected) == 0);
    assert(ringbuf_is_empty(&rb) && ringbuf_free(&rb) == 8);

    /* Pop with NULL out discards one byte; reset clears buffered state. */
    assert(ringbuf_write(&rb, tail_bytes, 4) == 4);
    assert(ringbuf_pop_byte(&rb, NULL));
    assert(ringbuf_len(&rb) == 3);
    ringbuf_reset(&rb);
    assert(ringbuf_is_empty(&rb) && ringbuf_free(&rb) == 8);

    /* Bulk zero-length and NULL checks. */
    assert(ringbuf_write(&rb, NULL, 0) == 0);
    assert(ringbuf_write(&rb, NULL, 4) == 0);
    assert(ringbuf_read(&rb, NULL, 0) == 0);
    assert(ringbuf_read(&rb, NULL, 4) == 0);

    printf("PASS: ringbuf push/pop/wrap/bulk/bounds\n");
    return 0;
}
