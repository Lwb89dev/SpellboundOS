/* Host unit test for the kernel heap (kernel/kmem.c is freestanding and portable).
 * Build: clang -I kernel tests/test_kmem.c -o /tmp/test_kmem && /tmp/test_kmem */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/kmem.c"

static unsigned char heap[64 * 1024];

int main(void) {
    kmem_init(heap, sizeof heap);

    struct kmem_stats s;
    kmem_get_stats(&s);
    assert(s.blocks == 1 && s.free_blocks == 1);
    uint32_t initial_free = s.free_bytes;
    assert(initial_free > sizeof(heap) - 64);

    /* Three distinct, aligned, non-overlapping blocks. */
    void *a = kmalloc(100);
    void *b = kmalloc(200);
    void *c = kmalloc(50);
    assert(a && b && c);
    assert(((uintptr_t)a % 8) == 0 && ((uintptr_t)b % 8) == 0 && ((uintptr_t)c % 8) == 0);
    assert((uintptr_t)a < (uintptr_t)b && (uintptr_t)b < (uintptr_t)c);
    assert((uintptr_t)a + 100 <= (uintptr_t)b);
    assert((uintptr_t)b + 200 <= (uintptr_t)c);
    memset(a, 0xaa, 100);
    memset(b, 0xbb, 200);
    memset(c, 0xcc, 50);

    /* Freeing the middle block makes the hole reusable (first-fit). */
    kfree(b);
    void *b2 = kmalloc(180);
    assert(b2 == b);

    /* Free everything: the heap must fully coalesce back to one free block. */
    kfree(a);
    kfree(c);
    kfree(b2);
    kmem_get_stats(&s);
    assert(s.free_blocks == 1 && s.blocks == 1);
    assert(s.free_bytes == initial_free);

    /* Oversized and zero requests fail cleanly. */
    assert(kmalloc(1000000) == NULL);
    assert(kmalloc(0) == NULL);

    /* Many small allocations then frees, interleaved, stay consistent. */
    void *p[64];
    for (int i = 0; i < 64; i++) {
        p[i] = kmalloc(64);
        assert(p[i] != NULL);
    }
    for (int i = 0; i < 64; i += 2) {
        kfree(p[i]);
    }
    for (int i = 1; i < 64; i += 2) {
        kfree(p[i]);
    }
    kmem_get_stats(&s);
    assert(s.free_blocks == 1 && s.free_bytes == initial_free);

    printf("PASS: kmem first-fit, split, coalesce, OOM\n");
    return 0;
}
