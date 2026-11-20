/* Heap arithmetic and coalescing on the actual 32-bit target. */
#include <stdint.h>
#include "../kernel/console.h"
#include "../kernel/kmem.h"

static unsigned char heap[4096];

void kernel_main(void) {
    int failed = 0;
    struct kmem_stats initial, result;
    kmem_init(heap, sizeof heap);
    kmem_get_stats(&initial);
    if (kmalloc(UINT32_MAX) || kmalloc(UINT32_MAX - 7) || kmalloc(0)) failed = 1;
    void *a = kmalloc(100);
    void *b = kmalloc(200);
    if (!a || !b || ((uintptr_t)a & 7) || ((uintptr_t)b & 7)) failed = 1;
    kfree(a);
    kfree(b);
    kmem_get_stats(&result);
    if (result.blocks != 1 || result.free_blocks != 1 ||
        result.free_bytes != initial.free_bytes) failed = 1;
    kmem_init((void *)0xfffffffcu, 16);
    kmem_get_stats(&result);
    if (result.total || kmalloc(8)) failed = 1;
    console_puts(failed ? "FAIL: heap boundaries\n" : "PASS: heap boundaries\n");
    for (;;) __asm__ volatile("wfi");
}
