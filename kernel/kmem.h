/* Kernel heap: first-fit free list with coalescing. Freestanding and portable
 * so the allocation logic can be unit-tested on the host. */
#ifndef SPELLBOUND_KMEM_H
#define SPELLBOUND_KMEM_H

#include <stddef.h>
#include <stdint.h>

/* Single-threaded; callers must serialize access including interrupts. A valid
 * region must remain available until reinitialization. */
void kmem_init(void *base, uint32_t size);
void *kmalloc(uint32_t size);
void kfree(void *ptr); /* NULL or a currently allocated pointer from this heap */

struct kmem_stats {
    uint32_t total;      /* usable bytes under management */
    uint32_t free_bytes; /* currently free payload bytes */
    uint32_t blocks;     /* total blocks */
    uint32_t free_blocks;
};
void kmem_get_stats(struct kmem_stats *out);

#endif /* SPELLBOUND_KMEM_H */
