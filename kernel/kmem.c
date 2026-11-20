/* First-fit kernel heap with forward coalescing. A single contiguous region is
 * split into blocks, each carrying an 8-byte-aligned header. */
#include "kmem.h"

#define ALIGN 8u
#define ALIGN_MASK ((uintptr_t)(ALIGN - 1u))
#define ALIGN_UP(x) (((uintptr_t)(x) + ALIGN_MASK) & ~ALIGN_MASK)

struct block {
    uint32_t size;      /* total block size including this header */
    uint32_t free;      /* 1 if available */
    struct block *next; /* physically next block, or NULL at the end */
};

#define HDR ALIGN_UP(sizeof(struct block))

static struct block *head;
static uint32_t managed;

void kmem_init(void *base, uint32_t size) {
    uintptr_t addr = ALIGN_UP((uintptr_t)base);
    uintptr_t end = (uintptr_t)base + size;
    if (end <= addr || (end - addr) < HDR + ALIGN) {
        head = NULL;
        managed = 0;
        return;
    }
    head = (struct block *)addr;
    head->size = (uint32_t)((end - addr) & ~ALIGN_MASK);
    head->free = 1;
    head->next = NULL;
    managed = head->size;
}

void *kmalloc(uint32_t size) {
    if (size == 0) {
        return NULL;
    }
    uint32_t need = ALIGN_UP(size) + HDR;
    for (struct block *b = head; b != NULL; b = b->next) {
        if (!b->free || b->size < need) {
            continue;
        }
        /* Split if the remainder can hold a header plus a minimal payload. */
        if (b->size >= need + HDR + ALIGN) {
            struct block *rest = (struct block *)((uintptr_t)b + need);
            rest->size = b->size - need;
            rest->free = 1;
            rest->next = b->next;
            b->size = need;
            b->next = rest;
        }
        b->free = 0;
        return (void *)((uintptr_t)b + HDR);
    }
    return NULL;
}

static void coalesce(void) {
    for (struct block *b = head; b != NULL && b->next != NULL;) {
        if (b->free && b->next->free) {
            b->size += b->next->size;
            b->next = b->next->next;
        } else {
            b = b->next;
        }
    }
}

void kfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    struct block *b = (struct block *)((uintptr_t)ptr - HDR);
    b->free = 1;
    coalesce();
}

void kmem_get_stats(struct kmem_stats *out) {
    out->total = managed;
    out->free_bytes = 0;
    out->blocks = 0;
    out->free_blocks = 0;
    for (struct block *b = head; b != NULL; b = b->next) {
        out->blocks++;
        if (b->free) {
            out->free_blocks++;
            out->free_bytes += b->size - HDR;
        }
    }
}
