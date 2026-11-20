/* RISC-V PLIC MMIO driver for a single machine interrupt context. */
#include "plic.h"
#include "../arch/riscv/riscv.h"
#include <stdbool.h>

#define MAX_SOURCES 127
#define ENABLE_BASE 0x2000u
#define ENABLE_STRIDE 0x80u
#define CONTEXT_BASE 0x200000u
#define CONTEXT_STRIDE 0x1000u
#define CLAIM_OFFSET 4u

static uintptr_t priority_base, enable_base, context_base;
static unsigned sources;
static struct {
    plic_handler handler;
    void *context;
} vectors[MAX_SOURCES + 1];

static volatile uint32_t *reg32(uintptr_t address) {
    return (volatile uint32_t *)address;
}

static volatile uint32_t *enable_word(unsigned source) {
    return reg32(enable_base + (source / 32u) * 4u);
}

int plic_init(uintptr_t base, unsigned context, unsigned source_count) {
    if (sources || !base || !source_count || source_count > MAX_SOURCES) {
        return -1;
    }
    priority_base = base;
    enable_base = base + ENABLE_BASE + context * ENABLE_STRIDE;
    context_base = base + CONTEXT_BASE + context * CONTEXT_STRIDE;
    for (unsigned source = 0; source <= source_count; source += 32) {
        *enable_word(source) = 0;
    }
    *reg32(context_base) = 0; /* accept priorities above zero */
    sources = source_count;
    return 0;
}

int plic_register(unsigned source, plic_handler handler, void *context) {
    if (!source || source > sources || !handler) {
        return -1;
    }
    uint32_t previous = irq_save();
    if (vectors[source].handler) {
        irq_restore(previous);
        return -1;
    }
    vectors[source].handler = handler;
    vectors[source].context = context;
    *reg32(priority_base + source * 4u) = 1;
    *enable_word(source) |= 1u << (source % 32u);
    __asm__ volatile("fence iorw, iorw" ::: "memory");
    set_csr(mie, MIE_MEIE);
    irq_restore(previous);
    return 0;
}

void plic_dispatch(void) {
    if (!sources) {
        return;
    }
    volatile uint32_t *claim = reg32(context_base + CLAIM_OFFSET);
    uint32_t source = *claim;
    if (!source) {
        return;
    }
    bool known = source <= sources && vectors[source].handler;
    if (known) {
        vectors[source].handler(vectors[source].context);
    }
    /* Complete after the handler's MMIO acknowledgement reaches the device. */
    __asm__ volatile("fence iorw, iorw" ::: "memory");
    *claim = source;
    if (!known && source <= sources) {
        *enable_word(source) &= ~(1u << (source % 32u));
    }
}
