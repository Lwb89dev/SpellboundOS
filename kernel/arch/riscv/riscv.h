/* RISC-V machine-mode CSR and bit helpers (RV32, independently authored). */
#ifndef SPELLBOUND_RISCV_H
#define SPELLBOUND_RISCV_H

#include <stdint.h>

/* mstatus */
#define MSTATUS_MIE (1u << 3) /* machine interrupt enable */
#define MSTATUS_MPIE (1u << 7)
#define MSTATUS_MPP_MACHINE (3u << 11)

/* mie / mip */
#define MIE_MTIE (1u << 7) /* machine timer interrupt enable */
#define MIE_MSIE (1u << 3) /* machine software interrupt enable */
#define MIE_MEIE (1u << 11) /* machine external interrupt enable */

/* mcause: top bit set marks an interrupt; low bits are the code. */
#define MCAUSE_INTERRUPT (1u << 31)
#define IRQ_MACHINE_TIMER 7u
#define IRQ_MACHINE_EXTERNAL 11u
#define EXCEPTION_MACHINE_ECALL 11u

#define read_csr(reg)                                                          \
    ({                                                                         \
        uint32_t v;                                                            \
        __asm__ volatile("csrr %0, " #reg : "=r"(v));                          \
        v;                                                                     \
    })
#define write_csr(reg, val) __asm__ volatile("csrw " #reg ", %0" ::"r"(val))
#define set_csr(reg, bits) __asm__ volatile("csrs " #reg ", %0" ::"r"(bits))
#define clear_csr(reg, bits) __asm__ volatile("csrc " #reg ", %0" ::"r"(bits))

static inline uint32_t irq_save(void) {
    uint32_t previous;
    __asm__ volatile("csrrc %0, mstatus, %1"
                     : "=r"(previous) : "r"(MSTATUS_MIE) : "memory");
    return previous;
}

static inline void irq_restore(uint32_t previous) {
    if (previous & MSTATUS_MIE) {
        __asm__ volatile("csrs mstatus, %0" :: "r"(MSTATUS_MIE) : "memory");
    }
}

#endif /* SPELLBOUND_RISCV_H */
