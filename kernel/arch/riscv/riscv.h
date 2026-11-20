/* RISC-V machine-mode CSR and bit helpers (RV32, independently authored). */
#ifndef SPELLBOUND_RISCV_H
#define SPELLBOUND_RISCV_H

#include <stdint.h>

/* mstatus */
#define MSTATUS_MIE (1u << 3) /* machine interrupt enable */

/* mie / mip */
#define MIE_MTIE (1u << 7) /* machine timer interrupt enable */
#define MIE_MSIE (1u << 3) /* machine software interrupt enable */
#define MIE_MEIE (1u << 11) /* machine external interrupt enable */

/* mcause: top bit set marks an interrupt; low bits are the code. */
#define MCAUSE_INTERRUPT (1u << 31)
#define IRQ_MACHINE_TIMER 7u

#define read_csr(reg)                                                          \
    ({                                                                         \
        uint32_t v;                                                            \
        __asm__ volatile("csrr %0, " #reg : "=r"(v));                          \
        v;                                                                     \
    })
#define write_csr(reg, val) __asm__ volatile("csrw " #reg ", %0" ::"r"(val))
#define set_csr(reg, bits) __asm__ volatile("csrs " #reg ", %0" ::"r"(bits))
#define clear_csr(reg, bits) __asm__ volatile("csrc " #reg ", %0" ::"r"(bits))

/* Caller-saved register frame pushed by trap_vector (see trap.S). */
struct trap_frame {
    uint32_t ra;
    uint32_t t[7]; /* t0..t6 */
    uint32_t a[8]; /* a0..a7 */
};

#endif /* SPELLBOUND_RISCV_H */
