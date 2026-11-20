/* Cooperative context switch (RV32). context_switch(old_sp, new_sp) saves the
 * callee-saved registers and ra of the current task to its stack, stores the
 * stack pointer through old_sp, then loads the next task's stack pointer from
 * new_sp and restores its context.  a0 = uint32_t **old_sp, a1 = uint32_t *new_sp. */
.section .text
.globl context_switch
context_switch:
    /* Keep the stack ABI-aligned even if an interrupt arrives here. */
    addi sp, sp, -64
    sw ra,  0(sp)
    sw s0,  4(sp)
    sw s1,  8(sp)
    sw s2, 12(sp)
    sw s3, 16(sp)
    sw s4, 20(sp)
    sw s5, 24(sp)
    sw s6, 28(sp)
    sw s7, 32(sp)
    sw s8, 36(sp)
    sw s9, 40(sp)
    sw s10, 44(sp)
    sw s11, 48(sp)
    sw sp, 0(a0)        /* *old_sp = sp */

    mv sp, a1           /* sp = new_sp */
    lw ra,  0(sp)
    lw s0,  4(sp)
    lw s1,  8(sp)
    lw s2, 12(sp)
    lw s3, 16(sp)
    lw s4, 20(sp)
    lw s5, 24(sp)
    lw s6, 28(sp)
    lw s7, 32(sp)
    lw s8, 36(sp)
    lw s9, 40(sp)
    lw s10, 44(sp)
    lw s11, 48(sp)
    addi sp, sp, 64
    ret

/* First entry into a task: context_switch restored s0 = task function and
 * s1 = task_exit; call the function, then fall through to task_exit. */
.globl task_trampoline
task_trampoline:
    jalr s0
    jalr s1
.Lhang:
    wfi
    j .Lhang
