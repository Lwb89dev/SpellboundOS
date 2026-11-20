.section .text.init
.globl _start
_start:
    csrr a0, mhartid
    bnez a0, .Lpark
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top
    la t0, __bss_start
    la t1, __bss_end
.Lzero:
    bgeu t0, t1, .Lstart
    sb zero, 0(t0)
    addi t0, t0, 1
    j .Lzero
.Lstart:
    call board_init
    bnez a0, .Lpark
    call kernel_main
.Lpark:
    wfi
    j .Lpark
