/* RISC-V machine timer over board-provided registers. */
#include "riscv.h"
#include "timer.h"
#include "../../board.h"

static uint32_t interval;        /* mtime ticks between interrupts */
static volatile uint64_t ticks;  /* elapsed timer interrupts */

static uint64_t mtime_read(void) {
    volatile uint32_t *mtime = (volatile uint32_t *)board_timer.time;
    uint32_t hi, lo, hi2;
    do {
        hi = mtime[1];
        lo = mtime[0];
        hi2 = mtime[1];
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}

static void mtimecmp_write(uint64_t value) {
    volatile uint32_t *mtimecmp = (volatile uint32_t *)board_timer.compare;
    /* Avoid a spurious match while the halves are inconsistent. */
    mtimecmp[0] = 0xffffffffu;
    mtimecmp[1] = (uint32_t)(value >> 32);
    mtimecmp[0] = (uint32_t)value;
}

void timer_init(uint32_t hz) {
    interval = hz ? (board_timer.frequency / hz) : board_timer.frequency;
    if (interval == 0) interval = 1;
    ticks = 0;
    mtimecmp_write(mtime_read() + interval);
    set_csr(mie, MIE_MTIE);
}

void timer_on_tick(void) {
    ticks++;
    mtimecmp_write(mtime_read() + interval);
}

uint64_t timer_ticks(void) {
    /* RV32 cannot load the counter atomically. Preserve the caller's MIE
     * state while preventing a tick between the two 32-bit loads. */
    uint32_t previous = irq_save();
    uint64_t value = ticks;
    irq_restore(previous);
    return value;
}
