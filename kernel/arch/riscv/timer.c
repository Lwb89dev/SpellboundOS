/* Machine timer on the QEMU virt CLINT (0x02000000). Board-specific: the Bip 6
 * SoC timer will have its own driver behind the same timer_* interface. */
#include "riscv.h"
#include "timer.h"

#define CLINT_BASE 0x02000000u
#define CLINT_MTIMECMP (CLINT_BASE + 0x4000u) /* hart 0, 64-bit */
#define CLINT_MTIME (CLINT_BASE + 0xbff8u)    /* 64-bit, 10 MHz on QEMU virt */

#define TIMER_HZ 10000000u /* QEMU virt mtime frequency */

static volatile uint32_t *const mtimecmp = (volatile uint32_t *)CLINT_MTIMECMP;
static volatile uint32_t *const mtime = (volatile uint32_t *)CLINT_MTIME;

static uint32_t interval;        /* mtime ticks between interrupts */
static volatile uint64_t ticks;  /* elapsed timer interrupts */

static uint64_t mtime_read(void) {
    uint32_t hi, lo, hi2;
    do {
        hi = mtime[1];
        lo = mtime[0];
        hi2 = mtime[1];
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}

static void mtimecmp_write(uint64_t value) {
    /* Avoid a spurious match while the halves are inconsistent. */
    mtimecmp[0] = 0xffffffffu;
    mtimecmp[1] = (uint32_t)(value >> 32);
    mtimecmp[0] = (uint32_t)value;
}

void timer_init(uint32_t hz) {
    interval = hz ? (TIMER_HZ / hz) : TIMER_HZ;
    ticks = 0;
    mtimecmp_write(mtime_read() + interval);
    set_csr(mie, MIE_MTIE);
}

void timer_on_tick(void) {
    ticks++;
    mtimecmp_write(mtime_read() + interval);
}

uint64_t timer_ticks(void) {
    return ticks;
}
