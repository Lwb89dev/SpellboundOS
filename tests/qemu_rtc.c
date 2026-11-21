/* Runtime Goldfish RTC clock and PLIC alarm interrupt check on QEMU virt. */
#include <stdbool.h>
#include <stdint.h>
#include "../kernel/console.h"
#include "../kernel/driver.h"
#include "../kernel/rtc.h"
#include "../kernel/sched.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"

static _Alignas(16) uint32_t stack[256];
static struct task_event alarm_event;
static volatile unsigned alarm_fired;
static volatile unsigned failures;

static void on_rtc_alarm(void *context) {
    alarm_fired++;
    task_event_signal(context);
}

static void alarm_worker(void) {
    uint64_t before = rtc_read_ns();
    uint64_t target = before + 50000000ull; /* +50 ms */
    if (rtc_set_alarm_ns(target, on_rtc_alarm, &alarm_event) != 0) {
        failures++;
        return;
    }
    if (!task_event_wait_for(&alarm_event, 200)) {
        failures++;
        return;
    }
    uint64_t after = rtc_read_ns();
    if (alarm_fired != 1 || after < target) {
        failures++;
    }

    /* A cleared alarm must not fire. */
    if (rtc_set_alarm_ns(after + 20000000ull, on_rtc_alarm, &alarm_event) != 0 ||
        rtc_clear_alarm() != 0) {
        failures++;
        return;
    }
    if (task_event_wait_for(&alarm_event, 8) || alarm_fired != 1) {
        failures++;
    }
}

void kernel_main(void) {
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);

    struct device *rtc = device_find("rtc0");
    if (!rtc || !rtc->bound || !rtc_is_bound()) {
        failures++;
    }

    uint64_t t1 = rtc_read_ns();
    uint64_t t2 = rtc_read_ns();
    if (t1 == 0 || t2 < t1) {
        failures++;
    }

    struct rtc_datetime dt;
    rtc_unix_to_datetime(rtc_read_sec(), &dt);
    if (dt.year < 2020 || dt.month < 1 || dt.month > 12 || dt.day < 1 || dt.day > 31 ||
        dt.hour > 23 || dt.minute > 59 || dt.second > 59 || dt.weekday > 6) {
        failures++;
    }

    if (task_create(alarm_worker, stack, sizeof stack) < 0) {
        failures++;
    }
    sched_run();

    console_puts(failures ? "FAIL: Goldfish RTC and alarm\n" :
                            "PASS: Goldfish RTC and alarm\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}
