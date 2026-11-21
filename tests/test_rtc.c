/* Host unit test for kernel/rtc.c and kernel/drivers/goldfish_rtc.c. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1

typedef void (*plic_handler)(void *context);

static unsigned mock_irq_depth = 0;
static unsigned mock_plic_source = 0;
static plic_handler mock_plic_handler = NULL;
static void *mock_plic_context = NULL;
static unsigned mock_plic_registrations = 0;

static inline uint32_t irq_save(void) {
    mock_irq_depth++;
    return mock_irq_depth == 1 ? 8u : 0u;
}

static inline void irq_restore(uint32_t previous) {
    assert(mock_irq_depth > 0);
    if (previous & 8u) {
        assert(mock_irq_depth == 1);
    }
    mock_irq_depth--;
}

static int plic_register(unsigned source, plic_handler handler, void *context) {
    mock_plic_registrations++;
    mock_plic_source = source;
    mock_plic_handler = handler;
    mock_plic_context = context;
    return 0;
}

#include "../kernel/driver.c"
#include "../kernel/rtc.c"
#include "../kernel/drivers/goldfish_rtc.c"

static unsigned alarm_calls = 0;
static void *alarm_seen_ctx = NULL;

static void on_alarm(void *ctx) {
    alarm_calls++;
    alarm_seen_ctx = ctx;
}

static void check_date(uint64_t unix_sec, uint64_t year, uint8_t month, uint8_t day,
                       uint8_t hour, uint8_t minute, uint8_t second, uint8_t weekday) {
    struct rtc_datetime dt;
    rtc_unix_to_datetime(unix_sec, &dt);
    assert(dt.year == year);
    assert(dt.month == month);
    assert(dt.day == day);
    assert(dt.hour == hour);
    assert(dt.minute == minute);
    assert(dt.second == second);
    assert(dt.weekday == weekday);
}

static void test_calendar(void) {
    /* Unix epoch: 1970-01-01 00:00:00 UTC (Thursday = 4). */
    check_date(0ull, 1970, 1, 1, 0, 0, 0, 4);
    /* Leap day on a 400-year century: 2000-02-29 23:59:59 UTC (Tuesday = 2). */
    check_date(951868799ull, 2000, 2, 29, 23, 59, 59, 2);
    /* Modern leap day: 2024-02-29 12:34:56 UTC (Thursday = 4). */
    check_date(1709210096ull, 2024, 2, 29, 12, 34, 56, 4);
    /* 2026-11-21 19:14:12 UTC (Saturday = 6). */
    check_date(1795288452ull, 2026, 11, 21, 19, 14, 12, 6);
    /* Signed 32-bit time_t overflow: 2038-01-19 03:14:08 UTC (Tuesday = 2). */
    check_date(0x80000000ull, 2038, 1, 19, 3, 14, 8, 2);
    /* Non-leap century: 2100-02-28 -> 2100-03-01 (Monday = 1). */
    check_date(4107456000ull, 2100, 2, 28, 0, 0, 0, 0);
    check_date(4107542400ull, 2100, 3, 1, 0, 0, 0, 1);

    /* Extreme 64-bit value must not trigger undefined behavior or invalid fields. */
    struct rtc_datetime max_dt;
    rtc_unix_to_datetime(UINT64_MAX, &max_dt);
    assert(max_dt.year > 500000000000ull);
    assert(max_dt.month >= 1 && max_dt.month <= 12);
    assert(max_dt.day >= 1 && max_dt.day <= 31);
    assert(max_dt.hour <= 23 && max_dt.minute <= 59 && max_dt.second <= 59);
    assert(max_dt.weekday <= 6);
}

static void test_goldfish_driver(void) {
    uint32_t mock_regs[8] = {0};
    mock_regs[RTC_IRQ_ENABLED] = 1u;

    assert(!rtc_is_bound());
    assert(rtc_read_ns() == 0 && rtc_read_sec() == 0);
    assert(rtc_set_alarm_ns(1000, on_alarm, NULL) == -1);
    assert(rtc_clear_alarm() == -1);

    driver_registry_reset();
    assert(driver_register(&goldfish_rtc_driver) == 0);
    static struct device rtc0 = {
        .name = "rtc0",
        .driver = GOLDFISH_RTC_DRIVER_NAME,
        .irq = 11,
    };
    rtc0.base = (uintptr_t)mock_regs;
    assert(device_register(&rtc0) == 0);
    assert(drivers_probe() == 1);
    assert(rtc0.bound == &goldfish_rtc_driver);
    assert(rtc_is_bound());
    /* Probe masks and clears hardware IRQ/alarm state. */
    assert(mock_regs[RTC_IRQ_ENABLED] == 0u);
    assert(mock_regs[RTC_CLEAR_ALARM] == 1u);
    assert(mock_regs[RTC_CLEAR_INTERRUPT] == 1u);

    /* 64-bit wall clock read (2026-11-21 19:14:12.500000000 UTC). */
    const uint64_t now_ns = 1795288452ull * NS_PER_SEC + 500000000ull;
    mock_regs[RTC_TIME_LOW] = (uint32_t)now_ns;
    mock_regs[RTC_TIME_HIGH] = (uint32_t)(now_ns >> 32);
    assert(rtc_read_ns() == now_ns);
    assert(rtc_read_sec() == 1795288452ull);

    /* Arm alarm and confirm PLIC registration + ALARM_HIGH/ALARM_LOW writes. */
    int cookie = 42;
    const uint64_t target_ns = now_ns + 50000000ull;
    assert(rtc_set_alarm_ns(target_ns, on_alarm, &cookie) == 0);
    assert(mock_plic_registrations == 1 && mock_plic_source == 11);
    assert(mock_plic_handler != NULL);
    assert(mock_regs[RTC_IRQ_ENABLED] == 1u);
    assert(mock_regs[RTC_ALARM_HIGH] == (uint32_t)(target_ns >> 32));
    assert(mock_regs[RTC_ALARM_LOW] == (uint32_t)target_ns);

    /* Simulated PLIC delivery clears IRQ, disables alarm IRQ, invokes callback once. */
    mock_regs[RTC_CLEAR_INTERRUPT] = 0u;
    mock_plic_handler(mock_plic_context);
    assert(mock_regs[RTC_CLEAR_INTERRUPT] == 1u);
    assert(mock_regs[RTC_IRQ_ENABLED] == 0u);
    assert(alarm_calls == 1 && alarm_seen_ctx == &cookie);

    /* Second alarm reuses PLIC registration; clear_alarm cancels callback. */
    assert(rtc_set_alarm_ns(target_ns + 1000ull, on_alarm, &cookie) == 0);
    assert(mock_plic_registrations == 1);
    mock_regs[RTC_CLEAR_ALARM] = 0u;
    assert(rtc_clear_alarm() == 0);
    assert(mock_regs[RTC_IRQ_ENABLED] == 0u && mock_regs[RTC_CLEAR_ALARM] == 1u);
    mock_plic_handler(mock_plic_context);
    assert(alarm_calls == 1);
    assert(mock_irq_depth == 0);
}

int main(void) {
    test_calendar();
    test_goldfish_driver();
    printf("PASS: rtc calendar and goldfish-rtc driver\n");
    return 0;
}
