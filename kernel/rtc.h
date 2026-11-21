/* Hardware-independent real-time clock interface and UTC calendar conversion. */
#ifndef SPELLBOUND_RTC_H
#define SPELLBOUND_RTC_H

#include <stdbool.h>
#include <stdint.h>

typedef void (*rtc_alarm_cb)(void *context);

struct rtc_ops {
    uint64_t (*read_ns)(uintptr_t context);
    int (*set_alarm_ns)(uintptr_t context, uint64_t time_ns, rtc_alarm_cb cb, void *cb_ctx);
    int (*clear_alarm)(uintptr_t context);
};

struct rtc_datetime {
    uint64_t year;   /* full Gregorian year, e.g. 2026 */
    uint8_t month;   /* 1..12 */
    uint8_t day;     /* 1..31 */
    uint8_t hour;    /* 0..23 */
    uint8_t minute;  /* 0..59 */
    uint8_t second;  /* 0..59 */
    uint8_t weekday; /* 0=Sunday .. 6=Saturday */
};

/* Bind the primary RTC once during boot. The ops table must remain valid. */
int rtc_bind(const struct rtc_ops *ops, uintptr_t context);
bool rtc_is_bound(void);

uint64_t rtc_read_ns(void);
uint64_t rtc_read_sec(void);
int rtc_set_alarm_ns(uint64_t time_ns, rtc_alarm_cb cb, void *cb_ctx);
int rtc_clear_alarm(void);

/* Convert seconds since 1970-01-01 00:00:00 UTC to proleptic Gregorian UTC. */
void rtc_unix_to_datetime(uint64_t unix_sec, struct rtc_datetime *out);

#endif /* SPELLBOUND_RTC_H */
