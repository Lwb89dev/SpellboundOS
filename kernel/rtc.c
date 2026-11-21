/* Primary RTC binding and freestanding Unix-to-UTC calendar conversion. */
#include "rtc.h"
#include <stddef.h>

#define NS_PER_SEC 1000000000ull
#define SECS_PER_DAY 86400ull

static const struct rtc_ops *primary_rtc;
static uintptr_t rtc_context;

/* Freestanding 64-bit unsigned div/mod without libgcc (__udivdi3). */
static uint64_t u64_divmod(uint64_t dividend, uint64_t divisor, uint64_t *rem_out) {
    uint64_t quotient = 0;
    uint64_t rem = 0;
    for (int bit = 63; bit >= 0; bit--) {
        rem = (rem << 1) | ((dividend >> bit) & 1ull);
        if (rem >= divisor) {
            rem -= divisor;
            quotient |= 1ull << bit;
        }
    }
    if (rem_out) {
        *rem_out = rem;
    }
    return quotient;
}

int rtc_bind(const struct rtc_ops *ops, uintptr_t context) {
    if (!ops || !ops->read_ns || primary_rtc) {
        return -1;
    }
    rtc_context = context;
    primary_rtc = ops;
    return 0;
}

bool rtc_is_bound(void) {
    return primary_rtc != NULL;
}

uint64_t rtc_read_ns(void) {
    return primary_rtc ? primary_rtc->read_ns(rtc_context) : 0;
}

uint64_t rtc_read_sec(void) {
    return u64_divmod(rtc_read_ns(), NS_PER_SEC, NULL);
}

int rtc_set_alarm_ns(uint64_t time_ns, rtc_alarm_cb cb, void *cb_ctx) {
    if (!primary_rtc || !primary_rtc->set_alarm_ns) {
        return -1;
    }
    return primary_rtc->set_alarm_ns(rtc_context, time_ns, cb, cb_ctx);
}

int rtc_clear_alarm(void) {
    if (!primary_rtc || !primary_rtc->clear_alarm) {
        return -1;
    }
    return primary_rtc->clear_alarm(rtc_context);
}

void rtc_unix_to_datetime(uint64_t unix_sec, struct rtc_datetime *out) {
    if (!out) {
        return;
    }
    uint64_t rem_sec = 0;
    uint64_t days = u64_divmod(unix_sec, SECS_PER_DAY, &rem_sec);
    uint32_t sod = (uint32_t)rem_sec;

    out->hour = (uint8_t)(sod / 3600u);
    sod %= 3600u;
    out->minute = (uint8_t)(sod / 60u);
    out->second = (uint8_t)(sod % 60u);

    uint64_t dow_rem = 0;
    (void)u64_divmod(days + 4ull, 7ull, &dow_rem); /* 1970-01-01 was Thursday (4) */
    out->weekday = (uint8_t)dow_rem;

    /* Proleptic Gregorian civil-from-days shifted to 0000-03-01. */
    uint64_t z = days + 719468ull;
    uint64_t doe_u64 = 0;
    uint64_t era = u64_divmod(z, 146097ull, &doe_u64);
    uint32_t doe = (uint32_t)doe_u64;
    uint32_t yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
    uint64_t y = (uint64_t)yoe + era * 400ull;
    uint32_t doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
    uint32_t mp = (5u * doy + 2u) / 153u;
    uint32_t d = doy - (153u * mp + 2u) / 5u + 1u;
    uint32_t m = mp < 10u ? mp + 3u : mp - 9u;
    if (m <= 2u) {
        y++;
    }

    out->year = y;
    out->month = (uint8_t)m;
    out->day = (uint8_t)d;
}
