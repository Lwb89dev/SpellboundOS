/* Pure-integer PPG heart rate estimator (40..220 BPM, median-of-5 IBI filter). */
#ifndef SPELLBOUND_HR_H
#define SPELLBOUND_HR_H

#include <stdbool.h>
#include <stdint.h>

#define HR_IBI_HISTORY 5u

struct hr_config {
    uint16_t sample_rate_hz; /* e.g. 25, 50 or 100 Hz */
    int32_t min_ac_amplitude; /* minimum peak-to-valley AC swing for valid contact */
    bool publish_sensor;      /* post SENSOR_HEART_RATE updates to sensor.h */
};

struct hr_state {
    struct hr_config cfg;
    bool initialized;
    int32_t dc_avg;
    int32_t lp_val;
    int32_t prev_lp;
    int32_t prev_slope;
    int32_t cycle_min;
    int32_t cycle_max;
    uint32_t sample_index;
    uint32_t last_peak_index;
    bool has_peak;
    uint32_t ibi_ring[HR_IBI_HISTORY];
    uint8_t ibi_count;
    uint8_t ibi_pos;
    uint16_t bpm;
    bool valid;
    uint32_t stale_samples;
};

void hr_init(struct hr_state *st, const struct hr_config *cfg);
void hr_reset(struct hr_state *st);

/* Feed one raw PPG sample. Returns true when a new heart-rate beat estimate is updated. */
bool hr_feed_sample(struct hr_state *st, int32_t raw_ppg);

uint16_t hr_get_bpm(const struct hr_state *st);
bool hr_is_valid(const struct hr_state *st);

#endif /* SPELLBOUND_HR_H */
