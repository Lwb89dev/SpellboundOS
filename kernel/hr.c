/* Pure-integer PPG heart rate estimator (40..220 BPM, median-of-5 IBI filter). */
#include "hr.h"
#include "sensor.h"
#include <stddef.h>

static uint16_t trimmed_mean_bpm(uint16_t sample_rate_hz, const uint32_t *vals, uint8_t count) {
    uint32_t tmp[HR_IBI_HISTORY];
    for (uint8_t i = 0; i < count; i++) tmp[i] = vals[i];
    /* Insertion sort on <= 5 elements */
    for (uint8_t i = 1; i < count; i++) {
        uint32_t key = tmp[i];
        int j = (int)i - 1;
        while (j >= 0 && tmp[j] > key) {
            tmp[j + 1] = tmp[j];
            j--;
        }
        tmp[j + 1] = key;
    }
    /* Drop min & max outlier when >= 4 samples; average middle samples for sub-sample precision. */
    uint8_t start = count >= 4u ? 1u : 0u;
    uint8_t end = count >= 4u ? (uint8_t)(count - 1u) : count;
    uint32_t sum = 0;
    uint32_t n = 0;
    for (uint8_t i = start; i < end; i++) {
        sum += tmp[i];
        n++;
    }
    if (sum == 0 || n == 0) return 0u;
    uint32_t num = (uint32_t)sample_rate_hz * 60u * n;
    return (uint16_t)((num + sum / 2u) / sum);
}

void hr_init(struct hr_state *st, const struct hr_config *cfg) {
    if (!st) return;
    if (cfg) {
        st->cfg = *cfg;
    } else {
        st->cfg = (struct hr_config){
            .sample_rate_hz = 50u,
            .min_ac_amplitude = 200,
            .publish_sensor = false,
        };
    }
    if (st->cfg.sample_rate_hz == 0) st->cfg.sample_rate_hz = 50u;
    if (st->cfg.min_ac_amplitude <= 0) st->cfg.min_ac_amplitude = 200;
    hr_reset(st);
}

void hr_reset(struct hr_state *st) {
    if (!st) return;
    st->initialized = false;
    st->dc_avg = 0;
    st->lp_val = 0;
    st->prev_lp = 0;
    st->prev_slope = 0;
    st->cycle_min = 0;
    st->cycle_max = 0;
    st->sample_index = 0;
    st->last_peak_index = 0;
    st->has_peak = false;
    st->ibi_count = 0;
    st->ibi_pos = 0;
    st->bpm = 0;
    st->valid = false;
    st->stale_samples = 0;
}

bool hr_feed_sample(struct hr_state *st, int32_t raw_ppg) {
    if (!st) return false;
    if (!st->initialized) {
        st->dc_avg = raw_ppg;
        st->lp_val = 0;
        st->prev_lp = 0;
        st->prev_slope = 0;
        st->cycle_min = 0;
        st->cycle_max = 0;
        st->initialized = true;
        st->sample_index = 1u;
        return false;
    }

    st->sample_index++;
    st->stale_samples++;

    /* Slow DC removal (31/32 old + 1/32 new) + light low-pass on AC component. */
    st->dc_avg += (raw_ppg - st->dc_avg) / 32;
    int32_t ac = raw_ppg - st->dc_avg;
    st->prev_lp = st->lp_val;
    st->lp_val += (ac - st->lp_val) / 2;

    if (st->lp_val < st->cycle_min) st->cycle_min = st->lp_val;
    if (st->lp_val > st->cycle_max) st->cycle_max = st->lp_val;

    /* Drop validity if no valid beat seen for > 3 seconds. */
    uint32_t timeout_samples = (uint32_t)st->cfg.sample_rate_hz * 3u;
    if (st->stale_samples > timeout_samples) {
        st->valid = false;
        st->bpm = 0;
        st->ibi_count = 0;
        st->has_peak = false;
    }

    int32_t slope = st->lp_val - st->prev_lp;
    bool beat_detected = false;

    /* Local maximum: slope crossed from > 0 to <= 0 while above zero with adequate AC swing. */
    if (st->prev_slope > 0 && slope <= 0 && st->prev_lp > 0) {
        int32_t swing = st->cycle_max - st->cycle_min;
        if (swing >= st->cfg.min_ac_amplitude) {
            uint32_t peak_idx = st->sample_index - 1u;
            uint32_t min_ibi = ((uint32_t)st->cfg.sample_rate_hz * 60u) / 220u; /* 220 BPM */
            uint32_t max_ibi = ((uint32_t)st->cfg.sample_rate_hz * 60u) / 40u;  /* 40 BPM */
            if (min_ibi < 2u) min_ibi = 2u;

            if (!st->has_peak) {
                st->has_peak = true;
                st->last_peak_index = peak_idx;
                st->cycle_min = st->lp_val;
                st->cycle_max = st->lp_val;
            } else {
                uint32_t ibi = peak_idx - st->last_peak_index;
                if (ibi >= min_ibi && ibi <= max_ibi) {
                    st->last_peak_index = peak_idx;
                    st->cycle_min = st->lp_val;
                    st->cycle_max = st->lp_val;
                    st->stale_samples = 0;

                    st->ibi_ring[st->ibi_pos] = ibi;
                    st->ibi_pos = (uint8_t)((st->ibi_pos + 1u) % HR_IBI_HISTORY);
                    if (st->ibi_count < HR_IBI_HISTORY) st->ibi_count++;

                    if (st->ibi_count >= 3u) {
                        st->bpm = trimmed_mean_bpm(st->cfg.sample_rate_hz, st->ibi_ring, st->ibi_count);
                        st->valid = true;
                        beat_detected = true;
                        if (st->cfg.publish_sensor) {
                            struct sensor_sample s = {
                                .timestamp_ticks = 0,
                                .type = SENSOR_HEART_RATE,
                                .x = (int32_t)st->bpm,
                            };
                            (void)sensor_post(&s);
                        }
                    }
                } else if (ibi > max_ibi) {
                    st->last_peak_index = peak_idx;
                    st->cycle_min = st->lp_val;
                    st->cycle_max = st->lp_val;
                }
            }
        }
    }

    st->prev_slope = slope;
    return beat_detected;
}

uint16_t hr_get_bpm(const struct hr_state *st) {
    return (st && st->valid) ? st->bpm : 0u;
}

bool hr_is_valid(const struct hr_state *st) {
    return st && st->valid;
}
