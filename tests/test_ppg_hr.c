/* Host unit tests for MAX8617X optical PPG SPI driver and integer HR estimator. */
#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"

static int mock_current_task = 0;
static uint64_t mock_ticks = 100;
static unsigned mock_irq_depth = 0;

static inline uint32_t irq_save(void) {
    mock_irq_depth++;
    return mock_irq_depth == 1 ? 8u : 0u;
}
static inline void irq_restore(uint32_t previous) {
    assert(mock_irq_depth > 0);
    if (previous & 8u) assert(mock_irq_depth == 1);
    mock_irq_depth--;
}
static uint64_t timer_ticks(void) { return mock_ticks; }
int task_current(void) { return mock_current_task; }
void task_event_signal(struct task_event *event) { event->pending = true; }
void task_event_wait(struct task_event *event) { event->pending = false; }
bool task_event_wait_for(struct task_event *event, uint32_t ticks) {
    if (event->pending) { event->pending = false; return true; }
    mock_ticks += ticks;
    return false;
}

#include "../kernel/bus.c"
#include "../kernel/sync.c"
#include "../kernel/sensor.c"
#include "../kernel/drivers/max8617x.c"
#include "../kernel/hr.c"

struct mock_max8617x {
    uint8_t regs[256];
    uint32_t fifo[64];
    uint16_t head;
    uint16_t count;
    uint16_t fake_count_override;
    bool use_fake_count;
};

static uint32_t pack_word(uint8_t ch, uint8_t meas, int32_t val) {
    return (((uint32_t)ch & 0x03u) << 29) |
           (((uint32_t)meas & 0x1Fu) << 24) |
           ((uint32_t)val & 0x000FFFFFu);
}

static int mock_ppg_spi(struct spi_bus *bus, const struct spi_config *cfg,
                        const struct spi_transfer *xfers, uint32_t count) {
    (void)cfg;
    struct mock_max8617x *m = bus->priv;
    assert(count == 1 && xfers[0].tx && xfers[0].len >= 3);
    uint8_t reg = xfers[0].tx[0];
    uint8_t op = xfers[0].tx[1];

    if (op == MAX8617X_SPI_WRITE_OP) {
        m->regs[reg] = xfers[0].tx[2];
        if (reg == MAX8617X_REG_FIFO_CFG2 && (xfers[0].tx[2] & 0x10u)) {
            m->count = 0;
            m->head = 0;
            m->use_fake_count = false;
        }
        return 0;
    }
    assert(op == MAX8617X_SPI_READ_OP && xfers[0].rx);
    if (reg == MAX8617X_REG_FIFO_DATA && xfers[0].len >= 6) {
        uint32_t words = (xfers[0].len - 2u) / 4u;
        for (uint32_t i = 0; i < words; i++) {
            assert(m->count > 0);
            uint32_t w = m->fifo[m->head];
            m->head = (uint16_t)((m->head + 1u) % 64u);
            m->count--;
            uint8_t *dst = &xfers[0].rx[2u + i * 4u];
            dst[0] = (uint8_t)(w >> 24);
            dst[1] = (uint8_t)(w >> 16);
            dst[2] = (uint8_t)(w >> 8);
            dst[3] = (uint8_t)w;
        }
        return 0;
    }
    uint16_t cnt = m->use_fake_count ? m->fake_count_override : m->count;
    if (reg == MAX8617X_REG_FIFO_OVF_CNT) {
        xfers[0].rx[2] = (uint8_t)(((cnt >> 8) & 0x03u) << 6);
        return 0;
    }
    if (reg == MAX8617X_REG_FIFO_DATA_CNT) {
        xfers[0].rx[2] = (uint8_t)(cnt & 0xFFu);
        return 0;
    }
    xfers[0].rx[2] = m->regs[reg];
    return 0;
}

static const struct spi_ops mock_ppg_ops = {.transfer = mock_ppg_spi};

struct cb_capture {
    struct max8617x_sample items[16];
    uint32_t n;
};
static void on_ppg_sample(const struct max8617x_sample *s, void *ctx) {
    struct cb_capture *c = ctx;
    assert(c->n < 16);
    c->items[c->n++] = *s;
}

static void test_max8617x_driver(void) {
    /* 20-bit signed decoding check (positive, -1, -524288) */
    struct max8617x_sample s;
    max8617x_decode_word(pack_word(2, 5, 12345), &s);
    assert(s.channel == 2 && s.meas_id == 5 && s.value == 12345);
    max8617x_decode_word(pack_word(1, 3, -1), &s);
    assert(s.channel == 1 && s.meas_id == 3 && s.value == -1);
    max8617x_decode_word(pack_word(0, 1, -524288), &s);
    assert(s.value == -524288);

    struct mock_max8617x mock = {0};
    mock.regs[MAX8617X_REG_PART_ID] = 0x3Au;
    struct spi_bus bus = {.name = "ppg_spi", .ops = &mock_ppg_ops, .priv = &mock};

    struct cb_capture cap = {0};
    struct max8617x_dev dev;
    struct max8617x_config cfg = {
        .bus = &bus,
        .spi_cfg = {.hz = 4000000u, .mode = 0, .cs = 1},
        .frame_words = 2,
        .expected_part_id = 0x3Au,
        .on_sample = on_ppg_sample,
        .cb_ctx = &cap,
    };

    assert(max8617x_init(&dev, &cfg) == 0 && dev.probed && dev.part_id == 0x3Au);
    assert(max8617x_enable(&dev, true) == 0 && dev.active);

    /* Push 5 words -> frame_words=2 aligns drain down to 4 words */
    for (int i = 0; i < 5; i++) {
        mock.fifo[mock.count++] = pack_word((uint8_t)(i & 1), 1, 10000 + i * 100);
    }
    int n = max8617x_fifo_drain(&dev, 16);
    assert(n == 4 && cap.n == 4 && mock.count == 1);
    assert(cap.items[0].value == 10000 && cap.items[3].value == 10300);

    /* Count >= 512 triggers recovery and returns -4 */
    mock.use_fake_count = true;
    mock.fake_count_override = 512;
    assert(max8617x_fifo_drain(&dev, 16) == -4);
    assert(dev.recovery_count == 1 && mock.count == 0);

    /* Wrong part ID returns -3 */
    mock.regs[MAX8617X_REG_PART_ID] = 0x11u;
    assert(max8617x_init(&dev, &cfg) == -3);
}

static void run_synthetic_hr(uint16_t target_bpm) {
    struct sensor_sample sq[32];
    assert(sensor_init(sq, 32) == 0);

    struct hr_state hr;
    struct hr_config cfg = {
        .sample_rate_hz = 50u,
        .min_ac_amplitude = 300,
        .publish_sensor = true,
    };
    hr_init(&hr, &cfg);

    /* Generate 8 seconds of clean PPG sine waveform at 50 Hz */
    const double two_pi = 6.283185307179586;
    double freq_hz = (double)target_bpm / 60.0;
    for (int i = 0; i < 400; i++) {
        double t = (double)i / 50.0;
        int32_t raw = 100000 + (int32_t)(1200.0 * sin(two_pi * freq_hz * t));
        (void)hr_feed_sample(&hr, raw);
    }
    assert(hr_is_valid(&hr));
    int diff = (int)hr_get_bpm(&hr) - (int)target_bpm;
    if (diff < 0) diff = -diff;
    assert(diff <= 2);

    struct sensor_sample s;
    assert(sensor_poll(&s) && s.type == SENSOR_HEART_RATE && s.x >= target_bpm - 3 && s.x <= target_bpm + 3);

    /* Flatline for > 3 seconds (200 samples at 50 Hz) invalidates HR */
    for (int i = 0; i < 200; i++) {
        (void)hr_feed_sample(&hr, 100000);
    }
    assert(!hr_is_valid(&hr) && hr_get_bpm(&hr) == 0);
}

int main(void) {
    test_max8617x_driver();
    run_synthetic_hr(60);
    run_synthetic_hr(75);
    run_synthetic_hr(140);
    assert(mock_irq_depth == 0);
    printf("PASS: MAX8617X optical PPG driver and integer HR estimator\n");
    return 0;
}
