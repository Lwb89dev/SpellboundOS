/* Runtime check for MAX8617X optical decoder and integer HR estimator on RV32 QEMU virt. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../kernel/board.h"
#include "../kernel/console.h"
#include "../kernel/hr.h"
#include "../kernel/sensor.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/drivers/max8617x.h"

/* 40-sample triangle wave at 50 Hz = 0.8 s period = 75 BPM */
static int32_t synth_75bpm(uint32_t idx) {
    uint32_t phase = idx % 40u;
    int32_t tri = phase < 20u ? (int32_t)phase * 100 : (int32_t)(40u - phase) * 100;
    return 100000 + tri;
}

void kernel_main(void) {
    unsigned failures = 0;
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);

    struct max8617x_sample s;
    max8617x_decode_word((2u << 29) | (4u << 24) | 0xFFFFFu, &s);
    if (s.channel != 2 || s.meas_id != 4 || s.value != -1) {
        failures++;
    }

    struct hr_state hr;
    struct hr_config cfg = {.sample_rate_hz = 50u, .min_ac_amplitude = 300, .publish_sensor = false};
    hr_init(&hr, &cfg);
    for (uint32_t i = 0; i < 300u; i++) {
        (void)hr_feed_sample(&hr, synth_75bpm(i));
    }
    uint16_t bpm = hr_get_bpm(&hr);
    if (!hr_is_valid(&hr) || bpm < 72u || bpm > 78u) {
        failures++;
    }

    console_puts(failures ? "FAIL: optical PPG and HR estimator\n" :
                            "PASS: optical PPG and HR estimator\n");
    board_poweroff();
}
