/* Host unit tests for sensor queue, LSM6DSO SPI IMU driver and ZTW622 I2C touch driver. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SPELLBOUND_HOST_TEST 1
#include "../kernel/sched.h"

static int mock_current_task = 0;
static uint64_t mock_ticks = 500;
static unsigned mock_irq_depth = 0;

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

static uint64_t timer_ticks(void) {
    return mock_ticks;
}

int task_current(void) {
    return mock_current_task;
}

void task_event_signal(struct task_event *event) {
    event->pending = true;
}

void task_event_wait(struct task_event *event) {
    assert(mock_irq_depth == 0);
    event->pending = false;
}

bool task_event_wait_for(struct task_event *event, uint32_t ticks) {
    assert(mock_irq_depth == 0);
    if (event->pending) {
        event->pending = false;
        return true;
    }
    mock_ticks += ticks;
    return false;
}

#include "../kernel/bus.c"
#include "../kernel/sync.c"
#include "../kernel/input.c"
#include "../kernel/sensor.c"
#include "../kernel/drivers/lsm6dso.c"
#include "../kernel/drivers/ztw622.c"

static uint32_t total_delay_ms = 0;
static void mock_delay(uint32_t ms, void *ctx) {
    (void)ctx;
    total_delay_ms += ms;
}

/* ---- Mock LSM6DSO over SPI ---- */

struct mock_lsm6dso {
    uint8_t regs[128];
    uint8_t fifo[64][7];
    uint16_t fifo_head;
    uint16_t fifo_count;
    bool fifo_overrun;
    uint32_t reset_polls_left;
    uint32_t fail_reads;
    uint32_t spi_calls;
};

static void mock_lsm_reset(struct mock_lsm6dso *m) {
    memset(m, 0, sizeof *m);
    m->regs[LSM6DSO_REG_WHO_AM_I] = LSM6DSO_WHO_AM_I_VAL;
    m->regs[LSM6DSO_REG_CTRL3_C] = 0x04; /* IF_INC default */
}

static void mock_lsm_push_word(struct mock_lsm6dso *m, uint8_t tag,
                               int16_t x, int16_t y, int16_t z) {
    uint16_t idx = (uint16_t)((m->fifo_head + m->fifo_count) % 64u);
    m->fifo[idx][0] = (uint8_t)(tag << 3);
    m->fifo[idx][1] = (uint8_t)((uint16_t)x & 0xFFu);
    m->fifo[idx][2] = (uint8_t)((uint16_t)x >> 8);
    m->fifo[idx][3] = (uint8_t)((uint16_t)y & 0xFFu);
    m->fifo[idx][4] = (uint8_t)((uint16_t)y >> 8);
    m->fifo[idx][5] = (uint8_t)((uint16_t)z & 0xFFu);
    m->fifo[idx][6] = (uint8_t)((uint16_t)z >> 8);
    m->fifo_count++;
}

static int mock_spi_transfer(struct spi_bus *bus, const struct spi_config *cfg,
                             const struct spi_transfer *xfers, uint32_t count) {
    (void)cfg;
    struct mock_lsm6dso *m = bus->priv;
    m->spi_calls++;
    assert(count == 1 && xfers[0].tx && xfers[0].len >= 2);
    uint8_t cmd = xfers[0].tx[0];
    bool is_read = (cmd & 0x80u) != 0;
    uint8_t reg = (uint8_t)(cmd & 0x7Fu);

    if (is_read) {
        if (m->fail_reads > 0) {
            m->fail_reads--;
            return -1;
        }
        assert(xfers[0].rx != NULL);
        xfers[0].rx[0] = 0xFF;
        uint32_t n = xfers[0].len - 1u;
        if (reg == LSM6DSO_REG_FIFO_DATA_TAG) {
            assert((n % 7u) == 0);
            uint32_t words = n / 7u;
            for (uint32_t w = 0; w < words; w++) {
                assert(m->fifo_count > 0);
                memcpy(&xfers[0].rx[1u + w * 7u], m->fifo[m->fifo_head], 7);
                m->fifo_head = (uint16_t)((m->fifo_head + 1u) % 64u);
                m->fifo_count--;
            }
            return 0;
        }
        if (reg == LSM6DSO_REG_FIFO_STATUS1) {
            m->regs[LSM6DSO_REG_FIFO_STATUS1] = (uint8_t)(m->fifo_count & 0xFFu);
            m->regs[LSM6DSO_REG_FIFO_STATUS2] = (uint8_t)(((m->fifo_count >> 8) & 0x03u) |
                                                          (m->fifo_overrun ? 0x40u : 0x00u));
        }
        if (reg == LSM6DSO_REG_CTRL3_C && (m->regs[reg] & 0x01u)) {
            if (m->reset_polls_left > 0) {
                m->reset_polls_left--;
            } else {
                m->regs[reg] &= (uint8_t)(~0x01u);
            }
        }
        for (uint32_t i = 0; i < n; i++) {
            uint8_t r = (uint8_t)((reg + i) & 0x7Fu);
            xfers[0].rx[1u + i] = m->regs[r];
        }
        return 0;
    }

    /* Register write */
    uint8_t val = xfers[0].tx[1];
    m->regs[reg] = val;
    if (reg == LSM6DSO_REG_FIFO_CTRL4 && (val & 0x07u) == 0) {
        m->fifo_overrun = false;
        m->fifo_count = 0;
    }
    return 0;
}

static const struct spi_ops mock_spi_ops = {.transfer = mock_spi_transfer};

/* ---- Mock ZTW622 over I2C + GPIO ---- */

struct mock_ztw622 {
    uint16_t selected_reg;
    uint16_t chip_id_info;
    uint16_t chip_id_reg;
    uint16_t fw_major, fw_minor, fw_release;
    uint16_t x_res, y_res, x_ch, y_ch;
    uint16_t active_cfg, nap_delay;
    uint16_t gesture_reg;
    uint8_t point_blk[16];
    uint32_t clear_int_calls;
    uint32_t reset_calls;
    uint32_t inject_fail_once;
    uint32_t gpio_toggles;
    bool fail_info_blk;
};

static void put_le16_t(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)(v >> 8);
}

static int mock_i2c_transfer(struct i2c_bus *bus, const struct i2c_msg *msgs, uint32_t count) {
    struct mock_ztw622 *z = bus->priv;
    assert(count == 1 && msgs[0].addr == ZTW622_I2C_ADDR);
    if (z->inject_fail_once > 0) {
        z->inject_fail_once--;
        return -1;
    }
    if ((msgs[0].flags & I2C_MSG_READ) == 0) {
        assert(msgs[0].len == 2 || msgs[0].len == 4);
        uint16_t reg = (uint16_t)msgs[0].buf[0] | ((uint16_t)msgs[0].buf[1] << 8);
        z->selected_reg = reg;
        if (msgs[0].len == 2) {
            if (reg == ZTW622_CMD_CLEAR_INT) {
                z->clear_int_calls++;
            }
            return 0;
        }
        uint16_t val = (uint16_t)msgs[0].buf[2] | ((uint16_t)msgs[0].buf[3] << 8);
        if (reg == ZTW622_REG_ACTIVE_CFG) z->active_cfg = val;
        if (reg == ZTW622_REG_NAP_DELAY) z->nap_delay = val;
        if (reg == ZTW622_REG_GESTURE_ID) z->gesture_reg = val;
        return 0;
    }

    /* Read from selected_reg */
    if (z->selected_reg == ZTW622_REG_INFO_BLOCK) {
        if (z->fail_info_blk) {
            return -1;
        }
        assert(msgs[0].len == 22);
        memset(msgs[0].buf, 0, 22);
        msgs[0].buf[8] = 0x12;
        msgs[0].buf[0x0C] = 0x56;
        msgs[0].buf[0x0D] = 0x34;
        put_le16_t(&msgs[0].buf[0x0A], z->chip_id_info);
        return 0;
    }
    if (z->selected_reg == ZTW622_REG_POINT_STATUS) {
        assert(msgs[0].len == 16);
        memcpy(msgs[0].buf, z->point_blk, 16);
        return 0;
    }
    assert(msgs[0].len == 2);
    uint16_t val = 0;
    switch (z->selected_reg) {
    case ZTW622_REG_CHIP_ID:    val = z->chip_id_reg; break;
    case ZTW622_REG_FW_MAJOR:   val = z->fw_major; break;
    case ZTW622_REG_FW_MINOR:   val = z->fw_minor; break;
    case ZTW622_REG_FW_RELEASE: val = z->fw_release; break;
    case ZTW622_REG_X_RES:      val = z->x_res; break;
    case ZTW622_REG_Y_RES:      val = z->y_res; break;
    case ZTW622_REG_X_CHANNELS: val = z->x_ch; break;
    case ZTW622_REG_Y_CHANNELS: val = z->y_ch; break;
    case ZTW622_REG_GESTURE_ID: val = z->gesture_reg; break;
    default: break;
    }
    put_le16_t(msgs[0].buf, val);
    return 0;
}

static int mock_i2c_reset(struct i2c_bus *bus) {
    struct mock_ztw622 *z = bus->priv;
    z->reset_calls++;
    return 0;
}

static const struct i2c_ops mock_i2c_ops = {
    .transfer = mock_i2c_transfer,
    .reset = mock_i2c_reset,
};

static int mock_gpio_cfg(struct gpio_chip *chip, uint32_t pin, enum gpio_mode mode) {
    (void)chip; (void)pin; (void)mode;
    return 0;
}
static int mock_gpio_write(struct gpio_chip *chip, uint32_t pin, bool high) {
    (void)pin; (void)high;
    struct mock_ztw622 *z = chip->priv;
    z->gpio_toggles++;
    return 0;
}
static const struct gpio_ops mock_gpio_ops = {
    .configure = mock_gpio_cfg,
    .write = mock_gpio_write,
};

/* ---- Tests ---- */

static void test_sensor_queue_and_remap(void) {
    struct sensor_sample storage[4];
    assert(sensor_init(NULL, 4) == -1);
    assert(sensor_init(storage, 0) == -1);
    assert(sensor_init(storage, 4) == 0);
    assert(sensor_pending() == 0 && sensor_dropped() == 0);

    for (int i = 0; i < 6; i++) {
        mock_ticks = 1000u + (uint64_t)i;
        struct sensor_sample s = {.type = SENSOR_ACCEL, .x = i, .y = -i, .z = 4096};
        bool ok = sensor_post(&s);
        assert(ok == (i < 4));
    }
    assert(sensor_pending() == 4);
    assert(sensor_dropped() == 2);

    struct sensor_sample out;
    assert(sensor_poll(&out) && out.timestamp_ticks == 1000u && out.x == 0 && out.z == 4096);
    assert(sensor_wait_for(&out, 5) && out.x == 1);

    /* Orientation remap: check all 8 orientations + wrist flip + bounds */
    int16_t x = 10, y = 20, z = 30;
    assert(!sensor_remap_xyz(8, false, &x, &y, &z));
    assert(x == 10 && y == 20 && z == 30);

    assert(sensor_remap_xyz(5, false, &x, &y, &z)); /* (y, -x, z) */
    assert(x == 20 && y == -10 && z == 30);

    x = 10; y = 20; z = 30;
    assert(sensor_remap_xyz(0, true, &x, &y, &z)); /* (-x, -y, z) */
    assert(x == -10 && y == -20 && z == 30);

    /* INT16_MIN clamping safety */
    x = -32768; y = 0; z = -32768;
    assert(sensor_remap_xyz(2, false, &x, &y, &z)); /* (-x, y, -z) */
    assert(x == 32767 && y == 0 && z == 32767);
}

static void test_lsm6dso_driver(void) {
    struct sensor_sample storage[16];
    assert(sensor_init(storage, 16) == 0);

    struct mock_lsm6dso mock;
    mock_lsm_reset(&mock);
    mock.reset_polls_left = 2;

    struct spi_bus spi = {.name = "hub_spi0", .ops = &mock_spi_ops, .priv = &mock};
    struct lsm6dso_dev imu;
    struct lsm6dso_config cfg = {
        .bus = &spi,
        .spi_cfg = {.hz = 8000000u, .mode = 3, .cs = 0},
        .delay_ms = mock_delay,
        .orientation = 5, /* (y, -x, z) */
        .wrist_flipped = false,
        .xl_offset = {5, -10, 2},
        .gy_offset = {-1, 2, -3},
    };

    /* Wrong WHO_AM_I returns -3 after 3 tries */
    mock.regs[LSM6DSO_REG_WHO_AM_I] = 0x6A;
    assert(lsm6dso_init(&imu, &cfg) == -3);
    assert(!imu.probed && imu.chip_id == 0x6A);

    /* Valid WHO_AM_I after 1 transient SPI read error succeeds */
    mock_lsm_reset(&mock);
    mock.reset_polls_left = 2;
    mock.fail_reads = 1; /* fails CTRL3_C read in reset; probe still succeeds */
    assert(lsm6dso_init(&imu, &cfg) == 0);
    assert(imu.probed && imu.chip_id == 0x6C);

    /* Enable dual stream (XL + GYRO) at 52 Hz, ±8g, 2000 dps */
    assert(lsm6dso_enable(&imu, LSM6DSO_ODR_52, LSM6DSO_XL_8G, true,
                          LSM6DSO_GY_2000DPS, LSM6DSO_PWR_HIGH_PERF) == 0);
    assert(imu.active && imu.gyro_enabled);
    assert(mock.regs[LSM6DSO_REG_CTRL1_XL] == ((3u << 4) | (3u << 2)));
    assert(mock.regs[LSM6DSO_REG_CTRL2_G] == ((3u << 4) | (6u << 1)));
    assert(mock.regs[LSM6DSO_REG_FIFO_CTRL3] == 0x33u);
    assert((mock.regs[LSM6DSO_REG_FIFO_CTRL4] & 0x07u) == 6u);
    assert((mock.regs[LSM6DSO_REG_CTRL3_C] & 0x44u) == 0x44u);

    /* Direct raw accel read with offsets + orientation 5 (y, -x, z) */
    mock.regs[LSM6DSO_REG_OUTX_L_A + 0] = 100; mock.regs[LSM6DSO_REG_OUTX_L_A + 1] = 0; /* 100 + 5 = 105 */
    mock.regs[LSM6DSO_REG_OUTX_L_A + 2] = 200; mock.regs[LSM6DSO_REG_OUTX_L_A + 3] = 0; /* 200 - 10 = 190 */
    mock.regs[LSM6DSO_REG_OUTX_L_A + 4] = 0;   mock.regs[LSM6DSO_REG_OUTX_L_A + 5] = 16; /* 4096 + 2 = 4098 */
    int16_t raw_xyz[3];
    assert(lsm6dso_read_accel_raw(&imu, raw_xyz) == 0);
    assert(raw_xyz[0] == 190 && raw_xyz[1] == -105 && raw_xyz[2] == 4098);

    /* Push 5 FIFO words (gyro enabled rounds drain down to 4, leaves 1 remaining) */
    mock_lsm_push_word(&mock, LSM6DSO_FIFO_TAG_XL_NC, 10, 20, 30);
    mock_lsm_push_word(&mock, LSM6DSO_FIFO_TAG_GYRO_NC, 100, -50, 25);
    mock_lsm_push_word(&mock, LSM6DSO_FIFO_TAG_XL_NC, -10, 40, 50);
    mock_lsm_push_word(&mock, LSM6DSO_FIFO_TAG_GYRO_NC, 0, 0, 10);
    mock_lsm_push_word(&mock, LSM6DSO_FIFO_TAG_XL_NC, 1, 2, 3);
    mock.fifo_overrun = true;

    uint16_t remaining = 99;
    int decoded = lsm6dso_fifo_drain(&imu, 16, &remaining);
    assert(decoded == 4);
    assert(remaining == 1);
    assert(imu.overrun_count == 1);
    assert(!mock.fifo_overrun); /* overrun cleared via bypass->continuous */
    assert(sensor_pending() == 4);

    struct sensor_sample s;
    /* First sample: XL (10+5=15, 20-10=10, 30+2=32) -> orient 5 => (10, -15, 32) */
    assert(sensor_poll(&s));
    assert(s.type == SENSOR_ACCEL && s.sensitivity == 4096u);
    assert((s.flags & SENSOR_FLAG_OVERFLOW) != 0);
    assert(s.x == 10 && s.y == -15 && s.z == 32);

    /* Second sample: GYRO (100-1=99, -50+2=-48, 25-3=22) -> orient 5 => (-48, -99, 22) */
    assert(sensor_poll(&s));
    assert(s.type == SENSOR_GYRO && s.sensitivity == 143u);
    assert(s.x == -48 && s.y == -99 && s.z == 22);

    /* Disable powers down ODR and sets FIFO bypass */
    assert(lsm6dso_disable(&imu) == 0);
    assert(!imu.active);
    assert((mock.regs[LSM6DSO_REG_CTRL1_XL] & 0xF0u) == 0);
    assert((mock.regs[LSM6DSO_REG_CTRL2_G] & 0xF0u) == 0);
    assert((mock.regs[LSM6DSO_REG_FIFO_CTRL4] & 0x07u) == 0);
    assert(lsm6dso_fifo_drain(&imu, 8, NULL) == -1);
}

static void test_ztw622_driver(void) {
    struct input_event ev_storage[16];
    assert(input_init(ev_storage, 16) == 0);

    struct mock_ztw622 z = {
        .chip_id_info = ZTW622_CHIP_ID,
        .chip_id_reg = ZTW622_CHIP_ID,
        .fw_major = 4, .fw_minor = 6, .fw_release = 3,
        .x_res = 390, .y_res = 450,
        .x_ch = 12, .y_ch = 16,
        .inject_fail_once = 1, /* exercises I2C bus-reset + retry on first cmd */
    };
    struct i2c_bus i2c = {.name = "i2c3", .ops = &mock_i2c_ops, .priv = &z};
    struct gpio_chip gpio = {.name = "gpio0", .pin_count = 64, .ops = &mock_gpio_ops, .priv = &z};

    struct ztw622_dev tp;
    struct ztw622_config cfg = {
        .bus = &i2c,
        .addr = 0, /* default 0x20 */
        .gpio = &gpio,
        .reset_pin = 15,
        .irq_pin = 21,
        .rotation = 2, /* (xres-x, yres-y) */
        .flip_180 = false,
        .max_fingers = 2,
        .large_object_enable = true,
        .gesture_mask = 0x0003u,
        .nap_delay = 50,
        .delay_ms = mock_delay,
    };

    assert(ztw622_init(&tp, &cfg) == 0);
    assert(tp.probed && tp.info.chip_id == 0xE622u);
    assert(tp.info.ium_id == 0x123456u);
    assert(tp.info.x_res == 390 && tp.info.y_res == 450);
    assert(z.active_cfg == 0x003Cu && z.nap_delay == 50u);
    assert(z.reset_calls == 1); /* bus reset retry happened */
    assert(z.gpio_toggles == 4);
    assert(z.clear_int_calls == 1);

    /* Fallback chip-ID path when info block fails */
    z.fail_info_blk = true;
    assert(ztw622_init(&tp, &cfg) == 0);
    assert(tp.info.chip_id == 0xE622u);

    /* Wrong chip-ID fails with -3 */
    z.chip_id_reg = 0x1234u;
    assert(ztw622_init(&tp, &cfg) == -3);
    z.chip_id_reg = ZTW622_CHIP_ID;
    z.fail_info_blk = false;
    assert(ztw622_init(&tp, &cfg) == 0);

    /* Point DOWN on slot 0 at (100, 150) -> rotation 2 => (290, 300) */
    memset(z.point_blk, 0, sizeof z.point_blk);
    put_le16_t(&z.point_blk[0], 0x0002u); /* point data bit */
    z.point_blk[2] = 1; /* count */
    put_le16_t(&z.point_blk[4], 100);
    put_le16_t(&z.point_blk[6], 150);
    z.point_blk[9] = 0x01u; /* active, bit3=0 => down */
    assert(ztw622_poll(&tp) == 1);

    struct input_event ev;
    assert(input_poll(&ev));
    assert(ev.type == INPUT_TOUCH && ev.action == INPUT_TOUCH_DOWN);
    assert(ev.code == 0 && ev.x == 290 && ev.y == 300);

    /* Second poll while down => MOVE */
    put_le16_t(&z.point_blk[4], 110);
    put_le16_t(&z.point_blk[6], 160);
    assert(ztw622_poll(&tp) == 1);
    assert(input_poll(&ev));
    assert(ev.action == INPUT_TOUCH_MOVE && ev.x == 280 && ev.y == 290);

    /* Release (bit3=1 in sub_status) => UP */
    z.point_blk[9] = 0x09u;
    assert(ztw622_poll(&tp) == 1);
    assert(input_poll(&ev));
    assert(ev.action == INPUT_TOUCH_UP && ev.code == 0);

    /* Large object event */
    memset(z.point_blk, 0, sizeof z.point_blk);
    put_le16_t(&z.point_blk[0], ZTW622_STATUS_LARGE_OBJ);
    assert(ztw622_poll(&tp) == 1);
    assert(input_poll(&ev));
    assert(ev.action == INPUT_TOUCH_GESTURE && ev.code == ZTW622_STATUS_LARGE_OBJ);

    /* Wake gesture state: matching gesture posts and clears 0x0126 */
    assert(ztw622_set_state(&tp, ZTW622_STATE_GESTURE) == 0);
    z.gesture_reg = 0x0002u;
    assert(ztw622_poll(&tp) == 1);
    assert(z.gesture_reg == 0);
    assert(input_poll(&ev));
    assert(ev.action == INPUT_TOUCH_GESTURE && ev.code == 0x0002u);

    /* Non-matching gesture posts 0 */
    z.gesture_reg = 0x0008u;
    assert(ztw622_poll(&tp) == 0);
    assert(z.gesture_reg == 0);
    assert(input_pending() == 0);
}

int main(void) {
    test_sensor_queue_and_remap();
    test_lsm6dso_driver();
    test_ztw622_driver();
    assert(mock_irq_depth == 0);
    assert(total_delay_ms > 0);
    printf("PASS: sensor queue, LSM6DSO SPI IMU and ZTW622 I2C touch\n");
    return 0;
}
