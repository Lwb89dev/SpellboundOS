/* Runtime check for LSM6DSO SPI IMU and ZTW622 I2C touch delivery on RV32 QEMU virt. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../kernel/board.h"
#include "../kernel/bus.h"
#include "../kernel/console.h"
#include "../kernel/input.h"
#include "../kernel/sched.h"
#include "../kernel/sensor.h"
#include "../kernel/arch/riscv/riscv.h"
#include "../kernel/arch/riscv/timer.h"
#include "../kernel/arch/riscv/trap.h"
#include "../kernel/drivers/lsm6dso.h"
#include "../kernel/drivers/ztw622.h"

static _Alignas(16) uint32_t stacks[2][384];
static struct sensor_sample sensor_storage[8];
static struct input_event input_storage[8];
static volatile unsigned failures;

/* Minimal simulated LSM6DSO over SPI */
static uint8_t imu_regs[128];
static uint8_t imu_fifo_words[2][7] = {
    {LSM6DSO_FIFO_TAG_XL_NC << 3, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10},
    {LSM6DSO_FIFO_TAG_GYRO_NC << 3, 0x0A, 0x00, 0x14, 0x00, 0x1E, 0x00},
};
static uint8_t imu_fifo_idx;
static uint8_t imu_fifo_left = 2;

static int virt_spi_xfer(struct spi_bus *bus, const struct spi_config *cfg,
                         const struct spi_transfer *xfers, uint32_t count) {
    (void)bus; (void)cfg;
    if (count != 1 || !xfers[0].tx || xfers[0].len < 2) return -1;
    uint8_t cmd = xfers[0].tx[0];
    uint8_t reg = (uint8_t)(cmd & 0x7Fu);
    if ((cmd & 0x80u) != 0) {
        uint32_t n = xfers[0].len - 1u;
        xfers[0].rx[0] = 0;
        if (reg == LSM6DSO_REG_FIFO_DATA_TAG) {
            for (uint32_t w = 0; w < n / 7u; w++) {
                for (uint32_t b = 0; b < 7u; b++) {
                    xfers[0].rx[1u + w * 7u + b] = imu_fifo_words[imu_fifo_idx][b];
                }
                imu_fifo_idx++;
                imu_fifo_left--;
            }
            return 0;
        }
        if (reg == LSM6DSO_REG_FIFO_STATUS1) {
            imu_regs[LSM6DSO_REG_FIFO_STATUS1] = imu_fifo_left;
            imu_regs[LSM6DSO_REG_FIFO_STATUS2] = 0;
        }
        for (uint32_t i = 0; i < n; i++) {
            xfers[0].rx[1u + i] = imu_regs[(reg + i) & 0x7Fu];
        }
        return 0;
    }
    uint8_t val = xfers[0].tx[1];
    imu_regs[reg] = (reg == LSM6DSO_REG_CTRL3_C) ? (uint8_t)(val & ~0x01u) : val;
    return 0;
}

static const struct spi_ops virt_spi_ops = {.transfer = virt_spi_xfer};
static struct spi_bus virt_spi = {.name = "virt_spi0", .ops = &virt_spi_ops};

/* Minimal simulated ZTW622 over I2C */
static uint16_t tp_reg;
static int virt_i2c_xfer(struct i2c_bus *bus, const struct i2c_msg *msgs, uint32_t count) {
    (void)bus;
    if (count != 1 || msgs[0].addr != ZTW622_I2C_ADDR) return -1;
    if ((msgs[0].flags & I2C_MSG_READ) == 0) {
        tp_reg = (uint16_t)msgs[0].buf[0] | ((uint16_t)msgs[0].buf[1] << 8);
        return 0;
    }
    for (uint32_t i = 0; i < msgs[0].len; i++) msgs[0].buf[i] = 0;
    if (tp_reg == ZTW622_REG_INFO_BLOCK && msgs[0].len == 22) {
        msgs[0].buf[0x0A] = 0x22; msgs[0].buf[0x0B] = 0xE6;
        return 0;
    }
    if (tp_reg == ZTW622_REG_POINT_STATUS && msgs[0].len == 16) {
        msgs[0].buf[0] = 0x02; msgs[0].buf[2] = 1;
        msgs[0].buf[4] = 50;   msgs[0].buf[6] = 80;
        msgs[0].buf[9] = 0x01; /* down */
        return 0;
    }
    if (tp_reg == ZTW622_REG_X_RES) { msgs[0].buf[0] = 0x86; msgs[0].buf[1] = 0x01; }
    if (tp_reg == ZTW622_REG_Y_RES) { msgs[0].buf[0] = 0xC2; msgs[0].buf[1] = 0x01; }
    return 0;
}

static const struct i2c_ops virt_i2c_ops = {.transfer = virt_i2c_xfer};
static struct i2c_bus virt_i2c = {.name = "virt_i2c0", .ops = &virt_i2c_ops};

static struct lsm6dso_dev imu_dev;
static struct ztw622_dev tp_dev;

static void producer_task(void) {
    struct lsm6dso_config imu_cfg = {
        .bus = &virt_spi,
        .spi_cfg = {.hz = 8000000u, .mode = 3, .cs = 0},
        .orientation = 0,
    };
    struct ztw622_config tp_cfg = {
        .bus = &virt_i2c,
        .reset_pin = -1,
        .irq_pin = -1,
        .max_fingers = 2,
    };
    if (lsm6dso_init(&imu_dev, &imu_cfg) != 0 ||
        lsm6dso_enable(&imu_dev, LSM6DSO_ODR_52, LSM6DSO_XL_8G, true,
                       LSM6DSO_GY_2000DPS, LSM6DSO_PWR_HIGH_PERF) != 0 ||
        lsm6dso_fifo_drain(&imu_dev, 8, NULL) != 2) {
        failures++;
    }
    if (ztw622_init(&tp_dev, &tp_cfg) != 0 || ztw622_poll(&tp_dev) != 1) {
        failures++;
    }
}

static void consumer_task(void) {
    struct sensor_sample s;
    if (!sensor_wait_for(&s, 50) || s.type != SENSOR_ACCEL || s.x != 256 || s.z != 4096) {
        failures++;
    }
    if (!sensor_wait_for(&s, 50) || s.type != SENSOR_GYRO || s.x != 10 || s.z != 30) {
        failures++;
    }
    struct input_event ev;
    if (!input_wait_for(&ev, 50) || ev.type != INPUT_TOUCH ||
        ev.action != INPUT_TOUCH_DOWN || ev.x != 50 || ev.y != 80) {
        failures++;
    }
}

void kernel_main(void) {
    trap_init();
    timer_init(100);
    set_csr(mstatus, MSTATUS_MIE);

    imu_regs[LSM6DSO_REG_WHO_AM_I] = LSM6DSO_WHO_AM_I_VAL;
    if (spi_register(&virt_spi) != 0 || i2c_register(&virt_i2c) != 0 ||
        sensor_init(sensor_storage, 8) != 0 || input_init(input_storage, 8) != 0) {
        failures++;
    }
    if (task_create(producer_task, stacks[0], sizeof stacks[0]) < 0 ||
        task_create(consumer_task, stacks[1], sizeof stacks[1]) < 0) {
        failures++;
    }
    sched_run();

    console_puts(failures ? "FAIL: LSM6DSO and ZTW622 drivers\n" :
                            "PASS: LSM6DSO and ZTW622 drivers\n");
    board_poweroff();
}
