/* Read-only hardware inventory constants for Amazfit Bip 6 (platform mhs003),
 * derived from verified static/native analysis reports in analysis/.
 *
 * IMPORTANT (see GOAL.md):
 * This header records verified peripheral bus/address/pin constants only.
 * It does NOT produce a bootable Bip 6 image. Physical device writes remain
 * gated on verified backup, recovery and a viable boot path. */
#ifndef SPELLBOUND_BIP6_BOARD_DESC_H
#define SPELLBOUND_BIP6_BOARD_DESC_H

#include <stdint.h>

#define BIP6_PRODUCT_NAME        "Amazfit Bip 6"
#define BIP6_PLATFORM_NAME       "mhs003"

/* Display: Chipone ICNA3311 AMOLED over MIPI DCS (rails LCD_1V8, LCD_3V3) */
#define BIP6_DISPLAY_WIDTH       390u
#define BIP6_DISPLAY_HEIGHT      450u
#define BIP6_DISPLAY_RAIL_1V8    "LCD_1V8"
#define BIP6_DISPLAY_RAIL_3V3    "LCD_3V3"

/* Touch: ZTW622 capacitive touch on i2c3 (rails LDO2_TP / TP_1V8) */
#define BIP6_TOUCH_I2C_BUS       "i2c3"
#define BIP6_TOUCH_I2C_ADDR      0x20u
#define BIP6_TOUCH_CHIP_ID       0xE622u
#define BIP6_TOUCH_RESET_GPIO    15u
#define BIP6_TOUCH_IRQ_GPIO      21u
#define BIP6_TOUCH_RAIL_VDDA     "LDO2_TP"
#define BIP6_TOUCH_RAIL_VDDD     "TP_1V8"

/* Ambient Light Sensor: STK31E60 on i2c3 (rail TP_1V8) */
#define BIP6_ALS_I2C_BUS         "i2c3"
#define BIP6_ALS_I2C_ADDR        0x48u
#define BIP6_ALS_CHIP_ID         0xE0u
#define BIP6_ALS_RAIL            "TP_1V8"

/* Battery Chargers: CW6305 or AW32012 (runtime auto-probed on sens_i2c1) */
#define BIP6_CHARGER_I2C_BUS     "sens_i2c1"
#define BIP6_CHARGER_CW6305_ADDR 0x0Bu
#define BIP6_CHARGER_AW32012_ADDR 0x49u

/* Sensor-hub IMU: LSM6DSO over 4-wire SPI (8 MHz) */
#define BIP6_IMU_SPI_HZ          8000000u
#define BIP6_IMU_WHO_AM_I        0x6Cu

/* Haptic vibration motor (dev_NL_motor) */
#define BIP6_MOTOR_GPIO          95u

/* GNSS (AG3335 PAIR over uart1) and Bluetooth (RTL8763 bluebox over uart2) */
#define BIP6_GNSS_UART           "uart1"
#define BIP6_GNSS_RAIL_1V8       "GPS_1V8"
#define BIP6_GNSS_RAIL_0V8       "GPS_0V8"
#define BIP6_BT_UART             "uart2"

/* External PSRAM banks (HSPI0 / HSPI1 at 198 MHz) */
#define BIP6_PSRAM0_BASE         0x70000000u
#define BIP6_PSRAM1_BASE         0x50000000u
#define BIP6_PSRAM_HZ            198000000u

#endif /* SPELLBOUND_BIP6_BOARD_DESC_H */
