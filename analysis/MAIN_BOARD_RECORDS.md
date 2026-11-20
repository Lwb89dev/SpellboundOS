# Main-image board records: the hardware map

`0x701632c4` registers every main-side board record with
`0x702b4dba(name, data, size)`. The tool `main_board_records.py` decodes that
function with an RV32C instruction scanner. The scanner resolves
`auipc`/`addi` pointer pairs and `li`/`c.li a2` sizes up to each registration
call. The tool then reads the 22 records from the startup-aware image memory.
The evidence, with raw words and hashes, is in
[main-board-records.json](main-board-records.json). It complements the
sensor-hub table in [SENSORHUB_IMU_INIT.md](SENSORHUB_IMU_INIT.md).

| Record | Decoded contents |
| --- | --- |
| `system_info` | firmware `4.6.0.3`, product `Amazfit Bip 6` |
| `gpio_key` | three words (`0x00130000`, `0x00010003`, `0x00030036`) |
| `dev_aw32012`, `dev_cw6305` | bus **`sens_i2c1`**, `0x00140001`, 3 |
| `dev_NL_motor` | `0`, **95** (motor) |
| `dev_ztw622` | touch on **`i2c3`**; reset pin 15 and interrupt pin 21; rails **`LDO2_TP`** (vdda) and **`TP_1V8`** (vddd) |
| `dev_stk31e60` | **`i2c3`**, rail **`TP_1V8`** |
| `dev_ag3335` | GNSS on **`uart1`**; rails **`GPS_1V8`**, **`GPS_0V8`**; u16 fields 46, 48, 56, 45, `0x404` |
| `dev_bluebox` | Bluetooth on **`uart2`**; fields 13, 78, 40, 71; two callbacks |
| `dev_psram0` / `dev_psram1` | `HSPI0` at `0x70000000` / `HSPI1` at `0x50000000`, **198 MHz** |
| `dev_psram` | `OSPI` |
| `dev_lcd`, `dev_icna3311` | rails **`LCD_1V8`**, **`LCD_3V3`**, word 90; icna3311 also `0x00030039` |
| `dev_flash`, `nand_partition` | `raw` partition descriptors |
| `dev_adc_volt` | ADC channel table, including `NTC_POWER` |
| `dev_gpu`, `dev_bt_log`, `dev_virtual_pm`, `dev_nand`, `dev_nand_pm` | callback or pointer records |

The ZTW622 field meanings come from the code that uses them:

- The attach code drives `+0` (an output, the reset line).
- The interrupt-state poll reads `+2`.
- The I2C handle lookup uses `+8`.
- The rail switch `0x701eb4dc` uses `+0xc`/`+0x10`.

The other pin numbers follow the main GPIO driver numbering. Physical pads,
bus speeds and rail voltages are not decoded.

```sh
python3 -m analysis_scripts.main_board_records firmware/bip6-4.6.0.3.zip > analysis/main-board-records.json
python3 -m unittest tests.test_main_board_records -q
```
