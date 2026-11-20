# Sensor-hub LSM6DSO register accessors: native sweep

All **95 native cases** pass (7,561 steps) in the `sensor-runtime` project. Each
case runs one original accessor from the hub LSM6DSO register block
(`0x80f7291a`–`0x80f72e86`) through the original context dispatch and SPI
callbacks (see [SENSORHUB_IMU_PROBE.md](SENSORHUB_IMU_PROBE.md)). Only the SPI
transfer helper and memcpy are supplied. The `spi` stub captures every byte on
the wire, so each accessor's register and bit field is observed directly. The
evidence is in [sensorhub-imu-regs.json](sensorhub-imu-regs.json).

## Accessor map

Each name is the ST `lsm6dso_reg.c` accessor whose register and field the body
matches.

| Address | Accessor | Register (field) |
| --- | --- | --- |
| `0x80f7291a` | `xl_full_scale_set` | CTRL1_XL `0x10` bits 3:2 |
| `0x80f72958` | ODR_XL field write | CTRL1_XL `0x10` bits 7:4 (`val << 4`, unmasked) |
| `0x80f72994` | `gy_full_scale_set` | CTRL2_G `0x11` bits 3:1 |
| `0x80f729d2` | ODR_G field write | CTRL2_G `0x11` bits 7:4 (`val << 4`, unmasked) |
| `0x80f72a0e` | `block_data_update_set` | CTRL3_C `0x12` bit 6 |
| `0x80f72a4e` | `xl_power_mode_set` | CTRL5_C `0x14` bit 7 = `val >> 1`, then CTRL6_C `0x15` bit 4 = `val & 1` |
| `0x80f72abe` | `gy_power_mode_set` | CTRL7_G `0x16` bit 7 |
| `0x80f72afc` / `0x80f72b1e` | `xl` / `gy_flag_data_ready_get` | STATUS_REG `0x1e` bit 0 / bit 1 |
| `0x80f72b42` | `angular_rate_raw_get` | 6 bytes from OUTX_L_G `0x22` |
| `0x80f72b4e` | `acceleration_raw_get` | 6 bytes from OUTX_L_A `0x28` |
| `0x80f72b5a` | `odr_cal_reg_get` | INTERNAL_FREQ_FINE `0x63`; stores 0 on a failed read |
| `0x80f72b82` | `mem_bank_get` | FUNC_CFG_ACCESS `0x01` bits 7:6 → 1, 2 or 0 |
| `0x80f72bb4` | `device_id_get` | WHO_AM_I `0x0f` |
| `0x80f72bbe` / `0x80f72bfa` | `reset_set` / `reset_get` | CTRL3_C `0x12` bit 0 |
| `0x80f72c1c` / `0x80f72c5a` | `boot_set` / `boot_get` | CTRL3_C `0x12` bit 7 |
| `0x80f72c7e` | `gy_filter_lp1_set` | CTRL4_C `0x13` bit 1 |
| `0x80f72cbc` | `gy_lp1_bandwidth_set` | CTRL6_C `0x15` bits 2:0 |
| `0x80f72cf8` | `i3c_disable_set` | CTRL9_XL `0x18` bit 1 = `val >> 7`, then I3C_BUS_AVB `0x62` bits 4:3 |
| `0x80f72d6a` / `0x80f72da6` | `fifo_xl` / `fifo_gy_batch_set` | FIFO_CTRL3 `0x09` bits 3:0 / 7:4 |
| `0x80f72de2` | `fifo_mode_set` | FIFO_CTRL4 `0x0a` bits 2:0 |
| `0x80f72e1e` | `fifo_data_level_get` | FIFO_STATUS1 `0x3a` + (FIFO_STATUS2 `0x3b` bits 1:0 << 8) |
| `0x80f72e60` | `fifo_ovr_flag_get` | FIFO_STATUS2 `0x3b` bit 6 |

## Behaviour

- **Setters** read the register, replace their field and write the byte back.
  A failed read skips the write and returns 1. A failed write returns 1. The
  two-register setters stop at the first failure.
- **Unmasked shifts:** the ODR, `boot_set` and `gy_power_mode_set` writers OR in
  `val << n` without masking `val`. Overflowing bits are dropped by the byte
  store, so `0xff` becomes `0xf0` or `0x80`.
- **Getters** store their field through the output pointer and return the read
  status. After a failed read they store a stale stack byte. The vectors do not
  exercise that path, and the model rejects it. The one exception is
  `odr_cal_reg_get`, which zeroes its buffer first.
- **Raw reads** use one 7-byte SPI transfer (`reg | 0x80` and six dummy bytes),
  which is the full capacity of the callback buffers.
- The sweep confirms the AndeStar `bfoz` semantics used by these bodies:
  - `msb == 0` inserts one bit at `lsb`;
  - `msb < lsb` inserts `rs1[lsb-msb:0]` at `[lsb:msb]`;
  - `msb >= lsb` extracts the field.

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_regs --vectors-output firmware/sensorhub-imu-regs-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-regs-vectors.json \
  firmware/sensorhub-imu-regs-validation.json
python3 -m analysis_scripts.sensorhub_imu_regs firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-regs-vectors.json \
  --validation firmware/sensorhub-imu-regs-validation.json > analysis/sensorhub-imu-regs.json
python3 -m unittest tests.test_sensorhub_imu_regs -q
```

The vectors, native report and evidence regenerate byte for byte.

## Remaining

The sweep shows what each accessor does. It does not show which accessors the
driver calls, in which order or with which values. That is the job of the
activate/configure callbacks (`0x80f70da2` and the descriptor callbacks), and
it is covered next. Nothing here drives a real LSM6DSO.
