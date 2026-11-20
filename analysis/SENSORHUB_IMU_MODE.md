# Sensor-hub LSM6DSO enable/disable: the applied configuration

All **26 native cases** pass (51,920 steps, bound 20,000 per case) in the
`sensor-runtime` project. They execute the mode setter `0x80f70da2(enable,
gyro)` with all its callees real:

- configuration `0x80f70aca`, rate `0x80f70b9a`, event `0x80f70192` and
  register dump `0x80f70a52`;
- every register accessor from [SENSORHUB_IMU_REGS.md](SENSORHUB_IMU_REGS.md);
- the SPI callbacks from [SENSORHUB_IMU_PROBE.md](SENSORHUB_IMU_PROBE.md).

Only the SPI transfer helper, memcpy, the delay, the logger and the event post
`0x80f63f6c` are supplied. Each case starts from the original image values of
the globals. The evidence is in [sensorhub-imu-mode.json](sensorhub-imu-mode.json).

## Original configuration values

| Global | Image value | Meaning |
| --- | --- | --- |
| `0x80f16b2d` | 3 | accelerometer full scale code, ±8 g |
| `0x80f16b2c` | 6 | gyroscope FS_G[3:1] code, 2000 dps |
| `0x80f16b2e` | 26 | rate in Hz |
| `0x80f16b1c` | 1 | accelerometer-only power selector |
| `0x80f16b1e` | 8 | embedded-function program selector; invalid, so it is cleared |
| `0x80f16b20` | 1 | one-shot register dump pending |
| `0x80f16b21` | 1 | last enable kind: 2 = gyroscope, 1 = accelerometer only |

## Gyroscope enable (`enable = 1, gyro = 1`): captured register writes

1. `CTRL3_C = 0x05`: software reset, polled until clear. The program selector is
   checked here: a value above 7 is cleared and logged, and 5 or 6 loads an
   embedded-function program (see below).
2. `i3c_disable_set(0)`: CTRL9_XL bit 1 = 0, I3C_BUS_AVB bits 4:3 = 0.
3. `xl_power_mode_set(0)`: high performance.
4. `block_data_update_set(1)`.
5. `xl_full_scale_set(3)`: ±8 g.
6. `gy_lp1_bandwidth_set(7)`, `gy_filter_lp1_set(1)` and `gy_power_mode_set(0)`
   (high performance).
7. `gy_full_scale_set(6)`: 2000 dps. The state byte becomes 2.
8. Rate: FIFO batch and ODR codes for the accelerometer, then the gyroscope.
   26/52/104/208/417/833 Hz map to codes 2–7, and any other rate maps to 2
   (26 Hz). The rate is stored at descriptor `+0x1a` for both sensors.
9. `fifo_mode_set(6)`: continuous mode.
10. Event `{0x103, (u32)(trimmed ODR × 100)}` is posted, e.g. **2604** for
    26.04 Hz. The active byte `0x80f17026` becomes 1.
11. If a register dump is pending: clear the flag, then read registers
    `0x00`–`0x7f` into `0x80f4fe80`. A failed read logs and stores `0xff`.

## Accelerometer-only enable (`enable = 1, gyro = 0`)

This path runs the same configuration with a power mode chosen by the selector
at `0x80f16b1c`:

| Selector | Power mode | ODR event value |
| --- | --- | --- |
| 0 | ultra-low power (`2`) | 0 |
| 2 | high performance (`0`) | trimmed ODR × 100 |
| other (image: 1) | low/normal power (`1`) | 0 |

Then the accelerometer batch and ODR codes are set, the rate goes to the
accelerometer descriptor only, the FIFO is set to continuous mode, the state
byte becomes 1 and the event is posted.

## Disable (`enable = 0`)

`gyro = 0` writes `ODR_XL = 0` and `ODR_G = 0`, powering both sensors down.
`gyro = 1` only logs an error. A pending dump still runs. The setter always
returns 0.

## Embedded-function programs (not executed)

Selector values 5 and 6 load one of two 380-pair `(register, value)` programs,
at `0x80fd8a88` and `0x80fd8790`. They are written directly through the
context write. Both use the ST embedded-function access pattern:
`FUNC_CFG_ACCESS = 0x80`, `PAGE_RW`, `PAGE_SEL`, `PAGE_ADDRESS`, 352
`PAGE_VALUE` bytes, then `FSM_ENABLE_A/B` and the embedded-function enables. In
other words, they are finite-state-machine programs in ST's UCF format. The
two programs differ in 15 pairs. They are identified by hash only, so that the
vendor configuration is not redistributed. With the image default selector
they are never loaded.

## Emulator repair

Ghidra 12.1.2 RV32 SLEIGH computes `fcvt.wu.s a5, fa0, rtz` into a p-code
temporary and never writes `a5`; a step trace confirmed this. The runner
repairs only the reviewed site `0x80f701a8` with the RISC-V semantics (round
toward zero, saturating) and records each repair as a `fix:` action. See
[NATIVE_REPAIR.md](NATIVE_REPAIR.md).

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_mode --vectors-output firmware/sensorhub-imu-mode-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-mode-vectors.json \
  firmware/sensorhub-imu-mode-validation.json
python3 -m analysis_scripts.sensorhub_imu_mode firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-mode-vectors.json \
  --validation firmware/sensorhub-imu-mode-validation.json > analysis/sensorhub-imu-mode.json
python3 -m unittest tests.test_sensorhub_imu_mode -q
```

The runner takes the per-case step bound from the vectors, with a ceiling of
50,000. The earlier IMU scopes regenerate byte for byte under the extended
runner.

## Remaining

- The callers: the descriptor callbacks (open/close/rate/flush) and who sets
  the selectors and rate at runtime.
- The FIFO read and decode path (`0x80f710ac`), interrupt handling after event
  `0x101`, and data delivery to the sensor framework.
- Electrical timing and the real device's FIFO behaviour.
