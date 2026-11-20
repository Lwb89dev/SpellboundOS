# Sensor-hub LSM6DSO attach and the hub board records

All **11 native cases** pass (4,308 steps) in the `sensor-runtime` project. They
execute the LSM6DSO attach routine `0x80f726ee` end to end, together with the
original probe chain from [SENSORHUB_IMU_PROBE.md](SENSORHUB_IMU_PROBE.md) and
the `INTERNAL_FREQ_FINE` accessor `0x80f72b5a`. The board record is the real
one from the image. The evidence is in
[sensorhub-imu-init.json](sensorhub-imu-init.json).

## Hub board records

`0x80f6257c` registers named board records (name, data, size). The rows below
are decoded from its `auipc`/`addi` pairs and the initialized `.data` they
point to:

| Record | Contents |
| --- | --- |
| `system_info` | version `1.0.0`, board **`Pamir`**, further words `0x9b`, `0x100`, `0x1570001`, `0`, `0x11b` |
| `dev_lsm6dso` | SPI device **`sens_spi1_dev0`**, interrupt pin **43**, mode **4** |
| `dev_bmi2xx` | identical to `dev_lsm6dso` (alternative IMU on the same bus/pin) |
| `dev_ak09918`, `dev_mmc5603` | bus **`sens_i2c2`** (alternative magnetometers) |
| `dev_max8617x` | SPI device **`sens_spi0_dev0`**, rails **`PPG_1V8`**, **`PPG_VLED`**, pin 39 (`0x27`), then `0xffff` and `4` |
| `dev_virtual_pm` | `{1, 0x80f16b00}` |

The pin and mode numbers are hub GPIO driver values. Their physical pads and
the meaning of mode 4 (edge or level) are not decoded here.

## Executed attach sequence

1. `board_find("dev_lsm6dso")` (`0x80f8748a`, a mutex-protected named list).
   A missing record logs `dev_lsm6dso bsd is NULL` and returns **4**.
2. `spi_dev_find_handle("sens_spi1_dev0", &0x80f17018)`. On failure it logs and
   returns **4**, and the configure call is not reached.
3. SPI configure (`0x80f89552`) with the captured structure
   `{8000000, 0x807, 0, 0, 0}`, i.e. an 8 MHz clock. The meaning of `0x807` is
   not decoded. The return value is ignored.
4. The board-record pointer is published at `0x80f17014`, then the probe runs.
   Any probe failure logs `fail id` and returns **1**.
5. `malloc(4, "drivers_sensor", 0x605, 4)`. Failure returns **10**. Otherwise
   the block is zeroed and published at `0x80f17020`, with `+0x460` at
   `0x80f1701c`.
6. `INTERNAL_FREQ_FINE` (`0x63`) is read as a signed byte. The trimmed 26 Hz
   output data rate `6667 × (1 + 0.0015 × fine) / 256` is stored as binary32 at
   `0x80f17028` and logged (`ok %d %.3f`). A failed read gives `fine = 0`,
   because the accessor zeroes its buffer first.
7. `gpio_dev_init(43, zeroed cfg)`, `gpio_dev_install_irq(43, 4, 0x80f701ba,
   0x80f17014)`, then `gpio_dev_disable_irq(43)`. The interrupt is installed
   but **left disabled**. A failure at any of these steps logs twice and still
   returns **0**.
8. The accelerometer (`0x80f15538`, `lsm6dso A`, type `0x012c0001`) and
   gyroscope (`0x80f15508`, `lsm6dso G`, type `0x012c0002`) descriptors are
   registered through `0x80f63fac`. Both carry `500` and their callback tables.

## Emulator note

Ghidra 12.1.2's RV32 SLEIGH makes `c.fsw` store the whole 64-bit FP register,
which is 8 bytes. The upper half is zero because the emulator does not NaN-box.
Hardware stores 4 bytes. A step trace confirmed that the computed value is the
correct IEEE binary32 (`0x41d05800` for `fine = 0`). The model records the
8-byte emulator write explicitly, and the extra 4 bytes at `0x80f1702c` are an
emulator artifact. In all 256 signed trim values, fused and unfused `fmadd.d`
give the same binary32 result.

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_init --vectors-output firmware/sensorhub-imu-init-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-init-vectors.json \
  firmware/sensorhub-imu-init-validation.json
python3 -m analysis_scripts.sensorhub_imu_init firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-init-vectors.json \
  --validation firmware/sensorhub-imu-init-validation.json > analysis/sensorhub-imu-init.json
python3 -m unittest tests.test_sensorhub_imu_init -q
```

Both scopes share the runner `ValidateSensorhubImuProbe.java`, which gained a
`capture` stub kind. The probe report regenerates byte for byte with the
extended runner.

## Remaining

- The interrupt handler `0x80f701ba`, the enable path and the sensor callbacks
  in both descriptors (activate, ODR/full-scale set, FIFO read, flush,
  calibration).
- The SPI device layer below `spi_dev_find_handle` and configure, the meaning
  of `0x807`, and the physical pads behind GPIO 43 and `sens_spi1`.
- Which IMU and magnetometer alternatives are fitted on the device.
