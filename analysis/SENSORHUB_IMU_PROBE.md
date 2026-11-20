# Sensor-hub LSM6DSO probe, reset and SPI register framing

All **12 native cases** pass (5,689 steps) in the `sensor-runtime` project. They
execute every original sensor-hub body from the LSM6DSO init/probe down to the
SPI read/write callbacks. Only the SPI transfer helper, memcpy, the delay and
the logger are supplied. The evidence is in
[sensorhub-imu-probe.json](sensorhub-imu-probe.json). This replaces the
earlier static reading in [DRIVER_INTERFACES.md](DRIVER_INTERFACES.md), where
custom instructions hid the error handling and the identity check.

## Layering

The driver follows the layout of ST's public `lsm6dso_reg.c` register layer:

| Layer | Address | Executed behaviour |
| --- | --- | --- |
| init/probe | `0x80f71cb2` | reset, read WHO_AM_I, accept only `0x6C`, three attempts |
| software reset | `0x80f7021c` | set `CTRL3_C.SW_RESET`, poll up to 10× with 1 ms delay |
| WHO_AM_I wrapper | `0x80f71c88` | read the id, copy the caller buffer to `0x80f17027` |
| `device_id_get` | `0x80f72bb4` | read register `0x0F`, one byte |
| `reset_set` | `0x80f72bbe` | read `CTRL3_C` (`0x12`), replace bit 0, write back; skip the write if the read fails |
| `reset_get` | `0x80f72bfa` | read `CTRL3_C`, return bit 0; the read status is ignored |
| context read / write | `0x80f7290e` / `0x80f72914` | call `ctx+4` / `ctx+0` with `ctx+8` as the handle |
| SPI read callback | `0x80f6fafa` | see framing below |
| SPI write callback | `0x80f6fb60` | see framing below |

The register context at `0x80fd876c` is `{write_reg = 0x80f6fb60,
read_reg = 0x80f6fafa, handle = 0}`. The names `lsm6dso G` and `lsm6dso A`
(gyroscope and accelerometer) follow it. The callbacks ignore the context
handle. They load the SPI bus handle from the `.bss` word `0x80f17018`, which is
zero in the image and set at runtime by the caller `0x80f726ee`. Its value in
these vectors is authored.

## SPI framing (captured)

The supplied helper is `0x80f898ae(handle, tx, rx, len, timeout)`. The `spi`
stub records the bytes the original callbacks place in `tx`:

- **Read** `n` bytes of register `r`: `tx = [r | 0x80, 0 × n]`, `len = n + 1`,
  timeout `5000`. On status zero, the data is copied from `rx[1 .. n]`.
  Otherwise the callback returns `1` and copies nothing. The buffers are 7 bytes
  on the stack, so a read is limited to six data bytes.
- **Write** register `r`: `tx = [r, data[0]]`, `len = n + 1`, timeout `5000`.
  Only the first data byte is placed. The return value is `status != 0`.

Captured examples: `92 00` (read `CTRL3_C`), `12 05` (write `CTRL3_C` = `0x04 |
SW_RESET`), `12 45` (other bits preserved), `8f 00` (read WHO_AM_I). This is
standard LSM6DSO 4-wire SPI addressing, with bit 7 as the read flag.

## Probe and reset behaviour

- The reset logs at level 3 after ten polls in which the bit stays set. It
  returns nothing in either case, and the probe continues after a timeout.
- A failed `CTRL3_C` read skips the write. A failed write still polls.
- The probe zeroes its id buffer once, before the first attempt. A failed
  WHO_AM_I read leaves the buffer unchanged, so the cached byte at `0x80f17027`
  is the previous attempt's value (`0x6A, 0x6A, 0x6C` in
  `probe_read_error_keeps_stale_id`).
- Result: `0` on `0x6C`; after three failures, `1` if the last attempt read a
  wrong id or `4` if it was a read error. Each failure logs at level 6, then waits
  10 ms.
- A failed read during the reset poll makes the original `reset_get` return an
  uninitialized stack bit. The vectors do not exercise this path, and the model
  rejects it.

## Relevance for SpellboundOS

This is the motion sensor's identity and bus contract: 4-wire SPI with bit-7
read addressing, the `0x6C` identity and a self-clearing reset. Because the
layer matches ST's public register-driver layout, an independently built OS
could use ST's BSD-licensed LSM6DSO register driver behind an authored SPI
transport instead of vendor code. Whether that is allowed must still be checked
against that driver's licence.

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_probe --vectors-output firmware/sensorhub-imu-probe-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-probe-vectors.json \
  firmware/sensorhub-imu-probe-validation.json
python3 -m analysis_scripts.sensorhub_imu_probe firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-probe-vectors.json \
  --validation firmware/sensorhub-imu-probe-validation.json > analysis/sensorhub-imu-probe.json
python3 -m unittest tests.test_sensorhub_imu_probe -q
```

The vectors, native report and evidence regenerate byte for byte.

## Remaining (needs further work or the device)

- The caller `0x80f726ee`: bus instance and SPI handle setup, chip select, SPI
  mode/clock (the `8000000` field) and interrupt initialization.
- The transfer helper `0x80f898ae` and the hub SPI controller below it.
- Configuration after identity: ODR, full scale, FIFO, interrupt routing and
  embedded functions (tap, tilt, step), and the data read path.
- Reset timing, electrical behaviour and confirmation of the fitted part on the
  watch.
