# Sensor-hub LSM6DSO FIFO read, packet and orientation remap

All **28 native cases** pass (24,301 steps) in the `sensor-runtime` project.
They execute the FIFO drain `0x80f710ac` with these original callees:

- the FIFO and identity getters ([SENSORHUB_IMU_REGS.md](SENSORHUB_IMU_REGS.md));
- the register dump;
- packet allocation `0x80f6453e` and release `0x80f6462c`;
- the tagged-word decoder `0x80f6fc42`;
- the orientation remap `0x80f64660`;
- the SPI callbacks.

The evidence is in [sensorhub-imu-fifo.json](sensorhub-imu-fifo.json).

## One drain pass

1. Return **3** if the driver is not active (`0x80f17030`).
2. If 160 or more words are already buffered (`0x80f17024`), log and go to the
   overflow path: increment `0x80f1700e`. From the third consecutive overflow
   on, call the sensor restore `0x80f70f92` and reset the counter. Post event
   `{0x102}` and return **6**.
3. Read `fifo_ovr_flag_get` and `fifo_data_level_get`. On overrun, log. If the
   one-shot flag `0x80f16b1f` is set, dump registers `0x00`–`0x7f` and compare
   the dumps. Read WHO_AM_I and the memory bank, log, then take the overflow
   path.
4. Take `n = min(level, 160 − buffered)` words. When the gyroscope flag
   `0x80f1702c` is set, round `n` down to an even number. `level − n` words are
   left in the FIFO and reported through the output pointer.
5. Read `7n + 1` bytes in one SPI transfer that starts with **`0xf8`**
   (`FIFO_DATA_OUT_TAG 0x78 | 0x80`). Up to 60 words use the cache tail
   (`+0x460`). More than 60 words use a heap buffer, and a failed allocation
   returns **10**. A failed transfer returns **4**.
6. Append the words to the driver cache at `cache + buffered × 7` and update
   the count.
7. Allocate a packet with one stream. Its header holds:
   - type 2 (accelerometer);
   - sensitivity **4096 LSB/g** (`0x80f16b28`, ±8 g);
   - the sample count (`n`, or `n/2` with the gyroscope flag);
   - the rate rounded down to a multiple of 25;
   - the source timestamp minus `(1000 / rate) ms` for each word left in the
     FIFO.
8. Decode each 7-byte word. The tag is `byte >> 3`: tag **2** (XL_NC) is an
   accelerometer sample, int16 x/y/z with the per-axis offsets at
   `0x80f4ff00[0..2]` added. Tag **1** (GYRO_NC) would use offsets `[3..5]`,
   but this caller passes no gyroscope header, so those words are skipped. If
   the number of tag-2 words differs from the header count, the decoder
   returns 7 and event `{0x102}` is posted.
9. Remap, apply the algorithm hook `0x80f63092` (which can raise event
   `{0x10e}`) and release the packet: the queue `0x80f85d14` keeps it, or it is
   freed.

## Orientation remap

`0x80fd4d0c` holds eight signed entries `(m00, m01, m10, m11, mz)`:

| Index | Entry | Index | Entry |
| --- | --- | --- | --- |
| 0 | `( 1, 0, 0, 1, 1)` | 4 | `(0, 1, 1, 0, −1)` |
| 1 | `( 1, 0, 0, −1, −1)` | 5 | `(0, 1, −1, 0, 1)` |
| 2 | `(−1, 0, 0, 1, −1)` | 6 | `(0, −1, 1, 0, 1)` |
| 3 | `(−1, 0, 0, −1, 1)` | 7 | `(0, −1, −1, 0, −1)` |

The remap computes `x' = m00·x + m01·y`, `y' = m10·x + m11·y` and
`z' = mz·z`, all in 16-bit arithmetic. When the wrist flag `0x80f16fb0` is 1,
x' and y' are negated. An index above 7 is logged and left unmapped.
Accelerometer and gyroscope (types 2 and 4) use index `0x80f16fb8`; the
magnetometer (type 8) uses `0x80f16fb4` and also negates z when
`0x80f63e44(3) == 0x25b`. All three are `.bss` values set at runtime.

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_fifo --vectors-output firmware/sensorhub-imu-fifo-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-fifo-vectors.json \
  firmware/sensorhub-imu-fifo-validation.json
python3 -m analysis_scripts.sensorhub_imu_fifo firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-fifo-vectors.json \
  --validation firmware/sensorhub-imu-fifo-validation.json > analysis/sensorhub-imu-fifo.json
python3 -m unittest tests.test_sensorhub_imu_fifo -q
```

The runner gained sequenced/`a1` return stubs and long SPI/memcpy transfers.
For transfers, only the first 16 transmitted bytes are recorded. All earlier
IMU scopes regenerate byte for byte.

## Remaining

- The gyroscope delivery path: the caller that passes a gyroscope header.
- The algorithm hook `0x80f63092`, the packet queue and its consumers.
- Who sets the orientation, wrist and offset values (main-side configuration
  over IPC).
- The descriptor callbacks and IRQ event `0x101` scheduling of the drain.
