# Sensor-hub LSM6DSO sample delivery

All **16 cases** pass (5,711 instructions) in the startup-aware `sensor-runtime`
project. They execute the original shared read callback `0x80f714a0`, packet
allocator `0x80f6453e`, tagged-word decoder `0x80f6fc42` and release wrapper
`0x80f6462c`. The thirteen earlier observations reproduce unchanged. See
[the machine-readable evidence](sensorhub-imu-read.json).

The caller optionally re-arms the device and clears the dirty flag. It passes a
stack output for the words still in the physical FIFO to the drain at
`0x80f710ac`. A drain error or zero buffered words returns NULL. The separate
[FIFO drain investigation](SENSORHUB_IMU_FIFO.md) executes that routine.

For a populated buffer, let `rate` be the configured u16 value at `0x80f16b2e`
and `streams` be one for accelerometer only or two when gyroscope is enabled.
The callback chooses `words = min(buffered, floor(1200 × rate / 1000) × streams)`
and `samples = floor(words / streams)` per stream. The allocator receives a
stride of `samples × 6` bytes and returns NULL for a zero stride. Each stream
header holds the sensor type (2 for accelerometer, 4 for gyroscope), configured
sensitivity, sample count and rate rounded down to a multiple of 25. The
callback backdates both headers by
`floor((buffered − words + fifo_remaining) / streams) × floor(1000 / rate)`
timestamp units. The captured vectors include a borrow from the low 32 bits.
The timestamp is stored in the stream header. The decoder copies XYZ triples
and applies the per-axis offsets in 16-bit arithmetic.

| Exercised case | Outcome |
| --- | --- |
| Accelerometer only, 65 buffered words at rate 26, three still in FIFO | Delivers 31 samples, backdates by `37 × 38`, and compacts the 34 remaining words with overlapping source and destination ranges |
| Accelerometer plus gyroscope, two of each tag, three still in FIFO | Delivers two samples per stream, backdates both by `1 × 38` |
| Dual mode, two of each tag plus one unknown tag | Delivers both streams and consumes all five words |
| Dual mode, two accelerometer tags and three gyroscope tags | Decoder rejects the excess gyroscope tag and preserves all five buffered words |
| Allocation failure or zero stride | Returns NULL and preserves the buffer |
| Missing accelerometer or gyroscope tag | Calls the packet release wrapper, posts event `0x102`, returns NULL and preserves the buffer. The supplied queue result selects whether the wrapper frees the packet |

Three cases connect the original drain to the callback, covering fresh
accelerometer words, dual-stream delivery with one word left in the FIFO, and
an SPI failure. The other cases supply the drain result. The SPI transfer,
re-arm, heap, clock, queue, algorithm hook, logger, event delivery, zeroing
and overlap-safe memory movement are supplied to the emulation. The memory
snapshots check the compacted bytes, packet headers and decoded samples. Live
SPI timing, interrupt scheduling, cache concurrency and downstream packet
consumption still require separate evidence.

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_read --vectors-output firmware/sensorhub-imu-read-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-read-vectors.json firmware/sensorhub-imu-read-validation.json
python3 -m analysis_scripts.sensorhub_imu_read firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-read-vectors.json \
  --validation firmware/sensorhub-imu-read-validation.json > analysis/sensorhub-imu-read.json
python3 -m unittest discover -s tests -p 'test_sensorhub_imu_*.py' -q
```
