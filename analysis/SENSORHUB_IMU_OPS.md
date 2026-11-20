# Sensor-hub LSM6DSO descriptor operations (enable / disable / control)

The accelerometer and gyroscope sensor descriptors registered by the attach
(see [SENSORHUB_IMU_INIT.md](SENSORHUB_IMU_INIT.md)) carry the operation
callbacks the hub invokes for open/close/control. This scope executes them in the
`sensor-runtime` project; the already-verified mode setter
([SENSORHUB_IMU_MODE.md](SENSORHUB_IMU_MODE.md), `0x80f70da2`) and the FIFO drain
([SENSORHUB_IMU_FIFO.md](SENSORHUB_IMU_FIFO.md), `0x80f710ac`) are supplied, so
only the callbacks' own sequencing and state is executed. The evidence is in
[sensorhub-imu-ops.json](sensorhub-imu-ops.json). All **10 native cases pass**.

## Callbacks

| Sensor | Enable | Disable | Control |
| --- | --- | --- | --- |
| accelerometer | `0x80f70f28` | `0x80f71046` | `0x80f716b2` |
| gyroscope | `0x80f70f62` | `0x80f71c24` | — |

- **Enable**: calls the mode setter (`(1, odr)` for the accelerometer,
  `(odr, 1)` for the gyroscope); on failure returns 2, else marks the sensor
  running (`0x80f17030`/`0x80f1702c`), clears the pending sample count
  (`0x80f17024`) and returns 0.
- **Disable**: mode set off, latches the power selector
  (`0x80f16b1c`/`0x80f16b1d = 1`), clears the running/sample state, logs the
  full-scale and stores the defaults (accelerometer `0x80f16b28 = 0x1000`,
  `0x80f16b2d = 3`; gyroscope `0x80f16b24 = 0x596`, `0x80f16b2c = 6`).
- **Control** (`0x80f716b2`): command 0 runs the self-test query and posts a
  result event, command 2 flushes the FIFO, any other command is a no-op that
  returns the command value.

## Return codes (observed natively)

| Case | Return |
| --- | --- |
| enable / disable ok | `0` |
| enable, mode set fails | `2` |
| control self-test / fifo flush | `0` |
| control passthrough (cmd 7) | `7` |

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_ops --vectors-output firmware/sensorhub-imu-ops-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-ops-vectors.json firmware/sensorhub-imu-ops-validation.json
python3 -m analysis_scripts.sensorhub_imu_ops firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-ops-vectors.json \
  --validation firmware/sensorhub-imu-ops-validation.json > analysis/sensorhub-imu-ops.json
python3 -m unittest tests.test_sensorhub_imu_ops -q
```

## Remaining

- The shared FIFO **read** callback `0x80f714a0` (sample delivery + ODR maths)
  and the full ioctl dispatchers `0x80f716ec` / `0x80f71d58` (rate/range/mode
  commands) are not executed here. With these, the LSM6DSO driver — probe,
  attach, registers, mode, FIFO and the operation callbacks — is otherwise
  complete.
