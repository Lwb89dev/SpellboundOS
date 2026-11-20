# Sensor-hub LSM6DSO accelerometer ioctl dispatch

The accelerometer descriptor's control callback `0x80f71d58(command, arg)` is a
command dispatcher: a comparison chain plus two jump tables route ~17 commands to
their handlers, and everything else logs `CMD%d unsupport`. This scope executes
the dispatcher in the `sensor-runtime` project for the commands whose handler is
a direct tail-call, with the handler targets supplied, so the **routing** is
verified; the full command map is decoded from the two verified jump tables. The
evidence is in [sensorhub-imu-ioctl.json](sensorhub-imu-ioctl.json). All **4
native cases pass**.

## Verified routing

| Command | Routes to |
| --- | --- |
| `0x01` (sample read) | `0x80f62f90` |
| `0xb2` | `0x80f6300e` |
| any unrouted (e.g. `0x30`, `0xc0`) | `CMD%d unsupport` logger `0x80f86d34` |

## Command map (decoded)

The direct comparisons handle `0x01`, `0x02`, `0xb2`, `0x101`, `0x102`; the jump
table at `0x80fd8658` covers `0x9d..0xab` and the one at `0x80fd8694` covers
`0x81..0x86`. Notable handlers: `0xa0` = read-id/mode (`0x80f71e2a`), `0xa1`
(`0x80f71eea`). The commands `0x82`, `0x9f`, `0xa2..0xa5`, `0xa7..0xaa` route to
the unsupported logger. The full table is in the evidence `command_map`.

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_ioctl --vectors-output firmware/sensorhub-imu-ioctl-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-ioctl-vectors.json firmware/sensorhub-imu-ioctl-validation.json
python3 -m analysis_scripts.sensorhub_imu_ioctl firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-ioctl-vectors.json \
  --validation firmware/sensorhub-imu-ioctl-validation.json > analysis/sensorhub-imu-ioctl.json
python3 -m unittest tests.test_sensorhub_imu_ioctl -q
```

## Remaining

- The individual command handlers (rate/range/mode/self-test and the jump-table
  commands) are decoded into the map but not individually executed; the shared
  FIFO read callback `0x80f714a0` remains (see the IMU FIFO work).

## Gyroscope ioctl (`0x80f716ec`)

The gyroscope control callback is a parallel dispatcher. Verified commands:

- `0x01`: no-op (returns the command);
- `0xab`: **get sample rate** — reads the ODR code (`0x80f16b2e`) and multiplier
  (`0x80f16b21`) and writes `160000 / (ODR_code * multiplier)` to the output
  argument (a2). Executed cases give `160000/16 = 10000` for both `ODR=16,mult=1`
  and `ODR=8,mult=2`;
- any other command logs `CMD%d unsupport` (`0x80f86d34`).

Commands `0x02`, `0x81`, `0xa0`, `0x201`, `0x202` route to their own handlers
(sensor read / config), decoded but not individually executed. Both ioctls take
`(command, a1, a2)`; the accelerometer handlers use `a1`, the gyroscope rate
command writes `a2`.
