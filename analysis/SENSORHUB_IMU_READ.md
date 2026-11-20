# Sensor-hub LSM6DSO FIFO read callback (entry / empty handling)

`0x80f714a0` is the shared accelerometer/gyroscope descriptor read callback. It
optionally re-arms the sensor (dirty flag `0x80f17026` → `0x80f700b4`), drains
the FIFO (`0x80f710ac`, verified in [SENSORHUB_IMU_FIFO.md](SENSORHUB_IMU_FIFO.md)),
and when samples are present allocates a sensor event (`0x80f6453e`) and fills it
with timestamped samples using the ODR code at `0x80f16b2e`. It returns the event
pointer, or NULL when the drain fails or no samples are available.

This scope executes the **entry, re-arm, drain and empty/error return paths**
with the FIFO drain and the re-arm supplied; the evidence is in
[sensorhub-imu-read.json](sensorhub-imu-read.json). All **4 native cases pass**.

| Case | Re-armed | Return |
| --- | --- | --- |
| empty, flag clear | no | NULL |
| empty, dirty flag set | yes (`0x80f700b4`) | NULL |
| drain error | no | NULL |
| drain error, dirty flag set | yes | NULL |

## Reproduction

```sh
python3 -m analysis_scripts.sensorhub_imu_read --vectors-output firmware/sensorhub-imu-read-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime sensor-runtime \
  -process sensor-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateSensorhubImuProbe.java firmware/sensorhub-imu-read-vectors.json firmware/sensorhub-imu-read-validation.json
python3 -m analysis_scripts.sensorhub_imu_read firmware/bip6-4.6.0.3.zip \
  --vectors firmware/sensorhub-imu-read-vectors.json \
  --validation firmware/sensorhub-imu-read-validation.json > analysis/sensorhub-imu-read.json
python3 -m unittest tests.test_sensorhub_imu_read -q
```

## Remaining

- The **sample-delivery data path** (event allocation `0x80f6453e` and the
  per-sample timestamp loop using the ODR timing) is not executed here. With it,
  the LSM6DSO driver — probe, attach, registers, mode, FIFO drain, ops, ioctl and
  the read callback's control flow — is otherwise fully executed.
