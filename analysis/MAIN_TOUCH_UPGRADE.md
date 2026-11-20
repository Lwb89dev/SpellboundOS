# ZTW622 TP firmware-upgrade worker (input-task body)

The input task started by [ztw622_open](MAIN_TOUCH_OPEN.md) runs the body at
`0x701eca9c`, dispatched by the state byte at `0x70f8e100`
(`0x70f8e0fc[4]`): **state 1** is the TP firmware upgrade / ODR worker
(`ztw622_uprgade_process` / `upgrade_odr_process`), **state 2** is the
work/config-reset process (`0x701ec2a4`), any other value returns. This is the
on-device consumer of the OTA **"TP firmware"** module (file types 49/51; see
[MAIN_OTA_INSTALL.md](MAIN_OTA_INSTALL.md)). The worker itself executes; the
already-verified register/reset/version/dispatch helpers are stubbed. The
evidence is in [main-touch-upgrade.json](main-touch-upgrade.json). All **4
native cases pass**.

## State 1 — firmware upgrade

1. **Prepare**: publish a progress event (`ztw622_process_event 0x701eac38`,
   mode 0), record the block count (`length >> 6` into context `+0x20`), stop
   the poll timer (`0x701eae1e`), disable the touch interrupt (`0x702bdac6`) and
   mark the context upgrading (`+0x2c = 5`).
2. **Enter the bootloader**: soft reset, then program registers `0x1d5`,
   `0xc000 = 1`, `0xc004`, `0xc002 = 1`, `0xc003 = 1`, `0x104 = 1`, `0x1d0`
   with 10 ms gaps; progress event mode 1.
3. **Stream the image** in 0x40-byte chunks. For each 8-byte group, build a
   10-byte I2C packet **`[0x01d1, data[k:k+8]]`** (`malloc` → I2C write
   `0x701ead14` → `free`) with a 1 ms gap; after each chunk bump `+0x24` and
   raise progress event mode 2. The captured packets are exactly the source
   image bytes in order.
4. **Leave the bootloader**: progress event mode 3, then `0xc003 = 0`,
   `0x104 = 0`, `0x1d0`.
5. **Verify**: for each 0x40 block, read register `0x1d2` back and `memcmp`
   (`0x70947ab0`) against the source; a mismatch logs `verify flash fail`.
6. **Finalize**: version read, post-version hook (`0x701ebdf0`), progress event
   mode 4, mark the context normal (`+0x2c = 1`), re-enable the interrupt
   (`0x702bda0c`) and restart the poll timer.

On any error the worker retries the whole upgrade up to three times, then sends
progress event mode 5, resets and restarts the timer.

## State 2 — work / config reset

Logs `reset tp from e-fuse`, calls the config-reset `0x701ec2a4`; on success
returns 0, on failure tail-logs and returns the log level (3).

## Return codes (observed natively)

| Case | Return |
| --- | --- |
| upgrade (1 or 2 chunks) | `0` |
| state 2 work process | `0` |
| state 2, config reset fails | `3` |

## Reproduction

```sh
python3 -m analysis_scripts.main_touch_upgrade --vectors-output firmware/main-touch-upgrade-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-touch-upgrade-vectors.json firmware/main-touch-upgrade-validation.json
python3 -m analysis_scripts.main_touch_upgrade firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-touch-upgrade-vectors.json \
  --validation firmware/main-touch-upgrade-validation.json > analysis/main-touch-upgrade.json
python3 -m unittest tests.test_main_touch_upgrade -q
```

## Remaining / limitations

- The register/reset/version/dispatch helpers, malloc/free, memcmp, the GPIO
  interrupt enable/disable, the timer stop/start and the logger are stubbed; the
  worker runs as real code and the streamed I2C packets are captured.
- The flash read-back comparison is stubbed (memcmp returns match); the
  on-device verify is not executed. The up-to-three-attempt retry on error is
  only partially covered.
- This completes the ZTW622 touch driver (report, control, open, delivery,
  upgrade). The non-touch offline blocks (`gpio_key`, BT RTL8763 transport,
  display DSI refresh, sensor-hub IMU callbacks) remain.
