# ZTW622 touch open: bus/GPIO bring-up, check-mode probe and task/timer start

`ztw622_open` (`0x701ebed8`) is the device-open ioctl that brings the touch
controller up after [attach/probe](MAIN_TOUCH_CONTROL.md). It executes in
`main-runtime` on top of the already-verified register/reset/version layer of
[MAIN_TOUCH_CONTROL.md](MAIN_TOUCH_CONTROL.md) and
[MAIN_TOUCH_REPORT.md](MAIN_TOUCH_REPORT.md). The evidence is in
[main-touch-open.json](main-touch-open.json). All **10 native cases pass**.

## Bring-up

1. Find the board record `dev_ztw622`, open and configure the I2C bus.
2. Zero a GPIO descriptor and configure the interrupt pin (record `+2`).
3. Attach the interrupt handler `0x701eacae` (`0x702bd834`).
4. Set the rotation flag (`0x701eb44a`).

## Check-mode probe

Up to **three attempts** read register `0x13` and register `0x121`
(`0x701eaf56`). A read failure soft-resets (`0x701eb702(1)`) and retries.

- If both reads return `0x13` / `0x121`, the device is taken as **normal mode**
  (context `+0x1c = 1`).
- Otherwise the **version block** `0x701ebc50` runs and the mode is recorded as
  **bootloader** (`+0x1c = 2`); a later log reports `"ops in normal mode"` vs
  `"ops in bootloader mode"` from this byte.
- If all three attempts fail to read, it proceeds as normal mode anyway.

## Enable

1. Write register `0xd4 = 0x3c`.
2. Soft reset `0x701eb702(2)` and clear the interrupt.
3. Enable the GPIO interrupt (`0x702bda0c`).
4. Allocate and start the input task (`0x80d3ddd8`, entry `0x701eca9c`,
   priority `0x64`); the message pointer is published at `0x70f8e0fc`.
5. Program the charge active-nap delay register `0xe3` from context `+0x3a`
   (`0x701ebe74`).
6. Create the poll timer (`0x80d36b96`, callback `0x701eb154`) into `0x70f8e104`.
7. Mark the context opened (`+0x2b = +0x28 = 1`) and return 0.

## Return codes (observed natively)

| Case | Return |
| --- | --- |
| normal mode / bootloader mode | `0` |
| I2C get fails | the service error (`3`) |
| interrupt attach fails | the service error (`0xA`) |
| task allocation fails | `-5` |
| timer create fails | `-6` |

Early failures return the service error with no teardown (unlike attach, which
unwinds power/GPIO/I2C/mutex).

## Reproduction

```sh
python3 -m analysis_scripts.main_touch_open --vectors-output firmware/main-touch-open-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-touch-open-vectors.json firmware/main-touch-open-validation.json
python3 -m analysis_scripts.main_touch_open firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-touch-open-vectors.json \
  --validation firmware/main-touch-open-validation.json > analysis/main-touch-open.json
python3 -m unittest tests.test_main_touch_open -q
```

## Remaining

- The input task body (entry `0x701eca9c`) that consumes the interrupt and the
  poll-timer callback (`0x701eb154`); these call the already-executed report
  handler `0x701eb18a`.
- `gpio_key` buttons and the display refresh path, still open.
