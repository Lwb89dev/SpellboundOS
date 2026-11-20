# ZTW622 touch control: attach/probe, rails, reset, modes and version

All **23 native cases** pass (6,990 steps) in `main-runtime`. They execute the
original ZTW622 attach/probe `0x701eb88a`, the rail switch `0x701eb4dc`, the
reset `0x701eb702`, the mode setter `0x701eb7c8` and the version read
`0x701ebc50`, on top of the register layer from
[MAIN_TOUCH_REPORT.md](MAIN_TOUCH_REPORT.md). They run over the original
`dev_ztw622` board record ([MAIN_BOARD_RECORDS.md](MAIN_BOARD_RECORDS.md)).
Supplied: board lookup, mutex, I2C/GPIO/regulator services, trace, delay,
memset, logger and bus transfers. The evidence is in
[main-touch-control.json](main-touch-control.json).

## Attach and power-up

1. Clear the context and look up `dev_ztw622`. Create the mutex.
2. Get the I2C handle for `i2c3` and configure it.
3. Configure the reset GPIO (pin 15) and drive it low. Configure the
   interrupt GPIO (pin 21).
4. vdda (`LDO2_TP`) off. Wait for vdda to discharge (`0x702b6944(h, 5)`).
5. Wait 100 ms. Switch on **vddd (`TP_1V8`)**, then **vdda (`LDO2_TP`)**.
6. Wait 1 ms, then run the **hardware reset**:
   - wait 1 ms;
   - drive reset high, then wait 10 ms;
   - suspend I2C, then drive reset low;
   - wait 100 ms, then drive reset high;
   - resume I2C, then wait 200 ms.
7. Probe:
   - send command `0x01f8`, then wait 100 ms;
   - write `0xc000 = 1`;
   - read the 22-byte information block at `0x09d2`;
   - soft reset: command `0x0ff8`, then 100 ms.
8. Chip id:
   - If the soft reset succeeded, take the chip id from info `[0x0a..0x0b]`
     and the ium value from `info[8] << 16 | info[0xd] << 8 | info[0xc]`.
   - Otherwise read register `0x0120`. A wrong id from the information block
     also falls back to this register, read up to twice.
   - The chip id must be **`0xe622`**.
9. On success, return the device object `0x70f60efc`.

Failures:

- Each failure logs a code (1–13).
- Rails are switched off (vdda, then vddd) and the interrupt and reset GPIO
  are released. The I2C handle, mutex and context are released too.
- The function returns 0.
- Each failure enters the cleanup at its own stage, matching the original
  labels `0x701eb9b0`–`0x701eb9e4`.

## Rails, reset types, modes and version

- **Rail switch** `(rail, on)`: rail 0 is vdda at record `+0xc` and rail 1 is
  vddd at `+0x10`. It looks up the regulator, enables or disables it, and
  always emits a `SWITCH` trace.
  - Invalid rail: −10.
  - No board record: −4.
  - No rail name: −6.
- **Reset types**:
  - 0: the hardware sequence above;
  - 1: command `0x0ff8` plus 100 ms;
  - 2: command `0x0000`;
  - any other type: −10.
- **Mode set** writes registers and always ends with five clear-interrupt
  commands, 50 ms apart:
  - mode `0x0b`: `0x122=0x1f`, `0x135=0x09`, `0x100=0x25`, `0x7f=0x64`, reset
    type 2, 25 ms, `0x10=0x0b`;
  - mode `0x0e`: `0x10=0x0e`, reset type 2;
  - any other mode: `0x122=0x0d`, `0x135=0`, `0x100=0x3c`, `0x10=mode`, reset
    type 2.
- **Version** runs reset type 2, then reads:
  - major `0x0012`, minor `0x0121`, release `0x0013`;
  - x/y resolution `0x00c0`/`0x00c1` into context `+0x18`/`+0x1a`;
  - x/y channels `0x0060`/`0x0061`;
  - glove `0x011f`.

## Reproduction

```sh
python3 -m analysis_scripts.main_touch_control --vectors-output firmware/main-touch-control-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-touch-control-vectors.json \
  firmware/main-touch-control-validation.json
python3 -m analysis_scripts.main_touch_control firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-touch-control-vectors.json \
  --validation firmware/main-touch-control-validation.json > analysis/main-touch-control.json
python3 -m unittest tests.test_main_touch_control -q
```

The runner now names the failing case in errors. The touch report scope
regenerates byte for byte.

## Remaining

- `ztw622_open` `0x701ebed8` and its init sequence: IRQ installation, mode
  check (`0x13`/`0x121`), `0xd4 = 0x3c`, the supported-finger count `0x15`,
  and the charger "active nap delay" `0xe3`.
- Firmware upgrade and version comparison `0x701ebdf0`.
- Suspend/resume and the input-layer consumer.
