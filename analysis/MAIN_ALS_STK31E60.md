# STK31E60 ambient-light sensor: registers, init, gain and ALS read

The ALS (`dev_stk31e60`, bus `i2c3`, rail `TP_1V8`) is driven at I2C address
**`0x48`** with 8-bit registers. All **31 native cases** pass (4,519 steps) in
`main-runtime`. They cover the register layer, init, integration time, gain,
data-ready wait and ALS read. Supplied: bus transfers, regulator, delays,
tick/time conversion, the register-dump helper and the logger. The evidence is
in [main-als-stk31e60.json](main-als-stk31e60.json).

## Register layer

The register read `0x701e9e4a` and write `0x701e9f9c` make three attempts,
2 ms apart. After the last failure they log and return the status.

## Init (`0x701ea444`)

1. Rail on, then 40 ms. A missing rail is skipped.
2. Force the vendor registers `0xe3/0xe5/0xea/0xec` to `0x80`, writing only
   those that differ.
3. Write `0x07 = 0x03`, `0x08 = 0xe7` and `0x3d = 0x00`.
4. Clear bit 4 of `0x6a`.
5. Write `0x6b = 0x01` and `0x17 = 0xb0` (gain code).
6. Set the integration time to **16.6 ms**. The code is
   `trunc(ms × 1000 / 99 − 1)`, giving `0x00a6`, and is written to `0x6e`
   (high) and `0x6f` (low).
7. Compute the gain ratio for code `0xb0` and set the initialised flag at
   `+0x69`.

Failures of `0x07`, `0x08` or the `0x6a` write return −1, logged twice.
Other failures return the bus status.

## Gain

`0x709d24e4` holds 16 `(code, factor)` pairs: `0xf0` → 4096, `0xe0` → 2048,
… `0xb0` → 256, … `0x00` → 0.0039. Unknown codes use 256. The ratio
`factor(0xb0) / factor(code)` is stored at `0x70f8e0f8`. `0xb0` is the
reference code.

## ALS read (`0x701ea670`)

1. Each mode `+0x68` has a period: 16.6, 332 or 2 ms. An invalid mode is
   logged and uses 16.6 ms.
2. If the elapsed time is below `period + 1`, sleep
   `trunc(period − elapsed + 3)` ms.
3. Poll data ready: `0x10` bit 7, three reads 200 ms apart. On timeout, dump
   the registers and return −2.
4. Read the value `0x13 << 8 | 0x14`. On a read error, the cached value at
   `0x70f8e0f0` is returned instead, with status 0. Chip id: `0x3e` must read
   `0xe0`.

## Emulator repairs

Two `fcvt.wu.s` sites have their `rd` dropped by Ghidra's SLEIGH:
`0x701ea072` (integration code) and `0x701ea716` (sleep time). The runner
repairs them with the RISC-V semantics. The gain-ratio `c.fsw` is recorded as
the emulator's 8-byte store. See [NATIVE_REPAIR.md](NATIVE_REPAIR.md).

## Reproduction

```sh
python3 -m analysis_scripts.main_als_stk31e60 --vectors-output firmware/main-als-stk31e60-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-als-stk31e60-vectors.json \
  firmware/main-als-stk31e60-validation.json
python3 -m analysis_scripts.main_als_stk31e60 firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-als-stk31e60-vectors.json \
  --validation firmware/main-als-stk31e60-validation.json > analysis/main-als-stk31e60.json
python3 -m unittest tests.test_main_als_stk31e60 -q
```

## Remaining

- Lux conversion and auto-gain (`auto gain update`).
- The stylefile load and the brightness consumer.
- Physical verification of the part.
