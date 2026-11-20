# AW32012 charger: register layer and controls

This is the alternative to the CW6305 charger
([MAIN_CHARGER_CW6305.md](MAIN_CHARGER_CW6305.md)) on the same `sens_i2c1`
bus. All **47 native cases** pass (3,424 steps) in `main-runtime`. Only the I2C
register transfer helpers and the logger are supplied. The evidence is in
[main-charger-aw32012.json](main-charger-aw32012.json).

## Bus

I2C address **`0x49`**, 8-bit registers, one byte per transfer, timeout 1000.
The handle is at `0x70f8e5b0`. Without a handle the helpers return −10.

## Registers and controls

| Register | Use in the driver |
| --- | --- |
| `0x01` | bit 3: charge **disable** (active high), written only on change; hibernate mode 3 also goes through it |
| `0x02` | bits 5:0: fast-charge current `(mA − 8) / 8` (`0x3f` above 519 mA), written only on change |
| `0x03` | bits 3:0: pre-charge/termination current `(mA − 1) / 2` (`0xf` above 32 mA); `set` and `check` |
| `0x06` | bit 5: power off |
| `0x08` | system status; bits 4:3: charge state |
| `0x09` | fault |
| `0x0a` | id |
| `0x0d` | bit 0: switch mode |
| `0x21` | bit 7: VBUS reset behaviour, set when the argument is 0 |
| `0x69` | `0xc2` unlocks and `0x00` locks the `0x21` access |

- **VBUS reset configuration:** unlock `0x69 = 0xc2`, then read-modify-write
  `0x21`, then relock `0x69 = 0`. The relock runs even when the unlock fails,
  and a failed relock returns −1.
- **Init:** enable the interrupt, write the original 13-register table
  `6f 6c 21 98 de 1a 42 37 00 40 00 41 c0` (registers `0x00`–`0x0c`, at
  `0x70f61cfc`, up to three attempts), then apply the VBUS reset
  configuration with argument 0.
- **Second table writer:** `0x702b83ac` writes registers `0x00`–`0x0d`.

## Reproduction

```sh
python3 -m analysis_scripts.main_charger_aw32012 --vectors-output firmware/main-charger-aw32012-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-charger-aw32012-vectors.json \
  firmware/main-charger-aw32012-validation.json
python3 -m analysis_scripts.main_charger_aw32012 firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-charger-aw32012-vectors.json \
  --validation firmware/main-charger-aw32012-validation.json > analysis/main-charger-aw32012.json
python3 -m unittest tests.test_main_charger_aw32012 -q
```

## Remaining

- Which charger is fitted: decided by the id test at runtime, so it needs the
  device.
- Interrupt handling, the charge-done handler and the power-supply framework.
