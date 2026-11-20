# CW6305 charger: register layer and controls

The main image carries **two alternative charger drivers**, both on
`sens_i2c1`: AW32012 and CW6305 (see
[MAIN_BOARD_RECORDS.md](MAIN_BOARD_RECORDS.md)). An id test decides at runtime
which one is fitted. This note covers CW6305. All **38 native cases** pass
(2,873 steps) in `main-runtime`. Only the I2C register transfer helpers and the
logger are supplied. The evidence is in
[main-charger-cw6305.json](main-charger-cw6305.json).

## Bus

- Register read `0x702b95dc(reg, out)` and write `0x702b9720(reg, value)` use
  I2C address **`0x0b`**. Registers are 8 bits wide and each transfer moves
  one byte, with timeout 1000.
- The handle is at `0x70f8e5cc`. Without a handle the helpers return −10.

## Registers and controls

| Register | Use in the driver |
| --- | --- |
| `0x00` | id (`cw6305_get_id_code`) |
| `0x01` | bit 6: charge enable (`chg_ctrl`), written only when it changes |
| `0x04` | bits 5:0: fast-charge current code |
| `0x06` | bits 6:5: safety timer |
| `0x07` | bit 7: power off |
| `0x08` | bit 7: charge watchdog; bit 6: discharge watchdog |
| `0x0b` | interrupt source; cleared by writing 0 |
| `0x0d`, `0x0e` | status, status 2 |

- **Power off** `0x702b9750` clears `0x08` bit 7, clears `0x08` bit 6, then sets
  `0x07` bit 7. A failure in the first two steps is logged and the sequence
  continues.
- **Hibernate** enable/disable (`0x702b9a42`/`0x702b9aa6`) act only for mode 3,
  through `chg_ctrl(1/0)`.
- **Fast-charge current** `0x702b9b0a(mA)` accepts **10–470 mA**; anything else
  returns −1. The field is written only when the code changes, and the top two
  bits of `0x04` are preserved. The 6-bit code has four segments:
  - 10–20 mA: 1.25 mA steps, codes 0–8;
  - 20–40 mA: 2.5 mA steps, codes 8–16;
  - 40–80 mA: 5 mA steps, codes 16–24;
  - 80–470 mA: 10 mA steps, codes 24–63.
- **Initial configuration** `0x702b9fbc` writes registers `0x00`–`0x0a` from the
  original table `14 03 8f bd eb 11 5a 1d 13 8f c3` (at `0x70f61db8`). A failed
  write is logged and the remaining writes continue. The wrapper `0x702b8c8e`
  retries the whole table up to three times.

## Reproduction

```sh
python3 -m analysis_scripts.main_charger_cw6305 --vectors-output firmware/main-charger-cw6305-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-charger-cw6305-vectors.json \
  firmware/main-charger-cw6305-validation.json
python3 -m analysis_scripts.main_charger_cw6305 firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-charger-cw6305-vectors.json \
  --validation firmware/main-charger-cw6305-validation.json > analysis/main-charger-cw6305.json
python3 -m unittest tests.test_main_charger_cw6305 -q
```

The `bus` stub now accepts a list of recorded argument registers. The touch
scopes regenerate byte for byte.

## Remaining

- The AW32012 alternative driver, and which of the two is fitted.
- Interrupt handling, JEITA control, the periodic charge work, VBUS
  measurement and the power-supply framework.
- The meaning of the init-table bytes (voltages and limits) without the
  datasheet.
