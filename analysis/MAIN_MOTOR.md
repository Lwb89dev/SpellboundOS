# Vibration motor (`dev_NL_motor`)

All **21 native cases** pass in `main-runtime`. Evidence:
[main-motor.json](main-motor.json).

- **On/off.** The motor is a plain GPIO output on record `+4`, which is
  **pin 95**. On `0x702d4fb0` drives the pin high and off `0x702d4d44` drives
  it low. Each switch emits a `MOTOR`/`SWITCH` trace with the GPIO status.
  Without a board record, both return −1 and nothing is written.
- **Pulse** `0x702d5034(mode, params)`:
  - Mode 1 is a plain switch-on.
  - Any other mode switches the motor on and starts the one-shot
    `nonlinear_motor` timer. Its duration comes from the requested level:
    levels 1–8 map to **25, 25, 50, 50, 80, 130, 25, 25 ms** (table
    `0x70a30a14`), and any other level uses **1000 ms**. The timer work then
    switches the motor off.
  - Null parameters return −1. A failed switch-on is logged and returned.
- **Duration query** `0x702d50d6(params)` writes the level duration to
  `params + 2`. Null parameters return −4.

GPIO, trace, timer and logger are supplied. The haptic pattern layer above
this driver and the timer work are not executed.

```sh
python3 -m analysis_scripts.main_motor --vectors-output firmware/main-motor-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-motor-vectors.json firmware/main-motor-validation.json
python3 -m analysis_scripts.main_motor firmware/bip6-4.6.0.3.zip --vectors firmware/main-motor-vectors.json \
  --validation firmware/main-motor-validation.json > analysis/main-motor.json
```
