# GPIO interrupt registration: callback-row insert/update and trigger mode

All **12 native cases** pass in **2,475 instruction steps**. This scope
completes the GPIO interrupt chain of
[MAIN_GPIO_DISPATCH.md](MAIN_GPIO_DISPATCH.md) and
[MAIN_GPIO_CONFIG.md](MAIN_GPIO_CONFIG.md) by executing the original
registration routine `0x80d43068`: it fills the callback rows the dispatcher
reads and the enable routine commits.

Everything runs over authored controller structs, authored MMIO banks and the
authored 16-row callback table at `0x80c118c8`. The configuration gate
`0x80d341d8`, the scheduler-state reader `0x80d362b0` and the critical
save/restore wrappers `0x80d379ee`/`0x80d37a1a` are supplied return stubs. The
evidence is in [main-gpio-register.json](main-gpio-register.json).

## Registration routine

`0x80d43068(base, pin_mask, arg0, mode, handler, arg1)`:

1. Converts `pin_mask` to a bit index with libgcc `__ctzsi2` (`0x7094514c`),
   which isolates the lowest set bit and looks it up in the bit-length table at
   `0x709babf8` (the same table `__clzsi2` uses). For a single-bit mask it
   returns that pin's index.
2. Scans the 16 rows for a row matching `(base, bit)`:
   - a matching row with a different handler has its handler (`+0x10`) and
     `arg1` (`+0x14`) updated in place;
   - otherwise the first row with a zero handler is filled with the full layout
     below;
   - if no row matches and none is free, it returns 1.
3. Programs the controller for the trigger mode and enables the pin.

The callback row layout, refined from the dispatcher's view (the previously
"reserved" word is the mode byte):

| Offset | Field |
| --- | --- |
| `+0x00` | controller base |
| `+0x04` | pin bit index |
| `+0x08` | handler argument 0 |
| `+0x0c` | mode byte |
| `+0x10` | handler |
| `+0x14` | handler argument 1 |

## Trigger modes

The `mode` argument (1–5) programs three controller registers; an invalid mode
returns 1 without touching the controller:

| Mode | `+0x38` | `+0x34` | `+0x3c` |
| --- | --- | --- | --- |
| 1 | 0 | 0 | 0 |
| 2 | 0 | 0 | 1 |
| 3 | 1 | 0 | 0 |
| 4 | 0 | 1 | 1 |
| 5 | 0 | 1 | 0 |

`+0x38`, `+0x34` and `+0x3c` are the controller's trigger-configuration bits
(working names level, trigger-A and trigger-B); their precise edge/level/
polarity meaning is not established. Every valid mode also clears the pin bit in
`+0x20` (disable mask) and sets it in `+0x2c` (enable), identical to the
enable/commit routine.

The controller update is bracketed by the same `0x900080b0` handshake: the
routine waits while the register is non-zero, writes the handshake value
(`2` when the gate returned non-zero, else `1`), confirms the read-back, applies
the five register writes and finally releases the register to `0`. When the
scheduler-state reader reports a non-zero state, the update is wrapped in the
critical save/restore pair.

## Cases

| Group | Cases | Selected observations |
| --- | ---: | --- |
| Fresh | 6 | A new row per trigger mode; `ctz` maps a high-bit mask to its index |
| Update | 2 | Existing row handler/arg updated in place; same handler reconfigures without a row write |
| Placement | 1 | First free row chosen after occupied rows |
| Critical | 1 | Non-zero scheduler state wraps the commit |
| Errors | 2 | Invalid mode and a full table both return 1 with no controller writes |

Every executed PC is inside a hash-guarded original range or a supplied stub.
The runner records every store, every CSR access, every callee call with its
arguments and the routine's return value, and supplies the gate/state returns in
sequence. The independent Python model reproduces all of them.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_gpio_register --vectors-output firmware/main-gpio-register-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainGpioRegister.java firmware/main-gpio-register-vectors.json \
  firmware/main-gpio-register-validation.json
python3 -m analysis_scripts.main_gpio_register firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-gpio-register-vectors.json --validation firmware/main-gpio-register-validation.json \
  > analysis/main-gpio-register.json
```

The vectors, native report and evidence regenerate byte for byte.

Remaining work:

- Recover the edge/level/polarity meaning of `+0x34`/`+0x38`/`+0x3c` and the
  callers that register each pin, to map the handlers to physical functions.
- Execute the scheduler-state reader `0x80d362b0` and the `0x900080b0` handshake
  against a modeled responder rather than an idle register.
- Follow the de-registration path and the handlers the rows point at.
