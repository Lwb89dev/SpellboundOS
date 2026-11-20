# ZTW622 touch delivery: event dispatcher and poll-timer callback

Two small delivery helpers sit above the [report handler](MAIN_TOUCH_REPORT.md)
and are wired up by [ztw622_open](MAIN_TOUCH_OPEN.md). Both execute in
`main-runtime`; the evidence is in
[main-touch-dispatch.json](main-touch-dispatch.json). All **7 native cases
pass**.

## Event dispatcher `0x701eac38(dev, mode, value_ptr)`

Builds a 0x38-byte input event on the stack and calls the device callback:

| Offset | Value |
| --- | --- |
| `+0` | `1` |
| `+8` | `1` |
| `+0xc` | `mode` (event sub-type) |
| `+0xe` | `*value_ptr` (16-bit) |

then `dev->callback(dev, &event, 0)` (callback at `dev+0x3c`). It returns `-4`
when the device or its callback is NULL, otherwise the callback's own result.
This is how the firmware-upgrade worker reports stage/progress events to the UI
(a captured event with `mode = 5`, `value = 0x00a0` is in the evidence).

## Poll-timer callback `0x701eb154`

1. Set the input state byte at `0x70f8e100` to `2` (poll).
2. Notify the input task (`0x80d3dedc`) on the task object at `0x70f8e110`.
3. If the notify returns non-zero, restart the 5000 ms poll timer via
   `0x701eb102` → `0x80d36ba0(timer, 0x1388)`, returning `-4` for a missing
   timer handle and `-14` when the timer-start service fails; a zero notify
   result just returns.

## Return codes (observed natively)

| Case | Return |
| --- | --- |
| dispatch event (callback ok) | `0` |
| dispatch, callback error | the callback's code (`0xD`) |
| dispatch, no callback / NULL device | `-4` |
| poll, notify + restart ok | `0` |
| poll, notify idle (returns 0) | `0` |
| poll, timer start fails | `-14` |

## Reproduction

```sh
python3 -m analysis_scripts.main_touch_dispatch --vectors-output firmware/main-touch-dispatch-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-touch-dispatch-vectors.json firmware/main-touch-dispatch-validation.json
python3 -m analysis_scripts.main_touch_dispatch firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-touch-dispatch-vectors.json \
  --validation firmware/main-touch-dispatch-validation.json > analysis/main-touch-dispatch.json
python3 -m unittest tests.test_main_touch_dispatch -q
```

## Remaining

- The input-task body (entry `0x701eca9c`): the TP firmware-upgrade / ODR worker
  that this dispatcher reports progress for — a large routine with chunked
  flash programming and a verify loop, still to be executed as its own block.
