# Main/sensor timer comparators and suspension arithmetic

This pass follows [timer division](TIMER_ARITHMETIC.md) into the periodic
timer and low-power paths of both OTA 4.6.0.3 images. The same numeric address
does not establish that two processor views share one physical counter.
Physical frequency and elapsed-time accuracy remain unmeasured.

## Periodic setup and interrupt prefixes

| Contract | Main | Sensor hub |
| --- | --- | --- |
| Setup entry | `0x80d37e14` | `0x80f80e42` |
| Periodic handler | `0x80d37f42` | `0x80f80f7c` |
| Compiled raw interval | 1000 | 33 (`0x21`) |
| Saved next compare | `0x80c07de8` | `0x80f17168` |
| Initial callback table base | `0x80c009f4` | `0x80f15914` |
| Table entry 7 | main handler pointer | sensor handler pointer |

Both read counter high/low/high at `0xe6000004`/`0xe6000000`, retrying a
changed high word. Setup writes `raw + interval` to compare low/high at
`0xe6000008`/`0xe600000c` and saves `raw + 2*interval` as the next compare.
These additions include carry and wrap to 64 bits. Native dispatchers
`0x80d35b10` and `0x80fd3d18` index their startup-copied tables with a **16-byte
record stride**, load the callback at `+0`, its argument at `+4`, and tail-jump
to it. Within the reviewed first 16 cause records, entries 3, 7 and 11 have
nonzero callbacks. Entry 7 points to the respective timer handler. Record
words `+8`/`+12` remain unclassified in this dispatch path. This is initial
data and instruction evidence, not observation of a live interrupt.

In the periodic handler, before the scheduler/tick call:

1. Clear bit 7 of CSR `mie` (`0x304`).
2. Write compare low zero, saved compare high, then saved compare low.
3. Advance the saved compare by the compiled interval, with carry.
4. Set bit 7 of `mie`.

The last operation sets the bit even if it was initially clear; this is not
a generic save-and-restore primitive. The next compare comes from saved
state, rather than a fresh current-time read. The register sequence alone
does not establish atomic bus behavior, missed-interrupt handling or a
guaranteed deadline. Separate source-14/source-15 callback registrations
in setup should not be confused with table entry 7.

`SeedRtosTimer.java` guards exact setup bytes, preserves CSR volatility and
restores selected wide-return reader signatures. It seeds returning debug,
registration and scheduler function boundaries to prevent Ghidra from
absorbing their bodies into callers. Initial exports that reduced most of
the sleep path to unreachable blocks are retained separately. The corrected
main sleep export has 170 lines and sensor export 179; these counts describe
the recovered output, not semantic completeness. Wide-register/type artifacts
remain in selected sleep expressions, so the formulas below were checked
against runtime-address instructions.

## A second counter bank and read consistency

Main reader `0x702a2bb0` and sensor reader `0x80f7e7b4` are byte-identical
30-byte routines. They read low/high/low/high at `0x910012f8`/`0x910012fc`,
requiring both complete pairs to agree. This differs from the high/low/high
timer reader. `SeedRtosTimer.java` adds the volatile `0x91001000` window;
without it and the wide signature, the sensor export incorrectly appeared
to do nothing. No counter value or hardware frequency was measured.

The bounded host `stable_aon` model permits 128 attempts. Native code has no
such attempt bound. Its host emulation uses a memory-read filter to supply
a stable sample, a low-word rollover and a changed high word; it verifies
read order, retry consumption and the resulting register pair.

## Suspension conversion and counter discontinuity

Main `0x80d37fce` and sensor `0x80f81008` suppress short-idle handling when
the requested count is at most 3. Selected deeper-idle branches subtract a
margin of 1 or 3 and calculate the alarm argument with **32-bit** arithmetic:

```text
alarm = (((expected_idle - margin) << 15) mod 2^32) / 1000
```

The shift precedes the unsigned divide. For example, `expected_idle=131073`,
margin 1 wraps the shifted value to zero. The host model preserves that
behavior instead of silently widening the multiplication. Which margin is
selected depends on the processor's reviewed sleep-state branch; the model
takes it explicitly and does not choose a power mode for a device.
Overflow examples describe the instruction arithmetic; reachability under
the caller's permitted idle limits remains unverified.

The elapsed-counter conversion on the selected resume branch is:

```text
tick_estimate = (((elapsed_counter * 1000) mod 2^64) >> 15) mod 2^32
```

The constants are consistent with an intended 32768-based low-power time
domain and a 1000-based RTOS time domain. That is an inference from compiled
conversions, not a measurement or a complete oscillator/divider specification.
The periodic raw intervals differ between the two images; a single physical
frequency must not be assigned to both from their shared numeric MMIO base.

The main resume path converts the estimate into increments of 1000 raw timer
counts; the sensor path uses increments of 33. The selected paths write the
counter itself at `0xe6000000`/`0xe6000004` as well as its compare registers.
Therefore software can rebase the raw counter around suspension. The earlier
scaled-reader predicate remains its numeric arithmetic; continuity across
power transitions and monotonicity require further evidence. The complete
sleep state machine, remainder helper semantics, floating-point residual
handling, wake latency and scheduler catch-up are not claimed fully emulated.

## Host validation and reproduction

[ValidateRtosTimer.java](../analysis_scripts/ValidateRtosTimer.java) executes
guarded setup and handler prefixes under corrected SLEIGH. For each processor,
13 setup cases and 26 handler cases verify compare-store order, carry/wrap,
saved-state advancement and the final `mie` value. Three additional cases
verify the second counter's stable/retry path; three dispatcher cases verify
the loaded callback and argument for initial causes 3/7/11. All **90 native cases** pass.
Each invocation is bounded to 512 instructions and stops before the setup's
registration call or handler's scheduler call. The AON reader returns normally
to a synthetic sink. No interrupt or register was accessed on hardware.

Private exports are in `runtime-rtos-timer-main-fixed` and
`runtime-rtos-timer-sensor-fixed` under ignored `firmware/decompiled/`.
The earlier directories without `-fixed` retain the comparison baseline.
Public [rtos-timer.json](rtos-timer.json) records 20 selected export hashes,
guarded byte ranges, startup callback entries, synthetic examples and the
private execution report hashes.

Using the established Ghidra headless environment and main/sensor projects:

```text
main:   -preScript SeedRtosTimer.java
sensor: -preScript SeedRtosTimer.java sensor
```

Export the `TARGETS` from `rtos_timer.py` using `DecompileWithAbi.java` for
main and `DecompileWithLogger.java` with logger `0x80f86d34` for sensor.
Run the validation separately for each project:

```text
-postScript ValidateRtosTimer.java main firmware/rtos-timer-main-validation.json
-postScript ValidateRtosTimer.java sensor firmware/rtos-timer-sensor-validation.json
```

```sh
python3 analysis_scripts/rtos_timer.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled --validations firmware > analysis/rtos-timer.json
python3 -m unittest discover -s tests -p 'test_rtos_timer.py' -v
```

Eleven host tests cover the two domains, callback record stride, carries/wrap, exact store ordering,
interrupt-bit policy, complete-pair retry, bounds and the fixed-width
suspension conversions. Firmware, exported vendor code and databases stay
ignored. No phone/watch setting or firmware was changed.
