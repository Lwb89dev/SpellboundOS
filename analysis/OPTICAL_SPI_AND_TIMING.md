# Optical SPI backend, polling completion and delay contracts

This continues [optical board reconstruction](PPG_AND_SENSOR_MEMORY.md) and
[FIFO framing](PPG_FIFO_AND_IPC.md) using corrected sensor-hub decompilation
and runtime-address instructions from OTA 4.6.0.3. It recovers additional
hardware-facing contracts without issuing SPI transfers on a device.

## Board binding and selected operations

Registration `0x80f624ac` binds `sens_spi0_dev0` to `sens_spi0` using the
initial chip-select record at `0x80f1533c`. Its bank address is `0x91003000`,
mask `0x200`. The bus record at `0x80f15348` names `sens_spi0` and gives
controller base `0x90004000`. The separate motion bus record at `0x80f152e4`
gives `0x90005000`. These are software bindings and register/mask values,
not a measured pinout or electrical chip-select waveform.

The bus operation table at `0x80f1589c` contains:

| Offset | Adapter | Lower implementation |
| --- | --- | --- |
| `+0x00` | `0x80f7b36c`, initialize | `0x80f7eb60` |
| `+0x04` | `0x80f7b2b8`, returns zero | no lower call in the reviewed body |
| `+0x08` | `0x80f7b3d0`, transmit | `0x80f7ee38` |
| `+0x0c` | `0x80f7b3b8`, receive | `0x80f7eecc` |
| `+0x10` | `0x80f7b3a0`, full duplex | `0x80f7ed84` |

The data adapters add 8 to their context pointer, forward the remaining
arguments and convert zero/nonzero HAL status into 0/2. Correct explicit
four-/five-argument signatures are necessary: earlier exports displayed
only the context argument and hid buffers, counts and timeout.

## Configuration word and controller programming

The optical probe requests frequency field 8,000,000, flags `0x801` and a
zero DMA-selection byte in its 20-byte public configuration. The adapter
copies the frequency into the lower context, forces its width field to 8,
and writes a mode byte equal to zero when `(flags & 6) == 0`, otherwise 3.
Thus the selected path maps `0x801` to low control bits zero. It does not
implement a four-way mapping of bits 1/2 or preserve other flag fields.
Electrical CPOL/CPHA labels remain unverified.

The lower initializer programs, relative to the controller base:

```text
control[+0x00] = (extra_mode_byte ? 0x1004 : 0x100c) | mode_byte
enable[+0x08] |= 0x18d
configuration[+0x04] = (old_configuration & 0xff800000)
                         | ((width_field - 1) << 16) | divider
```

For nonzero requested frequency, `ratio = nominal_source / requested`;
when ratio exceeds one, `divider = (ratio >> 1) - 1`, otherwise it remains
the ratio. Zero requested frequency omits the divider calculation. For a
synthetic 48 MHz source, 8 MHz request, zero extra mode and old word zero,
the resulting control is `0x100c` and configuration `0x00070002`.
These are calculated register words, not measured SPI speed.

For `sens_spi0`, the initializer enables clock-gate bit 2 at `0x90008008`
under the `0x900080b0` lock sequence, then selects its source from bits
12–13 of `0x90008000`. `sens_spi1` uses gate bit 3 and selection bits 14–15.
Modes 0/1 use compiled 48,000,000 constants; mode 2 uses the PLL formula
from `0x9100021c`, mode 3 from `0x91000214`. The sensor PLL helpers match
the arithmetic recovered in [clock/cache contracts](CLOCK_AND_CACHE_CONTRACTS.md).
Lock acquisition, clock state and actual peripheral timing were not observed.

The adapter discards the lower initializer's status and returns zero.
The optical probe also discards the public SPI initializer's return value.
These observations do not establish successful configuration on hardware.

## Polling status, timeout and error propagation

The selected full-duplex HAL polls controller status at `+0x0c`, reading
the word separately for its tests. Bit `0x4` gates the data-moving branch,
bit `0x2` permits one transmit byte, and mask `0x3f0` permits one receive
byte. Data-register accesses use 32-bit operations at `+0x18`, carrying the
low eight buffer bits. The host model takes separate supplied
status words and does not collapse the reads into one atomic snapshot.

Both full-duplex counts start at the requested length. A zero remaining
count is tested at the **start** of each loop. After any data movement,
the HAL reads the scaled timer and continues only while the unsigned
64-bit difference is **at most** the supplied timeout. Therefore timeout
is `delta > timeout`, unlike the IPC predicate `delta >= 1000`.

If the final bytes move on an iteration whose time check expires, the HAL
still returns status 3. Completion is recognized at the next loop entry
only if the time check allowed another iteration. A timeout therefore does
not establish that no bytes moved, or even that bytes remain. The transmit
path follows the same post-movement timeout order; the receive path writes
dummy zero bytes to generate input transfers.

The data adapter maps HAL timeout 3 to status 2; the public transfer wrapper
maps a nonzero adapter result to `-14`. Its other selected returns are `-10`
for a null handle and `-6` for an unmounted bus. Missing operation tables or
callbacks can return zero without a transfer. A zero wrapper return alone
must not be used as evidence of actual bus movement. DMA operation lifetimes,
release ordering and interrupt completion remain outside this model.

## Probe delays

The probe invokes two distinct timing paths:

- `0x80f63360(7)` multiplies the argument by 1000 in RV32 and reaches the
  CPU-cycle busy wait. Its target is based on the nominal CPU rate divided
  by 1,000,000, with 32-bit product wrap. This is consistent with an intended
  seven-millisecond active delay, not a measured duration.
- The failed-attempt path calls `0x80f7ff0e(10)`, a CMSIS-style scheduler
  wrapper. Its selected fast conversion multiplies/divides by 1000, leaving
  10 unchanged before the RTOS delay call. Large finite inputs enter a
  diagnostic/assertion helper whose returning path clamps to `0x418937`;
  `0xffffffff` is passed through. Interrupt/context guards remain part of
  the native path and are not simulated by the arithmetic model.

The [RTOS timer pass](RTOS_TIMER_AND_SUSPEND.md) establishes the compiled
periodic intervals and suspend conversions. It does not justify treating
these distinct delays, IPC waits and SPI timeouts as one measured clock.

## Validation and reproduction

[SeedOpticalSpi.java](../analysis_scripts/SeedOpticalSpi.java) guards the
52-byte adapter body, marks selected SPI/clock windows volatile and assigns
reviewed argument widths. Nineteen corrected exports are retained in ignored
`firmware/decompiled/runtime-optical-spi-fixed/`. The two earlier optical
export directories retain the comparison baseline.

[ValidateOpticalSpi.java](../analysis_scripts/ValidateOpticalSpi.java) executes
11 adapter configuration cases and 12 forwarding/return cases against the
actual guarded instructions under corrected SLEIGH. It checks the field
writes, context offset, buffer/count/timeout register forwarding, status
conversion and stack restoration. HAL calls are stopped and their return
values supplied synthetically; no hardware polling or SPI transfer is
executed by these 23 cases.

On the existing corrected sensor project, run `SeedOpticalSpi.java`, then
`DecompileWithLogger.java` using logger `0x80f86d34` and the addresses in
`optical_spi.py:TARGETS`. Separately run:

```text
-postScript ValidateOpticalSpi.java firmware/optical-spi-validation.json
```

```sh
python3 analysis_scripts/optical_spi.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-optical-spi-fixed \
  --validation firmware/optical-spi-validation.json > analysis/optical-spi.json
python3 -m unittest discover -s tests -p 'test_optical_spi.py' -v
```

[optical-spi.json](optical-spi.json) records image/table/instruction/export
hashes, bindings, selected contracts and the private execution-report hash.
Nine host tests cover source selection, flag collapse, divider truncation,
register masks, separate status inputs, strict timeout/completion order,
error conversion and delay bounds. This provides more driver contracts;
physical mode, exact optical silicon and working standalone support remain
unverified. No phone/watch setting or firmware was changed.
