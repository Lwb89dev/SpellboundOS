# Optical SPI bus ownership, chip selection and completion

This follows [SPI configuration and timing](OPTICAL_SPI_AND_TIMING.md) through
bus acquisition, chip-select adapters, generic DMA completion and the selected
resource-reference callbacks. Evidence is OTA 4.6.0.3 sensor code and bounded
host execution. No actual lock contention, GPIO transition or DMA operation
was observed on the watch.

## Initial operation tables and selected binding

The complete initial bus table at `0x80f1589c` has nine words. Its first five
entries are the previously recovered initialize/deinitialize/TX/RX/TXRX
adapters. All four remaining slots are **zero**:

| Offset | Generic public wrapper's use | Initial optical entry |
| --- | --- | --- |
| `+0x14` | DMA transmit | 0 |
| `+0x18` | Unclassified adjacent slot; no consumer recovered here | 0 |
| `+0x1c` | DMA full duplex | 0 |
| `+0x20` | DMA completion-callback registration | 0 |

The probe's configuration selects polling. This closes the DMA question for
the reviewed initial optical binding: it supplies no DMA implementation.
It does not establish whether runtime tables change or other buses implement
DMA. Generic DMA behavior below is exercised with synthetic nonzero callbacks.

The five-word device table at `0x80f15888` is separate:

| Offset | Adapter | Selected behavior |
| --- | --- | --- |
| `+0x00` | `0x80f7b2c0` | save the private bus context at device-private `+8` |
| `+0x04` | `0x80f7b404` | select using GPIO helper argument 0 |
| `+0x08` | `0x80f7b3e8` | deselect using GPIO helper argument 1 |
| `+0x0c` | `0x80f7b328` | increment the selected reference count |
| `+0x10` | `0x80f7b2d4` | decrement it if nonzero |

## Bus lifetime and discarded outcomes

For the reviewed public transmit (`0x80f897bc`) and full-duplex
(`0x80f898ae`) wrappers, the successful polling path is:

```text
mutex take -> device select -> bus operation -> device deselect -> mutex release
```

Acquisition helper `0x80f8965c` requests the bus mutex with wait word
`0xffffffff`, then invokes the device's select callback. It discards the
mutex wrapper's returned status. Thus, **if that call returns an error**, the
following select/operation path can still execute. This does not demonstrate
that a particular real mutex error is reachable or that diagnostics return
under every execution context.

A nonzero select result maps to `-14`; the public wrapper still invokes its
release helper. A nonzero operation result also maps to `-14` after release.
Release helper `0x80f896d8` invokes deselect, then releases the mutex even if
deselect reports an error. Its own result follows the device callback; the
mutex release result is discarded. The polling transfer wrapper discards the
release helper's result, so its operation-success result can remain zero.

If the operation table or selected operation pointer is absent, the wrapper
returns zero before taking the bus. With absent device select/release callbacks,
the mutex path still executes around the operation. The bounded host model
excludes malformed pointers, scheduler/context failures and concurrency.

## Deferred completion contract

In the generic DMA-success branch, the public wrapper returns zero while
leaving release for completion callback `0x80f89756`. A synchronous nonzero
DMA-operation return instead releases immediately and maps to `-14`.

The completion callback receives an event/result word plus the device handle.
For a valid device, it checks the **current** byte at handle `+0x14`. When
nonzero, it releases the bus; afterward it invokes the optional user callback
at `+0x5c` with the original event and user argument from `+0x60`. Release
errors do not change its zero return.

This callback body has no pending-transfer latch or completion-consumed flag.
In bounded execution, calling it twice repeats release/user notification.
Clearing the DMA flag before completion skips release while still notifying
the user. These facts describe the callback's contract, not a demonstrated
device bug: caller-side serialization, flag immutability, cancellation and
device lifetime rules remain to be established. The tests do not execute a
hardware DMA engine or prove an interrupt-to-callback route.

## Chip-select stores and reference callbacks

The logical optical chip-select record contains bank `0x91003000`, mask
`0x200`. The actual adapters call helper `0x80f7bdbc`, producing:

```text
select:   *(u32 *)(bank + 0x14) = mask
deselect: *(u32 *)(bank + 0x10) = mask
```

These are distinct full-word stores. Register names, electrical polarity and
physical pin mapping are not inferred solely from the offsets. Host execution
checks the complete values and that the other supplied register remains intact.

The enable/disable adapters use the private bus context's 16-bit field `+0x4c`
under native critical-section helper calls. Enable increments modulo 65536;
when the resulting count is nonzero it invokes optional callback `+0x50`.
This includes the 1-to-2 transition; it is not limited to the first enable.
An increment from 65535 wraps to zero and skips that callback.

Disable decrements only when the count is nonzero. Whenever the resulting
count is zero, it invokes optional callback `+0x54`, including a call that
started at zero. Actual resource power state, allowed nesting limits and who
installs those callbacks remain unresolved. Critical-section helper effects
and callback returns are supplied synthetically in the native tests.

## Validation and reproduction

[SeedSpiOwnership.java](../analysis_scripts/SeedSpiOwnership.java) guards the
complete initial bus table, marks the selected GPIO window volatile, and assigns
reviewed argument widths. Seventeen exports are retained in ignored
`firmware/decompiled/runtime-spi-ownership/`.

[ValidateSpiOwnership.java](../analysis_scripts/ValidateSpiOwnership.java)
executes **48 native invocations**: 26 public transfer cases, eight completion
calls, two actual chip-select adapter calls and 12 reference-count cases.
It checks call ordering, arguments, error results, GPIO words, reference
conditions, stack restoration and callee-saved registers. Mutex, diagnostic,
transfer-operation, critical-section and resource/user callbacks use synthetic
outcomes; this pass does not execute SPI polling. The separate
[integrated polling pass](SPI_REGISTER_NATIVE_EXECUTION.md) does.

On the established sensor project, run `SeedSpiOwnership.java`, then export
`spi_ownership.py:TARGETS` using `DecompileWithLogger.java`, logger `0x80f86d34`.
Run native validation with:

```text
-postScript ValidateSpiOwnership.java firmware/spi-ownership-validation.json
-postScript ValidateSpiPolling.java firmware/spi-polling-validation.json
```

```sh
python3 analysis_scripts/spi_ownership.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-spi-ownership \
  --validation firmware/spi-ownership-validation.json \
  --polling firmware/spi-polling-validation.json > analysis/spi-ownership.json
python3 -m unittest discover -s tests -p 'test_spi_ownership.py' -v
```

[spi-ownership.json](spi-ownership.json) fingerprints the image, native ranges,
operation tables, exports and private validation reports. Fifteen host tests
cover the recovered ownership, completion, reference and register-buffer
contracts. No firmware, phone setting or device register was changed.
