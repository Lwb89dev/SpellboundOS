# Main NAND bus and feature builders through actual QSPI HAL/FIFO

The later [main QSPI/DMA scope](MAIN_QSPI_DMA.md) executes actual DMA backend
init/setup/wait. This earlier evidence preserves its supplied DMA boundary.

All **24 native cases** pass in **14,877 instruction/service steps** (maximum
**1,846**, unaligned receive). Actual main bus transfer `0x70296c24`, original
feature-read/write builders and revision policy now join original main QSPI
command, direct FIFO and DMA-wrapper bodies.
[main-qspi-bus.json](main-qspi-bus.json) records **18 code/export and four data
hashes**, complete observations and limitations.

The controller is an explicitly authored initialized fixture. This scope does
not execute platform/probe/root initialization; the preceding
[bus/probe/root scope](MAIN_NAND_BUS_PROBE.md) preserves its supplied HAL boundary.
The original bus binding and first selected descriptor remain immutable. Reset/
ready/completion/FIFO/ROM inputs and DMA setup/wait/copy/diagnostic services remain
supplied. No physical flash, ROM revision, media operation or DMA completion is
established.

## Direct transfers, actual revision and bounce path

Original bus conversion creates the stack HAL frame and reaches actual command
register writes. Direct receive/transmit consumes the count through real FIFO
loops, including an unaligned 64-byte receive using byte accesses throughout.
Actual feature builders submit one-byte addressed operations through the same
path; write input `0x1a5` becomes FIFO byte `0xa5`.

Revision policy executes on every transfer against an authored ROM string.
Force-zero packets over 31 bytes use the bounce/DMA-wrapper path with exact
`v1.1.16`; 31-byte packets and old/unknown versions use direct FIFO. Successful
bounce receive copies after wrapper completion; bounce transmit copies before
command submission. DMA setup/wait remain supplied, and the successful wrapper
retains count +20 while direct FIFO reduces it to zero.

## Real HAL failures and retained data

| Selected failure | Original bus assertion |
| --- | --- |
| Empty command completion timeout | Owner `0x70a1bc8c`, line 294 |
| Direct receive readiness/completion timeout | Owner `0x70a1bc8c`, line 305 |
| Direct transmit readiness/completion timeout | Owner `0x70a1bc8c`, line 313 |
| Supplied bounce/DMA receive wait `-9` | Owner `0x70a1bca8`, line 374 |
| Supplied bounce/DMA transmit wait `-9` | Owner `0x70a1bca8`, line 386 |

Unlike the preceding supplied-HAL scope, direct timeout status 3 is produced by
actual HAL timer/status loops before the original bus logs, calls the supplied
diagnostic and asserts. Feature timeout also stops inside bus transport; helper
assertion bodies and recovery do not run. Stopped assertions claim no return ABI.

A selected DMA setup return `-9` with subsequent supplied wait success still
permits wrapper/bus success. Without an authored receive copy, bounce memory
retains its initial `0xa5` bytes and actual bus copies those unchanged bytes to
the caller. This establishes a caller/status dependency; it does not establish
that hardware would leave precisely that content after a real setup failure.

Conversely, supplied receive setup may fill bounce memory before wait returns
`-9`. Actual bus skips copyback and caller bytes remain unchanged while bounce
bytes retain the supplied payload. The request bit is cleared before the bus
assertion. Software count/status and buffer snapshots therefore do not by
themselves establish successful media or DMA operation.

## Reproduction, regression and continuation

```sh
python3 analysis_scripts/main_qspi_bus.py \
  --vectors-output firmware/main-qspi-bus-vectors.json
```

Use the seeded startup-aware project and headless environment from
[MAIN_QSPI_HAL.md](MAIN_QSPI_HAL.md), substituting the post-script arguments:

```text
-postScript ValidateMainQspiBus.java \
firmware/main-qspi-bus-vectors.json firmware/main-qspi-bus-validation.json
```

```sh
python3 analysis_scripts/main_qspi_bus.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-qspi-bus \
  --vectors firmware/main-qspi-bus-vectors.json \
  --validation firmware/main-qspi-bus-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_qspi_bus`, with
`DecompileWithLogger.java` and logger `0x702b38a2`. The new main HAL runner has
narrow hooks for this connected scope; older main/boot runners are unchanged.
Both new evidence files and vector sets reproduce. All **160 preceding main
native cases reproduce byte for byte** after the metadata additions. The two
scopes add **28 host checks** to the passing **1,722-test suite**.

Next work is actual main DMA initialization/setup/wait and cache services
(`0x702a0038`, `0x702a02a0`, `0x702a0358`), then connecting this HAL to actual
platform/probe/root and main UID/workaround/BBT/media paths. Peripheral timing,
physical pin mapping/coherency, restoration and standalone boot remain open.
