# Original main QSPI HAL, FIFO, timer policy and DMA wrappers

All **89 native cases** pass in **8,704 instruction/service steps** (maximum
**410**, command plus transmit). The original main HAL now executes independently
of the boot-image implementation over authored MMIO and timer/DMA services.
[main-qspi-hal.json](main-qspi-hal.json) records **14 code/export and two data
hashes**, complete observations and limitations. The model shares the previously
checked packet/FIFO policy; main-image instructions are executed and guarded
separately, rather than inferred from boot-image coverage.

| Body | Main address |
| --- | --- |
| Packet packing | `0x80d34800` |
| Completion wait | `0x80d348c8` |
| Receive/transmit readiness waits | `0x80d34954` / `0x80d349e8` |
| Transmit/receive FIFO counts | `0x80d34a7c` / `0x80d34aa0` |
| Controller initialization | `0x80d34ac4` |
| Command submission | `0x80d34b30` |
| Direct receive/transmit | `0x80d34c68` / `0x80d34dc0` |
| DMA receive/transmit wrappers | `0x80d34d60` / `0x80d34eb0` |
| Clock selector | `0x80d3580c` |
| Revision policy | `0x80d4556c` |

## Metadata and execution boundary

Earlier automatic Ghidra analysis attached the independent completion entry to
the command function as a second body range. `SeedMainQspiHal.java` assigns the
original contiguous command range and completion entry to their own functions,
sets reviewed argument/return metadata and exports the selected bodies. Imported
instruction bytes and emulator instruction semantics are unchanged. Native
execution follows original shared-tail jumps with normal-return ABI checks.

The standalone controller context, DMA handles, FIFO/status/reset self-clear,
completion W1C, timer/frequency values, ROM string and DMA services are authored.
The memory filter supplies each observed MMIO value; it does not access hardware.
Assertions and bounded non-progress cases do not claim a normal-return ABI.

## Command, FIFO and timing behavior

Controller initialization waits for supplied reset self-clear, conditionally
rewrites flag bits, enables FIFO control bits and selects `0x3300` widths.
Command rejects null context/frame/base with result 1. Original packing builds
the address, command and length registers, handles direction 7 specially and
sets the controller-specific bit for base `0x93240000`. Command stores the count
in context +20. A zero-length command waits for completion immediately.

Actual direct receive/transmit waits for readiness before each chunk. FIFO
counts use the appropriate byte of register +`0x54` and width bits from +`0x20`.
Aligned buffers use four-byte accesses plus byte tails; unaligned buffers use
byte accesses throughout. Cases cover lengths 1, 3, 4, 5, 8 and 9, count
consumption, unchanged buffer tails and command-to-data linkage.

Readiness/completion waits use supplied 64-bit tick reader `0x80d4549c` and
frequency reader `0x80d454b0`. The selected cases establish unsigned elapsed-time
handling, exact-deadline acceptance, low-word/full-counter wrap, high-word
expiration, sub-kHz conversion and 32-bit timeout-limit multiplication wrap.
Completion rechecks status after expiration and acknowledges a ready result by
writing 1 to +`0x24`; remaining timeout returns 3. These are arithmetic/control
contracts, without physical clock calibration or elapsed-time validation.

Four zero-FIFO cases stop after four non-progress chunks, including advancing
timestamps. Each chunk requests another readiness wait: this selected execution
does not establish a single deadline covering the whole transfer. The stopped
prefix retains count and transfers no bytes; it does not prove eventual return.

## DMA wrappers, clock and actual revision policy

The DMA wrappers call supplied setup `0x702a02a0` and wait `0x702a0358`. Selected
setup return `-9` is ignored; wait status is propagated. The request bit is
cleared after waiting even when it was already set on entry. A successful DMA
wrapper leaves the original count field unchanged, unlike the direct FIFO loop.
Supplied copying does not establish actual DMA completion or cache coherency.

Clock selection reads `0x9a000024`, masks a changed selector to four bits and
updates shadow `0x80c11c4c`. The equal-selector branch still refreshes the shadow.
Revision policy now executes its actual body against an authored string at
`0x30000024`, with bounded string comparison supplied. Exact `v1.1.03` maps to 1,
exact `v1.1.16` to 2; other strings, empty input and a suffixed version map to 0.
Original comparison literals at `0x709a84d4`/`0x709a84dc` are hash guarded.
No physical ROM version is observed by these cases.

## Reproduction and next boundary

```sh
python3 analysis_scripts/main_qspi_hal.py \
  --vectors-output firmware/main-qspi-hal-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainQspiHal.java \
  -postScript ValidateMainQspiHal.java \
  firmware/main-qspi-hal-vectors.json firmware/main-qspi-hal-validation.json

python3 analysis_scripts/main_qspi_hal.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-qspi-hal \
  --vectors firmware/main-qspi-hal-vectors.json \
  --validation firmware/main-qspi-hal-validation.json
```

Use the existing startup-aware main project. Export addresses in `RANGES` from
`analysis_scripts.main_qspi_hal` with `DecompileWithLogger.java`, logger
`0x702b38a2`. Firmware/exports stay local. Code/data hashes, return ABI,
controller/frame/ROM/buffer guards and immutable original literals are checked.

The [connected main bus scope](MAIN_QSPI_BUS.md) joins actual bus/feature
conversion and revision to these bodies. Actual main DMA backend/cache services,
full probe/root linkage through this HAL, UID/workaround/BBT, physical operation
and safe restoration/boot remain open.
