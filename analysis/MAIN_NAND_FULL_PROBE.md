# Main probe and root through original platform and QSPI FIFO

All **15 native root/consumer cases** pass in **98,379 instruction/service
steps** (maximum **11,401**, original candidate 10). Original main root/wrapper,
candidate probe/matcher, ID/reset/feature builders, platform/clock/QSPI FIFO,
revision policy and DMA initialization now execute together, followed by actual
registry/cache/PM publication and explicit open/geometry/close callers.
[main-nand-full-probe.json](main-nand-full-probe.json) records **43 code/export
and 40 data hashes**, complete observations and limitations.

Power, pin/GPIO, workaround/UID/BBT, BSP/RTOS/heap/library/PM bodies remain
supplied. Reset/status/ticks, FIFO IDs/features and ROM string are authored.
The scope name identifies the joined probe/root transport path; it does not
establish actual UID acquisition, BBT recovery, physical chip identity or a
complete hardware driver. These short forced packets use direct FIFO; actual
DMA setup/wait is covered separately in [MAIN_QSPI_DMA.md](MAIN_QSPI_DMA.md).

## All eleven unchanged descriptors through actual FIFO

Every candidate is selected in its own case using the original table and
descriptor addresses. No descriptor is cloned or patched here. Each rejected
candidate also runs real platform initialization before another ID request,
including the original clock word and its resulting selector transitions.

Platform initialization populates the original adjacent TX/RX records at
`0x80c10df4`/`0x80c10db0`, executes the real main DMA initializer, publishes
registry slots 26/27 and reciprocal controller pointers. Startup zero facts and
68-byte observed-record guards are retained from
[MAIN_NAND_PLATFORM.md](MAIN_NAND_PLATFORM.md). IRQ delivery/cache coherency and
complete production object extents remain unverified.

Actual ID packets produce four-byte-plus-byte FIFO reads from the authored
five-byte response. Reset reaches the actual command/completion path. Original
feature sequences use real one-byte FIFO writes and readbacks. Captured counts
and FIFO bytes agree for all eleven candidates; supplied HAL result callbacks
no longer substitute for these transfers.

## Publication and subsequent consumers

On success, original probe publishes its one-MiB guard counts, then wrapper/root
creates its driver mutex, allocates the object, executes actual registry lookup/
insertion, publishes cache and binds PM. Explicit harness callers subsequently
open, query geometry and close the object. The initializer does not itself make
those consumer calls.

Geometry follows the actually selected original descriptor for all eleven chips.
The output is software geometry, without fitted-part corroboration. Closing
drops the reference count to zero while registry/cache state remains. Actual
append links, duplicate rejection and late PM-property assertion execute with
their prior distinct state boundaries.

An authored BBT result of 1 with zero magic still permits registration and
inactive geometry. Duplicate registration retains a live unlinked allocation
but skips cache/PM. Missing PM property asserts at owner `0x70a30c60`, line 31,
after publication. Neither registration nor guard counts establish active BBT,
media validity, later reclamation or physical protection.

## Reproduction and bounds

```sh
python3 analysis_scripts/main_nand_full_probe.py --scope root \
  --vectors-output firmware/main-nand-full-probe-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript ValidateMainNandFullProbe.java \
  firmware/main-nand-full-probe-vectors.json firmware/main-nand-full-probe-validation.json

python3 analysis_scripts/main_nand_full_probe.py firmware/bip6-4.6.0.3.zip \
  --scope root --decompiled firmware/decompiled/runtime-main-nand-full-probe \
  --vectors firmware/main-nand-full-probe-vectors.json \
  --validation firmware/main-nand-full-probe-validation.json
```

Use the preceding startup-aware main project and metadata seeds. Export
addresses in `ranges()` from `analysis_scripts.main_nand_full_probe` using
`DecompileWithLogger.java`, logger `0x702b38a2`. Both full-probe scopes use a
**30,000-step fixture limit**, needed for repeated real platform/FIFO execution;
the original main-object runner's default remains 10,000. Instruction/service
steps and authored ticks are separate from measured elapsed time.

The full runner inherits actual root/object behavior through emulator/bound
hooks. Code/data hashes, immutable original tables/descriptors/literals, return
ABI, buffers, adjacent-record/flag/registry guards and private-field preservation
are checked. Firmware/exports stay local. The [retry/failure scope](MAIN_NAND_FULL_PROBE_FAULTS.md)
extends this chain to all 33 attempts and transport/caller failures.
