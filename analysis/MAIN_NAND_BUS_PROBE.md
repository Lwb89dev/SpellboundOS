# Actual main probe, bus/platform and feature packets through root consumers

The later [main probe/root FIFO scope](MAIN_NAND_FULL_PROBE.md) executes actual
HAL/FIFO and original DMA initialization in this caller chain. The evidence
below retains its supplied HAL boundary.

The later [main HAL/FIFO scope](MAIN_QSPI_HAL.md) and
[connected bus/feature scope](MAIN_QSPI_BUS.md) execute those lower bodies
separately. This earlier full probe/root scope keeps its supplied HAL boundary.

All **25 native cases** pass in **44,902 instruction/service steps** (maximum
**4,202**, original candidate 9). Actual main probe, matcher, ID/reset/feature
builders and [main bus/platform conversion](MAIN_NAND_BUS.md) now join original
root/wrapper/registry/cache/PM publication and subsequent open/geometry/close.
[main-nand-bus-probe.json](main-nand-bus-probe.json) records **26 code/export
and 38 data hashes**, complete observations and limitations.

This extends [the preceding probe/root scope](MAIN_NAND_PROBE_ROOT.md), which
supplies its bus and feature helpers. Here the original eleven descriptors,
feature sequences and bus binding remain unchanged. HAL command/data services,
revision, emulator MMIO, pin/DMA/clock, power, UID/workaround/BBT and BSP/RTOS/
heap/library/PM bodies remain supplied. This is offline control-flow evidence,
without physical flash identification, real UID/BBT acquisition or media access.

## All eleven original candidates and consumers

Each candidate is selected in a separate case. Every attempted candidate calls
real bus initialization with its original descriptor before ID. Descriptor
clock words are `[104,104,104,104,104,83,104,83,83,83,83]`; actual clock selection
follows each value, including earlier candidates rejected by the matcher.

Original ID and reset packets reach the actual bus converter and supplied HAL.
After matching, real feature builders serialize each original register/value
pair through actual transport, with supplied one-byte readback. These small
forced packets use the direct HAL path. The standalone bus scope separately
exercises bounce selection and copying.

Successful probe publishes the one-MiB guard counts, then root creates its mutex,
allocates and registers the object, publishes its cache and binds PM. Explicit
subsequent harness callers open/query/close it. Geometry follows actual selected
descriptor fields for **all eleven chips**, rather than a supplied geometry
array. Closing reaches reference count zero and retains registry/cache state.
Selected negative initialization-service returns remain ignored in this chain.

An authored BBT result of 1 with zero magic still permits registration, but
original BBT-active query marks geometry inactive. No actual BBT recovery runs.
Duplicate insertion retains the successful probe and live unlinked allocation,
while skipping cache/PM. A missing PM property asserts after registry/cache
publication, retaining probe guards and selection.

## Error propagation with actual transport and feature helpers

| Authored fault | First original stopped site / return |
| --- | --- |
| Bus disabled before ID transfer | ID-helper assertion, owner `0x70a30fa4`, line 383; zero HAL commands |
| ID/reset/feature command HAL error | Transport assertion, owner `0x70a1bc8c`, line 294 |
| ID or feature receive HAL error | Transport assertion, owner `0x70a1bc8c`, line 305 |
| Feature transmit HAL error | Transport assertion, owner `0x70a1bc8c`, line 313 |
| Bus disabled after reset command | Feature-write helper assertion, owner `0x70a31114`, line 74 |
| Bus disabled after first feature-write command | Feature-read helper assertion, owner `0x70a3112c`, line 55; prior write retained |
| Successful feature receive with mismatched value | Actual probe `-7`, then outer wrapper `-6`; selection retained, guard counts zero, no allocation |

The two later disabled-flag transitions are explicitly authored in the supplied
HAL service after selected command calls. They expose caller behavior for that
state; no physical event, asynchronous race or actual flag setter is established.

With actual feature helpers, supplied HAL failures stop at transport assertions;
disabled-bus returns stop at helper assertions. They do not exercise the outer
probe's `-5`/`-6` feature-return branches. The earlier supplied-helper scope
preserves its evidence for those caller branches. Assertion bodies do not run,
and their termination/recovery behavior remains unknown.

## Reproduction and regression

```sh
python3 analysis_scripts/main_nand_bus_probe.py \
  --vectors-output firmware/main-nand-bus-probe-vectors.json
```

Use the same seeded startup-aware project and headless environment as
[MAIN_NAND_BUS.md](MAIN_NAND_BUS.md), then run:

```text
-postScript ValidateMainNandBusProbe.java \
firmware/main-nand-bus-probe-vectors.json firmware/main-nand-bus-probe-validation.json
```

```sh
python3 analysis_scripts/main_nand_bus_probe.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-nand-bus-probe \
  --vectors firmware/main-nand-bus-probe-vectors.json \
  --validation firmware/main-nand-bus-probe-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_bus_probe`,
using `DecompileWithLogger.java` and logger `0x702b38a2`. The connected runner
inherits the existing main-object harness through narrow configuration/service/
snapshot/guard hooks; the parent defaults keep the previous behavior. Original
parent configuration, guard values and log tags remain exactly unchanged.

Both new evidence files reproduce; all **100 preceding main native cases
reproduce byte for byte**. The two scopes add **26 host checks** to the
**1,694-test suite**. Next work is actual main HAL/FIFO/DMA and the revision
body, followed by actual main UID/workaround/BBT and broader media/storage
callers. Physical pin/timing/coherency, safe backup/restoration, signed-chain
enforcement and standalone boot remain separate open requirements.
