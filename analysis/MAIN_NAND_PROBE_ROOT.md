# Original main probe joined to root publication and NAND consumers

The later [main bus/probe scope](MAIN_NAND_BUS_PROBE.md) adds actual platform,
bus conversion and feature builders. The earlier evidence below preserves its
supplied bus/feature boundary and regression vectors.

All **10 native cases** pass in **8,732 instruction/service steps** (maximum
**2,003**, three-round no-match initialization). The [original main candidate
probe, matcher and ID/reset builders](MAIN_NAND_PROBE.md) now join actual main
root/wrapper, registry insertion, cache/PM publication and subsequent generic
open/NAND geometry/close consumers.
[main-nand-probe-root.json](main-nand-probe-root.json) records **22 code/export
and 38 data hashes**, complete observations and limitations.

This extends [the preceding root scope](MAIN_NAND_ROOT_STACK.md), whose probe
remains supplied in its preserved regression vectors. Here candidate selection
and probe control flow execute; bus callbacks, regulator/feature services,
workaround/UID/BBT bodies, BSP/heap/RTOS/library/PM services and BBT magic remain
authored. No main physical initialization, actual UID or BBT recovery is claimed.

## Success and subsequent original consumers

The actual chain is property publication, probe/regulator/candidate search,
reset/feature/BBT call and guard publication, driver mutex creation, object
allocation, actual registry lookup/insertion, cache publication and PM binding.
Existing driver/registry mutexes skip creation while actual probing still runs.

After successful initialization, explicit authored callers open, query and close
the allocated original-method object. They are subsequent harness operations;
the initializer itself does not invoke these consumers. The real lower/context/
chip/BBT-active query path supplies geometry from the descriptor selected by ID.
First candidate yields 128 MiB from 2-KiB pages; candidate 3 yields 512 MiB from
4-KiB pages. These are software descriptor values, without physical identity
corroboration. Closing brings the reference count to zero while registry/cache
publication remains.

An authored BBT result of 1 with zero magic still permits successful probe,
registration and geometry. Actual BBT-active query returns zero and marks the
geometry inactive. Successful root publication therefore does not imply an
active or recovered BBT.

## Failures preserve different initialization stages

| Case | State at original return or stopped assertion |
| --- | --- |
| Three rounds without ID match | Outer `-6`, selected pointer/guard counters/cache zero, no allocation or driver mutex creation |
| Feature mismatch | Outer `-6`, selected original pointer retained, guard counters zero, no allocation/cache |
| Allocation failure after successful probe | Outer `-6`, selected pointer, driver mutex and probe guard counters retained; no live allocation/cache |
| Same-name/type seed in registry | Actual `-11`, successful probe retained; new allocation remains live and unlinked, no cache/PM call |
| Missing PM property | Assertion owner `0x70a30c60`, line 31, after successful probe, allocation, registry and cache publication |

Append to a differently named seed follows real registry links: head is
preserved, predecessor +52 points to the new object and new object +56 points
to the predecessor's link cell. Duplicate rejection retains the allocation at
return; later removal/reclamation is outside this execution. Assertions are
observed at their call sites, without executing assertion/recovery bodies.

## Reproduction and remaining boundary

Generate vectors and run the same project/script sequence as
[MAIN_NAND_PROBE.md](MAIN_NAND_PROBE.md), using `--scope root`, filenames
`firmware/main-nand-probe-root-vectors.json` and
`firmware/main-nand-probe-root-validation.json`, and export addresses from
`ranges('root')` in `analysis_scripts.main_nand_probe`.

```sh
python3 analysis_scripts/main_nand_probe.py --scope root \
  --vectors-output firmware/main-nand-probe-root-vectors.json
python3 analysis_scripts/main_nand_probe.py firmware/bip6-4.6.0.3.zip \
  --scope root --decompiled firmware/decompiled/runtime-main-nand-probe-root \
  --vectors firmware/main-nand-probe-root-vectors.json \
  --validation firmware/main-nand-probe-root-validation.json
```

Both new evidence files and the original main inventory reproduce. All **66
preceding main native cases reproduce byte for byte** after the shared-runner
extension and overridable probe model refactor. The two new scopes add **24
host checks**, bringing the suite to **1,668 tests**. Original guard/log values
are preserved, with new probe guards/tags added.

Actual main FIFO/DMA, feature/UID/workaround/BBT bodies, real peripheral/heap/PM
operation, initial BBT creation, broader startup/storage callers and
removal/reclamation/concurrency remain open. Physical backup/restoration,
signed-chain enforcement and standalone boot still require separate evidence.
