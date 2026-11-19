# Original main cache guards through DMA, IRQ and recovered NAND

Four native scopes now separate ordinary-call IRQ policy from actual execution
of the cache entry guards. All **140 new native cases** pass across these scopes:

| Scope | Cases | Instruction/service steps | Maximum per case |
| --- | ---: | ---: | ---: |
| [Main IRQ with supplied cache services](MAIN_DMA_IRQ.md) | 26 | 3,809 | 279 |
| Main backend/IRQ with actual cache guards | 72 | 6,936 | 283 |
| Full recovered main NAND read with actual cache guards | 16 | 524,220 | 33,932 |
| Full recovered main NAND program with actual cache guards | 26 | 851,374 | 34,398 |

The 72-case scope comprises the 26 IRQ cases plus all 46 preceding backend
cases with cache bodies enabled. These are executions under different service
boundaries, not 140 distinct hardware scenarios or a coverage percentage.
Reports are [main-dma-cache-guards.json](main-dma-cache-guards.json),
[main-nand-cache-read.json](main-nand-cache-read.json) and
[main-nand-cache-program.json](main-nand-cache-program.json). They pin respectively
**9**, **74** and **73 code/export hashes**; both NAND scopes also retain all
**68 original data hashes**.

## Actual signed guard, rather than a supplied cache return

Original prepare `0x7029fea0` and finish `0x7029ff04` both test whether the
32-bit address is **signed nonpositive** before saving interrupt state or
accessing cache CSRs. In these scopes the actual native routines execute that
branch and return zero. Selected arguments are:

- Authored backend source/destination at `0x81301000` / `0x81302000`.
- Original NAND private buffer at `0x80d93960`.
- Empty TX/cleared tracking represented by address and size zero.

All are signed nonpositive. The guard returns **before interrupt-state services,
CSR reads/writes or fences**. The earlier
[static/host cache contract](CLOCK_AND_CACHE_CONTRACTS.md) recorded this rule;
the new native scopes verify it inside real DMA setup/wait/cancel/IRQ and full
NAND callers. Positive-address cache-enabled/disabled/CSR-progress branches
remain unexecuted in these scopes.

Each selected cache call takes exactly **two more native instruction steps**
than the previous supplied-return service. Complete actions and state remain
identical. The original cache entry branch, zero-result instruction and return
are executed; a service hook does not substitute the body. Firmware hashes and
PC whitelists guard those paths. Cache calls still appear as boundary events
so prior ordering/state comparisons remain exact.

This establishes a software decision to skip maintenance at selected addresses.
It does not prove physical noncacheability, coherent aliases, correct DMA ordering
or that the device needs no maintenance.

## Connected original RX/TX and recovered BBT

The read scope repeats all 16 cases from
[MAIN_NAND_ASYNC_READ.md](MAIN_NAND_ASYNC_READ.md), and the program scope repeats
all 26 from [MAIN_NAND_MODE_ZERO_PROGRAM.md](MAIN_NAND_MODE_ZERO_PROGRAM.md).
The complete original probe/platform/DMA initialization, UID, BBT marker/read/
CRC/repair and root publication precede application IO as before.

Original RX/TX records remain `0x80c10db0` / `0x80c10df4`, in registry slots 27 /
26. BBT/UID and source data stay unchanged. Every prior action/state observation
matches exactly; read totals add 32 steps and program totals add 56 steps,
accounting for two extra instructions per selected cache call.

Primary RX completion still clears tracking after the skipped finish call;
alternate RX completion still returns zero with retained destination/size and
without finish. Actual cache bodies therefore do not remove that difference.
Primary TX completion still calls finish with `(0, 0)`, and alternate skips it.

Read DMA success still copies authored retained private-buffer bytes because
hardware DMA movement is not modeled. TX still stages source bytes before
prepare/setup, with no fabricated FIFO DMA writes. Original timeout assertions,
post-publication state, guard/column behavior and callback non-invocation remain
as recorded in the preceding reports. Copy, peripheral/status/ticks, pin/power/
RTOS/BSP/heap/PM services remain authored or supplied.

## Reproduction and continuation

After `SeedMainDmaIrq.java`, run the backend guard scope using
`ValidateMainDmaIrq.java` and the same nine exports:

```sh
python3 analysis_scripts/main_dma_irq.py --scope cache-guards \
  --vectors-output firmware/main-dma-cache-guards-vectors.json
```

```text
-postScript ValidateMainDmaIrq.java firmware/main-dma-cache-guards-vectors.json firmware/main-dma-cache-guards-validation.json
```

```sh
python3 analysis_scripts/main_dma_irq.py firmware/bip6-4.6.0.3.zip \
  --scope cache-guards --decompiled firmware/decompiled/runtime-main-dma-irq \
  --vectors firmware/main-dma-cache-guards-vectors.json \
  --validation firmware/main-dma-cache-guards-validation.json

python3 analysis_scripts/main_nand_cache_guards.py --scope read \
  --vectors-output firmware/main-nand-cache-read-vectors.json
python3 analysis_scripts/main_nand_cache_guards.py --scope program \
  --vectors-output firmware/main-nand-cache-program-vectors.json
```

Use the preceding complete NAND seeds and new cache metadata. Run
`ValidateMainNandReadCacheGuards.java` or `ValidateMainNandProgramCacheGuards.java`
with the corresponding vectors and validation paths. Export addresses from
`main_nand_cache_guards.ranges(scope)` with `DecompileWithLogger.java`, logger
`0x702b38a2`, to the matching `runtime-main-nand-cache-read` or
`runtime-main-nand-cache-program` directory. Then generate each report:

```sh
python3 analysis_scripts/main_nand_cache_guards.py firmware/bip6-4.6.0.3.zip \
  --scope read --decompiled firmware/decompiled/runtime-main-nand-cache-read \
  --vectors firmware/main-nand-cache-read-vectors.json \
  --validation firmware/main-nand-cache-read-validation.json
```

Substitute `program` for `read` for the program report. Firmware/exports remain
local. Backend and NAND bounds remain 10,000 and 200,000 steps respectively;
preceding fixed scopes keep their configurations and service boundaries.
All four JSON reports reproduce byte for byte. Thirty new host checks join the
passing **2,080-test suite**, covering native/model equality, original hashes,
callback/registry ordering, fault state and exact per-call instruction differences.

Subsequent [positive-address cache cases](MAIN_CACHE_CSR_RANGES.md) execute CSR
loops over explicit feedback, along with the original
[critical/context/diagnostic bodies](MAIN_RTOS_CRITICAL_SECTIONS.md).
Further work includes device CSR progression/completion, actual
IRQ/vector/controller/scheduling and callback consumers,
broader media/PM/partition integration and concurrency. Physical DMA/cache/
coherency/timing, persistent repair/atomicity, device backup/restoration and
standalone signed-chain boot remain unresolved.
