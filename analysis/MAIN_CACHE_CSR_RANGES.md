# Original main cache commands and positive-address CSR loops

All **43 native cases** pass in **6,039 instruction/service steps** (maximum
**330**, successive prepare/finish). The original four cache routines now execute
their positive-address control/command/readback branches, along with actual
context/save/restore, critical-section and diagnostic bodies. There are no
supplied function returns in this scope. Hardware CSR inputs/progress remain
authored, and the three fixed `fence` instructions are supplied as recorded
no-ops because Ghidra does not implement that userop.
[main-cache-range.json](main-cache-range.json) pins **ten code/export hashes**,
complete native observations and limitations.

The preceding [DMA/NAND guard scope](MAIN_DMA_CACHE_GUARDS.md) executed only
signed-nonpositive entry paths. This scope verifies the positive paths separately;
it does not establish a positive-address production DMA consumer or physical
cache/coherency behavior.

## Commands and control gate

| Original routine | Address | Command to CSR `0x7cc` | Gate / completion test |
| --- | --- | ---: | --- |
| Prepare range | `0x7029fea0` | 1 | Positive start, control bit 1; address readback compared to end |
| Finish range | `0x7029ff04` | 2 | Same |
| Invalidate range | `0x7029ff68` | 0 | Same |
| Whole-cache operation | `0x7029fe74` | 6 | Unconditional command after entering wrapper; no address readback loop |

The operation names retain the earlier
[clock/cache contract](CLOCK_AND_CACHE_CONTRACTS.md). Command values and access
order are original-code observations; actual hardware completion/status meanings
and ordering are not measured.

The three range routines return zero immediately for zero or high-half addresses
because the entry comparison is signed. For positive addresses, they enter the
actual RTOS wrapper before reading control CSR `0x7ca`. Only bit 1 selects the
command path. If clear, execution requests one `fence`, then leaves the wrapper.
Other control bits do not enable the range loop. The whole-cache routine issues
command 6 even with cache-control bit 1 clear and never reads address feedback.

## Alignment, wrapped end and supplied feedback

The range loop writes `start & ~31` to CSR `0x7cb`, then issues its command at
least once. It reads CSR `0x7cb` after every command and repeats while the
**unsigned** readback is below `(start + size) & 0xffffffff`.

No instruction increments the address by a presumed line stride. The harness
supplies each readback explicitly; it does not derive values from the command
or an assumed cache-line size. These native cases verify the consequences:

| Authored input | Original control flow |
| --- | --- |
| Start `0x1003`, size 64, feedback `0x1000, 0x1020, 0x1040, 0x1060` | One aligned address write, four commands/readbacks |
| Feedback moves `0x1020, 0x1000, 0x1043` | Three commands; backward feedback is accepted until final comparison succeeds |
| Aligned start `0x1000`, zero size, feedback `0x1000` | One command despite zero length |
| Unaligned start `0x1003`, zero size, feedback `0x1000, 0x1003` | Two commands despite zero length |
| Start `0x1000`, size `0xfffff000` | Wrapped end zero; one command still executes |
| Last positive start `0x7fffffff`, size 1, feedback `0x80000000` | Unsigned end comparison succeeds after one command |

These are supplied register streams, not measured device progression. The actual
CSR reads and writes execute without replacing the original loop or modifying
instruction semantics.

## Stalled command boundary

With readback fixed at `0x1000`, the loop has no software timeout or counter that
can force completion. Cases issue four commands/readbacks, then stop in the
harness **before** another command. The report marks `command_bound`, with no
normal return value or normal-return ABI claim. No firmware timeout is invented.

The stopped cache caller has not reached the exit wrapper. Under authored
scheduler-on/context-zero/depth-zero inputs, thread depth remains one and MIE
remains cleared. Under a nonzero context flag, the wrapper bypasses critical
entry and MIE/depth remain unchanged. These states are expanded in
[MAIN_RTOS_CRITICAL_SECTIONS.md](MAIN_RTOS_CRITICAL_SECTIONS.md).

## Fence and data limitations

Only the original fence sites `0x7029fee0`, `0x7029ff44` and `0x7029ffa8` are
accepted. Their containing code hashes and instruction lengths are checked;
the runner records the request and advances over the unsupported userop. It
models no memory-ordering, cache completion or electrical effect.

A fixed 512-byte payload, thread fields outside depth, global inputs and backing
guards remain unchanged. Cache-control instructions do not fabricate a payload
copy or prove any data was flushed. CSR state, RTOS state and diagnostic backing
are authored; live interrupt delivery, scheduling and physical coherency remain
outside this scope.

## Reproduction and continuation

Use the existing startup-aware main project. `SeedMainCacheControl.java` guards
ten complete original bodies before assigning reviewed signatures/bodies and
volatile CSR metadata. No firmware bytes or emulator instruction semantics change.

```sh
python3 analysis_scripts/main_cache_control.py --scope range \
  --vectors-output firmware/main-cache-range-vectors.json
python3 analysis_scripts/main_cache_control.py --scope critical \
  --vectors-output firmware/main-cache-critical-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainCacheControl.java \
  -postScript ValidateMainCacheControl.java \
  firmware/main-cache-range-vectors.json firmware/main-cache-range-validation.json \
  -postScript ValidateMainCacheControl.java \
  firmware/main-cache-critical-vectors.json firmware/main-cache-critical-validation.json

python3 analysis_scripts/main_cache_control.py firmware/bip6-4.6.0.3.zip \
  --scope range --decompiled firmware/decompiled/runtime-main-cache-control \
  --vectors firmware/main-cache-range-vectors.json \
  --validation firmware/main-cache-range-validation.json
```

Export addresses from `main_cache_control.RANGES` with `DecompileWithLogger.java`,
logger `0x702b38a2`, to the new export directory. Firmware/exports remain local.
All cases have a 5,000-step bound and at most 16 issued commands; marked bounded
stops do not assert normal ABI. All **186 preceding main backend/IRQ/guard/NAND
native cases reproduce byte for byte** after the metadata seed.

Remaining work includes production positive-address callers, actual cache CSR
progress/completion and ordering, IRQ/vector/controller/scheduler integration,
concurrent RTOS ownership, physical DMA/cache/coherency/timing, wider media/PM
consumers, persistent repair, backup/restoration and standalone boot.
