# Original main cache wrappers and RTOS critical-section state

All **22 native cases** pass in **1,922 instruction/service steps** (maximum
**165**, cache path with nonboolean diagnostic enable). Actual wrapper,
critical-section, context-query and diagnostic bodies now execute, including
cache callers. [main-cache-critical.json](main-cache-critical.json) shares the
ten code/export hashes and 5,000-step bound of
[MAIN_CACHE_CSR_RANGES.md](MAIN_CACHE_CSR_RANGES.md).

All RTOS/global/thread/CSR inputs are authored. The scheduler/context labels
below describe the tested working interpretation of those gates; this is not
a complete RTOS type/lifetime reconstruction, an interrupt trace or proof that
all supplied combinations occur in production. All selected support bodies
execute; full scheduler dispatch remains outside this scope.

## Original bodies and authored backing

| Body / state | Address | Selected observation |
| --- | --- | --- |
| Cache entry wrapper | `0x80d379ee` | Record caller, query context, branch to critical entry or write zero to output |
| Cache exit wrapper | `0x80d37a1a` | Query context, branch to critical exit or return |
| Context query | `0x80d41190` | Read word at `0x80c121a4` |
| Critical entry / exit | `0x80d3a062` / `0x80d3a0ae` | MIE and depth transitions below |
| Diagnostic recording | `0x80d33720` | Optional indexed word write based on enable byte |
| Scheduler gate | `0x80c07e5c` | Nonzero permits current-thread depth handling |
| Current-thread pointer | `0x80c07fa8` | Authored pointer to guarded thread backing; depth at +`0x50` |
| Diagnostic enable / table | `0x80c44244` / `0x80dff708` | Authored byte and twelve guarded words |

The source addresses and field offsets follow original loads/stores. The new
emulator executes those loads/stores and original CSR instructions; it does not
replace the entry/exit bodies with abstract lock callbacks.

## Entry and exit are depth transitions, not a saved-MIE restore

Critical entry records diagnostic stages, then clears **MIE bit 3** in `mstatus`
unconditionally. When the scheduler gate is nonzero, it increments the current
thread's +`0x50` word with 32-bit wrap and records a first-entry transition only
if the resulting depth is one. When the gate is zero, it returns after clearing
MIE without tracking depth.

Critical exit first checks the scheduler gate and existing depth. If either is
zero, it returns without changing MIE. Otherwise it decrements depth; only a
transition to zero records the last-exit stages and sets MIE bit 3. Other
`mstatus` bits remain unchanged.

| Authored sequence/state | Original result |
| --- | --- |
| Two entries, two exits, initial depth zero | Depths `1, 2, 1, 0`; MIE clear until the final exit sets it |
| Entry/exit with initial depth two | Depths `3, 2`; MIE remains clear even if initially set |
| Entry/exit with initial MIE clear and depth zero | Final depth zero and MIE set |
| Scheduler gate zero, entry/exit | Depth unchanged; MIE cleared and not reenabled |
| Exit alone with depth zero | MIE unchanged |
| Exit alone from depth one | Depth zero and MIE set |
| Exit alone from depth two | Depth one and MIE unchanged |
| Entry from depth `0xffffffff`, then exit | Increment wraps to zero; exit sees zero and leaves MIE clear |

These are code/state results under supplied inputs. They do not establish a
production bug or the legal calling preconditions of a complete RTOS.

## Context bypass and output argument

A nonzero queried context flag makes the cache entry wrapper write zero to its
output word and return without critical entry. Exit queries the flag again and
returns without critical exit. Both 1 and `0xffffffff` take this bypass. Cache
commands or a requested fence can still run between the wrappers.

With context zero, the entry wrapper tail-calls critical entry **without writing
the output word**. Standalone tests retain the authored `0xa5a5a5a5` sentinel.
The exit wrapper ignores its supplied argument in the selected path: querying
context overwrites the argument register, and critical exit uses global/thread
state rather than a saved MIE value. Tests with zero and `0xdeadbeef` arguments
produce identical observations. This is why the pair must not be modeled as
restoring the original interrupt-enable bit from its output cookie.

The context flag is held constant within each case. Concurrent changes between
entry and exit, thread migration, null/stale thread pointers and broader
scheduler invariants remain untested.

## Actual diagnostic body and bounded stalls

The diagnostic function reads its enable byte and, if nonzero, writes the given
word to the selected table index. Original calls use index 7 for the saved
caller's PC, index 9 for stages `3, 1, 2, 0`, and index 6 for first/last depth
transitions `1, 0`. Values 1 and 255 enable recording; zero preserves all table
sentinels while calls and enable-byte reads still execute.

A stalled positive-address cache loop stops only at the harness command bound.
With context zero, it retains depth one and cleared MIE; with context nonzero,
it retains depth zero and its original MIE bit. No exit, simulated unlock or
firmware timeout is inserted. These stopped paths claim no normal return ABI.
Normal completed paths preserve stack and saved registers. Void entry/exit/save/
restore helpers claim no residual return value.

Thread fields outside depth, global inputs, source bytes and all guards hold.
The only supplied instruction effect is the three reviewed fence no-ops from
the cache scope. Cache readback/CSR and RTOS inputs are authored; live interrupt
masking/delivery, ordering, hardware progression and physical coherency are not
established.

## Reproduction and remaining work

Follow [the shared seed/native procedure](MAIN_CACHE_CSR_RANGES.md) with critical
vectors and validation, then reproduce evidence:

```sh
python3 analysis_scripts/main_cache_control.py firmware/bip6-4.6.0.3.zip \
  --scope critical --decompiled firmware/decompiled/runtime-main-cache-control \
  --vectors firmware/main-cache-critical-vectors.json \
  --validation firmware/main-cache-critical-validation.json
python3 -m unittest tests.test_main_cache_control -q
```

The two scopes add **32 host checks** covering original hashes, complete native
observations, CSR feedback/control boundaries, depth/MIE transitions, diagnostics,
argument/output behavior, input bounds and marked nonreturning stops. All **186
preceding native backend/IRQ/cache/NAND cases reproduce byte for byte**.
Both new JSON reports reproduce byte for byte, and the complete **2,112-test
host suite passes**.

Remaining work includes actual IRQ entry/controller/scheduler integration,
concurrent current-thread/context state, broader critical-section and callback
consumers, production cache/DMA addresses, live cache progression/order/coherency,
physical persistence, safe restoration and standalone boot.
