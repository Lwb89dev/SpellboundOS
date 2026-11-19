# Main FreeRTOS kernel: tick, context selection, timer setup and task creation

All **61 native cases** pass in **10,317 instruction steps** (maximum **594**,
task creation with a long name). This scope executes the original main-image
FreeRTOS kernel and port bodies that
[MAIN_TRAP_IRQ_DISPATCH.md](MAIN_TRAP_IRQ_DISPATCH.md) still supplied:
`xTaskIncrementTick`, `vTaskSwitchContext`, `vPortSetupTimerInterrupt`, the
run-time counter, `pxPortInitialiseStack`, `prvInitialiseNewTask`,
`prvAddNewTaskToReadyList` and `xTaskCreateStatic`. The list primitives, the
task-level critical section and libgcc `__clzsi2` also run as original code.
Eight cases join these bodies to the original trap entry, timer handler,
first-task start and scheduler start. The evidence is in
[main-freertos-kernel.json](main-freertos-kernel.json).

No hardware timer or interrupt is delivered and `mret` is not executed. Timer
frequency, live preemption and multi-task behavior on the device remain
unproved.

## Routines and kernel layout

All routines except `__clzsi2` (`0x709450d0`, image) run from the RAM copy
`.copy2`. The evidence checks each RAM body against its load image and pins
every executed range by SHA-256. It also checks eleven direct `jal`/`j` call
sites with an independent raw decoder. These sites connect scheduler start →
run-time counter / port start → timer setup, the timer handler → tick/switch,
both task-creation paths → initialization/ready-list insertion, and stack
initialization.

| Routine | Address | Routine | Address |
| --- | --- | --- | --- |
| `vListInitialise` | `0x80d37d82` | `xTaskIncrementTick` | `0x80d3974e` |
| `vListInitialiseItem` | `0x80d37d96` | `vTaskSwitchContext` | `0x80d398d6` |
| `vListInsertEnd` | `0x80d37d9c` | `prvResetNextTaskUnblockTime` | `0x80d39378` |
| `uxListRemove` | `0x80d37de2` | `prvInitialiseNewTask` | `0x80d394f6` |
| Task return stub | `0x80d37e02` | `vTaskEnterCritical` / `Exit` | `0x80d3a062` / `0x80d3a0ae` |
| Source-14 handler | `0x80d37e08` → `0x80d42c68` | `prvAddNewTaskToReadyList` | `0x80d3a0fa` |
| `vPortSetupTimerInterrupt` | `0x80d37e14` | `xTaskCreateStatic` | `0x80d3a234` |
| `pxPortInitialiseStack` | `0x80d37e66` | `xTaskCreate` (static only) | `0x80d3a3bc` |
| Run-time base / value | `0x80d37f8c` / `0x80d37fa6` | 64-bit `mtime` read | `0x80d4548c` |

The names are the standard FreeRTOS roles that match the observed behavior.

| Global | Address | Global | Address |
| --- | --- | --- | --- |
| Run-time base (64-bit) | `0x80c07de0` | `xPendedTicks` | `0x80c07e58` |
| `ulTotalRunTime` / switched-in time | `0x80c07e30` / `0x80c07e38` | `xSchedulerRunning` | `0x80c07e5c` |
| `uxSchedulerSuspended` | `0x80c07e40` | Ready-priority bitmap | `0x80c07e60` |
| `xNextTaskUnblockTime` | `0x80c07e48` | `xTickCount` | `0x80c07e64` |
| `uxTaskNumber` | `0x80c07e4c` | `uxCurrentNumberOfTasks` | `0x80c07e68` |
| `xNumOfOverflows` | `0x80c07e50` | Saved `errno` | `0x80c07e6c` |
| `xYieldPending` | `0x80c07e54` | newlib `_impure_ptr` | `0x70f884f8` |
| Suspended / termination / pending-ready lists | `0x80c07e70` / `0x80c07e88` / `0x80c07e9c` | Overflow / delayed list pointers | `0x80c07eb0` / `0x80c07eb4` |
| Delayed lists | `0x80c07ecc`, `0x80c07eb8` | Ready lists (10 × `0x14`) | `0x80c07ee0` |

The executed code fixes several configuration values.

- **Priorities and names**: 10 priorities. Task names are 20-byte fields,
  so at most 19 characters plus NUL.
- **TCB**: `0x4c0` bytes, checked by `xTaskCreateStatic`.
- **Stack-overflow check**: method 2, testing the first 16 bytes for
  `0xa5a5a5a5`.
- **Run-time statistics**: enabled, with 64-bit counters.
- **newlib reentrancy**: enabled; the per-task `_reent` is `0x428` bytes at
  TCB + `0x88`.
- **Per-task `errno`**: at TCB + `0x4b8`.
- **Tick hook**: an empty `ret`.
- **Preemption and time slicing**: enabled.
- **Priority selection**: a bitmap with `31 - clz`, through libgcc
  `__clzsi2`. Its 256-byte table at `0x709babf8` is verified to be a
  bit-length table.

The 64-bit run-time counter type and the `xPendedTicks` name suggest a
FreeRTOS 10.5 or later kernel, but the version is still not established.

## Port timer and source 14

`vPortSetupTimerInterrupt` reads a consistent 64-bit `mtime` (`0xe6000004`
high, `0xe6000000` low, high again, retried while the high words differ):

- it writes `mtimecmp` = `mtime + 1000`, low word (`0xe6000008`) first, then
  high (`0xe600000c`);
- it stores the next compare (`mtime + 2000`) at `0x80c07de8`, with carry into
  both high words;
- it registers PLIC source `0xe` with handler `0x80d37e08` and argument 0, then
  enables it, through the original register/enable bodies.

The tick interrupt itself remains the core machine-timer cause 7. Each
period is therefore 1000 `mtime` counts; the real-time period depends on the
unestablished timer frequency. The initial compare write is low-then-high,
unlike the handler's zero/high/low sequence. This scope records that order but
does not establish whether it can cause an early match on hardware.

The source-14 handler ignores its argument. It reads the object word at
`0x80c000b8`, whose original copied value is `0x91005010`, and writes 2 to
`0x91005000` for that value or 4 otherwise. The register's function is
unknown. A connected case delivers claim `0xe` through the original trap
entry and external dispatcher to this handler.

The run-time base (`0x80d37f8c`, called by `vTaskStartScheduler` at
`0x80d3a382`) captures `mtime`. The counter returns `mtime − base` as a 64-bit
value, borrowing across the word boundary.

## Task stacks and creation

`pxPortInitialiseStack(top, pxStack, code, parameter)` returns a zeroed
`0x198`-byte frame at `top − 0x198`:

| Frame slot | Value |
| --- | --- |
| `ra` (`+0x04`) | `0x80d37e02`: `vTaskDelete(NULL)` if the task returns |
| `a0` (`+0x28`) | Task parameter |
| `mstatus` (`+0x80`) | `0x7880`: `MPIE`, `MPP` = machine, `FS` = 3 |
| `mepc` (`+0x84`) | Task entry |
| CSR `0x7c6` (`+0x88`) | `0x21` |
| CSR `0x7c7` (`+0x8c`) | `pxStack + 0x198` |

Under the AndeStar V5 CSR numbering, `0x7c6` is the hardware stack-protection
control (`mhsp_ctl`) and `0x7c7` its bound (`msp_bound`).

- `0x21` would enable overflow detection (bit 0) in machine mode (bit 5).
- The bound keeps one trap frame of headroom above the stack base.
- This interpretation fits the trap entry, which clears `0x7c6` while it
  saves a frame and restores both per task.

It replaces the earlier neutral labels, but it rests on documented CSR
numbering, not on a hardware observation.

A connected case runs `xTaskCreateStatic` and then the original
`xPortStartFirstTask`. The new task resumes with:

- `pc` = entry, `a0` = parameter, `ra` = `0x80d37e02`, `sp` = aligned top;
- `mstatus` = `0x7880`, `0x7c6` = `0x21`, `0x7c7` = stack base + `0x198`;
- `gp` = `tp` = 0;
- `fcsr` unchanged.

Startup sets `gp` at `0x70160238`. The fully analyzed listing contains no
genuine `gp`-relative access in executable code, which is consistent with a
build that does not use `gp` relaxation. That is a static observation, not a
proof that every task is safe with `gp` = 0.

`prvInitialiseNewTask` fills the stack with `0xa5`. It then sets:

- top = `(pxStack + 4·depth − 4) & ~7`, stored at TCB + `0x48`, and the depth
  at TCB + `0x4c`;
- the name (copied up to 20 bytes, then the last byte forced to NUL);
- the priority, **silently clamped** to 9 with no assertion, and the base
  priority;
- the list items, with the event value 10 − priority and owners set to the
  TCB;
- zero run-time, nesting and notification fields;
- newlib `_REENT_INIT`: memset `0x428`, the standard streams at TCB +
  `0x374`/`0x3dc`/`0x444`, the locale `0x709c4a58` and the `rand48` constants
  `0x330e`/`0xabcd`/`0x1234`/`0xe66d`/`0xdeec`/`5`/`0xb`.

`xTaskCreateStatic` asserts on a null stack (line `0x269`) or TCB (`0x26a`).
It marks TCB + `0x4b5` = 2, statically allocated. `xTaskCreate` allocates the
stack and a `0x4c0`-byte TCB through `0x80d3c324` with capability `0x20` and
marks 0. That path was not executed.

`prvAddNewTaskToReadyList` runs inside the direct task critical section.
That section clears `MIE`, increments the current task's nesting only while the
scheduler runs, and records diagnostics through the supplied body
`0x80d33720`.

- Before the scheduler starts, exit returns early. `MIE` therefore stays
  clear until the first task's `MPIE` restores it.
- The first task initializes all 15 kernel lists.
- Before start, a new task becomes current when its priority is greater than
  or **equal** to the current one, so the newest task wins ties.
- While the scheduler runs, a new task yields through the `ecall` wrapper only
  when it has strictly higher priority. The nesting depth returns to zero and
  `MIE` is restored first.

## Tick and context selection

The executed `xTaskIncrementTick` behaves as follows.

- While suspended it only counts pended ticks.
- Otherwise it increments the tick.
  - On a wrap it asserts if the delayed list is not empty (line `0xb64`).
    It then swaps the two delayed lists, counts the overflow and recomputes
    the unblock time.
  - Once the deadline is reached, it moves every expired task to its ready
    list in order. It also removes any event-list membership, sets the
    priority bit and adjusts a delayed-list index that pointed at the removed
    item. It stops at the first future deadline, or stores `0xffffffff` when
    the list empties.
- It requests a switch when a woken task's priority is greater than or equal
  to the current one, when the current priority has more than one ready task
  (time slicing) or when a yield is pending. Deadline comparisons are
  unsigned.

The executed `vTaskSwitchContext` behaves as follows.

- While suspended it only sets the yield-pending flag.
- Otherwise it clears that flag and accumulates
  `counter − switched_in + total` into TCB + `0x80` as 64 bits, only when the
  total exceeds the switched-in time. It then records the new switched-in time.
- It checks the outgoing stack. A mismatch in any of the four words calls
  `vApplicationStackOverflowHook` (`0x701645a0`, supplied) with the TCB and its
  name, then continues.
- It saves `errno` into the outgoing TCB.
- It selects priority `31 − clz(bitmap)` and asserts on an empty list
  (line `0xcc3`).
- It advances the round-robin index, skipping the end marker, and makes the
  owner current.
- It restores that task's `errno` and points `_impure_ptr` at its `_reent`.

A zero bitmap yields index −1. The code then reads the first delayed list
header at `0x80c07ecc` as if it were a ready list; with that list empty, the
case asserts. In normal operation the idle task keeps the bitmap nonzero.

## Cases

| Group | Cases | Selected observations |
| --- | ---: | --- |
| Port | 9 | Stable/retried `mtime`; compare carries; source-14 write 2/4; run-time borrow; initial frame; task return → `vTaskDelete` |
| Creation | 11 | List initialization; name truncation; priority clamp; null name; before-start ties; running yield/no yield; null-buffer asserts; create → first-task registers |
| Tick | 15 | Suspended; deadline; time slice; yield pending; wake higher/lower/equal; event removal; ordered wakes; index repair; wrap with/without overflow tasks; wrap assert; unsigned deadline |
| Switch | 18 | Suspended; highest priority; round robin and wrap; run-time equal/high-word/carry/base borrow; four stack-overflow words; `mtime` retry; clz for 1/`0x100`/`0x3ff`; empty list; zero bitmap |
| Connected | 8 | Timer handler with and without a switch; trap timer → peer; trap timer wakes a higher-priority task; no-switch trap; `ecall` yield → peer; source-14 claim; scheduler start with actual timer setup |

Supplied callees and their harness behavior:

- `memset` modifies memory without being recorded as a store.
- The critical-section diagnostic body (covered by the earlier critical-section
  scope) and the overflow hook return.
- `configASSERT`, `vTaskDelete` and the `ecall` yield wrapper are marked
  harness stops (`assert`, `task_delete`, `yield`).

Every executed PC is inside a hash-guarded original range or a supplied stub.
The runner records:

- every store outside the declared stack windows;
- every CSR transition;
- every supplied `mtime`/claim read;
- `a0`/`a1` for value-returning calls.

The independent Python model reproduces all of them.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_freertos_kernel --vectors-output firmware/main-freertos-kernel-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainFreertosKernel.java firmware/main-freertos-kernel-vectors.json \
  firmware/main-freertos-kernel-validation.json
python3 -m analysis_scripts.main_freertos_kernel firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-freertos-kernel-vectors.json \
  --validation firmware/main-freertos-kernel-validation.json > analysis/main-freertos-kernel.json
```

The vectors, native report and evidence regenerate byte for byte. The project
is opened read-only, so earlier golden exports and native reports are
unaffected.

Remaining work:

- Execute `vTaskStartScheduler`'s idle/timer-task creation and dynamic
  `xTaskCreate` allocation.
- Execute the blocking APIs (delay, queue/semaphore/event lists), task deletion
  and cleanup, and suspend/resume with pended-tick catch-up (`0x80d3a824`).
- Recover the meaning of the source-14 register at `0x91005000`, the stack-
  overflow hook and the remaining device handlers.
- Measure the `mtime` frequency, verify the Andes stack-protection
  interpretation and observe live preemption on hardware.
