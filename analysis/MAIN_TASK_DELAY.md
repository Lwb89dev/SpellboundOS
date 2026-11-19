# vTaskDelay: suspend, delayed-list insertion, resume and yield

All **8 native cases** pass in **1,337 instruction steps**. This scope executes
the original `vTaskDelay` (`0x80d3a84c`) end to end, reusing every lower body as
guarded original code: `vTaskSuspendAll` (`0x80d3969a`),
`prvAddCurrentTaskToDelayedList` (`0x80d3927a`), `vListInsert` (`0x80d37db4`),
`uxListRemove`, `vListInsertEnd` and the whole of `xTaskResumeAll`
(`0x80d3a720`, [MAIN_SCHED_RESUME.md](MAIN_SCHED_RESUME.md)). Only
`configASSERT`, the critical-section diagnostic body and `vPortYield` are
supplied stubs. The evidence is in [main-task-delay.json](main-task-delay.json).

## Behaviour

`vTaskDelay(ticks)`:

- with `ticks == 0`, tail-calls `vPortYield` and returns;
- otherwise asserts that `uxSchedulerSuspended` is zero (line `0x582`),
  calls `vTaskSuspendAll`, `prvAddCurrentTaskToDelayedList(ticks, 0)` and
  `xTaskResumeAll`, and yields when resume reports no switch.

`prvAddCurrentTaskToDelayedList(ticks, canBlockIndefinitely)`:

1. removes the current task's state list item from its ready list; if that list
   becomes empty, clears the task's bit in `uxTopReadyPriority`;
2. for `ticks == 0xffffffff` with `canBlockIndefinitely` set, inserts the item
   at the end of the suspended list (`0x80c07e70`) and returns (modeled, not
   exercised here — `vTaskDelay` always passes `0`);
3. otherwise computes `wake = tick + ticks`, stores it in the state item, and
   inserts the item with `vListInsert`:
   - when `wake < tick` (the counter wrapped) into the overflow list
     (`0x80c07eb0` → delayed list 2), with **no** `xNextTaskUnblockTime` update;
   - otherwise into the active delayed list (`0x80c07eb4` → delayed list 1),
     and updates `xNextTaskUnblockTime` (`0x80c07e48`) when `wake` is sooner.

`vListInsert` keeps the list ordered by item value, inserting a `0xffffffff`
item directly before the list end.

## Cases

| Case | Observation |
| --- | --- |
| `zero_ticks_yields` | `ticks == 0`: immediate yield, no list work |
| `delay_moves_to_delayed_list` | Task leaves the ready list, joins delayed list 1, `xNextTaskUnblockTime = 110` |
| `clears_ready_bit_when_last` | Last task at its priority clears the ready bit |
| `keeps_ready_bit_with_peer` | A same-priority ready peer keeps the bit set |
| `ordered_before_later_sleeper` | Earlier wake inserted ahead of an existing sleeper |
| `ordered_after_sooner_sleeper` | Later wake inserted behind an existing sleeper |
| `overflow_list_on_wrap` | Wrapped wake goes to the overflow list, no unblock update |
| `suspended_at_entry_asserts` | Entry with the scheduler already suspended asserts |

Every executed PC is inside a hash-guarded original range or a supplied stub.
The runner records every store, CSR access and callee call; the independent
model (the resume model, extended with suspend/add-to-delayed/delay) reproduces
all of them. `vPortYield` is a no-op stub, so the pending switch is visible only
in the kernel state left behind (the task moved off the ready lists onto a
delayed list).

## Reproduction

```sh
python3 -m analysis_scripts.main_task_delay --vectors-output firmware/main-task-delay-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainTaskDelay.java firmware/main-task-delay-vectors.json \
  firmware/main-task-delay-validation.json
python3 -m analysis_scripts.main_task_delay firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-task-delay-vectors.json --validation firmware/main-task-delay-validation.json \
  > analysis/main-task-delay.json
```

The vectors, native report and evidence regenerate byte for byte.

Remaining work: `xTaskDelayUntil`, the event-list block/unblock used by queues
and semaphores, task deletion and suspend/resume of individual tasks, and live
preemption on hardware.
