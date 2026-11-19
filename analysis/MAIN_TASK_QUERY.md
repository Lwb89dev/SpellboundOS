# Main FreeRTOS task query and priority

All **19 native cases** pass in **1,692 instruction steps**. This scope
executes the original `eTaskGetState` (`0x80d3a55e`), `uxTaskPriorityGet`
(`0x80d3a5f4`) and `vTaskPrioritySet` (`0x80d3a61c`) end to end, reusing the
lower bodies already covered by
[MAIN_FREERTOS_KERNEL.md](MAIN_FREERTOS_KERNEL.md) as guarded original code:
`vTaskEnterCritical`, `vTaskExitCritical`, `uxListRemove` and `vListInsertEnd`.
`vTaskPrioritySet` tail calls the original `vTaskExitCritical`. The evidence is
in [main-task-query.json](main-task-query.json).

Only `configASSERT`, the critical-section diagnostic body and `vPortYield` are
supplied stubs. Here the yield returns, so the priority change completes; the
resulting context switch is not modeled. No hardware is driven and `mret` is
not executed.

## eTaskGetState

`eTaskGetState(handle)` asserts a non-null handle (line `0x5ae`), then returns
the running code for the current task; otherwise it reads the task's state-list
container (TCB + `0x14`) inside a critical section and maps it to a state code:

| State-list container | Extra condition | Returned code |
| --- | --- | ---: |
| current task | — | `0` running |
| delayed or overflow list | — | `2` blocked |
| suspended list (`0x80c07e70`) | no pending event and notify state ≠ 1 | `3` suspended |
| suspended list | a pending event or notify state = 1 | `2` blocked |
| termination list (`0x80c07e88`) or `0` | — | `4` deleted |
| any other (ready) list | — | `1` ready |

The suspended-but-not-really case (a task on the suspended list that is still
waiting on an event, or has a pending notification) is reported as blocked, not
suspended.

## uxTaskPriorityGet

`uxTaskPriorityGet(handle)` enters the critical section, resolves `handle == 0`
to the current task, reads the active priority (TCB + `0x2c`), exits and returns
it.

## vTaskPrioritySet

`vTaskPrioritySet(handle, newPriority)`:

1. If `newPriority > 9`, assert (line `0x64e`) and clamp to 9.
2. Enter the critical section and resolve `handle == 0` to the current task.
3. Read the base priority (TCB + `0x5c`). If it already equals `newPriority`,
   do nothing.
4. Otherwise decide whether to yield:
   - raising the base: yield when the task is not the current one and the
     current task's active priority is `<= newPriority`;
   - lowering the base: yield when the task is the current one.
5. If the base equals the active priority (TCB + `0x2c`), update the active
   priority too. A task whose active priority was raised above its base by
   mutex inheritance keeps that inherited value.
6. Update the base priority. If the event-list item value (TCB + `0x18`) is not
   marked (top bit clear), rewrite it to `configMAX_PRIORITIES - newPriority`.
7. If the task sits on its old ready list, remove it (clearing the old priority
   bit when the list empties), set the new priority bit and re-insert it.
8. Yield if required, then tail call `vTaskExitCritical`.

## Cases

| Group | Cases | Selected observations |
| --- | ---: | --- |
| `uxTaskPriorityGet` | 2 | Current and explicit handle, both inside a critical section |
| `eTaskGetState` | 9 | Null assert; running; ready; delayed and overflow blocked; suspended; suspended-waiting and suspended-with-event reported blocked; termination and zero container deleted |
| `vTaskPrioritySet` | 8 | Above-max clamp assert; same-priority no-op; lower current reorders and yields; raise another to the current priority yields; raise below current does not yield; inherited active priority preserved; marked event value preserved |

Supplied callees and their harness behavior:

- The critical-section diagnostic body returns.
- `vPortYield` returns, so the priority change completes to the exit.
- `configASSERT` is a marked harness stop.

Every executed PC is inside a hash-guarded original range or a supplied stub.
The runner records every store outside the declared stack windows, every CSR
transition, every supplied call with its arguments and the returned `a0`. The
independent Python model reproduces all of them, reusing the kernel scope's
list and critical-section mirrors.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_task_query --vectors-output firmware/main-task-query-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainTaskQuery.java firmware/main-task-query-vectors.json \
  firmware/main-task-query-validation.json
python3 -m analysis_scripts.main_task_query firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-task-query-vectors.json \
  --validation firmware/main-task-query-validation.json > analysis/main-task-query.json
```

The vectors, native report and evidence regenerate byte for byte. The project
is opened read-only, so earlier golden exports and native reports are
unaffected.

Remaining work:

- Execute `vTaskSuspend`/`vTaskResume`, the mutex priority
  inheritance/disinheritance paths and the pending-ready list consumers.
- Cover the queue, semaphore, event-group and notification APIs.
- Validate live rescheduling after a priority change on hardware.
