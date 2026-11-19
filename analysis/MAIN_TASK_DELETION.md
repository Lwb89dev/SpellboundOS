# Main FreeRTOS task deletion: vTaskDelete and prvDeleteTCB

All **12 native cases** pass in **1,191 instruction steps**. This scope
executes the original `vTaskDelete` (`0x80d3a45c`) and `prvDeleteTCB`
(`0x80d3939c`) end to end, reusing the lower bodies already covered by
[MAIN_FREERTOS_KERNEL.md](MAIN_FREERTOS_KERNEL.md) as guarded original code:
`vTaskEnterCritical`, `vTaskExitCritical`, `uxListRemove`, `vListInsertEnd` and
`prvResetNextTaskUnblockTime`. The evidence is in
[main-task-deletion.json](main-task-deletion.json).

Only `configASSERT`, the critical-section diagnostic body, `vPortYield`,
newlib `_reclaim_reent` (`0x709490b4`) and `vPortFree` (`0x80d3c14e`) are
supplied stubs. No hardware is driven, and `mret` is not executed. The
deferred idle-task cleanup that actually frees a self-deleted task is not
executed here.

## prvDeleteTCB

`prvDeleteTCB(tcb)` reclaims the newlib reentrancy structure
(`_reclaim_reent(tcb + 0x88)`) and then frees memory according to
`ucStaticallyAllocated` at TCB + `0x4b5`:

| Mode | Meaning | Action |
| ---: | --- | --- |
| 0 | Stack and TCB dynamically allocated | `vPortFree(tcb->pxStack)` then `vPortFree(tcb)` |
| 1 | Only the TCB dynamically allocated | `vPortFree(tcb)` |
| 2 | Statically allocated | nothing |
| other | — | `configASSERT` at line `0x10b9` (`pxTCB->ucStaticallyAllocated == ...`) |

The free of the stack precedes the free of the TCB, and both are tail calls to
the same allocator free routine `0x80d3c14e`.

## vTaskDelete

`vTaskDelete(handle)` runs entirely inside the task critical section:

1. Enter the critical section.
2. Resolve `handle == 0` to the current TCB (`pxCurrentTCB`, `0x80c07fa8`).
3. Remove the task from its state list (`uxListRemove(tcb + 4)`). If that list
   is now empty for the task's priority, clear the priority bit in
   `uxTopReadyPriority` (`0x80c07e60`).
4. If the task is on an event list (`tcb + 0x28` nonzero), remove its event
   list item (`uxListRemove(tcb + 0x18)`).
5. Increment `uxTaskNumber` (`0x80c07e4c`).
6. If deleting the **running** task, append it to the termination list
   (`0x80c07e88`) and increment `uxDeletedTasksWaitingCleanUp` (`0x80c07e84`),
   leaving the actual free to the idle task. Otherwise decrement
   `uxCurrentNumberOfTasks` (`0x80c07e68`) and recompute the next unblock time.
7. Exit the critical section.
8. If deleting another task, call `prvDeleteTCB` immediately.
9. If the scheduler is running and the deleted task is the current one, assert
   that `uxSchedulerSuspended == 0` (line `0x516`) and then yield.

The yield is a tail call to the `vPortYield` wrapper `0x80d3965c`, the same path
the kernel scope covers; the harness stops at it. A delete before the scheduler
starts, or of a non-current task, never yields.

## Cases

| Case | Observation |
| --- | --- |
| `delete_tcb_static` | Mode 2 frees nothing |
| `delete_tcb_dynamic_stack_and_tcb` | Reclaim reent, then free stack and TCB in order |
| `delete_tcb_tcb_only` | Mode 1 frees only the TCB |
| `delete_tcb_bad_mode` | Invalid mode asserts |
| `delete_other_last_in_priority_clears_bit` | Priority bit cleared, count decremented, next unblock reset to `0xffffffff`, TCB freed |
| `delete_other_keeps_shared_priority_bit` | Shared priority keeps its bit; a peer stays ready |
| `delete_other_removes_event_list_item` | Event list item removed and its container cleared |
| `delete_other_before_scheduler_start` | No yield before the scheduler runs |
| `delete_self_moves_to_termination_and_yields` | Appended to the termination list, cleanup counter incremented, yields; no immediate free |
| `delete_null_handle_resolves_to_current` | `NULL` resolves to the running task, same self path |
| `delete_self_while_suspended_asserts` | Self-delete with the scheduler suspended asserts |
| `delete_self_before_scheduler_start_no_yield` | Self-delete before start records the task but does not yield |

Supplied callees and their harness behavior:

- `_reclaim_reent` and `vPortFree` return without modeling the heap.
- The critical-section diagnostic body returns.
- `configASSERT` and `vPortYield` are marked harness stops (`assert`, `yield`).

Every executed PC is inside a hash-guarded original range or a supplied stub.
The runner records every store outside the declared stack windows, every CSR
transition and every supplied call with its arguments. The independent Python
model reproduces all of them, reusing the kernel scope's list and
critical-section mirrors.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_task_deletion --vectors-output firmware/main-task-deletion-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainTaskDeletion.java firmware/main-task-deletion-vectors.json \
  firmware/main-task-deletion-validation.json
python3 -m analysis_scripts.main_task_deletion firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-task-deletion-vectors.json \
  --validation firmware/main-task-deletion-validation.json > analysis/main-task-deletion.json
```

The vectors, native report and evidence regenerate byte for byte. The project
is opened read-only, so earlier golden exports and native reports are
unaffected.

Remaining work:

- Execute `prvCheckTasksWaitingTermination`, the idle-task body and the actual
  heap free/reent reclamation paths.
- Cover the blocking APIs (delays already executed in
  [MAIN_TASK_DELAY.md](MAIN_TASK_DELAY.md); queues, semaphores, event groups
  and notifications remain) and task suspend/resume.
- Validate live rescheduling after a self-delete yield on hardware.
