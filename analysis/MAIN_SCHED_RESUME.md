# xTaskResumeAll: scheduler unlock, pending-ready and tick catch-up

All **9 native cases** pass in **1,593 instruction steps**. This scope executes
the original `xTaskResumeAll` at `0x80d3a720`, reusing every sub-body already
covered by [MAIN_FREERTOS_KERNEL.md](MAIN_FREERTOS_KERNEL.md): the task
critical section (`0x80d3a062`/`0x80d3a0ae`), the list primitives,
`xTaskIncrementTick` and `prvResetNextTaskUnblockTime` all run as guarded
original code. Only `configASSERT`, the critical-section diagnostic body and
`vPortYield` are supplied stubs. The evidence is in
[main-sched-resume.json](main-sched-resume.json).

## Behaviour

`xTaskResumeAll`:

1. asserts if `uxSchedulerSuspended` (`0x80c07e40`) is already zero (line
   `0x902`);
2. enters the task critical section and decrements `uxSchedulerSuspended`;
3. when it reaches zero and tasks exist, drains the pending-ready list
   (`0x80c07e9c`, index at `0x80c07ea8`): each task's event item
   (`tcb + 0x18`) and state item (`tcb + 4`) are removed, the priority bit is
   set and the task is inserted into its ready list, requesting a yield when its
   priority is at least the current task's;
4. if any task moved, calls `prvResetNextTaskUnblockTime`;
5. catches up `xPendedTicks` (`0x80c07e58`) by calling `xTaskIncrementTick` that
   many times, requesting a yield if any tick does, then clears the counter;
6. if a yield is pending (`0x80c07e54`), calls `vPortYield` and returns 1;
7. exits the critical section and returns.

The return value and `xYieldPending` report whether a context switch is due;
the switch itself is not modeled here (`vPortYield` is a no-op stub).

## Cases

| Case | Observation |
| --- | --- |
| `decrement_only` | Suspend count 2 → 1; no work, returns 0 |
| `unlock_no_work` | Count → 0, nothing pending, returns 0 |
| `unlock_no_tasks` | Zero tasks: work skipped |
| `pending_lower_priority_moved` | One task moved to its ready list, no yield |
| `pending_higher_priority_yields` | Moved and a yield requested, returns 1 |
| `two_pending_served` | Both tasks drained until the list empties |
| `pended_ticks_caught_up` | Three pended ticks replayed; equal-priority peer slices |
| `pended_ticks_wake_higher_priority` | Replayed ticks cross a deadline and wake a higher task |
| `not_suspended_asserts` | Entry with count zero hits the assertion |

Every executed PC is inside a hash-guarded original range or a supplied stub.
The runner records every store, CSR access and callee call; the independent
model (the kernel model, extended with the resume body) reproduces all of them.

## Reproduction

```sh
python3 -m analysis_scripts.main_sched_resume --vectors-output firmware/main-sched-resume-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainSchedResume.java firmware/main-sched-resume-vectors.json \
  firmware/main-sched-resume-validation.json
python3 -m analysis_scripts.main_sched_resume firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-sched-resume-vectors.json --validation firmware/main-sched-resume-validation.json \
  > analysis/main-sched-resume.json
```

The vectors, native report and evidence regenerate byte for byte.

Remaining work: `vTaskSuspendAll` and the blocking APIs (delay, queue,
semaphore, event groups) that pair with this unlock, and live preemption on
hardware.
