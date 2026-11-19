# Main trap entry, interrupt dispatch, PLIC API and FreeRTOS port

All **57 native cases** pass in **7,326 instruction steps** (maximum **536**,
IRQ initialization). This scope executes the original main-image trap
entry, the C trap handler, core and external interrupt dispatch, the
interrupt-controller API, timer, exception, syscall/yield and first-task/
scheduler-start bodies over authored memory, CSRs, registers and interrupt
claim values. The evidence is in [main-trap-irq.json](main-trap-irq.json).

This closes the open item from the previous scope: the "context" word
`0x80c121a4` that bypasses critical sections in
[MAIN_RTOS_CRITICAL_SECTIONS.md](MAIN_RTOS_CRITICAL_SECTIONS.md) is written
**only by the trap handler**. It is set to 1 on trap entry and cleared on
exit, so it is an "inside trap" flag. The scheduler gate and current-thread
fields are FreeRTOS kernel state (`xSchedulerRunning`, `pxCurrentTCB`,
`uxCriticalNesting`). The DMA interrupt handler covered in
[MAIN_DMA_IRQ.md](MAIN_DMA_IRQ.md) is now connected to its
actual registration and dispatch path.

No hardware interrupt is delivered and `mret` is not executed. Preemption,
priority arbitration, nesting timing, live scheduling and the physical timer
frequency remain unproved.

## Where the code lives

The trap code runs from RAM. The startup copy `.copy2` copies image
`0x70dce45c` to `0x80d32e00` (`0x14d38` bytes), so every RAM routine below also
appears in the image at address − `0x0ff649a4`. The evidence checks that the
copied bytes equal their load image. None of these routines were disassembled
in the existing analysis projects. Previous reference scans therefore found
only reads of the scheduler and context fields, and no writers.

Two tracked scanners recover what the project metadata misses:

- `ScanNativeDataReferences.java` resolves constant addresses built from
  `lui`/`auipc` + `addi`/load/store/`jalr`.
- `ScanNativeFlowsAndCsrs.java` lists control-flow sources and CSR/trap
  instructions.

`DisassembleNativeRange.java`, `DecompileNativeAt.java` and
`DecompileCallSites.java` disassemble or decompile in memory only: the projects
are opened read-only and nothing is saved.

## FreeRTOS identification

The kernel assertion paths name `..//./core/freertos/tasks.c` and contain the
FreeRTOS `configASSERT` expressions `( listLIST_IS_EMPTY( pxDelayedTaskList ) )`
and `listCURRENT_LIST_LENGTH( &( pxReadyTasksLists[ uxTopPriority ] ) ) > 0`.
The decompiled tick and switch bodies match `xTaskIncrementTick` and
`vTaskSwitchContext` in structure:

- delayed and overflow list swap;
- `xNextTaskUnblockTime`;
- pended ticks and `xYieldPending`;
- 64-bit run-time counters;
- the four-word `0xa5a5a5a5` stack-overflow check;
- ready-priority bitmap with `31 - clz`;
- per-task errno;
- newlib reentrancy pointer at TCB + `0x88`.

The FreeRTOS version is not established.

| Field | Address / offset | Interpretation |
| --- | --- | --- |
| `pxCurrentTCB` | `0x80c07fa8` | Current task; word 0 is the saved trap-frame pointer |
| `xSchedulerRunning` | `0x80c07e5c` | Gate read by critical enter/exit |
| `uxSchedulerSuspended` | `0x80c07e40` | Tick/switch suspended branch |
| `xTickCount` | `0x80c07e64` | Incremented by `xTaskIncrementTick` |
| Ready lists | `0x80c07ee0`, stride `0x14` | `pxReadyTasksLists[]` |
| `uxCriticalNesting` | TCB + `0x50` | Depth tested in the previous scope |
| Priority / stack / name | TCB + `0x2c` / `0x30` / `0x34` | Name length 28 (`0x1c`) |
| In-trap flag | `0x80c121a4` | Written only by the C trap handler |
| Saved `mie` | `0x80c121a0` | Written by mask-all, restored by restore-all |

The labels are the standard FreeRTOS names for the observed roles. Only the
behavior executed below is verified.

## Trap entry and frame

`xPortStartFirstTask` (`0x80d36000`) writes `mtvec = 0x80d35e00` in direct
mode. `xPortStartScheduler` (`0x80d37eca`) asserts on any `mtvec` mode bits
(line `0x105`) and on a misaligned ISR stack (line `0x10a`). It then calls
`vPortSetupTimerInterrupt` (`0x80d37e14`), sets `mie |= 0x880` and starts the
first task. The trap entry builds a `0x198`-byte frame on the interrupted stack:

| Offset | Content |
| --- | --- |
| `0x00` | Zero |
| `0x04`–`0x7c` | `x1`–`x31` in register-number order; the `sp` slot holds the frame address |
| `0x80` / `0x84` | `mstatus` / `mepc` |
| `0x88` / `0x8c` | Andes CSR `0x7c6` (moved through `mscratch`) / CSR `0x7c7` |
| `0x90`–`0x188` | `f0`–`f31` as 64-bit values |
| `0x190` | `fcsr`; `0x194` is padding and left untouched |

On entry the code temporarily clears CSR `0x7c6` and stores the frame address
into `*pxCurrentTCB`. It then calls the C handler (`0x80d35b60`) with
`(mcause, mepc, frame)`. If the in-trap flag is zero it switches to the ISR
stack `0x80e00000`, a constant at `0x70a1d8ac`; otherwise it stays on the
current stack. On return it reloads the frame from `*pxCurrentTCB`, which may
now be another task's frame. This is the context switch.

Two consequences hold for the tested inputs:

- `mscratch` is used as scratch and ends holding the restored frame's
  `0x7c6` value, not its entry value.
- `xPortStartFirstTask` does not restore `fcsr`, unlike the trap return.

A nested trap (in-trap flag already 1) still overwrites
`*pxCurrentTCB` with the nested frame and clears the flag on exit. The outer
handler would then continue with the flag at zero. The code shows this
behavior, but whether a nested trap can occur depends on interrupts being
re-enabled inside a handler, which this scope does not establish. The
critical-section wrappers skip enter/exit when the flag is set. That avoids
the `MIE` re-enable that a depth transition to zero would otherwise perform
inside a handler.

## Dispatch

The C handler sets the in-trap flag and optionally records diagnostics. The
diagnostic area at `0x80dff7c8` holds cause, claim, the current task name and
the frame `mepc`, plus magic `0xaabbccdd`.

- **Interrupts** (`mcause` bit 31 set) index the core table `0x80c009f4`
  (32 × 16 bytes) by the code in bits 30..0, with no bound check:
  - code 3 (software): a bare `ret` at `0x80d4118c`;
  - code 7: the timer handler;
  - code 11: the external dispatcher;
  - every other original entry is zero and jumps to address zero (harness
    stop `null_vector`).
- **External interrupts** read the claim at `0xe4200004` and call
  `{handler, argument}` from the 0x53-entry table at `0x80c11c70` without a
  bound or null check. They then write the claim back to complete it.
  - IRQ initialization fills every entry with `0x80d41188`, an infinite loop.
    An unregistered source or a claim of zero therefore never completes.
  - Claim `0x53` reads one entry past the table, i.e. the saved-`mie` word as
    handler and the in-trap flag as argument.
- **Timer**: clears `MTIE` and writes `mtimecmp` (`0xe6000008`) as low = 0,
  high, low. It then advances the stored compare by 1000 counts with carry and
  re-enables `MTIE`. It calls `xTaskIncrementTick`, and `vTaskSwitchContext`
  only when the tick returns nonzero. The physical tick period depends on the
  unestablished timer frequency.
- **Exceptions** call `table[mcause](mepc, frame)` from `0x70a1d418`
  (12 entries). They then always advance the saved `mepc` by the faulting
  instruction's length (2 or 4), including for faults. Cause 12 and above jump
  to zero.
- **Syscall** (cause 11): yields when frame `a7` is `0xf0000000`
  (`vPortYield` at `0x80d3965c`), calling `vTaskSwitchContext`. Every syscall
  writes 0 into the frame `a0`, and the `mepc` advance goes into the
  interrupted task's frame even when another task resumes.

## Interrupt-controller API

The register layout is consistent with an Andes/SiFive-style PLIC. The roles
are working interpretations of the observed accesses:

| Register | Address |
| --- | --- |
| Priority | `0xe4000000 + 4n` (word 0 written 1 at init) |
| Enable | `0xe4002000` |
| Threshold | `0xe4200000` |
| Claim/complete | `0xe4200004` |

The API functions and their contracts:

- **Register** (`0x80d35c6c`, `irq, handler, argument`).
  - External sources `0..0x52` store `{handler, argument, 0, 1}` and priority 1.
  - Bit 28 selects a core-local source `0..15`, stored in core table entry 16 + n.
  - The ID mask is `0xefffffff`: only bit 28 is removed. IDs with bits 29–31
    set are out of range, not aliases.
- **Enable / disable** (`0x80d35bcc` / `0x80d35c1c`).
  - For external sources they update the PLIC bit and the table's enabled word.
  - Local sources update `mie` bit 16 + n. The bound is 16, not 15: source 16
    shifts by 32 and sets or clears `mie` bit 0.
- **Mask-all / restore-all** (`0x80d35cc8` / `0x80d35cdc`).
  - Mask-all saves `mie` and clears it.
  - Restore-all re-enables each entry marked enabled, rewrites its stored
    priority and restores the saved `mie`.
- **Init / deinit** (`0x80d411ac` / `0x80d41200`).
  - Init clears `mie` and resets the PLIC: enables, priorities via memset,
    threshold 0, word 0 = 1. It then installs default handlers and sets
    `MEIE`, `MSIE` and `mstatus.MIE`.
  - Deinit clears `MIE` and resets the PLIC.

An independent raw RV32C decoder recovers the 18 far-call (`auipc`/`jalr`)
registration sites in the image with their constant arguments. They match the
bulk decompiler output:

| IRQ | Handler | Argument |
| --- | --- | --- |
| `0x12`, `0x16`, `0x19`, `0x1c` | `0x702a041c` (main DMA IRQ) | `0x92000000`, `0x93000000`, `0x93040000`, `0x93080000` |
| `9`, `10`, `0x2a`–`0x2d` | `0x70293d50` (shared) | `0x91003000`, `0x91004000`, `0x98005000`, `0x9a00a000`–`0x9a00c000` |
| `0xb`, `0xc`, `0x10`, `0x4f`, `0x50`, `0x51` | Distinct handlers | Zero |
| Two sites | `0x70296530`, `0x702a2e74` | IRQ and argument from object fields |

Five more registrations are direct `jal` calls inside the RAM copy. Source
`0xe` is registered three times with different RAM handlers: once by
`vPortSetupTimerInterrupt` with handler `0x80d37e08` (then enabled), and at
`0x80d4219c` and `0x80d42a58` with handlers `0x80d42004` and `0x80d429dc`.
Sources `0xc` and `0xb` are re-registered at `0x80d421b4`/`0x80d421cc` with
RAM handlers `0x80d42018`/`0x80d4202c`, replacing their image handlers whenever
those calls run. Because registration overwrites the entry, the effective
handler depends on call order, which this scope does not establish.

The following is static only and was not executed here. The routine at
`0x80d4217c` performs the `0xe`/`0xc`/`0xb` re-registrations only when
`0x80d341d8` returns 1; that function reads custom CSR `0xfc1`. All three RAM
handlers are identical: they test bit 12 of `0x90008020` and tail-call
`0x80d41fb8`. The `0x90008000` block is also used by the deep-sleep routine,
which suggests a power-management wake path.

The four DMA registrations are the only registrations of the DMA handler. This
supports, without proving, that the previously covered `0x93100000`
unknown-base fallback is not a fifth registered controller. Interrupt numbers
9 and 10 use the same bases that the deep-sleep routine at `0x80d34554` passes
to `0x80d43044`.

## Cases

| Group | Cases | Selected observations |
| --- | ---: | --- |
| Init / deinit | 2 | 0x53 default-handler entries, PLIC reset order, `mie`/`mstatus` transitions |
| Registration | 9 | Four-controller DMA sequence; external/local bounds; bit-28-only mask |
| Enable / disable | 16 | PLIC words 0/2, bound `0x52`, local bit 19, wrap at 16, out of range |
| Mask / restore | 2 | Only enabled entries re-enabled with stored priorities |
| External | 7 | Claim/complete, trace, default handler, claim zero, past-table entry, switch, nested |
| Timer / software / local | 8 | `mtimecmp` order, compare carry, conditional switch, null core vectors |
| Exceptions / syscall | 9 | Yield with/without switch, other syscall, 2/4-byte skip, past-table vector |
| Start | 4 | `mtvec` install, first-task restore without `fcsr`, `mtvec` mode-bit assertions |

Every stop other than `mret` is a marked harness stop:
- `default_handler`: before the firmware's infinite loop;
- `null_vector`: a jump to address zero;
- `assert`: before the assertion body.

Every executed PC is inside a hash-guarded original range or is a supplied
stub. The runner records every store outside the declared stack windows, every
CSR transition and every claim read. The independent Python model reproduces
all of them.

## Reproduction and remaining work

Use the startup-aware main project read-only:

```sh
python3 -m analysis_scripts.main_trap_irq --vectors-output firmware/main-trap-irq-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainTrapIrq.java firmware/main-trap-irq-vectors.json firmware/main-trap-irq-validation.json
python3 -m analysis_scripts.main_trap_irq firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-trap-irq-vectors.json --validation firmware/main-trap-irq-validation.json \
  > analysis/main-trap-irq.json
```

The native report and the evidence JSON regenerate byte for byte. No project
metadata is changed, so earlier golden exports and native reports are
unaffected.

Remaining work:

- Execute the original `xTaskIncrementTick`, `vTaskSwitchContext` and
  `vPortSetupTimerInterrupt` and the task-creation/stack-initialization path
  around `0x80d37e90`.
- Recover the remaining device interrupt handlers (`0x70293d50`, the
  zero-argument sources and the RAM handlers for `0xb`/`0xc`/`0xe`), the
  re-registration order and the dynamically registered sources.
- Cover the deep-sleep save/`wfi`/resume routine at `0x80d34470`–`0x80d34554`
  and its peripheral polling.
- Establish the live PLIC priority/threshold semantics, the timer frequency,
  Andes CSR `0x7c6`/`0x7c7` meanings and any actual interrupt nesting on the
  device.
