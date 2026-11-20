# SpellboundOS kernel

An independently authored RV32 kernel, QEMU `virt` first (see [GOAL.md](../GOAL.md)).
This is bring-up scaffolding, not a Bip 6 image.

## Layout

| File | Role |
| --- | --- |
| `arch/riscv/start.S` | reset entry: park secondary harts, set `gp`/`sp`, zero `.bss`, initialize the board, call `kernel_main` |
| `arch/riscv/trap.S` / `trap_frame.h` | save integer registers, PC and status, then restore the selected frame with `mret` |
| `arch/riscv/trap.c` | direct machine trap vector setup, timer dispatch and scheduler requests |
| `arch/riscv/timer.c` | CLINT machine timer (`mtime`/`mtimecmp`), periodic tick at a chosen Hz |
| `arch/riscv/riscv.h` | CSR access helpers and bit definitions |
| `console.c` / `console.h` | console formatting and byte I/O |
| `drivers/uart16550.c` | polled access to the QEMU virt UART |
| `drivers/plic.c` | external interrupt registration, claim and completion |
| `boards/qemu-virt/board.c` | UART registration, PLIC context and timer configuration |
| `sched.c` / `sched.h` | round-robin scheduler with cooperative and timer-driven switching |
| `kmem.c` / `kmem.h` | first-fit kernel heap (split + coalesce), host-testable |
| `driver.c` / `driver.h` | fixed-size device/driver registration and probe, host-testable |
| `main.c` | bring-up: console → traps → polled echo → 100 Hz timer → two round-robin tasks → tick loop |
| `boards/qemu-virt/linker.ld` | load at `0x80000000`, `.text/.rodata/.data/.bss`, 16 KiB stack |

## Current capabilities

- Boots on QEMU `virt`, single hart.
- Machine-mode traps use direct `mtvec`. An unhandled trap prints `mcause`,
  `mepc` and `mtval`, masks interrupt sources and parks the hart.
- CLINT machine timer: a periodic tick (100 Hz) via `MTIE` + global `MIE`, with a
  64-bit tick counter read protected from interrupts and safe RV32 `mtime`/`mtimecmp` access.
- External interrupts use the PLIC machine context for hart 0. A registered
  handler acknowledges its device before the controller completes the claim.
  The test triggers two UART transmit-ready interrupts through this path.
  See the [QEMU virt board description](https://www.qemu.org/docs/master/system/riscv/virt.html).
- UART console (`puts`/`puthex`/`putdec`/`getc`), polled echo.
- Round-robin tasks can yield, exit or sleep for a number of timer ticks. The scheduler waits on the boot stack when all tasks sleep and reuses slots when tasks exit. Call `trap_init` before running tasks.
- `sched_set_preemption(true)` enables one tick per time slice. The default is cooperative. Both modes save integer registers and the interrupt state in the task's trap frame. A stack must have at least 272 bytes after alignment and enough space for the task's calls and trap handling. Tasks share machine-mode memory on hart 0. Serialize shared heap, registry and console access if using preemption.
- Kernel heap `kmalloc`/`kfree` (first-fit, block split, forward coalescing); the allocator logic is portable and unit-tested on the host (`make test-host`). Access must be serialized, including against interrupts.
- Device/driver registry: explicit name-based binding and retryable probe passes. QEMU virt registers and probes its console UART before `kernel_main`. Registration is single-threaded and reset only clears registry bindings.

## Build and test

```sh
make                 # needs clang, ld.lld, llvm-objcopy
make LLD=/path/to/ld.lld   # if ld.lld is not on PATH (e.g. an LLVM/NDK toolchain)
make test            # needs qemu-system-riscv32; checks boot, echo, timer,
                     # scheduling, preemption, heap and trap diagnostics on RV32 QEMU virt
make test-host       # host tests for heap and driver registry (clang + ASan/UBSan)
```

The build is linker-agnostic (any LLVM `ld.lld`); running the `test`/`qemu`
targets needs a *system* QEMU (`qemu-system-riscv32`), not the user-mode
`qemu-riscv32` static binaries.

## Next foundations

- Add board support for further devices.
