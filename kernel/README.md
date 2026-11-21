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
| `ringbuf.c` / `ringbuf.h` | bounded byte ring buffer, host-testable |
| `drivers/uart16550.c` | interrupt-driven RX and polled TX for the QEMU virt UART |
| `drivers/plic.c` | external interrupt registration, claim and completion |
| `rtc.c` / `rtc.h` | primary RTC interface and freestanding Unix-to-UTC calendar conversion, host-testable |
| `drivers/goldfish_rtc.c` | Goldfish RTC wall clock and one-shot alarm IRQ driver |
| `drivers/sifive_test.c` | SiFive Test syscon poweroff/reboot driver for QEMU virt |
| `bus.c` / `bus.h` | hardware-independent GPIO, I2C and SPI bus abstractions, host-testable |
| `input.c` / `input.h` | watch input event queue (keys, touch, gestures) backed by `msgq`, host-testable |
| `drivers/gpio_keys.c` | portable GPIO button debouncer and gesture state machine (click, long, double, combo) |
| `boards/qemu-virt/board.c` | UART, Goldfish RTC and SiFive Test syscon registration, PLIC context and timer configuration |
| `sched.c` / `sched.h` | round-robin scheduler with cooperative and timer-driven switching |
| `sync.c` / `sync.h` | non-recursive mutex (`kmutex`) and bounded FIFO message queue (`msgq`), host-testable |
| `kmem.c` / `kmem.h` | first-fit kernel heap (split + coalesce), host-testable |
| `driver.c` / `driver.h` | fixed-size device/driver registration and probe, host-testable |
| `main.c` | bring-up, RTC boot timestamp and demo tasks for serial input and the clock |
| `boards/qemu-virt/linker.ld` | load at `0x80000000`, `.text/.rodata/.data/.bss`, 16 KiB stack |

## Current capabilities

- Boots on QEMU `virt`, single hart.
- Machine-mode traps use direct `mtvec`. An unhandled trap prints `mcause`,
  `mepc` and `mtval`, masks interrupt sources and parks the hart.
- CLINT machine timer: a periodic tick (100 Hz) via `MTIE` + global `MIE`, with a
  64-bit tick counter read protected from interrupts and safe RV32 `mtime`/`mtimecmp` access.
  Interrupts before the programmed deadline leave the counter and scheduler
  unchanged. A short handling delay preserves the periodic phase. If another
  period has already elapsed, the timer counts one tick and schedules from the
  current time. See the [RISC-V machine timer specification](https://docs.riscv.org/reference/isa/v20240411/priv/machine.html#machine-timer-registers-mtime-and-mtimecmp).
- External interrupts use the PLIC machine context for hart 0. A registered
  handler acknowledges its device before the controller completes the claim.
  The test triggers two UART transmit-ready interrupts through this path.
  See the [QEMU virt board description](https://www.qemu.org/docs/master/system/riscv/virt.html).
- UART console (`puts`/`puthex`/`putdec`/`getc`). The demo enables RX interrupts
  after trap setup. A waiting console task wakes when the receive queue becomes
  readable, including before the timer starts. A separate clock task sleeps
  between reports. The 64-byte receive ring buffer (`ringbuf`) preserves order
  and drops new bytes when full. TX uses polling.
  See the [emulated 16550](https://github.com/qemu/qemu/blob/master/hw/char/serial.c).
- Real-time clock (`rtc.c` and `drivers/goldfish_rtc.c`): QEMU virt registers
  and probes `rtc0` at `0x00101000` (PLIC IRQ 11) during `board_init`. Reads
  latch `TIME_LOW` before `TIME_HIGH` with interrupts masked. One-shot alarms
  write `ALARM_HIGH` before `ALARM_LOW` and invoke a registered callback from
  the PLIC handler after clearing the device interrupt. `rtc_unix_to_datetime`
  converts Unix timestamps to UTC calendar dates without libgcc division.
- Round-robin tasks can yield, exit, sleep for a number of timer ticks or query
  `task_current()`. The scheduler waits on the boot stack when all tasks sleep
  and reuses slots when tasks exit. Call `trap_init` before running tasks.
- A task can wait on a zero-initialized `task_event`. A signal wakes one waiter,
  or latches one pending signal if there are no waiters. Interrupt handlers can
  signal events. When all tasks block, the scheduler idles on the boot stack.
  `task_event_wait_for` adds a timeout in timer ticks. A zero timeout checks the
  latch immediately, and a signal at or after expiry can satisfy a later wait.
- Task synchronization (`sync.c`): `kmutex` provides non-recursive, owner-checked
  mutual exclusion with blocking and bounded-timeout waits (`kmutex_lock`,
  `kmutex_lock_for`, `kmutex_try_lock`, `kmutex_unlock`). `msgq` provides a
  fixed-size bounded FIFO message queue with ISR-safe `msgq_try_send`/`msgq_try_recv`
  and task-context blocking/timed `msgq_send`/`msgq_recv`.
- `sched_set_preemption(true)` enables one tick per time slice. The default is cooperative. Both modes save integer registers and the interrupt state in the task's trap frame and clear the hart's LR/SC reservation on a stack switch. A stack must have at least 272 bytes after alignment and enough space for the task's calls and trap handling. Tasks share machine-mode memory on hart 0. Serialize shared heap, registry and console access if using preemption.
- Kernel heap `kmalloc`/`kfree` (first-fit, block split, forward coalescing); the allocator logic is portable and unit-tested on the host (`make test-host`). Access must be serialized, including against interrupts.
- Device/driver registry: explicit name-based binding and retryable probe passes. QEMU virt registers and probes its console UART, Goldfish RTC and SiFive Test syscon (`0x00100000`, `board_poweroff`/`board_reboot`) before `kernel_main`. Registration is single-threaded and reset only clears registry bindings.
- Bus abstractions (`bus.c`): named registries and validated wrappers for GPIO (`configure`/`read`/`write`/`set_irq`), I2C (`transfer`/`write`/`read`/`write_read`/`reset`) and SPI (`transfer`/`write_then_read`).
- Watch input layer (`input.c`, `drivers/gpio_keys.c`): `input_post` (ISR-safe with auto-timestamping and drop accounting), `input_poll`/`input_wait`/`input_wait_for`, and a portable GPIO button debouncer/gesture engine supporting short click, double click, long press and simultaneous two-key combo events.

## Build and test

```sh
make                 # needs clang, ld.lld, llvm-objcopy
make LLD=/path/to/ld.lld   # if ld.lld is not on PATH (e.g. an LLVM/NDK toolchain)
make test            # needs qemu-system-riscv32; checks boot, echo, timer,
                     # scheduling, preemption, heap, traps, PLIC, sync, RTC and input/syscon on RV32 QEMU virt
make test-host       # host tests for heap, driver registry, ringbuf, sync, RTC and bus/input/syscon (clang + ASan/UBSan)
```

The build is linker-agnostic (any LLVM `ld.lld`); running the `test`/`qemu`
targets needs a *system* QEMU (`qemu-system-riscv32`), not the user-mode
`qemu-riscv32` static binaries.

## Next foundations

- Portable peripheral drivers on top of `bus.h` (LSM6DSO IMU over SPI, ZTW622 touch over I2C) and sensor sample delivery.
- Interactive console command shell and Bip 6 board scaffolding once the boot/recovery gate is resolved.
