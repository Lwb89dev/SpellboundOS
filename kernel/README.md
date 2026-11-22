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
| `kstring.c` | freestanding `memcpy`/`memmove`/`memset`/`memcmp` for RV32 |
| `ringbuf.c` / `ringbuf.h` | bounded byte ring buffer, host-testable |
| `drivers/uart16550.c` | interrupt-driven RX and polled TX for the QEMU virt UART |
| `drivers/plic.c` | external interrupt registration, claim and completion |
| `rtc.c` / `rtc.h` | primary RTC interface and freestanding Unix-to-UTC calendar conversion, host-testable |
| `drivers/goldfish_rtc.c` | Goldfish RTC wall clock and one-shot alarm IRQ driver |
| `drivers/sifive_test.c` | SiFive Test syscon poweroff/reboot driver for QEMU virt |
| `bus.c` / `bus.h` | hardware-independent GPIO, I2C and SPI bus abstractions, host-testable |
| `input.c` / `input.h` | watch input event queue (keys, touch, gestures) backed by `msgq`, host-testable |
| `drivers/gpio_keys.c` | portable GPIO button debouncer and gesture state machine (click, long, double, combo) |
| `sensor.c` / `sensor.h` | sensor sample delivery queue (`msgq`-backed) and 8-orientation 3D axis remap, host-testable |
| `drivers/lsm6dso.c` | portable LSM6DSO 6-axis IMU SPI driver (probe, reset, ODR/FS, tagged FIFO drain -> `sensor.h`) |
| `drivers/ztw622.c` | portable ZTW622 capacitive touch I2C driver (probe, 2-finger tracking, rotation, wake gestures -> `input.h`) |
| `drivers/stk31e60.c` | portable STK31E60 ambient light sensor I2C driver (probe, gain/IT config, DRDY poll -> `sensor.h`) |
| `drivers/charger.c` | portable CW6305 (`0x0B`) and AW32012 (`0x49`) I2C charger drivers with auto-probe and current encoding |
| `drivers/motor.c` | portable GPIO haptic vibration motor driver with level durations and non-blocking pattern sequencer |
| `fb.c` / `fb.h` | freestanding RGB565 2D framebuffer, dirty-rect tracking, geometric primitives and 5x7 ASCII font |
| `drivers/icna3311.c` | portable Chipone ICNA3311 AMOLED MIPI DCS panel driver (9-variant probe, brightness/HBM, dirty-rect flush) |
| `notify.c` / `notify.h` | watch notification store (16 items + 4 actions), Roadstr turn-by-turn nav state and call state |
| `proto.c` / `proto.h` | SpellboundFit v1 binary framed companion protocol with IEEE CRC-32, streaming decoder and dispatch |
| `shell.c` / `shell.h` | freestanding interactive serial command shell (`help`, `uptime`, `date`, `heap`, `notify`, `nav`, `poweroff`, `reboot`) |
| `power.c` / `power.h` | screen power state machine (`ACTIVE`/`DIM`/`AOD`/`SLEEP`), ALS auto-brightness curve and ICNA3311 sync |
| `ui.c` / `ui.h` | watch UI compositor (watchface, notifications, Roadstr turn-by-turn navigation, call screen, quick settings) |
| `kv.c` / `kv.h` | power-fail-safe append-only log key-value settings store with CRC-32 records and compaction |
| `activity.c` / `activity.h` | pure-integer IMU pedometer (step counter + cadence filter) and wrist-raise wake detector |
| `drivers/ag3335.c` | portable Airoha AG3335M GNSS PAIR command framer, `PAIR001` ACK and fixed-point NMEA RMC/GGA parser |
| `drivers/max8617x.c` | portable MAX8617X optical PPG/SpO2 SPI driver (10-bit FIFO count, big-endian 20-bit signed decode, recovery) |
| `hr.c` / `hr.h` | pure-integer PPG heart-rate estimator (40..220 BPM, median-of-5 IBI filter, flatline drop -> `sensor.h`) |
| `watch_app.c` / `watch_app.h` | unified watch runtime loop integrating input, sensors, activity, proto, KV settings, power, haptics and UI |
| `boards/bip6/board_desc.h` | read-only Bip 6 (`mhs003`) hardware inventory constants from verified analysis reports |
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
- Sensor delivery and portable peripheral drivers (`sensor.c`, `drivers/lsm6dso.c`, `drivers/ztw622.c`): bounded `msgq`-backed `sensor_sample` queue with 8-orientation 3D remap; LSM6DSO SPI IMU driver (WHO_AM_I `0x6C`, soft-reset polling, dual-stream XL/GYRO config, 7-byte tagged FIFO drain with overrun recovery); ZTW622 I2C touch driver (`0x20`, chip ID `0xE622`, I2C bus-reset retry, 2-finger DOWN/MOVE/UP state tracking, 0°/90°/180°/270° rotation + 180° flip, large-object and wake-gesture dispatch to `input.h`).
- Ambient light, battery charging, haptics and display stack (`drivers/stk31e60.c`, `drivers/charger.c`, `drivers/motor.c`, `fb.c`, `drivers/icna3311.c`): STK31E60 I2C ALS (`0x48`, ID `0xE0`, integer IT/gain/lux conversion); CW6305 (`0x0B`) & AW32012 (`0x49`) I2C chargers with runtime auto-probe, piecewise fast-charge current encoders and VBUS/poweroff controls; GPIO haptic motor with level durations and tick-driven patterns; RGB565 2D framebuffer with dirty-rect tracking and 5x7 scalable ASCII font; ICNA3311 MIPI DCS AMOLED driver (RDID1–3 9-variant check, page-0 unlock/lock brightness/dimming/HBM, even-aligned dirty-rect RAM flush).
- Watch services, companion protocol and interactive shell (`notify.c`, `proto.c`, `shell.c`): 16-slot notification store with unread tracking, oldest-eviction and action callbacks; Roadstr turn-by-turn navigation and incoming call state stores; SpellboundFit v1 binary framed protocol (`"SB"`, IEEE CRC-32, streaming byte-by-byte decoder, dispatch for `PING`/`TIME_SYNC`/`NOTIFY_POST`/`NOTIFY_DISMISS`/`NAV_UPDATE`/`NAV_CLEAR`/`CALL_STATE` and watch-to-phone `NOTIFY_ACTION`/`TELEMETRY` encoders); extensible serial shell with line editing and quoted arguments.
- Power manager, watch UI compositor and Bip 6 hardware map (`power.c`, `ui.c`, `boards/bip6/board_desc.h`): `ACTIVE`/`DIM`/`AOD`/`SLEEP` screen manager with pure-integer piecewise ALS auto-brightness curve (24..255 + HBM >= 245) applied to `icna3311`; RGB565 compositor rendering watchface (RTC clock, battery, unread badge, steps/HR, AOD), notifications with quick actions, Roadstr turn-by-turn navigation (geometric maneuver arrows + distance + street + ETA), incoming call screen and quick settings; read-only Bip 6 (`mhs003`) hardware inventory constants header.
- Persistence, activity tracking and companion protocol interop (`kv.c`, `activity.c`, `companion/protocol.py`, `companion/roadstr.py`): CRC-32 append-only key-value settings store with torn-write recovery and compaction; pure-integer pedometer (3-step cadence confirmation, distance/calories) and wrist-raise wake detector; Python SpellboundFit v1 protocol codec + Roadstr English/Italian notification parser verified end-to-end against `kernel/proto.c`.
- GNSS driver and unified watch runtime (`drivers/ag3335.c`, `watch_app.c`): Airoha AG3335M `$PAIR<code>[,<params>]*HH\r\n` framing with verified XOR checksums (`002`/`003`/`066`/`104`), `PAIR001` ACK parsing and fixed-point NMEA `$GxRMC`/`$GxGGA` microdegree position/altitude/speed decoding; `watch_app` vertical-slice orchestrator connecting input, sensors/activity, companion protocol, KV settings, power, haptic patterns, UI rendering, ICNA3311 dirty-rect flushes and periodic telemetry.
- Optical PPG and heart-rate pipeline (`drivers/max8617x.c`, `hr.c`): MAX8617X SPI driver implementing 10-bit FIFO count (`((reg3 & 0xC0) << 2) | reg4`), `0x08 0x80` burst FIFO read, big-endian 20-bit signed sample decoding, frame alignment and overflow recovery (`0x09`/`0x0D`); pure-integer PPG heart-rate estimator (40–220 BPM, median-of-5 IBI filter, skin-contact flatline invalidation) publishing `SENSOR_HEART_RATE`.

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

- Android SpellboundFit companion app scaffolding (NotificationListenerService + Roadstr bridge + BLE GATT transport speaking SpellboundFit v1 binary protocol).
- Bip 6 device bring-up once the signed boot, backup and recovery gate is resolved.
