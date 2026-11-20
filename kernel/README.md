# SpellboundOS kernel

An independently authored RV32 kernel, QEMU `virt` first (see [GOAL.md](../GOAL.md)).
This is bring-up scaffolding, not a Bip 6 image.

## Layout

| File | Role |
| --- | --- |
| `arch/riscv/start.S` | reset entry: park secondary harts, set `gp`/`sp`, zero `.bss`, call `kernel_main` |
| `arch/riscv/trap.S` | machine-mode trap vector: save caller-saved registers, call `trap_handler`, restore, `mret` |
| `arch/riscv/trap.c` | `trap_init` (install `mtvec`, direct mode) and `trap_handler` (timer IRQ → tick; exceptions reported and parked) |
| `arch/riscv/timer.c` | CLINT machine timer (`mtime`/`mtimecmp`), periodic tick at a chosen Hz |
| `arch/riscv/riscv.h` | CSR access helpers and bit definitions |
| `console.c` / `console.h` | 16550 UART console (QEMU virt; the Bip 6 UART is separate) |
| `main.c` | bring-up: console → traps → polled echo → 100 Hz timer → tick loop |
| `boards/qemu-virt/linker.ld` | load at `0x80000000`, `.text/.rodata/.data/.bss`, 16 KiB stack |

## Current capabilities

- Boots on QEMU `virt`, single hart.
- Machine-mode trap handling (direct `mtvec`); synchronous exceptions print
  `mcause`/`mepc` and park.
- CLINT machine timer: a periodic tick (100 Hz) via `MTIE` + global `MIE`, with a
  64-bit tick counter and safe RV32 `mtime`/`mtimecmp` access.
- UART console (`puts`/`puthex`/`putdec`/`getc`), polled echo.

## Build and test

```sh
make                 # needs clang, ld.lld, llvm-objcopy
make LLD=/path/to/ld.lld   # if ld.lld is not on PATH (e.g. an LLVM/NDK toolchain)
make test            # runs tests/qemu_boot.py (needs qemu-system-riscv32):
                     #   verifies boot, UART echo and the first timer tick
```

The build is linker-agnostic (any LLVM `ld.lld`); running the `test`/`qemu`
targets needs a *system* QEMU (`qemu-system-riscv32`), not the user-mode
`qemu-riscv32` static binaries.

## Next foundations

- A cooperative/preemptive task abstraction driven by the timer tick.
- A small heap/allocator and a device/driver registration model.
- Board abstraction so the same core runs on QEMU and (later) the Bip 6.
