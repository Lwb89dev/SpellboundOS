# GPIO pad multiplexer, shared IRQ handler and per-pin callback dispatch

All **18 native cases** pass in **2,405 instruction steps**. This scope
executes three original main-image bodies that form a GPIO/pad controller:

- the pad multiplexer `0x80d42c84`;
- the GPIO interrupt dispatcher `0x80d436b4`;
- the shared interrupt handler `0x70293d50`, which registration bound to PLIC
  sources 9, 10 and `0x2a`–`0x2d` in [MAIN_TRAP_IRQ_DISPATCH.md](MAIN_TRAP_IRQ_DISPATCH.md).

Everything runs over authored controller structs, authored MMIO banks and an
authored 16-row callback table; the registered per-pin handlers are supplied
return stubs. The evidence is in [main-gpio-dispatch.json](main-gpio-dispatch.json).
It reuses and re-pins the trap/PLIC ranges, so no earlier golden export or
report changes.

## Pad multiplexer

`0x80d42c84(base, pin, value)` writes a 4-bit field for one pin into a pad
configuration register. The controller base selects a register bank:

| Controller base | Pad bank | Notes |
| --- | --- | --- |
| `0x91003000` | `0x91000080` | from the table at `0x80d4744c` |
| `0x91004000` | `0x91000090` | from the table |
| `0x98005000` | `0x910000a0` | from the table |
| `0x9a00a000` | `0x910000b0` | direct; the pin is bounded to `<= 4` |

Within a bank, the register is `bank + (pin >> 3) * 4` and the field is at
`(pin & 7) * 4` bits. The body reads the register, clears that nibble and sets
the low 4 bits of `value`, leaving every other nibble intact. An unknown base,
or a pin above 4 on the direct controller, writes nothing. Eight pins share a
32-bit register, four bits each. The bank base table is verified to be
`{0x91000080, 0x91000090, 0x910000a0}`.

## GPIO interrupt dispatcher

`0x80d436b4(controller)` reads the pending mask at `controller + 0x28`. If it
is zero it returns. Otherwise, for each set bit from 0 to 31, it searches the
16-row callback table at `0x80c118c8` (each row is `0x18` bytes) for a row whose
base equals the controller and whose bit equals the pin. On a match it:

- writes `(1 << bit)` to `controller + 0x30` (the per-pin acknowledge);
- records the pin in the trace word `0x80dff7bc` when tracing is enabled;
- calls the row's handler at offset `0x10` with `(arg0 at +8, arg1 at +0x14)`
  when the handler is non-zero.

The table row layout is `{base (+0), bit (+4), arg0 (+8), reserved (+0xc),
handler (+0x10), arg1 (+0x14)}`. A pending bit with no matching row, or a
matching row with a null handler, produces no call; a matching row's
acknowledge is still written. Bits are served in ascending order. When the
trace flag `0x80c07fac` is set at entry, the dispatcher first records the
pending mask at `0x80dff7c4` (base) and `0x80dff7c0` (pending), in that order.

## Shared interrupt handler

`0x70293d50(base)` is registered for PLIC sources 9, 10 and `0x2a`–`0x2d`
(bases `0x91003000`, `0x91004000`, `0x98005000`, `0x9a00a000`–`0x9a00c000`).
For bases `0x91003000` and `0x91004000`, when `0x90008020` bit 12 is set, it
performs the clock/PM wake poke documented in
[MAIN_PM_WAKE.md](MAIN_PM_WAKE.md) (set and restore `0x90008000`, toggle bit 4
of `0x90008014` and bit 16 of `0x91000004`, with a bounded delay). On every
path it then tail-calls the dispatcher `0x80d436b4`. The native evidence
confirms both tail-call sites (`auipc`/`jr`) resolve to the dispatcher with an
independent decoder.

## Cases

| Group | Cases | Selected observations |
| --- | ---: | --- |
| Pad mux | 8 | Each bank; direct controller and its pin bound; unknown base ignored; high pin selects a higher word; only the addressed nibble changes |
| Dispatcher | 7 | No pending; one registered pin; traced; unregistered bit; null handler; two pending in bit order; wrong-base row skipped |
| Shared | 3 | Wake then dispatch; bit 12 clear dispatches only; another base never wakes |

Every executed PC is inside a hash-guarded original range or a supplied stub.
The runner records every store, every CSR access and every handler call. The
independent Python model reproduces all of them.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_gpio_dispatch --vectors-output firmware/main-gpio-dispatch-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainGpioDispatch.java firmware/main-gpio-dispatch-vectors.json \
  firmware/main-gpio-dispatch-validation.json
python3 -m analysis_scripts.main_gpio_dispatch firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-gpio-dispatch-vectors.json --validation firmware/main-gpio-dispatch-validation.json \
  > analysis/main-gpio-dispatch.json
```

The vectors, native report and evidence regenerate byte for byte.

Remaining work:

- Recover the routine that populates the callback table `0x80c118c8` (the GPIO
  interrupt registration) and the pins each row serves.
- Follow the bulk pad-configuration applier at `0x80d42cfc`, which iterates all
  32 pins across the four controller bases.
- Establish the controller struct layout, the physical pin assignments and the
  edge/level configuration registers from board evidence.
