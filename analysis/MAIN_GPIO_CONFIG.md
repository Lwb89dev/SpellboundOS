# GPIO pull/drive pad writer and interrupt enable/commit

All **13 native cases** pass in **895 instruction steps**. This scope extends
[MAIN_GPIO_DISPATCH.md](MAIN_GPIO_DISPATCH.md) with two more original
main-image bodies of the GPIO/pad controller:

- the pull/drive pad writer `0x80d42fcc`;
- the interrupt enable/commit routine `0x80d43774`.

Both run over authored controller structs, authored MMIO banks and an authored
16-row callback table (the same table at `0x80c118c8` the dispatcher walks).
The configuration gate `0x80d341d8`, the scheduler-state reader `0x80d362b0`
and the critical save/restore wrappers `0x80d379ee`/`0x80d37a1a` — all covered
elsewhere — are supplied return stubs. The evidence is in
[main-gpio-config.json](main-gpio-config.json). It reuses and re-pins the
trap/PLIC ranges, so no earlier golden export or report changes.

## Pull/drive pad writer

`0x80d42fcc(base, pin, value, _, _, base0)` writes a 2-bit field for one pin
into a pad configuration register. It is a sibling of the pad multiplexer: a
different bank table and a different field width. The first controller base is
passed as the sixth argument (`base0`); the others are compared against
constants.

| Controller base | Pull bank |
| --- | --- |
| `base0` (`0x91003000`) | `0x91000100` |
| `0x91004000` | `0x91000120` |
| `0x98005000` | `0x91000140` |
| `0x9a00a000` | `0x91000160` (direct; pin bounded to `<= 4`) |

The register is `bank + (pin >> 2) * 4` — four pins per 32-bit register, an
8-bit slot each. The written field is bits 4–5 of the slot: the body clears
`0x30 << ((pin & 3) * 8)` and sets `(value & 0x30) << ((pin & 3) * 8)`. Only
bits 4–5 of `value` survive. An unknown base, or a pin above 4 on the direct
controller, writes nothing. The bank table at `0x80d4745c` is verified to be
`{0x91000100, 0x91000120, 0x91000140}`.

The companion pad multiplexer `0x80d42c84` writes a 4-bit field (one pin per
8-bit slot, banks `0x91000080`/`0x90`/`0xa0`/`0xb0`); this writer writes a 2-bit
field in a different bank set. The two configure different pad properties of the
same pins.

## Interrupt enable/commit

`0x80d43774()` walks all 16 rows of the callback table at `0x80c118c8`. For
each row with a non-zero handler it enables that pin on its controller:

1. writes `(1 << bit)` to `controller + 0x30` (acknowledge);
2. calls the gate `0x80d341d8` (its result selects the handshake value) and the
   scheduler-state reader `0x80d362b0`, storing the state at `0x80c11730`;
3. when the state is non-zero, wraps the commit in the critical save wrapper
   `0x80d379ee(0x80c11734)` and, after it, the restore wrapper
   `0x80d37a1a(*0x80c11734)`;
4. the commit itself: spins while `0x900080b0` is non-zero, writes the handshake
   value (`2` when the gate returned non-zero, else `1`), re-reads until it
   matches, clears the pin bit in `controller + 0x20` (disable mask), sets it in
   `controller + 0x2c` (enable), then writes `0` back to `0x900080b0`.

So `controller + 0x30` is a per-pin acknowledge, `controller + 0x20` a disable
mask that is cleared to enable, and `controller + 0x2c` the enable register.
`0x900080b0` is a commit handshake that must be observed idle before, and is
released after, each pin is enabled. The critical wrapping is applied only when
the scheduler-state reader reports a non-zero state.

## Cases

| Group | Cases | Selected observations |
| --- | ---: | --- |
| Pull writer | 7 | Each bank; direct controller and its pin bound; unknown base ignored; `(pin>>2)` register select; value masked to bits 4–5 |
| Enable | 6 | No registered rows; one pin with state zero; gate-set handshake value 2; state non-zero wraps critical; unregistered rows skipped; two pins on distinct controllers |

Every executed PC is inside a hash-guarded original range or a supplied stub.
The runner records every store, every CSR access and every callee call with its
arguments, and supplies the gate/state return values in sequence. The
independent Python model reproduces all of them.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_gpio_config --vectors-output firmware/main-gpio-config-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainGpioConfig.java firmware/main-gpio-config-vectors.json \
  firmware/main-gpio-config-validation.json
python3 -m analysis_scripts.main_gpio_config firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-gpio-config-vectors.json --validation firmware/main-gpio-config-validation.json \
  > analysis/main-gpio-config.json
```

The vectors, native report and evidence regenerate byte for byte.

Remaining work:

- Recover the registration routine that populates `0x80c118c8` (the row writer),
  so the enable routine has real controller/pin/handler entries.
- Execute the scheduler-state reader `0x80d362b0` and its handshake meaning
  against a modeled `0x900080b0` responder rather than an idle register.
- Follow the callers of the enable routine (startup and the dynamic
  `0xb`/`0xc`/`0xe` re-registration wake path) and establish the physical pin
  roles from board evidence.
