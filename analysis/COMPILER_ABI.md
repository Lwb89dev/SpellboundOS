# Register-save ABI and a second decompilation failure mode

The main image contains four shared register-save paths and four matching
restore paths. Their behavior is visible in ordinary RV32 instructions, with
no Andes custom opcode needed in the stubs themselves. These are compiler
prologue/epilogue candidates, not health-service functions.

| Save entry | Restore entry | Frame bytes | Saved registers |
| --- | --- | ---: | --- |
| `0x70946264` | `0x709462a0` | 64 | `ra`, `s0`–`s11` |
| `0x7094626c` | `0x709462a4` | 48 | `ra`, `s0`–`s10` |
| `0x7094627a` | `0x709462ae` | 32 | `ra`, `s0`–`s6` |
| `0x70946294` | `0x709462b8` | 16 | `ra`, `s0`–`s2` |

Save calls use `AUIPC t1; JALR t0,t1,imm`, and the stub exits through `JR t0`.
Restore paths are entered by a tail jump and return through the restored `ra`.
Neither path changes the argument registers `a0`–`a7`; restores also preserve
the result in `a0`/`a1`.

[`riscv_save_restore.py`](../analysis_scripts/riscv_save_restore.py) includes a
strict, bounded host interpreter for only the stack/register instructions in
these stubs. Each pair is checked for stack balance and restoration of distinct
test register values after a simulated body changes saved registers. The body
is not firmware code. Unsupported instructions, unknown stack reads, truncated
instructions and unbounded loops are rejected. This validates the observed
instruction effects, not application behavior or the rest of the ABI.

## Impact on the broad corpus

The byte scan finds 3,961 candidate save references and 3,956 candidate restore
references. Counts differ because the scan is not a function/call-graph
analysis. It scans two-byte boundaries including data and can miss other call
forms. There are 2,064 main-image C exports mentioning these helpers. Not every
such export has been individually shown incorrect.

Concrete failures include:

- `0x703d4752` is exported as `void`, with a final call to `0x709462b8`.
  Its instructions actually save registers, call `0x7022bc46`, pass its
  result to `0x7022bf16`, then restore registers while preserving the result.
- `0x703d5a0a` saves its incoming `a0` on the stack, obtains a service context
  from `0x70248018`, reloads the original argument into `a1`, calls
  `0x7024814c`, then returns through the restore path. The pseudocode loses
  that argument relationship.
- `0x70247684` derives apparent inputs from a fictitious return value of
  `0x70946294`; the stub does not produce such a value.

This is separate from the falsely non-returning logger already documented in
[DISPLAY_AND_LIGHT.md](DISPLAY_AND_LIGHT.md). A completed decompilation can
therefore have both truncated control flow and incorrect register/stack models.
The old function counts remain an inventory, not reliable semantic coverage.

## Reproduction

```sh
python3 analysis_scripts/riscv_save_restore.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/main > analysis/riscv-save-restore.json
python3 -m unittest discover -s tests -p 'test_riscv_save_restore.py' -v
```

The [JSON inventory](riscv-save-restore.json) records helper checks, candidate
reference addresses, the main-member and stub-region hashes, and source-text
hashes for affected corpus files. Six independent synthetic-fixture tests cover
the bounded interpreter and reference scan. LLVM disassembly of the stubs and
the example callers provides a second inspection path; use the ELF preparation
in [SENSOR_CLASSES.md](SENSOR_CLASSES.md) and offsets `0x7e6264`–`0x7e62c4`.

A future Ghidra pass needs to model these paths as caller prologue/epilogue
effects (including the alternate return register), and fix the logger's call
effects, before regenerating selected functions. Merely renaming the stubs or
changing their return type does not repair the stack/register model. No broad
corpus repair has yet been performed. A subsequent bounded 12-function pass
implements all four fixups in a fresh project; see
[NATIVE_REPAIR.md](NATIVE_REPAIR.md) for recovered arguments, remaining warnings
and the reproducible script.
