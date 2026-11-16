# AndeStar v5 decoding investigation

Latest pass: [corrected native IPC analysis](RPMSG_NATIVE_AND_FRAGMENTS.md)
records an exact-hash-guarded local BBS repair, rebuilt Sleigh language and
36 fresh targeted exports. The broader corpus remains unaudited.

Follow-up: [zrpc branches](ZRPC_BRANCHES_AND_MEMORY.md) identifies a concrete
Ghidra 12.1.2 `bbs` predicate defect for bit indices above zero. Selected native
branches are independently decoded there. Profile selection alone does not
resolve this defect; older affected pseudocode needs review.

The earlier generic `RISCV:LE:32:default` imports decoded many extension words
as `custom2`, dropping essential register and branch effects. Ghidra 12.1.2
ships a separate `RISCV:LE:32:AndeStar_v5` language. A fresh import using it
produced coherent additional control flow in independent routines:

- Main `0x703cd15a`: checks the return of the initial read against `0x48`,
  tests the first two bytes for `GM`, checks a size field, and counts set bits
  in a 32-bit header field. The prior result ended after the read.
- Main `0x7041c89e`: compresses the SHA-256 context when its buffer reaches
  64 bytes. The prior generic result omitted the condition.
- Main `0x70163860`: waits for the value at `0x90008084` to become 1, bounded
  by a time comparison. The prior result omitted the state comparison.

This is strong evidence that the AndeStar profile is useful for these bytes.
It does not establish the exact CPU model, all extensions, physical addresses,
or complete correctness of Ghidra's inferred code. In particular, some exported
functions have suspicious empty loops or unresolved external calls even with
this profile, and need instruction-level review. One empty checksum loop was
subsequently resolved by assigning its return type and arguments explicitly;
see RADIO_PACKAGE.md. This shows that decoder selection alone is insufficient.

The language definition and instruction semantics used are the files
`Ghidra/Processors/RISCV/data/languages/andestar_v5.ldefs` and
`andestar_v5.instr.sinc` in the local Ghidra 12.1.2 distribution. These define
`beqc` and `bnec` in the custom-2 opcode space. Opcode 0x5b alone cannot identify
a vendor: the slot is generally available for custom instructions.

## Reproduction

Use the existing `DecompileFunctions.java` script and the main image import
command in the earlier reports, replacing the processor argument with
`RISCV:LE:32:AndeStar_v5`, and use a fresh project. Pass addresses
`0x703cd15a 0x70163860 0x7041c89e` to reproduce these comparisons.

`analysis_scripts/decompile_ota.py --ghidra /absolute/path/to/analyzeHeadless`
starts a larger analysis of the bootloader payload, recovery, sensor hub,
factory firmware, main firmware and the ramdump diagnostic executable. Analysis budgets are 300 seconds per smaller image and 1800 seconds for the main
image; each recognized function gets up to 10 seconds for decompilation.
An analysis timeout can leave functions undiscovered. The script preserves
exit codes, discovered function counts and decompiler completion counts locally.
Decompiler completion means pseudocode was emitted, not that it is correct or
that every executable byte has been found. The resulting pseudocode and Ghidra
projects remain under ignored `firmware/`.
