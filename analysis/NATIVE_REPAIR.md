# Targeted startup/ABI-aware decompilation

A fresh Ghidra project imports the startup-aware main ELF. The script
[`DecompileWithAbi.java`](../analysis_scripts/DecompileWithAbi.java) installs
program-local p-code fixups for all four verified save/restore pairs, marks
the logger as returning, and exports explicit targets. Image bytes are not
patched. A SHA-256 guard checks the 96-byte stub region before installation.
Tail jumps into restore helpers get call/return flow overrides. These changes
affect analysis metadata, not device execution.

The fixups model stack allocation, saved-register stores/loads, save-helper
`t1` effects and the restore's final return. The bounded instruction model in
[COMPILER_ABI.md](COMPILER_ABI.md) independently checks those effects.

## Results

The pass emits 12 targets, ten with matching old C files. The comparison is
[native-repair-summary.json](native-repair-summary.json): non-returning-call
warnings fall from nine to zero, and assignments from fictitious save-helper
results fall from five to zero. These diagnostics do not prove semantic
correctness. New injection/unreachable-block warnings remain, some return
types are underspecified, and some call targets remain unseeded. The broad
corpus is unchanged.

Recovered relationships include:

- `0x703d5950`: two incoming SpO2 registration arguments are preserved and
  passed alongside the acquired service context to `0x70248048`.
- `0x703d5a0a`: the SpO2 last-record output pointer reaches `0x7024814c`.
- `0x70247684`: context and output-pointer arguments replace the old fictitious
  pointer obtained from a register-save helper.
- `0x7022d83e`: two explicit HR last-value service inputs are recovered.
- `0x7045a85a`: the HR `today` array-building loop is visible past the logger.
- `0x80d361fc`: a relocated allocation wrapper can be analyzed at its startup
  destination, rather than as an unmapped address.

## Glucose records past the logger

The recovered `0x70456dce` body converts a JS argument to a number, allocates
a type-1 record through `0x7030007e(1,1)`, associates the app ID, stores the
value as a float, calls `0x70300100(1,record)`, frees the temporary record and
can schedule a change event. It returns a tagged boolean from the write
result. Callback `0x70456be2` emits the sensor change event.

The old `0x70300100` export corroborates a record-service write via an indirect
callback, with time filling when required, but is itself affected by the ABI
and logger defects. The full schema/persistence backend still need recovery.
This add operation consumes an app-supplied value; it does not establish
optical glucose sensing or exclude other sources feeding the record store.

## Reproduction

Ghidra 12.1.2 was reacquired from the
[official release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build).
The archive SHA-256 matched the published value
`b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d` before
extraction. Installation/preferences/cache stay under `/tmp`; projects and
vendor-derived exports stay under ignored `firmware/`.

After generating the startup-aware ELF:

```sh
mkdir -p firmware/ghidra-runtime
/path/to/ghidra/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -import firmware/main-runtime.elf -processor RISCV:LE:32:AndeStar_v5 \
  -cspec gcc -noanalysis -scriptPath analysis_scripts \
  -postScript DecompileWithAbi.java firmware/decompiled/runtime-main \
  0x703d4752 0x703d5a0a 0x703d5950 0x70247684 0x80d361fc \
  0x7022d83e 0x7045a85a 0x7045ddbc 0x7045bf06 0x70456dce \
  0x70248048 0x80d3c2f4
python3 analysis_scripts/summarize_native_repair.py \
  --before firmware/decompiled/main --after firmware/decompiled/runtime-main \
  > analysis/native-repair-summary.json
```

The session used a five-target first pass then a 12-target pass on that saved
fresh project. For the latter, replace `-import ...` with
`-process main-runtime.elf`. Logs are `firmware/ghidra-runtime-main-stdout.log`
and `firmware/ghidra-runtime-main-pass2-stdout.log`. The JSON records exact
source-text hashes. Inferred C names/types can depend on analysis history;
identical C output from a different history is not promised.

The Python instruction checks, ELF checks, LLVM inspection and successful
Ghidra execution validate separate layers. None is a full firmware or hardware
behavioral test.

## Floating-point emulation defects (2026-11-20)

The sensor-hub IMU scopes found two defects in Ghidra 12.1.2's RV32 SLEIGH
floating-point semantics. Both were confirmed with single-step traces:

- `c.fsw` stores the whole 64-bit FP register (8 bytes) instead of 4. The
  emulator does not NaN-box, so the upper half is zero. The stored low 4 bytes
  are the correct IEEE binary32. The IMU attach model records the 8-byte
  emulator write explicitly
  ([SENSORHUB_IMU_INIT.md](SENSORHUB_IMU_INIT.md)).
- `fcvt.wu.s rd, fs, rtz` computes `TRUNC` into a p-code temporary and never
  writes `rd`, so `rd` keeps its old value. The IMU runner repairs only the
  reviewed site `0x80f701a8` with the RISC-V semantics (round toward zero,
  saturating). It records the repair as a `fix:<pc>:<value>` action
  ([SENSORHUB_IMU_MODE.md](SENSORHUB_IMU_MODE.md)).

Other native scopes that execute FP stores or FP-to-integer conversions should
check for the same defects before trusting the emulator's results.
