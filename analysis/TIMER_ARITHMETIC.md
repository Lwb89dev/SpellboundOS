# Andes DSP, unsigned division and IPC timer scaling

Follow-up: [RTOS timer and suspension](RTOS_TIMER_AND_SUSPEND.md) recovers
distinct main/sensor raw intervals and counter rebasing during sleep.
The numeric conversion below does not imply continuity across power states.

The previously truncated helper at `0x70945b3c` is now decoded throughout its
reviewed body and checked by executing its native instructions as corrected
SLEIGH p-code. The scaled counter reader returns `floor(raw_unsigned_64/1000)`.
This closes the arithmetic uncertainty recorded in
[clock/cache contracts](CLOCK_AND_CACHE_CONTRACTS.md); physical timer frequency
and live timeout duration remain open.

## Two missing DSP semantics

Ghidra 12.1.2's packed-instruction table has `pkbb16` and `maddr32` forms with
opcode `0x3f` and `unimpl` semantics. The watch helper uses opcode `0x7f`.
Ordinary RV32 multiply/divide instructions already worked; changing the
generic M extension was not the missing step.

The opcode and function fields agree with the
[andes-riscv package's own source](https://github.com/hpmicro-rs/andes-riscv/blob/main/src/dsp.rs).
Its reviewed snapshot is retained under ignored `firmware/tool-evidence/`,
SHA-256 `fbf427bbf3b64c034d79956adbb3661afe246beee235d412086ba36951edab4d`.
The independent [NMSIS intrinsic documentation](https://doc.nucleisys.com/nmsis/doxygen/core/html/group__NMSIS__Core__DSP__Intrinsic__NON__SIMD__MISC.html)
also describes the RV32 multiply-and-accumulate operation. These references
support instruction interpretation; they do not establish the watch's exact
CPU model or every extension it implements.

| Operation | Masked encoding (`word & 0xfe00707f`) | RV32 result |
| --- | --- | --- |
| `pkbb16 rd,rs1,rs2` | `0x0e00107f` | `((rs1 & 0xffff) << 16) \| (rs2 & 0xffff)` |
| `maddr32 rd,rs1,rs2` | `0xc400107f` | low 32 bits of `old_rd + rs1*rs2` |

There are four pack sites at `0x70945bd4`, `0x70945cc6`, `0x70945d7e`,
`0x70945e08`, and one accumulation site at `0x70945e48`. Some destinations
alias a source register. Authored SLEIGH expressions preserve input values
before assignment and handle 32-bit truncation.

[repair_ghidra_dsp.py](../analysis_scripts/repair_ghidra_dsp.py) accepts only
the exact BBS-corrected Ghidra source, appends these two RV32 forms and is
idempotent. It leaves the earlier BBS fix intact. It does not enable the rest
of the DSP instruction family. The resulting source hash is
`aee5ee54eef0c31a8cba18035596de361be7caf253dca63f38727b5ef97f4fc9`;
compiled `andestar_v5.sla` hash is
`aca3cd4069bc22d200a8c5dcf79839a9cbe78de56416b0abe2b635f855cb60fa`.

## Native execution against an independent division oracle

[SeedTimerArithmetic.java](../analysis_scripts/SeedTimerArithmetic.java)
fingerprints the `0x3a4`-byte body, replaces its stale analysis metadata and
redisassembles it with the corrected language. `SeedClockCache.java` restores
the unsigned 64-bit register-pair arguments/return. New exports are retained
in ignored `firmware/decompiled/runtime-timer-arithmetic/`; earlier export
directories and their reports remain unchanged.

The helper's branches implement normalized halfword quotient estimation and
correction for unsigned 64-bit division. Its 256-byte lookup table at
`0x709babf8` is also fingerprinted. Both the helper and scaled-reader exports
now complete without bad-instruction truncation or decompiler warnings.
The selected IPC caller still has `extraout` register-pair artifacts, so raw
instructions remain the authority for its wide subtraction/comparison.

[ValidateTimerArithmetic.java](../analysis_scripts/ValidateTimerArithmetic.java)
executes the guarded native helper with Ghidra's emulator and compares results
to Java `Long.divideUnsigned`. It checks the return target and stack pointer,
bounds execution to 512 instructions per call, and rejects control flow outside
the helper or the selected reader. Inputs include all pairs of powers of two
and their neighbors, seeded random full-width/32-bit/variable-width divisors,
and the timer divisor 1000. The reader additionally executes its stack and
stable synthetic MMIO snapshot path before calling the same helper.

The recorded run passes **52,294 division cases and 200 reader cases**.
Every DSP site executes. Actual step totals, per-site counts, conditional
edges and unvisited helper instruction addresses are recorded in
[timer-arithmetic.json](timer-arithmetic.json). This is bounded host execution
using the authored instruction semantics, not a silicon conformance test or
an exhaustive proof. Division by zero is excluded. The MMIO inputs are stable;
the asynchronous high-word retry path is not exercised by this run.

## Timeout scale, phase and rollover

Let `R` be the unsigned 64-bit high/low/high memory-counter snapshot.
The reviewed main reader at `0x80d45464` returns:

```text
T(R) = floor(R / 1000)
```

The selected IPC wait at `0x707bf7e0` expires when its unsigned 64-bit
reader difference is at least 1000. Conversion occurs on **each snapshot**
before subtraction, rather than on their raw difference:

```text
expired = ((T(now_raw) - T(start_raw)) mod 2^64) >= 1000
```

Without raw-counter rollover, the first threshold crossing is
`1,000,000 - (start_raw mod 1000)` raw ticks after the start. That is
999,001–1,000,000 ticks. Poll order, polling latency and scheduling may delay
observation; this formula is the numeric threshold, not a guaranteed deadline.
It cannot yet be labeled one second: the physical counter rate has not been
measured or established by a complete clock-source configuration path.

Raw-counter rollover and scaled-reader rollover are different. After raw
`2^64-1` wraps to zero, unsigned subtraction of the scaled values yields a
large difference. The host predicate preserves that observed arithmetic and
does not reinterpret it as a short elapsed interval. The interval helper
rejects threshold calculations that would cross raw rollover.

`wait_expired` in the earlier IPC model accepts **reader values**. The new
[timer_arithmetic.py](../analysis_scripts/timer_arithmetic.py) supplies the
explicit raw-snapshot conversion and phase-aware threshold model. Nine host
tests cover all 1000 phases, unsigned boundaries, raw wrap, opcode masks and
the guarded source repair. No device register, clock or firmware was changed.

## Reproduction

On a clean Ghidra 12.1.2 installation, first apply the existing BBS repair,
then run `repair_ghidra_dsp.py` on `andestar_v5.instr.sinc` and recompile
`andestar_v5.slaspec` using Ghidra's `support/sleigh`. The old BBS-only evidence
reports describe that earlier language stage and retain their original hashes.
On this already corrected installation, rerun only the idempotent DSP script;
the BBS-only repair intentionally rejects a source with additional changes.

On the startup-aware `firmware/ghidra-bbs main-bbs` project, process
`main-runtime.elf` with `-noanalysis`, `-scriptPath analysis_scripts`, and:

```text
-preScript SeedTimerArithmetic.java
-preScript SeedClockCache.java
-postScript DecompileWithAbi.java firmware/decompiled/runtime-timer-arithmetic 0x70945b3c 0x80d45464 0x707bf7e0
```

Then run the emulator separately on the same project:

```text
-postScript ValidateTimerArithmetic.java firmware/timer-arithmetic-validation.json
```

The stdout logs are `firmware/ghidra-timer-arithmetic-stdout.log` and
`firmware/ghidra-timer-validation-stdout.log`. As with previous Ghidra runs,
inspect script errors as well as the process exit status.

```sh
python3 analysis_scripts/timer_arithmetic.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-timer-arithmetic \
  --language firmware/tools/ghidra_12.1.2_PUBLIC/Ghidra/Processors/RISCV/data/languages \
  --validation firmware/timer-arithmetic-validation.json \
  --reference firmware/tool-evidence/andes-riscv-dsp.rs \
  > analysis/timer-arithmetic.json
python3 -m unittest discover -s tests -p 'test_timer_arithmetic.py' -v
```

The public report fingerprints the images, helper, language, exports,
reference and private execution report. Vendor code, firmware, projects and
tool installation remain ignored. Broader DSP support, remaining native
analysis artifacts, physical counter frequency and shared-memory coherency
remain open.
