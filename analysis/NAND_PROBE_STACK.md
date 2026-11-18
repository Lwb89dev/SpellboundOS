# NAND candidate probing through original platform and QSPI FIFO

All **26 native cases** pass in **256,313 instruction/service steps**
(maximum **38,801**, `fifo_probe_last_allowed_attempt`). All **608 previous
native cases reproduce byte for byte** with the extended runner. Eighteen host
checks bring the suite to **1,498 passing tests**.

Original probe `0x80c2874a`, matcher `0x80c28318`, ID/reset builders and operation
initializer `0x80c27aac` now connect per-candidate platform/clock/pin/DMA setup
to the original bus and QSPI HAL. Full observations and 42 code/export plus
30 data hashes are in [nand-probe-stack.json](nand-probe-stack.json).

This extends [the supplied-bus probe](NAND_PROBE_AND_CHIP_TABLE.md) and
[platform initialization](NAND_PLATFORM_AND_PINS.md). IDs and peripheral
register effects are authored. Power/delay, workaround, UID, BBT and mutex
services remain supplied. No watch/phone, physical ID or electrical behavior
was observed. This is a connected probe pass, not complete NAND/BBT startup.

## ID transport and candidate order

Each attempt executes original platform initialization with the actual candidate
descriptor, then the original ID builder and bus transfer. The QSPI FIFO supplies
five ID bytes to the original stack buffer; the original matcher consumes them.
The selected descriptor stays zero during identification and is published only
after a match. No ID helper or bus initializer result replaces these bodies.

All eleven original candidate prefixes select the expected descriptor. Failed
prefixes cause the next original candidate to be initialized. An unmatched ID
executes all 33 attempts across three rounds and returns `-4`. Delayed inputs
can succeed in rounds two and three, including the last candidate on attempt 33.
These IDs are scripted values, not identification of the fitted chip.

The selected optional-tail case still matches the first candidate with received
fourth/fifth bytes `12 34`: its optional descriptor fields are zero. The earlier
authored-descriptor fifth-field counterexample remains a separate supplied-bus
test, not a property of these unchanged original descriptors.

## Clock selection and feature verification

Original descriptor word +12 is 104 for candidates 0–4 and 6, and 83 for
candidates 5 and 7–10. The original initializer compares it with 100 to choose
clock selector 1 or 2. Repeated attempts execute original pin/MMIO, QSPI reset
and DMA descriptor initialization; their complete traces and preserved fields
are recorded. These selectors are not measured clock frequencies or physical
pinout corroboration.

After selection, original reset emits `ff`. Original feature builders transmit
each candidate's table values with opcode `1f` and read them back with `0f`.
The supplied peripheral register map records FIFO writes and answers FIFO reads;
the feature helper bodies are not substituted. For example, candidate zero
transmits `00 18`, whereas the ESMT candidate transmits `02 10`.

A scripted bit flip in the second feature read returns `-7` through original
comparison/error logging. The written register map still contains the transmitted
values. Selection remains published, but boot guard counts are still zero and
the BBT callback has not run. A nonzero selected pointer alone does not establish
successful completion of probing.

## Actual transport failures stop inside the bus

Selected ID RX, reset-command completion and feature TX timeouts execute real
HAL polling and stop at bus assertion owner `0x80c37b7c`, respectively lines
`0x12a`, `0x11f` and `0x132`. They stop before the outer helper/probe can log its
normal error return. The ID failure retains selected zero; reset and feature
failures retain the already selected descriptor, with boot guard counts unset.

This differs from the earlier cases that supplied negative bus/helper results.
Those cases covered distinct outer error branches; they did not establish the
normal outcome of these actual bus assertions. The current stops execute no
assertion body and make no normal-return ABI claim.

## Remaining supplied services and publication

The power sequence still uses supplied regulator lookup, disable/enable and
delay callbacks. Selected negative power results are ignored; missing power
handle logs and continues. The requested delay values are recorded, without
emulating elapsed electrical timing.

Workaround, optional UID and BBT bodies remain supplied. The original descriptor
flag controls whether UID is requested. Their selected negative supplied returns
do not prevent the probe from publishing first-MiB guard counts: 512 pages/eight
blocks for 2,048-byte pages or 256/four for 4,096-byte pages. This establishes
control flow and arithmetic, not physical protection or successful BBT recovery.

The original operation wrapper creates a supplied mutex only after successful
probing, and an existing mutex skips creation without skipping probing. Failed
creation stops at owner `0x80c3d434`, line `0x1e`, after descriptor selection and
guard publication. Outer driver-object allocation/registration is not connected
in this pass.

## Evidence and reproduction

Original candidate descriptors, feature tables, pointer inventory, platform data
and executable spans are hash guarded. Candidate inputs and the caller buffer
remain immutable; normal returns check ABI and existing controller/DMA/BBT/
descriptor/private-buffer guards. FIFO ID/feature values and register behavior,
board MMIO/timers and the listed auxiliary services are authored. No physical
DMA movement, NAND cells, reset persistence or live heap behavior is modeled.

```sh
python3 analysis_scripts/nand_probe_stack.py \
  --vectors-output firmware/nand-probe-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedNandProbe.java \
  -postScript ValidateQspiHal.java firmware/nand-probe-stack-vectors.json \
  firmware/nand-probe-stack-validation.json

python3 analysis_scripts/nand_probe_stack.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-probe-stack \
  --vectors firmware/nand-probe-stack-vectors.json \
  --validation firmware/nand-probe-stack-validation.json
```

Generate exports with `DecompileWithLogger.java`, logger `0x80c1cd7a` and
`TARGETS` from `analysis_scripts.nand_probe_stack`. Firmware/exports stay local.

Next work includes joining actual BBT recovery and auxiliary UID/workaround
paths to the probe, broader driver registry/startup, physical chip/timing/ECC
corroboration, persistent write/retire/reboot reconstruction and safe
backup/restoration/standalone boot. Passing ID fixtures cannot close those gates.
