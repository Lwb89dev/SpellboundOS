# Original probe joined to actual BBT recovery and selected workaround

All **12 native cases** pass in **235,814 instruction/service steps**
(maximum **37,339**, `probe_bbt_no_good`). The original selected first-chip probe
now calls real BBT recovery through NAND/QSPI, and executes the unsupported-
family branch of the real workaround. Eleven targeted host checks are part of
the combined **1,525-test passing suite**. Observations and 93 code/export plus
36 data hashes are in [nand-probe-bbt-stack.json](nand-probe-bbt-stack.json).

All **634 previous native reports reproduce byte for byte** with the extended
runner, including the original 26 connected probe cases after model refactoring.

This joins [the connected probe](NAND_PROBE_STACK.md) to
[connected BBT recovery](NAND_BBT_STACK.md). No device was accessed. The selected
ID, geometry/backing, marker/record/status streams, power/UID/mutex and library/
peripheral effects remain authored. This does not establish physical chip
identity, valid device BBT records or persistent repair.

## Actual positive no-BBT result inside the probe

The selected ID reaches the original first descriptor through actual platform/
ID FIFO and matching. Original feature write/readback then precedes actual BBT
resume. The harness observes the resume return at the original probe's return
address; it does not supply that result.

With both record copies invalid, real resume logs `no_bbt`, returns **1** and
leaves inactive magic. The original probe still sets first-MiB guard counts and
returns **zero**. Its operation wrapper can then create the supplied mutex.
The earlier negative supplied-BBT callback demonstrated ignored returns; this
pass establishes the positive no-table outcome from the actual implementation.

Probe success and mutex existence therefore do not establish an active BBT.
The no-table result may be meaningful to later policy; this pass does not infer
that a watch cannot operate in that state or that a device fault occurred.

## Backup failures, assertions and ordering

Valid primary and backup-repair cases complete normally. The latter captures
feature bytes `00 18` followed by the actual 140-byte BBT program payload.
Selected backup-reread ECC, primary erase and primary program failures still
produce BBT return zero with restored backup-derived RAM magic. The probe
returns zero and sets boot guard counts despite each repair-failure log.

An all-bad tail instead reaches the real BBT assertion. That stops the probe
with its selected descriptor already published, but before guard counts and
mutex creation. A feature mismatch returns `-7` without entering BBT resume.
Normal wrapper mutex creation follows BBT completion, including the positive
no-table result; assertions execute no body or normal-return ABI check.

These observations distinguish selection, BBT state, probe return, software
guard counts and mutex publication. None is proof of physical bad-block
protection, media redundancy or complete driver registration.

## Workaround and UID boundaries

For the selected first descriptor, actual workaround `0x80c29f5c` executes its
compatibility check, performs two original-prefix comparisons and returns the
unsupported-family result. The probe ignores it. The comparison leaf is
supplied, while the original branch/control body executes. A separate case keeps
an explicitly supplied workaround return for comparison with the earlier pass.

Only this first-chip integration is claimed here. Supported-family workaround
reset/level paths were covered separately, not joined to this probe in these
cases. UID remains a supplied callback: its selected negative return is still
ignored before real BBT recovery. The actual UID body and full object registry/
startup remain open integration work.

The subsequent [UID/probe/BBT pass](NAND_PROBE_UID_BBT.md) replaces that UID
callback with original acquisition and adds post-probe ioctl export. The
[supported-family pass](NAND_PROBE_AUX.md) separately joins reset/E0-level/UID
inside candidate 3; its 4-KiB-page BBT service remains supplied.

## Reproduction and verification

All original spans and relevant descriptor/table/CRC data are hash guarded.
Normal returns check ABI and existing controller/DMA/BBT/private/descriptor
guards; the main caller buffer stays immutable. BBT RAM is deliberately mutable
and its final 164 bytes and observed resume result are captured. Read-only record
fixtures do not change when program/erase commands execute, so persistence is
excluded.

```sh
python3 analysis_scripts/nand_probe_bbt_stack.py \
  --vectors-output firmware/nand-probe-bbt-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedNandProbe.java \
  -postScript SeedNandBbt.java -postScript ValidateQspiHal.java \
  firmware/nand-probe-bbt-stack-vectors.json firmware/nand-probe-bbt-stack-validation.json

python3 analysis_scripts/nand_probe_bbt_stack.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-probe-bbt-stack \
  --vectors firmware/nand-probe-bbt-stack-vectors.json \
  --validation firmware/nand-probe-bbt-stack-validation.json
```

Generate exports with `DecompileWithLogger.java`, logger `0x80c1cd7a` and
`TARGETS` from `analysis_scripts.nand_probe_bbt_stack`. Firmware/exports stay local.

Remaining gates include initial BBT creation and physical provenance,
supported-family BBT geometry, broader registry/startup, complete
persistent write/retire/reboot behavior, concurrency, backup/restoration and
standalone boot through the signed chain.
