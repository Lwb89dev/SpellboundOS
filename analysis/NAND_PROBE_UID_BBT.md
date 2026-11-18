# Original UID acquisition inside probe and BBT recovery

All **11 native cases** pass in **245,971 instruction/service steps**
(maximum **34,710**, `uid_bbt_last_copy`). The original selected first-chip
probe now executes UID acquisition before its feature table and actual BBT
recovery through NAND/QSPI. The operation wrapper and subsequent UID ioctl
export also execute in selected cases. Evidence and **98 code/export plus
37 data hashes** are in [nand-probe-uid-bbt.json](nand-probe-uid-bbt.json).

This extends [the probe/BBT pass](NAND_PROBE_BBT_STACK.md) using the original
first descriptor, `Winbond W25N01GWZEIB`, and its original UID sequence.
Original candidate descriptors remain unchanged. IDs, UID bytes, status/record/marker streams,
register effects, power/mutex/library services and peripherals remain authored.
No device was accessed; this does not identify a fitted chip or physical UID.

## Acquisition, feature restoration and BBT ordering

Actual UID body `0x80c28422` writes feature B0=`0x48`, loads the UID page and
polls C0 through original command builders, platform and direct FIFO. It reads
32-byte copies with opcode `0x03`, two column bytes and eight dummy cycles.
The first, second and sixteenth selected complement-valid copies publish UID
length 16. The final-copy case requires all 16 reads. The UID buffer retains the
32-byte data/complement pair, with its trailing 96 authored sentinel bytes.

The ordinary probe feature table then restores B0=`0x18`, and real BBT recovery
runs. Captured TX begins `48 00 18`; the backup repair case appends its 140-byte
record. Valid UID does not establish valid BBT: actual no-table return 1 remains
ignored by the probe, which returns zero and publishes first-MiB guard counts.
A real primary erase error likewise leaves backup-derived active RAM magic and
successful probe return. Record inputs remain immutable during writes.

The first-chip workaround follows its original unsupported-family branch.
The wrapper creates the supplied mutex after UID and BBT completion.
The [supported-family pass](NAND_PROBE_AUX.md) separately executes real reset
and E0-level handling inside the candidate-3 probe.

## Error state and subsequent ioctl export

With all 16 complement pairs invalid, the original UID body logs `-200` and
clears UID length to zero. Probe and BBT still succeed. Calling original ioctl
24 afterwards exports a zero length and leaves subsequent caller bytes intact.

A UID feature-readback mismatch logs feature `-7` and UID `-5`; a selected ECC
status logs UID `-101`. Both happen before the length reset. Starting with an
**authored prior length 17 and 128 bytes of `0xa5`**, both preserve that state.
The probe proceeds through actual feature programming and valid BBT recovery,
returns zero, and actual ioctl 24 subsequently exports those 17 old bytes.
Successful acquisition instead exports the verified first 16 bytes.

The retained length and bytes are deliberately initialized by the harness. They
are neither an observed device UID nor evidence that cold startup contains
this state. The result establishes an error-state/publication contract for
the selected call chain; physical identity provenance remains open.

## Reproduction and limits

```sh
python3 analysis_scripts/nand_probe_uid_stack.py --scope bbt \
  --vectors-output firmware/nand-probe-uid-bbt-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedNandProbe.java \
  -postScript SeedNandIdentity.java \
  -postScript SeedNandBbt.java -postScript ValidateQspiHal.java \
  firmware/nand-probe-uid-bbt-vectors.json firmware/nand-probe-uid-bbt-validation.json

python3 analysis_scripts/nand_probe_uid_stack.py firmware/bip6-4.6.0.3.zip \
  --scope bbt --decompiled firmware/decompiled/runtime-nand-probe-uid-bbt \
  --vectors firmware/nand-probe-uid-bbt-vectors.json \
  --validation firmware/nand-probe-uid-bbt-validation.json
```

Generate exports with `DecompileWithLogger.java`, logger `0x80c1cd7a`, and the
addresses from `ranges('bbt')` in `analysis_scripts.nand_probe_uid_stack`.
Use the existing startup-aware, seeded runtime project with identity bodies.
Firmware and exports remain local. Original code/data guards and normal-return
ABI, caller/private-buffer, controller, DMA, BBT and UID guards remain active.
The original UID body has supplied bounded zero/format/logging leaves.

The subsequent [driver-root pass](NAND_DRIVER_ROOT_STACK.md) now connects the
outer original operation-table callback, allocation and actual object registry
around this probe/UID/BBT path.

The two auxiliary scopes share 20 targeted host tests. All **667 preceding
shared-runner native cases reproduce byte for byte**. Initial BBT creation,
supported-family BBT geometry, broader registry/startup, electrical timing,
concurrency, real persistence, backup/restoration and standalone boot remain
open.
