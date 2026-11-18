# Supported-family reset, E0 level and UID inside original probe

All **10 native cases** pass in **131,238 instruction/service steps**
(maximum **28,586**, `aux_supported_no_uid_copy`). The original candidate-3
probe now executes its real workaround/reset/level and UID bodies through
original command builders, platform and QSPI FIFO. Evidence and **49 code/export
plus 31 data hashes** are in [nand-probe-aux.json](nand-probe-aux.json).

The selected original descriptor is `Winbond W25N04LWZEIG`. It is selected by
authored ID FIFO bytes without modifying its geometry, name or UID sequence.
This scope retains a **supplied BBT service** for its 4-KiB pages and 2,048
blocks. The [first-chip UID/BBT scope](NAND_PROBE_UID_BBT.md) instead joins
actual BBT for the original 2-KiB-page descriptor. No device was accessed.

## Workaround before UID

Actual workaround `0x80c29f5c` performs the two supported-prefix comparisons,
then emits reset opcodes `0x66` and `0x99`, requesting delays 1,000 and 5,000
through the supplied delay service. The original E0 read follows. Zero low
three bits need no level write; selected initial E0=2 enters the original
setter, writes zero and verifies it before UID acquisition.

An authored stream requiring a second level attempt captures two writes before
confirmation. With E0 writes deliberately ignored by the peripheral model,
all five writes fail to establish zero and each mismatch is logged. E0 remains
2, yet the setter and probe return zero and valid UID length 16 is published.
The full probe therefore retains the earlier [isolated setter exhaustion
behavior](NAND_RETRY_UID_STACK.md). These are authored register semantics and requested delays, without
physical reset, elapsed-time or correction evidence.

UID acquisition writes B0=`0x48`, checks its value, loads the page, polls C0 and
reads complement-paired 32-byte copies with original opcode `0x03`. The normal
feature table subsequently writes A0=0, B0=`0x19`, D0=0. Captured TX is
`48 00 19 00`, with the preceding zero-level writes where applicable.

## UID failures, export and BBT boundary

First- and second-copy success, all-copy failure, feature mismatch and selected
ECC failure are covered. All-invalid pairs clear UID length; early feature/ECC
errors preserve the authored prior length 17 and `0xa5` buffer. Actual ioctl
24 subsequently exports the successful 16-byte UID or retained 17 old bytes,
as appropriate. The [first-chip report](NAND_PROBE_UID_BBT.md) records the
corresponding fully connected BBT cases and stale-state limitations.

Actual BBT recovery for this descriptor is outside this scope. One case
explicitly supplies BBT return `-9`; the original probe still returns zero.
This is an observed caller policy over a supplied result, with no claim about
4-KiB-page table recovery, stored UID authenticity or persistent media changes.
Power, mutex, copy/format/logging/delay and peripheral effects remain authored.

## Reproduction and verification

```sh
python3 analysis_scripts/nand_probe_uid_stack.py --scope supported \
  --vectors-output firmware/nand-probe-aux-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedNandProbe.java \
  -postScript SeedNandIdentity.java \
  -postScript ValidateQspiHal.java \
  firmware/nand-probe-aux-vectors.json firmware/nand-probe-aux-validation.json

python3 analysis_scripts/nand_probe_uid_stack.py firmware/bip6-4.6.0.3.zip \
  --scope supported --decompiled firmware/decompiled/runtime-nand-probe-aux \
  --vectors firmware/nand-probe-aux-vectors.json \
  --validation firmware/nand-probe-aux-validation.json
```

Use the existing startup-aware, seeded runtime project with identity bodies.
Generate exports using `DecompileWithLogger.java`, logger `0x80c1cd7a`, and
addresses from `ranges('supported')` in `analysis_scripts.nand_probe_uid_stack`.
All code/data guards, normal-return ABI and existing controller/DMA/caller/
descriptor/UID buffer guards remain active. The two new scopes share 20 host
tests; **667 preceding shared-runner native cases reproduce byte for byte**.
Broader chip/BBT integration, initial table creation, registry/startup,
physical timing/UID, persistence and safe device restoration remain open.
