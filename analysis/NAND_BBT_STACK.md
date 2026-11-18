# BBT recovery and subsequent mapping through original NAND/QSPI

All **21 native cases** pass in **342,220 instruction/service steps**
(maximum **34,562**, `bbt_no_good_blocks`). Original BBT verification/CRC,
tail-marker scan, backup reread/erase/program and subsequent mapped reads now
execute through original NAND, bus and QSPI. Sixteen targeted host checks are
part of the combined **1,525-test passing suite**. Evidence includes 87 code/
export and fourteen data hashes in [nand-bbt-stack.json](nand-bbt-stack.json).

All **634 previous native reports reproduce byte for byte** with the shared
runner extended for both macroblocks.

This extends [the earlier BBT pass](NAND_BBT_AND_MAPPING.md), which supplied
page/erase/program/bad-marker results. No device was accessed. The selected
ready chip, geometry, initial RAM, marker/record/status inputs and peripheral/
library services are authored. Captured erase/program commands do not update
the read-only record fixture; no physical cells or persistence are modeled.

## Real marker reads, record transfer and CRC

The selected geometry is 1,024 blocks, 2,048 data bytes plus 64 spare bytes and
64 pages per block. Original resume clears the 164-byte context and scans the
last sixteen blocks. Each actual marker query reads the spare pair from up to
three pages through the lower NAND/QSPI stack. The selected clean tail yields
primary 1,023 and backup 1,022; a bad-tail fixture selects 1,022/1,020 instead.
An initially rejected primary candidate can be queried twice, as in the earlier
supplied-service pass.

Original verification reads 140 record bytes through page-load/status/cache
commands. The real CRC routine executes with its guarded original table, while
the independent host contract uses `zlib.crc32`. Native snapshots retain the
original header and counted entries; the exporter aliasing caveat in the earlier
report still applies.

Count fourteen is accepted with this reserve limit; count fifteen is rejected
before CRC. CRC failure does not publish a record. CRC-valid unsorted `[7, 1]`
and duplicate `[1, 1]` records remain accepted. Their subsequent actual page
reads map caller page 64 to 64 and 192 respectively. These are bounded authored
records, not observations of corrupt device metadata.

## Backup repair and error propagation

When primary validation fails and backup validation succeeds, the table is
already published in RAM. Original resume clears its magic before rereading
backup, erasing primary and programming the 140-byte record. Captured erase/
program addresses name primary page 65,472 without active-table remapping;
captured program FIFO bytes exactly match the supplied backup record.

Three connected failures preserve the earlier observed return policy:

| Authored lower result | Original behavior |
| --- | --- |
| Backup reread reports uncorrectable ECC | Skips erase/program, logs repair failure |
| Primary erase reports erase-failure status | Skips program, logs repair failure |
| Primary program reports program-failure status | Captures the record write, logs repair failure |

In all three selected cases, resume restores active magic and returns zero.
The backup-derived RAM mapping remains usable by a subsequent actual NAND read.
This proves neither a repaired primary copy nor redundant persistent records.
The record fixture remains unchanged even after a captured successful program.

Both invalid copies instead produce return **1** with inactive magic. No-good
and only-one-good tail scans reach original assertion owner `0x80c3d3b0`, line
`0xac`, before normal return. These are explicit stops without return-ABI claims.

## The recovered map is consumed by the lower stack

After loading `[1, 3, 7]`, a separate actual read of caller page 600 reaches
page-load address **792**. Its 32-byte column-16 result is authored independently;
the address evidence comes from the command trace, not physical source-page
integrity. With inactive mapping after two invalid records, caller page 600
instead loads page 600. Reserved caller page 65,216 is rejected by remapping
before any additional NAND command.

A direct verifier call with an already active table has a different prerequisite
from resume: its reserved primary address can be rejected by the underlying
remapper before any flash read, leaving the old RAM table intact and returning
zero. Normal resume clears the table before verification. This demonstrates
selected call-context constraints, not a failing production call sequence.

## Evidence and reproduction

Original executed ranges and CRC/format data are hash guarded. Normal returns
check ABI. Context/BBT, caller/private buffer, scratch/map/flag, descriptor and
registry guards remain checked. Zero/copy/text-format, timers and RTOS/library
leaf effects are supplied; CRC and the relevant storage bodies execute.

```sh
python3 analysis_scripts/nand_bbt_stack.py \
  --vectors-output firmware/nand-bbt-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedNandBbt.java \
  -postScript ValidateQspiHal.java firmware/nand-bbt-stack-vectors.json \
  firmware/nand-bbt-stack-validation.json

python3 analysis_scripts/nand_bbt_stack.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-bbt-stack \
  --vectors firmware/nand-bbt-stack-vectors.json \
  --validation firmware/nand-bbt-stack-validation.json
```

Generate exports with `DecompileWithLogger.java`, logger `0x80c1cd7a` and
`TARGETS` from `analysis_scripts.nand_bbt_stack`. Firmware and exports remain
local and ignored by version control.

The companion [probe/BBT integration](NAND_PROBE_BBT_STACK.md) calls this real
recovery path from the original first-chip probe. Initial table creation,
physical record provenance, power-loss persistence, broader startup/registry,
concurrency/coherency and safe backup/restoration/standalone boot remain open.
