# EFTL map reconstruction through original NAND marker and OOB reads

All **22 native cases** pass in **156,671 instruction/service steps**
(maximum **19,315**, `scan_mixed`). Original scanner `0x80c01d8a`, bad-block
adapter `0x80c028d8` and NAND marker checker `0x80c29042` now connect through
actual partition/ioctl/context/mutex, page/BBT, bus and QSPI code. Eighty-three
code/export and twelve data hashes plus full observations are in
[eftl-scan-stack.json](eftl-scan-stack.json). Eighteen new host checks bring the
suite to **1,461 passing tests**. All **563 previous native cases reproduce
byte for byte** with the extended runner and new function metadata.

This extends [the earlier supplied-service scan](EFTL_OOB_MAPPING_RESUME.md).
No watch or phone was accessed. Marker/OOB FIFO bytes, status sequences, ready
context/maps/flags/counters, RTOS and other leaf services are authored. Erase
effects and physical NAND cells are not modeled. These are direct scan calls,
not actual reboot recovery or full initializer execution.

## Original three-page bad-marker check

The EFTL adapter uses ioctl 10. The fast route reaches original chip ioctl
directly with the partition base converted to blocks; the generic route executes
original partition and context/mutex wrappers first. Original NAND marker
checking reads two spare bytes from each of the block's first three pages,
using actual page load, status polling, BBT remapping and cache-read commands.

If both bytes are `ff` on all three pages, it returns zero. The first pair whose
bitwise AND differs from `ff` returns **103** and stops reading more pages. The
selected second/third-page fixtures confirm that order, and `ff fe` alone is
enough to produce the positive marker result. These bytes occupy the start of
the spare area, distinct from the EFTL record at spare offset 20 in the selected
four-byte-unit layout.

With the authored partition base of 512 pages and immutable BBT entries
`[1, 3, 7]`, relative block zero's first page reaches mapped page 704. That is
original address arithmetic over supplied backing, not identification of the
watch's physical partition or bad blocks.

## Reconstructed mappings and duplicate policy

After a clean marker check, original OOB reading fetches 64 spare bytes and
extracts the four-byte logical-ID/tag/checksum record. Both direct four-byte and
selected segmented two-byte layouts execute. The latter runs original
extraction control with supplied copy services into the scanner's stack record;
source offsets 4 and 20 are recorded.

| Authored case | Observed result |
| --- | --- |
| Valid records for logical 2 and 0 | Maps logical 2 to relative block 0 and logical 0 to block 1; used count 2 |
| Two valid records for logical 0 | Keeps relative block 0; block 1 stays flag `fe`, but is not counted free or used |
| First block marked, second record valid | Skips the first and maps logical 0 to block 1; first scan returns 1 because free is zero and reserved is nonzero |
| Existing logical mapping | Keeps it without incrementing used/free for the scanned duplicate |
| Wrong tag or checksum | Counts the block free; wrong tag skips checksum execution, bad checksum logs an error |

The selected duplicate scan retains the first mapping encountered; it does not
compare record generations here. The fixture name `scan_duplicate_old_first`
labels an authored interpretation of block order, not measured record age.
This connects the earlier policy to actual NAND/OOB transport, but does not
prove what remains on media after a failed retirement write.

Mapped flags encode `64 << 1`, yielding `80` with the selected zero low bit.
The scanner reads first-page metadata; that flag is not evidence of the last
page actually programmed. A mixed four-block fixture ends with flags
`80 fe 80 ff` and free/used/reserved counts `1, 2, 1`.

The local logical-index check remains absent: a valid logical-7 record with
declared block count 1 writes map slot 7. The runner explicitly supplies eight
slots and checks their guards. No hardware overwrite, invalid production input
or caller invariant is inferred.

## Error and repair behavior across the lower stack

An uncorrectable marker-page read still receives authored cache bytes, then
returns an error through the original NAND marker checker. The scanner logs it
and attempts original erase even in first-scan mode. A positive marker result
instead skips erase in first-scan mode and permits it in repair mode. Subsequent
OOB content is separately supplied; it is not an emulation of erase effects.

When erase fails, the scanner reserves the block. The selected first scan
returns 1 without setting marker `a5`; repair mode can set `a5` and return zero
even with no usable mapped/free block. Zero does not guarantee usable capacity.

An OOB read error returns `-1` while retaining earlier mappings/counters and the
pending block's initial `fe` flag. A lower bus assertion stops before the
scanner's OOB-error log or normal cleanup. Its exact owner/line and guards are
recorded. Empty scans set the marker without NAND commands.

## DMA and evidence boundaries

Generic scans execute original DMA control for 64-byte OOB transfers. Hardware
DMA movement is not simulated: RX copies the initialized private buffer rather
than the supplied FIFO record. The selected generic case counts two free
blocks, whereas the IRQ-context direct-FIFO route reconstructs both maps.
Two-byte marker reads use polling FIFO even on that generic route. This is a
harness boundary, not a diagnosis of device DMA behavior.

Code bytes are hash guarded and unmodified; the metadata seed declares reviewed
function boundaries/signatures. Normal-return ABI, caller-buffer immutability,
scratch/map/flag/context/private-buffer/descriptor/BBT guards and selected mutable
state are checked. Ready-state and immutable-BBT assumptions remain. No physical
backup/restoration or standalone boot is claimed.

## Reproduction

```sh
python3 analysis_scripts/eftl_scan_stack.py \
  --vectors-output firmware/eftl-scan-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedEftlScan.java \
  -postScript ValidateQspiHal.java firmware/eftl-scan-stack-vectors.json \
  firmware/eftl-scan-stack-validation.json

python3 analysis_scripts/eftl_scan_stack.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-eftl-scan-stack \
  --vectors firmware/eftl-scan-stack-vectors.json \
  --validation firmware/eftl-scan-stack-validation.json
```

Generate the export directory with `DecompileWithLogger.java`, logger
`0x80c1cd7a` and `TARGETS` from `analysis_scripts.eftl_scan_stack` after the
metadata seed. Firmware/exports stay local, outside version control.

Next work includes full initializer/geometry/scan/retry connection to this lower
stack, larger scans and BBT provenance, persistent write/retire/reboot
reconstruction, power-loss behavior, concurrency/coherency and hardware/boot
feasibility. Independent authored inputs cannot establish persistence.
