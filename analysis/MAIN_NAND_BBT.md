# Actual main BBT recovery, verification and CRC inside probe

All **18 native cases** pass in **117,251 instruction/service steps** (maximum
**7,082**, maximum accepted first-chip entry count). Original main BBT verifier
`0x702d569c`, resume `0x702d58ac` and CRC `0x70161332` now join the original
first-chip probe, [UID acquisition](MAIN_NAND_UID.md), platform/QSPI FIFO,
root/registry/PM publication, geometry and [UID export](MAIN_NAND_UID_EXPORT.md).
[main-nand-bbt.json](main-nand-bbt.json) records **57 code/export and 67 data
hashes**, observations and limitations.

**BBT page read/write/erase and bad-marker services are supplied.** Their inputs,
record bytes and return statuses are authored. This scope executes the BBT
control logic and actual CRC/table, not the NAND transport for BBT pages.
The earlier main QSPI FIFO path continues to execute for probe/features/UID.
No physical record, persistent write or repair atomicity is established.

## Original main state and record acceptance

Main BBT state starts at `0x70f9bbac`: a 140-byte record followed by six geometry/
reservation/primary/backup words. Resume clears all 164 bytes and stores the
original selected descriptor's 1024 blocks, 2048-byte pages, 64 pages per block
and 16 reserved tail blocks. Descending marker queries select two usable tail
blocks. Cases select the immediate pair, skip authored bad blocks, and reach
the final reserved pair at blocks 1009/1008. No-good and one-good cases stop at
original assertion owner `0x70a30e6c`, line 196, before registration or export.
UID acquisition has already completed in those stopped cases.

The original verifier accepts magic `0x746242`, an entry count at most reserve
minus two, and the actual CRC over exactly twice that count of bytes. The main
CRC executes against original 1024-byte table `0x709bc4fc`; its result agrees with
the separate host policy. Empty and 14-entry records pass; a 15-entry record is
rejected before CRC/publication. Original code does not reject the selected
unsorted/duplicate entry lists when count/magic/CRC pass. This establishes
acceptance only; downstream remapping of those lists is outside this scope.

Successful verification copies the complete 140-byte record into RAM through a
bounded supplied helper. Formatting/logging services have stack and value
bounds. All original descriptors, sequences, bindings and constant data remain
immutable. Only the original first-chip geometry is selected for BBT integration.

## Backup repair and outer caller behavior

| Authored condition | Actual original control flow / RAM result |
| --- | --- |
| Primary record accepted | Return zero with active RAM table; no backup repair |
| Primary CRC or page-read error, backup accepted | Fall back, publish backup, attempt primary repair |
| Backup accepted | Clear RAM magic during reread/erase/write callbacks; restore magic afterward |
| Backup reread, erase or write callback fails | Log repair failure, restore active RAM magic, still return zero |
| Neither record accepted | Return one with inactive RAM table; outer probe ignores this result and registers the object |

The repair sequence uses original selected primary page/block arithmetic.
Callbacks record the temporarily cleared magic and the exact write payload.
A failing reread skips erase/write; erase failure skips write. The harness does
not persist callback writes, and no follow-up reboot/media recovery is inferred.

After a normal BBT return, actual probe computes guard pages/blocks, root
registers the object, geometry queries report the actual RAM magic, and direct
UID export consumes acquisition state. With no accepted BBT, geometry reports
inactive BBT despite successful registration. With a valid BBT and an earlier
handled UID setup mismatch, UID export still returns the authored prior length
17 and bytes. Neither software state proves freshness of the other.

The 164-byte BBT ends exactly where the 128-byte UID backing begins:
`0x70f9bbac + 164 == 0x70f9bc50`. The new harness guards the **combined 292-byte
span**, rather than treating the final BBT bytes as an unused lower UID guard.
Snapshots verify the UID source remains intact while actual BBT mutates its
adjacent state. The preceding scopes retain their original guard policy.

## Reproduction and regression

Use the startup-aware main project and prior auxiliary/UID-export seeds, then
apply `SeedMainNandBbt.java`. It checks original byte hashes before changing
function metadata; it does not change instructions or emulator semantics.

```sh
python3 analysis_scripts/main_nand_bbt.py \
  --vectors-output firmware/main-nand-bbt-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandBbt.java \
  -postScript ValidateMainNandBbt.java \
  firmware/main-nand-bbt-vectors.json firmware/main-nand-bbt-validation.json

python3 analysis_scripts/main_nand_bbt.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-nand-bbt \
  --vectors firmware/main-nand-bbt-vectors.json \
  --validation firmware/main-nand-bbt-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_bbt` with
`DecompileWithLogger.java`, logger `0x702b38a2`. Firmware/exports stay local.
All **434 previous main native cases reproduce byte for byte**, including prior
UID/export cases, after narrow operation/BBT/combined-buffer hooks. Their fixed
configurations and bounds remain unchanged. These two scopes add **38 host
checks**; the complete suite has **1,868 passing tests**.

The subsequent [main remapping scope](MAIN_NAND_BBT_MAPPING.md) executes original
block/page remappers over the recovered RAM table. The subsequent
[main page-read scope](MAIN_NAND_PAGE_READ.md) connects actual direct reads to
mapping/load/busy/cache/FIFO after recovery; recovery's own page callbacks remain
supplied. Next work includes those callbacks, asynchronous/DMA/program/erase
integration, further identity/media/PM consumers and alternate chip geometries.
Supplied library/power/pin/RTOS/BSP/heap/PM behavior, IRQ/cache/coherency, physical
provenance and persistence, safe backup/restoration and standalone boot remain
separate open requirements.
