# GNSS container and touch firmware candidates

Static investigation on 2026-11-15 of members of the Bip 6 OTA with SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
No device commands, flash operations or hardware measurements were performed.

## GNSS container: observed fields

`META/extfw/fw_gps.bin` is 1,260,868 bytes, SHA-256
`7221d15903058ff050fceb3790b82c571c71358d4c02edfad24d7b26b8ebc41f`.
Its prefix declares `AG3352B_V3.1.0_20250120,S,H`. A word at offset `0x20` has
bytes `55 aa aa 55`; five little-endian words at `0x24` through `0x34` give
lengths `0xabb4`, `0x1b0`, `0x5280`, `0x123860`, and `0x400`. Their sum plus
`0x100` exactly equals the member size. This supports the following candidate
region boundaries; the individual region roles have not all been identified.

| Candidate | File offset | Bytes |
| --- | --- | --- |
| 0 | `0x100` | `0xabb4` |
| 1 | `0xacb4` | `0x1b0` |
| 2 | `0xae64` | `0x5280` |
| 3 | `0x100e4` | `0x123860` |
| 4 | `0x133944` | `0x400` |

Readable content includes chip-driver source paths mentioning `ag3352`, UART,
DMA and clocks, plus FreeRTOS strings. Those are bundled-code clues rather than
proof of the fitted GNSS model or of the exact target CPU.

## First-region ARM Thumb mapping and startup

The first candidate region begins with coherent Thumb instructions: a literal
load into SP, interrupt disable and indirect call. Literal pointers support an
experimental mapping of this region at `0x04200000`; the first indirect call
target is `0x0420a6ad` (Thumb address bit set), inside the same region. The stack
literal is `0x04014000`. This is stronger evidence than a filename/entropy
classification, but does not independently measure the runtime memory map.

A targeted Ghidra 12.1.2 import using `ARM:LE:32:Cortex`, TMode=1, and the
candidate base emits a startup function and three helpers. Instruction-level
inspection and helper decompilation show a zeroing helper at `0x0420a6f6` and
a copying helper at `0x0420a6e4`. The startup zeroes ranges including
`0x0420abb4..0x0420f29c` and `0x04000efc..0x0400bfc8`, then copies bytes from
candidate source `0x04200178` into `0x04000000..0x04000ee4`, and from
`0x0420105c` into `0x04000ee4..0x04000efc`. The source spans are within the
first declared region, supporting its mapping. Initialization subsequently
branches indirectly to a literal `0x04205fb1`.

The initial targeted import mapped all bytes after the container header
contiguously to inspect these helpers. That mapping is not appropriate for
asserting the roles of later regions: zeroing a runtime address that numerically
follows the first stored region is not evidence that the next file region
belongs at that address. A subsequent bounded bulk analysis therefore imports
**only** the first `0xabb4` bytes. It recognized 254 functions and emitted
pseudocode for all 254. Forty-five output files contain warning comments, and
logs include missing-memory flows into runtime copy destinations such as
`0x0400009c`. Decompiler completion does not mean every function is correct or
that all executable bytes were discovered. The other four regions remain
unmapped and undecompiled in this pass.

Local files are `firmware/components/gnss-first-region.bin`, Ghidra project
`firmware/ghidra-gnss-region/gnss-region`, log
`firmware/bulk-gnss-first-region.log`, and exports
`firmware/decompiled/gnss-first-region/`. The first region SHA-256 is
`aa171102514c9e8685ef01351e07e99b1f9256cb62005f5c5a1d97f7b2384008`.

## Touch candidates: comparison rather than forced architecture

The two touch candidates are both exactly 49,152 bytes:

- `META/extfw/00151501_005c0913_0000009b_tp.bin`, SHA-256
  `b337b46fc49bb76021dbc3f62701c119bc6193fada71159110f2ff9b3a6458f7`.
- `META/extfw/00161501_005B0913_0000009b_tp.bin`, SHA-256
  `ed7ec863c7842e6df98c44b71440423f32603e0f244ad16ef4e270dfa1b61e30`.

They differ at only eight byte positions, with every other byte identical:

| Offset | First | Second |
| --- | --- | --- |
| `0x30` | `15` | `16` |
| `0x3c` | `06` | `05` |
| `0x46` | `15` | `16` |
| `0x47` | `15` | `16` |
| `0xaf26` | `06` | `05` |
| `0xaf28` | `15` | `16` |
| `0xb15c` | `15` | `14` |
| `0xb15d` | `cd` | `cc` |

Both contain bytes `22 e6 e6 22` at offset `0x40`, consistent with the
`0xe622` identifier expected by the main firmware's touch probe (see
[TOUCH_AND_SERIAL.md](TOUCH_AND_SERIAL.md)). This is a consistency clue, not a
readout of the attached touch chip. The changed bytes plausibly encode version,
configuration or integrity metadata; their exact meanings are not established.
Neither an executable format nor a CPU architecture was validated for these
images. Applying the main processor's RISC-V decoder would be unjustified.
They remain undecoded proprietary touch-firmware payloads.

## Reproduction

`analysis_scripts/gnss_inspect.py` reads the original archive, checks the
observed GNSS header and length accounting, hashes candidate regions and reports
the exact touch differences. Optional `--first-region NEW_FILE` writes the
first region and refuses to overwrite an existing file.

```sh
python3 analysis_scripts/gnss_inspect.py firmware/bip6-4.6.0.3.zip \
  --first-region firmware/gnss-first-repro.bin
mkdir -p firmware/ghidra-gnss-repro
/path/to/ghidra/support/analyzeHeadless "$PWD/firmware/ghidra-gnss-repro" gnss \
  -import "$PWD/firmware/gnss-first-repro.bin" -loader BinaryLoader \
  -loader-baseAddr 0x04200000 -processor ARM:LE:32:Cortex -cspec default \
  -scriptPath "$PWD/analysis_scripts" -preScript gnss_Seed.java \
  -postScript ExportFunctions.java "$PWD/firmware/decompiled/gnss-repro" \
  -analysisTimeoutPerFile 60 -log "$PWD/firmware/gnss-repro.log"
python3 -m unittest tests/test_gnss_inspect.py -v
```

The synthetic parser tests check whole-payload accounting and rejection of
truncated/inconsistent headers. JSON regenerated from the original archive
matches the initial local inspection byte for byte. No runtime or physical
validation follows from these checks.

## Runtime-copy reconstruction

A further bounded pass reconstructs only memory ranges explicitly copied or
zeroed by the startup. `gnss_MapRuntime.java` copies the first source span to
`0x04000000..0x04000ee4`, copies the initialized data span to
`0x04000ee4..0x04000efc`, and initializes the two observed zeroing ranges with
zero bytes. The copied code range is analyzed as Thumb. This is a static
reconstruction of the initial state inferred from startup, not a runtime memory
capture, and does not map any of the remaining four file regions.

With these reconstructed ranges, Ghidra recognizes 288 function sites and emits
pseudocode for all 288. Thirty-three output files contain warning comments,
compared with 45 in the original 254-function export. Earlier missing-memory
flows into `0x0400009c` disappear; unresolved flows into addresses such as
`0x04404e60` remain. Some additional function sites correspond to copied/aliased
instructions already present in the first region, so the two counts must not
be summed or described as distinct recovered source functions.

The original output stays at `firmware/decompiled/gnss-first-region/`; the new
output is `firmware/decompiled/gnss-runtime/` and its log is
`firmware/bulk-gnss-runtime.log`. The same local Ghidra project now includes the
reconstructed runtime ranges. To reproduce after the preceding first-region
import, process its program with `-preScript gnss_MapRuntime.java`,
`-postScript ExportFunctions.java NEW_EXPORT_DIRECTORY`, and
`-analysisTimeoutPerFile 60`. The script expects a first-region project without
those ranges already present; existing blocks are not overwritten.

## Additional regions: later bounded pass

A subsequent investigation identifies two more plausible Thumb regions from
instruction patterns and independent literal-pointer/string correspondence.
The `gnss_find_bases.py` tool ranks bases aligned to 1024 bytes by matching
aligned words to NUL-terminated ASCII strings within the same candidate region.
This is a heuristic: duplicated strings and unrelated data produce false
matches. It is used together with startup code and literal targets, not alone.

- Region 2 (`0x5280` bytes) supports base `0x04000000`. Three independent
  pointer/string matches select this base; the region starts with a Thumb SP
  load, interrupt disable and a zeroing loop whose bounds are literal RAM
  addresses. Its strings include a `[Bootloader]` label. A 60-second-bounded
  Ghidra analysis completes with 155 recognized function sites, all emitting
  pseudocode; 28 output files contain warning comments. The exact installed
  boot role and runtime execution are unverified.
- Region 3 (`0x123860` bytes) supports base `0x08009000`: 1,332 literal/string
  correspondences select it, compared with 150 for the next-ranked base.
  Its startup loads SP `0x04010000` and calls literal Thumb target
  `0x080091d5`, which lands at region offset `0x1d4`. This independently
  corroborates the base. A proposed `0x04400000` mapping does not explain
  these pointers, so unresolved earlier flows into `0x04404e60` are not
  resolved by assigning this region there.
- Region 1 (`0x1b0` bytes) contains 385 zero bytes; region 4 (`0x400` bytes)
  contains 522 `ff` bytes and 362 zero bytes. They appear structured/data-like,
  but their precise field meanings remain unidentified. No code entry or CPU
  architecture was forced onto them.

The stage-2 map at `0x04000000` overlaps the first stage's reconstructed runtime
copy. The analyses are kept in separate projects; this may represent different
boot stages, and combining both byte sets at that address would be incorrect.

Reproduce region extraction and the base-ranking heuristic with:

```sh
python3 analysis_scripts/gnss_inspect.py firmware/bip6-4.6.0.3.zip \
  --extract-regions firmware/gnss-repro-regions
python3 analysis_scripts/gnss_find_bases.py firmware/gnss-repro-regions/2.bin \
  --low 0x04000000 --high 0x05000000
python3 analysis_scripts/gnss_find_bases.py firmware/gnss-repro-regions/3.bin \
  --low 0x08000000 --high 0x09000000
```

For Ghidra, use the previous first-region command with a new project and the
selected region file, replacing the base with `0x04000000` for region 2 or
`0x08009000` for region 3. Pass that same address as an argument to
`-preScript gnss_Seed.java`. The Seed script's default remains `0x04200000`
for first-region reproduction. Set a separate export directory for each stage
and retain `-analysisTimeoutPerFile 60` for the bounded comparison. The parser
and heuristic tests now include a synthetic literal/string pair with a known
base; all three tests pass. All five extracted regions were compared byte for
byte with the initial local extractions and matched.
