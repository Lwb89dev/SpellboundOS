# Original main block/page remapping after BBT recovery

All **20 native cases** pass in **134,246 instruction/service steps** (maximum
**6,858**, repeated success/failure sequence). Original main block remapper
`0x702d5a32` and page remapper `0x702d5a72` now consume the actual RAM state
produced by [main BBT recovery](MAIN_NAND_BBT.md), following original probe/UID/
platform/FIFO/root publication, geometry and UID export.
[main-nand-bbt-mapping.json](main-nand-bbt-mapping.json) records **59 code/export
and 67 data hashes**, complete observations and limitations.

BBT page/marker, library, RTOS, power and heap services remain supplied over
authored records/peripherals. This is direct remapper execution after recovery;
it does not establish physical media or persistent repairs.

## Translation, limits and retained output

An inactive RAM magic passes the input through without applying the active BBT
boundary. An active table walks its entries in stored order: each entry at most
the evolving physical block advances that block by one. Page mapping divides by
the recovered pages-per-block, maps the block and preserves the page remainder.
The recovered backup block is the exclusive physical limit.

For the accepted `[1, 3, 7]` table and primary/backup 1023/1022:

| Input | Actual result |
| --- | --- |
| Block 1 / block 3 | Block 2 / block 5 |
| Page 65 / page 193 | Page 129 / page 321 |
| Last usable logical page 65215 | Physical page 65407 |
| Block 1019 / page 65216 | Return `0xffffffff`, output unchanged |
| Active block input `0xffffffff` | Unsigned increment wraps; result zero |
| Active page input `0xffffffff` | Reserved-boundary failure |
| Inactive block/page input `0xffffffff` | Passes through unchanged |

The wrapping input is an authored software counterexample, not a physical
addressing claim. The page reader has additional validation after remapping.
A native sequence alternates successful and failing mappings; failures preserve
the preceding successful output rather than clearing it. Selecting the final
reserved tail pair moves the exclusive limit to block 1008. An empty active
table still enforces that limit.

## Accepted malformed lists and recovery consequences

The verifier's accepted `[1, 1]` list advances logical block 1 twice to block 3.
The accepted `[7, 1]` list stops immediately at 7 and returns block 1, leaving the
later listed block unexamined. Count/magic/CRC acceptance therefore does not
establish sortedness or uniqueness required by the ordinary mapping meaning.
The subsequent [main page read scope](MAIN_NAND_PAGE_READ.md) follows the changed
physical source into actual load/cache/FIFO reads.

A supplied backup-repair write error still leaves active RAM magic; subsequent
mapping returns through the original remapper. When neither record is accepted,
outer probe still registers the object and remapping follows its inactive path.
Remappers preserve the recovered record, UID source and object state.

## Reproduction and regression

Use the seeded startup-aware main project from [MAIN_NAND_BBT.md](MAIN_NAND_BBT.md).
`SeedMainNandBbtMapping.java` verifies original byte hashes and changes function
metadata only. It does not change firmware instructions or emulator semantics.

```sh
python3 analysis_scripts/main_nand_bbt_mapping.py \
  --vectors-output firmware/main-nand-bbt-mapping-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandBbtMapping.java \
  -postScript ValidateMainNandBbtMapping.java \
  firmware/main-nand-bbt-mapping-vectors.json firmware/main-nand-bbt-mapping-validation.json

python3 analysis_scripts/main_nand_bbt_mapping.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-nand-bbt-mapping \
  --vectors firmware/main-nand-bbt-mapping-vectors.json \
  --validation firmware/main-nand-bbt-mapping-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_bbt_mapping`
using `DecompileWithLogger.java`, logger `0x702b38a2`. The recorded corpus was
exported after the subsequent page-reader metadata seed. Firmware/exports stay
local. Sixteen new host checks cover mapping, retained outputs and native/hash
consistency. The final regression reproduces all **452 preceding main native
cases** and these **20 mapping cases byte for byte** after the page-read hooks;
original fixed configurations and bounds remain unchanged.

Further main read/program/erase/DMA consumers, wider geometries, physical BBT
provenance, concurrency, persistent repair, safe restoration and standalone boot
remain open. Direct main page read is covered by the next bounded scope.
