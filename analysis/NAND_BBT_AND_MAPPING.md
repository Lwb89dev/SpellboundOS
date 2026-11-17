# NAND bad-block table, recovery and connected page mapping

Two native passes now cover the BBT and its connection to page operations:

| Pass | Cases | Total steps | Maximum steps |
| --- | ---: | ---: | ---: |
| Verification, recovery, block/page mapping and active query | 58 | 11,561 | 2,441 |
| Page/program/copy/OOB/erase with actual remapping and busy loops | 21 | 51,756 | 48,179 |

All cases pass. Complete observations and provenance are in
[nand-bbt.json](nand-bbt.json) and [nand-page-mapping.json](nand-page-mapping.json).
The preceding 77-case [page-policy pass](NAND_PAGE_POLICY.md) was rerun with the
extended runner and produced a byte-for-byte identical native report. Fifty new
host tests bring the full suite to **1,047 passing tests**.

Storage records, geometry, bad-block query results and command/feature/cache
services are authored. BBT verification/resume/remapping and CRC execute as
actual firmware instructions. The connected pass also executes actual page
policy and busy loops, with an immutable authored BBT. No watch or phone was
accessed; no physical record, erase/program effect or persistence is established.

## BBT layout and acceptance

The 164-byte RAM context starts at `0x80df42cc`:

| Offset | Field |
| --- | --- |
| `0x00` | Active magic `0x00746242`, bytes `Bbt\0` |
| `0x04` | Number of bad-block entries |
| `0x08` | CRC-32 of the counted entries |
| `0x0c` | Up to 64 little-endian 16-bit entries in the 140-byte stored record |
| `0x8c` | Total blocks |
| `0x90` | Data bytes per page |
| `0x94` | Pages per block |
| `0x98` | Reserved-count limit |
| `0x9c` | Primary BBT block |
| `0xa0` | Backup BBT block / exclusive mapped-block limit |

Actual verifier `0x80c27662(block)` requests a direct 140-byte read at
`block * pages_per_block`, column zero. It accepts only the magic above, a count
no greater than `reserved_count - 2`, and matching CRC over exactly `count * 2`
entry bytes. Actual CRC routine `0x80c00b24` executes against the original guarded
CRC table. An independent host `zlib.crc32` supplies the expected result.

On success, the verifier copies all 140 record bytes to RAM, preserving the six
geometry/location words, logs entries in groups of 20, and returns **1**. Zero
means verification failed. An empty valid table is accepted. Bad magic/count
are rejected before CRC; read failure skips record inspection. Failed validation
does not clear a pre-existing RAM table in the direct verifier fixtures. Resume
clears the context before verification.

Fresh verifier pseudocode incorrectly aliases a CRC result with a header stack
slot. Native snapshots establish that the original magic/header bytes are
published intact. This is another reason to use execution and byte comparisons
instead of treating the fresh export as a standalone source reconstruction.

## Mapping algorithm and malformed-table constraints

Actual active query `0x80c27a78` checks the magic only. With inactive magic,
actual block remapper `0x80c279d8` and page remapper `0x80c27a18` pass through the
input, including the bounded `0xffffffff` fixture, without a geometry check.

With active magic, block mapping starts at the logical block and walks entries
from the beginning. Each entry no greater than the current mapped block shifts
that block by one. Walking stops at the first greater entry or after the counted
entries. The result must be less than the backup-block field. Failure returns
`0xffffffff` without changing the caller output.

For authored sorted entries `[1, 3, 7]`, logical blocks `0, 1, 2, 3, 5` map to
`0, 2, 4, 5, 8`. With backup 1,022, logical block 1,018 maps to 1,021, while
logical block 1,019 fails. Page mapping applies block mapping to the quotient
and preserves the in-block remainder; both 64- and 128-page fixtures execute.

The verifier does **not** reject the bounded CRC-valid unsorted and duplicate
records used here. Verification followed immediately by actual mapping shows:

- `[7, 1]` is accepted; logical block 1 remains block 1 because the walk stops
  at 7 before seeing the later entry 1.
- `[1, 1]` is accepted; logical block 1 shifts twice to block 3.
- A separate direct block-map input `0xffffffff` with one entry `[1]` wraps to
  zero and succeeds under the supplied limit.

These are authored counterexamples, not observations of corrupt device metadata.
They establish ordering/uniqueness/input constraints a compatible independent
implementation must handle explicitly. They do not establish how physical BBT
records are created or whether callers can supply those extreme inputs.

## Resume and backup recovery

Actual `0x80c2785a(blocks, page_size, pages_per_block)` clears all 164 context
bytes, stores geometry and derives `reserved_count = blocks >> 6`. It scans
backward within that many final blocks, using supplied bad-block checks, and
selects the last two good blocks as primary and backup. For 1,024 blocks, the
fixtures select 1,023/1,022; bad-tail and last-reserved-pair cases select different
locations. With no second good candidate, execution reaches assertion owner
`0x80c3d3b0`, line `0xac`. The runner stops before its body and claims no return
ABI. A primary candidate rejected while no primary is selected can be queried
twice in the same scan iteration; this call ordering is recorded.

The primary is verified first. A valid primary ends resume with zero and avoids
backup reads or repair. If both records fail, resume logs `no_bbt`, returns **1**
and leaves mapping inactive. This routine does not create a replacement table
in the selected no-BBT branch.

When the backup verifies, its table is already in RAM. Resume then clears the
active magic, rereads the backup, erases the primary and writes the 140-byte
record to the primary, all with direct-mode argument 1. Disabling the magic
prevents remapping those storage addresses during the repair request.

Injected reread, erase and write errors stop subsequent repair operations and
log `repair_failed`. In every such case, resume still restores the active magic
and returns **zero**. A connected map after resume uses the backup-derived RAM
table successfully. A zero resume result therefore does not by itself prove
that the primary copy was repaired or that storage is redundant. No physical
repair or crash/power-loss atomicity is validated here.

## Connection to actual page policy

The second pass executes all five actual operations from
[NAND_PAGE_POLICY.md](NAND_PAGE_POLICY.md), both busy loops and both actual
remappers together. Remapper entry observations are recorded without replacing
their execution. For `[1, 3, 7]` and 64 pages per block:

- Read/program input page 600 reaches physical-address arithmetic page 792.
- Copy and copy-with-OOB load mapped source 792 and program mapped destination
  892 for caller inputs 600/700.
- Erase input block 12 reaches mapped block 15.
- The last usable caller page 65,215 loads mapped page 65,407. Caller page
  65,216 fails remapping with outer `-150` before loading. A reserved copy
  destination fails before loading its source. Reserved erase returns `-151`.

First-MiB guards inspect **mapped** addresses: caller page 319 remains below
physical page 512 and is rejected with `-250`; caller page 320 maps to 512 and
is accepted. Caller erase block 4 is rejected, while block 5 maps to 8 and is
accepted. This describes address arithmetic and software guard placement, not
physical write protection or a complete device partition map.

Inactive BBT fixtures preserve caller addresses. Unsorted/duplicate fixtures
produce the corresponding actual load addresses. The connected mapped-read
all-busy case still runs 2,000 status reads, logs timeout, then can return zero
after a successful supplied cache read, as in the previous page-policy pass.

## Reproduction and evidence boundaries

```sh
python3 analysis_scripts/nand_bbt.py \
  --vectors-output firmware/nand-bbt-native-vectors.json
python3 analysis_scripts/nand_page_mapping.py \
  --vectors-output firmware/nand-page-mapping-native-vectors.json
```

In the startup-aware `boot-runtime` project, apply `SeedNandBbt.java` and export
`nand_bbt.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`, to
`firmware/decompiled/runtime-nand-bbt`. Run:

```text
-postScript ValidateNandBbt.java firmware/nand-bbt-native-vectors.json firmware/nand-bbt-native-validation.json
```

For connected page mapping, apply `SeedNandPage.java`, export
`nand_page_mapping.py:TARGETS` to `firmware/decompiled/runtime-nand-page-mapping`
and run the extended page runner:

```text
-postScript ValidateNandPage.java firmware/nand-page-mapping-native-vectors.json firmware/nand-page-mapping-native-validation.json
```

```sh
python3 analysis_scripts/nand_bbt.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-bbt \
  --vectors firmware/nand-bbt-native-vectors.json \
  --validation firmware/nand-bbt-native-validation.json > analysis/nand-bbt.json
python3 analysis_scripts/nand_page_mapping.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-page-mapping \
  --vectors firmware/nand-page-mapping-native-vectors.json \
  --validation firmware/nand-page-mapping-native-validation.json > analysis/nand-page-mapping.json
```

The BBT runner pins six code and two data ranges, bounds cases to 100,000 steps,
checks normal return ABI or explicit assertion stops, exact RAM context/output
bytes, guards, CRC inputs and complete query/read/repair/publication/log traces.
The connected page runner pins ten code and three original data ranges, bounds
cases to 300,000 steps and checks BBT/descriptor immutability, buffer hashes/guards,
normal return ABI and full call order. Six and ten fresh export hashes are
recorded respectively. The original page fixtures continue to supply remapping;
only fixtures with `native_bbt` execute the additional guarded routines.

Remaining work includes physical BBT provenance and initial creation, complete
page-to-QSPI integration, actual lower HAL/ROM, UID and retry workaround, SFTL,
mapping repair and persistence across failed writes/power loss. Device-specific
backup/restoration and standalone boot through the signed chain remain open.
