# Native NAND partition dispatch, geometry and OOB serialization

All 58 bounded native cases pass, totaling 5,983 steps (maximum 746 for geometry
collection through the board fallback). Actual ROM lookup, NAND partition
wrappers, driver dispatch, chip geometry ioctl handling, EFTL geometry collection,
OOB reading/extraction and inverse OOB composition execute. Complete observations
and provenance are in [nand-partition.json](nand-partition.json).

The two partition tables are original image data. Driver registration roots,
the chip descriptor and low page/control services are authored. Page bytes are
procedural fixture data; no physical NAND, ECC engine, bus or erase is accessed.
The collected fixture geometry is not a measurement of the watch.

## Lookup and geometry refresh

Actual `0x80c29478(name)` first calls the named partition registry. A matching
row is returned only after querying the driver for page size, total page count
and pages per block, updating globals in that order. Query failure returns zero
without rolling back preceding updates. An injected page-count-query failure
therefore preserves a newly collected page size with the earlier count/block
values. No fallback is attempted after that driver's query failure.

If registry lookup itself returns zero, the function obtains the supplied
`nand_partition` board property and searches its original 16 rows. The tested
`eftl` entry resolves to `0x80c33a74` in the primary table or `0x80c336b4` in the
fallback table. An unready registry can therefore log an error while board
fallback still succeeds. Missing board data or a missing name returns zero.

The actual driver dispatchers use the selected root at `0x80d81f10`, its pointed
operation table, and the read/ioctl slots at +8/+24. Missing root, operation
table or callback returns `-6`. Actual chip ioctl `0x80c292ee` reads the selected
chip descriptor at `0x80d81f28`; absent descriptor returns `-2`, while an unsupported
command returns `-9`. Driver registration/probing that supplies these roots is
not executed here.

## Partition-relative geometry and control requests

Actual `0x80c2964c` validates page alignment of the partition offset and span.
A zero span derives the remainder from the refreshed total page geometry.
The selected commands behave as follows:

| Command | Observed partition-wrapper behavior |
| --- | --- |
| 1 | Returns partition span divided by page size, without a driver call |
| 8 | Requires block alignment and erases each selected block, ignoring results |
| 10/11/12 | Require block-aligned base; add the base block to a temporary caller index |
| 15 | Add the base page to both first caller words, then dispatch |
| Other selected geometry commands | Forward to the actual chip ioctl handler |

Commands are decimal in this table. Command 15 mutates the caller's two page
words before dispatch: supplied values 5/9 become 517/521 in the fixture. The
mutation survives a negative lower result and even a missing driver root.
Block commands instead use temporary storage and preserve the caller's index.
The format fixture erases blocks 8 and 9, receives two supplied failures and
still returns zero.

The chip ioctl handler expands descriptor fields into 32-bit outputs, including
four ECC position words read from u16 descriptor slots. These software descriptor
reads now execute; the descriptor's actual hardware provenance remains unknown.

Actual EFTL geometry collection now runs through ROM partition lookup, actual
partition ioctls, driver dispatch and descriptor reads. With supplied 2,048-byte
pages, 32,768 total pages and 64 pages/block, the original `eftl` span yields
5,632 partition pages, 88 blocks and base page 512. The total page-count query
and partition page-count query are distinct. Both primary and fallback routes
execute. This pass does not run the full allocator/scan initializer over those
88 blocks; its earlier bounded integration used a smaller authored geometry.

## Read dispatch and the OOB adapter

Actual `0x80c29532` checks handle/output presence and partition alignment, adds
the partition base in pages and forwards page/column/count through the actual
read dispatcher. Selected negative and positive service statuses propagate.
Zero-length requests still dispatch. A requested page beyond the declared span
also reaches the supplied service: this wrapper does not check that request
against the span here. Lower physical-driver bounds remain outside coverage.

Actual `0x80c027b0` requests the spare bytes at column `page_size & 0xffff` into
scratch immediately after the page area. The generic route uses the partition
read path; the alternate route calls the supplied fast service with the added
base page and flag 1. Only zero service status proceeds to extraction. A supplied
short copy with zero status can leave earlier scratch bytes in the extracted
record; this is a fault fixture, not a claim about the real page-service contract.

## ECC-position extraction and inverse composition

Actual extractor `0x80c025d4` requires total ECC size at least four bytes. With
ECC unit size below four, it gathers up to four bytes from the position entries.
When the first position is zero, the first segment skips two marker bytes and
subtracts two from that segment length. With unit size at least four, it copies
four contiguous bytes from the **second** position word.

Actual composer `0x80c026a6` first fills the spare area with `ff`, then writes the
four input bytes using the corresponding segmented or contiguous layout. The
selected compositions preserve their input buffer. Native compose/extract round
trips recover `01 00 45 46` for segmented, contiguous and marker-skip fixtures.
These operations serialize scratch metadata; no physical page is programmed.

Additional direct fixtures document caller constraints:

- Zero ECC unit size can make four empty copies and return zero with the output
  unchanged, or leave only the cleared spare area on composition.
- Unit size one with first position zero wraps the subtraction before clipping
  to four bytes in the extractor.
- Insufficient total ECC reaches the extractor's assertion before copying; the
  composer's corresponding assertion occurs after spare clearing.

Assertions stop before their bodies. Malformed direct fixtures bypass the
normal geometry collector's validation and do not establish device faults.

## Reproduction and verification

Use startup-aware `boot-runtime.elf`, apply `SeedNandPartition.java`, then export
`nand_partition.py:TARGETS` through `DecompileWithLogger.java`, logger
`0x80c1cd7a`, into ignored `firmware/decompiled/runtime-nand-partition`. The seed
guards partition-ioctl bytes and declares reviewed signatures without modifying
the image.

```sh
python3 analysis_scripts/nand_partition.py \
  --vectors-output firmware/nand-partition-native-vectors.json
```

Run headless with:

```text
-postScript ValidateNandPartition.java firmware/nand-partition-native-vectors.json firmware/nand-partition-native-validation.json
```

```sh
python3 analysis_scripts/nand_partition.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-partition \
  --vectors firmware/nand-partition-native-vectors.json \
  --validation firmware/nand-partition-native-validation.json > analysis/nand-partition.json
python3 -m unittest discover -s tests -p 'test_nand_partition.py' -q
```

The runner pins 11 executed code ranges and three original table/configuration
ranges, rejects unexpected PCs/service arguments, and caps each case at 100,000
steps. It checks return ABI for normal exits, explicit assertion stops, complete
lookup/dispatch/page/control/copy/log traces, geometry updates, caller argument
mutations and context/output/scratch bytes or hashes. Synthetic driver/chip/probe
inputs, packing input and output guards are checked. Eleven fresh export hashes
and the storage-facts file hash are recorded. Forty-three new host checks pass;
the full Python suite reaches 896 passing tests.

Next work includes actual driver registration/probe and chip-geometry provenance,
lower page/ECC/bus operations, program/erase effects, mapping repair/write paths,
SFTL and physical persistence. Device-specific backup/restoration and a viable
standalone boot path through the signed chain remain unresolved.

The subsequent [candidate/probe pass](NAND_PROBE_AND_CHIP_TABLE.md) recovers 11
original descriptors and executes matching, ID/reset command builders, probe,
mutex/root setup and original OOB layout round trips in 60 native cases. Bus
responses remain supplied; no fitted chip is identified by those fixtures.
