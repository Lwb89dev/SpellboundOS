# Native EFTL mapping reconstruction from OOB records

All 27 bounded native cases pass, totaling 2,988 steps (maximum 426 for a direct
repeat). Actual scan `0x80c01d8a` and checksum verifier `0x80c01a0a` execute over
authored bad-block, erase and first-page OOB services. Complete observations and
provenance are in [eftl-resume.json](eftl-resume.json).

This extends the [logical translation/read pass](EFTL_TRANSLATION_AND_PAGE_READ.md)
by executing selected reconstruction logic for its u16 mapping table. Geometry,
OOB bytes, initial counters and backing storage are synthetic. Physical NAND,
ECC, buses, erase effects, the complete initializer and real mapping provenance
remain outside coverage. No watch or phone is accessed.

## Four-byte OOB record and checksum

The selected record consists of a little-endian u16 logical-block index, tag
byte `0x45` (`E`) and one checksum byte. The checksum verifier accepts when the
last byte equals the sum of the first three modulo 256. For example,
`ff 80 45 c4` passes. The verifier itself does not check the tag; the scan checks
the tag before calling it. A wrong tag therefore skips checksum verification.

The scan requests this record from the first page of each candidate block,
using page number `block_index * pages_per_block`. The OOB adapter that extracts
the record from NAND is supplied at `0x80c027b0`, so the physical OOB layout and
ECC metadata format are not inferred from these four fixture bytes.

## Block classification and reconstruction

Each visited flag byte is first ORed with `0xfe`. Actual control flow then:

1. Calls the supplied bad-block service. Zero permits the OOB read directly.
2. Logs a nonzero result. A negative result, or any nonzero result in repair
   mode, attempts the supplied erase service. A positive result in the first
   scan skips erase.
3. If the resulting status remains nonzero, sets flag bit 0 and increments the
   u16 reserved counter, without reading OOB.
4. Otherwise reads the first-page record. Any nonzero read status, including a
   positive one, logs an error and returns `-1`. Earlier mappings/counters and
   the pending block's flag update remain visible.
5. A correct tag/checksum with an empty (`0xffff`) logical mapping stores the
   current physical block index, increments the u16 used counter and encodes
   `pages_per_block << 1` in the flag byte while preserving bit 0.
6. A wrong tag or checksum increments the u16 free counter. A duplicate mapping
   does neither: the first mapping is retained, the flag stays at its initial
   ORed value, and neither used nor free is incremented for the duplicate.

The mixed fixture maps logical block 2 to block 0 and logical block 0 to block 2,
counts one free and one reserved block, and finishes with flags
`08 fe 08 ff 00 00 00 00`. Existing mappings are also retained unchanged.

## Completion and retry signal

At the end of the first scan, no free blocks combined with a nonzero reserved
count produces return 1 without setting context marker `0xa5`. Otherwise the
scan sets that marker and returns zero. Repair mode sets the marker and returns
zero on completion even if all visited blocks remain reserved after supplied
erase failures. A zero return therefore does not establish usable capacity.

These are direct scan calls. A direct repeat does not reset the caller's
counters: the mixed fixture accumulates additional free/reserved counts while
retaining its mappings. The outer initializer's buffer allocation, reset and
retry orchestration are not executed in this pass.

## Bounded index and integer counterexamples

The selected scan uses the OOB logical index directly for its mapping-table
access without comparing it to the declared block count here. An authored
one-block fixture with logical index 7 writes slot 7 within the runner's explicit
eight-slot backing. This establishes the missing local check, not an observed
hardware overwrite or the bounds guaranteed by all callers.

Free/used/reserved counters wrap at 16 bits. Fixtures show free-count wrap
causing retry, reserved-count wrap allowing completion, and used-count wrap
preserving the new mapping. The flag's page-count encoding also truncates to a
byte: a supplied 128-page block encodes zero in those bits. Real geometry and
caller invariants must be established before assigning physical consequences.

## Reproduction and verification

Use startup-aware `boot-runtime.elf`, apply `SeedEftlResume.java`, then export
`eftl_resume.py:TARGETS` through `DecompileWithLogger.java`, logger `0x80c1cd7a`,
into ignored `firmware/decompiled/runtime-eftl-resume`. The seed guards scan
bytes and declares reviewed function signatures; it changes no image bytes.

```sh
python3 analysis_scripts/eftl_resume.py \
  --vectors-output firmware/eftl-resume-native-vectors.json
```

Run headless with:

```text
-postScript ValidateEftlResume.java firmware/eftl-resume-native-vectors.json firmware/eftl-resume-native-validation.json
```

```sh
python3 analysis_scripts/eftl_resume.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-eftl-resume \
  --vectors firmware/eftl-resume-native-vectors.json \
  --validation firmware/eftl-resume-native-validation.json > analysis/eftl-resume.json
python3 -m unittest discover -s tests -p 'test_eftl_resume.py' -q
```

The runner guards both executed code ranges, rejects unexpected PCs and service
arguments, caps each case at 100,000 steps and verifies returned ABI. Complete
bad-block/erase/OOB/log order, record bytes, flags, mappings, counters, marker and
context hashes match an independent host contract. Output guards and immutable
checksum input are checked. Two fresh export hashes are recorded. Twenty-six
new host checks pass; the full Python suite reaches 819 passing tests.

Next work is the full allocator/geometry/scan/retry initializer, actual geometry
discovery and OOB transport, the remaining mapping repair/program/erase paths
and SFTL. Physical backup/restoration, signed boot and hardware persistence
remain open.
