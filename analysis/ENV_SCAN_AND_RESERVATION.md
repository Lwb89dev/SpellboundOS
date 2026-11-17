# Empty-cache lookup, sector traversal and reservation policy

This pass extends [environment records and staged writes](ENV_RECORDS_AND_STORAGE.md)
to lookup with empty caches, light sector-header decoding, linked traversal,
record filtering, reservation and maintenance/retry scheduling. All 41 native
cases pass: 16 find, two getter, four next-sector, three header, ten reservation,
two maintenance and four retry cases. They total 503,936 bounded steps including
supplied calls; the maximum is 67,100 for a CRC-bad record and following search.
All 607 Python tests pass, including 29 new checks. Complete observations and
provenance are in [env-scan.json](env-scan.json).

All storage reads return complete bytes from synthetic sector/record arrays.
Every case starts with empty key and sector caches. This does not execute
startup, reset or actual reconstruction of all caches after a reboot.
Detailed sector parsing (`0x80c0c818` with full/detail argument 1) is supplied:
the runner injects free count and cursor from the fixture. The GC callback
`0x80c0d27e` is also supplied and only records that it was reached. Record
relocation, erase and changes in available space do not run. The light/header
mode, traversals, record parser/CRC, filtering and scheduling execute natively.

## 1. EF40 header and next-sector walker

Actual `0x80c0c818(address, descriptor, 0)` reads a 20-byte aligned-sector
header. The covered descriptor fields are:

| Offset | Observed field in light mode |
| --- | --- |
| +0 | Header recognized: 1 for `EF40`, 0 otherwise |
| +1 | Primary state, decoded from the first three header bytes |
| +2 | Dirty state, decoded from header bytes +3 through +5 |
| +4 | Input sector address |
| +8 | Header word from bytes +8, expected `EF40` (`0x30344645`) |
| +12 | Word from header +12; `0xffffffff` for an unrecognized header |
| +16 and +20 | Untouched by this mode; later free-count/cursor fields |

The recognized header returns zero; the unrecognized one returns 7 and retains
the observed magic word in the descriptor. Status-byte decoding uses the actual
backward-zero helper checked previously. Aligned addresses and complete reads
are prerequisites of these cases; alignment assertion and partial read behavior
are not covered.

Actual `0x80c0c364(descriptor)` uses the base global at `0x80d81d4c`:

- Current address `0xffffffff` returns the base.
- Next-link word `0xffffffff` advances 4,096 bytes from the current address.
- Another link value advances that many 4,096-byte units from the current
  address, then checks against base + `0x4000`.
- Reaching/exceeding that upper boundary returns `0xffffffff`.

The synthetic base is `0x6000`. This confirms arithmetic in this walker, not
physical partition addresses or flash geometry. Fixtures use bounded noncyclic
chains. A two-unit link is exercised both directly and in record lookup,
skipping the intervening sector's header entirely.

## 2. Actual lookup from empty caches

Actual `0x80c0cdf6` falls through the empty key cache into actual
`0x80c0cd82`, which walks sectors. Header failures are skipped here. Only primary
states 2 or 3 reach record traversal; state 1 does not yield record candidates.

Actual `0x80c0c44c` initially proposes sector +20. After a decoded record it
advances by that record's total length when validity is nonzero, or one byte
when validity is zero. It then searches for `KV40`, reading 32-byte windows with
28-byte stride and interpreting the magic position as record address +8.
Cases cover contiguous records, an erased gap and resynchronization after a
CRC-bad record. Arbitrary corrupt lengths, embedded magic in payloads, malformed
first slots, sector-cache shortcuts and all possible boundary placements remain
outside this fixture set.

Each candidate reaches the actual descriptor parser and CRC routines checked in
the preceding pass. Actual comparison callback `0x80c0c54c` accepts only:

1. Stored key length equals requested string length.
2. Parsed validity is nonzero.
3. Record status is exactly 2.
4. Name comparison succeeds.

It sets the caller's found byte and stops traversal. The resulting record address
is inserted into the key cache by the native caller. Wrong name/length, CRC error
and states 1, 3 and 4 fail the filter. A later valid record is found after a
deleted or CRC-bad first record. Two eligible records with the same name return
the first encountered one in the covered traversal; no freshness field is used
by this callback.

Connected actual getters read `payload` from the found record, including a
three-byte capacity case that still reports original length 7. A state-1 record
is rejected from empty caches. This complements the prior cached-path result,
where a failed final state-2 write could still leave a readable cached payload.
It does not simulate a reset or establish what the initialization path restores.

## 3. Reservation and its free-space guard

Actual `0x80c0ca72(context, requested_size)` first enumerates light sector
headers and counts recognized primary-state-1 and primary-state-2 sectors
through actual callback `0x80c0c6d4`.

If primary-state-2 sectors exist, it traverses them, obtains the **supplied**
detailed free-count/cursor view and calls actual `0x80c0c59c`. A candidate requires:

- Recognized header.
- `requested_size < free_count`, with unsigned comparison.
- Dirty state 1, or dirty state 2 while maintenance flag `0x80d81d3f` is zero.

Equality is rejected: a request of 100 fails with free count 100 and succeeds
with 101. Dirty state 3 is rejected. A second eligible sector is tried after an
insufficient first candidate; the selected result is its supplied cursor.

If no candidate is found and primary-state-1 sectors exist, exactly one such
sector with a clear maintenance flag triggers diagnostic `0x506`, sets the flag
and returns `0xffffffff` without attempting it. Otherwise the same candidate
test is applied to primary-state-1 sectors. Cases cover both multiple available
sectors and the single sector with its flag already set.

The policy is native; free counts/cursors come from fixtures. These results do
not establish that detailed scanning computes those values correctly or that
reservation programs a sector header or changes device storage.

## 4. Maintenance and connected retry

Actual `0x80c0cb16` enumerates primary-state-1 headers and counts recognized ones
with actual callback `0x80c0c392`. After diagnostic `0x603`, a count below two
starts another traversal across sectors, invoking the **supplied** GC callback
at each visited sector. A count of at least two skips that traversal. The actual
function finally clears the maintenance flag.

Actual `0x80c0cb7a` first calls reservation. Only failure (`0xffffffff`) with a
nonzero maintenance flag triggers diagnostic `0x5b4`, maintenance, then one more
reservation attempt. Cases demonstrate:

- No eligible sectors and a clear flag: failure, no maintenance.
- No eligible sectors with a set flag: maintenance followed by another failure.
- One last primary-state-1 sector: the first attempt sets the flag; maintenance
  clears it; the second attempt rearms it and fails again.
- A dirty-state-2 candidate initially blocked by a set flag: maintenance clears
  the flag and the second attempt selects the same supplied cursor.

The last success follows flag policy; the supplied GC callback does not move any
record or free space. None of these cases establishes effective compaction,
erase behavior, durability or recovery after interrupted writes.

## Reproduction and remaining work

Use the startup-aware `boot-runtime` / `boot-runtime.elf` project with the
existing AndeStar repairs. Apply `SeedEnvScan.java`, then export the twelve
`env_scan.py:TARGETS` using `DecompileWithLogger.java`, logger `0x80c1cd7a`, into
ignored `firmware/decompiled/runtime-env-scan/`.

```sh
python3 analysis_scripts/env_scan.py \
  --vectors-output firmware/env-scan-native-vectors.json
```

Run headless with `-process boot-runtime.elf -noanalysis -scriptPath analysis_scripts`:

```text
-postScript ValidateEnvScan.java firmware/env-scan-native-vectors.json firmware/env-scan-native-validation.json
```

```sh
python3 analysis_scripts/env_scan.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-env-scan \
  --vectors firmware/env-scan-native-vectors.json \
  --validation firmware/env-scan-native-validation.json > analysis/env-scan.json
python3 -m unittest discover -s tests -p 'test_env_scan.py' -v
```

The runner guards twelve code ranges and the CRC table, rejects unexpected PCs,
checks supplied service arguments, caps each case at 200,000 steps, verifies
returned ABI, output guards, immutable inputs/storage, complete read/boundary
traces, descriptor/header/output hashes, cache pointer and maintenance flag
against an independent host contract. Twelve fresh export hashes and the
original boot-member hash are recorded. Vendor material stays ignored.

Detailed sector/free-space parsing and end-cache reconstruction, GC relocation
and erase, actual initialization/reboot behavior, storage semantics and physical
persistence remain open. The subsequent boot/recovery/UI consumer, safe physical
backup/restoration and viable independent boot through the signed chain also
remain unresolved.

The following [detailed-space/tail pass](ENV_SPACE_AND_TAIL_SCAN.md) removes the
supplied free-count/cursor boundary in 36 native cases, including cache reuse and
connected reservation after a CRC error. Low-level storage remains synthetic;
GC relocation/erase and startup/device persistence remain open.
