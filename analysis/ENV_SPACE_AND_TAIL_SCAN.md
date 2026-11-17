# Detailed sector space, tail scan and cached reservation

This pass removes the supplied detailed-space boundary from
[sector lookup/reservation](ENV_SCAN_AND_RESERVATION.md). Actual
`0x80c0c818(address, descriptor, 1)` executes its record walk, CRC, tail scan
and sector-end cache handling. Connected reservation uses these computed values.
All 36 native cases pass: 30 space-first and six reservation-first, including
four multi-call sequences. They total 2,484,506 bounded steps including supplied
calls; the maximum is 198,385 for two-sector reservation. All 636 Python tests
pass, including 29 new checks. Observations and provenance are in
[env-space.json](env-space.json).

Low-level device reads/writes, scratch memset and diagnostics are supplied.
Storage is a synthetic 16-KiB array with complete reads; successful marker writes
apply bytewise AND, a runner-imposed assumption. No real device is accessed.
Startup, GC relocation/erase, physical geometry/timing, power-loss behavior and
persistence remain outside scope.

## 1. Detailed header and record-space accumulation

The actual light EF40 header path executes first. A bad header returns 7.
Recognized headers initialize free count at descriptor +16 to zero and cursor
at +20 to sector +20. The primary-state branches are:

| Primary state | Detailed behavior in tested cases |
| --- | --- |
| 1 | Free 4,076, cursor sector +20; no record/tail walk |
| 2 with matching end cache | Cached cursor, free = sector +4,096 - cursor; no record/tail walk |
| 2 without matching cache | Walk records, scan the remaining tail and update the end cache |
| 0 or 3 | Free zero, cursor sector +20; no record/tail walk |

A cold state-2 scan starts with free 4,076 and cursor sector +20. Each accepted
record adds its parsed total length to the cursor and subtracts it from free.
A valid 42-byte `upgrade`/`payload` record produces cursor +62 and free 4,034;
two contiguous records produce +104 and 3,992. Incomplete state-1 and deleted
state-4 records with valid CRC also consume space.

When record validity is zero, states 1 or 5 still consume their parsed extent.
Other tested states (2, 3, 4) log the integrity warning, set free to zero, retain
the current cursor, and proceed to the tail scan with return status 2. Arbitrary
corrupt record sizes and assertion paths are outside this case set.

## 2. Tail scan and the free-count/error combination

The native tail pass reads chunks of up to 32 bytes from the accumulated cursor
through the sector end. It tracks transitions from non-`ff` to `ff` across chunk
boundaries. If the final byte is non-`ff`, it chooses the sector end. Otherwise
it uses the last tracked start of an erased run. If that differs from the old
cursor, both cursor and free count are recomputed.

Cases cover a gap between records, programmed tail bytes, alternating erased
holes, a transition at a chunk boundary and a programmed final sector byte.
Two records starting at +20 and +100 have their byte-accounting cursor corrected
to +142. Programmed tail bytes at +100 through +103 move a single-record cursor
to +104. A programmed byte at +4095 makes free zero. These selected patterns do
not establish general crash consistency.

The tail pass can overwrite the zero free count set after a CRC error. In the
tested CRC-bad state-2 record, the full parser returns **2**, but also reports
cursor +62 and free **4,034**. This combination is checked against native
execution, including warning, complete read trace and descriptor hash.

Connected actual `0x80c0ca72` reservation still selects that computed cursor
when other eligibility checks pass: the enclosing sector iterator does not use
the detailed parser's return status. The same size guard remains strict:
a 4,034-byte request fails, while a 4,033-byte request selects that cursor.

## 3. Sector-end cache reuse

After cold scanning, actual `0x80c0c30a` updates the four-slot sector-end cache
at `0x80de62e4`. The runner compares all 32 bytes. A sector-end cursor does not
create an entry in the initially empty cache.

A second detailed parse after a successful scan performs only the 20-byte header
read and uses the cached end. Fixtures also seed slots 0, 2 and 3, including a
cursor exactly at the sector end. Those cached cursors are trusted by this path;
no record or tail bytes are read.

The CRC-error case also caches its computed cursor. A connected second parse
returns zero with the same cursor/free count and no new warning. A subsequent
reservation can use it. These are differences between cold and cached behavior,
not post-reset reconstruction or durable acceptance of a damaged record.

## 4. Parsing can attempt a status write

The first candidate in an open sector is sector +20, including when that slot
is erased in the supplied backing. Actual `0x80c0c6f8` treats selected invalid
total lengths (tested zero and `0xffffffff`) as a 28-byte invalid record. If its
parsed state is not already 5, it emits diagnostic `0x283` and calls the actual
status writer for state 5, attempting a zero byte at record +4.

The full sector parser permits that invalid/state-5 extent, consumes 28 bytes
and continues. An otherwise erased open-sector fixture returns zero with cursor
+48 and free 4,048; its synthetic marker byte is cleared. The corresponding
supplied write failure leaves the bytes unchanged but still produces return
zero and the same accounting. No physical flash operation is performed.

## Reproduction and bounds

Use startup-aware `boot-runtime` / `boot-runtime.elf` with existing AndeStar
repairs. Apply `SeedEnvRecords.java` and `SeedEnvScan.java`, then export the nine
`env_space.py:TARGETS` using `DecompileWithLogger.java`, logger `0x80c1cd7a`,
into ignored `firmware/decompiled/runtime-env-space/`.

```sh
python3 analysis_scripts/env_space.py \
  --vectors-output firmware/env-space-native-vectors.json
```

Run headless with `-process boot-runtime.elf -noanalysis -scriptPath analysis_scripts`:

```text
-postScript ValidateEnvSpace.java firmware/env-space-native-vectors.json firmware/env-space-native-validation.json
```

```sh
python3 analysis_scripts/env_space.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-env-space \
  --vectors firmware/env-space-native-vectors.json \
  --validation firmware/env-space-native-validation.json > analysis/env-space.json
python3 -m unittest discover -s tests -p 'test_env_space.py' -v
```

The runner guards fourteen code ranges and the CRC table, rejects unexpected
PCs/services, caps each case at 300,000 steps and checks returned ABI, output
guards, key immutability, complete read/write/diagnostic traces, header/storage/
cache hashes, cursor/free values and maintenance flag against an independent
host model. Nine fresh export hashes and the original boot-member hash are
recorded. Vendor code/images/tools/databases stay ignored.

The model reuses prior traversal and reservation contracts; the native runner
executes the actual detailed branch and callers. Broader malformed inputs,
stale-cache provenance, concurrency, GC relocation/erase, startup initialization
and actual device semantics remain open. Safe device-specific backup/restoration
and viable independent boot through the signed chain are still unresolved.
