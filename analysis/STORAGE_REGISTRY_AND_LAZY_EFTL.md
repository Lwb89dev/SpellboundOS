# Native storage registry population and lazy EFTL geometry

All 32 bounded native cases pass, totaling 13,890 steps (maximum 1,490 for
allocation-failure retry). Actual device/partition initialization, backend find,
owner population, deferred EFTL/SFTL initializers, lazy EFTL geometry arithmetic
and the EFTL read wrapper execute. Complete traces and state observations are in
[storage-registry.json](storage-registry.json).

The runner uses the [original five-backend/16-partition configuration](STORAGE_MAP_AND_DRIVER_BINDINGS.md).
NAND/nandraw/disk initialization, heap allocation, geometry discovery and the
inner EFTL read's result/data are supplied services. No device, physical flash,
RTOS scheduling, FTL reconstruction or full boot executes.

## Device and partition initialization

Actual `0x80c24106` calls `0x80c23bd0` with the original five device pointers,
then `0x80c24340` with the original 16 rows. Both actual deferred EFTL/SFTL
callbacks execute and return zero after logging. The other three initializer
entries are supplied, with failures tested at indices 0, 1 and 3. Device ready
is set only after all callbacks succeed. Outer setup maps any initialization
failure to `-1`; a direct device call preserves its callback status.

Actual partition initialization publishes its table/count before attempting
owner allocation. Owner population `0x80c24140` requests 64 bytes for 16 pointers,
then resolves backend names through actual `0x80c23cee`. All 16 original rows
receive their matching descriptor pointers in the successful case.

Allocation failure leaves device readiness set, partition readiness clear,
the published partition pointer/count intact, and the outer device table unset.
A repeated setup retries allocation without rerunning device callbacks and can
then succeed. Existing owner storage is reused; existing device/partition ready
flags skip their respective work. An already-ready partition can therefore
leave the supplied stale owner array intact.

## Missing owners and extent checks

Missing backend lookup logs a warning and continues without assigning its slot.
Renaming only the EFTL device in an emulator fixture makes all seven EFTL-backed
partitions miss. Their owner words remain the supplied allocation pattern
`0xa5a5a5a5`, or `0x55555555` when reusing a stale array. Partition initialization
still returns zero and sets its ready byte. This is a control-flow/data result
with supplied heap contents, not proof of an observed device failure.

The start check uses a signed comparison against the descriptor capacity.
A start equal to capacity rejects, clears the partition count and leaves the
preceding owner assignments intact. Selected counterexamples also execute:

- Offset `0x80000000` is accepted against capacity `0x7fffffff` by the signed
  comparison.
- An oversized declared span is accepted when its start passes; this routine
  does not check the full extent.

These malformed fixtures stop at registration. No subsequent access through an
invalid owner/extent is attempted; the original image tables are not altered.

## Lazy EFTL descriptor update

Actual `0x80c231d6` checks ready byte `0x80d81ea2`. If clear, it calls supplied
geometry discovery `0x80c02298(0x80de5fb8, 0, 0)`. A negative result leaves the
descriptor and ready byte unchanged; zero or a positive result updates:

```text
block_size = pages_per_block * page_size
capacity = (block_count - reserved_count_u16) * block_size
```

Both assignments use the selected 32-bit arithmetic, then readiness is set and
a success message emitted. Supplied geometry `[64, 2048, 128, 4]` yields block
size 131,072 and capacity 16,252,928. A repeated call skips discovery. Separate
bounded cases show multiplication wrapping to zero and reserved-count
subtraction wrapping; neither is presented as actual NAND geometry.

Actual EFTL read wrapper `0x80c23252(offset, output, size)` runs lazy setup when
needed, returning `-14` if readiness remains clear. Otherwise it forwards to
`0x80c0219a(context, output, offset, size)`, supplied at this boundary. Full,
short and negative supplied results propagate; expected bytes and output guards
are checked. This pass does not execute the translation loop behind that call.

## Reproduction and guards

Use startup-aware `boot-runtime.elf` with `SeedStorageMap.java`. Export
`storage_registry.py:TARGETS` through `DecompileWithLogger.java`, logger
`0x80c1cd7a`, into ignored `firmware/decompiled/runtime-storage-registry`.

```sh
python3 analysis_scripts/storage_registry.py \
  --vectors-output firmware/storage-registry-native-vectors.json
```

Run headless with:

```text
-postScript ValidateStorageRegistry.java firmware/storage-registry-native-vectors.json firmware/storage-registry-native-validation.json
```

```sh
python3 analysis_scripts/storage_registry.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-storage-registry \
  --vectors firmware/storage-registry-native-vectors.json \
  --validation firmware/storage-registry-native-validation.json > analysis/storage-registry.json
python3 -m unittest discover -s tests -p 'test_storage_registry.py' -q
```

The runner pins nine code ranges plus eight original configuration/table/
descriptor ranges. It rejects unexpected PCs and supplied-service arguments,
caps each case at 100,000 steps, verifies return ABI, full action order, owner
arrays/backing hashes, capacity/block/ready/publication state and read buffers.
It also checks immutable descriptor control bytes, partition rows and pointer
tables, and heap/output guards. Nine export hashes and the original storage
facts file hash are recorded. Twenty-four new host checks pass.

Physical initialization and geometry, translation-table provenance and payloads,
real NAND reads/writes/erase/rewrite, atomicity, concurrency, persistence,
device-specific restoration and standalone boot remain open.
