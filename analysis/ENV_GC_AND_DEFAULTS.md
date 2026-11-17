# Record relocation, sector collection and defaults restoration

This pass follows [detailed space/tail scanning](ENV_SPACE_AND_TAIL_SCAN.md) into
actual relocation, sector collection, erase/reformat and defaults restoration.
All 35 native cases pass: 13 move, ten collection, five format, two maintenance
and five defaults cases. They total 874,556 bounded steps including supplied
calls; the maximum is 166,469 for the duplicate-present move path. All 666 Python
tests pass, including 30 new checks. Complete observations and provenance are in
[env-gc.json](env-gc.json).

Reservation, detailed space parsing, record search/CRC, status updates, append,
cache updates, relocation and the collection callback all execute natively.
Low-level reads/writes/erase, memory/string services and diagnostics are supplied.
Writes apply bytewise AND to arrays; a successful supplied erase fills a sector
with `ff`. These are runner assumptions, not verified physical flash behavior.
No device, real environment or physical flash is accessed.

## 1. Logical range and sector formatter

Actual `0x80c0d184(sector)` requires 4,096-byte alignment and an address below
`0x4000`. Its erase adapter `0x80c0c172` checks alignment, calls the supplied
device erase service `0x80c245be`, and converts a negative result to 1 after
logging; nonnegative results become zero.

These fixtures therefore use logical sector addresses 0, `0x1000`, `0x2000`,
`0x3000`. The earlier scan fixtures deliberately used an arbitrary `0x6000`
base; they did not execute this formatter. The startup-derived base global is
also initially zero, but actual device mapping/handle setup remains open. Host
models now parameterize this base while preserving earlier fixtures exactly.

After successful erase, the formatter programs a 20-byte header:

| Header offset | Bytes |
| --- | --- |
| +0 through +2 | `00 ff ff`, primary state 1 |
| +3 through +5 | `00 ff ff`, dirty state 1 |
| +6 through +7 | `ff ff` |
| +8 through +11 | `EF40` |
| +12 through +19 | Eight `ff` bytes |

It removes the sector from the end cache even when that header write fails.
An existing cached end word can remain behind an invalidated address tag.
This routine itself does not invalidate the key cache. Erase failure returns 1
without writing a header; header-write failure returns 3 after the array erase.
A supplied three-byte write result produces success with only an incomplete
header programmed. Whether the actual device service can return partial counts
is still unknown.

## 2. Actual raw record relocation

`0x80c0cfac(record_descriptor)` receives a parsed descriptor. Direct move cases
supply that descriptor; collection cases obtain it through the actual parser.
The observed sequence is:

1. If the source status is 2, attempt the state-3 mark and set pending-replacement.
2. Reserve the descriptor's total size through actual sector enumeration and
   detailed-space parsing. Failure returns 6, leaving the attempted source mark.
3. If global `0x80d81d3e` is set, scan for an eligible same-name record. Finding
   one skips copying and proceeds to source finalization.
4. Otherwise prepare the destination sector, write destination state 1 and copy
   source bytes from +8 through its total extent in chunks of at most 32 bytes.
5. Attempt destination state 2, update sector-end/key caches, log `0x5a4`, then
   attempt source state 4.

The destination gets its own status bytes; header/CRC/key/payload bytes are copied
verbatim. Positive tests provide at least two primary-state-1 sectors, exercising
an actual copy rather than the last-empty-sector reservation guard. A separate
no-space case checks that guard/failure path.

The move result is the last body-copy write status. A first-chunk write failure
can be overwritten by a successful final chunk. Sector preparation, initial/final
status writes and source finalization do not determine that return value. Cases
inject errors into all seven writes of the ordinary move; later actions still
execute. A failed last body write returns 3 after cache publication and attempted
source deletion. A short body write can likewise leave an incomplete destination
while the move returns zero.

A source already in state 3 skips the initial mark. With pending-replacement
initially zero, its final deletion can invalidate the newly updated key-cache
entry even though the copied record remains in storage. The covered state-2
path sets pending and preserves the destination cache on final source deletion.
These are bounded caller-state cases, not a claim that every fixture state is
reachable through a live initialization sequence.

The duplicate-guard cases execute the actual name scan with absent/present
duplicates. A present eligible record skips the copy and finalizes the old
source. This flag is linked statically to the initialization caller below;
its complete lifecycle has not yet been executed.

## 3. Collection, maintenance and failure handling

Actual `0x80c0d27e(sector_descriptor)` returns immediately for an unrecognized
sector or dirty states other than 2/3. Otherwise it attempts dirty state 3,
walks records and relocates only CRC-valid records in states 2/3. Deleted and
CRC-bad records are skipped. One- and two-record cases verify destination bytes
and cache state. After traversal it calls the formatter on the source, logs
`0x5f0` and returns zero.

A nonzero move result logs `0x5e9` but does not stop collection. In the supplied
no-space and copy-error cases, the source is still erased/reformatted. An erase
error from that final formatter also does not change collection's zero return.
Full storage hashes and error/call order are checked. These cases delimit error
propagation under injected failures; they do not prove device-level invariants,
atomicity or safe recovery from interrupted programming.

Actual maintenance `0x80c0cb16` now calls the actual collector, rather than the
previous supplied GC boundary. With fewer than two recognized primary-state-1
sectors it traverses sectors for collection, then clears the maintenance flag.
An already-set flag allows the selected last-empty-sector move in the positive
maintenance fixture. With enough empty sectors, collection is skipped.

## 4. Defaults restoration is a separate destructive operation

Actual `0x80c0d494()` requires a nonnull default table at `0x80d81d48` and nonzero
count at `0x80d81d44`; assertion paths are not executed here. It takes the
environment lock path, formats all four logical sectors, then appends entries
from the configured table. Entries are 12 bytes: key pointer, value pointer and
length. A zero length requests actual caller-side string length through the
supplied string service. The fixture table/data are independently authored,
not recovered device defaults.

Formatting errors stop the loop, unlock and propagate (1 for erase failure,
3 for header-write failure). Per-entry append status is ignored. Both a failed
sector-preparation write and a failed final record marker can coexist with
defaults restoration returning zero. The successful two-entry case checks
`upgrade=one` from a zero length field and `mode=tw` from an explicit length 2.
Every write/erase here affects only the synthetic array.

## 5. Initialization caller: static follow-up

A fresh export and separate disassembly identify `0x80c0d58e` as a caller of
repair/format/scan logic. Selected instructions confirm it sets global
`0x80d81d3e`, can call `0x80c0bd10` before falling back to defaults restoration,
uses a three-attempt maintenance/scan loop, and calls `0x80c0bc28` / `0x80c0bd10`
again on its retry route. The return route clears the duplicate-scan flag.

This caller is exported/hashed but **does not execute in the 35 native cases**.
The callbacks at `0x80c0d242`, `0x80c0cd56`, `0x80c0d0f4`, storage dump/copy helpers
and the outer binding routine still need connected validation. This pass does
not establish boot initialization, real default-table population or persistence
across a reset.

## Reproduction

Use startup-aware `boot-runtime` / `boot-runtime.elf` with existing AndeStar
repairs and prior environment metadata. Apply `SeedEnvGC.java`, then export the
eight `env_gc.py:TARGETS` using `DecompileWithLogger.java`, logger `0x80c1cd7a`,
into ignored `firmware/decompiled/runtime-env-gc/`.

```sh
python3 analysis_scripts/env_gc.py \
  --vectors-output firmware/env-gc-native-vectors.json
```

Run headless with `-process boot-runtime.elf -noanalysis -scriptPath analysis_scripts`:

```text
-postScript ValidateEnvGC.java firmware/env-gc-native-vectors.json firmware/env-gc-native-validation.json
```

```sh
python3 analysis_scripts/env_gc.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-env-gc \
  --vectors firmware/env-gc-native-vectors.json \
  --validation firmware/env-gc-native-validation.json > analysis/env-gc.json
python3 -m unittest discover -s tests -p 'test_env_gc.py' -v
```

The runner guards twenty code ranges plus the CRC table, rejects unexpected
PCs/services, caps each case at one million steps, checks returned ABI and output
guards, compares complete I/O/diagnostic traces, full synthetic storage/cache
hashes and pending/maintenance flags against an independent host contract. Eight
export hashes include the separately identified static caller. Vendor material
stays ignored. Physical backup/restoration, actual storage semantics and viable
independent boot through the signed chain remain unresolved.

The subsequent [initializer/binding/copy pass](ENV_INITIALIZATION_AND_BACKUP.md)
adds 34 native cases executing the previously static initializer and callbacks.
The helpers at `0x80c0bc28` / `0x80c0bd10` are identified as diagnostic dump and
reserve-image copying. Actual device-handle setup and physical persistence remain open.
