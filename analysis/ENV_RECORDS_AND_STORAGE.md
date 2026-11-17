# Environment records, cached reads and staged writes

This pass follows [boot environment wrappers and key policy](BOOT_ENVIRONMENT_AND_KEY_POLICY.md)
into actual record serialization, CRC, status markers, cached lookup, descriptor
parsing, deletion and connected get/set paths. All 57 native cases pass: 24
append-first, five setter-first, six removal-first, three decoder, one getter,
nine read-adapter and nine write-adapter cases. They total 136,410 bounded steps,
including supplied calls; the maximum is 88,419 for the maximum-size record and
cached read. All 578 Python tests pass, including 28 new checks.
Observations and provenance are in [env-records.json](env-records.json).

Low-level device reads/writes use a synthetic 32-KiB array. Successful writes
apply bytewise AND to model one possible erased-flash programming constraint;
partial results copy/program only the supplied count. This behavior is imposed
by the runner, not recovered from real hardware. Reservation, sector-scan misses
and maintenance remain supplied. No sector enumeration, garbage collection,
reboot reconstruction, physical I/O or power-loss recovery executes.

## 1. Storage routing and return-value conversion

Actual `0x80c0bf58(address, output, count)` and
`0x80c0bfe2(address, input, count)` route calls as follows:

| Logical address | Selected handle and forwarded offset |
| --- | --- |
| `0x4000 <= address < 0x5000`, handle at `0x80d81d28` nonzero | That handle; `address - 0x4000` |
| Same window, first handle zero, fallback at `0x80d81d34` nonzero | Fallback handle; unchanged address |
| Same window, both handles zero | Log; return 2 for read or 3 for write, without calling the device service |
| Outside window | Handle at `0x80d81d30`; unchanged address |

Outside that special window even a zero general handle is forwarded; its meaning
belongs to the underlying service. Supplied read/write services are at
`0x80c24446` / `0x80c24502`.

A negative service result becomes 2 for read or 3 for write after logging.
Every nonnegative result becomes zero. The adapters do not compare it with the
requested count. Direct tests include a three-byte result for a larger request,
and append tests include zero-byte writes at each later stage. Whether the real
device services can return such partial counts remains unverified.

The address-window tests use synthetic logical addresses and handles. They do
not identify actual partitions, flash base addresses or device geometry.

## 2. Record layout and native CRC

Actual `0x80c0cbca(context, key, payload, payload_length)` accepts tested ASCII
keys of up to 32 bytes and total record length up to `0xfec` (4,076). A 33-byte
key returns 4; total 4,077 returns 6. The layout is:

| Offset | Serialized bytes |
| --- | --- |
| +0 through +4 | Five status bytes, initially erased; successive states clear individual bytes |
| +5 through +7 | Erased padding |
| +8 | Four bytes `KV40` (`0x3034564b`, little endian) |
| +12 | Little-endian total `28 + key_length + payload_length` |
| +16 | CRC-32 over bytes +20 through the end |
| +20 | One-byte key length |
| +21 through +23 | Three erased bytes `ff ff ff` |
| +24 | Little-endian payload length |
| +28 | Exact key bytes, followed immediately by payload; no key terminator |

The actual CRC thunk `0x80c0d85c` jumps to `0x80c00b24`. Both execute, using
the original guarded table, and agree with host CRC-32 chaining across the
eight bytes at +20, the key and the payload. CRC does not cover the status,
padding, `KV40`, total-length field or CRC field itself.

`0x80c0c5cc(address, scratch, state_count, state)` fills `state_count - 1`
scratch bytes with `ff`, clears scratch byte `state - 1`, then requests a
one-byte write at `address + state - 1`. Covered record states are 1 through 4
with count 6. `0x80c0c2f0` scans backward across those count-minus-one bytes,
returning the last zero's index plus one, or zero when none is zero. Invalid
arguments/assertion loops and broader malformed-record lengths are outside
this native case set.

## 3. Append ordering and sector/key cache effects

The supplied sector context has relevant fields at +1 (state), +4 (sector
address), +16 (free count) and +20 (record cursor). Cursor `0xffffffff` requests
supplied reservation; a failed reservation returns 6.

Actual sector preparation `0x80c0c660` can change a sector's primary status.
State 1 requests state 2. For context state 2, a free count below 60, or unsigned
`free - total` below 60, requests state 3, drops its cached end pointer through
actual `0x80c0c30a`, and sets a caller-local full flag. Cases distinguish 59 from
60 remaining bytes. A deliberately inconsistent supplied free count of 64 with
a 99-byte record wraps the subtraction and does not set that full flag; this
documents arithmetic under synthetic input, not a reachable device condition.

After successful sector preparation, the native append order is:

1. Write record state 1 at record +0.
2. Write the 20-byte header at record +8.
3. Write the key at record +28.
4. Unless full, update the sector-end cache to record + total. Update the key
   cache through actual `0x80c0c3a2`, even if the key write just returned an error.
5. If the key write succeeded, write the payload.
6. If that succeeded, write record state 2 at record +1. On success with the
   full flag, set global maintenance byte `0x80d81d3f` to 1.

Negative results at each of the five ordinary record writes return 3 and stop
later writes, while preserving prior bytes/cache updates. A failed key write
can therefore coexist with an advanced sector-end cache and published key
cache entry. A supplied zero-byte write still produces adapter success, so
append continues and can return zero with incomplete record bytes.

These observations delimit the code's error propagation; they do not establish
physical flash atomicity, durability or the behavior after a reset.

## 4. Cached lookup and descriptor parsing

Actual `0x80c0cdf6` searches the 16-slot key cache at `0x80de6304`, using the
upper 16 bits of the key CRC. On the covered hit it reads 32 bytes from record
+28, compares the requested key length, updates the cache age, sets descriptor
+48 to the record address and calls actual `0x80c0c6f8`. Misses reach supplied
`0x80c0cd82`, which reports no record. Full scans, collisions, eviction and
reconstruction of the cache after startup are not validated here.

For the bounded complete records tested, the parser reads 28 bytes, extracts
status and total length, then checks CRC in chunks of up to 32 bytes. On CRC
match it fills the following 56-byte descriptor fields:

| Descriptor offset | Value |
| --- | --- |
| +0 | Parsed status |
| +1 | CRC-valid flag 1 |
| +2 | Key length |
| +8 | Total record length |
| +12 | Payload length |
| +16 | Key bytes |
| +48 | Caller-supplied record address |
| +52 | Payload address, record +28 + key length |

CRC mismatch clears validity and leaves other payload/key fields untouched;
the direct decoder case seeds those fields with zero. A changed `KV40` field
with otherwise valid bytes gives the same parsed descriptor, confirming that
this parser itself does not validate that field. Other scanner filters are
outside scope.

One append/get sequence injects an error on the final state-2 write: append
returns 3, the record remains state 1, and an actual cached getter still returns
the complete 16-byte payload. The equivalent zero-byte final-write case makes
append return zero and the cached getter also succeeds. This is evidence about
cached visibility before the final marker, not about post-reboot acceptance.
Getter tests with corrupt CRC or arbitrary stale descriptor backing are not
included. Structured operations use complete supplied reads.

## 5. Delete, replacement and the upgrade payload

Actual `0x80c0ced6` resolves a null descriptor through lookup; a supplied scan
miss returns 4. A non-final call writes state 3 and sets pending-replacement
byte `0x80d81d3d` to 1, including after a write error. A final call attempts
state 4 and clears that byte. Successful final removal invalidates the key
cache only when the pending byte was previously zero, allowing replacement
to preserve the newly appended record's cache entry.

After a successful record-state write, deletion reads the sector's separate
three-byte dirty-state field at aligned-sector +3. Dirty state 1 requests state
2, writing at sector +4. These dirty markers differ from the primary sector
markers used by append. A dirty-marker error propagates after the record state
has already changed.

Connected actual setter/getter cases cover new records, existing-record
replacement, failed old-record marking and failed final old-record removal.
The last failure returns 3 while a subsequent cached getter reads the new value.
Failed marking retains the old cache/value and leaves pending-replacement set.

Another connected case uses the exact 298-byte `upgrade` payload reconstructed
and separately checked against the native boot-main prefix in the previous
pass. Actual setter, append, CRC, cached lookup, parser and getter write/read
those bytes inside a 333-byte `KV40` record on synthetic storage. Boot-main and
the later recovery consumer are not executed in this case.

## Reproduction and remaining work

Use the startup-aware `boot-runtime` / `boot-runtime.elf` project with existing
AndeStar repairs. Apply `SeedEnvRecords.java`, then use `DecompileWithLogger.java`
with logger `0x80c1cd7a` to export the eleven `env_records.py:TARGETS` into ignored
`firmware/decompiled/runtime-env-records/`.

```sh
python3 analysis_scripts/env_records.py \
  --vectors-output firmware/env-records-native-vectors.json
```

Run headless with `-process boot-runtime.elf -noanalysis -scriptPath analysis_scripts`:

```text
-postScript ValidateEnvRecords.java firmware/env-records-native-vectors.json firmware/env-records-native-validation.json
```

```sh
python3 analysis_scripts/env_records.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-env-records \
  --vectors firmware/env-records-native-vectors.json \
  --validation firmware/env-records-native-validation.json > analysis/env-records.json
python3 -m unittest discover -s tests -p 'test_env_records.py' -v
```

The runner guards eleven code ranges and the CRC table, rejects unexpected
PCs/services, caps each case at 200,000 steps, checks returned ABI, output guards,
unchanged inputs, complete storage traces, storage/output/descriptor hashes,
cache pointers and pending/maintenance flags against an independent host model.
It tests one key/cache slot per case. Fixture bounds are not firmware validation
guarantees. Eleven fresh export hashes and the original boot-member hash are
recorded. Vendor code/images/tools/databases stay ignored.

Reservation and sector enumeration/scan filters, garbage collection/maintenance,
startup cache reconstruction, actual storage/device semantics, reset/power-loss
behavior and subsequent recovery/UI consumers remain open. Physical backup,
device-specific restoration and standalone signed-chain boot are still unresolved.

The subsequent [empty-cache scan/reservation pass](ENV_SCAN_AND_RESERVATION.md)
adds 41 native cases for light EF40 parsing, traversal, record filtering, policy
and retry scheduling. Detailed free-space decoding and GC relocation remain
supplied; the pass does not execute startup or establish post-reset persistence.
