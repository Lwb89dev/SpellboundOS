# Boot environment wrappers, reason cache and key policy

This pass connects [recovery selection and stopped handoff](RECOVERY_SELECTION_AND_HANDOFF.md)
to environment wrappers, cached boot reasons, the keyboard policy and the actual
boot-main prefix that constructs an `upgrade` record. All 64 native cases pass:
ten getter, 16 setter, one commit-only, 12 reason, 17 key-policy and eight caller
prefix cases. They total 11,630 bounded steps, including intercepted calls;
the maximum is 1,060. All 550 Python tests pass, including 28 new checks.
Complete observations and provenance are in [boot-environment.json](boot-environment.json).

Storage lookup/read/reserve/append/remove/maintenance, locks, board initialization,
power/keyboard/delay, strings and diagnostics are supplied. The runner checks
callback arguments, order, statuses and payload hashes. It does not implement
environment persistence, visibility after replacement, rollback or flash atomicity.
All retained bytes and keyboard samples are synthetic. No device is accessed.

## 1. Environment getter and setter

Actual `0x80c0d344(key, destination, capacity, original_length_output)` first checks
the initialized byte at `0x80d81d40`. If zero, it logs and returns zero without
resetting the optional length output. Otherwise it locks, looks up the key through
`0x80c0cdf6` into a 56-byte descriptor, then unlocks before returning.

A missing key sets the optional length output to zero. A found key reports the
stored length from descriptor +12, while returning `min(capacity, stored_length)`.
A nonnull destination requests a read from the address at descriptor +52,
including when the clipped count is zero. A null destination skips that read but
preserves the count. The read service status is ignored: a supplied error 2 with
no bytes copied still produces the clipped return count and original length.
An unchanged output therefore cannot be interpreted from that count alone.

Actual `0x80c0d3b4(key, data, length)` returns 7 if uninitialized. Otherwise it
locks and follows these branches:

| Branch | Observed callback order and result |
| --- | --- |
| Null data | `remove(key, 0, 1)`; propagate status, unlock; no reserve/lookup/maintenance |
| Nonnull data | Reserve `length + 28 + strlen(key)` using new descriptor `0x80de62cc` |
| Reservation returns `0xffffffff` | Return 6 after unlock; no lookup or maintenance |
| New key | Append using new descriptor; return append status |
| Existing key | Lookup into old descriptor `0x80de6294`, `remove(key, old, 0)`, append, then `remove(key, old, 1)` |

The existing-key sequence stops after any nonzero mark/append result. Final
remove status propagates. A reservation result of zero is accepted. A nonnull
empty value still reserves/appends and differs from deletion.

After lookup/mutation branches, a nonzero byte at `0x80d81d3f` triggers supplied
maintenance `0x80c0cb16`, whose return is ignored. This also occurs after a failed
mark step. The fixture maintenance clears the flag; its internals do not execute.
Direct deletion and reservation failure skip this maintenance test entirely.

Actual `0x80c0d490()` executes `return 0` with no other work. Both a direct case
and a setter/commit sequence confirm the boundary. Calling this function does
not establish that a preceding append reached nonvolatile storage.

## 2. Boot-reason cache and retained override

Actual `0x80c0ec70()` uses global `0x80d81afc`. Any value other than `0xffffffff`
returns immediately. Otherwise it calls supplied raw-reason service `0x80c12244`
and actual retained-copy wrapper `0x80c01884`, which requests 32 bytes from
`0x80dff738` through the supplied copy service.

When retained word zero is `0x5a5a5a5a`, word +4 becomes the reason/cache value.
Without that magic, raw values 1, 2 and 3 map to 0, 1 and 2; other tested values
map to 8. Repeated calls use the cache. A retained reason of `0xffffffff` remains
the uninitialized sentinel, so a second call repeats both services. These tests
do not establish which physical reset conditions produce these values.

## 3. Actual key policy

Actual `0x80c00312(handle)` obtains the reason and rejects 3 or 6 before power
or keyboard callbacks. It then requires supplied power-query status zero and a
nonzero output word. Keyboard requests use command 6, logical indices 0 and 1,
a one-byte output pointer and a final zero argument.

The native policy has three phases:

1. Poll index 0 until its value is zero. A nonzero value requests delay 50 and
   repeats. There is no local iteration limit in this initial release phase.
2. Try at most 20 pairs of index 0 then index 1. Both values must be exactly 1.
   A failed pair requests delay 50, including the twentieth failed pair. Success
   on attempt 20 is accepted.
3. Require 20 consecutive pairs with both values nonzero. Each successful pair
   requests delay 50, including the twentieth, then the function returns 1.

Any keyboard status error returns zero immediately; a zero during the hold phase
also fails. The press phase rejects `(2,1)`, while the hold phase accepts `(2,7)`.
Fixtures cover release waiting, the last press attempt, timeout, last hold-pair
release, both sample positions and driver errors in all three phases.

The service's argument 50 has no physically calibrated time unit here. Logical
indices do not establish the number or mapping of physical buttons. Finite input
traces and the emulator step cap bound these tests, not the real release loop.

## 4. Boot-main prefix and exact upgrade record

Actual `0x80c00454` runs from entry through keyboard setup and the record branch,
then stops at `0x80c005b8`, before the call to `0x80c01704` and subsequent dispatch.
Its board/display/hardware services are supplied. Registration requests
`keyboard` and global `0x80d81ce8`; successful registration calls initialization,
whose failure clears that global. Registration failure leaves its previous value
untouched. A synthetic preexisting handle therefore still reaches key detection
after a registration error; this does not establish a live stale-handle condition.

A zero keyboard global takes actual fallback `0x80c00450`, reason lookup and its
diagnostic. A nonzero global reaches the actual key policy. On key success the
native caller constructs the following 298-byte zero-initialized stack record:

| Offset | Bytes/field observed |
| --- | --- |
| +0 | Little-endian `0xb007cca6` |
| +4 | Little-endian length `0x12a` (298) |
| +8 | Bytes `02 01` |
| +10 through +41 | Zero |
| +42 | Byte 1 |
| +43 through +296 | 254-byte field containing `/mnt/backup/backup_fw_sign.zip`, padded with zero |
| +297 | Explicit zero |

It calls the actual environment setter for `upgrade` with that record and length
298, then actual `0x80c0d490`. Reservation requests 333 bytes for this key/payload.
The caller ignores setter status: uninitialized environment, reservation failure
and append error 5 still reach the same stopped record/key result. The backend
journal distinguishes no append from an append attempt returning failure.
Neither a constructed record nor reaching the stop proves persistence or that
recovery subsequently reads/accepts it.

The stopped prefix retains a live 0x150-byte caller frame. The runner checks saved
register slots, the original return address, live global-pointer registers,
record hash and unlocked state. It does not claim this function returned. Failed
key detection leaves the record zero in the covered branch. Recovery UI, erase,
restore, image launch and the remaining boot-main body do not execute here.

## Reproduction and bounds

Use the startup-aware `boot-runtime` / `boot-runtime.elf` project in ignored
`firmware/ghidra-runtime`, with the existing AndeStar repairs. Apply
`SeedBootEnvironment.java`, then export the eight `boot_environment.py:TARGETS`
with `DecompileWithLogger.java`, logger `0x80c1cd7a`, into ignored
`firmware/decompiled/runtime-boot-environment/`.

```sh
python3 analysis_scripts/boot_environment.py \
  --vectors-output firmware/boot-environment-native-vectors.json
```

Run headless with `-process boot-runtime.elf -noanalysis -scriptPath analysis_scripts`:

```text
-postScript ValidateBootEnvironment.java firmware/boot-environment-native-vectors.json firmware/boot-environment-native-validation.json
```

```sh
python3 analysis_scripts/boot_environment.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-boot-environment \
  --vectors firmware/boot-environment-native-vectors.json \
  --validation firmware/boot-environment-native-validation.json > analysis/boot-environment.json
python3 -m unittest discover -s tests -p 'test_boot_environment.py' -v
```

The runner checks four code-range hashes, rejects unexpected PCs/services, caps
each case at 100,000 steps, verifies complete action traces and snapshots against
an independent host contract, checks output guards and unchanged input data,
and verifies returned ABI or the distinct stopped frame. Host fixture bounds are
1,024-byte stored/copy data, 512-byte supplied payloads, ASCII keys of 1–31 bytes
and at most 160 keyboard samples. These are test limits, not inferred firmware
input validation. Eight fresh export hashes and the original boot-member hash
are recorded. Vendor code/images/tools/databases stay ignored.

Remaining work includes the environment backend layout, actual lookup/append/
remove/maintenance and write-atomicity semantics, the subsequent boot/recovery
dispatch and UI consumers, retained-state provenance, physical key/timing
behavior, non-destructive backup/restoration and signed-chain standalone boot.

The subsequent [record/backend pass](ENV_RECORDS_AND_STORAGE.md) adds 57 native
cases for actual append/delete, CRC, status updates, cache paths and connected
get/set with synthetic low-level storage. Reservation, full scans, maintenance,
post-reset persistence and physical behavior remain open.
