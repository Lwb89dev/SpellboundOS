# Storage registry, environment setup and NVMS mirror repair

This pass connects named device lookup, partition validation and callback dispatch
to environment handle setup, NVMS mirror repair, bootstrap and a stopped framework
caller. All 52 native cases pass, totaling 26,784 bounded steps including supplied
calls; the maximum is 4,024 for fallback bootstrap. All 729 Python tests pass,
including 33 new checks. Complete observations and provenance are in
[env-storage.json](env-storage.json).

Registry rows/owners, device descriptors, volume bases/spans and physical driver
callbacks are synthetic. Actual lookup, validation, dispatch, setup, mirror logic,
write fallback and clean environment binding execute. Mutex callbacks count
acquisition/release without blocking; heap, programming, erase and rewrite operate
only on authored arrays. No device or physical flash is accessed.

## 1. Registry handles and partition dispatch

Actual `0x80c243d6(name)` scans the registry only when its initialized byte is set.
It uses a 60-byte stride and returns a pointer to the matching row, or zero.
This is name lookup, not an open/allocate operation. Relevant registry globals
are owner-array pointer `0x80d81ed4`, count `0x80d81ed8`, ready `0x80d81edc` and
row-base pointer `0x80d81ee0`.

Actual `0x80c24218` checks the selected row's owner and request extent. Tested
handles are valid aligned row addresses; arbitrary interior/out-of-range handles
and assertion paths are excluded. The relevant fields are:

| Structure | Offset | Observed role |
| --- | --- | --- |
| Registry row | +0 | Name compared by lookup |
| Registry row | +24 | Name used in diagnostics |
| Registry row | +48 | Physical offset added before callback |
| Registry row | +52 | Partition span; zero derives device capacity minus offset |
| Device descriptor | +28 | Capacity used for the derived-span case |
| Device descriptor | +44/+48/+52/+56 | Read/program/erase/rewrite callbacks |

Read `0x80c24446`, program `0x80c24502`, erase `0x80c245be` and rewrite
`0x80c24652` execute through this validator. A request extending beyond the span
is clipped; an offset at the span is rejected. Missing owner rejects without
calling a driver. Negative driver results propagate; a missing rewrite callback
returns `-1` with its diagnostic. Tests check all four clipped lengths, callback
physical offsets, negative results and derived capacity. Invalid read/program
callback pointers, arithmetic overflow and actual table population remain open.

The authored volume bases/spans in the runner are deliberately **not** evidence
of the watch's physical partition map.

## 2. Environment setup and the recovered default table

Actual `0x80c0be14(table_output, count_output)` publishes table `0x80c36518` and
count 1 before attempting mutex creation. The image table contains:

| Key pointer/value | Payload pointer/value | Length field |
| --- | --- | --- |
| `0x80c36510`: `boots` | `0x80c385b0`: `0` | 0, requesting string length |

The table/strings are independently checked against the original ZIP; their
provenance is recorded in the JSON. Clean bootstrap passes this actual table
to binding. This pass does not exercise inserting that ROM default into an
erased environment or establish all factory/device-specific settings.

Setup creates a mutex only if `0x80d81d38` is zero, then performs these lookups:

1. `easyflash`: if found, store it as fallback (`0x80d81d34`) and reserve
   (`0x80d81d2c`) handle.
2. Otherwise look up optional `envbak` for the reserve handle, then require
   `nvms` for special-window handle `0x80d81d28`.
3. Require `env` as active handle `0x80d81d30`.

The preferred branch leaves any previously supplied special handle untouched.
Failures return 7 while preserving the output table/count and preceding global
updates. Successful lookups call actual mirror synchronization but ignore its
return value; setup zero therefore does not establish valid/synchronized mirrors.

## 3. Two 160-byte records and routing

Actual `0x80c1c51a` reads two 160-byte records through `0x80c0d736`, at NV offsets
0 and `0x1000`. A primary read error returns `-14`; a secondary read error uses
an all-`ff` temporary secondary buffer. Observed selection is:

- Primary magic `0x55aa55aa`: equal records require no write; otherwise copy
  the primary to the secondary.
- Otherwise a secondary with that magic is copied to the primary.
- Neither magic valid: diagnostic and `-14`.

Only this magic/equality policy is established for the opaque records. Their
remaining field meanings and physical provenance are unknown.

The NV wrappers add `0x4000` to the caller's offset. The previously checked
special window covers only logical `0x4000`–`0x4fff`: it uses the special handle
with offset rebased by `0x4000`, or the fallback handle with offset unchanged.
Logical `0x5000` uses the active handle with unchanged offset. Both preferred
and alternate setup routes execute with coherent authored descriptors.

## 4. Rewrite fallback, error propagation and mutex accounting

Actual `0x80c0d776` first tries the rewrite callback under the mutex. A failed
rewrite or missing callback falls back to a second acquisition, one 4-KiB heap
buffer and a page loop: read, merge requested bytes, erase, program. The buffer
is freed and the mutex released after the loop in the successful allocation
cases. Both one-page record repair and a two-page request execute.

Independent byte checks show preservation outside the updated record on success.
The fallback retains the read status as its return: supplied erase/program
failures can still yield zero. A failed program after successful erase leaves
the whole authored page erased while mirror repair reports success. A failed
read instead stops, frees and unlocks, producing a mirror failure.

Allocation failure returns without the fallback acquisition's matching release:
the simulated lock depth remains 1, with no heap allocation. This checks the
missing-release control path under successful supplied mutex operations; it does
not simulate real RTOS blocking, recursion or concurrency effects.

The fast path routes the whole request according to its starting address. The
fallback splits by 4-KiB pages and routes each page separately. A supplied fast
callback accepting a boundary-crossing request and the forced fallback therefore
touch different authored volumes for the second half. Real callback alignment/
boundary constraints remain unknown. These are selected synthetic contracts,
not device atomicity or recovery guarantees.

## 5. Bootstrap and retained gate

Actual `0x80c0c27a` uses its own ready byte at `0x80d81d3c`. If unset, it calls
setup, then actual table binding `0x80c0d67a`. Preferred and fallback clean-header
cases execute the actual environment initializer and set both readiness flags.
An already-set inner flag skips binding work; an outer flag skips the entire
bootstrap. Setup failure propagates and leaves outer readiness clear.

Actual framework caller `0x80c1a022` calls bootstrap, restores its frame and
tail-jumps to `0x80c0b7b0`. The runner stops there before the next phase, checking
restored ABI and bootstrap status. Both zero and error 7 reach this boundary;
the next phase and complete boot do not execute.

Actual `0x80c01704`, called by the previously stopped boot-main path, also runs
separately. An invalid retained magic initializes `0x80dff700` to `0xabcd1234`,
clears the value word at +4 and returns zero. Valid magic returns the low byte
while preserving the full stored word. Physical retention/reset provenance is
not established by these supplied words.

## Reproduction and bounds

Use startup-aware `boot-runtime` / `boot-runtime.elf` with the prior guarded
AndeStar/environment metadata. Apply `SeedEnvStorage.java`, then export the 13
`env_storage.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`,
into ignored `firmware/decompiled/runtime-env-storage/`.

```sh
python3 analysis_scripts/env_storage.py \
  --vectors-output firmware/env-storage-native-vectors.json
```

Run headless with `-process boot-runtime.elf -noanalysis -scriptPath analysis_scripts`:

```text
-postScript ValidateEnvStorage.java firmware/env-storage-native-vectors.json firmware/env-storage-native-validation.json
```

```sh
python3 analysis_scripts/env_storage.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-env-storage \
  --vectors firmware/env-storage-native-vectors.json \
  --validation firmware/env-storage-native-validation.json > analysis/env-storage.json
python3 -m unittest discover -s tests -p 'test_env_storage.py' -v
```

The runner guards 32 code ranges plus the CRC table, rejects unexpected PCs and
service arguments, caps each case at two million steps, checks returned/stopped
ABI, output guards, immutable registry/owner/device/input bytes, heap ownership,
complete lookup/validation/callback/lock/log traces and storage/cache/state hashes
against an independent host contract. Thirteen fresh export hashes and the
actual default-table hash are recorded. Vendor material stays ignored.

Registry/device population, the actual physical map and driver implementations,
mutex behavior, mirror payload meaning, physical reserve-image provenance and
persistence, the following startup phase and boot/recovery/UI dispatch remain
open. Safe device-specific restoration and independent boot through the signed
chain are still unresolved.

The subsequent [original storage-table pass](STORAGE_MAP_AND_DRIVER_BINDINGS.md)
recovers five backend descriptors, their callback addresses and two identical
16-row partition tables. These static bindings replace none of this pass's
supplied descriptors; FTL translation and native registry initialization remain
outside its coverage.
