# Algorithm registry, lifetime and actual HR adapter

This pass follows the actual main HR algorithm record beyond the supplied
algorithm registration in [ENGINE_CACHE_AND_HR_POLICY.md](ENGINE_CACHE_AND_HR_POLICY.md).
It adds 48 passing bounded native cases in four groups: 14 registration/lookup,
eight lifetime, 16 dispatch/mask and ten control cases. They execute 7,672 steps
including intercepted boundaries; the largest case takes 466 steps. All 438
Python tests pass, including 23 new checks. Complete observations, byte/export
hashes and limits are in [algorithm-manager.json](algorithm-manager.json).

The native manager, actual HR adapters, real HR configuration copier and
uninitialized-processing guard execute in Ghidra's emulator. Mathematical
initialization, normal processing, teardown and the optional configuration
extension are supplied boundaries. The results do not establish HR measurement
accuracy, complete mathematical behavior, live activation or hardware operation.

## 1. Registration and the actual HR record

| Item | Main runtime contract |
| --- | --- |
| Raw registration | `0x704c4a24(record)` returns the record address on success, zero on failure |
| Operations registration | `0x704c4cb6(record)` additionally requires a processing callback; no meaningful return |
| Record lookup / active lookup | `0x704c4c3a(id)` / `0x704c4c0c(id)` |
| Table | `0x70fc1ffc + (id - 0x1000) * 8`: record pointer, enabled byte, three reserved bytes |
| Accepted bounded IDs | `0x1001` through `0x1039`, inclusive |
| HR registration | Actual wrapper `0x7031348e -> 0x704c4cb6(0x70f638e0)` |

Raw registration rejects null input, invalid record ID or a populated slot.
Success resets the record's 16-bit reference count at + 12, supplies default
init/exit callbacks if absent, clears the slot's enabled byte and stores the
original record pointer. It does not clone the record or check the processing
callback. Duplicate registration preserves the existing slot and rejected
record. The operations wrapper rejects a null record or missing processing
callback before calling the raw registry; failures after raw registration
produce both the specific raw diagnostic and the wrapper's registration error.

The actual initialized 48-byte HR record at `0x70f638e0` has:

| Offset | Field / initial value |
| --- | --- |
| + 0 / + 4 | Name pointer `0x70a4347c`, associated pointer `0x70a43464` |
| + 8 | ID `0x100d` |
| + 12 | 16-bit reference count, initially zero |
| + 16 | Init adapter `0x70313478 -> 0x7089adca` |
| + 20 | Exit adapter `0x70313470 -> 0x7089b360` |
| + 24 / + 28 | 64-bit type mask `0x82012` |
| + 32 | Zero |
| + 36 | Processing adapter `0x7031345a -> 0x7089b82c` |
| + 40 | Control adapter `0x70313446 -> 0x7089d110` |
| + 44 | Zero |

The mask contains `2`, `0x10`, `0x2000` and `0x80000`. It excludes `0x8000`,
which was admitted by the deliberately broad synthetic record in the previous
HR policy tests. That earlier result remains a consumer/output-policy test;
it did not establish live routing for its sample types. Engine 7's initial
engine mask is separately 1; this pass does not execute the changes needed to
activate the complete engine/algorithm pipeline.

The model reconstructs the record from named fields and verifies all 48 bytes
against startup-aware OTA memory. Native cases use the actual HR record and
registration wrapper, plus synthetic records for invalid/duplicate/default
callback cases. Complete table/record hashes are compared after every operation.

## 2. Enable/disable and reference ownership

Enable thunk `0x704c4d3c` calls `0x704c4ac2(id)`. For a registered ID it first
increments the 16-bit reference count, including when initialization later
fails. If already enabled it returns zero without calling init again. Otherwise
it invokes the init callback: zero enables the slot; nonzero logs an error,
leaves the slot disabled and returns that callback value. The actual HR adapter
normalizes a backend return to Boolean nonzero, so supplied backend 7 or
`0xffffffff` becomes return 1. A generic callback's error 7 remains 7.

Disable thunk `0x704c4d40` calls `0x704c4b86(id)`. It decrements a nonzero count.
An enabled slot whose count is then zero invokes exit and clears the enable
byte. Repeated disable at zero does not underflow or call exit again after
the slot has been cleared. Exit's return is ignored. Missing/invalid IDs log;
enable returns 1, while disable has no meaningful return.

The cases check two owners sharing one init/exit pair, failed init followed
by retries and balancing disables, default no-op lifecycle callbacks and ignored
exit errors. Two explicit supplied-state cases cover enabled-with-zero-count
and count `65535 -> 0`: enable does not saturate the counter or clear enabled
on wrap; the following disable invokes exit. These are synthetic states and
bounded arithmetic contracts. Caller balancing, live reachability, concurrency
and the full mathematical allocator lifetime remain open.

## 3. Processing dispatch and mutable masks

Actual dispatcher `0x704c4d44(id, descriptor, work, output)` checks output first.
Null output logs an invalid-input diagnostic. Otherwise it clears only output
byte 0 and writes the low 16 bits of ID at output + 2 before checking whether
the algorithm is active. Other output bytes retain their previous contents.

For an enabled registered algorithm, a nonnull descriptor must intersect the
record's 64-bit mask. A null descriptor bypasses this manager mask comparison
and is passed to the processing callback. The null fixture intercepts the HR
backend; it does not establish that initialized mathematical processing safely
accepts null input. Actual mask setter `0x704c4e58(id, low, high)` updates the
registered record in place, even without checking enable state. Missing lookup
and invalid bounded IDs cause no mask write.

The native cases check each of the actual HR mask's four bits, rejection of
`0x8000` and 1, high-word mask mutation, zero mask, null descriptor/output,
disabled/missing algorithm and ready=false output. The real HR processing
adapter normalizes backend error to Boolean nonzero. The dispatcher logs that
error but preserves output fields supplied by the backend, including ready=1.
This agrees with the downstream ready/error behavior checked in the prior pass.

One fixture executes the actual processing guard in `0x7089b82c`: with backend
initialized byte `0x80c461be = 0`, it logs and returns 1 before processing data.
The real adapter returns 1 and the manager logs a processing error; no ready
result appears. The fixture deliberately enables the manager slot through a
supplied successful init without changing backend state, making this a guard
test, not a normal live initialization sequence. The initialized signal path
and its numerical operations are not executed.

## 4. Real HR control copying and extension status

`0x704c4e00(id, source)` looks up the record and invokes a nonnull control
callback. It does not require the algorithm to be enabled and does not validate
the source pointer. Missing record/callback is a no-op. A generic nonzero
callback return produces a control-error diagnostic. The actual HR adapter
`0x70313446` calls `0x7089d110(source)` and always returns zero, suppressing
that manager error path regardless of the backend return.

The real configuration copier `0x7089d110` is executed with 48-byte synthetic
sources and a 160-byte backend state window starting at `0x80c46120`:

| Source / condition | Native destination or action |
| --- | --- |
| Entry | Clear the first 56 bytes of backend configuration |
| Bytes 0..5 | Same offsets in backend configuration |
| Byte 6 | Separate byte `0x80c461bd`; destination config byte 6 stays zero |
| Bytes 7..16, 17..26, 27..36 | Three ten-byte copies to the same offsets |
| Byte 37 | Configuration byte 37 (`0x80c46145`) |
| Source word + 40 is zero | Set `0x80c461bc = 1`, log absent extension |
| Source word + 40 is nonzero | Invoke `0x7089a252(source_word40, source_word44)` |
| Extension returns exactly 1 | Set `0x80c461bc = 0`; copier returns 1 |
| Extension returns another value | Set `0x80c461bc = 1`, log the branch; return follows supplied logger result |

The no-extension branch's return also follows the logger. The runner supplies
logger return zero; that result is not claimed to be an intrinsic copier
return contract. The enclosing HR control adapter unconditionally returns zero.
The meaning of the extension flag and byte 6 is not inferred from these writes.

Ten control cases check disabled/enabled calls, no callback/missing record,
generic error, extension absent/0/1/7 and repeated configuration. One direct
copier call distinguishes its return 1 from the adapter's zero. Every row checks
the full 160-byte backend-state hash, including preserved bytes beyond the
56-byte clear. Source/descriptor/work buffers remain unchanged in the selected
cases. Copy/zero and the extension implementation are supplied boundaries.

## Reproduction and limits

Use startup-aware `main-bbs` / `main-runtime.elf`, the established guarded
AndeStar repair and corrected logger metadata. Apply `SeedAlgorithmManager.java`,
then export the 21 `algorithm_manager.py:TARGETS` with `DecompileWithLogger.java`,
logger `0x702b38a2`, into ignored
`firmware/decompiled/runtime-algorithm-manager/`.

```sh
python3 analysis_scripts/algorithm_manager.py \
  --vectors-output firmware/algorithm-manager-native-vectors.json
```

Run on the main project with `-process main-runtime.elf -noanalysis`:

```text
-postScript ValidateAlgorithmManager.java firmware/algorithm-manager-native-vectors.json firmware/algorithm-manager-native-validation.json
```

```sh
python3 analysis_scripts/algorithm_manager.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-algorithm-manager \
  --vectors firmware/algorithm-manager-native-vectors.json \
  --validation firmware/algorithm-manager-native-validation.json > analysis/algorithm-manager.json
python3 -m unittest discover -s tests -p 'test_algorithm_manager.py' -v
```

The runner checks the code/record hashes before execution, rejects unexpected
PCs/logs and limits every case to 100,000 steps. Stack, `s0..s11` and the four
saved floating-point registers used by the processing guard are checked after
each entry. All table/record/output/backend-state snapshots are compared with
an independent host contract after every operation. Byte/export counts are
provenance, not semantic coverage. Public manager IDs are deliberately bounded
to 16 bits; wider caller inputs are outside this model.

Mathematical init/process/exit, extension logic, full engine activation, the
HR motion/minute/reset/wear paths, other health algorithms, transport/concurrency
and physical validation remain open. Vendor code/binaries/tools/databases stay
ignored. No phone/watch access or firmware changes were performed.

The follow-up [HR_WORKSPACE_AND_EXTENSION.md](HR_WORKSPACE_AND_EXTENSION.md)
executes outer HR allocation/free, repeated lifecycle and restart, initialized
unsupported-type processing and the actual extension header/view builder in
21 additional native cases. Numerical setup/internal cleanup and supported
mathematical processing remain boundaries.
