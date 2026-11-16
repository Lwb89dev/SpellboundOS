# Main engine cache registration, event ownership and HR result policy

OTA 4.6.0.3 now has 40 additional passing bounded native cases: seven for
listener registration/removal and 33 for receive, engine-event delivery and
selected HR result handling. They total 54,087 steps including intercepted
boundaries; the largest case takes 3,045 steps. All 415 Python tests pass,
including 23 new host checks. Results, byte/export hashes and limitations are
in [engine-cache.json](engine-cache.json).

The native instructions execute in Ghidra's emulator against synthetic memory.
OS services, allocation/free/copies, event scheduling and mathematical algorithm
outputs are supplied. This extends the receiver work in
[CACHE_RECEIVER_AND_OWNERSHIP.md](CACHE_RECEIVER_AND_OWNERSHIP.md) into an
identified application consumer. It does not establish measured heart rate,
live engine activation, complete algorithm behavior or physical sensor operation.

## 1. Cache listener registration and removal

| Item | Main runtime address / contract |
| --- | --- |
| Register cache callback | `0x701e320e(callback)` |
| Remove cache callback | `0x701e328e(callback)` |
| Generic insert / remove | `0x701e28d8(3, 0, callback)` / `0x701e29a4(3, 0, callback)` |
| List head | `0x70f92920` |
| Node | 16 bytes: next pointer, previous pointer, selector zero, callback |
| Allocator boundary | Pool 5, `drivers/sensor` tag `0x709d09ec`, allocation `0x80d3c324`, free `0x80d3c35a` |

New nodes append to the circular doubly linked list. Registering the same
callback again logs a duplicate and returns 1 without allocating a second
node. Null registration/removal returns 0. Allocation failure logs and returns
0 without inserting a node. Removing an absent callback returns 0; it logs
when the list is nonempty, while an empty list returns quietly. Successful
removal returns 1, unlinks the node, restores its own next/previous pointers
to itself and passes it to the free boundary.

The seven native cases check return values, dispatch order, active-list
head/tail/previous-pointer invariants and full 16-byte node hashes, including
removed nodes. Cases include reverse removal, reinsertion, empty dispatch,
duplicates, nulls, missing callbacks and allocation failure. The supplied OS
context predicate returns 1, so the registration lock branch is not exercised.

## 2. Engine cache listener and retained event

The fresh initializer export at `0x704c41c0` statically installs recipient 39
with handler `0x704c3f3a` and requests callback `0x704c3ea8` through
`setControl(0, 7, &args)` at `0x704c2a3a`. The selected control/worker chain is
`0x704c585a -> 0x704c545e -> 0x704c7502(0x14, callback)`, then worker
`0x704c712e -> 0x704c70ee -> 0x701e320e`. This initialization/registration
queue is a static association, not an executed queue test. The native cases
call the real register wrapper directly with the identified callback.

The connected native path is:

```text
receive 7071fd60 -> parse 70720ac0 -> opcode-21 handler 707200f2
  -> new buffer, copy, pointer reconstruction
  -> configured default bridge 7071ed94 -> cache dispatch 701e330e
  -> registered listener 704c3ea8 -> 704c3576(39, view)
  -> retain buffer -> supplied event post
  -> receiver releases its reference
  -> supplied scheduling of real handler 704c3f3a
  -> supplied invocation of real destructor 704c3340 -> buffer release
```

`0x704c3576` validates recipient `< 40` and a nonnull view, requests an event
with destructor `0x704c3340`, stores the `SENSOR_CACHE` tag at `0x70c02afc`,
kind 6 at event + 4 and the buffer view at event + 16. It retains the buffer
through `0x701e4f7c`, then posts through `0x704c43e6` / `0x70304a62`.
The harness checks destructor identity, supplied bus, recipient, event pointer,
kind and view. Tag assignment is recorded statically.

After receive returns, the queued-event fixture has one reference and valid
magic. After processing and the actual destructor's native release, reference
count and magic are zero before the supplied free boundary. Event allocation
failure does not retain or post; receive frees its own buffer. Listener-node
allocation failure prevents event creation entirely. Complete buffer and guard
hashes and unchanged borrowed wire bytes are checked. Event allocation/post,
task scheduling and invocation of the destructor are supplied separately;
event-object deallocation and concurrency are not executed. The post boundary
returns 1; post failure is not covered.

## 3. Packed iterator and engine delivery gate

Kind 6 enters `0x701e53b0` through thunk `0x704c586a`, using actual callback
`0x704c4148`. Native decoder code walks `u32 length | packet` records until
exhaustion or a null slice. Zero/overrun record prefixes stop traversal without
changing the outer-validity return of 1. Callback return values are ignored;
the fixtures deliberately return `0xdeadbeef` from generic callbacks.

The gate requires a nonnull packet and descriptor pointer at packet + 20.
For slots 0 through 38, it uses actual engine lookup `0x704c31fc` and requires:

- A record, nonnull callback at + `0x2c` and nonzero enabled byte at + 1.
- Slot index different from 30; slot 39 is outside the iteration.
- A nonnull handle at record + 20, handle state byte + 12 exactly 2
  (`0x704c253e`) and nonzero cache byte + 21 (`0x704c2556`).
- An intersection of the packet and record 64-bit type masks at + 8/+ 12.

Delivery calls `callback(record, packet)`. The cached branch does not compare
the packet's private field with an engine-private value. The selected native
cases check low/high-word masks, private value `0x1234`, nonboolean enabled/cache
flags, absent callbacks/handles, states 1/3, disabled flags and indices
0/7/30/38/39. Engine records and states are synthetic; this does not establish
which engines are enabled on the watch.

## 4. Actual HR consumer, algorithm selection and output policy

Initializer `0x70315634` creates engine 7 and installs callback `0x703150f4`
at record + `0x2c`. That callback iterates 40-byte descriptors and calls
`0x70314ba4`. The initializer's record mask is initially 1. The harness supplies
a broader mask to exercise non-type-1 descriptors; it does not execute the
configuration transitions required to admit those descriptors on a real watch.
The initializer also sets additional HR state; harness state is explicitly
synthetic and is not a replay of full initialization.

When feature byte `0x70fa06f5` is nonzero, the descriptor consumer zeroes
44-byte work and `0x520`-byte output areas and calls actual algorithm dispatcher
`0x704c4d44(0x100d, descriptor, work, output)`. Enable lookup `0x704c4c0c` uses
`0x70fc2068`; record lookup `0x704c4c3a` uses `0x70fc2064`. A present/enabled
record whose 64-bit mask at + 24 intersects the descriptor type calls its
backend at + 36. The dispatcher initializes output-ready to zero and tag at
output + 2 to `0x100d`.

The harness supplies the algorithm record and intercepts only that backend:
ready byte, pulse byte at output + 8, quality byte at + 9 and return status.
The real dispatch, descriptor handling and HR global-state updates execute.
Missing/disabled/mask-mismatched records and absent results are checked.
A nonzero backend return logs an error, but a simultaneously supplied ready
flag still causes HR policy processing. These are synthetic outputs, not
measurements or validated physical units/quality semantics.

For a ready result the selected policy is:

| Condition | Observed native update |
| --- | --- |
| Any ready result | Seen byte `0x70fa06ea = 1`, last pulse `0x70fa06e9`, last quality `0x70fa06eb` |
| Quality > 3 and pulse 30 through 220 inclusive | Accumulate and store packed pulse/quality at `0x70fa06c8` |
| Quality 4 through 6 | Status at `0x70fa06ca` becomes 2 if feature bit 1 is set and counter >= limit; otherwise 1 |
| Quality >= 7 | Status 2; manual-success log if feature bit 1 is set, otherwise periodic-success log if feature bit 0 is set |
| Accepted result and control byte `0x70fa06f4 & 6` nonzero | Marker `0x70fa06f6 = 1` |

The accumulator at `0x70fa06e4` packs a 16-bit count above a 16-bit sum. Each
accepted descriptor increments count and adds pulse to sum; the halves wrap
independently. Temporary count at `0x70fa06d0` remains 32 bits, including
65536 when the stored count wraps to zero. Counter `0x70fa06dc` and limit
`0x70fa06e0` are supplied and the selected non-type-1 path does not increment
the counter. A four-descriptor fixture checks four accumulations.

All 188 bytes from `0x70fa0680` are hashed after execution. Boundary fixtures
cover pulses 29/30/220/221, qualities 3/4/7, manual threshold/success, marker
control, aggregate wrap and error-with-ready. HR cases exclude descriptor type
1, omit auxiliary engine 9, set wear state to zero and supply zero reset flags.
Motion/minute reporting, resets, wear/fusion dependencies, actual backend
registration/math and remaining health consumers stay open.

## Reproduction and provenance

Use the startup-aware `main-bbs` project / `main-runtime.elf` with the existing
guarded AndeStar and ABI/logger repairs. Apply `SeedEngineCache.java`, then
export the 21 `engine_cache.py:TARGETS` with `DecompileWithLogger.java`, main
logger `0x702b38a2`, into ignored `firmware/decompiled/runtime-engine-cache/`.
Native byte spans and all fresh exports have hashes in the public report.
Export/guard sizes are provenance and do not measure semantic coverage.

```sh
python3 analysis_scripts/engine_cache.py \
  --vectors-output firmware/engine-cache-native-vectors.json
```

Run on the main project with `-process main-runtime.elf -noanalysis`:

```text
-postScript ValidateEngineCache.java firmware/engine-cache-native-vectors.json firmware/engine-cache-native-validation.json
```

```sh
python3 analysis_scripts/engine_cache.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-engine-cache \
  --vectors firmware/engine-cache-native-vectors.json \
  --validation firmware/engine-cache-native-validation.json > analysis/engine-cache.json
python3 -m unittest discover -s tests -p 'test_engine_cache.py' -v
```

The runner rejects unexpected PCs/logs, checks stack and `s0..s11` after each
entry and limits every case to 100,000 steps. The host model independently
compares complete expected actions, deliveries, algorithm calls, registry state
and buffer/node/HR hashes with native observations. Vendor binaries, exported
C, Ghidra databases and tool distributions remain ignored. No device access,
phone/watch configuration changes or firmware writes were performed.
