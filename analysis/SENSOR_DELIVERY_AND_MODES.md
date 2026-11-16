# Native packet lifetime, delivery, cache queue and optical modes 2/3

This pass extends [flush and packet construction](SENSOR_FLUSH_AND_PACKETS.md)
through four bounded blocks: reference operations, listener delivery, cache
enqueue/dequeue ownership, and the three-word optical consumer. There are
178 new native cases: 97 reference, 40 delivery, 12 cache and 29 consumer.
They total 42,835 bounded steps including intercepted calls. Inputs, packet
registration and OS services remain synthetic; no watch or phone was accessed.

The checked results and provenance are in [sensor-delivery.json](sensor-delivery.json)
and [ppg-three-word.json](ppg-three-word.json). The shared consumer harness also
replayed all 557 earlier cases with exactly identical results. All 354 Python
tests pass, including 28 added tests and independent binary packet fixtures.

## Block 1: native references and the last-release boundary

Packet retain `0x80f64622(packet)` is a null-safe tail call to increment
`0x80f85cbe(packet + 16)`. Release `0x80f6462c(packet)` calls
`0x80f85d14(packet + 16, 1)` and frees only when the resulting word is zero.
Before calling the pool-4 free service (`0x80f84d24`, tag `drivers/sensor`),
it clears the descriptor pointer at packet `+20`. Validation executes these
instructions and observes the free arguments and pointer ordering. The
allocator/free service itself is intercepted and does not erase the fixture.

The reference word wraps modulo 2^32. Synthetic retain from `0xffffffff`
produces zero without a free. Release from zero produces `0xffffffff`
without a free. These cases record the absence of saturation/underflow guards;
they do not establish a reachable ownership failure on the device. Legitimate
retain/release sequences and null packet operations are also covered.

Both arithmetic helpers execute critical wrappers `0x80f80aa2` and
`0x80f80ace`. Context predicate `0x80f7f5e4` is supplied, while the selected
critical code and CSR instructions execute under emulation:

| Supplied context/state | Observed instruction effects |
| --- | --- |
| Predicate nonzero | bypass the MIE/depth operations |
| Predicate zero, scheduler word `0x80f1719c` nonzero | clear `mstatus.MIE`, increment current task `+80` nesting, decrement on exit, set MIE when depth becomes zero |
| Predicate zero, scheduler word zero | clear MIE on entry; selected exit leaves it clear |
| Predicate zero, pre-existing nonzero depth | balance depth; leave MIE clear |

These helpers do not restore a saved previous MIE bit. In the tested outermost
scheduled case, an initially clear MIE bit becomes set on exit. The nesting
word also uses wrapping 32-bit arithmetic. Tests include its wrap boundary.
Debug-state writes are disabled with byte `0x80f16f78 = 0`. Stack backing is
initialized synthetically; the predicate-zero wrapper does not populate the
temporary argument later passed to the exit wrapper, which does not use it
on that selected context branch.

This is evidence about emitted instructions and selected context assumptions.
It does not prove interrupt exclusion, cross-core atomicity, correct scheduler
state or safe concurrent reference access on physical hardware.

## Block 2: delivery and listener reference ownership

Entry `0x80f649be` reads a normalized packet through `0x80f648dc`. That read,
the fusion operation `0x80f66326`, the IMU synchronization helper and the cache
call are supplied boundaries in these delivery cases. The selected dispatcher,
listener iteration and reference cleanup execute natively.

When the read returns no packet, delivery ends. Otherwise the selected order is:

1. For the IMU group, request synchronization through `0x80f63f96`.
2. Call fusion with the original packet.
3. If fusion returns zero, cache and dispatch the original packet.
4. If fusion returns a distinct packet, cache/dispatch it only when its first
   descriptor's 16-bit frame count at `+20` is nonzero, then release it.
5. Release the original packet.

A nonnull fusion result with zero first-descriptor frame count suppresses
original-packet delivery too; both packet references are released. Tests use
distinct valid synthetic packets for this branch. Aliasing fusion output to
the input, malformed descriptor pointers and real fusion algorithms remain
outside this pass.

Dispatch `0x80f63f7a` selects one of two native listener lists:

| Packet header | List and matching policy |
| --- | --- |
| Private field `+6` is zero | `0x80f4faf8`; sensor IDs 1–35 only; exact ID, wildcard 36, shared IMU group 1/2, or shared membership in mask `0x6de0ffe0` |
| Private field `+6` is nonzero | `0x80f4fb00`; its low byte must be 1–5; exact low-byte type or wildcard 6 |

Normal matching tests group bits using `listener_type & 31`; a synthetic
listener type 257 therefore matches the IMU group. A private field of 257
selects private type 1, while 256 and 6 are rejected. Wildcard 36 belongs to
the normal list and is not the private wildcard.

Callbacks run in list order with the packet pointer as their argument. The
dispatcher does **not** increment the reference for each callback. The owner
releases its reference after dispatch. To check the lifetime boundary, selected
synthetic callbacks invoke the real native retain wrapper; after delivery
finishes, the harness invokes native release for each retained reference.
Callbacks that do not retain make no implicit ownership claim. Actual listener
registration, listener implementations and list mutation/concurrency are not
executed.

The thread-context cases execute the context-gated list-lock call sites with
supplied lock outcomes. This verifies their ordering and arguments, not the
OS mutex implementation or behavior when acquiring that mutex fails.

## Block 3: cache queue holds and transfers a packet reference

Cache entry `0x80f65a0e` has a fast path when both packet type-mask words are
fully included in the configured cache mask. It retains the original packet
and enqueues an eight-byte native record:

```text
u32 packet_allocation_size
u32 packet_pointer
```

For the one-stream/four-byte fixture, size is 68. The queued destructor is
`0x80f655f8(record)`, which releases the packet pointer stored at record `+4`.
The fixture's original owner is released separately after the cache call.

This pass executes native queue put `0x80fa6028` and get `0x80fa60e4`, their
list/count updates and destructor calls. Queue allocation, copying, OS locks
and free services are supplied. The complete 24-byte node and eight-byte
output record are checked along with packet hashes and ownership actions.
Each case uses one initially empty synthetic queue.

| Outcome | Native ownership behavior under supplied inputs |
| --- | --- |
| Queue put succeeds, no drain | original owner releases; queue retains one packet reference |
| Queue magic invalid or node allocation fails | cache logs and calls record cleanup, balancing its added reference |
| Get buffer has room for the eight-byte record | dequeue copies the record and frees the queue node without invoking its destructor; the packet reference transfers to the receiver |
| Get buffer is too short | dequeue invokes the node destructor, logs, frees the node and returns 1; output bytes remain unchanged |

The successful-get harness inspects the copied record and then explicitly
calls native `0x80f655f8` to release the received reference. Consequently,
queue-node free precedes packet free in that case. In the short-buffer case,
packet cleanup precedes queue-node free and occurs before releasing the
synthetic queue lock.

Cache accounting word `0x80f16fd8` increases by packet size only after successful
enqueue. It requests pressure flushing when the resulting word exceeds
`0x4fff`, or the supplied free-memory value is less than `0x19001`. Boundary
cases check equality and one-step differences. Actual flush `0x80f65920` is
intercepted as a requested action; the test does not drain through its packing
or event/IPC path. A direct queue get does not itself decrement the cache
accounting word, so this field is not treated as live queue occupancy.

Cache-disabled and no-selected-type branches are covered. Partial mask
selection/copy, multi-node queues, motion-specific triggers, real pressure
handling and delivery to another processor remain open. The delivery block's
cache interception and this separate cache execution are not one uninterrupted
consumer-to-IPC trace.

## Block 4: three-word optical consumer modes 2 and 3

This pass extends the shared native consumer runner to set mode/frame fields
and selected channel/threshold state explicitly. Modes 2 and 3 share the
selected three-word path at `0x80f747c0`. As in the earlier mode-1 cases, a
prefilled ring and reader-mode byte 1 skip physical acquisition. Channel-count
byte `0x80f17059` is zero, so channel-derived descriptor scaling searches are
outside the tested configuration.

For each retained frame the consumer pops three words, creating two streams
or three when optional-stream byte `0x80f17086` is one:

| Output stream | Descriptor type | Source and adjustment |
| --- | --- | --- |
| First | `0x10` | signed low 20 bits of word 3, plus `byte[0x80f516e4] * 0x7ffff >> 5` |
| Second | `0x8000` | word 1 through the tag-checking signed conversion, plus the existing global RV32 offset |
| Optional third | `0x100000` | word 2 through that conversion and global offset |

Without the optional stream, word 2 is popped and discarded. Word 3 does not
use the measurement-tag diagnostic helper; changing its tag does not change
the selected conversion or produce that diagnostic. Values remain native
sample integers with unverified physical units and channel meanings.

The ring auxiliary count decreases for each marked pop in these non-mode-1
paths. With policy 2, the first stream's 16-bit flag at descriptor `+28`
records whether any consumed word was marked; other policy values set it to
1 in the tested path. The other two tested stream types skip this flag write.
An odd/incomplete frame remains cached, and wrap at ring index 1000 is covered.

With byte `0x80f1706c` nonzero, a frame is counted out of range when either:

- the absolute **unadjusted third-word sample** exceeds 524286; or
- the adjusted third-word value is outside the signed min/max words at
  `0x80f51778`/`0x80f51774`.

Equality to the configured min/max passes. Both extreme positive 524287 and
negative -524288 fail the magnitude condition. A mixed batch clears the
running out-of-range counter. Only a batch in which every retained frame is
out of range adds its frame count to that counter. If the resulting signed
counter reaches `2*rate`, it is cleared and, with calibration byte
`0x80f17065` zero, helper `0x80f74798` is requested. That helper is intercepted;
its register/peripheral effects are not assigned a completed reset meaning.
A nonzero calibration byte suppresses the call while still clearing the
counter at this threshold.

The earlier frame limit, pointer-bearing packet layout, timestamp backdating,
lock/allocation failure and native arithmetic contracts remain in force.
At rate 10 with 20 three-word frames, 12 frames are consumed and 24 words
remain cached. This does not establish a physical sample frequency or final
health measurement accuracy.

## Reproduction and remaining work

Use the corrected startup-aware sensor project and existing guarded BBS/DSP
metadata. Apply `SeedSensorDelivery.java` and export `sensor_delivery.py:TARGETS`
plus `0x80f747c0` through `DecompileWithLogger.java`, logger `0x80f86d34`,
into ignored `firmware/decompiled/runtime-sensor-delivery/`. There are eighteen
ownership/delivery/queue exports and one fresh consumer export; these counts
do not measure branch coverage.
Ghidra can expand direct tail jumps into allocator/OS pseudocode despite
restricted function address sets. That expansion is not executed coverage:
the native runner stops at the explicit free/lock service boundaries.

```sh
python3 analysis_scripts/sensor_delivery.py \
  --vectors-output firmware/sensor-delivery-native-vectors.json
python3 analysis_scripts/ppg_three_word.py \
  --vectors-output firmware/ppg-three-word-native-vectors.json
```

Run the following scripts sequentially on that project:

```text
-postScript ValidateSensorDelivery.java firmware/sensor-delivery-native-vectors.json firmware/sensor-delivery-native-validation.json
-postScript ValidateSensorPackets.java firmware/ppg-three-word-native-vectors.json firmware/ppg-three-word-native-validation.json
```

```sh
python3 analysis_scripts/sensor_delivery.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-sensor-delivery \
  --vectors firmware/sensor-delivery-native-vectors.json \
  --validation firmware/sensor-delivery-native-validation.json > analysis/sensor-delivery.json
python3 analysis_scripts/ppg_three_word.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-sensor-delivery \
  --vectors firmware/ppg-three-word-native-vectors.json \
  --validation firmware/ppg-three-word-native-validation.json > analysis/ppg-three-word.json
```

The delivery run uses 29,309 bounded steps, at most 699 per case. The consumer
run uses 13,526, at most 1,760 per case. Runners reject execution outside
selected native ranges or explicit synthetic boundaries and check stack/
`s0..s11` preservation. Code hashes, full expected-vector hashes, checked
native results and fresh export hashes support reproduction. Vendor bytes,
tools, decompiled code and databases remain ignored.

Remaining work includes normalized read/driver selection, real fusion and
cache filtering, the pressure-flush serializer/event/IPC route, other optical
modes and calibration, actual listeners and concurrency, allocator internals
and hardware bus/timing/measurement validation. Boot/recovery and independent
hardware operation remain unresolved as recorded in [RE_STATUS.md](RE_STATUS.md).
