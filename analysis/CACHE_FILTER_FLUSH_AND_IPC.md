# Native cache filtering, flush buffers and opcode-21 IPC send

This pass follows the [cache queue ownership](SENSOR_DELIVERY_AND_MODES.md)
through partial type filtering, packed-buffer reconstruction, queue flushing,
the cache listener/event handler and the opcode `0x15` send callback.
Twenty-nine native cases pass: eleven filter, eight buffer and ten flush
cases. They use 25,611 bounded steps including intercepted calls, at most
3,311 per case. Full checked results and fingerprints are in
[cache-pipeline.json](cache-pipeline.json). Seventeen added host tests bring
the Python suite to 371 passing tests.

These are offline software contracts using synthetic packets, registrations,
allocator/free/copy operations, locks, contexts, event scheduling, routing and
send results. No phone/watch setting, firmware or hardware was changed.

## Partial filtering creates a packet with independent pointer storage

Cache entry `0x80f65a0e` intersects the packet's two type-mask words with
configured masks at `0x80f16fd0`/`0x80f16fd4`. Full selection retains the
original packet. No intersection creates no cache record. With a partial
intersection, the native code:

1. Counts set bits in the full 64-bit intersection and allocates that many
   descriptors with the original 16-bit payload stride through `0x80f6453e`.
2. Copies sensor/private header fields and writes the intersected masks.
3. Visits original descriptors in order, selecting those with an intersecting
   low or high type word.
4. Copies each selected descriptor's first 32 bytes and its full stride of
   payload into the new allocation, leaving its new pointer slots intact.
5. Enqueues the new packet reference through native `0x80fa6028`.

The first-32-byte copy carries type, timestamp and sample metadata, while
descriptor `+32` keeps the newly allocated payload pointer. The word at
`+36` is not copied and remains zero in these allocations. Distinct nonzero
source values at that offset verify the copy boundary. A high-word-only
type (`1 << 32`) is selected correctly; filtering is not limited to low
32-bit types.

The fixtures use distinct single-bit descriptor types and consistent header
masks. Therefore population count equals selected descriptor count. The pass
does not establish behavior for inconsistent masks, multibit type aliases,
corrupt pointers/counts or concurrent access.

On clone allocation failure, the allocator and cache log without enqueuing.
On queue-node allocation failure, cache cleanup releases the new clone. The
source owner is released separately. Successful cases execute native filtering,
queue put, source-owner release and flush, then compare the entire source,
clone and buffer allocations. The earlier cache tests' all-selected path is
also included in this connected sequence.

## Buffer allocation and reconstruction have shallow validity checks

Allocator `0x80f657ee(capacity)` returns zero immediately for capacity zero.
Otherwise it requests `capacity + 16` bytes from pool 4, clears them, and
returns a view eight bytes after the allocation base:

| Allocation-relative offset | Field |
| --- | --- |
| `+0` | 32-bit initial reference value 1 |
| `+4` | magic `0xa3b4c5d6` |
| `+8` | capacity initially; replaced with used length during flush |
| `+12` | data pointer, allocation base + 16 |
| `+16` | packed records |

Validator `0x80f655d2(view)` checks only nonnull view, nonzero length and data
pointer, and the preceding magic. It does not validate record contents or
internal descriptor/payload pointers.

Reconstructor `0x80f658c6(view)` visits records containing a 32-bit length
followed by a native packet. For each complete nonzero record it calls
`0x80f645e2(packet)` to reset its reference value and reconstruct descriptor/
payload pointers relative to the copied packet base. It stops on a zero
record length or an end beyond the view's used length. Its return remains
the outer validator's value: **return 1 does not establish that every record
was reconstructed or structurally valid**. Supplied zero/overrun record
prefixes demonstrate this distinction.

Buffer retain `0x80f6585e` and release `0x80f65884` also use that outer
validator. Last release clears magic before calling pool-4 free on `view - 8`.
With zero length, invalid magic or null data pointer, the selected retain/
release paths leave the reference unchanged and make no free call. The direct
buffer cases check these branches separately from record reconstruction.

The new host parser deliberately checks more than the native outer validator:
envelope length, complete nonzero record extents, and agreement between each
packet size and its header count/stride. It leaves sender pointer values
opaque. Its validation rules are host-side bounds, not recovered firmware
guarantees.

## Flush packs complete records into 4000 data bytes

Flush entry `0x80f65920` reads the native queue count. When it obtains zero,
it clears accounting `0x80f16fd8` and motion counter `0x80f16fdc` and returns.
Otherwise it allocates a 4000-byte data buffer, peeks an eight-byte
`(packet_size, packet_pointer)` queue record and checks remaining space for
`4 + packet_size`.

For each fitting packet it executes native dequeue, pushes a 32-bit
little-endian length, copies the entire packet, and calls record cleanup to
release the queued packet reference. The packed representation is:

```text
u32 packet_size_0 | native_packet_0
u32 packet_size_1 | native_packet_1
...
```

After filling the buffer, it stores used length, reconstructs embedded
pointers, dispatches the view through `0x80f63c2e`, releases its own buffer
reference and repeats. Native queue count/peek/get, encoder integer writes,
cleanup, reconstruction and dispatch execute in these cases. Memory copies,
allocation/free and OS locks are supplied boundaries.

The fitting test is inclusive: a 3996-byte packet plus its four-byte prefix
fills all 4000 bytes. Five 1064-byte packets produce buffers of 3204 and 2136
used bytes. Tests check full allocations, queue/reference cleanup and the
resulting IPC wire hashes. A direct queue get does not decrease the cache
accounting word; this flush clears accounting after observing zero queue
count. Accounting is retained when a supplied allocation failure leaves
packets queued.

The code checks peek status but does not check the subsequent get result
before encoding. These cases use a stable queue and do not inject a concurrent
consumer or a failed get after successful peek. They do not establish safe
behavior under that race.

## A too-large head makes no progress under the supplied schedule

A synthetic 3997-byte head packet cannot fit with its four-byte prefix. In
the selected native path, it remains queued while the flush dispatches a
buffer with used length zero, releases through the outer-validity helper and
tries another buffer. Because zero length fails that helper's validity check,
the observed path does not decrement that buffer's reference or call free.

The bounded case supplies two successful buffer allocations and then one
allocation failure. Both produced buffers retain reference 1 and their magic;
queue count and both accounting words remain unchanged. The third allocation
failure causes the native allocator and flush diagnostics, then return. A
second case first consumes a fitting packet before reaching the too-large
head, confirming that the valid prefix is processed and the remainder stays
queued.

These cases use a synchronous synthetic listener so that zero-length buffers
are not sent into the event serializer. They establish this conditional
no-progress/free-call behavior, not an observed watch hang, actual allocation
exhaustion or reachability of such a packet through the complete live producer.
Corrupt length overflow and inner packet pointer corruption are excluded.

## Cache listener retains the buffer across the event boundary

The synthetic buffer-list registration points to the actual native cache
listener `0x80f9b390`. For a nonnull view it requests an event with cleanup
callback `0x80f9b34e`, writes module tag `shSensor`, event kind 3 and the view
pointer, and retains the buffer through thunk `0x80fa27e6`/`0x80f6585e`.
It posts through the configured operation-table callback at offset `0x20`.

The flush's subsequent buffer release leaves the event reference alive.
The harness supplies event scheduling: after flush returns, it invokes actual
handler `0x80f9ba6e(event)`, then the registered cleanup function with the
buffer view. Cleanup tail-calls `0x80fa27ea`/`0x80f65884`, which clears magic
and reaches free when this is the last reference. The event allocator,
registration process, scheduler and scheduler's cleanup invocation are not
executed; this is a connected native contract across explicit supplied OS
boundaries, not one uninterrupted device trace.

## Event kind 3 becomes sensor IPC opcode `0x15`

Handler `0x80f9ba6e`'s kind-3 branch reads used length and data pointer from
the view, constructs a message with opcode 21, and calls native
`0x80f99ce0`/`0x80f99c26`. Native serializer `0x80f9a5e6` produces:

```text
u8  opcode = 0x15
u32 packed_length, little endian
u8  packed_records[packed_length]
```

The records are copied after pointer reconstruction. Consequently native
reference/pointer fields remain in the payload, with addresses of the sender's
packed buffer. This pass does not establish a portable address-independent
record format or execute receiver-side reconstruction.

The serializer requests `packed_length + 5` wire bytes through operation-table
offset `+8`. Sending uses offset `+0x10`, with a three-byte routing header
and timeout argument 1200. The supplied route lookup returns 1, yielding
header `00 01 02` in these cases; it is not an observed physical routing ID.
The send callback captures the complete wire hash and prefix. A single
68-byte packet yields 72 packed bytes and 77 wire bytes; the exact-fit
4000-byte buffer yields 4005 wire bytes.

Both success and a supplied nonzero send result execute. The error path logs
at the sender and event handler. When the harness subsequently invokes the
registered event cleanup, it still releases the retained buffer reference.
Actual transport queueing, retries, zrpc/rpmsg transmission, receiver parsing
and live message delivery are outside the send boundary.

## Reproduction and remaining work

Use the corrected startup-aware sensor project with prior BBS/DSP, packet
and delivery metadata. Apply `SeedCachePipeline.java`, then export the 25
addresses in `cache_pipeline.py:TARGETS` through `DecompileWithLogger.java`
with logger `0x80f86d34` into ignored
`firmware/decompiled/runtime-cache-pipeline/`. Export counts and hash-guard
spans are provenance, not semantic-coverage counts.

```sh
python3 analysis_scripts/cache_pipeline.py \
  --vectors-output firmware/cache-pipeline-native-vectors.json
```

Run on that project:

```text
-postScript ValidateCachePipeline.java firmware/cache-pipeline-native-vectors.json firmware/cache-pipeline-native-validation.json
```

```sh
python3 analysis_scripts/cache_pipeline.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-cache-pipeline \
  --vectors firmware/cache-pipeline-native-vectors.json \
  --validation firmware/cache-pipeline-native-validation.json > analysis/cache-pipeline.json
python3 -m unittest discover -s tests -p 'test_cache_pipeline.py' -v
```

Every case checks stack/`s0..s11` preservation, full source/clone/buffer hashes,
selected status returns, queue/accounting state, allocation/free/log actions
and emitted wire hashes. Execution outside selected native spans or supplied
boundaries is rejected; each case has a 200,000-step bound. Vendor firmware,
decompiled code, tools and databases remain ignored.

Remaining work includes receiver parsing/reconstruction and consumer ownership,
actual event registration/scheduling/cleanup, transport/rpmsg operation, queue
concurrency and corrupted producer records, complete producer/fusion and other
optical modes, calibration, boot/recovery and physical verification. The
project is still short of independently booting and operating the watch.
