# Native sensor flush coordination and optical sample packets

This pass follows the previous [FIFO recovery request](PPG_FIFO_LIFECYCLE.md)
into the command backend and then executes a selected optical consumer path.
It covers three blocks: coordinated flush, packet allocation/rebinding, and
mode-1 consumption into a native packet. All execution is offline, with
synthetic driver records, heap, clock, SPI replies and lock outcomes.

The 557 cases pass against the independently authored host models: 517 flush,
23 allocation/rebinding and 17 consumer cases. Their 132,769 bounded steps
include intercepted calls; the largest case uses 1,520 steps. Complete observed
state, actions and buffer hashes are in [sensor-packets.json](sensor-packets.json).
These are software contracts under supplied inputs, not live sensor measurements.

## Block 1: command `0x81` coordinates a flush

The previous harness ends at control request
`0x80fa286a(6, 0x81, 0, 0)`. This harness starts at backend
`0x80f64238(sensor, 0x81, 0, 0)`. The intervening queue, worker, ownership
decision and possible remote transport are not executed here; the two tests
must not be presented as one uninterrupted recovery trace.

The backend first resolves a driver through `0x80f632dc`. No handle returns 2.
With a handle, it calls `0x80f66298`, which first runs fusion flush
`0x80f65e2e`. The two active-group predicates are native reads of word
`0x80f4fd1c`:

| Predicate | Test |
| --- | --- |
| A, `0x80f65cd6` | `(flags & 0x38) != 0` |
| B, `0x80f65ce8` | `(flags & 6) != 0` |

For ordinary sensor IDs, coordinated flush is selected when:

```text
(A and (sensor is 1/2 or belongs to mask 0x6de0ffe0))
or (B and sensor is 1/2/3)
```

The mask includes IDs 5–15, 21–24, 26, 27, 29 and 30. The machine tests
mask membership using `sensor & 31`. The exact sensor-3 comparison uses
the full ID. In particular, a B-only active state does not coordinate an
optical-ID-6 request: it falls back to the optical callback alone.

Coordinated callback order is sensor 1, then sensor 6 if A is active, then
sensor 3 if B is active. Helper `0x80f64216` resolves each driver separately
and tail-calls its `handle + 0x20` callback with `(0x81, 0, 0)` if present.
An absent callback is skipped. The command backend returns 0 regardless of
the supplied callback return; this status does not prove hardware recovery.
If fusion did not take the request, the helper invokes the original sensor's
callback instead.

The synthetic sensor-6 record points to the real optical control function
`0x80f763be`. Its native `0x81` branch restores its stack/registers and
tail-calls `0x80f73906(0)`. With the optical gate enabled, that executes the
previously recovered metadata and register reset. Argument zero suppresses
another recovery event. Thus this selected backend path resets without
recursively generating the kind-2 event. With the gate clear, the optical
callback returns without changing the tested FIFO metadata.

Fusion flush also clears selected counters/cache state. The harness checks
all 512 bytes at `0x80f4fb20`, initially filled with a nonzero canary, rather
than checking only the callback list. The seven count fields at
`0x80f4fb34 + 0x30*i` are cleared with **16-bit stores**, preserving the
next two bytes. Their companion words at `0x80f4fb48 + 0x30*i` are cleared
with 32-bit stores. This corrects misleading widths in the old broad C export.
Other reviewed vector/flag fields are cleared according to the request's
group, including selected resets even when fusion returns false.

After a coordinated flush, `0x80f66298` clears each active group's 16-byte
record at `0x80f4fcf8` or `0x80f4fd08` and writes the supplied wide timestamp
into its first eight bytes. Both active groups cause two clock calls. Their
exact actions and final memory are checked separately from optical metadata.

The driver lookup has a narrow but useful boundary detail: it checks
`((sensor - 1) & 255) < 35`, then indexes the table with the **full** sensor
value, not that low byte. A synthetic ID 257 and an explicitly populated
distant table slot demonstrate this distinction. Normal IDs 1–35, missing
handles/callbacks and invalid IDs 0/36/256 are covered. No claim is made that
untrusted callers can reach this helper with arbitrary IDs on the device.

## Block 2: allocation and reconstruction of native pointers

Allocator `0x80f6453e(streams, stride)` returns zero immediately if either
argument is zero. Otherwise it requests pool 4, tag `drivers/sensor`, alignment
4 and the RV32 size:

```text
size = (24 + streams * (40 + stride)) mod 2^32
```

On allocation failure it logs and returns zero, without clearing memory or
reading the clock. On success it clears the requested span and writes:

| Packet offset | Native field |
| --- | --- |
| `+0`, `+2` | 16-bit stream count and per-stream payload stride |
| `+16` | 32-bit initial reference value 1 |
| `+20` | descriptor pointer, packet base + 24 |
| `+24 + 40*i + 8` | shared 64-bit timestamp, read once per allocation |
| `+24 + 40*i + 32` | payload pointer, base + 24 + 40*streams + stride*i |

Descriptors occupy 40 bytes each; the payload region follows all descriptors.
The successful cases hash every allocated byte, including initially zero
descriptor fields and payloads. Allocation-failure cases additionally cover
32-bit size wrap without attempting a malformed successful allocation.

Helper `0x80f645e2(packet)` reconstructs descriptor/payload pointers for the
supplied packet base and resets the reference field to 1. It leaves payload
and timestamps intact. Validation copies the whole allocation to a different
synthetic address, deliberately changes its reference value to 7, executes
the native helper and checks the complete resulting allocation.

Reconstruction reads **16-bit header count/stride**. The original allocator
uses the full argument widths for size and payload placement, but truncates
the header fields. A synthetic successful stride-65536 case records that
reconstruction uses stride zero, making both stream pointers coincide. The
successful host model bounds stream count to 1–32 and stride to 1–65536;
these bounds are not a claim that all such values are legitimate device
configurations. Wider malformed values exercise allocation failure only.

This object contains native pointers and a reference field. It is not an
interchangeable IPC wire packet. Reference increment/decrement/free paths
and asynchronous ownership remain follow-up work.

## Block 3: mode-1 optical consumer

Consumer `0x80f747c0` has many mode branches. This pass executes only mode 1,
with frame width 2, a prefilled native ring and reader-mode byte
`0x80f1706e = 1`, which skips peripheral acquisition in this entry. The
allocator, cache pop and sample conversion execute native instructions.
Mutex helper `0x80f73014` and release `0x80f80382` have supplied outcomes;
their OS implementations and concurrent access are not executed.

With optical gate clear, the consumer returns zero without locking. A failed
lock also returns zero. Once acquired, the selected paths release the lock,
including empty-cache and allocation-failure paths. No frame is consumed on
those failures.

The frame count is `cached_words / 2`, limited to
`rate * 1200 / 1000`. The number of output streams is
`1 + byte[0x80f17086]`; the tested byte values are 0 and 1. Payload stride is
four bytes per retained frame. Every retained frame pops **two** ring words.
Without the second stream the second word is discarded without tag checking;
with it enabled, both words pass through the signed low-20-bit conversion.
An odd trailing cached word remains. The ring index wraps at 1000 and popped
bytes are retained; the full ring hash is checked.

Each output sample adds:

```text
offset = ((word[0x80f17048] * 0x7ffff) mod 2^32) >> 5
sample = (signed_low20(raw_word) + offset) mod 2^32
```

No saturation is introduced by the host model. Invalid measurement tags still
log and produce samples; tags 21/22 remain accepted exceptions. These values
are native sample integers, not heart rate or oxygen saturation.

The first descriptor's type word is `0x8000`; the optional second is
`0x100000`. The selected path writes frame count at descriptor `+20`, rate
at `+22`, and constant 20 at `+24`. This constant's broader meaning and the
sample units remain unassigned. Other flag words remain zero for these
types under the tested configuration.

If the frame limit removes `dropped` frames from the count used for the
packet, each descriptor timestamp is decreased by
`floor(dropped * 1000 / rate)`, with the native 64-bit borrow preserved.
The consumer pops the retained number of frames from the current read index;
it does not first discard the excess words. At rate 10 with 20 cached frames,
it returns 12 frames and leaves 16 words cached. Zero rate leads to a
zero-stride allocator call, no packet and no pops. Physical clock units and
sample frequency have not been measured.

## Reproduction and remaining work

Use the startup-aware sensor project with the guarded BBS/DSP repairs and
existing FIFO metadata. Run `SeedSensorPackets.java`, then export the eleven
addresses in `sensor_packets.py:TARGETS` with `DecompileWithLogger.java`
(logger `0x80f86d34`) into ignored
`firmware/decompiled/runtime-sensor-packets/`. Function export count and
hash-guard spans are provenance, not branch-coverage counts.

```sh
python3 analysis_scripts/sensor_packets.py \
  --vectors-output firmware/sensor-packets-native-vectors.json
```

On that project, execute:

```text
-postScript ValidateSensorPackets.java firmware/sensor-packets-native-vectors.json firmware/sensor-packets-native-validation.json
```

Then regenerate the public evidence:

```sh
python3 analysis_scripts/sensor_packets.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-sensor-packets \
  --vectors firmware/sensor-packets-native-vectors.json \
  --validation firmware/sensor-packets-native-validation.json > analysis/sensor-packets.json
python3 -m unittest discover -s tests -p 'test_sensor_packets.py' -v
```

All cases check stack and `s0..s11` preservation, use a 100,000-step bound,
and reject execution outside selected native ranges or explicit synthetic
call boundaries. Twenty-one added host tests cover independent binary
fixtures, routing boundaries and failure semantics. All 326 Python tests
pass with the existing cipher/signature dependencies available.

Remaining work includes the other consumer modes and configuration/calibration,
packet reference/free and asynchronous delivery, fusion algorithms, the
queue/worker/IPC gap, and physical bus/IRQ/timing validation. The current
tests establish neither final measurement accuracy nor a working independent
hardware driver. No phone/watch setting, firmware or hardware was changed.

The subsequent [delivery and modes pass](SENSOR_DELIVERY_AND_MODES.md) covers
native reference wrappers through the free-call boundary, selected listener
fanout, cache queue ownership and consumer modes 2/3. Allocator internals,
cache-flush IPC and other modes remain open.
