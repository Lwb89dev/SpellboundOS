# Native optical FIFO faults, recovery and cache consumption

This pass executes the OTA 4.6.0.3 optical FIFO reader and selected recovery,
event-dispatch and cache-consumer primitives under corrected SLEIGH. It follows
[register transactions](SPI_REGISTER_NATIVE_EXECUTION.md) into the caller that
batches optical words. SPI outcomes, context queries, tick values and listener
registration are synthetic. No hardware fault, chip measurement or recovery
success was observed on a watch.

## Entry-to-entry timing and status reads

Reader `0x80f74526` calls tick wrapper `0x80f7f958`, whose two context branches
read kernel tick word `0x80f171a4` through `0x80f8263e`/`0x80f82648`. Its next
call, `0x80f80aa0`, is just `ret`: it preserves the supplied return register.
Restoring these signatures removes an earlier misleading void/empty export.
This is separate from the scaled memory-counter reader used by the SPI HAL.

When saved entry tick `0x80f17050` is nonzero, the guard expires only when
unsigned 32-bit `now - saved` exceeds limit `0x80f1704c`. Equality passes;
rollover arithmetic is preserved. A saved zero skips the guard. Before the
status/transfer work, the reader records the current entry tick. Thus this
guard measures the interval between reader entries, rather than the duration
of the burst that follows. Physical elapsed time and scheduler latency remain
unmeasured.

The local status bytes start at zero. The reader calls register-read wrappers
for registers 3 and 4, but does not check either return. A failed read that
leaves its output unchanged contributes zero to the count calculation:

```text
available = ((status_3 & 0xc0) << 2) | status_4
```

Counts at least 512 request recovery. The cache-capacity check uses the full
`available + cached` count **before** rounding to a complete frame. For
example, cached 998, available 3 and frame width 2 still request recovery,
although the rounded two-word read would fit. Equality at 1000 is accepted.

## Burst failure and retained staging bytes

The selected metadata fields are 16-bit count/write/read/frame at
`0x80f1705c`/`5e`/`60`/`62`. Frame-total counter `0x80f17054` is 32-bit.
The native reader rounds available words down to complete frames and, when
nonzero, increments the frame-total counter **before** transfer or validation.
The supplied model bounds the frame field to 0–32; its zero-frame case makes
no burst. Native validation reads the low byte of this field for frame-start
checks, so corrupt/high-byte configurations are outside the model.

For a nonempty burst, the reader writes only prefix bytes `08 80` at staging
base `0x80f4ff38`, then requests `2 + 4*words` bytes in place through public
SPI full duplex. It does not clear the remaining staging bytes. The supplied
SPI return word is discarded and decoding starts at offset 2 regardless.

The native cases confirm these conditional outcomes:

| Supplied SPI outcome | FIFO effect |
| --- | --- |
| Complete data and success | words are cached in the recovered big-endian order |
| Complete data and error | the same words are cached; error does not gate decoding |
| Error with no response writes | retained payload words are cached if they pass the frame check |
| Error after a partial word | new high bytes and retained low bytes can form one accepted word |

In the partial-word vector, retained `0x21000009` becomes `0x2100aa09` after
only the three high payload bytes are replaced. This is synthetic evidence
of the software's behavior; it does not establish how often such a peripheral
failure occurs on the device. The earlier SPI pass independently showed that
its error can follow partial or complete data movement.

The ring at `0x80f5073c` contains 1000 words. Writes wrap at index 1000.
The harness hashes all 4000 ring bytes and a 2052-byte staging window ending
at the ring base; this window is a host observation span, not a recovered C
object-size declaration. The maximum tested burst is 511 words/2046 bytes.

For nonzero mode, only each frame's first word is tested. Rejection requires
both measurement field not equal to 1 **and** channel field nonzero. A word
with channel zero passes that condition, as does a mismatched word at a
non-start position. The tests preserve this weaker check.

## Recovery is gated and does not erase all state

Recovery entry `0x80f73906` acts only when byte `0x80f17091` is nonzero.
Its selected active path clears the saved entry tick, calls metadata reset
`0x80f72e86`, and performs register recovery through `0x80f738be`.
Metadata reset clears count/write/read and reloads frame width from byte
`0x80f16b30`. It leaves the staging/ring contents, frame-total counter and
auxiliary field `0x80f17066` intact.

On a frame error after a valid prefix, that prefix has already been stored.
Its write/count and auxiliary updates are committed before recovery. An
active recovery clears selected metadata but retains the written ring bytes;
with the recovery gate clear, prefix metadata remains too. Frame totals are
not rolled back. The auxiliary counter increments modulo 65536 only when
policy byte `0x80f1706d` is not 2 and mode `0x80f17070` is not 1; its complete
application meaning remains unassigned.

The register sequence uses one initially zero temporary byte:

```text
read 9 -> write 9 with bit 4 set
read 0x0d -> write it with bit 1 set -> write the saved byte again
```

None of those SPI results is checked. If the second read fails without
updating the temporary, the writes to register `0x0d` reuse the byte read
from register 9. In the supplied example, register 9 returns 5 and the
register-13 read fails, producing writes `9=21`, `13=7`, `13=5`. These are
observed native arguments under the selected inputs, not asserted electrical
register semantics or evidence that recovery succeeded.

## Recovery notification reaches a control request

When requested, recovery supplies eight local bytes
`02 06 00 00 00 00 00 00`: event kind 2, sensor ID 6. This differs from the
normal optical process IRQ's kind 1 message and from any BLE/wire packet.

The test executes native dispatch `0x80f63f6c`/`0x80f63aa6` with either an
empty list or one synthetic listener bound to callback `0x80fa40b0`. With
that listener installed, the callback reaches control entry `0x80fa286a`
with arguments `(sensor=6, command=0x81, data=0, length=0)`. Execution stops
there with a supplied return. Allocation, worker queues, ownership routing,
IPC transmission and the final command backend are not executed or assigned
a completed recovery meaning.

## Cache pop and signed sample primitive

Pop helper `0x80f72ea4` returns zero without changing metadata when empty.
Otherwise it returns the raw cached word, decrements count, advances/wraps
the read index and leaves the cached bytes intact. If the auxiliary count is
nonzero and mode is not 1, it decrements that count and ORs bit 0 into the
supplied flag byte, preserving its other bits. Returned zero alone therefore
does not distinguish an empty cache from a stored zero word.

Helper `0x80f72f18` sign-extends the low 20 bits, yielding
`-524288..524287`. It compares the measurement tag to the expected low-byte
index-plus-one; tags 21/22 are accepted exceptions. Other mismatches log a
diagnostic **and still return the signed sample**. It does not validate or
compute a final health measurement. Full `0x80f747c0` consumer branches,
calibration, channel/unit meanings and inter-processor sample delivery remain
open.

## Reproduction and validation

The 45 native cases comprise 28 reader scenarios, six recovery scenarios,
one metadata reset, four pops and six sample conversions. They pass against
the independently authored Python state/buffer model. Every case checks final
metadata, complete ring/staging hashes, register/event/control actions,
relevant return/flag values, stack restoration and callee-saved registers.
The recorded run has 19,258 bounded execution steps, at most 14,416 per case.
Steps include intercepted calls; they are not measured device cycles.

Context queries, SPI operations, diagnostics and control-call outcomes are
supplied. Native tick branches, buffer handling, recovery instructions,
dispatch/list traversal and selected cache/sample primitives execute normally.
No concurrency, peripheral FIFO state machine or real callback-registration
process is modeled. Parent entry `0x80f75bf6` mutex ownership and the complete
`0x80f747c0` consumer are not executed. Frame and metadata bounds are host
limits, not proof of all valid device configurations.

On the established corrected sensor project, run `SeedPpgFifo.java` and
export `ppg_fifo_lifecycle.py:TARGETS` with `DecompileWithLogger.java`, logger
`0x80f86d34`, into ignored `firmware/decompiled/runtime-ppg-fifo/`.
The 16 exports include consumer follow-up material; export count is not
semantic coverage. Then run:

```sh
python3 analysis_scripts/ppg_fifo_lifecycle.py \
  --vectors-output firmware/ppg-fifo-native-vectors.json
```

```text
-postScript ValidatePpgFifo.java firmware/ppg-fifo-native-vectors.json firmware/ppg-fifo-native-validation.json
```

```sh
python3 analysis_scripts/ppg_fifo_lifecycle.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-ppg-fifo \
  --vectors firmware/ppg-fifo-native-vectors.json \
  --validation firmware/ppg-fifo-native-validation.json > analysis/ppg-fifo-lifecycle.json
python3 -m unittest discover -s tests -p 'test_ppg_fifo_lifecycle.py' -v
```

The private stdout log is `firmware/ghidra-ppg-fifo-validation-stdout.log`.
[ppg-fifo-lifecycle.json](ppg-fifo-lifecycle.json) fingerprints the images,
selected native ranges, exports, vectors and execution results. Eighteen host
tests additionally check the recovered contracts and input bounds. Vendor
code, image bytes, databases and private tool artifacts remain ignored.
