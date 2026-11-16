# Main/sensor cache receiving, reconstruction and listener ownership

This pass follows the [opcode-21 sender](CACHE_FILTER_FLUSH_AND_IPC.md) into
both main and sensor receiver implementations. Four blocks are covered:
borrowed decoding, receive/copy/reconstruction, listener ownership, and
bounded malformed-record behavior. All 66 native cases pass: 33 per core,
each comprising eight decoder, eleven parser and fourteen receiver cases.
The checked results and provenance are in [cache-receiver.json](cache-receiver.json).

The run has 16,439 bounded steps including intercepted calls: 8,350 main
(maximum 701 per case) and 8,089 sensor (maximum 679). Twenty-one added host
tests bring the Python suite to 392 passing tests. One input wire has exactly
the hash captured by the preceding native sender's `flush_one` case; the new
test checks that link against the committed sender report.

Input messages, allocation/free/copy services, critical-section boundaries,
context and listener registration are synthetic. Decoder logic, receive
dispatch, packet pointer reconstruction, buffer references and list traversal
execute natively. This does not execute zrpc/rpmsg or establish a live receive
trace. No phone/watch setting, firmware or hardware was changed.

## Selected native counterparts

| Function | Main | Sensor |
| --- | --- | --- |
| Receive callback | `0x7071fd60` | `0x80f993d0` |
| Protocol parser | `0x70720ac0` | `0x80f99ea8` |
| Opcode-21 handler | `0x707200f2` | `0x80f996e4` |
| Parsed-message cleanup | `0x70722a98` | `0x80f9afa0` |
| Buffer allocator | `0x701e4f04` | `0x80f657ee` |
| Buffer reconstruction | `0x701e4ff0` | `0x80f658c6` |
| Embedded packet reconstruction | `0x701e3cb8` | `0x80f645e2` |
| Buffer retain / release | `0x701e4f7c` / `0x701e4fa6` | `0x80f6585e` / `0x80f65884` |
| Buffer listener dispatcher | `0x701e330e` | `0x80f63c2e` |

Main RAM reference helpers execute at their copied runtime PCs
`0x80d3d5a2`/`0x80d3d622`; using their file-source PCs would give incorrect
relative calls. Their arithmetic executes here, while critical enter/exit
is supplied. No cross-core atomicity or physical interrupt exclusion is
inferred from these tests.

## Block 1: borrowed decoder and envelope boundaries

The decoder's state is base, length, cursor and a byte error field. It is
16 bytes including padding, rather than just the three pointer/size words
shown by some old exports. Initialization with empty input sets those words
to zero and error to 1. Valid nonempty input starts at error 0.

The native byte/u32/slice helpers have these checked contracts on both cores:

- A u32 read is little endian. An insufficient read returns zero without
  advancing the cursor or returning a partial value.
- Insufficient reads set error 2 only when it was zero. Error 2 is sticky,
  but remaining-space calculation and later fitting reads still operate.
  A failed four-byte read from `ab`, followed by byte and one-byte-slice
  reads, returns zero, `a`, and a pointer to `b`, with error 2 throughout.
- A zero-length slice returns null without advancing or setting an error.
- Slice pointers refer directly into the input message; these helpers do
  not allocate or copy the selected bytes.

The opcode-21 parser reads one opcode byte, a u32 declared size and a slice
of that size. It stores the declared size even when slice extraction fails.
Zero declared size, truncated length fields, declared size beyond available
bytes and `0xffffffff` length return parser status 1 in the reviewed cases.

On success the decoded pointer is input base + 5. The parser does not check
complete consumption of the envelope: extra trailing bytes are accepted and
excluded from the selected payload. The stricter host parser introduced in
the preceding pass rejects that mismatch. Both behaviors are retained in
their respective models rather than treating host validation as firmware
behavior.

This parser does not check the packed records' internal shape. A one-byte
nonempty payload passes envelope parsing in the standalone parser case;
it is not passed into reconstruction in this harness, which would first
need to read a four-byte record prefix. Decoder/receiver inputs remain
bounded, and physical alignment/trap behavior is not emulated.

## Block 2: receive dispatch copies before reconstructing pointers

The receive callback clears its fourth argument's output byte, parses into
a temporary message, and dispatches through the opcode function table.
The report calls that opaque byte `ack`; these tests establish only its
write to zero, not an on-wire ACK meaning. Standalone parser/decoder cases
leave its synthetic initial value 165 unchanged.

The supplied opcode-21 table entry selects the real handler. If parsing
fails, the callback logs and returns that status without allocation or
consumer calls. A missing opcode handler returns zero without allocation.
With a handler installed and valid envelope, the native sequence is:

1. Allocate a buffer of declared payload size, using 16 extra bytes for
   reference, magic, size and data pointer.
2. Copy only the declared bytes from the borrowed input slice.
3. Run reconstruction over the copied packed records.
4. Call the configured buffer consumer/dispatcher.
5. Release the handler's buffer reference.

Allocation uses main pool 5 and sensor pool 4, with their respective
`drivers/sensor` tags. Failure returns 8 after allocator/handler diagnostics;
there is no consumer call. Input bytes, including any trailing bytes, remain
unchanged in every checked case.

The previous sender's 77-byte wire input contains one 68-byte native packet
inside 72 packed bytes. Main and sensor both copy those 72 bytes to a new
88-byte allocation. Sender pointers refer to synthetic base `0x81100000`;
the receiver allocation uses distinct base `0x81200000`. Embedded reference,
descriptor and payload pointers are reconstructed relative to the latter
before listeners run. Complete copied-buffer hashes verify the distinction.

Parsed-message cleanup makes no free call for opcode 21. The borrowed input
remains externally owned; transport release of that message is outside this
pass. Embedded packets are not independently freed by this handler: their
bytes reside in the reference-counted parent buffer.

## Block 3: listener dispatch and retained buffer references

The main module's default four-callback table at `0x709b8898` contains
`0x7071eda4`, `0x7071ed9c`, `0x7071ed94`, `0x7071ed8c`. Static setup
`0x7071fcb6` and manager initialization `0x707209e4` provide the path that
copies the callback record into globals beginning at `0x70fd5ffc`. Its
third callback, selected by the opcode-21 handler at `0x70fd6004`, tail-jumps
to buffer dispatcher `0x701e330e`.

The native main tests supply that default callback binding and a synthetic
listener list at `0x70f92920`. Sensor cases supply the corresponding
`0x80f9891c` bridge to `0x80f63c2e`, with list head `0x80f4fb10`. Initializer
and default-binding evidence is static; actual startup/registration is not
executed. The receiver's handler and bridge execute with those bindings.

Listeners run in list order with the new buffer view. Dispatch does not
implicitly retain for each listener. The synthetic listeners either capture
the view and return, or invoke the actual native buffer-retain helper before
returning. The receive handler then releases its reference.

With two retaining listeners, they observe reference values 1 and 2 before
their respective increments. After handler return, reference value 2 and
valid magic remain. The harness separately schedules one native release per
retained reference; the final release clears magic and reaches the pool free
service. With no retaining listeners, the handler's release reaches free
immediately. Empty-list and absent-handler cases are checked separately.

The snapshots distinguish state after the handler returns from state after
the supplied deferred releases. Actual application listeners, their scheduling
and health algorithms are not executed. Free services preserve the fixture
bytes for inspection rather than running the vendor allocator.

## Block 4: malformed records can reach dispatch after incomplete fixup

The receive handler does not use reconstruction's return value to decide
whether to dispatch. The reconstructor's outer-validity return is also
insufficient to establish record validity, as the preceding pass showed.

On both cores, the bounded receiver cases confirm:

| Supplied packed input | Native behavior with capturing listeners |
| --- | --- |
| Zero record-size prefix followed by packet bytes | reconstruction stops; opaque copied bytes still reach the listener; receiver returns zero |
| Record end beyond declared packed length | same stop/dispatch behavior |
| Valid first record, overrun second record | first is reconstructed; second remains unchanged; buffer still reaches the listener |
| Complete 68-byte record whose packet header claims two descriptors | packet reconstruction trusts that count and performs a pointer write beyond the buffer allocation |

For the last fixture, the 72-byte packed payload leads to an 88-byte parent
allocation. Its embedded packet starts at allocation + 20. A header count
of two makes reconstruction write the second descriptor's payload pointer
at allocation + 116, which is 28 bytes into the synthetic guard following
the allocation. The expected guard contains that exact four-byte pointer
write (`receiver_base + 128`), while valid cases leave all 128 guard bytes
unchanged. The first descriptor also receives a payload pointer outside the
declared allocation, but the capturing listeners do not dereference it.

The malformed count is deliberately bounded to two, and all affected memory
is synthetic emulator backing. These results establish the checked native
trust in inner metadata under those inputs. They do not establish a reachable
live protocol attack, real allocator corruption, downstream measurement
behavior or a device crash. Transport/authentication acceptance and full
producer constraints remain unverified. The strict host packet parser rejects
the inconsistent record/count fixture.

## Reproduction and remaining work

Use the corrected startup-aware main and sensor projects with the established
SLEIGH repairs. Apply `SeedCacheReceiver.java main` or `sensor`, then export
the corresponding eighteen functions used by `cache_receiver.py:evidence`
with `DecompileWithLogger.java`: logger `0x702b38a2` on main and `0x80f86d34`
on sensor. Exports go into ignored
`firmware/decompiled/runtime-cache-receiver-main/` and
`firmware/decompiled/runtime-cache-receiver-sensor/`. Counts and guard spans
are provenance, not semantic-coverage measurements.

```sh
python3 analysis_scripts/cache_receiver.py \
  --vectors-output firmware/cache-receiver-native-vectors.json
```

Run sequentially on the respective projects:

```text
-postScript ValidateCacheReceiver.java firmware/cache-receiver-native-vectors.json firmware/cache-receiver-main-validation.json main
-postScript ValidateCacheReceiver.java firmware/cache-receiver-native-vectors.json firmware/cache-receiver-sensor-validation.json sensor
```

```sh
python3 analysis_scripts/cache_receiver.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled \
  --vectors firmware/cache-receiver-native-vectors.json \
  --main-validation firmware/cache-receiver-main-validation.json \
  --sensor-validation firmware/cache-receiver-sensor-validation.json > analysis/cache-receiver.json
python3 -m unittest discover -s tests -p 'test_cache_receiver.py' -v
```

Runners check stack/`s0..s11` preservation, input immutability, decoder state,
parser fields, callback snapshots, before/after-owner reference state, complete
allocation/guard hashes and relevant diagnostics/returns. Unexpected PCs and
logs are rejected; each case has a 100,000-step bound. Runtime main RAM code
is mapped from the startup copy tables. Vendor bytes, code, tools and databases
remain ignored.

The follow-up [ENGINE_CACHE_AND_HR_POLICY.md](ENGINE_CACHE_AND_HR_POLICY.md)
executes actual main cache listener registration, the identified engine-cache
callback/event/destructor, engine fanout and selected engine-7 HR consumer
handling with supplied mathematical results. Its 40 native cases extend these
receiver boundaries; the full registration queue and real engine activation
remain unexecuted.

Remaining work includes other application consumers and registration,
transport/event lifetimes and concurrency, complete malformed-input and producer
constraints, actual algorithm math, other optical modes, fusion/calibration
and physical validation.
These receiver contracts do not close the standalone boot/recovery or live
hardware requirements in [RE_STATUS.md](RE_STATUS.md).
