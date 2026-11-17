# NAND QSPI platform, command packets and busy deadlines

All 51 native cases pass in 67,695 steps, with a maximum of 30,838 for the
200-read busy timeout. Actual platform initialization, packet conversion,
ROM-version policy, selected NAND command builders and busy loops execute.
Complete observations and provenance are in [nand-bus.json](nand-bus.json).

MMIO is emulator backing. HAL, clock, pin, DMA initialization, memory-copy,
string comparison, delay, scheduler and diagnostic services are supplied.
ROM identity and response bytes are authored inputs. No watch or phone was
accessed, and no physical NAND transfer or DMA completion is established.

## Platform initialization

Actual `0x80c10580(descriptor)` compares descriptor word +`0x0c` with 100. Values
below 100 pass 2 to clock selector `0x80df9f80`; values of 100 or more pass 1.
Original descriptor values 83 and 104 and authored boundary values 99/100 are
covered. The comparison does not establish a physical clock frequency or divider.

The initializer sets bit `0x200` at `0x9a00000c` and bits `0x200 | 8` at
`0x9a000004`, preserving other bits. Controller state at `0x80dfb880` receives
base `0x93240000`, zero words at +8/+12 and DMA pointers at +32/+36. Pinmux
receives `(0, 127, 63)`; the GPIO service receives `(0, 127, 1)`.

Two DMA descriptors receive these first ten words:

| Descriptor | Words at offsets 0 through 36 |
| --- | --- |
| `0x80de64a0` | `12, 2, 0, 2, 0, 0, 6, 1, 0x93080000, 5` |
| `0x80de645c` | `12, 1, 2, 0, 0, 0, 6, 1, 0x93080000, 6` |

Word +40 remains unchanged. Word +44 is set to the controller pointer after
each supplied DMA initialization call. Untouched bytes retain authored `a5`
sentinels. Two fences are recorded and skipped as single-thread ordering markers;
this does not verify coherency or electrical ordering. Injected negative return
values from the supplied initialization services are ignored; the selected
initializer returns zero.

## ROM policy and packet conversion

Actual `0x80c12298` reads the ROM identity at `0x30000024`. It returns 1 for
`v1.1.03`, 2 for `v1.1.16` and zero for the selected unknown strings. This is
a ROM-version query; it does not report interrupt or scheduler state.

Actual transfer `0x80c106f0(descriptor, packet)` clears nonzero flag
`0x80d81d6c` and runs the actual initializer before transfer. It converts the
packet to an eleven-word HAL command frame:

| Packet field | HAL word / behavior |
| --- | --- |
| byte +0 | word 0: zero for read, 2 for any nonzero write value |
| byte +1 | word 10: zero or 8 for a nonzero dummy flag |
| byte +2 | nonzero forces the direct path |
| byte +4 | word 4, command-phase field |
| word +8 | word 2, opcode |
| byte +`0x0c` | word 7, address-length field |
| word +`0x10` | word 5, address |
| word +`0x14` | caller data pointer |
| word +`0x18` | word 9, transfer count |
| byte +`0x1c` | word 8, data-phase field |

HAL words 1, 3 and 6 are fixed at 0, 1 and 1. The additional packet word
+`0x20` used by some quad builders is not consumed by this selected transfer.

The private buffer at `0x80dfb8c0` is selected only when packet byte +2 is zero,
count exceeds 31 and the actual ROM query returns more than 1. Tests distinguish
31/32 bytes and old/unknown ROM identities. Writes copy to that buffer before
issuing the command; successful reads copy back after the supplied receive.
The 512-byte harness bound does not establish the real buffer allocation size.

The supplied HAL boundaries are command `0x80df928c`, direct receive/transmit
`0x80df93c4` / `0x80df951c` and buffered receive/transmit `0x80df94bc` /
`0x80df960c`. All receive `(controller, frame-or-data, 1000)`. Their actual
implementations and physical completion remain outside this execution pass.
Direct fixtures use a sentinel controller context; init/reinit fixtures construct
the actual software configuration. A partial supplied receive also confirms
that the wrapper does not independently validate how many bytes were delivered.

Any nonzero HAL status, including positive 1, reaches an error log, supplied
diagnostic and an assertion boundary. Direct command/read/write assertion lines
are `0x11f` / `0x12a` / `0x132`, owner `0x80c37b7c`; buffered equivalents are
`0x162` / `0x16f` / `0x17b`, owner `0x80c37b98`. Execution stops before the
assertion body and claims no return ABI for those cases. Failed buffered reads
do not copy data to the caller.

## NAND command builders

The original selected descriptor and bus-operation pointers feed actual command
builders through the actual transfer routine. The report verifies these opcode
bytes against all eleven original descriptors. The executed builder fixtures use
the first descriptor; the shared opcode check is not execution on every chip.

| Entry | Operation | Opcode | Address bytes | Data |
| --- | --- | --- | ---: | --- |
| `0x80c27ce8` | Read feature | `0f` | 1 | One byte read |
| `0x80c27d48` | Write feature | `1f` | 1 | One byte write; argument truncates to byte |
| `0x80c27db0` | Write enable | `06` | 0 | None |
| `0x80c27e0e` | Read page to cache | `13` | 3 | None |
| `0x80c27fa8` | Program execute | `10` | 3 | None |
| `0x80c28136` | Erase block | `d8` | 3 | None; address is block × 64 |
| `0x80c27e70` | Cache read, single | `03` | 2 | Phase field 1, dummy 8 |
| `0x80c27ed6` / `0x80c27f3e` | Cache read, quad | `6b` | 2 | Phase field 3, dummy 8 |
| `0x80c2806c` / `0x80c280d0` | Cache write, quad | `32` | 2 | Phase field 3, no dummy |

The second quad entry in each pair permits the private-buffer branch; the first
forces direct transfer. Vendor “nonblock” naming does not by itself establish
asynchronous completion. The selected builders return zero after successful
supplied HAL calls. A command failure stops at the inner platform assertion.

## Busy loops and timeout return values

Actual `0x80c2836e(timeout, output)` initializes the caller byte to `ff`, requests
a delay of 5 through the actual bus wait wrapper and reads feature register `c0`
through the actual builder and transfer. The wait wrapper `0x80c102f0` forwards
the argument to supplied `0x80c12154` and returns zero.

The loop checks its deadline **after the read and before the busy bit**:
`iteration >= ((timeout * 1000) & 0xffffffff) / 5`. A ready response exactly at
the deadline is therefore treated as a timeout. Timeout 1 gives 200 reads;
timeout 0 still performs one read. On timeout with successful supplied reads,
the helper logs the timeout, returns the last feature status **zero**, and leaves
the caller byte **ff**. A ready response before the deadline copies the full
status byte, including non-busy bits such as `0x10`.

Actual erase loop `0x80c286b2` requests supplied scheduler sleep 1 each iteration
and checks `iteration >= timeout` before the busy bit too. Timeout 1 with an
immediately ready response times out; timeout 2 with responses `[1, 0]` times
out; timeout 3 with the same responses succeeds. These are observed software
contracts with authored statuses, not elapsed physical timing. Downstream page,
program and erase callers still need inspection before assessing the consequence
of a zero return accompanied by output `ff`.

Actual bus deinitializer `0x80c102e0` returns zero without other effects in its
selected four-byte body.

## Reproduction and remaining work

Generate vectors with:

```sh
python3 analysis_scripts/nand_bus.py \
  --vectors-output firmware/nand-bus-native-vectors.json
```

In the startup-aware `boot-runtime` Ghidra project, apply `SeedNandBus.java`,
export all `nand_bus.py:TARGETS` with `DecompileWithLogger.java` and logger
`0x80c1cd7a` into `firmware/decompiled/runtime-nand-bus`, then run:

```text
-postScript ValidateNandBus.java firmware/nand-bus-native-vectors.json firmware/nand-bus-native-validation.json
```

```sh
python3 analysis_scripts/nand_bus.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-bus \
  --vectors firmware/nand-bus-native-vectors.json \
  --validation firmware/nand-bus-native-validation.json > analysis/nand-bus.json
python3 -m unittest discover -s tests -p 'test_nand_bus.py' -q
```

The runner pins 18 code and five original data ranges, bounds each case to
200,000 steps and rejects unexpected PCs and service arguments. It checks
normal return ABI, explicit assertion stops, complete call traces, controller
and DMA bytes, emulated MMIO, buffer hashes/guards and input immutability.
The report records 18 fresh export hashes. Thirty-four new host checks bring
the full suite to 966 passing tests.

Next work includes lower RAM HAL/ROM implementations, connected page/ECC and
program/erase error policy, UID/BBT, SFTL and physical metadata provenance.
Physical chip identity, electrical timing, DMA ownership/completion, actual
persistence, device-specific restoration and standalone signed-chain boot
remain unresolved.

The subsequent [page-policy pass](NAND_PAGE_POLICY.md) executes the actual
read/program/copy/erase callers together with the actual busy loops. It verifies
that the selected read can proceed after timeout with ff status, while program
and erase return status failures. Its command/feature/remap services are supplied;
it does not establish physical NAND behavior.
