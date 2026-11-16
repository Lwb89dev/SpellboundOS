# Native optical register transactions with synthetic peripheral inputs

Follow-up: [FIFO lifecycle](PPG_FIFO_LIFECYCLE.md) follows supplied SPI outcomes
into the native batching reader, metadata reset, recovery notification and
selected cache/sample primitives. The full consumer and actual sensor remain
outside these host executions.

This pass extends the earlier adapter-only checks by executing the actual
register wrappers, public SPI transfer, bus acquisition/release, chip-select
adapters and polling HAL together under corrected SLEIGH. It complements
[ownership and completion](SPI_OWNERSHIP_AND_COMPLETION.md).

The inputs are deliberately synthetic: SPI status/data words, scaled timestamp
values and successful mutex/diagnostic outcomes. No watch, real SPI bus,
elapsed-time source, optical measurement or fitted chip identity is exercised.

## Guarded native chain

```text
read:  0x80f7304c -> 0x80f898ae -> 0x80f7b3a0 -> 0x80f7ed84
write: 0x80f73152 -> 0x80f897bc -> 0x80f7b3d0 -> 0x80f7ee38
bus:   0x80f8965c / 0x80f896d8
CS:    0x80f7b404 / 0x80f7b3e8 -> 0x80f7bdbc
```

Read wrapper `0x80f7304c` creates a three-byte stack buffer:
`register, 0x80, 0`. It uses the **same buffer** for transmit and receive,
passes length 3 and timeout word 1000, and copies only byte 2 to the caller
when the public transfer returns zero. Both wrappers preserve the underlying
integer result, correcting the earlier broad exports that appeared void.

Write wrapper `0x80f73152` creates `register, 0, value`, then calls public
transmit with length 3 and timeout 1000. Buffer registers/values are narrowed
to bytes. Prefix semantics and echo content are not independently validated
on hardware; these are the bytes the bundled code constructs.

The test sets the optical handle and operation records in emulator memory,
using the actual polling adapters and chip-select functions. Peripheral status
and data reads are intercepted at `0x9000400c` and `0x90004018`; native stores
are observed at the data register and the two logical GPIO offsets. The timer
reader at `0x80f7b594` is intercepted and returns supplied unsigned pairs.
Its previously analyzed division is not re-executed by this test.

## Thirteen bounded cases

| Case | Result and observed behavior |
| --- | --- |
| Register read | emits `ff 80 00`, consumes three supplied RX bytes, copies `0x46` |
| Delta exactly 1000 | all bytes complete, result remains zero |
| Delta 1001 after final byte | all TX/RX bytes move, result `-14`, caller output remains `0xa5` |
| Delta 1001 after first byte | one TX/RX byte moves, result `-14`, output unchanged |
| Busy status until timeout | no data movement; release still occurs |
| TX-ready only | all three TX bytes emitted, no RX; timeout |
| RX-available only | three supplied RX bytes consumed, no TX; timeout |
| Supplied timestamp wrap | unsigned 64-bit subtraction permits completion |
| Missing operation table | result zero, no clock/GPIO/data access, output becomes initial dummy byte zero |
| DMA flag with initial null DMA slot | same no-transfer zero result and copied dummy byte |
| Register write | emits `ff 00 ab`, result zero |
| Write timeout after final byte | same three TX bytes emitted, result `-14` |
| Direct zero-length full-duplex HAL | one initial timestamp, no data transfer, result zero |

The `0x46` response is a chosen test byte, not a measured identity. The busy,
TX-only and RX-only status inputs test the software branches; they are not
assertions about which status sequences occur on real silicon. The full-width
timestamp-wrap case checks subtraction arithmetic, not reachability of those
values from the actual scaled counter or continuity across sleep.

For every real-operation case in this group, the observed lifetime is mutex
take, select store, deselect store, mutex release. The no-operation cases
perform none of those actions. All thirteen cases verify the native result,
output byte, exact emitted bytes, receive/timestamp read counts, event order,
stack restoration and callee-saved registers. Every executed instruction or
intercepted call is bounded to the selected ranges and at most 10,000 steps
per transaction. Stored traces include actual step counts.

## Implications and remaining limits

The earlier post-movement timeout finding now reaches the register caller:
even with all RX bytes supplied, a final-iteration timeout suppresses the
output copy. Conversely, a zero result from an absent operation can copy a
buffer byte that was initialized locally. Neither result is sufficient on its
own to infer what happened electrically or whether an optical register was
read. A new independent driver must define its own explicit completion and
error contracts using the recovered behavior as evidence.

These tests use ordinary emulator memory plus read/write interception. They
do not model peripheral FIFO ordering, reset/enable semantics, clock shifting,
interrupt races, cache coherence, DMA, bus arbitration or actual mutex state.
The in-place buffer is faithfully executed; correctness under all asynchronous
hardware status/data sequences is not established. FIFO batching and health
sample processing remain separate paths.

## Reproduction

Use the established startup-aware sensor project, corrected language and
`SeedOpticalSpi.java`/`SeedSpiOwnership.java` metadata. Run:

```text
-postScript ValidateSpiPolling.java firmware/spi-polling-validation.json
```

The private stdout log is `firmware/ghidra-spi-polling-validation-stdout.log`.
The public [spi-ownership.json](spi-ownership.json) includes all thirteen
synthetic traces, their report hash, and hashes for every selected native
range. Rebuild it with the command in the ownership report. Extracted vendor
code, image bytes, tool files and Ghidra projects remain ignored.
