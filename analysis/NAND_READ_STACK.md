# NAND page read through the original bus, QSPI and DMA stack

All **31 native cases** pass in **1,418,115 instruction/service steps**, with a
maximum of **678,807** for the last-poll ECC case. The original page reader now
executes together with BBT remapping, page-load/status/cache command builders,
busy polling, platform initialization and actual QSPI/FIFO/DMA routines.
[nand-read-stack.json](nand-read-stack.json) records every compared register
event, return/stop, buffer hash, descriptor and code/data/export hash.

The prior 90 QSPI, 28 connected DMA and 47 platform cases reproduce byte for byte.
Twenty new host checks bring the suite to **1,230 passing tests**. No phone or
watch was accessed. Peripheral state, FIFO contents, timers and lower services
are fixtures; there is no claim of physical NAND data delivery.

## Connected original execution

The root is `0x80c28a98(buffer, page, column, length, blocking)`. It calls the
actual page/block remappers, then submits opcode `0x13` through the real bus and
HAL. The actual busy loop invokes the original wait wrapper and feature builder,
which reads register `0xc0` using opcode `0x0f` through the real polling FIFO path.
Only the leaf delay implementation is supplied and records argument 5.

The final quad-cache builder submits opcode `0x6b`, two address bytes and eight
dummy bits. Blocking reads use the actual direct FIFO receiver. The other branch
uses the actual private-buffer builder: lengths up to 31 still select polling,
while lengths 32 and 64 select actual QSPI DMA wrappers and actual DMA setup/wait.
Generic copy/cache services and peripheral status remain authored.

Complete selected bus initialization uses the original pin/clock/QSPI/DMA
functions and original adjacent DMA addresses. A deferred case instead reaches
the actual initializer inside the first bus transfer, **after** page remapping.

## Address and status consequences

With authored active BBT entries `[1, 3, 7]`, logical page 600 becomes physical
page 792 before opcode `0x13` is submitted. Inactive, unsorted and duplicate
tables retain the previously observed remapper behavior. The reserved-page
failure returns `-150` before any NAND command; the last usable logical page
65215 submits physical page 65407. The BBT and descriptor are checked immutable.

The authored plane flag is applied to the **mapped** page. Logical page 536 has
bit 64 clear but maps to page 728 with it set, so column 16 becomes `0x1010`.
Logical page 600 has the bit set but maps to 792 with it clear, so column 16 stays
16. These are software arithmetic observations, not physical plane verification.

The first original candidate descriptor uses ECC mask `0x30` and bad value
`0x20`. Status `0x10` completes without entering retry. With `0x20`, actual retry
and compatibility selection execute; the original first-chip name matches
neither supported family, so retry returns `-1`. The page reader nevertheless
performs the cache transfer and then returns `-101`. The bounded `strncmp`
service is supplied and its three original string inputs are byte guarded.
Supported-family retry levels remain covered by the separate
[retry/UID pass](NAND_RETRY_AND_UID.md), over a supplied bus.

## Timeout and assertion behavior

Both full 2,000-poll cases execute through the original status builder, bus and
HAL on every iteration. At the last iteration, the busy helper checks its limit
**before** accepting the new status. It logs timeout, leaves output `0xff`, and
returns the last successful feature-helper status, zero. Consequently:

- A permanently busy authored status 1 can be followed by cache transfer and a
  successful page-read return.
- An ECC-bad `0x20` arriving on the last poll is discarded. The caller sees
  `0xff`, whose masked value `0x30` does not equal `0x20`, and skips retry.

The full stack confirms these behaviors previously found with supplied command
services. They are firmware failure semantics, not proof that a physical timeout
recovers successfully.

Load-command, feature-receive, DMA-wait and cache-completion failures stop at the
original bus assertions with checked owner/line pairs. They do not return the
synthetic outer helper-error codes used in earlier isolated policy tests.
Failed private reads do not copy the buffer back. Alternate DMA status can still
return zero while leaving tracking live, as in the separate backend pass.

## Payload and evidence limits

Direct FIFO payload is an authored `0x5a + 7*i` stream independent of status-byte
reads. Private DMA execution does **not** manufacture hardware movement: the
authored `0xa5` buffer is copied back after a successful control-path return.
Different direct/private buffer hashes are expected fixture outcomes.

The runner pins 37 code ranges and eight data ranges, uses a 1,500,000-step cap,
checks normal-return ABI canaries, and guards caller buffers, the command frame,
BBT, descriptor, DMA registry and the adjacent original DMA pair. The fresh
exports are provenance aids; original instruction execution resolves volatile
and decompiler ambiguities.

Remaining work includes connected program/erase/copy policies, supported-family
retry through the HAL, physical BBT/chip/geometry/ECC corroboration, board timing,
pin wiring, IRQ/cache coherency, persistence, restoration and standalone boot.
The first candidate is a fixture choice, not identification of the fitted chip.

The subsequent [program-stack pass](NAND_PROGRAM_STACK.md) closes selected
connected program/guard paths and compares their complete timeout behavior with
this read path. Physical programming remains unvalidated.

The subsequent [erase/copy/OOB stack pass](NAND_ERASE_COPY_STACK.md) connects
those selected policies through actual BBT, builders, busy loops, platform, bus
and QSPI/FIFO, including a source-copy timeout followed by successful return.
Peripheral inputs remain authored; physical flash effects remain unvalidated.

The subsequent [connected retry/UID pass](NAND_RETRY_UID_STACK.md) executes
supported-family retry, page-read recovery, UID acquisition and selected ioctl
through original platform/bus/QSPI/FIFO, with selected private-read DMA.
Feature/UID/peripheral effects remain authored; physical correction and identity
provenance are unvalidated.
