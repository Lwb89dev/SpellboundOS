# NAND page program through the original BBT, bus, QSPI and DMA stack

All **27 native cases** pass in **2,087,540 instruction/service steps** (maximum
**679,083** for the ready-at-timeout case). Actual page program now connects BBT
mapping, write-enable/cache/program/status builders, platform initialization,
bus transfer, QSPI/FIFO and DMA setup/wait. Full observations and code/data/export
hashes are in [nand-program-stack.json](nand-program-stack.json).

The previous 90 QSPI, 28 DMA, 47 platform and 31 connected read cases reproduce
byte for byte with the extended runner. Eighteen new host checks bring the suite
to **1,248 passing tests**. All execution is emulation; no phone or watch was
accessed and no physical flash was programmed.

## Connected command and payload path

Original root `0x80c28c06(buffer, page, column, length, blocking)` executes this
sequence through original builders and lower code:

1. Remap the caller's page through the actual BBT page/block helpers and validate
   geometry and the configured mapped-page guard.
2. Submit write-enable opcode `0x06`.
3. Submit quad cache-load opcode `0x32`, using the selected column and payload.
4. Submit program-execute opcode `0x10`, addressed to the **mapped** page.
5. Poll status register `0xc0` with opcode `0x0f` through the real direct FIFO
   receiver, then apply program-failure bit `0x08`.

Direct transfers capture the caller's original bytes in FIFO writes, including
a 13-byte word/tail case. The private builder selects polling at length 31 and
actual QSPI/DMA setup/wait at lengths 32/64. On the DMA path, the supplied generic
copy moves caller bytes to the private buffer **before** cache-command submission.
Actual DMA setup uses that buffer as source and the QSPI FIFO as destination.
No physical DMA payload movement is simulated; the copied buffer hash and
register/control sequence are the established outcomes.

Both normal platform initialization and bus-triggered deferred initialization
execute through the original pin, clock, QSPI and adjacent DMA descriptor paths.
Deferred initialization happens after remapping, inside the write-enable bus
transaction. Peripheral status, version 2, timers, delay/cache/copy bodies and
BBT/guard/plane variants are authored.

## Guard, address and status consequences

The configured fixture guard threshold is 512 pages. With authored BBT entries
`[1, 3, 7]`, logical page 319 maps to 447 and is rejected with `-250` before any
NAND command; logical page 320 maps to 512 and is accepted. This is software
address policy, not proof of physical write protection. An explicitly disabled
guard permits the authored low-page fixture.

The authored plane bit follows the mapped page: logical 536 maps to 728 and
changes column 16 to `0x1010` for cache load. Program-execute still uses page 728.
Reserved BBT mappings return `-150`; missing chip, null buffer, zero length and
ordinary geometry errors stop before write-enable. Unlike the read remap-error
path, program remap failure also logs the page result.

The column/length check uses **wrapping 32-bit addition**. Column `0xfffffff0`
plus length 64 becomes 48 and passes the bounds comparison; the untruncated
column word reaches the QSPI address register. This proves an arithmetic
validation gap in the software. The effect of the two-byte address phase on a
physical bus and actual NAND is unverified.

After programming, authored status `0x08` produces `-102`, while ECC bits
`0x20` alone do not fail this program-status check. A busy/then-ready case
performs all three status reads after opcode `0x10` before returning zero.

## Complete timeout and lower failure paths

Three cases each execute the full 2,000-poll busy loop through actual command,
bus and HAL code. Permanent busy, a final failure byte, and a final ready byte
all hit the limit before the helper accepts the last status. The helper logs
timeout, returns zero and leaves its output `0xff`.

The page-program caller then rejects bit `0x08` in `0xff` and returns `-102`.
In particular, an authored ready byte zero arriving at the last poll is still
rejected. This contrasts with the now-connected
[read path](NAND_READ_STACK.md), which can proceed to success after the same
sentinel-producing timeout.

Write-enable completion, cache FIFO, cache DMA and program-execute completion
failures stop at the original bus assertions with checked owner/line values.
They do not return the isolated outer policy's injected helper-error codes.
Failed cache transfer prevents opcode `0x10` and subsequent status polling.
Alternate DMA status can return zero and permit execution to continue; its
hardware meaning remains unverified.

## Evidence and remaining work

The runner pins 39 code ranges and eight data ranges, checks the normal-return
ABI, and guards immutable BBT/descriptor/frame inputs, caller buffers, registry
and original adjacent DMA backing. Each case has a 1,500,000-step cap.

Connected erase/copy/OOB policies and supported-family retry through the HAL
remain open, along with physical ID/geometry/BBT/ECC corroboration, IRQ/coherency,
board timing/pins, persistence, recovery/restoration and standalone boot. The
first original candidate is a fixture choice, not identification of the fitted
chip or proof that a successful program control path persists data.

The subsequent [erase/copy/OOB stack pass](NAND_ERASE_COPY_STACK.md) connects
those selected policies through actual BBT, builders, busy loops, platform, bus
and QSPI/FIFO, including a source-copy timeout followed by successful return.
Peripheral inputs remain authored; physical flash effects remain unvalidated.
