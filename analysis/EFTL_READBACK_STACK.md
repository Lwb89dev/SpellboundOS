# Enabled EFTL write readback through NAND/QSPI

All **16 native cases** pass in **799,362 instruction/service steps** (maximum
57,438). Original write/readback, page/OOB extraction and checksum execute
through the lower stack, including selected TX/RX DMA. The prior 485 native
cases reproduce byte for byte. Twelve new host checks bring the suite to
**1,393 passing tests**. Observations and 77 code/export plus twelve data hashes
are in [eftl-readback-stack.json](eftl-readback-stack.json).

No device was accessed. Ready mapping, RTOS/peripheral results and cache bytes
are authored. Physical readback, ECC correction and persistence are unverified.

## Readback checks and publication

Context byte +5 enables the original readback branch after full-page program.
The code reloads the page through original NAND read, fetches spare bytes,
extracts four metadata bytes and checks tag `0x45` and the original additive
checksum at `0x80c01a0a`. A bad tag short-circuits the checksum. A bad checksum
executes that helper, logs its error and returns `-2` through the upper API.

The comparison **does not verify the logical block number against the requested
block**. A supplied record `[7, 0, 0x45, 0x4c]` passes while writing logical block
zero. This is a conditional software acceptance result, not an observed device
corruption or evidence of correct physical data.

Successful first-page allocation publishes the new RAM mapping after readback.
Checksum failure leaves the new block's next-page flag advanced but the mapping
unpublished. Rewrite propagates the same check result; logical erase converts
the writer failure into `-14`. With readback disabled, observations exactly
match the prior normal-program fixture.

## Direct FIFO and private DMA fixture behavior

Fast or context-direct readback consumes an authored 64-byte spare stream. The
real OOB extractor and checksum consume those bytes without replacing their
intermediate helpers. Generic IRQ/context-direct mode executes the original
driver callbacks too.

Normal private write stages a full page in the private buffer. Private readback
executes actual RX DMA setup/wait, but the peripheral model still simulates no
DMA movement. The following copy therefore returns stale TX buffer bytes into
spare scratch; the selected authored input fails metadata validation. This is
an expected model boundary, not proof that real DMA returns stale data.

A cache-receive failure stops at the original bus assertion before checksum.
Caller input, scratch, mapping, flags, guards and ABI on normal returns are
checked alongside the lower traces. Readback I/O errors entering relocation,
bad marking and prefix-copy repair are handled in subsequent work.
