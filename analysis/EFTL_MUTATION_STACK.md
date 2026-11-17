# Upper storage program, logical erase and rewrite through EFTL/NAND/QSPI

All **36 native cases** pass in **266,399 instruction/service steps** (maximum
**54,825** for logical erase using direct FIFO). Original upper storage mutation
entries, EFTL callbacks/page writer/free-block selector/OOB packer, NAND adapters,
context/mutex wrappers, BBT, bus/QSPI and selected DMA execute together.
[eftl-mutation-stack.json](eftl-mutation-stack.json) records observations and
76 code/export plus twelve data hashes.

All **449 prior native cases reproduce byte for byte**. Twenty new host checks
bring the suite to **1,381 passing tests**. No watch or phone was accessed.
Registry, ready mapping/flags/counters, RTOS/peripheral results and leaf services
remain authored; physical programming, persistence and recovery are unverified.

## Complete partial-page staging and NAND transfer

Upper storage program `0x80c24502` performs actual owner/bounds checks and calls
original EFTL program `0x80c23336`, which enters writer `0x80c01eea`. The selected
geometry is 2,048 data bytes plus 64 spare bytes. Readback is explicitly disabled.

At aligned offset 2048, a 32-byte caller request copies those bytes into the
scratch page, fills the remaining 2,016 data bytes with `0xff`, fills spare with
`0xff`, and packs the actual four-byte EFTL record at spare offset 20. The record
contains logical block, tag `0x45` and additive checksum. Original `nvms`,
`envbak` and `recovery` offsets produce different logical-block metadata.

The writer submits the complete **2,112-byte page and OOB**, not only the caller's
32 bytes. Generic mode reaches original partition write/callback/context/mutex
and private TX DMA; fast/context-direct mode captures every byte in FIFO writes.
The caller's 512-byte input backing stays unchanged in every fixture.

The private path copies scratch into the original private-buffer address before
submission and executes actual TX DMA setup/wait. DMA status selection follows
the descriptor used by actual setup for these mutation fixtures. Physical DMA
movement is not simulated. The direct FIFO payload and private-buffer hash match
the prepared page/OOB exactly, conditional on the authored peripheral model.

This pass supplies **2,112 bytes of emulator backing** at the private-buffer
address. It does not establish the original allocation size, neighboring live
objects or safe physical capacity. The old smaller fixtures retain their prior
backing/guards and reproduce unchanged. The host FIFO model has a fixture-specific
iteration cap of 1,024 to cover complete direct page transfer; old fixtures keep
their cap of 128.

## Mapping selection and sequential state

For a non-first page, the writer uses the existing mapped physical block. Before
calling NAND, it compares the target page index against the flag's next-page
value and updates that flag to the following page. An authored next-page value
3 rejects page 1 with a sequence-error log and `-2`, after scratch/OOB preparation
but before any NAND command.

For the first page, actual selector `0x80c01a5a` erases an existing suitable
mapped block, or scans the authored eight-byte flags array for a free `0xfe`
entry. A free-block fixture selects block 5, executes original erase/program and
publishes mapping entry 5 only after successful program return. No-free-block
selection logs map-full and returns `-2` without issuing NAND commands.

The flags/mapping/counters are supplied ready state, not reconstruction of real
flash metadata. Counters and complete allocator invariants are not established
by these bounded cases.

## Logical erase initializes a block through the writer

Original EFTL erase callback `0x80c232a0` requires block-aligned addresses. The
bounded positive-offset remainder helper is supplied and checks the original
131,072-byte divisor. Aligned zero size returns zero; unaligned zero size still
fails alignment.

For each touched logical block, the callback calls the actual page writer with
a one-byte `0xff` source. That path selects/erases a physical block, prepares a
data page filled with `0xff` and **valid EFTL OOB metadata**, then programs it.
Logical erase therefore does more than submit a raw NAND erase command.

A 131,104-byte request crosses two blocks and executes two erase/program
sequences; the callback returns 131,104. Final scratch contains the second
block's EFTL record. No-free-block writer failure `-2` becomes `-14` in this
erase callback, then crosses the original upper storage erase-error log.

These results describe original software control and payload preparation. They
do not demonstrate erased physical cells, a valid persisted map or atomicity.

## Rewrite is an original alias of program

The original rewrite callback at `0x80c23384` consists of four bytes
`6f f0 3f fb`: a branch to the program callback at `0x80c23336`. Original branch
execution reaches the same EFTL writer. A metadata-only call/return annotation
makes the fresh export show this alias; execution reports before and after that
annotation reproduce byte for byte.

The rewrite and program fixtures have identical observed actions and final state.
For an existing non-first page, rewrite adds no erase or replacement transaction.
Its callback name does not establish overwrite support or atomic replacement.
An explicitly authored missing rewrite pointer returns `-1` at the upper
wrapper without entering EFTL.

## Failures and state ordering

Upper null handle/input cases stop at original assertion owner/line pairs.
Owner, range, alignment, sequence and no-free failures execute their original
returns/logs. Bounds clipping can yield an unaligned backend request, which the
writer rejects. Program alignment is checked before zero-length completion too.

The next-page flag is advanced **before** the NAND callback acquires its mutex
or submits commands. Acquisition, release, direct-FIFO and DMA-wait assertion
fixtures preserve that advanced flag while the callback aborts. Caller input
and prior mapping remain checked. This ordering does not establish a production
data race: higher caller serialization and complete concurrency remain unknown.

Readback, program/erase returned-status failures entering bad-mark/relocation,
allocation-failure repair and complete rewrite/repair atomicity are explicitly
deferred. Such paths are excluded by the bounded fixture contract rather than
replaced with successful helper returns. The selected assertion cases stop at
actual bus/mutex assertions before those repair paths execute.

## Evidence boundary and remaining work

The runner compares scratch, full private-buffer, registry/owner/backend,
EFTL context/map/flags and caller hashes/bytes, guards external bounds, and
checks ABI canaries on normal return. Generic copy/fill and the bounded
nonnegative remainder helper are supplied; original intermediate write/erase/
packing/selection and NAND/HAL code execute. Each case has a 1,500,000-step cap.

Remaining work includes readback and relocation/bad marking, broader allocator
and map reconstruction, repair/write atomicity, full concurrency/cache/IRQ
behavior and physical chip/geometry/BBT/ECC/data/persistence corroboration.
Device-specific backup/restoration and standalone boot remain unresolved.
