# Bad marking, erase reselection and zero-prefix EFTL relocation

All **22 native cases** pass in **801,098 instruction/service steps**
(maximum **112,664**). Original repair `0x80c01b6e`, bad-mark adapter and NAND
marker routine execute through upper/EFTL/NAND/bus/QSPI. The prior **501 native
cases reproduce byte for byte**. Sixteen new host checks bring the suite to
**1,409 passing tests**. Observations and 80 code/export plus twelve data hashes
are in [eftl-repair-stack.json](eftl-repair-stack.json).

No device was accessed. Ready maps/flags/counters, statuses, cache bytes,
RTOS/peripheral results and leaf services are authored. Physical marking,
successful persistent relocation and atomicity remain unverified.

## Original marker writes and returned failures

Actual NAND marker routine `0x80c29126` programs two zero bytes into the spare
area of each of a block's first three pages. Each iteration executes original
page remapping, write-enable, cache write, program-execute and status polling.
The selected normal fixtures capture six zero bytes in direct FIFO writes.

For EFTL block 3 and base block 8, marker input pages are 704, 705 and 706. The
actual authored BBT then maps them to physical-address arithmetic 896–898. The
generic adapter reaches original partition ioctl 11 and context/mutex wrappers;
the fast adapter calls the original NAND marker directly. No physical OOB
modification or fitted-chip bad-block convention is established.

An authored program-failure status stops the marker after its first attempted
page and returns `-2` after logging. Generic ioctl adds its chip-error log.
However, the original EFTL marking adapter returns void: repair continues to
set the old block's RAM flag to 1 without propagating that marking failure.
Both generic and fast paths are covered.

## No-free and selected-block results

Repair first sets the old block's low bad flag, then invokes original free-block
selection. If no free block exists, it still attempts to mark the old block
before returning `-1`. The existing RAM mapping is not cleared. The connected
writer translates that outcome into its original `-2` error.

With a free block and no earlier pages to migrate, repair erases/selects block
5, retires/marks block 3 and returns 5. A direct repair call does **not** publish
mapping entry 5 or program the pending current page. Its caller must continue.
The selected block's flag is zero after erase and the old mapping still names 3.

Even if NAND marking of block 3 returns an error, repair can still return 5.
This proves return/control behavior under authored statuses, not that physical
bad marking or relocation succeeded.

## Connected writer retry and erase reselection

A first-page program-failure fixture enters real repair, selects block 5,
marks the old block, retries the pending 2,112-byte page and publishes mapping
5 only after that retry succeeds. The normal generic path also executes actual
TX DMA control; fast paths capture direct FIFO bytes. Old/new final flags are
1 and 2 respectively. Rewrite and logical erase reach the same selected repair
path through their original callbacks.

An erase-failure fixture executes original find/mark/reselect logic before
programming a different free block. Failed marking does not prevent reselection.
If both candidates fail erase, flags become bad, no replacement map is published
and the writer returns `-2`. Marker program status checks bit `0x08`, while erase
checks `0x04`; the authored all-erase-failure case exercises that distinction.

Enabled readback I/O error reaches repair through the original negative return
path, rather than metadata-check rejection. In the selected no-free case it
marks the old block and fails the write; checksum validation is not reached.
Checksum/tag failures covered by the prior pass instead return directly without
entering this relocation branch.

## Prefix allocation failure and ordering

If earlier pages need migrating, repair selects/erases a new block before
allocating a 2,112-byte temporary buffer. The supplied allocator returns zero
in these explicit failure fixtures. Execution stops at the original allocation
assertion; no heap success is substituted.

At that stop the old RAM flag is already marked bad, the selected new block is
erased/flag-zero, and the mapping still names the old block. Cleanup's physical
bad-mark operation has not run yet. A writer-driven example retains old flag 5
(advanced page index plus bad bit), while direct repair with its different
initial progress retains flag 1. These are selected ordering observations, not
proof of a production race, leak or recoverable persistent state.

Successful prefix copying, allocation/free lifetime, recursive migration and
broader readback/repair/metadata atomicity remain deferred and are excluded by
the fixture contract. The selected successful relocation has **zero preceding
pages**, so it does not stand in for those larger paths.

The subsequent [prefix migration pass](EFTL_PREFIX_STACK.md) covers selected
one/two-page copies, supplied heap lifetime and one recursive relocation. The
limitations above describe this earlier pass; complete atomicity remains open.

## Evidence boundary

Normal-return ABI and caller, scratch/private-buffer, registry/owner/backend,
context/map/flag and BBT guards/state are checked. Original intermediate marker,
repair, selection, page and bus/HAL code execute. Allocation is supplied only as
failure; no actual allocator body, NAND cells or physical DMA movement execute.

Broader map/BBT provenance, full concurrency/cache/IRQ behavior, persistent data
and device-specific backup/restoration/standalone boot remain open.
