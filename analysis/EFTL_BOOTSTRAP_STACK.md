# EFTL initialization and readiness through original NAND/QSPI

All **23 native cases** pass in **648,613 instruction/service steps**
(maximum **83,438**, `bootstrap_force_format`). Original initializer
`0x80c02298`, geometry `0x80c02460`, partition lookup, format, scan/retry and
lazy wrapper `0x80c231d6` now execute together through original NAND/BBT/QSPI.
Nineteen host checks bring the suite to **1,480 passing tests**. Eighty-nine
code/export and twelve data hashes and complete observations are in
[eftl-bootstrap-stack.json](eftl-bootstrap-stack.json).

All **585 previous native cases reproduce byte for byte** with the extended
runner and initializer metadata.

This connects [the earlier initializer](EFTL_INITIALIZATION_AND_GEOMETRY.md)
to [the lower scan stack](EFTL_SCAN_STACK.md). No device was accessed. The chip
descriptor is the selected original OTA descriptor, but its ready binding,
one-row NAND registry and eight-block partition are authored. Heap slots, clocks,
string/cache/copy/RTOS services, FIFO records and status sequences are supplied.
No physical erase, DMA movement, persistence or complete device boot is modeled.

## Actual lookup and geometry with a bounded partition

The authored registry contains one `eftl` row with backend `nand`, offset
`0x100000` and span `0x100000`. Original registry traversal/lookup executes;
string comparison is supplied at its leaf boundary. Successful lookup executes
the original driver ioctls for raw page size, page count and pages per block.
Geometry then executes original partition ioctls, including spare/ECC fields.
The collector is not fed a replacement geometry result.

The original descriptor supplies 2,048 data bytes, 64 spare bytes, 64 pages per
block, ECC total/unit 16/4 and positions 4/20/36/52. The authored partition extent
limits the collector to 512 pages and eight blocks, with base page 512. These
are fixture-derived context values, not corroboration of the physical partition
map or actual flash capacity.

Direct geometry with an existing handle skips lookup. An absent authored
registry row reaches the supplied empty board-property fallback and stops at
the original missing-handle assertion (`owner=0x80c34480`, line `0x1a`).

## Reset, allocations and forced cleanup

Normal initialization clears the complete 64-byte context before collecting
geometry. That clears the fast-path flag. It subsequently sets readback byte +5
to 1; the connected scan therefore uses the original generic NAND route. The
IRQ-context fixtures reach direct FIFO, while the normal-context fixture
executes DMA control for its OOB reads.

Original allocation/fill call sites request exactly:

| Role | Requested bytes | Supplied guarded slot |
| --- | --- | --- |
| Flags | 8 | `0x8130c000` |
| Mapping | 16 | `0x81309100` |
| Page and spare scratch | 2,112 | `0x8130a000` |

The allocator body is supplied. Slots permit a marked forced initialization to
free its three old allocations, reset context, run actual format and reuse the
same addresses for three new allocations. Old hashes are captured when freed;
new hashes come from final live backing. This establishes call ordering and
bounded ownership in this allocator model, not production allocator internals.

An existing `a5` marker with no force skips initialization and preserves the
old allocations. A successful second ordinary call also uses this guard without
extra lookup, clock, allocation or scan effects.

Each supplied allocation failure reaches the next original fill call with a
null destination. Execution stops there before writing address zero. Earlier
successful allocations remain live, the failed pointer field is zero, and no
scan has started. These are stopped snapshots without normal-return ABI claims.

## Scan retry, format and partial failure

The normal fixture reconstructs logical 0/1 in blocks 0/1 and counts six free
blocks. Original first-scan return 1 triggers zero/ff fills of flags/maps and a
reset of all three counters before repair scan. An all-reserved first pass
followed by successful erase/OOB inputs finishes with eight free blocks, not
accumulated reserved counts from both passes.

Forced format kind zero executes original marker checks before attempting
erase; kind one attempts all eight erases. The selected ready-status erase
failures are ignored by the original format loop, and subsequent authored OOB
records can still produce successful initialization. Those records are an
independent stream: they do not represent actual data retained after erase.

An OOB scan error returns `-1` from eager initialization with marker clear and
all three supplied allocations still live. With an initially clear global ready
byte, the lazy wrapper leaves it clear and preserves the capacity word. The
eager initializer itself does not clear a preexisting global ready byte: a forced
reinitialization can fail its scan with context marker zero while global ready
remains 1 and the capacity word remains unchanged. Its old buffers were freed
and three new allocations remain live. This is a selected normal-return path,
not a claim that the resulting state occurs on the watch. Repeated failing
attempts with distinct live heap generations remain outside this slot contract.

The connected duplicate case still keeps the first logical mapping. The second
copy is not counted free or used; six free plus one used does not account for
all eight candidates. This reconstructs selected policy, not media age or
persistent recovery after a real interrupted relocation.

## Context marker, global readiness and capacity

Eager success sets context marker `a5` but does not set global readiness. The
lazy wrapper publishes block size and capacity separately after nonnegative
initialization. The selected results are:

| Authored lazy case | Context marker | Free/used/reserved | Ready | Published capacity |
| --- | --- | --- | --- | --- |
| Two records, six empty blocks | `a5` | 6/2/0 | 1 | 1,048,576 |
| One marked, one used, six empty | `a5` | 6/1/1 | 1 | 917,504 |
| Repair completes with every erase failing | `a5` | 0/0/8 | 1 | 0 |
| First OOB read fails | 0 | 0/0/0 | 0 | Initial `0x7fffffff` retained |
| Forced eager reinitialization fails while already ready | 0 | 0/0/0 | 1 retained | Initial `0x7fffffff` retained |

Block size is 131,072 in these fixtures. Readiness does not guarantee positive
usable capacity. An independently supplied ready byte also skips the wrapper
without validating the context marker. That guard fixture deliberately authors
inconsistent initial state; it is not an observed device fault.

## DMA and evidence boundary

The normal-context fixture copies the initialized private RX buffer because the
harness does not simulate hardware DMA movement. It consequently counts eight
free blocks rather than the two valid records seen over IRQ-context FIFO. This
is a model boundary, not evidence that the device loses those records.

All original code ranges are SHA-256 guarded. Normal returns check ABI; caller,
context/map/flag/scratch/private/registry/descriptor/BBT guards and heap lifetime
are checked. Logger, clock/conversion, allocator, string, copy/cache and RTOS
leaf services remain supplied. Registry population/probing/BBT startup and the
physical boot chain are not executed as part of this EFTL initialization.

## Reproduction

```sh
python3 analysis_scripts/eftl_bootstrap_stack.py \
  --vectors-output firmware/eftl-bootstrap-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedEftlInitialize.java \
  -postScript ValidateQspiHal.java firmware/eftl-bootstrap-stack-vectors.json \
  firmware/eftl-bootstrap-stack-validation.json

python3 analysis_scripts/eftl_bootstrap_stack.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-eftl-bootstrap-stack \
  --vectors firmware/eftl-bootstrap-stack-vectors.json \
  --validation firmware/eftl-bootstrap-stack-validation.json
```

The startup-aware project already has the [scan seed](EFTL_SCAN_STACK.md).
Generate exports with `DecompileWithLogger.java`, logger `0x80c1cd7a` and
`TARGETS` from `analysis_scripts.eftl_bootstrap_stack`. Firmware and exports
remain local and ignored by version control.

Remaining work includes broader registry/probe/BBT startup and partitions,
repeated failing initialization with separate heap generations, further format
and malformed-input branches, persistent write/retire/reboot reconstruction,
concurrency/coherency, physical corroboration, backup/restoration and standalone
boot. This pass closes the selected initialization connection, not those gates.
