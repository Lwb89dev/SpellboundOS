# EFTL prefix migration, temporary-buffer lifetime and recursive relocation

All **20 native cases** pass in **3,211,729 instruction/service steps**
(maximum **323,829**, `prefix_recursive`). Original repair `0x80c01b6e`
copies one or two preceding pages through actual NAND/QSPI paths, with supplied
allocation/copy/free services. The previous **523 native cases reproduce byte
for byte**. Eighteen new host checks bring the suite to **1,427 passing tests**.
Eighty code/export and twelve data hashes, native observations and explicit
limitations are in [eftl-prefix-stack.json](eftl-prefix-stack.json).

No device was accessed. Source cache pages, ready maps/flags, peripheral statuses,
RTOS results and leaf services are authored. These cases establish selected
control/data-flow contracts, not successful migration of physical NAND contents.

## Saving the pending page and publishing the copied prefix

Repair first marks the old block's RAM flag bad and selects/erases a replacement.
For a nonempty prefix, it allocates 2,112 bytes and saves the current pending
page, including its spare area, before reading earlier pages into shared scratch.
Each preceding page is read from the old block and programmed to the same page
index in the replacement. Direct FIFO cases capture the distinct authored page
payloads and their order.

After every selected prefix page succeeds, repair sets the replacement flag to
`prefix_count << 1` plus its low bit and publishes the logical-to-physical RAM
mapping. It then marks/retires the old block, restores the saved pending page and
frees the temporary buffer. A standalone repair call returns the replacement
block without writing the pending page. The connected writer retries that page
after repair returns and advances the new block's progress. Selected upper
program and rewrite entries produce the same observations.

These tests cover prefixes of one and two pages, not full-block migration. RAM
publication and captured commands do not prove persistent ordering or recovery
after power loss.

## Prefix validation differs from ordinary write readback

Original OOB extraction supplies the logical block ID; repair compares that ID
with the requested logical block. A mismatch returns `-3` from direct repair,
while the connected writer returns `-2`. In the observed prefix-copy path,
repair does **not** perform ordinary readback's tag/checksum validation: an
authored matching logical ID with a bad tag and checksum is copied successfully.

The earlier [readback pass](EFTL_READBACK_STACK.md) found the complementary
selected behavior: ordinary write readback checks tag/checksum but accepts a
different logical block ID. Neither observation establishes how such records
arise on a real device.

## Failure cleanup and recursion

An authored prefix-read failure returns `-2` from repair. Read failure or logical
ID mismatch retires the old block and restores/frees the pending-page buffer
without publishing a new mapping. A mismatch on the second page leaves an
already partly programmed destination with flag zero and the old mapping still
present. No physical erasure or persistence guarantee is inferred.

A prefix-program failure takes a different branch. Repair restores and frees
the pending-page buffer **before** marking the failed replacement and recursively
calling repair on the original old block and prefix. With a second free block,
the selected recursive attempt copies the prefix, publishes that block, cleans
up its own buffer and lets the writer retry the pending page. Both allocations
save the same pending-page bytes; both are freed once. Without a second free
block, the selected upper call returns `-2`, retains its old mapping and leaves
no live supplied heap allocation.

First and recursive allocation failures stop at the original assertion
(`owner=0x80c3436c`, line `0xa3`). A bus assertion during the first prefix read
instead stops with its saved heap buffer still live. That is an assertion-stop
snapshot, not evidence of an unrecoverable production leak. Guards around each
supplied heap slot and the ordinary scratch/caller/private/context/map/flag
backings are checked, as are normal-return ABI registers.

## DMA and allocator boundaries

Generic paths execute original DMA control and copy the full 2,112-byte private
RX buffer into scratch. This harness does not simulate hardware DMA movement;
the private buffer can therefore contain stale data from the pending-page TX.
The selected generic fixtures pass the logical-ID check on those bytes. They
do not prove that physical source pages were fetched or copied accurately.
Direct FIFO cases separately check distinct source pages and their order.

Allocation/copy/free bodies are supplied at original call boundaries. The
allocator gives guarded, bounded storage; freed backing is retained only for
final hashes and lifetime checks. Original allocation/copy/free call sites,
repair branches, page adapters, NAND commands, bus and HAL execute. No production
allocator body, physical NAND cells, concurrent IRQ/cache effects or board
timing is modeled.

## Reproduction and next work

Generate the vectors from the locally held OTA and run the existing Ghidra
runner against the startup-aware `boot-runtime.elf` project:

```sh
python3 analysis_scripts/eftl_prefix_stack.py \
  --vectors-output firmware/eftl-prefix-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript ValidateQspiHal.java \
  firmware/eftl-prefix-stack-vectors.json firmware/eftl-prefix-stack-validation.json

python3 analysis_scripts/eftl_prefix_stack.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-eftl-prefix-stack \
  --vectors firmware/eftl-prefix-stack-vectors.json \
  --validation firmware/eftl-prefix-stack-validation.json
```

The export directory is generated with `DecompileWithLogger.java`, logger
`0x80c1cd7a` and `TARGETS` from `analysis_scripts.eftl_prefix_stack`.
Firmware bytes and exports remain local, outside version control.

Broader migration, combined enabled-readback/repair behavior, repeated failures,
map/BBT reconstruction, complete persistence/atomicity and concurrency remain
open. Device-specific backup/restoration and a viable standalone boot path
remain prerequisites for hardware writes; additional emulator cases cannot
close those gates.

The subsequent [combined repair/readback pass](EFTL_REPAIR_READBACK.md) covers
selected enabled-readback and repeated-relocation branches, including OOB
scratch reuse and failures after prefix publication. Broader persistence and
atomicity remain open.
