# Combined EFTL prefix repair and enabled write readback

All **20 native cases** pass in **4,426,280 instruction/service steps**
(maximum **381,917**, `combined_retry_io_relocate`). The unchanged original-byte
runner now connects prefix migration with enabled write readback, repeated
outer relocation and recursive prefix repair. Sixteen additional host checks
bring the suite to **1,443 passing tests**. Observations and the same eighty
code/export and twelve data hashes are in
[eftl-repair-readback.json](eftl-repair-readback.json).

This extends [prefix migration](EFTL_PREFIX_STACK.md) and
[ordinary readback](EFTL_READBACK_STACK.md). No device was accessed. FIFO page/OOB
bytes, status sequences, ready maps/flags, guarded heap/copy/free and other leaf
services are authored. Source reads and final readback are independent supplied
inputs, not a NAND-cell simulation or proof of physical persistence.

## Failure after prefix publication does not roll back the RAM map

A failed current-page program can enter real repair, copy the prefix, publish
replacement block 5 and return to the writer. The writer retries the pending
page and performs enabled readback. If the authored final tag/checksum is bad,
the upper call returns `-2`, while the map still names 5 and its flag records
progress through the retried page. The prefix buffer has already been freed.

This differs from first-page allocation followed by failed readback in the
earlier pass: that path had no prefix mapping to publish before the final check.
The combined cases establish selected RAM ordering, not a general atomicity
guarantee or a recoverable persistent layout.

The final check still accepts an authored different logical ID with a valid tag
and checksum. A two-page prefix advances the target flag to 6; selected rewrite
and program entries produce the same observations.

## Failed readback can change the pending OOB that repair saves

The original OOB read uses the spare area of the shared pending-page scratch.
Under the selected ECC-error status it still receives authored cache bytes,
then reports an I/O failure. Repair subsequently saves the whole 2,112-byte
scratch, including that newly received spare area, and restores it after copying
the prefix. The pending-page retry therefore transmits those spare bytes.

Two direct FIFO examples supply logical ID 7 or a bad tag during this initial
failed readback. Both captured retries contain those exact OOB bytes; the data
area still contains the original pending payload. Saved-heap hashes distinguish
the altered spare area. A separately supplied valid final readback lets these
fixtures return 32. That final input is independent of the transmitted bytes:
the cases demonstrate scratch reuse and retry data flow, not a physical device
accepting or persisting inconsistent records.

After successful final readback, scratch can contain the final supplied OOB
instead of the OOB captured in the freed save buffer. Both hashes are recorded;
they are not interchangeable evidence of what was programmed.

## Retry failures and a second relocation

If readback of the retried page returns an I/O error, the writer enters repair
again. With no free block, the selected call returns `-2`, retains mapping 5 and
sets block 5's bad flag. A retry-program error has the same selected final map
and flag outcome. Neither path clears the previously published map.

With another free block, the second outer repair copies a new authored prefix,
publishes block 6 and retries the pending page again. Both heap buffers are
freed once. For the readback-error case their saved hashes differ because the
intervening OOB read changed scratch; for the program-error case they match.

Separate recursive-prefix failure coverage reaches the same final readback
through one outer repair invocation and an inner recursive attempt. This is
distinct from two outer repairs after a pending-page retry failure. The selected
allocation failure and final-readback bus assertion also preserve different
states: the latter occurs after prefix publication and temporary-buffer free.

## DMA boundary and remaining work

The generic path executes original TX/RX DMA control, but this harness performs
no physical DMA movement. Prefix RX copies the stale private TX buffer; later
64-byte OOB RX copies its first 64 bytes, not the physical spare area. This
selected generic fixture fails the final metadata check with map 5 retained.
The IRQ-context direct FIFO case succeeds with the supplied page/OOB inputs.
Neither result predicts the corresponding device transfer.

Normal-return ABI, heap lifetimes and existing caller/scratch/private/context/
map/flag guards remain checked. The Java runner and original eighty guarded
code ranges are unchanged from the prefix pass, whose regression run reproduced
523 earlier native cases exactly.

Regenerate vectors with:

```sh
python3 analysis_scripts/eftl_repair_readback.py \
  --vectors-output firmware/eftl-repair-readback-vectors.json
```

Use the [prefix pass's Ghidra command](EFTL_PREFIX_STACK.md), replacing its vector
and validation filenames with `eftl-repair-readback-vectors.json` and
`eftl-repair-readback-validation.json`. Its existing export directory is reused
because neither code bytes nor export targets changed. Verify and emit evidence:

```sh
python3 analysis_scripts/eftl_repair_readback.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-eftl-prefix-stack \
  --vectors firmware/eftl-repair-readback-vectors.json \
  --validation firmware/eftl-repair-readback-validation.json
```

Larger migrations, further failure/metadata branches, map/BBT reconstruction,
physical correction/data, persistence across reset, power-loss behavior,
concurrency/coherency and complete board integration remain open. Device-specific
backup/restoration and standalone boot are still major feasibility gates.
