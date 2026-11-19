# Original main tail-marker scan and record reads through QSPI

All **13 native cases** pass in **285,080 instruction/service steps** (maximum
**49,444**, final reserved tail pair). Original main bad-marker checker
`0x702d7168` now joins BBT tail selection and [actual recovery record reads](MAIN_NAND_BBT_RECORD_READ.md)
through original page remapping, load/status/cache and direct QSPI FIFO. The path
continues to original probe/UID/root publication, geometry, UID export and
selected mapping consumers. [main-nand-bbt-marker-read.json](main-nand-bbt-marker-read.json)
records **63 code/export and 67 data hashes**, observations and limitations.

Marker/record/status/FIFO/timer/peripheral bytes are authored. Repair erase/write,
bounded library, power/pin/RTOS/BSP/heap/PM services remain supplied. Three good
markers do not prove a physically good block, and simulated repair callbacks do
not establish persistent media state.

## Actual three-page marker policy

For each selected original block, the checker reads two bytes at column 2048
on each of its first three pages. Every page goes through actual main reader,
load, status and direct x4 cache/FIFO. A successful block check requires all
three reads to succeed and each byte pair's AND to equal `0xff`.

The ordinary immediate pair at blocks 1023/1022 therefore performs six marker
page reads plus one 140-byte record read: **seven actual reads and 152 cache
bytes**. Backup verification/repair reread raises this to nine reads and 432
cache bytes. Supplied record/marker helper returns are absent from this scope.

The authored marker-page overrides can make a block fail on its second or third
page. Original code then selects the next usable tail blocks; partial marker
work remains in the observed trace. Before a primary exists, the original
selector can check a rejected candidate twice, repeating its partial page work.
An ECC rejection returns `-101` through the actual reader after payload delivery;
the marker checker logs and propagates that status.

| Selected case | Actual original scan consequence |
| --- | --- |
| Third/second marker bad in block 1023 | Candidate is checked twice while primary is missing; six/four reads there, then pair 1022/1021 and one record read (13/11 reads total) |
| ECC failure on both initial checks | Negative statuses propagated; pair 1022/1021 selected afterward |
| First check ECC failure, second check succeeds | Primary remains zero, backup becomes 1023; original selector asserts despite authored usable later blocks |
| Final reserved pair 1009/1008 | 30 checker calls and 35 page reads including record; recovery succeeds |
| No good blocks | 32 checker/page calls; original selector rechecks candidates while no primary exists; stops at assertion |
| Only block 1023 good | Three reads on that block plus 15 failing candidates; 18 reads total; stops at assertion |
| No valid records after good markers | Return one; outer probe registers object with inactive BBT |

No-good/one-good and transient-ECC cases reach original owner `0x70a30e6c`, line 196, before record
verification, object allocation or UID export. UID acquisition has already
completed. The transient-ECC case performs four actual reads: one failed first
check and three successful pages on its second check. This establishes a
software selection counterexample, not an observed physical failure. Assertions
stop before their bodies and claim no normal return ABI.

## Transport failures retain completed earlier work

Marker load timeout reaches transport owner `0x70a1bc8c`, line 294, before cache
data. Marker cache completion timeout instead reaches line 305 after two `0xff`
bytes have been delivered, before the checker can accept them. A record-cache
readiness timeout after the two successful marker checks preserves six completed
marker reads and 12 received marker bytes, but no record data/publication.

Snapshots separate checker/page/record counts, actual completed status reads,
cache requests, cumulative cache bytes and the last read's delivered FIFO bytes.
The BBT/UID adjacency guards remain intact; UID source and DMA initialization
records are unchanged by these forced-direct reads. No DMA setup/wait, IRQ or
real cache coherency is inferred.

## Reproduction and continuation

Use the project/seed/export procedure in
[MAIN_NAND_BBT_RECORD_READ.md](MAIN_NAND_BBT_RECORD_READ.md), substituting:

```sh
python3 analysis_scripts/main_nand_bbt_read.py --scope markers \
  --vectors-output firmware/main-nand-bbt-marker-read-vectors.json
```

Run `ValidateMainNandBbtRead.java` with
`firmware/main-nand-bbt-marker-read-vectors.json` and
`firmware/main-nand-bbt-marker-read-validation.json`, then reproduce evidence:

```sh
python3 analysis_scripts/main_nand_bbt_read.py firmware/bip6-4.6.0.3.zip \
  --scope markers --decompiled firmware/decompiled/runtime-main-nand-bbt-read \
  --vectors firmware/main-nand-bbt-marker-read-vectors.json \
  --validation firmware/main-nand-bbt-marker-read-validation.json
```

The 200,000-step bound covers the complete selected reserved-tail scans. Both
scopes share exports and the existing 1024-byte aggregate FIFO trace guard;
the final-pair case receives 284 total FIFO bytes. Previous bounds
and fixed configurations remain unchanged. All **495 preceding main native
cases reproduce byte for byte**. The two scopes' **28 host checks** join the
passing **1,936-test suite**.

Next work is actual main repair erase/program through the lower transport,
asynchronous/private DMA reads, full busy exhaustion, wider geometries and
further media/PM consumers. Physical marker/record provenance, persistence,
electrical/timing/IRQ/cache/coherency validation, safe backup/restoration and
standalone boot remain separate open requirements.
