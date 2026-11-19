# Actual main recovery record reads through NAND and QSPI

All **14 native cases** pass in **189,370 instruction/service steps** (maximum
**19,562**, backup reread ECC rejection). Original main BBT verifier/resume/CRC
now execute their own 140-byte page reads through actual main remap, load, busy,
direct x4 cache and QSPI FIFO, inside original first-chip probe/UID/root and
later geometry/UID-export/mapping consumers.
[main-nand-bbt-record-read.json](main-nand-bbt-record-read.json) records **63
code/export and 67 data hashes**, observations and limitations.

Marker checks and repair erase/write remain supplied in this scope. The next
[marker-read scope](MAIN_NAND_BBT_MARKER_READ.md) executes the actual checker too.
FIFO records/status/UID/ID/timers/peripherals and bounded library, power/pin/RTOS/
heap/BSP/PM services remain authored or supplied. No physical record, persistent
repair, actual elapsed timing or safe device-write route is established.

## From recovery callback to original reader

The earlier [page-read scope](MAIN_NAND_PAGE_READ.md) intercepted recovery's own
reader calls. Here the original verifier's page read and resume's backup reread
execute the original reader body at `0x702d6bbe`. Destinations stay in the original
nested stack frames, with complete span checks. The actual direct cache packet
requests 140 bytes at column zero, x4 data and two address bytes, forced direct.

The initial table is inactive during primary/backup verification and explicitly
cleared again for repair reread. Actual remapping therefore passes the selected
tail page through rather than applying an already accepted table to its own
backup. First-chip geometry and original descriptors remain unchanged. FIFO
responses supply the authored record for that physical block. The original CRC
then checks the delivered entry bytes against the record header.

Primary success performs one actual record read. Backup recovery performs three:
primary attempt, backup verification and backup reread, for 420 cache bytes.
The supplied repair callbacks receive the reread's actual payload and observe
RAM magic cleared. Empty records, missing records, bad CRC and busy-then-ready
status also execute through the original transport.

## Actual lower errors and recovery decisions

| Authored input | Actual consequence |
| --- | --- |
| Primary status ECC rejection | Reader still receives cache bytes, returns `-101`; verifier skips that record and tries backup |
| Backup reread ECC rejection | Full payload delivered, then `-101`; repair erase/write skipped, RAM magic restored, recovery returns zero |
| Supplied repair erase/write failure | Actual reads complete; recovery logs failure, retains active RAM table and returns zero |
| Neither delivered record accepted | Recovery returns one; outer probe registers object with inactive BBT |
| Load completion timeout | Actual transport assertion line 294 before status/cache |
| Status/cache readiness timeout | Actual transport assertion line 305 before data from that FIFO request |
| Cache completion timeout | Assertion line 305 after all 140 bytes have been delivered; no CRC/publication or normal recovery return |

Assertions use owner `0x70a1bc8c` and stop before assertion/recovery bodies.
Read errors are produced by original page/status/transport code, rather than
injected arbitrary page-helper returns. The new contract rejects supplied
`read_status`/reread error fields. The captured last FIFO bytes distinguish data
delivery from successful acceptance; a timeout does not imply publication.

The harness routes transport logger formats past the older BBT-only logger
service while preserving original transport assertions. Existing scripts and
fixed configurations remain unchanged. This changes harness interception only,
not firmware instructions or emulator semantics.

## Reproduction and regression

Use the seeded startup-aware main project through the prior BBT/remap/page-read
scopes. `SeedMainNandBbtRead.java` checks the original marker-checker byte hash and
updates metadata only. Both new scopes share the same guarded export corpus.

```sh
python3 analysis_scripts/main_nand_bbt_read.py --scope records \
  --vectors-output firmware/main-nand-bbt-record-read-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandBbtRead.java \
  -postScript ValidateMainNandBbtRead.java \
  firmware/main-nand-bbt-record-read-vectors.json firmware/main-nand-bbt-record-read-validation.json

python3 analysis_scripts/main_nand_bbt_read.py firmware/bip6-4.6.0.3.zip \
  --scope records --decompiled firmware/decompiled/runtime-main-nand-bbt-read \
  --vectors firmware/main-nand-bbt-record-read-vectors.json \
  --validation firmware/main-nand-bbt-record-read-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_bbt_read` using
`DecompileWithLogger.java`, logger `0x702b38a2`. Firmware and exports remain local.
The new scope allows **200,000 steps per case**, shared with the complete marker
scan scope; previous scope bounds remain unchanged. The existing 1024-byte
aggregate FIFO trace guard remains sufficient and is not a physical FIFO size.
All **495 preceding main native cases reproduce byte for byte** after the new
metadata seed. Both scopes add **28 host checks** to the **1,936-test passing
suite**.

Actual marker IO is covered next. The later [erase](MAIN_NAND_BBT_ERASE.md) and
[program](MAIN_NAND_BBT_PROGRAM.md) scopes execute repair callbacks through the
original lower transport. Asynchronous/private DMA reads, full busy exhaustion,
wider geometries/media consumers and physical
IRQ/cache/coherency/contents/persistence/restoration/boot remain open.
