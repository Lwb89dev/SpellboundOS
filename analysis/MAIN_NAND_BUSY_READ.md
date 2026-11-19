# Complete main NAND read busy boundaries inside BBT recovery

All **five native cases** pass in **3,759,349 instruction/service steps** (maximum
**754,985**, penultimate-poll ECC followed by backup rejection). Original main
busy `0x702d6470` executes complete 2000-poll workloads through actual feature/
bus/QSPI FIFO inside the [connected BBT recovery path](MAIN_NAND_BBT_PROGRAM.md).
[main-nand-busy-read.json](main-nand-busy-read.json) records **69 code/export and
67 data hashes**, counted trace digests, complete outer observations and limits.

All firmware instructions and selected exports match the preceding repair scope.
Status/FIFO/timer/peripheral inputs and library/pin/power/RTOS/BSP/heap/PM services
remain authored or supplied. Requested delay 5 is recorded on each poll without
establishing elapsed time or physical NAND readiness.

## Limit check precedes readiness and ECC publication

The original helper initializes its caller's output byte to `0xff`. Each poll
requests a wait, reads the original status register and checks its poll limit
**before** examining the busy bit and publishing the byte. On the 2000th poll it
logs a timeout and returns the feature helper's zero result. The caller's output
remains `0xff`, including when the last FIFO byte is ready or indicates ECC.

The selected target is the primary-record read after six actual marker reads.
The original UID and other marker/record busy calls still execute ordinary
one-poll windows; their event hashes are checked as well.

| Authored target status stream | Actual busy output / BBT consequence |
| --- | --- |
| Busy for all 2000 reads | Zero helper return, output `0xff`; page reader still receives and accepts the authored valid primary record |
| Ready on read 2000 | Final zero byte is discarded; output remains `0xff`, same outer acceptance |
| Ready on read 1999 | Output zero is published; no timeout log; ordinary acceptance |
| ECC status 32 on read 2000 | ECC byte is discarded; output `0xff` does not match the descriptor's ECC-reject value; record is accepted |
| ECC status 32 on read 1999 | ECC byte is published; original retry rejects the unsupported family, page returns `-101`; with invalid backup, outer probe still registers an inactive BBT |

Different last-poll FIFO values produce different native trace hashes even when
the published output and outer success are identical. The penultimate-ECC case
executes the actual second record read and ends with real no-table return one.
No arbitrary page-helper success or error return is substituted.

These are bounded software counterexamples over authored records/status. They
do not establish that a physical still-busy device would deliver those bytes or
that a real firmware run has encountered this condition.

## Counted full-window trace

The selected original NAND/bus/HAL instructions execute on every poll; existing
leaf services remain supplied. Only storage of busy-window trace strings changes: the native harness and separate host model
stream each exact UTF-8 event followed by one LF byte into SHA-256 and count
its events. Outside each window, ordinary actions and complete state snapshots
remain in the evidence. A compact action has this form:

```text
busy_window:kind:ordinal:limit:polls:output_byte:return_value:event_count:sha256
```

The selected full 2000-poll window has 36,001 events, including the timeout log.
The 1999-poll ready/ECC windows have 35,982 events. Chunking the stream at feature
calls does not change event order or hashing. The digest is checked against the
host model; raw event strings inside each window are not retained in JSON and
cannot be recovered from the hash alone. No loop iterations are shortcut or patched.

The new per-case bound is **4,000,000 instruction/service steps**. Its
**8192-byte aggregate RX trace guard** covers the complete polling workload;
individual status packets remain one byte and cache reads keep their original
size. This is not a physical FIFO-capacity change. Prior scripts keep their
original bounds and configurations.

## Reproduction and continuation

Use the seeded startup-aware main project and exports from
[MAIN_NAND_BBT_PROGRAM.md](MAIN_NAND_BBT_PROGRAM.md). No new firmware addresses,
metadata seed or export regeneration are required.

```sh
python3 analysis_scripts/main_nand_busy.py --scope read \
  --vectors-output firmware/main-nand-busy-read-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript ValidateMainNandBusy.java \
  firmware/main-nand-busy-read-vectors.json firmware/main-nand-busy-read-validation.json

python3 analysis_scripts/main_nand_busy.py firmware/bip6-4.6.0.3.zip \
  --scope read --decompiled firmware/decompiled/runtime-main-nand-bbt-repair \
  --vectors firmware/main-nand-busy-read-vectors.json \
  --validation firmware/main-nand-busy-read-validation.json
```

The following [repair busy scope](MAIN_NAND_BUSY_REPAIR.md) executes complete
4000/2000-poll erase/program boundaries. All **546 preceding main native cases
reproduce byte for byte**. Both scopes add **24 host checks** to the passing
**1,990-test suite**. Asynchronous/private DMA, other consumers/geometries,
physical readiness/timing/IRQ/cache/coherency/persistence, safe restoration and
standalone boot remain open.
