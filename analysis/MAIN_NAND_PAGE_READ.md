# Actual main mapped page read through direct QSPI FIFO

All **23 native cases** pass in **186,325 instruction/service steps** (maximum
**10,686**, 128-byte payload). Original main reader `0x702d6bbe`, actual block/
page remappers, load builder, busy loop, direct x4 cache builder `0x702d5fac` and
QSPI command/count/timer/FIFO now consume the BBT recovered inside the original
first-chip probe/UID/platform/root chain. Original retry `0x702d8010` executes its
unsupported-family branch on ECC rejection.
[main-nand-page-read.json](main-nand-page-read.json) records **62 code/export and
67 data hashes**, observations and limitations.

**BBT recovery page/marker services remain supplied.** During BBT recovery the
reader entry is still intercepted as a supplied page callback; the later explicit
read operation executes its original body and lower direct transport. This does
not yet connect recovery's own page IO to QSPI. FIFO page/status/ID/UID data,
timers, peripheral behavior, library/power/pin/RTOS/heap/PM services remain
authored or supplied. No physical page contents, persistence or elapsed timing
is established.

## Recovered mapping reaches the physical load/cache source

Original `[1, 3, 7]` BBT maps logical page 65 to physical page 129, then executes
load `0x13`, status `0x0f` and cache `0x6b`. Cache packets request two address
bytes, dummy cycle encoding and x4 data, and force the direct path even at
128 bytes. One-byte, word-tail, 32-byte and complete 128-byte backing cases
capture delivered bytes and untouched tails. The authored data pattern depends
on the mapped page and requested column, so source changes are observable.

Last usable logical page 65215 reaches physical page 65407. Reserved-limit or
large-page remapping failures return `-150` before load/status/cache and do not
emit the ordinary page-result error log. With inactive BBT, the selected valid
page passes to the reader's own bounds checks. A backup-repair error can leave
an active table that still maps and reads successfully.

Accepted unsorted `[7, 1]` and duplicate `[1, 1]` records lead page 65 to physical
pages 65 and 193 respectively. Actual cache payloads follow those sources. This
joins the [remapping counterexamples](MAIN_NAND_BBT_MAPPING.md) to an actual
main reader and transport without changing original descriptors or table bytes.

## Errors and delivered data are separate observations

| Authored condition | Actual behavior |
| --- | --- |
| Status busy once, then ready | Two actual status FIFO reads and requested waits |
| Status ECC field rejected | Original unsupported-family retry returns failure; reader still obtains cache payload, then returns `-101` |
| Null output buffer or zero length | Return `-1` before load |
| Column 2080, length 32 | Exact 2112-byte page-plus-OOB end accepted |
| Column 2081, length 32 | Return `-1` before load |
| Column `0xfffffff8`, length 16 | Wrapped unsigned sum passes the original check; authored cache transfer executes |
| Load command completion timeout | Transport assertion line 294 before status/cache |
| Status or cache readiness timeout | Transport assertion line 305; no bytes from that FIFO request delivered |
| Cache completion timeout after FIFO delivery | Transport assertion line 305 with already received payload retained |

The wrapping-column case is a software arithmetic counterexample. It does not
prove what address a real two-byte-address peripheral observes. Assertions use
owner `0x70a1bc8c` and stop before assertion/recovery bodies; no normal return ABI
is claimed for those cases. Cache-read readiness timeout retains the authored
initial output bytes; completion timeout retains the received bytes.

Each operation records controller/MMIO/FIFO counts, status counts and output
independently. A repeated-read case preserves both intermediate payloads. The
new model snapshot hooks avoid reporting final read counters on earlier root/
geometry operations. BBT/UID source and DMA initialization records remain
unchanged by these forced-direct reads; no DMA setup/wait is inferred.

## Reproduction and continuation

Use the startup-aware main project and prior BBT/remapping seeds.
`SeedMainNandPageRead.java` checks code hashes and updates metadata only.

```sh
python3 analysis_scripts/main_nand_page_read.py \
  --vectors-output firmware/main-nand-page-read-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandPageRead.java \
  -postScript ValidateMainNandPageRead.java \
  firmware/main-nand-page-read-vectors.json firmware/main-nand-page-read-validation.json

python3 analysis_scripts/main_nand_page_read.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-nand-page-read \
  --vectors firmware/main-nand-page-read-vectors.json \
  --validation firmware/main-nand-page-read-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_page_read` using
`DecompileWithLogger.java`, logger `0x702b38a2`. Firmware/exports remain local.
All **472 preceding main native cases reproduce byte for byte**, including the
20 mapping cases, after narrow snapshot/packet-failure/data-line hooks. Prior
fixed configurations and bounds remain unchanged. The two scopes add **40 host
checks** to the complete **1,908-test passing suite**.

Next work is connecting actual main BBT recovery page IO to the lower transport,
asynchronous/private DMA reads, program/erase, full busy exhaustion, alternate
geometries and further media consumers. IRQ/cache/coherency, physical contents/
identity/timing, persistence, safe backup/restoration and standalone boot remain
separate open requirements.
