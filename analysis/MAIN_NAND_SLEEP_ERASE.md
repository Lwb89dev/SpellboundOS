# Original main mode-zero erase and sleep-based status polling

All **14 native cases** pass in **473,271 instruction/service steps** (maximum
**39,369**, ready on the twentieth poll). Original main erase `0x702d730c` with
mode argument zero selects original helper `0x702d67c0` and requests a one-tick
sleep before each status read. This runs after actual BBT marker/read/CRC/
repair erase/program/root publication, with original recovered remapping and
published guard geometry.
[main-nand-async-erase.json](main-nand-async-erase.json) records **72 code/export
and 68 data hashes**, observations and limitations. It shares the corpus and
harness with [mode-zero page reads](MAIN_NAND_ASYNC_READ.md).

Sleep, status/timer/peripheral behavior and library/cache/pin/power/RTOS/BSP/
heap/PM services remain authored or supplied. A requested sleep is not actual
scheduler execution or elapsed-time evidence. Mode zero still loops in the
selected caller; IRQ-driven erase completion is not established.

## Original mapping, guards and wait strategy

Logical block 12 maps through recovered `[1, 3, 7]` BBT to physical block 15.
Actual code enables writes, issues erase at page 960, requests sleep argument 1
and reads original status through feature/bus/QSPI FIFO. Busy once then ready
uses two sleeps/status reads. Status 4 returns `-104`; status 32 is outside the
original erase-failure mask and returns zero.

The original guard byte at `0x70f87ad0` remains one. Probe has already published
eight guard blocks and 512 guard pages. Logical block 4 maps to physical block
6 and is rejected with `-250` before enable or sleep; logical block 5 maps to
physical block 8 and is accepted. Reserved-limit rejection returns `-151`
before erase. These are software arithmetic/guard results over an authored
selected descriptor, not a physical write-protection guarantee.

## Complete twenty-poll boundary

Unlike the blocking helper's 4000 erase polls, the sleep-based helper takes a
20-poll limit directly. It reads status and increments the poll count, then checks
the limit **before** readiness/publication. Its caller's status output starts
at `0xff`.

| Authored stream | Actual original result |
| --- | --- |
| Busy on all 20 reads | 20 sleep requests/status reads; timeout log; helper returns zero with output `0xff`; erase returns `-104` |
| Ready on read 20 | Final zero byte is ignored; same `-104` result |
| Ready on read 19 | Ready byte is published; erase returns zero after 19 sleeps |

Full direct traces retain the different final FIFO bytes despite identical
late-ready/exhausted outputs. No compressed-loop model or skipped iterations
are used for these short complete workloads. Requested sleeps do not establish
real twenty-tick timing.

## Assertions after publication

Enable/erase-command completion faults reach owner `0x70a1bc8c`, line 294,
before any sleep. Status readiness/completion faults instead reach line 305
after one sleep request; only completion failure counts a delivered status byte.
Assertions stop before their bodies and claim no normal return ABI. The object
and BBT have already been published and remain present in the observed state.

These application erases do not change the recovered RAM BBT or UID source.
No physical erase or persistent table/partition change is simulated. The original
DMA initialization records are unrelated to this sleep/poll branch; no DMA
transfer is inferred from it.

## Reproduction and remaining work

Use the seed/export procedure from [MAIN_NAND_ASYNC_READ.md](MAIN_NAND_ASYNC_READ.md),
substituting these vectors and validation paths:

```sh
python3 analysis_scripts/main_nand_async.py --scope erase \
  --vectors-output firmware/main-nand-async-erase-vectors.json
```

Run `ValidateMainNandAsync.java` with
`firmware/main-nand-async-erase-vectors.json` and
`firmware/main-nand-async-erase-validation.json`, then reproduce evidence:

```sh
python3 analysis_scripts/main_nand_async.py firmware/bip6-4.6.0.3.zip \
  --scope erase --decompiled firmware/decompiled/runtime-main-nand-async \
  --vectors firmware/main-nand-async-erase-vectors.json \
  --validation firmware/main-nand-async-erase-validation.json
```

All **557 preceding main native cases reproduce byte for byte**; previous fixed
configurations and bounds remain unchanged. The two scopes add **34 host
checks** to the passing **2,024-test suite**. Subsequent
[mode-zero program cases](MAIN_NAND_MODE_ZERO_PROGRAM.md) connect original TX
DMA staging and execute/status. Next work includes
actual IRQ/event scheduling, wider media/PM consumers and physical validation.
DMA movement/coherency, electrical/timing/IRQ behavior, persistent repair and
atomicity, safe backup/restoration and standalone boot remain open.
