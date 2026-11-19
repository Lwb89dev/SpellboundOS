# Complete main erase/program busy limits inside BBT repair

All **six native cases** pass in **6,783,698 instruction/service steps** (maximum
**1,498,880**, erase ready on its penultimate poll followed by actual program).
Original busy loops execute **4000 erase polls** and **2000 program polls**
through actual feature packets and QSPI FIFO, inside the original connected
marker/read/CRC/erase/program/root BBT path.
[main-nand-busy-repair.json](main-nand-busy-repair.json) records **69 code/export
and 67 data hashes**, counted event hashes and complete outer observations.

Firmware bytes, constant data and exports are unchanged from the preceding
repair scope. Only the new harness/model supply long status streams and compact
busy-window trace storage. Peripheral/status/timer/library/platform inputs remain
authored or supplied. Actual elapsed waits, media readiness or persistence are
not established.

## Original boundary ordering and caller-specific errors

The original busy helper reads status, then checks the loop limit before testing
readiness or publishing the byte. At the final allowed poll it logs a timeout,
returns zero and leaves output `0xff`. This is the same helper contract observed
in [full read polling](MAIN_NAND_BUSY_READ.md), with a 20-unit caller argument for
erase and 10 for program.

| Selected condition | Actual original repair result |
| --- | --- |
| Erase busy for all 4000 polls | Busy returns zero/output `0xff`; erase failure-mask check returns `-104`; program skipped |
| Erase ready on poll 4000 | Ready byte ignored; same `-104` result |
| Erase ready on poll 3999 | Ready byte published; erase succeeds and exact 140-byte program path executes |
| Program busy for all 2000 polls | Busy returns zero/output `0xff`; program failure-mask check returns `-102` after full TX |
| Program ready on poll 2000 | Ready byte ignored; same `-102` result |
| Program ready on poll 1999 | Ready byte published; program succeeds |

All six selected cases return normally from the helper and surrounding repair.
They do not simulate a transport timeout: the HAL ready/completion inputs remain
ready while the authored NAND status remains busy. There is no transport
assertion. For handled `-104`/`-102` results, original resume logs repair failure,
restores active RAM magic and returns zero. Actual root publication follows.

Program busy polling happens after all 140 cache-load bytes and the program
command. Erase failure prevents that program phase entirely. The ready-before-
limit erase case performs 3999 erase status reads and then the ordinary program
window. Remaining UID, marker and record windows keep their one-poll behavior.
No repaired-primary readback or authored backend record update is added.

## Full execution with bounded evidence

The new validator executes each selected NAND/bus/HAL loop iteration; existing
leaf services remain supplied. Busy-window events use the
canonical counted SHA-256 encoding described in
[MAIN_NAND_BUSY_READ.md](MAIN_NAND_BUSY_READ.md). Complete 4000-poll windows contain
72,001 events; the 3999-poll ready window contains 71,982. Different final FIFO
bytes yield different trace hashes even when final published byte stays `0xff`.

The per-case bound is 4,000,000 steps; the aggregate RX guard is 8192 bytes.
The erase-exhaustion case receives **4482 total FIFO bytes**, beyond the preceding
scope's 1024-byte aggregate guard. Individual status reads remain one byte. These
limits are harness accounting, not hardware FIFO size or timing claims. DMA
initialization records and UID source remain intact.

## Reproduction and remaining work

Use the startup-aware project and unchanged export corpus from
[MAIN_NAND_BBT_PROGRAM.md](MAIN_NAND_BBT_PROGRAM.md). Substitute the repair paths
in the read-busy reproduction command:

```sh
python3 analysis_scripts/main_nand_busy.py --scope repair \
  --vectors-output firmware/main-nand-busy-repair-vectors.json
```

Run `ValidateMainNandBusy.java` with
`firmware/main-nand-busy-repair-vectors.json` and
`firmware/main-nand-busy-repair-validation.json`, then reproduce evidence:

```sh
python3 analysis_scripts/main_nand_busy.py firmware/bip6-4.6.0.3.zip \
  --scope repair --decompiled firmware/decompiled/runtime-main-nand-bbt-repair \
  --vectors firmware/main-nand-busy-repair-vectors.json \
  --validation firmware/main-nand-busy-repair-validation.json
```

All **546 preceding main native cases reproduce byte for byte**, preserving
previous fixed configurations and bounds. The two busy scopes add **24 host
checks** to the passing **1,990-test suite**. Next work is asynchronous/private
DMA paths, nonblocking erase scheduling, wider descriptors/media/PM consumers
and physical validation. Electrical/timing/IRQ/cache/coherency, durable repair
and atomicity, safe backup/restoration and standalone boot remain open.
