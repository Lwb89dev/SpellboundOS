# Original main BBT repair program and exact TX FIFO payload

All **13 native cases** pass in **378,902 instruction/service steps** (maximum
**32,348**, both repair phases busy then ready). Original main program
`0x702d6d2c`, direct cache-load builder `0x702d6152`, program-command builder
`0x702d6086`, enable/remapping/busy and QSPI TX FIFO now join actual BBT marker/
record reads, verifier/CRC and [repair erase](MAIN_NAND_BBT_ERASE.md).
[main-nand-bbt-program.json](main-nand-bbt-program.json) records **69 code/export
and 67 data hashes**, complete observations and limitations.

The selected first original NAND descriptor now has a connected software
recovery path from marker selection through record verification/reread, erase,
program and root/geometry/UID publication. Peripheral status/FIFO/timer inputs,
records/markers and library/pin/power/RTOS/BSP/heap/PM services are authored or
supplied. **Emitted commands and TX bytes do not establish persistent NAND
contents, repair atomicity or physical operation.** No hardware was accessed.

## Exact original program sequence

Recovery clears RAM magic before repair. After successful actual erase,
original program passes primary page 65472 through inactive-table remapping,
enables writes with `0x06`, sends the reread backup record using cache-load
`0x32`, issues program `0x10` at that page and polls original status.

The cache-load packet uses column zero, two address bytes, x4 data and the
original direct-path flag. All **140 bytes** from the original stack-backed
reread buffer appear in TX FIFO in order; their hash matches the accepted backup
record. The earlier feature-write bytes remain separately visible in the total
TX stream. No private-buffer copy or DMA setup/wait is inferred.

The harness's default feature-write guard remains unchanged. A narrow override
accepts bounded 1/4-byte cache-load writes, exactly 140 payload bytes, within a
512-byte aggregate TX trace ceiling for this scope. The guard is a harness bound,
not a physical FIFO-capacity claim. UID source and original DMA initialization
records remain unchanged.

## Returned status versus stopped transport

| Authored condition | Actual original result |
| --- | --- |
| Ready status | Program returns zero, resume restores active RAM magic and returns zero |
| Program failure bit 3 (status 8) | Program returns `-102` after full TX; resume logs failure, restores active RAM magic and still returns zero |
| Busy once then ready in erase/program | Each original busy loop performs the selected additional status read |
| Status 32 | Program-failure mask does not reject it |
| Actual erase failure | Program body and TX payload are skipped |
| Enable/program command completion timeout | Assertion line 294; program-command timeout retains the prior full cache-load transmission |
| Cache-load readiness timeout | Assertion line 313 before cache-load TX bytes |
| Cache-load completion timeout | Assertion line 313 after all 140 TX bytes, before program command |
| Program-status readiness/completion timeout | Assertion line 305; completed status count differs, but neither path returns normally |

Transport assertions use owner `0x70a1bc8c` and stop before their bodies. Stopped
repairs leave RAM magic zero and prevent later root publication. By contrast,
a handled program-status error can retain an active RAM table and successful
outer registration after sending exactly the same payload. Transmission and
software publication are separate observations.

This selected original recovery does **not reread the repaired primary** after
program status. It still performs only the primary attempt, backup verification
and backup reread. The fixture intentionally does not update its authored
primary record store after TX; no readback or persistence is fabricated.

## Reproduction and continuation

Use the seed/export procedure in [MAIN_NAND_BBT_ERASE.md](MAIN_NAND_BBT_ERASE.md),
substituting the program vectors and validation paths:

```sh
python3 analysis_scripts/main_nand_bbt_repair.py --scope program \
  --vectors-output firmware/main-nand-bbt-program-vectors.json
```

Run `ValidateMainNandBbtRepair.java` with
`firmware/main-nand-bbt-program-vectors.json` and
`firmware/main-nand-bbt-program-validation.json`, then reproduce evidence:

```sh
python3 analysis_scripts/main_nand_bbt_repair.py firmware/bip6-4.6.0.3.zip \
  --scope program --decompiled firmware/decompiled/runtime-main-nand-bbt-repair \
  --vectors firmware/main-nand-bbt-program-vectors.json \
  --validation firmware/main-nand-bbt-program-validation.json
```

All **522 preceding main native cases reproduce byte for byte** after the
policy-factory/FIFO-write hooks; previous fixed configurations and bounds stay
unchanged. Both new scopes use the existing 200,000-step bound and 1024-byte
aggregate RX guard. Their **30 host checks** join the passing **1,966-test suite**.

The subsequent [read-busy scope](MAIN_NAND_BUSY_READ.md) and
[repair-busy scope](MAIN_NAND_BUSY_REPAIR.md) execute complete 2000/4000-poll
boundaries, including discarded last-poll ready/ECC bytes. Asynchronous/private DMA paths, wider
geometries and further media/PM consumers remain open. Physical contents,
electrical/timing/IRQ/cache/coherency, durable repair/atomicity, safe backup/
restoration and standalone boot remain separate open requirements.
