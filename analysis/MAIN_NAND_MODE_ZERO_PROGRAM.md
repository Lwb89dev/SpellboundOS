# Main mode-zero page program through original initialized TX DMA

All **26 native cases** pass in **851,318 instruction/service steps** (maximum
**34,390**, two successive programs). Original main page program `0x702d6d2c`
with mode argument zero now joins original cache builder `0x702d61ba`, bus/QSPI
and DMA setup/wait using the original platform-initialized TX record. This
executes after actual marker/read/CRC/BBT repair/root publication and uses the
recovered page map and enabled published guard.
[main-nand-program.json](main-nand-program.json) records **71 code/export and
68 data hashes**, observations and limitations. The preceding
[read](MAIN_NAND_ASYNC_READ.md) and [erase](MAIN_NAND_SLEEP_ERASE.md) scopes cover
the corresponding selected mode-zero paths.

Source bytes, MMIO/status/ticks and other peripheral inputs are authored.
Cache/copy/pin/power/RTOS/BSP/heap/PM services remain supplied. DMA data movement,
physical program/erase, readback and NAND persistence are **not modeled**.
Software command emission and authored completion do not prove a physical write.

## Recovered mapping and original protection

Recovered BBT `[1, 3, 7]` maps logical page 513 to physical page 705. Original
software protection remains enabled by original byte one at `0x70f87ad0` and
published guard size 512 pages. Logical page 256 maps to 384 and returns `-250`
before write enable; logical page 320 maps exactly to 512 and proceeds.
Reserved-page rejection returns `-150`; null source and zero size return `-1`.
All of these precede DMA/staging/status work.

The original column check accepts column 2080 plus 32 bytes, rejects 2081 plus
32, but also accepts `0xfffffff8` plus 16 because unsigned addition wraps. That
case reaches the actual original cache builder and direct FIFO. The observed
address register retains the full unsigned word; this does not establish what
an attached NAND would do with the selected two-address-byte command encoding.
No malformed physical write was attempted.

## Staging and original TX binding

The immutable 128-byte source follows `(0x96 + 11*i) & 255`; the private buffer
starts as 512 bytes of `0x3c`. Original bus logic uses direct FIFO for 1/13/31
bytes and private-buffer DMA for 32/64 on the selected newer ROM revision.
Authored older string `v1.1.03` selects direct FIFO even for 32 bytes.

On the DMA path the bounded copy service stages exactly the requested source
prefix into private buffer `0x80d93960` **before** QSPI command/DMA setup.
Actual setup/wait use original TX record `0x80c10df4`, controller link
`0x80d94a60` and registry slot 26. Source is the private buffer, destination the
QSPI FIFO `0x93240100`, with the requested byte count. The harness records no
fabricated FIFO writes for DMA. Direct cases instead emit the exact source
prefix through actual FIFO stores, including word/tail handling.

Primary TX completion invokes cache finish with `(0, 0)`: original direction-2
setup clears destination tracking and prepares the source cache range.
Alternate completion skips finish and also returns zero. Both can then issue
program-execute at mapped page 705 and read status. The builder stores original
no-op callback `0x702d6418`; instrumentation observes no call to it. Mode zero
selects the cache transport here; the subsequent program busy wait still uses
the original blocking helper, rather than the sleep helper selected by erase.

## Fault boundaries after root publication

| Authored fault/result | Observed original software consequence |
| --- | --- |
| DMA wait timeout | Bus assertion owner `0x70a1bca8`, line 386; staged bytes retained; no execute/status |
| QSPI completion timeout after primary DMA | Same assertion and retained staging; cache finish has already run; no execute/status |
| Write-enable completion timeout | Owner `0x70a1bc8c`, line 294; no staging or DMA |
| Direct cache readiness timeout | Same owner, line 313; no emitted payload or execute |
| Execute completion timeout | Same owner, line 294; staging/DMA complete and execute helper entered; no status |
| Status readiness / completion timeout | Same owner, line 305; zero / one delivered status byte |
| Ready status with bit 8 | Caller returns `-102` after execute |
| Ready status with bit 4 only | Program failure mask does not reject it; caller returns zero |

Busy once then ready consumes two actual status/FIFO polls. Repeated programs
capture independent intermediate staged-buffer hashes and mapped execute pages
705 and 833. Source bytes/guards, recovered BBT and UID remain unchanged. The
already published object/cache remains present after application transport
assertions. Assertions stop before their bodies and claim no normal return ABI.
There is no persistent record mutation or fabricated readback.

## Reproduction and continuation

Use the startup-aware main project and preceding metadata seeds from
[MAIN_NAND_ASYNC_READ.md](MAIN_NAND_ASYNC_READ.md). `SeedMainNandProgram.java`
hash-checks the original 106-byte TX builder and updates function metadata only.
It does not change firmware bytes or emulator instruction semantics.

```sh
python3 analysis_scripts/main_nand_program.py \
  --vectors-output firmware/main-nand-program-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandProgram.java \
  -postScript ValidateMainNandProgram.java \
  firmware/main-nand-program-vectors.json firmware/main-nand-program-validation.json

python3 analysis_scripts/main_nand_program.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-nand-program \
  --vectors firmware/main-nand-program-vectors.json \
  --validation firmware/main-nand-program-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_program` with
`DecompileWithLogger.java`, logger `0x702b38a2`. Firmware/exports remain local.
The new scope keeps the 200,000-step bound; previous fixed scope limits remain
unchanged. All **587 preceding main native cases reproduce byte for byte**
after the metadata seed. The new **26 host checks** compare all native
observations, original hashes, data boundaries and fault-specific state against
the independent model. All **2,050 host tests pass**. The final metadata seed
compiles, and all **71 exports reproduce byte for byte** after reapplying it.

Remaining work includes actual IRQ/event scheduling and cache services, wider
media/partition/PM consumers and geometry, physical DMA movement/coherency and
peripheral timing, persistent repair/atomicity, safe backup/restoration and
standalone boot. The selected read/program/erase mode-zero software paths do
not establish those broader hardware or operating-system contracts.

Subsequent [connected cache-guard cases](MAIN_DMA_CACHE_GUARDS.md) execute the
original prepare/finish guards at the selected high-half/zero arguments with
identical observations. Positive-address CSR paths and physical coherency remain open.
