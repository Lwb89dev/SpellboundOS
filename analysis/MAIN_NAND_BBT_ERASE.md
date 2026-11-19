# Actual main BBT repair erase through original NAND/QSPI

All **11 native cases** pass in **278,269 instruction/service steps** (maximum
**27,397**, busy-then-ready erase). Original main erase `0x702d730c`, enable
builder `0x702d5e7a`, erase-command builder `0x702d6224`, block remapping, busy
status and QSPI command/FIFO now execute inside actual first-descriptor BBT
recovery. This joins original marker/record reads, verifier/CRC, probe/UID/root
and subsequent geometry/UID-export/mapping consumers.
[main-nand-bbt-erase.json](main-nand-bbt-erase.json) records **69 code/export and
67 data hashes**, complete observations and limitations.

Program remains supplied in this scope. The subsequent
[program scope](MAIN_NAND_BBT_PROGRAM.md) executes it too. Status/FIFO/record/
marker/timer/peripheral inputs and library/pin/power/RTOS/BSP/heap/PM services
remain authored or supplied. Issued erase commands do not establish physical
erasure, persistence or a device-specific restoration route.

## Original backup repair ordering

After accepting backup and rereading its 140 bytes through actual NAND/QSPI,
resume has RAM magic zero. Actual erase therefore passes primary block 1023
through block remapping, enables writes with `0x06`, issues erase `0xd8` at page
65472 and reads status `0x0f` through the original busy loop. Guard globals are
still the pre-publication values; this selected tail operation does not test
physical protected-area enforcement.

Ready on the first status and busy once then ready execute. The original first
descriptor's erase-failure mask is bit 2. Authored status 4 returns `-104`; status
32 is ignored by the erase result check. An accepted primary or no accepted
record skips erase entirely.

| Selected condition | Actual erase / outer recovery behavior |
| --- | --- |
| Erase status ready | Erase returns zero; supplied program callback follows |
| Erase status 4 | Erase returns `-104`; program skipped; RAM magic restored and recovery returns zero |
| Supplied program failure after real erase | Repair failure logged; RAM table remains active with zero recovery return |
| Enable or erase command completion timeout | Transport assertion line 294 before normal erase return |
| Status readiness timeout | Transport assertion line 305 before completed erase-status read |
| Status completion timeout | Status FIFO read counted, then line 305 assertion before erase returns |

Transport assertions use owner `0x70a1bc8c` and stop before their bodies/recovery.
A stopped repair leaves RAM magic zero and never reaches object allocation/
publication. A handled erase-status error instead permits resume to restore
active RAM magic and publish the object. The two outcomes must not be conflated.

## Reproduction and regression

Use the startup-aware main project seeded through
[MAIN_NAND_BBT_MARKER_READ.md](MAIN_NAND_BBT_MARKER_READ.md).
`SeedMainNandBbtRepair.java` checks original byte hashes and updates metadata for
six erase/program/builders, including their full epilogues. It removes interior
function metadata within those verified bodies when defining their boundaries;
firmware instructions and emulator semantics remain unchanged.

```sh
python3 analysis_scripts/main_nand_bbt_repair.py --scope erase \
  --vectors-output firmware/main-nand-bbt-erase-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandBbtRepair.java \
  -postScript ValidateMainNandBbtRepair.java \
  firmware/main-nand-bbt-erase-vectors.json firmware/main-nand-bbt-erase-validation.json

python3 analysis_scripts/main_nand_bbt_repair.py firmware/bip6-4.6.0.3.zip \
  --scope erase --decompiled firmware/decompiled/runtime-main-nand-bbt-repair \
  --vectors firmware/main-nand-bbt-erase-vectors.json \
  --validation firmware/main-nand-bbt-erase-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_bbt_repair`
using `DecompileWithLogger.java`, logger `0x702b38a2`. Both new scopes share
exports and the 200,000-step bound. Firmware and exports remain local.
All **522 preceding main native cases reproduce byte for byte** after narrow
policy-factory/FIFO-write hooks. Previous bounds and fixed configurations are
unchanged. The two scopes add **30 host checks** to the **1,966-test passing
suite**.

Actual program/TX FIFO follows in the next scope. Asynchronous/private DMA,
complete busy exhaustion, wider geometries/media consumers, physical effects/
timing/IRQ/cache/coherency, persistent repair/atomicity, safe restoration and
standalone boot remain open.
