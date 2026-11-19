# Main mode-zero page reads through original private-buffer DMA

All **16 native cases** pass in **524,188 instruction/service steps** (maximum
**33,924**, two successive DMA reads). Original main reader `0x702d6bbe` with
mode argument zero now joins cache builder `0x702d6018`, original bus/QSPI DMA
wrapper and actual DMA setup/wait over the original platform-initialized RX
record, after complete first-descriptor BBT recovery/repair/root publication.
[main-nand-async-read.json](main-nand-async-read.json) records **72 code/export
and 68 data hashes**, observations and limitations.

The mode-zero name does not establish IRQ-driven asynchronous completion.
The selected wrapper still waits for DMA and QSPI completion. Hardware DMA data
movement is **not modeled**. MMIO/status/ticks, initial private-buffer bytes,
small direct-read FIFO payloads and library/cache/copy/power/pin/RTOS/BSP/heap/PM
services remain authored or supplied. No physical page data, coherency or
persistence is established.

## Original branch, buffer and descriptor provenance

The mode-zero builder keeps the x4 cache opcode/two address bytes/dummy encoding,
clears the force-direct flag and stores original callback address `0x702d6418`
in the extra packet word. The callback's original two-byte body is a return;
it is not invoked by this selected bus path. The harness records an invocation
if one occurs, and none appears in the native corpus.

The bus chooses the private-buffer path only when length exceeds 31 and original
revision logic returns greater than one. Cases cover 1/13/31-byte direct reads,
32/64-byte DMA requests and a 32-byte request using authored older ROM string
`v1.1.03`, which falls back to direct FIFO. Recovered BBT maps page 65 to 129
before the load and cache request.

For DMA, actual original setup/wait use RX record `0x80c10db0`, its original
controller link and registry slot 27. The transfer source is FIFO address
`0x93240100`; destination is original private buffer `0x80d93960`. Initialization
comes from actual probe/platform code; no cloned DMA binding replaces it.

## Data movement and completion are separate observations

The private buffer is authored as 512 bytes of `0x3c`, while the application
output starts as `0xa5`. No simulated DMA engine overwrites those private bytes.
Actual software completion followed by the bounded copy service therefore
copies the retained `0x3c` prefix into the caller, leaving its tail untouched.
This demonstrates the copy/control contract, not delivery of NAND data.
Small direct reads instead consume the authored page/column-dependent FIFO
payload. Their RX byte counts distinguish that data from DMA status-only work.

| Authored completion/input | Actual software consequence |
| --- | --- |
| Primary DMA status bit | Cache-finish service called; tracked destination/size cleared; copy and page success follow |
| Alternate DMA status bit | Zero return and private-buffer copy, but tracking remains and cache finish is skipped |
| DMA wait timeout | Bus assertion owner `0x70a1bca8`, line 374, before output copy; tracking retained |
| QSPI timeout after primary DMA completion | Same bus assertion, output still untouched, but tracking already cleared |
| ECC rejection before cache transfer | Original retry rejects unsupported family; DMA/copy still execute, then reader returns `-101` |
| Reserved mapping / null caller buffer | Return `-150` / `-1` before status or DMA |
| Direct/status readiness timeout | Actual owner `0x70a1bc8c`, line 305, without the corresponding FIFO data |

These application operations occur **after** root publication. Their transport
assertions do not undo the already registered object or active BBT. This differs
from an assertion during initialization. Assertions stop before their bodies and
claim no normal return ABI.

Per-operation snapshots retain the pre-read contexts/counters and both outputs
of a repeated DMA sequence. BBT/UID source and private-buffer guards hold. The
new DMA-read filter hook preserves the preceding scope's default behavior.

## Reproduction and continuation

Use the startup-aware main project seeded through
[MAIN_NAND_BBT_PROGRAM.md](MAIN_NAND_BBT_PROGRAM.md).
`SeedMainNandAsync.java` hash-checks original builder/callback/sleep-loop bodies
before updating metadata. The original guard flag byte at `0x70f87ad0` is one
and remains hash-guarded; original descriptors and bindings remain unchanged.

```sh
python3 analysis_scripts/main_nand_async.py --scope read \
  --vectors-output firmware/main-nand-async-read-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandAsync.java \
  -postScript ValidateMainNandAsync.java \
  firmware/main-nand-async-read-vectors.json firmware/main-nand-async-read-validation.json

python3 analysis_scripts/main_nand_async.py firmware/bip6-4.6.0.3.zip \
  --scope read --decompiled firmware/decompiled/runtime-main-nand-async \
  --vectors firmware/main-nand-async-read-vectors.json \
  --validation firmware/main-nand-async-read-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_nand_async` using
`DecompileWithLogger.java`, logger `0x702b38a2`. Firmware/exports remain local.
Both new scopes share a 200,000-step bound. All **557 preceding main native
cases reproduce byte for byte**, including full busy-window hashes, after the
narrow DMA status hook and metadata seed. Original fixed configurations and
bounds remain unchanged. These scopes add **34 host checks** to the passing
**2,024-test suite**.

The [sleep-based erase scope](MAIN_NAND_SLEEP_ERASE.md) follows the other selected
mode-zero wait strategy. IRQ-driven scheduling, physical DMA/cache/coherency,
mode-zero program and further media/PM consumers, persistence/atomicity, safe
restoration and standalone boot remain open.
