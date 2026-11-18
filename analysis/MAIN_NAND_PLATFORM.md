# Original main NAND platform and adjacent DMA records

All **eight native initialization cases** pass in **2,802 instruction/service
steps** (maximum **353**, clock word 99). Original main platform initializer
`0x70296ab0` now executes actual main clock selection, QSPI initialization and
DMA initialization using the original adjacent DMA record addresses.
[main-nand-platform.json](main-nand-platform.json) records **21 code/export and
four data hashes**, observations and explicit limitations. The same guarded
corpus supports the [connected transfer scope](MAIN_NAND_PLATFORM_TRANSFER.md).

Pin-mux/GPIO, cache/copy and physical peripherals remain supplied. Board/QSPI/
DMA registers, controller mode, reset/status/timestamps and ROM string are
authored emulator inputs. Fences are recorded single-thread ordering markers;
atomic register operations execute against that backing without establishing
physical concurrency or coherency.

## Original addresses and startup evidence

| Record/link | Main address / field |
| --- | --- |
| TX DMA record, channel 5 | `0x80c10df4` |
| RX DMA record, channel 6 | `0x80c10db0` |
| Controller | `0x80d94a60` |
| Controller's TX/RX pointers | controller +32 / +36 |
| Each DMA record's controller pointer | record +44 |
| Reinitialization / disabled flags | `0x80c10e38` / `0x80c10e39` |

RX plus 68 equals TX; TX plus 68 reaches the adjacent flags. Native execution
reads/writes fields through +64, so the harness uses **68-byte observed records**
with guards around the combined records/flag region. This establishes selected
accesses, without claiming a complete production object-allocation extent.

[main-nand-platform-facts.json](main-nand-platform-facts.json) independently
records the startup zero-table region covering both records and hashes of their
68 zero bytes in the startup-aware main memory model. Controller initial state
is authored separately; these facts do not establish full physical startup.

## Actual initialization and preserved fields

Clock selection follows the original descriptor's bus word: below 100 selects
2, otherwise 1. Cases cover 83, 99, 100 and 104. The first original descriptor
is cloned only to vary that word; original source descriptor and bus binding
remain immutable and hash guarded.

Native instructions separately clear and set board bit `0x200` at `0x9a00000c`,
although decompilation combines them into one expression. They invoke supplied
pin-mux/GPIO services with the original arguments, record a fence, set board
bits at `0x9a000004`, execute real QSPI reset/FIFO setup and record another fence.
Selected supplied pin results `-9` are ignored. Controller mode 1 is retained.

Actual code populates the ten public DMA words, calls the real main DMA
initializer and publishes reciprocal controller/record links. Registry slots
26/27 hold the original TX/RX addresses. Initialization clears tracked address/
length at +60/+64, while leaving +40 and private +48..+59 unchanged. A selected
`0xa5` private backing case checks those preserved bytes explicitly. No IRQ
callback is invoked or validated.

Initialization itself preserves the adjacent reinitialization/disabled flags.
Both may remain set after successful explicit initialization. The connected
scope distinguishes initialization from later permission to transfer.

## Reproduction

```sh
python3 analysis_scripts/main_nand_platform.py firmware/bip6-4.6.0.3.zip \
  --facts-output /tmp/main-nand-platform-facts.json
cmp analysis/main-nand-platform-facts.json /tmp/main-nand-platform-facts.json
python3 analysis_scripts/main_nand_platform.py --scope init \
  --vectors-output firmware/main-nand-platform-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript ValidateMainNandPlatform.java \
  firmware/main-nand-platform-vectors.json firmware/main-nand-platform-validation.json

python3 analysis_scripts/main_nand_platform.py firmware/bip6-4.6.0.3.zip \
  --scope init --decompiled firmware/decompiled/runtime-main-nand-platform \
  --vectors firmware/main-nand-platform-vectors.json \
  --validation firmware/main-nand-platform-validation.json
```

Use the preceding startup-aware main project and metadata seeds. Export
addresses from `ranges()` in `analysis_scripts.main_nand_platform`, using
`DecompileWithLogger.java` and logger `0x702b38a2`. Firmware/exports stay local.
Code/data hashes, return ABI, source/clone/packet immutability, adjacent-record/
flag guards and preserved private fields are checked. Physical pin assignment,
DMA movement, IRQ/cache behavior and full probe/root integration remain open.
