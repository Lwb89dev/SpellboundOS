# Original main NAND bus/platform and feature packet conversion

All **35 native cases** pass in **3,168 instruction/service steps** (maximum
**200**, transfer with requested reinitialization). Main initialization
`0x70296ab0`, transfer `0x70296c24`, feature-read `0x702d5daa` and feature-write
`0x702d5e0e` execute unchanged. [main-nand-bus.json](main-nand-bus.json) records
**four code/export and two data hashes**, bounded observations and limitations.

HAL command/data, revision, DMA-init, pin/clock and bounded copy services remain
supplied. MMIO is authored emulator backing; fences are recorded as single-thread
ordering markers. No physical peripheral, elapsed timing or DMA completion runs.
The host model shares packet policy with the boot model but uses main addresses,
flags and assertions; these main instructions are independently executed and
hash guarded.

## Initialization and adjacent state

Initialization reads descriptor word +12 and requests clock discriminator 2
below 100, otherwise 1. Cases cover 83, 99, 100 and 104. Actual code populates
controller `0x80d94a60`, ORs emulator MMIO bits at `0x9a000004`/`0x9a00000c`,
calls supplied pin/GPIO/controller services and builds both DMA records:

| Record | Original address | Published controller link |
| --- | --- | --- |
| DMA 0 | `0x80c10df4` | controller +32 |
| DMA 1 | `0x80c10db0` | controller +36 |

Each DMA record publishes the controller pointer at +44 after the supplied
DMA-init call. Selected negative returns from the initialization services are
ignored; actual initialization still returns zero. Initialization itself leaves
the two adjacent flag bytes unchanged.

The direct fixture clones the first original descriptor to vary its bus word.
Original source descriptor and bus binding `0x80c007c4` remain immutable and
hash guarded. The [connected probe scope](MAIN_NAND_BUS_PROBE.md) instead uses
all eleven unchanged original descriptors.

## Early rejection, reinitialization and transfer selection

Transfer first reads disabled flag `0x80c10e39`. When nonzero it returns `-1`
before reading/clearing reinitialization flag `0x80c10e38`, querying revision or
issuing a command. With both flags set, reinitialization remains pending and
controller state is unchanged.

Otherwise a nonzero reinitialization flag is cleared before actual bus init is
called with the transfer context. This fixture supplies a valid descriptor
context. The main probe's pre-selection ID context is zero; reinitialization
during that particular interval is outside these cases.

The bus then requests a revision value from `0x80d4556c`. It chooses bounce
buffer `0x80d93960` only when packet force byte +2 is zero, length exceeds 31
and the **unsigned** revision exceeds 1. Cases cover 31/32-byte boundaries,
revisions 0, 1, 2 and `0xffffffff`, forced direct operation and zero length.
Revision return values are authored; the revision body does not execute.

Original conversion emits the 11-word HAL frame: direction 0/2, zero, opcode,
constant 1, command lines, address, constant 1, address-byte count, data lines,
length, and dummy count 0/8. Nonzero packet direction/dummy bytes normalize to
these values. HAL command timeout is forwarded as 1000. For a nonzero length,
original code calls the selected receive/transmit service. Bounce writes copy
before command submission; successful bounce reads copy back after receiving.
Partial supplied receives preserve the unwritten caller bytes.

## Transport faults and feature builders

| Failed supplied service | Original assertion owner / line |
| --- | --- |
| Direct command | `0x70a1bc8c` / 294 |
| Direct receive | `0x70a1bc8c` / 305 |
| Direct transmit | `0x70a1bc8c` / 313 |
| Bounce command | `0x70a1bca8` / 361 |
| Bounce receive | `0x70a1bca8` / 374 |
| Bounce transmit | `0x70a1bca8` / 386 |

These failures log and call supplied diagnostic `0x70296834` before the actual
assertion. Both negative and positive nonzero command statuses take that path.
Execution stops at the assertion call site; assertion/recovery bodies do not run.

Feature builders read opcodes `0x0f`/`0x1f` from the selected original descriptor,
create one-byte addressed packets and follow the original transfer binding.
Feature-write truncates a supplied `0x1a5` to `0xa5`. A disabled bus returns `-1`
to the builder, which asserts at owner `0x70a3112c`, line 55 (read), or
`0x70a31114`, line 74 (write). HAL faults instead stop inside transport first.
Normal feature helpers return zero. These cases do not establish ordinary
feature-helper error returns to the outer probe.

## Reproduction and next bodies

```sh
python3 analysis_scripts/main_nand_bus.py \
  --vectors-output firmware/main-nand-bus-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandBus.java \
  -postScript ValidateMainNandBus.java \
  firmware/main-nand-bus-vectors.json firmware/main-nand-bus-validation.json

python3 analysis_scripts/main_nand_bus.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-nand-bus \
  --vectors firmware/main-nand-bus-vectors.json \
  --validation firmware/main-nand-bus-validation.json
```

Use the preceding startup-aware main project. The seed changes function
metadata only. Export with `DecompileWithLogger.java`, logger `0x702b38a2`, and
addresses in `RANGES` from `analysis_scripts.main_nand_bus`. Firmware/exports
stay local. Code/data hashes, stack/return ABI, descriptor/packet immutability,
controller/buffer/DMA guards and explicit flag fields are checked.

The next supplied HAL boundaries are controller init `0x80d34ac4`, command
`0x80d34b30`, direct receive/transmit `0x80d34c68`/`0x80d34dc0`, bounce receive/
transmit `0x80d34d60`/`0x80d34eb0`, DMA initializer `0x702a0038` and revision
`0x80d4556c`. Their instruction bytes are readable in the startup-aware main
memory model; their semantics are outside this evidence. Main UID/workaround/
BBT, broader media/storage callers, physical behavior and restoration/boot
remain open.
