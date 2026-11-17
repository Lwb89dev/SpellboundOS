# NAND platform initialization and original pin-control mapping

All 47 native cases pass in 11,934 steps (maximum 1,037 for bus-triggered
reinitialization followed by private-buffer read). Actual grouped/table-driven
pin helpers and the complete selected NAND bus initializer execute. The latter
connects actual clock selection, QSPI controller initialization and DMA
initialization at the original descriptor addresses, then selected actual
private-buffer transfers. Complete observations and provenance are in
[nand-platform.json](nand-platform.json); original pin records/startup facts
are in [nand-pins.json](nand-pins.json).

The previous 90-case QSPI and 28-case QSPI/DMA reports reproduce byte for byte
with the extended runner. Twenty-five new host tests bring the suite to
**1,210 passing tests**.

Peripherals, reset-bit clearing, timestamps, ROM-version result and cache/copy
bodies remain supplied. Fences are recorded single-thread ordering markers.
DMA payload movement, electrical pin functions and hardware startup are not
validated. No watch or phone was accessed.

## Original table-driven pin helper

The table at `0x80d81c30` has 23 eight-byte records. Each gives a register offset
relative to `0x91000000` and a four-bit field shift. Actual helper `0x80df8e94`
uses them as follows:

| Logical selector | Table indices | Register/shift |
| --- | --- | --- |
| P0 bits 0–1 | 0–1 | `0x910000b4`, shifts 24/28 |
| P0 bits 2–5 | 2–5 | `0x910000b8`, shifts 0/4/8/12 |
| P0 bits 6–11 | 6–11 | `0x910000b4`, shifts 0/4/8/12/16/20 |
| P1 bits 0–2 | 12–14 | `0x910000b8`, shifts 16/20/24 |
| P1 bits 3–10 | 15–22 | `0x910000bc`, shifts 0 through 28 |

Its internal iterator `0x80df8d94` executes too. Every logical selector is
individually tested, along with a combined mask. A requested bit at or above 12
in either input mask rejects the entire request before MMIO. P1 bit 11 passes
that bound but does not select a table entry and produces no write.

Each selected field is updated as
`(register & ~(0xf << shift)) | (value << shift)`. The value is **not masked to
four bits**. An authored value 31 can therefore set a bit in a neighboring field.
The original initializer passes value 1; the spill example is a bounded helper
counterexample, not an observed board request.

These selectors and register fields do not identify package pad numbers, PCB
traces, GPIO directions or electrical alternate-function meanings. The names
P0/P1 here label software mask arguments only.

## Grouped six-bit control helper

Actual `0x80c13408(p0, p1, value)` masks its value to six bits. Selection differs
from the table-driven helper: several mask bits share one field, and higher mask
groups are accepted.

| Input mask group | Register | Field shifts |
| --- | --- | --- |
| P0 `1`, `2`, `3c` | `0x910001ac` | 0, 8, 16 |
| P0 `40`, `80`, `f00` | `0x910001b4` | 0, 8, 16 |
| P1 `1`, `2`, `4`, `7f8` | `0x910001b0` | 0, 8, 24, 16, in that order |
| P0 bits 12–15 | `0x910001b8` | 0, 8, 16, 24 |
| P1 bits 12–15 | `0x910001bc` | 0, 8, 16, 24 |
| Any P0 bit 16–31 | `0x910001c0` | Both 0 and 8 |
| Any P1 bit 16–31 | `0x910001c0` | Both 16 and 24 |

Each of the final paired updates is **two separate read-modify-write sequences**,
even though fresh pseudocode combines the expression. No atomicity or
concurrent-writer protection is established. Tests cover single/grouped/high
selectors and all bits with an authored all-ones value, confirming the six-bit
mask and preservation of the other register bits.

## Actual bus initialization sequence

Actual `0x80c10580(descriptor)` now executes through the previously supplied
services from the [bus pass](NAND_BUS_AND_COMMANDS.md):

1. Compare descriptor word +`0x0c` with 100 and call actual clock selection with
   2 below the threshold or 1 otherwise. Original values 83/104 and authored
   boundary values 99/100 are covered. No MHz/divider interpretation is claimed.
2. Store QSPI base `0x93240000` and zero selected context fields.
3. At `0x9a00000c`, **clear bit `0x200`, then set it again using a second
   read-modify-write**. This transient was not captured by earlier final-state
   observations. Its electrical/reset effect remains unverified.
4. Execute grouped control `(0, 0x7f, 0x3f)` and table-driven control
   `(0, 0x7f, 1)`, selecting the seven P1 records at indices 12–18.
5. Record a fence, set bit `0x200` at `0x9a000004` and execute actual controller
   initialization with authored reset-bit clearing.
6. Record another fence, set bit 3 (`0x8`) at `0x9a000004`, populate both original DMA
   descriptors and execute actual DMA initialization.
7. After each DMA initializer returns, link its owner field +`0x2c` to QSPI
   context `0x80dfb880` and publish the descriptor pointer in that context.

Other board bits are preserved by these sequences. The actual QSPI initializer
sets FIFO configuration `0x3300` and selected enable/control fields, as in the
[HAL pass](QSPI_HAL_AND_FIFO.md). The covered initializer returns zero. This is
the NAND bus initializer, not execution of complete board startup, regulator
setup, interrupt-controller registration or the signed boot chain.

## Original adjacent DMA backing

The original receive/transmit descriptor addresses are `0x80de645c` and
`0x80de64a0`, separated by **68 bytes**. The context fields used by selected
DMA initialization/setup/wait extend through the word at +`0x40`, ending at
+`0x44` (68 bytes). Fixtures use that observed footprint and guard the combined
136-byte interval, rather than placing a guard inside the neighboring descriptor.
This is not a complete allocation/type-size claim.

Both addresses lie within the reconstructed startup zero region. The native
runner pins the original zero-table record at `0x80c00284`; the host inventory
records its zero-region bounds. Ghidra does not expose those BSS bytes as an
initialized readable block, so they are not treated as copied image bytes.
The harness supplies zero backing according to that startup record.

A separate authored `a5`-filled descriptor case confirms which fields are
overwritten and which survive. Actual DMA initialization clears tracking words
+`0x3c` / +`0x40`, while other unassigned words remain untouched. No IRQ is
delivered in that dirty-state fixture; it is not presented as a valid interrupt
configuration.

Actual registry slots 26/27 receive the **original** transmit/receive pointers,
and QSPI context fields +`0x20` / +`0x24` point to them. This extends the earlier
[QSPI/DMA integration](QSPI_DMA_INTEGRATION.md), which used relocated authored
descriptor backing.

## Initialization-to-transfer and reinitialization

After the actual initialization, selected 64-byte NAND cache read/write cases
run through actual builders, bus transfer, HAL command/DMA wrappers and actual
DMA setup/wait. The private-buffer copy boundaries and all lower register events
are checked together. ROM-version result 2 and generic copy/cache services are
supplied; physical DMA payload movement is still intentionally absent. Sentinel
read-buffer results are authored fixtures, not NAND contents.

A further case starts with bus-reinitialization flag `0x80d81d6c` set and invokes
the cache-read builder directly. Actual bus transfer clears the flag and calls
the complete actual initializer before the version query and transfer. The
descriptor copy's low clock word selects argument 2. This verifies the nested
reinitialization route, not only a manually sequenced setup/transfer.

## Reproduction and remaining work

```sh
python3 analysis_scripts/nand_platform.py firmware/bip6-4.6.0.3.zip \
  --pins-output analysis/nand-pins.json
python3 analysis_scripts/nand_platform.py \
  --vectors-output firmware/nand-platform-native-vectors.json
```

Apply `SeedQspiHal.java` and `SeedNandPlatform.java` to the startup-aware
`boot-runtime` project. Export `nand_platform.py:TARGETS` with
`DecompileWithLogger.java`, logger `0x80c1cd7a`, to
`firmware/decompiled/runtime-nand-platform`, then run:

```text
-postScript ValidateQspiHal.java firmware/nand-platform-native-vectors.json firmware/nand-platform-native-validation.json
```

```sh
python3 analysis_scripts/nand_platform.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-nand-platform \
  --vectors firmware/nand-platform-native-vectors.json \
  --validation firmware/nand-platform-native-validation.json > analysis/nand-platform.json
python3 -m unittest discover -s tests -p 'test_nand_platform.py' -q
```

The runner pins 28 code spans and five original data/table spans, and records
28 fresh export hashes. Each case is bounded to 100,000 steps. It checks all
board/QSPI/DMA events, fences, descriptor/registry/link state, immutable inputs,
memory guards and normal stack/saved-register restoration. Pin helpers claim no
return-value semantics. Earlier QSPI/DMA fixtures retain their earlier boundary
choices and reproduce unchanged with the extended runner.

Remaining work includes complete page/ECC and board/regulator/IRQ integration,
physical pin/package mapping and electrical verification, DMA payload movement,
cache coherency and persistence. BBT/factory-data provenance, SFTL,
device-specific backup/restoration and standalone boot remain open.
