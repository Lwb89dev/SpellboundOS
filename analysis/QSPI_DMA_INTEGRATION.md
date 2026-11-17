# Connected QSPI/DMA backend and NAND private-buffer transfers

All 28 native cases pass in 11,754 steps, with a maximum of 567 for private-buffer
NAND write followed by controller timeout. Actual QSPI command/DMA wrappers and
DMA initialization/setup/wait execute together. Selected actual NAND cache
builders also run through the bus wrapper, private buffer, HAL and DMA backend.
Complete observations and provenance are in [qspi-dma.json](qspi-dma.json).

The extended QSPI runner reproduces its previous 90-case native report byte for
byte. The original 60-case backend report remains exactly reproducible after
allowing relocated descriptors and caller-selected setup addresses in the host
model. Twenty-two new host checks bring the suite to **1,185 passing tests**.

Peripheral status, timestamps, cache-maintenance bodies, ROM-version result and
generic copy services remain supplied. **Physical DMA payload movement is
intentionally not simulated.** A zero control-path result therefore does not
establish delivered data. No watch or phone was accessed.

## Connection between the previously separate layers

The [QSPI HAL pass](QSPI_HAL_AND_FIFO.md) supplied DMA setup/wait callbacks. The
[DMA backend pass](DMA_BACKEND_AND_IRQ.md) executed those routines independently.
This pass removes that callback interception for selected fixtures:

```text
actual QSPI DMA wrapper
  → actual DMA setup 0x80c12628
  → actual DMA wait 0x80c126e0
  → actual QSPI completion wait
```

Both DMA descriptors are initialized by actual `0x80c123ac` before the selected
transfer. Their fields match the earlier NAND-style transmit/receive configurations:
request 12, controller `0x93080000`, channels 5/6, byte widths and opposite
source/destination increment settings. The fixture relocates the descriptors to
`0x81304000` / `0x81305000`; they are not live hardware objects. Both are published
in registry slots 26/27. The controller enable write occurs only once across
the two actual initializations, and later initialization preserves prior
channel-state writes.

The actual QSPI context points to these descriptors. Receive setup programs
source `0x93240100` and the caller buffer as destination; transmit reverses those
roles. Initializer masks/configuration, setup/cache requests, wait cleanup and
QSPI register changes are compared as one ordered event stream.

Receive still requests backend setup before setting QSPI DMA-enable bit zero;
transmit sets that bit before setup. Caller addresses offset by one byte are
programmed unchanged in the selected unaligned fixtures. Zero-count calls still
execute actual setup and wait. These observations do not establish peripheral
alignment requirements or functional zero-length hardware transfers.

## Completion and residual state

As in the backend report, status **A** and **B** name tested software branches,
not independently verified hardware completion/error meanings.

| DMA result | QSPI outcome | Receive tracking |
| --- | --- | --- |
| A observed, controller completes | Returns zero | Finalized through supplied cache helper, then cleared |
| B observed, controller completes | Returns zero | Destination/count preserved |
| Both observed | A cleanup takes precedence | Cleared |
| Neither before DMA timeout | Returns 3 without controller wait | Preserved |
| A observed, later controller timeout | Returns 3 | Already cleared |

Both the backend channel enable and the QSPI DMA-enable bit are cleared on the
covered timeout paths. A successful wrapper return on B still leaves the tracked
receive range live. Transmit preparation clears tracking for its mode, so its B
case has different residual state despite the same zero result.

The software context data count remains the submitted count in these DMA
wrappers. The emulated peripheral does not decrement the programmed hardware
count, so its final register value is not evidence of physical DMA progress.

## Independent wait budgets

The wrapper passes the full caller timeout to DMA wait, then uses the full value
again for controller completion. It does not subtract elapsed DMA time.

Two connected cases use DMA timestamps `[0, 1000]` and controller timestamps
`[1000, 2000]`, with timeout 1,000 and supplied controller frequency 1,000. Each
wait completes exactly at its inclusive limit and the wrapper returns zero.
This establishes separate software budgets in the authored timing scenario,
not a measured two-second duration or calibrated relationship between physical
clock domains. Full-counter wrap handling and independent controller
timeout after DMA success are covered.

## NAND private-buffer path

Selected original cache builders `0x80c27f3e` / `0x80c280d0` request quad read
`6b` / write `32` without forcing direct mode. At 64 bytes and supplied ROM
version result 2, the actual bus wrapper selects private buffer `0x80dfb8c0`:

```text
actual NAND cache builder
  → actual NAND bus 0x80c106f0
  → actual HAL command conversion
  → actual QSPI DMA wrapper
  → actual DMA setup/wait
  → actual QSPI completion
```

Writes request a supplied copy from caller buffer to the private buffer before
submitting the command. Actual DMA setup then uses that private buffer as source.
Reads set it as DMA destination and request copy-back to the caller only after
both waits return success. Copy arguments, count, content hashes and ordering
are checked; the generic memcpy implementation itself is supplied.

Because no DMA payload movement is simulated, successful read fixtures copy
the authored private-buffer `a5` bytes. Their purpose is to verify the connected
control/copy path, not to present those bytes as NAND data. B-status read success
can request copy-back while tracking still names the private buffer/count.

Actual DMA timeout and later controller timeout both reach the platform's
private-buffer error log, supplied diagnostic and assertion: owner
`0x80c37b98`, line `0x16f` for receive or `0x17b` for transmit. Execution stops
before the assertion body, with no return ABI claim. Failed reads do not request
copy-back. Receive tracking remains set after DMA timeout but is already cleared
after an A-status DMA success followed by controller timeout. Failed writes can
leave the earlier input copy in the private buffer; no rollback is claimed.

The connected cases use the original first chip descriptor/bus binding, supplied
ROM-version result 2, a cleared bus-reinitialization flag and authored initialized
QSPI context. They do not execute complete board/pin initialization or page/ECC
operations. The 512-byte private-buffer backing is a harness bound, not proof of
its actual firmware allocation size.

## Reproduction and boundaries

```sh
python3 analysis_scripts/qspi_dma.py \
  --vectors-output firmware/qspi-dma-native-vectors.json
```

Apply `SeedQspiHal.java` to the startup-aware `boot-runtime` project. Export
`qspi_dma.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`, to
`firmware/decompiled/runtime-qspi-dma`, then run the extended runner:

```text
-postScript ValidateQspiHal.java firmware/qspi-dma-native-vectors.json firmware/qspi-dma-native-validation.json
```

```sh
python3 analysis_scripts/qspi_dma.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-qspi-dma \
  --vectors firmware/qspi-dma-native-vectors.json \
  --validation firmware/qspi-dma-native-validation.json > analysis/qspi-dma.json
python3 -m unittest discover -s tests -p 'test_qspi_dma.py' -q
```

The runner retains supplied DMA services for the earlier QSPI fixtures; only
`native_dma` fixtures execute the additional code. Twenty-four code spans and
three original data spans are guarded, and 24 fresh export hashes are recorded.
Each case is bounded to 100,000 steps. All MMIO/timer/cache/copy/log events,
descriptor tracking/registry state, preserved context fields, buffer hashes/
guards and normal return ABI or explicit assertion stops are checked. The prior
90-case report is unchanged with the extended runner.

Remaining work includes complete page/board integration, original factory-data
and BBT provenance, SFTL, physical DMA payload movement, IRQ delivery and cache
coherency. Physical status meanings, timing, persistence, device-specific backup/
restoration and standalone signed-chain boot remain unresolved.

The subsequent [NAND platform pass](NAND_PLATFORM_AND_PINS.md) executes actual
pin controls and complete selected bus initialization at the original adjacent
DMA addresses, including initialization-to-transfer and nested reinitialization.
This earlier pass retains its relocated descriptor fixtures; physical DMA,
coherency and complete board startup remain unvalidated.

The later [connected page-read pass](NAND_READ_STACK.md) executes actual page
read and BBT mapping through status/cache builders, platform, QSPI and DMA,
including full busy-timeout and selected ECC/assertion behavior. Hardware inputs
remain authored.
