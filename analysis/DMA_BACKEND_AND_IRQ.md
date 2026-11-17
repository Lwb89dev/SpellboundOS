# DMA backend initialization, setup, wait, cancel and IRQ dispatch

All 60 native cases pass in 4,898 steps (maximum 280 for connected initialization,
setup and IRQ dispatch). Actual DMA initializer, both setup variants, cancellation,
remaining-count query, polling wait and IRQ handler execute. Complete observations
and provenance are in [dma-backend.json](dma-backend.json). Thirty-five new host
checks bring the full suite to **1,163 passing tests**.

This follows the [QSPI HAL pass](QSPI_HAL_AND_FIFO.md), which supplied DMA setup
and wait services. Here those backend routines execute independently and in
connected init→setup→wait/IRQ cases. Cache-maintenance bodies, timestamps,
callbacks, descriptors and MMIO/status values remain supplied. Physical DMA
movement, cache coherency and actual interrupt delivery are not established.
No watch or phone was accessed.

## Controller banks and descriptor state

Actual initializer `0x80c123ac(descriptor)` accepts four controller bases and
publishes the descriptor into the 28-pointer registry at `0x80de65ec`:

| Controller base | Registry start slot | Initializer channel range |
| --- | ---: | --- |
| `0x92000000` | 0 | 0–3 |
| `0x93000000` | 7 | 0–6 |
| `0x93040000` | 14 | 0–6 |
| `0x93080000` | 21 | 0–6 |

Initializer channel rejection returns 1 before MMIO. An unknown base reaches a
fatal boundary only after selected register/context changes; it does not roll
them back. Those cases stop at `0x80c1b5c0`, line `0x2a`, before the fatal body
and claim no return ABI.

Relevant descriptor offsets are:

| Offset | Observed use |
| --- | --- |
| `0x00` | Request field, masked to four bits during initialization |
| `0x04` | Direction/mode selector |
| `0x08` / `0x0c` | Source/destination increment fields |
| `0x10` / `0x14` | Source/destination width fields |
| `0x18` / `0x1c` | Burst/priority fields |
| `0x20` / `0x24` | Controller base / channel |
| `0x28` | Linked-mode flag used by IRQ primary-status path |
| `0x30` / `0x34` | Primary/alternate IRQ callback pointers |
| `0x3c` / `0x40` | Tracked destination / byte count for cache finalization |

The fixtures provide 80-byte descriptor backing; this is not an allocation-size
claim. Initialization clears the tracking pair, sets controller enable bit zero
if needed, requests channel status clearing and programs channel registers at
`base + channel * 0x20 + 0x100`. The linked-list register at +`0x110` is cleared.
Other descriptor fields remain unchanged.

The authored NAND-style transmit/receive configurations at base `0x93080000`
use channels 5/6 and the field values from the preceding platform-initialization
pass. Native control/configuration results are `0x460090` / `0x3807` for transmit
and `0x4600c0` / `0xe7` for receive. Numeric fields are masked during construction;
the tested mode-3 and oversized-field fixtures do not cause general enum rejection.
This does not establish the fitted controller or electrical configuration.

## Transfer setup and count units

Actual setup `0x80c12628(descriptor, source, destination, bytes)` selects cache
requests and tracking based on mode:

| Mode | Cache preparation requests | Destination tracking |
| ---: | --- | --- |
| 0 | Source and destination | Destination / byte count |
| 1 | Destination | Destination / byte count |
| 2 | Source | Cleared |
| 3, authored | None in selected path | Previous tracking preserved |

It writes source/destination to channel +`0x108` / +`0x10c` and count to +`0x114`,
then sets channel control bit zero. Count is `bytes >> (source_width & 31)`;
13 bytes produce counts 13/6/3/1 for widths 0/1/2/3. A width-32 fixture uses shift
zero. The selected setup does not round up or reject the non-integral byte
counts used here. Zero bytes still program and enable the channel.

Variant `0x80c12548` additionally clears configuration bits zero and one at
channel +`0x104` before enabling. This report calls it the IRQ setup variant
because it is paired with IRQ dispatch in the fixtures; the electrical meaning
of those bits is not independently verified. Both selected setup bodies return
zero. No negative setup return is observed here; the earlier QSPI pass's injected
negative callback return remains a synthetic wrapper-branch test.

## Polling wait and status precedence

Actual wait `0x80c126e0(descriptor, timeout)` samples supplied 64-bit scaled ticks
from `0x80c121e4`. For clarity, this report calls the tested bit at controller
+`0x14` **status A** and the bit at +`0x18` **status B**. These names describe
software branches, not confirmed hardware completion/error meanings.

The actual instructions load both status words before choosing the branch. A
matching channel bit in either word can produce return **zero**, with different
state transitions:

| Observed status | Return | Cache-finalization request | Tracking pair |
| --- | ---: | --- | --- |
| A set | 0 | Requested with tracked address/count | Cleared |
| B set, A clear | 0 | None | Preserved |
| Both set | 0 | A takes precedence | Cleared |
| Neither before timeout | 3 | None | Preserved |

Every covered exit ORs the channel mask into controller +8 and +`0x10`, then
clears channel-enable bit zero. The harness records those writes without
claiming physical acknowledgement semantics.

Elapsed ticks equal to the limit are accepted. A final status recheck can still
produce zero after elapsed time exceeds it. Tests cover both final branches,
low-word/full-64-bit wrap and elapsed time beyond 32 bits. Unrelated channel
bits do not complete the wait. Timestamp frequency and physical timeout duration
remain unverified.

The status-B result is particularly relevant to callers: a zero wait result does
not prove that the tracked destination was finalized or cleared. The physical
meaning of B must be corroborated before calling that path an error or success
on actual silicon.

## Cancellation and remaining-count query

Actual cancel `0x80c125ec` requests cache finalization, clears tracking, sets
channel-control bit 15 and clears bit zero. It requests the cache helper even
for an empty tracking pair; the helper body is supplied here.

Actual query `0x80c126c0(descriptor, output)` copies channel +`0x114` and returns
zero. Null descriptor or output returns 1 without writing output. This reports
the register's count units; it does not establish byte progress on hardware.

## IRQ dispatch

Actual handler `0x80c1279c(base)` reads pending words at controller +4 / +`0x0c`,
writes those masks to +8 / +`0x10` and walks seven registry slots in the selected
bank. The handler is called normally by the fixture; IRQ entry/exit, nesting and
interrupt-controller delivery are not executed.

For each channel with a primary pending bit, it disables the channel when the
linked flag is zero, requests cache finalization, clears tracking and then calls
the optional primary callback. With linked flag one, that branch keeps the
channel enabled but still finalizes/clears tracking. The alternate pending bit
always disables the channel and calls its separate optional callback, leaving
tracking unchanged by that branch. Its callback pointer has its low bit cleared
before invocation.

If both pending bits are set, primary handling runs first, followed by alternate
handling; the alternate callback sees already-cleared tracking. A two-channel
case verifies ordering across channels and both callbacks. Missing callbacks are
skipped. No pending bits permits an empty registry. Bit 7 is outside the selected
seven-slot walk; its mask is still included in the acknowledgement write.

The initializer's restricted 0–3 range at `0x92000000` differs from the handler's
seven-slot walk. Active fixture bits always have registered contexts. Null active
registry entries, concurrency and real interrupt sources remain outside coverage.
IRQ return-value semantics are not claimed; stack and saved-register preservation
are checked on normal returns.

## Reproduction and remaining work

```sh
python3 analysis_scripts/dma_backend.py \
  --vectors-output firmware/dma-backend-native-vectors.json
```

Apply `SeedDmaBackend.java` to the startup-aware `boot-runtime` project. Export
`dma_backend.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`, to
`firmware/decompiled/runtime-dma-backend`, then run:

```text
-postScript ValidateDmaBackend.java firmware/dma-backend-native-vectors.json firmware/dma-backend-native-validation.json
```

```sh
python3 analysis_scripts/dma_backend.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-dma-backend \
  --vectors firmware/dma-backend-native-vectors.json \
  --validation firmware/dma-backend-native-validation.json > analysis/dma-backend.json
python3 -m unittest discover -s tests -p 'test_dma_backend.py' -q
```

Seven original code ranges and seven fresh export hashes are pinned. Every case
is bounded to 100,000 steps. The runner rejects unexpected PCs, MMIO offsets/
widths and cache/callback arguments. It checks full register/timer/cache/callback
traces, complete descriptor/tracking and registry state, normal return ABI or
fatal stops, memory guards and source/destination immutability. The latter checks
also ensure the emulated CPU does not silently manufacture a DMA data copy.

Next work includes connecting actual QSPI wrappers to this backend, live DMA/IRQ
delivery, real cache maintenance/coherency and remaining board/pin services.
Physical status-bit meanings, timing, payload movement, storage persistence,
backup/restoration and standalone signed-chain boot remain unresolved.

The subsequent [connected QSPI/DMA pass](QSPI_DMA_INTEGRATION.md) links actual
QSPI wrappers and selected NAND private-buffer builders to actual backend
initialization/setup/wait. The physical DMA data path, cache coherency and IRQ
delivery remain unvalidated.
