# Main NAND platform, original DMA links and reinitialized bounce transfers

All **14 native transfer cases** pass in **9,235 instruction/service steps**
(maximum **1,057**, reinitialization after prior successful initialization).
Original main platform initialization and its actual adjacent DMA bindings now
join NAND bus conversion, actual revision/QSPI/DMA backend and selected bounce
transfers. [main-nand-platform-transfer.json](main-nand-platform-transfer.json)
records **21 code/export and four data hashes**, complete observations and
limitations.

This extends the [authored-descriptor QSPI/DMA scope](MAIN_QSPI_DMA.md).
Here the platform publishes original records at `0x80c10df4`/`0x80c10db0`; the
preceding scope preserves its separate fixture pointers. The first chip
descriptor is cloned to vary its clock word. Pin/GPIO/cache/copy bodies,
MMIO/reset/status/timestamps/ROM backing and physical data movement remain
supplied or outside execution. Full chip detection, UID/BBT/media and outer
probe/root are not executed here.

## Transfer and reinitialization order

Normal cases run the real platform initializer first, then original NAND bus
transfer. Deferred cases instead enter transfer with a pending reinitialization
flag: the actual bus clears it before calling the real initializer with the
descriptor context, then follows revision and command/DMA execution.

A separate case explicitly initializes successfully while leaving the flag
pending, then enters transfer. The platform runs **twice**, retaining the same
record addresses and untouched private fields. The second clock selection
refreshes its shadow without another write when the selector already matches.
Both QSPI reset sequences and both pairs of fences are captured.

| Selected blocked state | Original observed result |
| --- | --- |
| Disabled and pending before initialization | `-1`, flag still pending, no platform/clock/revision/command calls and no registry publication |
| Explicit initialization followed by disabled transfer | `-1`, original DMA/controller links retained, flag still pending; no revision/command calls |

The disabled check precedes clearing the reinitialization flag. Initialization
alone does not make a blocked transfer run, and a pending flag does not prove
that its initialization call occurred.

## Completion, partial state and fixture data

Successful read/write follows actual platform, command, DMA setup/wait and
QSPI completion. Primary receive status clears tracking; alternate success
retains the original bounce address and length. Backend or later QSPI timeout
reaches the original bus assertions, owner `0x70a1bca8`, lines 374/386, with
request-bit cleanup and original DMA registry links retained.

There is no modeled physical DMA movement. Successful receive can therefore
copy unchanged authored `0xa5` bounce bytes to the caller; timeout skips copyback.
These are software control/state observations over explicit peripheral inputs,
without proof of real data delivery, electrical operation or cache coherency.

## Reproduction and regression

Generate vectors with:

```sh
python3 analysis_scripts/main_nand_platform.py --scope transfer \
  --vectors-output firmware/main-nand-platform-transfer-vectors.json
```

Use the same seeded project/environment and `ValidateMainNandPlatform.java`
command as [MAIN_NAND_PLATFORM.md](MAIN_NAND_PLATFORM.md), substituting
`firmware/main-nand-platform-transfer-vectors.json` and
`firmware/main-nand-platform-transfer-validation.json`. Both scopes share exports:

```sh
python3 analysis_scripts/main_nand_platform.py firmware/bip6-4.6.0.3.zip \
  --scope transfer --decompiled firmware/decompiled/runtime-main-nand-platform \
  --vectors firmware/main-nand-platform-transfer-vectors.json \
  --validation firmware/main-nand-platform-transfer-validation.json
```

Startup facts, both vector sets and both evidence files reproduce. All **347
preceding main native cases reproduce byte for byte**. The existing DMA harness
adds narrow descriptor-pointer/backing hooks and an inheritable I/O filter;
its default behavior and fixed guard configuration are preserved. The two new
scopes add **24 host checks** to the passing **1,774-test suite**.

Next work is full main candidate probe/root through this platform/HAL/backend,
followed by actual UID/workaround/BBT/media, main IRQ/cache bodies and broader
storage callers. Physical coherency/timing, safe restoration and standalone boot
remain separate open requirements.
