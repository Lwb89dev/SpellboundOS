# Actual main QSPI/DMA backend and NAND bounce packets

The later [main NAND platform scope](MAIN_NAND_PLATFORM.md) and
[reinitialized transfer scope](MAIN_NAND_PLATFORM_TRANSFER.md) use the original
adjacent DMA addresses. This earlier evidence preserves its authored descriptors.

All **28 native cases** pass in **11,758 instruction/service steps** (maximum
**574**, NAND bounce transmit with QSPI completion timeout). Actual main DMA
init/setup/wait now joins original main QSPI command/completion/DMA wrappers
and selected original NAND bounce-packet transfers.
[main-qspi-dma.json](main-qspi-dma.json) records **21 code/export and four data
hashes**, complete observations and limitations.

This extends the [main bus/HAL scope](MAIN_QSPI_BUS.md), whose DMA setup/wait
remains supplied. Here two authored 80-byte descriptors are initialized by
actual code, registered at the main table and used through the QSPI context's
DMA pointers. The main platform initializer's original descriptor addresses,
full candidate probe/root, IRQ delivery and cache bodies remain outside this
scope. MMIO/status/timestamps/ROM backing and bounded cache/copy services remain
authored. Physical DMA data movement is deliberately not simulated.

## Actual initialization, setup and status cleanup

Original initializers publish TX channel 5 and RX channel 6 in main registry
slots 26/27. The descriptor pointers are authored at `0x81304000`/`0x81305000`.
QSPI calls real DMA setup with its peripheral FIFO address and the direct caller
buffer or NAND bounce buffer. Actual DMA code programs addresses/count, cache
service arguments and channel start. QSPI then enables its request bit and calls
the real backend wait; no supplied setup/wait result substitutes for those bodies.

The selected cases cover primary, alternate and both status bits, timeout,
zero size, unaligned caller pointers, counter wrap and command-to-DMA linkage.
Primary success clears receive tracking; alternate success retains destination/
length while also returning zero. Both flags take the primary cleanup path.
Backend timeout returns 3. QSPI clears its request bit after waiting, then uses
its separate completion wait only if the backend returned zero.

## Separate waits and failure consequences

Selected cases reach backend readiness at its exact limit, then finish a
separate QSPI completion wait. The code does not combine these two budgets into
one end-to-end deadline. DMA and QSPI tick services are separate supplied inputs;
their physical rates and relationship remain unverified.

A backend timeout propagates through the DMA wrapper. A later QSPI timeout can
also return 3 after successful backend cleanup. For NAND bounce read/write, both
failures reach the original bus assertions at owner `0x70a1bca8`, lines 374/386.
Assertion bodies and recovery do not run. Descriptor, registry, request-bit,
tracking and output state are captured at these boundaries.

## Control success without modeled data delivery

Successful direct DMA cases leave caller bytes unchanged and record no FIFO
payload accesses. This is the authored peripheral model's result; it does not
establish actual DMA delivery. Successful NAND bounce receive similarly copies
the initial `0xa5` bounce bytes back to the caller. Backend status/cleanup and
copyback are actual software behavior; sentinel contents are fixture inputs.

Timeout skips receive copyback. Alternate status can permit successful copyback
while leaving receive tracking live. These observations distinguish software
completion/cleanup from independently verified data, cache coherency and physical
media operation.

## Reproduction and regression

```sh
python3 analysis_scripts/main_qspi_dma.py \
  --vectors-output firmware/main-qspi-dma-vectors.json
```

Use the seeded startup-aware project and headless environment from
[MAIN_DMA_BACKEND.md](MAIN_DMA_BACKEND.md), then run:

```text
-postScript ValidateMainQspiDma.java \
firmware/main-qspi-dma-vectors.json firmware/main-qspi-dma-validation.json
```

```sh
python3 analysis_scripts/main_qspi_dma.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-qspi-dma \
  --vectors firmware/main-qspi-dma-vectors.json \
  --validation firmware/main-qspi-dma-validation.json
```

Export addresses from `ranges()` in `analysis_scripts.main_qspi_dma` using
`DecompileWithLogger.java`, logger `0x702b38a2`. The existing main HAL harness now
has a default I/O-filter factory hook; its prior behavior and configuration are
unchanged. Both new evidence files and vectors reproduce. All **273 preceding
main native cases reproduce byte for byte**. The two scopes add **28 host
checks** to the passing **1,750-test suite**.

Next work is original main platform/DMA descriptor linkage and reinitialization,
then full probe/root through HAL/backend and main UID/workaround/BBT/media. Main
IRQ dispatch, cache maintenance, physical coherency/timing, safe restoration and
standalone boot remain open.
