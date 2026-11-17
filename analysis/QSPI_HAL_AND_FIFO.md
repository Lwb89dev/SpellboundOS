# QSPI HAL, FIFO transfers, DMA wrappers and connected NAND commands

All 90 native cases pass in 11,326 steps (maximum 522 for connected NAND cache
write). Actual RAM HAL initialization/command/polling/DMA-wrapper routines,
phase/count/status helpers and clock selection execute. Selected actual NAND
builders also run through the actual bus wrapper and HAL to an authored FIFO.
Complete observations and provenance are in [qspi-hal.json](qspi-hal.json).

The initial 81 cases retain identical observations and step counts after adding
the connected command cases. Thirty-seven new host checks bring the full suite
to **1,128 passing tests**.

MMIO is a synthetic peripheral model. Reset clearing, FIFO/status values,
completion acknowledgement, timer/frequency reads and DMA services are authored.
No watch or phone was accessed. This executes another software layer beneath
the preceding [bus](NAND_BUS_AND_COMMANDS.md) and [retry/UID](NAND_RETRY_AND_UID.md)
passes; it does not establish electrical operation or physical DMA completion.

## Controller and clock configuration

Actual initializer `0x80df9220(context)` writes `0x100` at controller +`0x10` and
polls until that bit clears. The fixtures clear it after one or two reads. The
selected loop has no timer-service call; stuck physical reset is not validated.
Unless context word +`0x10` equals 1, it then applies
`(register & 0xffffffec) | context[2] | context[3]`. It preserves other bits,
ORs `0x300` at controller +`0x34` and writes `0x3300` at +`0x20`.

Actual clock selector `0x80df9f80(selector)` reads `0x9a000024` once and updates
only bits 12–15, storing a shadow at `0x80de67dc`. A matching selector skips the
MMIO write. The comparison uses the full argument but the stored selector is
masked to four bits; authored selector 17 can therefore issue a redundant write
of field value 1. No physical frequency or clock-divider calibration is inferred.

## Command register construction

Actual command routine `0x80df928c(context, frame, timeout)` returns 1 for a null
context, frame or controller base before MMIO. Valid fixtures use the original
controller base `0x93240000`; a separate base `0x93200000` exercises the branch
which omits request bit zero.

The eleven-word frame from the earlier bus pass is converted as follows:

| Register offset | Construction |
| --- | --- |
| `0x00` | Frame word 5, address |
| `0x04` | `(word4 << 24) | (word10 << 16) | word7` |
| `0x08` | Word 9, data count |
| `0x0c` | `(opcode << 24) | direction | phase_bits`, plus bit 0 for base `0x93240000` |

The phase helper `0x80df8f38` selects `00/20/40/60/80/a0/c0` from frame words
3, 6 and 8. Unsupported selected codes fall back to zero. Direction/mode 7 adds
bit `0x10000000` to register +4 and also contributes `opcode << 16` to +`0x0c`.

The routine stores data count at context +`0x14`. For nonzero count it returns
zero immediately after register submission. Zero count instead waits for
completion and can return 3 on timeout. Consequently, successful command
submission alone does not prove completion of a data transfer.

## FIFO transfer and software count

Actual direct receive/transmit entries are `0x80df93c4` / `0x80df951c`. They
wait on controller +`0x18`, using bit 1 for receive and bit 0 for transmit. Count
helpers `0x80df91fc` / `0x80df91d8` decode controller +`0x54` and width fields in
+`0x20`. They calculate bytes as `units * 4 >> (3 - width_field)`, using the
receive high-byte or transmit low-byte units. Tests execute all four width codes.

For the initialized `0x3300` configuration, aligned buffers use 32-bit accesses
at FIFO +`0x100` followed by byte tails. Unaligned buffers use byte accesses.
Lengths 0/1/3/4/5/8/9 are covered. The software count is decremented before each
chunk is transferred; success consumes it to zero. A later completion timeout
can therefore return 3 after data was transferred and count reached zero.

The receive/transmit loops query FIFO capacity twice when the first query is
no greater than the remaining count. These fixtures hold capacity stable; races
between those observations remain outside coverage. Zero-length direct calls
skip FIFO data accesses but still perform the final completion wait.

## Timeouts and bounded no-progress prefixes

Actual completion helper `0x80df9000` and receive/transmit wait helpers
`0x80df9098` / `0x80df9138` obtain supplied 64-bit ticks and a supplied frequency.
The tick limit is the 32-bit result of `(frequency / 1000) * timeout`. The division
truncates before multiplication. Tests cover frequency below 1,000, multiplication
wrap, low-word wrap, full 64-bit wrap and elapsed time beyond 32 bits.

Each wait accepts elapsed ticks equal to the limit. After elapsed time exceeds
it, a final status recheck can still produce success. Completion success writes
1 to register +`0x24`; the harness explicitly models that write as clearing the
completion flag. This write-one-to-clear behavior is authored peripheral
semantics, not a hardware measurement.

Each FIFO chunk starts a fresh wait. If the readiness bit is already set but
the FIFO count is zero, the selected code makes no progress and starts another
wait. Bounded prefixes demonstrate four such iterations with count unchanged,
including supplied start times `0, 1001, 2002, 3003` for timeout 1,000 at frequency
1,000. They stop **before a fifth chunk wait**, with no normal return/ABI claim.
The caller timeout is therefore not an observed total-transfer deadline in this
path. This does not establish that real hardware produces that status combination
or that a physical transfer hangs.

## DMA wrapper ordering and error state

Actual DMA receive/transmit entries are `0x80df94bc` / `0x80df960c`. Context
+`0x24` supplies the receive DMA handle; +`0x20` supplies transmit. Underlying
setup `0x80c12628` and wait `0x80c126e0` remain supplied and are not executed here.
The handles are authored opaque pointers, not validated live DMA objects.

Receive requests DMA setup before setting bit 0 of controller +`0x20`; transmit
sets the bit before setup. Both call DMA wait with the caller timeout, then clear
that bit even if it was already set initially. A nonzero wait status is returned
after clearing the bit, without a final controller wait. On supplied DMA success,
the wrapper also waits for controller completion, which can independently time out.

The selected wrappers ignore the setup callback's return value. The fixture
where setup returns `-9` but wait and controller completion succeed returns zero;
the receive buffer remains unchanged because that supplied setup did not copy
bytes. This is an explicit callback-return injection; it does not establish a
naturally reachable negative return from the actual setup implementation or a
functional hardware transfer after DMA failure. Zero-count calls still invoke setup/wait.
These wrappers do not decrement the context count themselves in the covered
paths. Actual DMA internals, descriptor updates and ownership remain open.

## Connected NAND command path

Seven cases execute selected original NAND builders, actual bus transfer
`0x80c106f0`, actual HAL command/data routines and the authored FIFO:

- Feature read `0f`, register `b0`, receives one FIFO byte.
- Feature write `1f`, register `b0`, sends the local argument byte `a5`.
- Cache read `03` and quad cache write `32` transfer nine bytes through the
  actual packet/frame/phase conversion.
- Feature receive/transmit completion timeouts reach platform assertion lines
  `0x12a` / `0x132`, owner `0x80c37b7c`, after the actual HAL returns 3.
- Zero-count write-enable command `06` times out in the actual command wait
  and reaches platform assertion line `0x11f`.

The assertion cases execute the error log and supplied diagnostic, then stop
before the assertion body. They claim no return ABI. The connected cases use
the original first descriptor and bus binding, a supplied ROM-version result 2,
direct-mode packets, cleared reinitialization flag and an authored controller
context. They do not execute full board initialization, private-buffer transfer
or a physical page/ECC operation.

## Reproduction and remaining work

```sh
python3 analysis_scripts/qspi_hal.py \
  --vectors-output firmware/qspi-hal-native-vectors.json
```

Apply `SeedQspiHal.java` to the startup-aware `boot-runtime` project. Export
`qspi_hal.py:TARGETS` with `DecompileWithLogger.java`, logger `0x80c1cd7a`, to
`firmware/decompiled/runtime-qspi-hal`, then run:

```text
-postScript ValidateQspiHal.java firmware/qspi-hal-native-vectors.json firmware/qspi-hal-native-validation.json
```

```sh
python3 analysis_scripts/qspi_hal.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-qspi-hal \
  --vectors firmware/qspi-hal-native-vectors.json \
  --validation firmware/qspi-hal-native-validation.json > analysis/qspi-hal.json
python3 -m unittest discover -s tests -p 'test_qspi_hal.py' -q
```

Nineteen code and three original data ranges are guarded. Each case is bounded
to 100,000 steps. Unexpected PCs, MMIO widths/offsets and DMA/service arguments
fail validation. The runner compares every MMIO/timer/DMA/log event, context
count and preserved fields, input/frame immutability, buffer hashes/guards and
normal return ABI or explicit stops. Nineteen fresh export hashes are recorded.

Next work includes actual DMA initialization/setup/wait/IRQ behavior, remaining
pin/board services and complete page/private-buffer-to-HAL integration. Physical
timing, FIFO/ready/W1C semantics, clock calibration, coherency and persistence
remain unverified. BBT creation/provenance, SFTL, device-specific backup/
restoration and standalone signed-chain boot remain open.

The subsequent [DMA backend pass](DMA_BACKEND_AND_IRQ.md) executes actual
initializer/setup/wait/cancel/count/IRQ code, including connected backend flows.
The earlier QSPI pass retains its supplied DMA boundary. Integration between
these two executed layers and real DMA/IRQ/coherency remain open.

The later [connected QSPI/DMA pass](QSPI_DMA_INTEGRATION.md) enables actual DMA
backend execution for explicit new fixtures and connects private-buffer NAND
builders too. This earlier 90-case native report remains byte-for-byte identical
with the extended runner; its original DMA services remain supplied.
