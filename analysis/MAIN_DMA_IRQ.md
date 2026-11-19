# Original main DMA IRQ dispatch and registry fallback

All **26 native cases** pass in **3,809 instruction/service steps** (maximum
**279**, connected initialization/setup/dispatch). Original handler `0x702a041c`
now executes over authored pending words, MMIO and guarded descriptor/registry
backing. [main-dma-irq.json](main-dma-irq.json) records **nine code/export hashes**,
complete observations and limitations. Initialization/setup/cancel/count/wait
remain described in [MAIN_DMA_BACKEND.md](MAIN_DMA_BACKEND.md).

The harness calls the handler as an ordinary function. It does not execute an
interrupt vector, trap entry/exit, controller delivery, nesting or RTOS scheduling.
Callbacks and cache services are supplied in this IRQ scope. The subsequent
[actual cache-guard scopes](MAIN_DMA_CACHE_GUARDS.md) execute the selected original
cache entry/return paths too. No physical DMA data movement is modeled.

## Bank selection and acknowledgement

The handler reads controller pending words at +4 and +12, then **writes those
complete words** to +8 and +16 before channel work. These writes replace the
old authored values rather than ORing them, unlike the completion-wait helper.
Pending bits outside 0–6 are still acknowledged but do not dispatch a channel.

| Supplied controller base | Registry indices walked |
| --- | --- |
| `0x92000000` | 0–6 |
| `0x93000000` | 7–13 |
| `0x93040000` | 14–20 |
| `0x93080000` | 21–27 |
| Unrecognized base (`0x93100000` in cases) | 28–34 |

The last branch agrees with the main initializer's fallback publication. It
executes without the boot image's fatal-boundary behavior. The harness explicitly
supplies 35 slots plus guards; this does not establish production allocation
extent, a valid fifth hardware bank or a memory-corruption finding.

Each iteration loads a registry pointer; descriptor fields are consumed only
for active pending bits. Active slots must be populated in this scope. Empty
registry cases cover no pending bits and unwalked high bits. Missing active
entries and concurrent registry changes remain outside coverage.

The `0x92000000` IRQ walk includes channel 6, although the initializer rejects
channels above 3 for that base. A supplied registered channel-6 context verifies
this software difference; it does not establish a usable physical channel.

## Tracking, linked flag and callback order

| Pending group | Channel state and tracking | Supplied callback observation |
| --- | --- | --- |
| Primary only | Stop channel if descriptor +40 is zero; finish tracked cache range and clear +60/+64 | Primary callback sees zero tracking |
| Alternate only | Always stop channel; preserve tracking without finish | Alternate callback sees retained tracking |
| Both | Primary work first, then alternate stop | Primary callback followed by alternate, both seeing zero tracking |

Any nonzero linked word preserves the channel in the primary-only branch; both
one and `0x80000000` are covered. Alternate handling still stops it. Missing
callbacks do not skip the branch's cleanup. Empty tracking still reaches finish
with `(0, 0)`.

Primary callback comes from descriptor +48. Alternate pointer at +52 carries
an authored low bit; actual invocation reaches the even service address, matching
RISC-V indirect-call masking. Callback bodies remain supplied. These observations
establish arguments, order and visible tracking, not application behavior.

Two-channel cases verify ascending pending-bit order even when descriptor backing
is stored in reverse order. Fallback tests cover slots 28 and 34 together.
Connected init/setup-IRQ cases execute actual registry publication, interrupt-mask
changes and dispatch for both a recognized and the fallback bank.

IRQ return values are unspecified. Normal stack and saved-register preservation
are checked; no return-value contract is inferred from residual argument registers.
Source/destination bytes and descriptor fields outside tracking remain unchanged.

## Reproduction and remaining work

Use the startup-aware main project and prior main DMA metadata. The seed guards
the complete 250-byte IRQ body and two original 100-byte cache routines before
updating signatures/bodies. No firmware bytes or instruction semantics change.

```sh
python3 analysis_scripts/main_dma_irq.py --scope irq \
  --vectors-output firmware/main-dma-irq-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainDmaIrq.java \
  -postScript ValidateMainDmaIrq.java \
  firmware/main-dma-irq-vectors.json firmware/main-dma-irq-validation.json

python3 analysis_scripts/main_dma_irq.py firmware/bip6-4.6.0.3.zip \
  --scope irq --decompiled firmware/decompiled/runtime-main-dma-irq \
  --vectors firmware/main-dma-irq-vectors.json \
  --validation firmware/main-dma-irq-validation.json
```

Export `main_dma_irq.RANGES` with `DecompileWithLogger.java`, logger `0x702b38a2`.
Use the new export directory because added cache signatures can change displayed
call names in decompilation. Firmware and exports stay local. The 10,000-step
bound remains fixed. All **46 preceding main backend cases reproduce byte for
byte** after the narrow harness hooks and metadata seed.

Live interrupt-controller delivery, vector/context integration, actual callback
consumers, removal/reclamation/concurrency, positive-address cache CSR paths,
physical status meanings/coherency/timing/data movement, persistence, safe
backup/restoration and standalone boot remain open.
