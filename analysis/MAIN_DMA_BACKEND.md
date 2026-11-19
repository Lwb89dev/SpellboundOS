# Original main DMA initialization, setup, cancel, count and wait

All **46 native cases** pass in **3,021 instruction/service steps** (maximum
**204**, connected initialization/setup/wait timeout). Original main DMA bodies
execute over authored descriptors, register backing, status/timestamps and
supplied cache services. [main-dma-backend.json](main-dma-backend.json) records
**six code/export hashes**, complete observations and limitations.

| Body | Main address |
| --- | --- |
| Initialization | `0x702a0038` |
| Setup with interrupt-mask changes | `0x702a01c0` |
| Cancellation | `0x702a0264` |
| Setup | `0x702a02a0` |
| Remaining-count query | `0x702a0338` |
| Completion wait | `0x702a0358` |

The policy model shares the previously checked boot DMA implementation where
native observations agree. Main instructions and ABI are checked independently.
Main IRQ dispatch and cache-maintenance bodies remain outside this scope;
callback pointer fields are preserved fixture data, not exercised callbacks.
The subsequent [main IRQ scope](MAIN_DMA_IRQ.md) executes original dispatch and
callback boundaries; [cache-guard scopes](MAIN_DMA_CACHE_GUARDS.md) execute the
selected original signed entry guards too.

## Initialization and registry fallback

Initialization rejects channels over 6 and channels over 3 for base
`0x92000000` before register accesses. It enables the authored engine when needed,
clears tracked address/length at descriptor +60/+64, programs control/request/
width/increment fields and publishes the descriptor in registry `0x80c11738`.

The four explicitly recognized bases use bank offsets 0, 7, 14 and 21 for
`0x92000000`, `0x93000000`, `0x93040000` and `0x93080000`, respectively. Tests cover
each bank, NAND-style channels 5/6, disabled/already-enabled control and field
masking. Source-width shifts in setup use the low five bits: width 32 produces
the same transfer-count shift as zero.

Main differs from the earlier boot initializer for an unrecognized base. The
main body falls through to **slot `28 + channel`** and returns zero instead of
calling the boot fatal boundary. For authored base `0x93100000`, channel 5,
native execution writes fixture descriptor pointer into slot 33. The harness
provides 35 slots plus guards explicitly. This establishes the original computed
write, without establishing a valid fifth hardware bank, production allocation
extent or a memory-corruption claim.

## Tracking, setup and cancellation

Memory/receive modes track the destination and length; transmit mode clears
tracking. Cache prepare receives the applicable source/destination ranges.
Setup programs addresses/count and starts the selected channel. The interrupt
variant additionally clears two mask bits before starting. Count query returns
1 for null context/output without writing the sentinel output; valid query
returns the authored channel count.

Cancellation calls supplied cache finish for the tracked range, clears tracking,
sets the cancel bit and clears start. Even an empty tracked range reaches the
supplied finish service. Cache calls establish arguments/order only, without
physical maintenance or coherency evidence.

## Wait, status priority and cleanup

Native observations read **both** status registers +20/+24 before choosing the
primary branch, including when primary is already set. The decompiled control
expression alone could suggest short-circuit reading; the emulator trace is
the recorded access order. Both registers are read again on timeout recheck.

| Selected status result | Original return and retained tracking |
| --- | --- |
| Primary bit set, including both set | Zero; supplied cache finish, tracking cleared |
| Alternate bit only | Zero; tracking retained, no finish call |
| Neither bit before expiration/recheck | 3; tracking retained |

All selected completion/timeout paths acknowledge both interrupt groups and
clear channel start. The labels primary/alternate identify software branches;
hardware meanings of these bits remain unverified. Exact deadline, low-word/
full-counter wrap, high-word expiration, unrelated bits and ready-on-recheck
cases execute using supplied 64-bit tick reader `0x80d45464`. No elapsed-time
calibration or actual peripheral completion is established.

## Reproduction and continuation

```sh
python3 analysis_scripts/main_dma_backend.py \
  --vectors-output firmware/main-dma-backend-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainDmaBackend.java \
  -postScript ValidateMainDmaBackend.java \
  firmware/main-dma-backend-vectors.json firmware/main-dma-backend-validation.json

python3 analysis_scripts/main_dma_backend.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-main-dma-backend \
  --vectors firmware/main-dma-backend-vectors.json \
  --validation firmware/main-dma-backend-validation.json
```

Use the existing startup-aware main project. The seed assigns reviewed function
metadata, including the complete wait timeout-result tail; image bytes are
unchanged. Export addresses in `RANGES` from `analysis_scripts.main_dma_backend`
with `DecompileWithLogger.java`, logger `0x702b38a2`. Firmware/exports stay local.
Code hashes, return ABI, descriptor fields/guards, payload immutability and
35-slot registry guards are checked.

The [main QSPI/DMA scope](MAIN_QSPI_DMA.md) joins actual setup/wait to QSPI and
NAND bounce packets. Main IRQ, real cache maintenance/data movement, original
platform bindings and full probe/root/media integration remain open.
