# Main NAND geometry through original context, chip and BBT-active code

All **13 native cases** pass in **4,213 instruction/service steps**
(maximum **499**, `main_stack_geometry`). The [main NAND object consumer](MAIN_NAND_OBJECT.md)
now executes the original lower ioctl, context/lock wrappers, chip query switch
and BBT-active body. Their results are read from original descriptor bytes and
an authored BBT-magic word, replacing the preceding supplied geometry results.
Evidence and **14 code/export plus 13 data hashes** are in
[main-nand-query-stack.json](main-nand-query-stack.json).

The selected descriptor pointer, magic, mutex handle and RTOS results remain
authored. This does not execute the main probe, BBT recovery/CRC or NAND media
transport, and establishes no fitted chip, physical capacity or valid stored BBT.
No device was accessed.

## Original geometry data flow

Generic ioctl and the original NAND method issue queries 13, 2, 1, 14. Actual
lower wrapper `0x702d5c26` selects direct or locked context. Actual chip ioctl
`0x702d7414` reads the selected original descriptor at `0x70f8e6f8`, and query
14 invokes actual BBT-active `0x702d5ad2` against magic at `0x70f9bbac`.

| Authored original descriptor selection | ID result | Page bytes | Page count | Capacity result |
| --- | --- | --- | --- | --- |
| `0x70a3204c` | `0xbaef` | 2,048 | 65,536 | `0x08000000` |
| `0x70a318b0` | `0xb2ef` | 4,096 | 131,072 | `0x20000000` |

The original descriptor records and query jump table remain unchanged and
hash guarded. No descriptor fields are patched to obtain those outputs.
Output writes remain at +0, +8 and +12, preserving intervening/trailing bytes.
Only exact magic `0x746242` yields active byte one; zero or selected wrong magic
leaves the same descriptor-derived capacity with byte zero. This is a RAM magic
test, without verification of media records or complete remapping state.

With a null selected pointer, actual chip ioctl logs and returns `-2` on the
first query. Normal-context release still executes; geometry output remains
untouched. The selected no-op and null-output paths issue no lower query.

## Context and mutex boundaries

Actual context routine `0x702d5b32` requests IRQ state and, when appropriate,
scheduler state through supplied ROM services. Selected IRQ/scheduler states
skip driver locks. Normal context with a handle executes four separate
acquire/query/release sequences; without a handle, the wrappers return without
calling those lock services.

An acquire error stops at the real assertion before chip query. A release
error stops after its first chip result but before the NAND method publishes
the caller geometry. Owners are `0x70a30f20`, line 36, and `0x70a30f08`, line 42.
Assertion bodies do not execute; no normal-return ABI or real RTOS behavior is
claimed for those stops. Normal returns check ABI and buffer/data guards.

## Reproduction

```sh
python3 analysis_scripts/main_nand_stack.py --scope geometry \
  --vectors-output firmware/main-nand-query-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandStack.java \
  -postScript ValidateMainObjects.java \
  firmware/main-nand-query-stack-vectors.json firmware/main-nand-query-stack-validation.json

python3 analysis_scripts/main_nand_stack.py firmware/bip6-4.6.0.3.zip \
  --scope geometry --decompiled firmware/decompiled/runtime-main-nand-query-stack \
  --vectors firmware/main-nand-query-stack-vectors.json \
  --validation firmware/main-nand-query-stack-validation.json
```

Use the preceding startup-aware main runtime project and main-object metadata.
Export with `DecompileWithLogger.java`, logger `0x702b38a2`, and addresses from
`ranges('geometry')` in `analysis_scripts.main_nand_stack`. Firmware/exports stay
local. All **41 previous main-object native cases reproduce byte for byte**;
previous runner guards and log values stay unchanged. The two new scopes share
24 host checks in the **1,644-test suite**. The [root pass](MAIN_NAND_ROOT_STACK.md)
adds original initializer/wrapper/registry/PM publication with a supplied probe.
