# Original main NAND family check, reset and level workaround

All **eight native cases** pass in **51,955 instruction/service steps** (maximum
**11,317**, five unconfirmed level writes). Original main compatibility check
`0x702d7ee6`, level setter `0x702d7f36` and workaround `0x702d80fe` now execute
inside the [main probe/platform/FIFO/root chain](MAIN_NAND_FULL_PROBE.md).
[main-nand-aux-workaround.json](main-nand-aux-workaround.json) records **54
code/export and 65 data hashes**, observations and limitations. The shared corpus
also supports [actual main UID acquisition](MAIN_NAND_UID.md).

UID and BBT remain supplied in this workaround scope. E0/status/ID inputs,
reset/completion/readiness, ticks and ROM string are authored; power/pin/BSP/
RTOS/heap/PM and bounded library services remain supplied. Delay calls record
requested arguments without establishing elapsed time or physical reset.

## Family selection and actual reset packets

Compatibility executes its original bounded name comparisons against
`Winbond W25N02LWZEIG` and `Winbond W25N04LWZEIG`. The original candidate-3 name
matches the latter. First-chip candidate 0 is unsupported: actual workaround
returns `0xffffffff`, but original probe ignores that return and continues to
the selected supplied UID/BBT and actual feature/registration/geometry path.

For candidate 3, original reset-enable `0x702d6354` and power-reset `0x702d63b6`
produce command-only `0x66` and `0x99` packets through actual main bus/HAL.
Requested delay arguments 1000 and 5000 follow the respective commands through
the original thunk `0x701648f8` to supplied delay service `0x80d453d4`.
The actual workaround then reads register E0 through FIFO.

## Level setter and unconfirmed writes

An E0 value whose low three bits are already zero returns success. Otherwise
actual setter reads E0, preserves its upper bits and requests level zero. It
performs up to five original feature-write/readback attempts. Cases cover a
confirmed first write and a scripted second confirmation.

With authored E0 writes left unapplied, all five readbacks may disagree and log
level mismatches, yet the actual setter and workaround still return zero. Probe
continues and registers the object while the authored E0 state retains value 2.
This independently establishes the main-image status behavior; it does not
establish a physical register failure or a safe retry setting.

Completion failure on `0x66` or `0x99` reaches the actual bus assertion, owner
`0x70a1bc8c`, line 294, before workaround returns. E0 readiness failure instead
reaches line 305 before a completed E0 FIFO read. These are actual HAL wait
results from authored status/ticks. Assertion bodies/recovery do not run.

## Reproduction and continuation

[main-nand-identity.json](main-nand-identity.json) independently extracts all
eleven main descriptors' UID sequences, mode/copy/page/size and ECC fields,
with unchanged original descriptor/name pointers and hashes. It is separate
from the boot identity inventory.

```sh
python3 analysis_scripts/main_nand_aux.py firmware/bip6-4.6.0.3.zip \
  --inventory-output /tmp/main-nand-identity.json
cmp analysis/main-nand-identity.json /tmp/main-nand-identity.json
python3 analysis_scripts/main_nand_aux.py --scope workaround \
  --vectors-output firmware/main-nand-aux-workaround-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandAux.java \
  -postScript ValidateMainNandAux.java \
  firmware/main-nand-aux-workaround-vectors.json firmware/main-nand-aux-workaround-validation.json

python3 analysis_scripts/main_nand_aux.py firmware/bip6-4.6.0.3.zip \
  --scope workaround --decompiled firmware/decompiled/runtime-main-nand-aux \
  --vectors firmware/main-nand-aux-workaround-vectors.json \
  --validation firmware/main-nand-aux-workaround-validation.json
```

Use the preceding startup-aware main project and seeds. The new seed changes
metadata only, including the actual void UID return. Export addresses from
`ranges()` in `analysis_scripts.main_nand_aux` using `DecompileWithLogger.java`,
logger `0x702b38a2`. Firmware/exports stay local. Code/data hashes, immutable
original descriptors/sequences/names/literals, return ABI and buffer/record
guards are checked. Physical family/register operation, main BBT/page/media,
IRQ/cache/coherency and restoration/boot remain open.
