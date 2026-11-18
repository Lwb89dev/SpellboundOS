# Main NAND root, registry and PM publication with original geometry consumers

All **12 native cases** pass in **4,763 instruction/service steps**
(maximum **725**, `main_root_append`). Original main root `0x702d54c6`, operation
initializer `0x702d5b56`, registry lookup/insertion and later object consumers now
execute together. Geometry follows the [actual main context/chip/active path](MAIN_NAND_QUERY_STACK.md).
Evidence and **18 code/export plus 16 data hashes** are in
[main-nand-root-stack.json](main-nand-root-stack.json).

Probe `0x702d685c`, BSP property lookup, heap/RTOS/library and PM-binding services
remain supplied. The supplied probe publishes the selected original descriptor
on success; it does not execute candidate detection, UID, BBT recovery or bus
initialization. BBT magic is explicitly authored. This scope establishes selected
caller/publication behavior, without physical initialization or ownership proof.

## Initialization and actual registry insertion

The supplied `dev_nand` property returns original pointer `0x70f87acc`. Actual
root stores it at `0x70f8e6e0`, calls the original operation initializer through
the original table and observes its supplied probe result. On success the
initializer creates its driver mutex when absent. Existing handles skip creation
while probing still occurs.

Root then requests 60 bytes through the supplied allocator with class 59 and
original allocation label `drivers_nand`. It clears the object, binds original
methods `0x70f624c0` and invokes real main registry `0x703192ca`, including actual
lookup `0x70319252`, duplicate checks and link publication at `0x70f8ead0`.
The registry uses its separate mutex at `0x70f8ead4` with supplied RTOS services.

First insertion and append to a seeded list execute. The latter preserves the
head and updates predecessor +52 and new object's +56 to the preceding link
cell. Successful registration precedes cached-object publication at
`0x70f8e6dc`. Supplied zero/name-copy/comparison leaves are bounded; complete
object/list bytes and immutable original tables are checked.

## PM binding and partial initialization

After publishing the cache, root requests `dev_nand_pm`. Its supplied property
contains an opaque word. Actual code forwards discriminator 2, the cached
object and that word to service `0x80d46cc8`. The PM role is inferred from the
property name; service internals and physical power behavior remain unverified.

The selected supplied return value `-9` is ignored; the actual service's status
convention remains unverified. Root returns zero and subsequent
open/geometry/close operations still execute. With a missing PM property,
execution instead stops at the real assertion, owner `0x70a30c60`, line 31,
**after** allocation, registry insertion and cache publication. Those values are
captured at the assertion call; its body and recovery effects do not execute.

| Selected earlier failure | Observed stage at return or assertion |
| --- | --- |
| Property missing | Assertion at owner `0x70a30c88`, line 49, before supplied probe/allocation |
| Supplied probe error | Outer `-6`, property root retained, no allocation/cache/PM binding |
| Driver mutex creation fails | Assertion at owner `0x70a30ef0`, line 30, after supplied descriptor publication and before allocation |
| Allocation fails | Outer `-6`, selected descriptor/driver mutex retained, no object registration |
| Seeded same-name/type object | Real registry `-11`; new allocation remains live and unlinked; object cache and PM call remain absent |

The duplicate path does not free the allocation in this selected body. This
captures its state at return, without proving later reclamation never occurs.
It also distinguishes a registry mutex or allocated object from successfully
published root cache/PM binding.

## Post-root consumers and reproduction

After successful return, explicit harness consumers open, query and close the
actual allocated object. These are authored caller operations, rather than calls
attributed to the initializer itself. The cached pointer and registry links
remain after closing the reference count. Two original descriptor selections
and inactive magic still drive original geometry output; physical chip/media
and full BBT provenance remain open.

```sh
python3 analysis_scripts/main_nand_stack.py --scope root \
  --vectors-output firmware/main-nand-root-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainNandStack.java \
  -postScript ValidateMainObjects.java \
  firmware/main-nand-root-stack-vectors.json firmware/main-nand-root-stack-validation.json

python3 analysis_scripts/main_nand_stack.py firmware/bip6-4.6.0.3.zip \
  --scope root --decompiled firmware/decompiled/runtime-main-nand-root-stack \
  --vectors firmware/main-nand-root-stack-vectors.json \
  --validation firmware/main-nand-root-stack-validation.json
```

Use the preceding startup-aware main-object project. Export with
`DecompileWithLogger.java`, logger `0x702b38a2`, and addresses from
`ranges('root')` in `analysis_scripts.main_nand_stack`. Firmware/exports stay
local. Original code/descriptor/switch/property/method/operation data, normal-
return ABI and object/seed/name/PM/input/output guards are checked. Both evidence
files reproduce; **41 previous main-object native cases reproduce byte for
byte**. Twenty-four new host checks join the **1,644-test suite**. Actual main
probe/UID/BBT/platform/media, wider startup/storage consumers, PM internals,
removal/reclamation/concurrency and safe backup/restoration/boot remain open.
