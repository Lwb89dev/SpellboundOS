# Original object registry lookup and insertion

All **19 native cases** pass in **16,274 instruction/service steps**
(maximum **1,103**, `object_append_three`). Original lookup `0x80c2ce64` and
registration `0x80c2cecc` now execute their list traversal, duplicate checks,
field updates and insertion bodies. Evidence, **44 code/export and 33 data
hashes** are in [nand-object-stack.json](nand-object-stack.json). These counts
include the existing platform prelude; they do not count newly recovered
functions or measure overall reverse-engineering coverage.

Objects, query strings and initial list state are authored. Mutex, bounded
string/zero operations and diagnostic/assertion services are supplied. The
existing NAND platform prelude executes over authored peripherals, but direct
registry cases do not execute a chip probe. No device was accessed.

## List structure and duplicate policy

The registry head is `0x80d81f90`, followed by its mutex at `0x80d81f94`.
The selected objects have 60 bytes: name storage occupies the first 32 bytes,
type is a byte at +36, methods at +40, another field at +48, next at +52 and
the address of the preceding link cell at +56. The method pointer is preserved
by registration. The first object's +56 points to the global head cell;
subsequent objects point to the preceding object's +52, rather than its base.

Registration first performs original name/type lookup, then a separate pointer
membership traversal. A duplicate name/type or already linked pointer returns
`-11`, without renaming or linking the rejected object. Identical names with
different types can coexist. Empty strings are accepted; null name or object
reaches the original assertion, owner `0x80c3f614`, line 125. The harness stops
there and makes no assertion-body or normal-return claim.

First insertion, three appends and append/reject against seeded lists capture
all four object buffers and their actual pointer links. No removal, reclamation
or concurrent ownership contract is established by this pass.

## Name and type width boundaries

Lookup compares up to **32 bytes** using the supplied C-style bounded comparison
leaf. Successful insertion clears 32 name bytes but copies only **31**.
A 31-byte name is findable unchanged. A selected 32-byte name registers, but
lookup using the full original name misses; querying its 31-byte prefix finds
the object. Repeating registration with that full 32-byte name can therefore
insert another object with the same stored name/type. Prefix lookup finds the
first. These are bounded authored strings, without evidence of a corresponding
device collision or application input.

Type is stored as a byte, while lookup compares it against its full argument.
Selected type 279 is stored as 23: lookup 279 misses, lookup 23 finds it, and
another registration using 279 can insert a second stored type-23 object.
Caller-side constraints on actual type values remain separate work.

## Lock service boundaries

An existing mutex avoids creation. Even an empty lookup can initialize the
mutex without publishing an object. Registration's lookup, membership and
insertion use separate lock intervals. Returned lock/unlock errors are not
checked by these original bodies in the selected cases.

For explicit failure vectors, the supplied mutex creator can return null and
the supplied lock service accepts that handle while returning `-9`. Original
list mutation can still complete under those assumptions. This does **not**
establish what the actual RTOS does with a null mutex or prove a real race,
thread-safety guarantee or physical failure mode.

## Reproduction and verification

```sh
python3 analysis_scripts/nand_object_stack.py --scope registry \
  --vectors-output firmware/nand-object-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedObjectRegistry.java \
  -postScript ValidateQspiHal.java \
  firmware/nand-object-stack-vectors.json firmware/nand-object-stack-validation.json

python3 analysis_scripts/nand_object_stack.py firmware/bip6-4.6.0.3.zip \
  --scope registry --decompiled firmware/decompiled/runtime-nand-object-stack \
  --vectors firmware/nand-object-stack-vectors.json \
  --validation firmware/nand-object-stack-validation.json
```

Use the existing startup-aware runtime project with the preceding NAND/QSPI
metadata. Export using `DecompileWithLogger.java`, logger `0x80c1cd7a`, and
addresses from `ranges('registry')` in `analysis_scripts.nand_object_stack`.
Firmware and exports stay local. Original code/data and normal-return ABI are
guarded; object buffers have surrounding sentinels and query backing stays
immutable. The [connected root pass](NAND_DRIVER_ROOT_STACK.md) uses this real
registry after original NAND probe/UID/BBT startup. Both scopes share 25 host
tests; all **688 preceding shared-runner native cases reproduce byte for byte**.
