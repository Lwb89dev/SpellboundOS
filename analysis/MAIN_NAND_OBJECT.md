# Main-image NAND methods through generic object consumers

All **15 native cases** pass in **1,430 instruction/service steps**
(maximum **157**, `nand_main_two_refs`). Actual main-image generic opening,
closing, active/write/ioctl policy now connects to original NAND open
`0x702d5484`, close `0x702d5442` and ioctl `0x702d52c6`. Evidence and
**eight code/export plus ten data hashes** are in
[main-nand-object.json](main-nand-object.json).

The object is authored and bound to the unchanged original method table at
`0x70f624c0`. Original property `0x70f87acc` points to operation table
`0x70f624dc`. Its lower ioctl callback `0x702d5c26` is supplied at the query
boundary. Main probing, registration, NAND peripherals/media, RTOS and physical
state transitions do not execute. This differs from the separately verified
[boot root/consumer path](NAND_OBJECT_CONSUMER.md), which joins actual boot
probe/UID/BBT beneath its geometry queries.

## Original method table and close/reopen sequence

Original owner strings identify NAND open, close and ioctl. For the selected
non-null object, actual open and close methods return zero. Generic open raises
the reference count; repeated open skips the backend. Intermediate close only
decrements. Final close calls the real NAND close method and leaves count zero,
so generic ioctl then rejects it before lower queries. A later open executes
the real NAND open method again and geometry ioctl succeeds.

These methods establish a software call/reference contract without hardware
power-off or teardown evidence. The authored object is not produced by actual
main initialization/registration, and close does not establish removal from a
registry or heap reclamation.

The original table's **+8 write slot is null**, as verified both from bytes and
through the real generic write dispatch. An opened object can therefore return
zero from write without a backend transfer. This is this object interface's
selected behavior; the separately covered NAND partition/page/program paths
have different call chains.

## Geometry propagation and partial failures

Original NAND ioctl commands 0x1001/0x1002 issue lower queries **13, 2, 1, 14**.
The supplied responses are descriptor ID, page size, page count and active-BBT
byte. Their selected values `[0xbaef, 2048, 65536, 1]` produce writes at output
+0, +8 and +12: ID, 32-bit page-size times count, and the byte flag. Other bytes
retain the supplied sentinel. No fitted chip, physical capacity or actual BBT
is inferred from these authored responses.

A failure at each of the four lower query positions propagates its status
before output publication. Original close still runs afterwards in the authored
caller sequence. An authored zero BBT flag is exposed unchanged. A large
page-size/count pair demonstrates multiplication wrapping to zero, not an
observed hardware capacity.

Command 0x1003 returns zero with a null output; invalid command 0x1000 returns
`-10`; null geometry output logs and returns `-10`. None issues a lower query.
No transfer or persistent state change is supplied or demonstrated here.

## Reproduction and verification

```sh
python3 analysis_scripts/main_object_lifecycle.py --scope nand \
  --vectors-output firmware/main-nand-object-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainObjects.java \
  -postScript ValidateMainObjects.java \
  firmware/main-nand-object-vectors.json firmware/main-nand-object-validation.json

python3 analysis_scripts/main_object_lifecycle.py firmware/bip6-4.6.0.3.zip \
  --scope nand --decompiled firmware/decompiled/runtime-main-nand-object \
  --vectors firmware/main-nand-object-vectors.json \
  --validation firmware/main-nand-object-validation.json
```

Use the existing startup-aware main runtime project. Export with
`DecompileWithLogger.java`, logger `0x702b38a2`, and addresses from
`ranges('nand')` in `analysis_scripts.main_object_lifecycle`. Main image hash,
original code/data/owner names, ABI, unchanged method/property/operation tables,
input data and surrounding buffer guards are checked. The independent main
runner leaves the existing boot runner and vectors unchanged. Both new
evidence files reproduce. The two scopes share 24 host checks in the
**1,620-test suite**. Actual main lower NAND/probe/registration, wider callers,
removal/reclamation/concurrency, persistence and physical backup/restoration/
standalone boot remain open.

The subsequent [main query-stack pass](MAIN_NAND_QUERY_STACK.md) replaces the
supplied geometry results with actual context/chip/BBT-active code over authored
state. The [root pass](MAIN_NAND_ROOT_STACK.md) joins original initialization,
registry and cache/PM publication with an explicitly supplied probe.
