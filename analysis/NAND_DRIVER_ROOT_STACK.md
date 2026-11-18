# Original NAND driver root through probe, UID, BBT and object registration

All **14 native cases** pass in **245,078 instruction/service steps**
(maximum **40,092**, `root_bbt_assertion`). Original driver-root initializer
`0x80c27524` now invokes its original operation table and wrapper, actual
first-chip probe/platform/QSPI, UID acquisition and BBT recovery, followed by
real object registry lookup and insertion. Evidence and **101 code/export plus
38 data hashes** are in [nand-root-stack.json](nand-root-stack.json).

This connects the [UID/probe/BBT path](NAND_PROBE_UID_BBT.md) with the
[object registry](NAND_OBJECT_REGISTRY.md). Original descriptor, operation and
method tables remain unchanged. Property lookup, allocation, mutex and library
leaves, peripheral effects, IDs, UID and media/status records remain authored.
The existing platform setup prelude supplies a controlled prior bus state;
this is neither a full cold-start trace nor a physical driver test.

## Successful publication and actual lookup

The supplied `dev_nand` property result is the original pointer `0x80d81b28`.
The original root stores it at `0x80d81f10` and invokes the original operation
initializer `0x80c27aac`. Probe selection, UID acquisition, normal features and
BBT recovery execute before wrapper mutex creation and the 60-byte object
allocation. The root clears the object, binds original methods `0x80d811d8` at
+40 and calls original registration with name `dev_nand`, type 23.

The real registry publishes the head or appends after seeded objects. A
post-return original lookup retrieves that actual allocated pointer. A seeded
same-name object of another type coexists; lookup 23 returns the new NAND
object. Existing driver and registry mutexes skip their respective creation
calls while the original probe still executes.

## Errors preserve different stages of initialization

| Selected condition | Observed outer result and retained state |
| --- | --- |
| Property missing | Assertion at owner `0x80c3d208`, line 49; root/selected descriptor remain zero; no probe or object allocation |
| Actual ordinary feature mismatch after successful UID | Inner `-7` becomes outer `-6`; property root, selected descriptor and UID remain; BBT, guard counts, driver mutex and allocation are absent |
| Driver mutex creation fails | Assertion after UID/BBT and guard counts; no object allocation |
| No good reserved BBT blocks | Actual BBT assertion after descriptor/UID publication, before guard/mutex/object allocation |
| Object allocation fails | Outer `-6`; successful probe/UID/BBT, guard counts, property root and driver mutex remain |
| Same-name/type object already registered | Real registry returns `-11`; the newly allocated object remains live and unlinked, with its method table bound; existing lookup still returns the earlier object |

No deallocation executes on the selected duplicate-registration return path.
This establishes live allocation at this function's return, without proving
that later callers never reclaim it. Follow-up lookup is explicitly authored
by the harness and can itself create the registry mutex, even after allocation
or feature failure; mutex existence alone does not imply registration.

## Successful registration does not imply complete media or UID state

Actual BBT no-table return 1 remains ignored through the probe and wrapper all
the way to successful outer registration. The device object can be findable
while BBT magic is inactive. A real backup-repair erase failure likewise allows
registration, with backup-derived RAM mapping active and a repair-failure log.
Authored media inputs do not change when erase/program commands execute.

An early UID feature failure retains authored prior length 17 and `0xa5`
bytes. Probe, BBT and actual registry insertion still succeed; original ioctl
24 after root completion exports those old bytes. Those inputs are deliberate
retained-state fixtures, without physical UID or cold-boot provenance.

Selected registry mutex failure cases also retain the supplied-lock-service
limitations from [the registry report](NAND_OBJECT_REGISTRY.md). No actual
RTOS synchronization, electrical operation or persistent repair is claimed.

## Reproduction and remaining work

```sh
python3 analysis_scripts/nand_object_stack.py --scope root \
  --vectors-output firmware/nand-root-stack-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedNandProbe.java \
  -postScript SeedNandIdentity.java -postScript SeedNandBbt.java \
  -postScript SeedObjectRegistry.java -postScript ValidateQspiHal.java \
  firmware/nand-root-stack-vectors.json firmware/nand-root-stack-validation.json

python3 analysis_scripts/nand_object_stack.py firmware/bip6-4.6.0.3.zip \
  --scope root --decompiled firmware/decompiled/runtime-nand-root-stack \
  --vectors firmware/nand-root-stack-vectors.json \
  --validation firmware/nand-root-stack-validation.json
```

Use the existing startup-aware NAND/QSPI runtime project. Export with
`DecompileWithLogger.java`, logger `0x80c1cd7a`, and addresses from
`ranges('root')` in `analysis_scripts.nand_object_stack`. Firmware/exports stay
local. Original code/data, table immutability, normal-return ABI and controller/
DMA/private/caller/UID/BBT/object guards remain active. Both new evidence files
reproduce, and **688 preceding shared-runner native cases reproduce byte for
byte**. The two scopes add 25 host checks to the **1,570-test suite**.

Initial BBT creation/provenance, broader chip geometry, registry removal and
lifetimes/concurrency, real property/heap/mutex services, wider storage/startup
callers, persistent write/retire/reboot reconstruction, physical backup and
restoration, and standalone boot through the signed chain remain open.
