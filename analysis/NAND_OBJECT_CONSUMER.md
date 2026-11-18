# Original NAND object opening and geometry consumers

All **15 native cases** pass in **261,061 instruction/service steps**
(maximum **21,629**, `consumer_no_bbt`). After [actual driver-root startup and
registration](NAND_DRIVER_ROOT_STACK.md), authored caller operations now execute
original generic open/ioctl, original NAND methods and the geometry query path
through actual context/mutex/chip/BBT routines. Evidence and **108 code/export
plus 44 data hashes** are in [nand-object-consumer.json](nand-object-consumer.json).

The calls occur after the original root returns; they are explicit harness
consumers, rather than additional calls attributed to the root body. Original
candidate, method and operation tables remain unchanged. Property/heap/RTOS/
library/peripheral effects and ID/UID/media streams remain authored. There was
no hardware access or persistent media mutation.

## Opening the registered NAND object

Generic open invokes original NAND open method `0x80c274e6`, which checks the
object pointer and returns zero for the selected non-null object. Its reference
count becomes one. A repeated open increments to two without repeating the
method callback. Registration alone leaves count zero: an ioctl before opening
returns `-14` before reaching the NAND method.

The original method table at `0x80d811d8` is preserved throughout. Failed root
allocation leaves outer return `-6` and skips all consumer operations. The report
captures the root return separately from each subsequent operation and assertion.

## Original geometry response

Object ioctl `0x80c2d0ba` tail-dispatches to NAND method `0x80c27338`.
Commands **0x1001 and 0x1002** follow the same selected geometry path. They issue
original driver ioctl queries **13, 2, 1, 14**, which reach original chip ioctl
and, for query 14, the real BBT-active check.

| Output offset | Selected original write |
| --- | --- |
| +0, 4 bytes | Descriptor's first two ID bytes, `0xbaef` |
| +8, 4 bytes | Page size times page count, `0x08000000` (128 MiB) |
| +12, 1 byte | Actual BBT-active result, 1 or 0 |

The word at +4 and bytes after +12 retain their authored sentinel values.
Descriptor-derived ID/capacity are software results over authored matching
inputs, without physical identity or capacity corroboration. An ignored real
no-BBT result still allows registration/opening and publishes the same capacity
with active byte **zero**. Early UID acquisition error likewise does not prevent
geometry publication; its authored old UID length 17 is retained separately.

Command **0x1003** returns zero without output, including a selected null output.
Command 0x1000 returns `-10`. Null output for 0x1001 logs the original geometry
error and returns `-10` before lower queries. These observations are bounded to
the original intact callback tables in this scope.

## Context, mutex failures and selected suspend/resume methods

Normal context executes four separate acquire/query/release sequences. IRQ or
the selected scheduler context bypasses those mutex services. Acquisition or
release error reaches the original assertion at line 36 or 42, after successful
root registration and open. The geometry output remains untouched because
publication follows all four queries. The report keeps root return zero while
marking the later operation as stopped. Real RTOS behavior and coherent geometry
under concurrent state changes remain unproven.

Original assertion-owner strings identify `0x80c27466` as `dev_nand_suspend`
and `0x80c27424` as `dev_nand_resume`. Both check the non-null object and return
zero without transfer calls or output changes in these selected cases. This
does not establish a physical power-state transition. The original method table
also contains two null slots at +8 and +12. The separately verified
[NAND partition dispatch](NAND_DISPATCH_STACK.md) and lower NAND/QSPI data paths
remain distinct paths with their own evidence. The original owner-name strings
are byte checked and included in the evidence with their hashes.

## Reproduction and limits

```sh
python3 analysis_scripts/nand_object_lifetime.py --scope consumer \
  --vectors-output firmware/nand-object-consumer-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedObjectRegistry.java \
  -postScript SeedObjectLifetime.java -postScript ValidateQspiHal.java \
  firmware/nand-object-consumer-vectors.json firmware/nand-object-consumer-validation.json

python3 analysis_scripts/nand_object_lifetime.py firmware/bip6-4.6.0.3.zip \
  --scope consumer --decompiled firmware/decompiled/runtime-nand-object-consumer \
  --vectors firmware/nand-object-consumer-vectors.json \
  --validation firmware/nand-object-consumer-validation.json
```

Use the preceding startup-aware, seeded NAND root/QSPI project. Export with
`DecompileWithLogger.java`, logger `0x80c1cd7a`, and addresses from
`ranges('consumer')` in `analysis_scripts.nand_object_lifetime`. Firmware and
exports stay local. Existing code/data/ABI/controller/DMA/caller/BBT/UID/object
guards remain active; dedicated output and immutable method-table guards are
added. Both evidence files reproduce. The two scopes add 26 host checks to the
**1,596-test suite**; **721 preceding shared-runner native cases reproduce byte
for byte**. Close/removal/reclamation/concurrency, wider startup/storage callers,
initial BBT provenance, physical I/O and safe backup/restoration/standalone boot
remain open.

The subsequent [main-image NAND method pass](MAIN_NAND_OBJECT.md) verifies
opening/closing and geometry consumers in the main firmware, with its own
original tables and supplied lower-query boundary.
