# Main-image object open, close, write and ioctl contracts

All **26 native cases** pass in **691 instruction/service steps**
(maximum **84**, `main_two_refs`). Original main-image open `0x70319470`, close
`0x703194e0`, write `0x70319562`, ioctl `0x703195e0` and active-count query
`0x70319664` execute on authored objects. Evidence, original owner-name strings,
**five code/export and four data hashes** are in
[main-object-lifecycle.json](main-object-lifecycle.json).

This follows the [boot-image opening pass](NAND_OBJECT_OPEN.md) into the main
image, whose strings and code include `dev_obj_close` and `dev_obj_write`.
Their boundaries were checked against instructions and original assertion-owner
strings. The images have distinct addresses and guarded bytes; behavioral
similarities do not establish that every API or caller is interchangeable.

The object, reference counts, method table, callback results/effects and buffers
are authored. Diagnostic/logger/assertion services are supplied. No device,
actual registration, deallocation, media access or RTOS scheduling executes.

## Closing and reference ownership

The selected +48 count is interpreted as signed. With count greater than one,
close decrements and returns zero without invoking the backend. On the final
close, it decrements from one to zero **before** tail-calling the close callback.
An error from that callback propagates without restoring the count. Subsequent
active query returns false; close or ioctl then returns `-14` without retrying
the failed callback. Explicit reopening calls the open callback again.

With a missing method table or close callback, close instead returns zero
without decrementing a positive count. Its active query remains true.
These results distinguish wrapper return, reference state and backend result;
they do not prove physical teardown or a complete reclamation policy.

Zero and negative count fixtures reject close. Open increments an existing
positive count without a callback; missing/failed open does not establish a
positive count. Selected -1 and signed-overflow fixtures reproduce the earlier
boot counter boundaries. The native active query is true only for a non-null
object with positive signed count; a null object returns false.

## Write/ioctl dispatch and assertions

Positive count permits actual write tail dispatch through method-table +8.
Object, offset, input pointer and size reach the supplied callback; count or
error return propagates and references stay unchanged. Missing write callback
returns zero without transfer. A null object or input buffer reaches the real
assertion even before the positive-count check.

Ioctl uses method-table +24. Selected callback output remains visible even when
that supplied callback returns an error. Missing ioctl callback returns zero
without output; nonpositive count returns `-14`. Input data and method table
remain immutable throughout all cases.

Null open, close, write and ioctl reach their original assertions at lines
297, 331, 400 and 491, with owner strings `dev_obj_open`, `dev_obj_close`,
`dev_obj_write`, `dev_obj_ioctrl`. The harness stops before their bodies and
claims no normal-return ABI check for those paths. Normal returns check saved
registers and stack restoration. Guarded object snapshots record reference
updates and all other bytes; no registry membership is inferred from this
standalone fixture.

## Reproduction

```sh
python3 analysis_scripts/main_object_lifecycle.py --scope callbacks \
  --vectors-output firmware/main-object-lifecycle-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime main-runtime -process main-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedMainObjects.java \
  -postScript ValidateMainObjects.java \
  firmware/main-object-lifecycle-vectors.json firmware/main-object-lifecycle-validation.json

python3 analysis_scripts/main_object_lifecycle.py firmware/bip6-4.6.0.3.zip \
  --scope callbacks --decompiled firmware/decompiled/runtime-main-object-lifecycle \
  --vectors firmware/main-object-lifecycle-vectors.json \
  --validation firmware/main-object-lifecycle-validation.json
```

Use the existing startup-aware main runtime project. Export with
`DecompileWithLogger.java`, logger `0x702b38a2`, and addresses from
`ranges('callbacks')` in `analysis_scripts.main_object_lifecycle`. Firmware and
exports stay local. The separate [main NAND method pass](MAIN_NAND_OBJECT.md)
executes original open/close/ioctl methods behind this generic API. The two
scopes share 24 host tests in the **1,620-test suite**. Removal, deallocation,
callback lifetime/concurrency and physical shutdown remain open.

The subsequent [main root/registry pass](MAIN_NAND_ROOT_STACK.md) constructs the
object through original initialization and insertion before these consumers,
with probe/BSP/heap/RTOS/PM services still supplied.
