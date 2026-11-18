# Original object opening, reference counts and ioctl policy

All **17 native cases** pass in **12,660 instruction/service steps**
(maximum **922**, `open_registered_duplicate`). Original register-and-open
`0x80c2cfe0`, open `0x80c2d04e` and ioctl `0x80c2d0ba` execute over authored
objects, method tables and callbacks. Evidence and **47 code/export plus
35 data hashes** are in [nand-object-open.json](nand-object-open.json).

This extends [object registration](NAND_OBJECT_REGISTRY.md) with the selected
opening/reference/dispatch contract. The existing platform prelude runs over
authored peripherals. Method callback results/effects, initial counts, mutex
and library services remain supplied. Original owner-name strings identify `dev_obj_open` and `dev_obj_ioctrl`; their
bytes and names are validated in the evidence. No device was accessed.

## Open success and usable state

Object +48 is used as a signed reference count by these bodies. For a positive
count, open increments it without calling the backend. Otherwise, an available
open callback is invoked with the original object and flags; success increments
the existing count and failure propagates without incrementing it.

If the method table or open callback is absent, open returns **zero without
incrementing** a zero count. Actual ioctl then logs the object-not-open path and
returns `-14`. Open return zero therefore does not establish positive count or
usable ioctl dispatch in these selected states.

Explicit retained-count fixtures cover two boundaries. Starting at `0xffffffff`
(-1), a successful callback increments to zero and ioctl still fails. Starting
at `0x7fffffff`, open skips the callback and wraps to `0x80000000`; ioctl again
rejects the signed nonpositive count. These are authored inputs, not observed
device corruption. Atomic increments, concurrent ownership, close/decrement,
removal and reclamation remain unverified.

## Registration followed by opening

Register-and-open runs real name/type/pointer checks and list publication before
the method callback. An open callback error leaves a registered object with
count zero, logs the open failure and returns the callback status. Subsequent
ioctl rejects it as unopened. Missing callback can similarly leave a registered
zero-count object while returning zero.

A second register-and-open on the same object maps registration's `-11` to
**`-1`** and leaves its existing count unchanged. It does not repeat the open
callback. This wrapper does not remove an object after the selected open error.

## Ioctl forwarding and output effects

Positive count permits tail dispatch to method-table slot +24. Original object,
command and remaining argument registers reach the supplied callback unchanged.
A missing table/ioctl callback returns zero without writing output. A supplied
callback may write output and then return an error; the wrapper preserves both
the effect and status. A null output is forwarded in the selected fake-callback
case, rather than validated here.

Null object pointers reach original assertions: open owner `0x80c3f5f4`, line
297; ioctl owner `0x80c3f5d4`, line 491. Execution stops before the assertion body
and makes no normal-return claim. All normal returns check ABI. Object, method-
table and output buffers have guards; input names and method tables stay
immutable. The main caller buffer is not used as this fixture's ioctl output.

## Reproduction

```sh
python3 analysis_scripts/nand_object_lifetime.py --scope open \
  --vectors-output firmware/nand-object-open-vectors.json

XDG_CONFIG_HOME=/tmp/spellbound-ghidra-config \
XDG_CACHE_HOME=/tmp/spellbound-ghidra-cache \
GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.home=/tmp/spellbound-ghidra-home \
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  firmware/ghidra-runtime boot-runtime -process boot-runtime.elf -noanalysis \
  -scriptPath analysis_scripts -postScript SeedObjectRegistry.java \
  -postScript SeedObjectLifetime.java -postScript ValidateQspiHal.java \
  firmware/nand-object-open-vectors.json firmware/nand-object-open-validation.json

python3 analysis_scripts/nand_object_lifetime.py firmware/bip6-4.6.0.3.zip \
  --scope open --decompiled firmware/decompiled/runtime-nand-object-open \
  --vectors firmware/nand-object-open-vectors.json \
  --validation firmware/nand-object-open-validation.json
```

Use the preceding startup-aware NAND/QSPI project. Generate exports with
`DecompileWithLogger.java`, logger `0x80c1cd7a`, and addresses from
`ranges('open')` in `analysis_scripts.nand_object_lifetime`. Firmware and exports
stay local. The [consumer pass](NAND_OBJECT_CONSUMER.md) connects original NAND
methods after actual root/probe/UID/BBT/registration. Both scopes share 26 host
tests; all **721 preceding shared-runner native cases reproduce byte for byte**.
