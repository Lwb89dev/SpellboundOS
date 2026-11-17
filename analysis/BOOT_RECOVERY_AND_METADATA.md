# Boot/recovery control flow and variable signed metadata

This investigation uses the original OTA 4.6.0.3 and fresh startup-aware
AndeStar v5 imports. It does not exercise the watch's buttons, change boot
environment variables, enter recovery or invoke an updater.

## Signed metadata variants

Metadata immediately preceding the final 64-byte signature is self-sized:
the little-endian length at metadata offset 8 is 48 or 64 in the observed
objects. A fixed 112-byte total trailer applies only to the 48-byte variant.

| Object | Magic | Metadata bytes | Version field |
| --- | --- | ---: | --- |
| OTA ZIP | `HMZPSIGN` | 48 | `4.6.0.3` |
| Bootloader | `HMBZSIGN` | 48 | `2.0.6` |
| Recovery | `HMRVYSIG` | 48 | `2.3.1` |
| Main firmware | `HMZPSIGN` | 64 | `4.6.0.3` |
| Factory firmware | `HMZPSIGN` | 64 | `4.6.0` |
| Sensor hub | `HMZPSIGN` | 64 | `1.0.0` |

Common literal fields are magic `+0`, metadata size `+8`, a body-size field
`+10`, two 16-bit fields at `+14` and `+16`, a 16-byte version field `+18`,
and a second 32-bit size-like field `+34`. The first body-size field matches
the metadata's offset in every object. The two 16-bit fields are 155 and 256
throughout; the boot validator treats them as product/variant identifiers in
some branches, but they must not be conflated with the OTA catalog's other
production/product fields.

In the 64-byte variants, bytes `+38` onward contain readable build timestamps.
The 48-byte boot/recovery metadata uses a different tail: the validation code
reads byte `+38` for hardware major/minor comparison. Applying that meaning
to the timestamp bytes of the 64-byte variant would be incorrect.

The bootloader's second size field differs from its body-size field by
`0x400`, consistent with its existing outer wrapper and stripped analysis
payload. Main, recovery, factory and hub have equal size fields. In the ZIP,
the second field is 154,568,252, while summing actual ZIP member sizes gives
154,568,899, a difference of 647 bytes. Its precise scope remains unresolved;
it is not used as a validation rule by the host inspector.

The metadata is inside the payload covered by the existing ECDSA checks.
Structural parsing does not authenticate it; the separate
`verify_ota_signatures.py` checks mathematical signatures with the embedded
public key. No signature bypass follows from finding these variants.

## Raw recovery validation route

Boot wrapper `0x80c0e9c2` calls `0x80c0e7e0` with validation enabled. The
fresh targeted export confirms an effective final argument of 1 in the call
to `0x80c0e6ea`. That validator:

1. Chooses `recovery0`, `recovery1` or `recovery_ota` from a selector.
2. Reads a 72-byte partition header, checks `RECO` and compares a checksum
   over its first 68 bytes. The follow-up
   [RECOVERY_VALIDATOR_NATIVE.md](RECOVERY_VALIDATOR_NATIVE.md) independently
   recovers this as raw reflected CRC-32, seed `0xffffffff`, without final
   complement, and executes the selected validator paths.
3. Examines the recovery image at partition offset `0x1000`, using the image
   length from the header. It checks the 48-byte `HMRVYSIG` metadata and,
   on this wrapper's path, invokes the signature-validation branch.
4. Compares the image version with the partition header's version field.

Selection `0x80c0e9cc` considers the available partitions, boot/completion
counters and version/order fields. Preparation `0x80c0eaa6` copies a selected
image to `0x80d00000`, updates recovery state and hands off through the separate
jump routine. Counter updates mean this is not a read-only diagnostic path.
The static branch analysis strengthens the validation-path evidence but does
not prove device runtime enforcement, partition contents or recovery success.

## Reset is distinct from image handoff

The old export of `0x80c0082c` appeared to take a function pointer returned by
`0x80c007b0` and jump through it. Raw instructions show that `0x80c007b0`
ends in `C.J` to itself at `0x80c007d8`, after reset-related calls. It cannot
normally return to the following `0x80c0084a` entry.

[`SeedBootFlow.java`](../analysis_scripts/SeedBootFlow.java) checks those
self-loop bytes and marks the reset helper non-returning. The re-export then
ends `0x80c0082c` at the reset call. The actual image handoff remains a distinct
function at `0x80c0084a`, with its own argument and stack frame. This removes
an apparent boot route created by erroneous fallthrough inference. The logger
still returns: return behavior must be established per function, not by
removing every non-return annotation.

## Key detection and recovery UI

Boot detector `0x80c00312` rejects boot reasons 3 and 6, checks a power-supply
condition, then polls keyboard command 6 with logical indices 0 and 1. It
uses two 20-iteration windows and a delay-like argument `0x32`. These indices
are not evidence of two physical keys; one can represent a key state/event.
The exact physical gesture and time units are unverified.

Its caller `0x80c00454` can write the `upgrade` environment record, whose
observed magic is `0xb007cca6` and record size `0x12a`. Recovery
`0x80d005ec` reads that record and includes UI paths named Erase All Data,
Restore System and Exit/Restart, plus backup checks. Those operations can
format partitions and alter device-specific state, including BLE-address
handling. This is not a proven non-destructive debug/unlock route or an
installation procedure; no such action was attempted.

## Reproduction and remaining gaps

```sh
python3 analysis_scripts/signed_metadata.py firmware/bip6-4.6.0.3.zip \
  > analysis/signed-metadata.json
python3 analysis_scripts/export_startup_elf.py firmware/bip6-4.6.0.3.zip \
  --image boot --output firmware/boot-runtime.elf
python3 analysis_scripts/export_startup_elf.py firmware/bip6-4.6.0.3.zip \
  --image recovery --output firmware/recovery-runtime.elf
```

The exporter now supports all four main/sensor/boot/recovery layouts. Boot
strips the outer `0x400` bytes. Both boot and recovery use two copy records at
relative `0x26c` and one zero record at `0x284`; partial-word sizes are rounded
by the actual startup loop. The same bounded memory/ELF tests apply.

The [metadata JSON](signed-metadata.json) reproduces from the original ZIP and
includes all object hashes. Five synthetic tests cover both sizes, incidental
magic, malformed/truncated blocks and observational size mismatches.
The full Python suite has 110 passing tests with signature dependencies.

Private targeted Ghidra logs are `firmware/ghidra-runtime-boot-stdout.log` and
`firmware/ghidra-runtime-boot-flow-stdout.log`. Import the boot ELF with
AndeStar v5/gcc and `-noanalysis`; seed logger `0x80c1cd7a` before targets
`0x80c00312 0x80c0e7e0 0x80c0e6ea 0x80c007b0 0x80c0082c`.
Then process it with `-preScript SeedBootFlow.java` and
`-postScript DecompileFunctions.java 0x80c0082c 0x80c0084a 0x80c0e9c2`.
LLVM inspection of `0x80c007b0`–`0x80c00876` independently confirms the loop
and separate handoff frame. Physical entry/recovery, actual raw-partition
backups, device-specific data and any independent-code boot path remain open.

The later [native validation pass](RECOVERY_VALIDATOR_NATIVE.md) adds 62 passing
cases with synthetic partition/service inputs: CRC, hardware/metadata policy,
signature-read/hash orchestration, embedded key/curve bridge and partition/
mandatory-wrapper checks. It supplies SHA hardware services and ECDSA arithmetic;
no physical recovery operation or standalone boot path is established.

The subsequent [selection/counter/handoff pass](RECOVERY_SELECTION_AND_HANDOFF.md)
adds 64 native cases with synthetic availability and partition/BSP services.
It checks header writes, signed counter/order selection, completion acknowledgments
and stopped launch, including the entry jump to startup + `0x22c`. Physical
entry, backup/restoration, environment lifecycle and independent-code boot remain open.

The later [environment and key-policy pass](BOOT_ENVIRONMENT_AND_KEY_POLICY.md)
executes 64 cases covering environment wrappers, the reason cache/retained copy,
key polling and the caller prefix constructing the 298-byte `upgrade` record.
The setter status is ignored by that caller, and its following commit function
simply returns zero. Backend persistence and subsequent recovery dispatch remain open.
