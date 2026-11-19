# Bootloader main-firmware load, signature gate and image handoff

All **10 native cases** pass in **460 instruction steps**. This scope executes
the original bootloader boot decision at `0x80c00918` and the firmware loader at
`0x80c00876` end to end in the `boot-runtime` project, supplying the file-system
leaves (stat/open/read/close), the signature verifier `0x80c0e2b6` and the image
handoff `0x80c0084a` as stubs. The evidence is in
[main-boot-gate.json](main-boot-gate.json).

This upgrades the boot-chain control flow in
[BOOT_RECOVERY_AND_METADATA.md](BOOT_RECOVERY_AND_METADATA.md) from static
reading to bounded execution. It is directly relevant to whether a modified
main firmware could ever boot, and therefore to any future attempt at a safe
install.

## The gate

`FUN_80c00918` is the main-firmware boot decision:

1. Run pre-load init (`0x80c0b190`).
2. `stat("/mnt/system/firmware_sign.bin")` for the image size.
3. If the size exceeds `0xe00000` (14 MiB), log
   `firmware is too large , size 0x%08X, limit 0x%08X` and **return without
   loading**.
4. Otherwise call the loader `FUN_80c00876(path, 0x70160000)`.
5. If the loader returns `0` (success), log `jump to address 0x%08X` and hand
   off to the image at `0x70160000` (`0x80c0084a`).
6. If the loader returns nonzero, log `load firmware failed!!!` and **return
   without handing off**.

`FUN_80c00876` is the loader:

1. `stat` the file for its size.
2. `open` it; a negative handle logs and returns `0xffffffff`.
3. `read` the whole image to `0x70160000`; if the byte count does not equal the
   stat size, log, close and return `0xffffffff`.
4. `close`, then call the signature verifier `0x80c0e2b6(image, size)`.
5. If the verifier returns nonzero, return `0` (success). Otherwise log
   `firmware secure verify failed!!!` and return `0xffffffff`.

So the main firmware at `0x70160000` is entered **only** when the loader returns
success, which happens **only** when the signature verifier returns nonzero.
Every other outcome — verification failure, a short read, a failed open, or an
oversize image — returns to the caller without any jump into the loaded bytes.

## What the executed cases show

| Case | Verifier | Outcome |
| --- | --- | --- |
| `verified_firmware_hands_off` | pass | handoff to `0x70160000` |
| `maximum_size_still_loads` | pass | 14 MiB exactly still loads and hands off |
| `verify_failure_no_handoff` | fail | two failure logs, no handoff |
| `oversize_firmware_rejected` | — | rejected before open/verify |
| `open_failure_no_handoff` | — | no read, no verify, no handoff |
| `short_read_no_handoff` | — | handle closed, no verify, no handoff |
| `loader_*` | both | the loader returns `0` only after a nonzero verifier result |

The verified path is observed to call the verifier strictly before the handoff,
and the handoff is the final action. The verify-failure path calls the verifier
and then two loggers (the loader's "secure verify failed" and the decision's
"load firmware failed") and returns.

## Relationship to the signature verifier

`0x80c0e2b6` is supplied here with a pass/fail result to exercise both branches
of the boot decision. Its internals are the ECDSA secp256k1 over SHA-256 check
against the embedded public key; the equivalent orchestration is executed for
the recovery image in [RECOVERY_VALIDATOR_NATIVE.md](RECOVERY_VALIDATOR_NATIVE.md),
and the archive/image signatures are checked independently in
[OTA_ARCHIVE_SIGNATURE.md](OTA_ARCHIVE_SIGNATURE.md). Supplying a passing result
here does not imply a bypass: producing a nonzero verifier result on the device
still requires a signature that validates against the embedded key, i.e. the
corresponding private key.

## Safe-boot feasibility, honestly

This block strengthens, with execution, the central obstacle recorded in
[GOAL.md](../GOAL.md):

- The normal boot path does not execute unsigned or modified main firmware.
  There is no observed branch in the decision or the loader that jumps to the
  image without a positive verifier result. A custom main firmware cannot boot
  through this path without a valid signature.
- The failure behaviour is a clean return, not a jump into unverified bytes, so
  a failed verification does not by itself execute attacker-controlled code
  here. Whether a failed main boot then automatically enters the recovery image
  (prepared by `0x80c0eaa6` and handed off by the already-covered
  `0x80c0098c`/`0x80c0084a`) versus halting is a policy of the caller above
  `0x80c00918` and the boot reason, covered in
  [RECOVERY_SELECTION_AND_HANDOFF.md](RECOVERY_SELECTION_AND_HANDOFF.md).

What this does **not** establish, and what a safe boot attempt still requires:

1. A complete, verified physical backup of the device flash. The OTA is not a
   full flash/ROM dump, so a backup needs on-device read access (test points,
   a recovery read command, or a debug port) that cannot be obtained offline.
2. A reliable, tested recovery-entry gesture and the guarantee that recovery can
   always restore a known-good signed image after a bad write.
3. Confirmation of device-side enforcement: this is emulated boot-image code,
   not an observation of the silicon honouring the check (e.g. a mask-ROM or
   eFuse root of trust) or of debug-port lockdown.

Until 1–3 are satisfied with device evidence, no write to the watch is
justified. This remains a hard feasibility gate, not a solved problem.

## Reproduction and remaining work

```sh
python3 -m analysis_scripts.main_boot_gate --vectors-output firmware/main-boot-gate-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime boot-runtime \
  -process boot-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateMainBootGate.java firmware/main-boot-gate-vectors.json \
  firmware/main-boot-gate-validation.json
python3 -m analysis_scripts.main_boot_gate firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-boot-gate-vectors.json \
  --validation firmware/main-boot-gate-validation.json > analysis/main-boot-gate.json
```

The vectors, native report and evidence regenerate byte for byte. The boot
project is opened read-only.

Remaining work:

- Execute the caller above `0x80c00918` to establish whether a failed main boot
  deterministically falls through to recovery (the safety guarantee) or halts.
- Execute `0x80c0e2b6` itself for the main image, as the recovery validator does
  for the recovery image, to confirm the hashed region and key for main firmware.
- Everything in the feasibility list above needs on-device observation.
