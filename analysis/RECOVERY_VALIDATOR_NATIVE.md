# Native boot recovery validation with synthetic partitions

This pass extends [BOOT_RECOVERY_AND_METADATA.md](BOOT_RECOVERY_AND_METADATA.md)
from static association into bounded execution of selected boot validation code.
All 62 new native cases pass: seven CRC, thirteen metadata-policy, thirteen
signature-orchestration, ten image-validator and nineteen partition/wrapper
cases. They total 24,438 steps including intercepted calls; the maximum is
2,567. All 495 Python tests pass, including 24 new checks. Complete observations,
code/data/export hashes and limitations are in
[recovery-validator.json](recovery-validator.json).

The code runs in Ghidra's emulator with synthetic partition contents. Partition
I/O, allocation/memory/string services, board properties, time, SHA-256 hardware
wrappers and ECDSA arithmetic are supplied. The actual CRC, policy, hash/read
orchestration, key/curve bridge and partition/wrapper control flow execute.
No recovery entry, counter/environment update, flash write or device operation
is performed. These results do not establish an independent-code boot route.

## 1. Recovery header CRC

| Routine / data | Native contract |
| --- | --- |
| `0x80c00b52(seed, bytes, length)` | Reflected CRC-32 update with polynomial `0xedb88320`; no entry/exit complement |
| `0x80c00b24(seed, bytes, length)` | Complement seed, perform the same update, complement result |
| `0x80c32e8c` | 256-word table; every word matches the independently generated polynomial table |
| Partition validator | Seed `0xffffffff`, first 68 header bytes, compare raw result with little-endian word at header + 68 |

For `123456789`, the raw seeded result is `0x340bc6d9`, and the complemented
form with seed zero is `0xcbf43926`. The selected recovery header stores the raw
form; applying the usual final inversion changes the compared checksum. Native
fixtures include empty input, the known string, all byte values and a custom
seed; host tests also check incremental continuation and the standard-library
CRC relationship. Correct return metadata restores the CRC value omitted by
the older void-return decompilation.

## 2. Selected 48-byte metadata policy

Actual `0x80c0e578(metadata, expected_magic_low, expected_magic_high)` calls
board-property helpers before comparing metadata. Supplied absent OTA-version
information produces a diagnostic but does not itself abort this function.
For the supplied board hardware byte:

- `0xff` logs unknown hardware and skips the nibble compatibility comparisons.
- Otherwise metadata and board high nibbles must match, and the metadata low
  nibble must be at least the board low nibble. Failures log distinct `0xb4`
  and `0xba` diagnostics.

The two magic words must match the caller's expected values. Product field
at + 14 must be 155. For expected `HMZPSIGN`, variant at + 16 must additionally
be 256; selected matching `HMRVYSIG` fixtures do not require that variant value.
The checker does not inspect metadata size at + 8 or body-size fields in these
paths. Native cases include an inconsistent synthetic size/body field accepted
by this checker, with the crypto service separately supplied.

This does not make the native recovery path a general parser for 64-byte
metadata. Its image validator reads exactly 48 bytes at `image_end - 112`.
The host [signed_metadata.py](../analysis_scripts/signed_metadata.py) supports
the observed self-sized variants for structural inspection; those are different
contracts. The hardware byte at + 38 in the selected boot/recovery layout must
not be interpreted as a timestamp as in the 64-byte layout, or vice versa.

## 3. Image checks, signed coverage and key bridge

`0x80c0e6ea(fd, start, total, version_out, capacity, magic_low, magic_high, verify)`:

1. Rejects total below 112; reads exactly 48 metadata bytes at
   `start + total - 112` and requires the read result to equal 48.
2. Copies metadata, executes the actual policy above and returns failure if
   it rejects the input.
3. When verify is nonzero, calls actual `0x80c0e3c2`, whose wrapper explicitly
   supplies a null progress callback to `0x80c0e38c` / `0x80c0e180`.
4. On success, optionally copies the metadata version, then forces a terminator
   at `capacity - 1`. Zero capacity/null output skips copying in this inner path.

The signature path rejects total at most 64, reads the final 64 bytes as the
signature, allocates a 4,096-byte read buffer and processes every preceding
byte in chunks up to 4,096. Exact chunk boundaries do not cause an empty extra
chunk. Native control code executes the SHA init/update/final calls, while the
runner supplies SHA-256 over the actual intercepted input bytes. It does not
execute the hardware SHA implementation or its MMIO/clock/cache behavior.

Hash coverage includes the metadata and excludes exactly the final 64 signature
bytes. The hash read buffer is released after finalization and before the
verification bridge. A supplied progress callback receives hashed-byte progress
and the total size including the signature; for total 4,161 its calls are
`(4096,4161)` and `(4097,4161)`.

Actual bridge `0x80c0e144` copies 64 key bytes from `0x80c36c94`, obtains the
curve-record pointer `0x80c3f378` through `0x80c2c5aa`, then calls the supplied
ECDSA service at `0x80c2c5b4(key, digest, 32, signature, curve)`. Native code
Boolean-normalizes its return. Key hash
`436da64f07264e8d1ddf568e7ec0edce6e52ea0f469af4ca54a36a2761aff547`
matches the embedded key used by the earlier independent host signature checks
in [ota-signatures.json](ota-signatures.json). Current native fixtures supply
crypto results; they do not repeat the ECDSA arithmetic or prove device
enforcement. Earlier host mathematical checks remain separate evidence.

The signature orchestration does not check the signature/body read return counts
before passing data onward. Bounded direct-signature fixtures supply short reads:
the signature's missing byte retains its initial synthetic backing value, and
body hashing includes the requested byte count, including unchanged read-buffer
bytes. The verifier is still called. Those cases supply rejection; they do not
establish a signature bypass or a reachable live fault. Header/metadata read
counts are checked earlier and stop their respective paths immediately.

## 4. Partition validation and mandatory wrapper

Actual `0x80c0e7e0(selector, verify, version_out, capacity)` allocates a 72-byte
header, then selects `recovery0` for 0, `recovery1` for 1 or `recovery_ota` for 8.
Invalid selectors, open failure, a short header read, incorrect `RECO` magic
or incorrect raw CRC fail before image validation. The header's image length
at + 16 controls validation at partition offset `0x1000`.

The selected path calls actual image and signature orchestration, compares the
version against header + 20 with length 15, optionally returns a version,
closes the handle and releases the header. Error cases verify the corresponding
cleanup, including a rejected signature and version mismatch. All successful
allocations' complete hashes and release state are checked.

Inner version extraction uses capacity 15 and overwrites byte 14 with zero.
Thus a synthetic 15-character metadata version can fail the header comparison
even when the source header contains the same 15 characters. Outer output is
capped at 16 bytes and supports capacity one by writing just the terminator.
Outer nonnull output capacity zero/negative is excluded from this bounded model.

Most importantly, actual wrapper `0x80c0e9c2(selector)` supplies verify=1 and
null version output when calling this validator. A lower-level fixture with
verify=0 can skip the supplied cryptographic check, but the real wrapper ignores
that fixture preference and performs it. This is a call-contract distinction;
no caller-controlled bypass on the watch is established.

Recovery selection, preparation, counter updates and image handoff are not
executed in this pass. Physical partition contents, backup/restoration behavior,
non-destructive entry and standalone boot remain unresolved.

## Reproduction

Use startup-aware `boot-runtime` / `boot-runtime.elf` under
`firmware/ghidra-runtime`, the established guarded AndeStar repair and corrected
logger metadata. Boot analysis strips the original outer `0x400` bytes; evidence
checks the original bootloader member hash before mapping copy/zero tables.
Apply `SeedRecoveryValidator.java` and export its ten `recovery_validator.py:TARGETS`
using `DecompileWithLogger.java`, logger `0x80c1cd7a`, into ignored
`firmware/decompiled/runtime-recovery-validator/`.

```sh
python3 analysis_scripts/recovery_validator.py \
  --vectors-output firmware/recovery-validator-native-vectors.json
```

Run with `-process boot-runtime.elf -noanalysis`:

```text
-postScript ValidateRecoveryValidator.java firmware/recovery-validator-native-vectors.json firmware/recovery-validator-native-validation.json
```

```sh
python3 analysis_scripts/recovery_validator.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/runtime-recovery-validator \
  --vectors firmware/recovery-validator-native-vectors.json \
  --validation firmware/recovery-validator-native-validation.json > analysis/recovery-validator.json
python3 -m unittest discover -s tests -p 'test_recovery_validator.py' -v
```

The runner guards code/CRC-table/key hashes, rejects unexpected PCs/logs/service
arguments and caps each case at 100,000 steps. Stack/`s0..s11`, immutable input,
output/heap guards and complete buffer hashes are checked. Read requests, hash
chunks, progress, digest/signature/key bridge fields, diagnostics, cleanup and
returns are compared with an independent host contract. Vendor code, binaries,
Ghidra databases and tools remain ignored; byte/export counts are provenance,
not semantic-coverage percentages.
