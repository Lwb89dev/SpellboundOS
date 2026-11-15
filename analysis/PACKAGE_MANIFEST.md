# Package manifest and the `res_info` mismatch

Static investigation on 2026-11-15 of the Bip 6 OTA 4.6.0.3 archive, SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The tool is
`analysis_scripts/package_manifest.py`; its output is
[package-manifest.json](package-manifest.json). The checks only hash archive
members; nothing was installed.

The first inventory pass recorded one unexplained manifest mismatch, for
`META/res_info`. This report explains it.

## Manifest

`filehash` is a single-line JSON object that maps 12,882 member paths to
SHA-256 digests. 12,881 entries match the archive. None is missing. The only
archive files it does not list are `filehash` itself, `packageDiscription.json`
(vendor spelling) and `update-script`. The one mismatching entry is
`META/res_info`.

## Why `res_info` cannot match

`META/res_info` has three lines:

```text
2026-09-24 11:54:48,root,f21c9e650e53
4.6.0.3
b9519665377b6e59a7a0a21c1ffb0bd2074051c236da792b11c96f39c6cc3560
```

| Line | Equals |
| --- | --- |
| 1: build stamp | the full content of `META/build_info` |
| 2: version | the firmware version in `META/fw_info` and `firmwareVer` in the package description |
| 3: appended hash | the SHA-256 of `filehash` itself, which the package description also gives as `resourceHash` |

The digest that `filehash` lists for `res_info` is the SHA-256 of line 1 alone.
That is also the digest it lists, correctly, for `build_info`. This fixes the
packaging order:

1. `res_info` holds only the build stamp, identical to `build_info`;
2. `filehash` is computed over the files, including that short `res_info`;
3. the version and `SHA-256(filehash)` are appended to `res_info`.

The mismatch is therefore built into the package format, not damage.
`res_info` carries the manifest's own digest, so the manifest can only record
the earlier, shorter `res_info`. Any change to `filehash` breaks the chain
through `res_info` line 3 and `resourceHash`.

## Other package metadata

`META/fw_info` lists the three boot images. All sizes and standard CRC-32
values match the archive members:

| Image | Version | Member |
| --- | --- | --- |
| firmware | 4.6.0.3 | `META/firmware_sign.bin` |
| bootloader | 2.0.6 | `META/bootloader_sign.bin` |
| recovery | 2.3.1 | `META/extfw/recovery_sign.bin` |

`packageDiscription.json` declares platform `mhs003`, the firmware and
bootloader versions, a bootloader upgrade command
`write_image("META/bootloader_sign.bin", "boot", 0);`, and a `bsdiff` policy.
Delta updates are enabled under `META/resources/fonts` and
`META/resources/locale`, with the two `allfont` TrueType files excluded.
`update-script` reads:

```text
mkfs("SYSTEM");
package_extract_dir("META/", "/mnt/system/");
package_extract_file("filehash", "/mnt/system/filehash");
```

That is, the installer formats a `SYSTEM` file system, extracts `META/` to
`/mnt/system/` and keeps the manifest there. Which component executes these
commands, and how it verifies the manifest on device, has not been traced.

## Reproduction

```sh
python3 analysis_scripts/package_manifest.py firmware/bip6-4.6.0.3.zip \
  > analysis/package-manifest.json
python3 -m unittest tests/test_package_manifest.py -v
```

The tests build a synthetic package in the same order. They check that
`res_info` is the only mismatch and that the chain validates. They also check
that tampering with a firmware image or with the manifest is detected.

## Limitations

This explains how the metadata relate to each other, not how the device
enforces them. Signature verification of the images is covered in
[OTA_ARCHIVE_SIGNATURE.md](OTA_ARCHIVE_SIGNATURE.md) and
[BOOT_RECOVERY_AND_METADATA.md](BOOT_RECOVERY_AND_METADATA.md). The update
script's interpreter, rollback behavior and the on-device use of `filehash`
remain open.
