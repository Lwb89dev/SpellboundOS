# Watch-side OTA install path: integrity, validation and persisted records

The live [Gadgetbridge session](LIVE_GADGETBRIDGE.md) observed a BLE connection
to stock firmware. This note reverse-engineers the watch-side OTA pipeline
that receives packages and decides whether to stage them. The evidence is in
[main-ota-install.json](main-ota-install.json). Physical backup and recovery
access are tracked in [the feasibility record](RECOVERY_INPUTS.md).

## Delegate and state machine

`bx_ota_control_init` asserts a delegate of **six downloader callbacks**:
`ota_state_for_downloader`, `downloader_request_start`,
`downloader_write_chunk_data`, `downloader_request_validate`,
`downloader_request_upgrade` and `downloader_request_complete`. A single OTA
manager owns one global state byte at `0x70f95948`; every transition is logged
`"OTA state %d -> %d"` by the setter `0x7021b364` (mutex-guarded). The transfer
is chunked: `request_start` opens the file, `write_chunk_data` appends, and
`request_validate` runs the integrity check before `request_upgrade` stages it.

## Integrity: standard CRC32 (native)

- The core is `0x70161360(crc, buffer, length)` — a **reflected CRC32 update**
  that indexes the 256-entry table at `0x709bc4fc`. The table is verified to be
  the standard `0xedb88320` polynomial table.
- The OTA code seeds it with `0xffffffff`, chains it in `0x4000`-byte chunks
  (`ota_calculate_file_crc32` `0x7021e3ba`) and finally inverts the result
  (`not`), i.e. the **standard zlib CRC32**.
- This function executes natively in `main-runtime`. All **8 cases** pass. The
  check vector `"123456789"` gives `0xCBF43926` after inversion, and a
  two-chunk run (`range(16)` then `range(16,32)`) reproduces the one-pass CRC of
  the 32 bytes — proving the function is a pure chained update.

## Validation flow (`downloader_request_validate`, `0x7021b990`)

1. If the start size is zero, the CRC32 check is skipped.
2. The CRC32 **received in the BLE start header** must equal the file's declared
   CRC32, else `received CRC32 … != file CRC32`.
3. The file is then **read back from flash** and its CRC32 recomputed; it must
   equal the declared CRC32 again, logging `readback CRC32 matched!`.
4. Only then does the state advance toward `request_upgrade`.

The readback step means the stored file is re-hashed from flash, not trusted
from the transfer — a corrupt write is caught before the package is staged.

## Persisted records (survive reboot for recovery)

Records are base64-encoded (`0x7030c06c`) and stored as **system properties**
(`0x7030c300`), restored with `0x7030bf98`:

- **Download record** — `file_type(1), file_size(4), CRC32(4), received_size(4),
  received_CRC32(4)` — keyed per file type by the 9-entry table at `0x709ed450`:
  types `0/254/48/49/50/51` → `ota.record.v1.firmware`, types `8/252/160` →
  `ota.record.v1.data`.
- **Upgrade-package record** — 40 bytes, key `ota.record.v1.upgrade.package`.
  It is only saved once a download record exists whose file size and CRC32
  agree, tying the staged package to a verified transfer.

## Module catalog and ceilings

The 13 upgrade modules at `0x70f60fa8` map a file type to an install path:

| File type | Install path |
| --- | --- |
| 0, 254, 48, 49, 50, 51 | `/mnt/data/ota/firmware.bin` |
| 8, 160, 252 | `/mnt/data/ota/data.bin` |
| 19 | `/mnt/data/resources/offlineasr_data.zip` |
| 224, 3, 144 | (bootup transfer modules; no `+4` path) |

Bootup staging also uses `/mnt/cache/ota/firmware.zip`,
`/mnt/cache/ota/bootloader.zip`, `/mnt/system/extfw/backup_fw_sign.zip` and
`/mnt/system/extfw/boot_res_sign.bin`. File-size ceilings:
**firmware 0x20000000 (512 MiB)**, **data 0x200000 (2 MiB)**.

## Reproduction

```sh
python3 -m analysis_scripts.main_ota_install --vectors-output firmware/main-ota-install-vectors.json
firmware/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless firmware/ghidra-runtime main-runtime \
  -process main-runtime.elf -noanalysis -readOnly -scriptPath analysis_scripts \
  -postScript ValidateNativeScope.java firmware/main-ota-install-vectors.json firmware/main-ota-install-validation.json
python3 -m analysis_scripts.main_ota_install firmware/bip6-4.6.0.3.zip \
  --vectors firmware/main-ota-install-vectors.json \
  --validation firmware/main-ota-install-validation.json > analysis/main-ota-install.json
python3 -m unittest tests.test_main_ota_install -q
```

## Remaining

- The **bootloader apply step** after reboot (`Upgrade bootloader/firmware/boot
  resource`) and the **cryptographic image signature** it checks — this block
  covers transfer integrity (CRC32) and the persisted records, not the signed
  install. The boot gate itself is in [MAIN_BOOT_GATE.md](MAIN_BOOT_GATE.md).
- The BLE/BT downloader transport that calls `write_chunk_data` (below
  `bx_hal_trans`), still to be executed.
- The backup-firmware recovery path (`.backup_start`, `backup_fw_sign.zip`) as a
  recoverability guarantee.
