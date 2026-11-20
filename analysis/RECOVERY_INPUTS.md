# Bip 6 backup and restoration evidence

The local OTA 4.6.0.3 archive matches the recorded size and SHA-256. The
inventory verifies **one stock OTA**. There is currently no device readback
or device export in the inventory.

```sh
python3 -m analysis_scripts.backup_audit firmware analysis/bip6-stock-ota-inventory.json
python3 -m analysis_scripts.verify_ota_signatures firmware/bip6-4.6.0.3.zip
```

The first command compares bytes with the recorded inventory and reports
counts by artifact kind. The second checks the mathematical signatures against
the key embedded in the archived bootloader. Together, these checks identify
the local stock software reference. The expected hash comes from the recorded
acquisition in the [repository README](../README.md).

For future local captures, keep a private schema-1 inventory with one artifact
entry per file. Record its basename, byte length, SHA-256 and kind
(`stock_ota`, `device_readback` or `device_export`). Record the identity of the
source device and the capture method separately in the private working
directory. A file of any kind passes the tool only when its length and digest
match the inventory. The kind is supplied by the investigator and describes
provenance. It does not prove coverage.

| Evidence | Current status |
| --- | --- |
| Stock software reference | OTA inventory and offline signature checks reproduce |
| Device data and geometry | Need a documented read-only acquisition method, two independently read matching copies and an inventory of covered ranges, spare/OOB and device-specific data |
| Restoration | Need a legitimate recovery entry route and a verified restore rehearsal, including post-restore readback and original firmware boot |
| Standalone boot | The main-image gate requires a positive signature result. A supported entry path on the Bip 6 remains undemonstrated |

The local hardware inventory for this run showed no phone in ADB and no Bip 6
USB interface. ADB enumeration measures phone availability. It provides no
evidence about the watch's flash or Bluetooth connection. The project keeps
its [backup and recovery requirement](../GOAL.md) for any future device write.
