# Bip 6 backup, recovery and signed boot feasibility

**Flashing remains blocked as of 2026-11-22.** The Bip 6 is reachable through
the existing phone connection. The inventory verifies **one stock OTA**. A
physical backup, a tested restoration route and an accepted boot path for
SpellboundOS are still required. [Project goal](../GOAL.md).

```sh
python3 -m analysis_scripts.backup_audit firmware analysis/bip6-stock-ota-inventory.json
python3 -m analysis_scripts.verify_ota_signatures firmware/bip6-4.6.0.3.zip
```

The first command compares the recorded byte length and SHA-256. The second
reproduces the checked-in result for the ZIP and all five signed members
(bootloader, main firmware, recovery, factory firmware and sensor hub). All
six signatures verify against the archived bootloader's public key and each
modified payload is rejected offline. The physical watch's root of trust and
the effect of the recorded `META/res_info` manifest mismatch on recovery
remain unknown. [Acquisition and manifest notes](../README.md#ota-catalog).

For future local captures, keep a private schema-1 inventory with one artifact
entry per file. Record its basename, byte length, SHA-256 and kind
(`stock_ota`, `device_readback` or `device_export`). Record the identity of the
source device and the capture method separately in the private working
directory. A file of any kind passes the tool only when its length and digest
match the inventory. The kind is supplied by the investigator and describes
provenance. It does not prove coverage.

## Physical observations

After the user connected the phone by USB, host USB and ADB enumeration saw
the Samsung SM-S921B. Android's Bluetooth service showed an active encrypted
LE link to the Amazfit Bip 6 and an open GATT channel held by Gadgetbridge and
Android HID. This session observed the existing connection through Android
diagnostics. The firmware 4.6.0.3 and hardware 0.135.23.0 identifiers are from
the earlier [device inventory](../README.md).

Host USB enumeration was identical before and after the user connected the
magnetic puck to the computer and confirmed charging on the running Bip 6.
The watch stayed connected over BLE. The manufacturer identifies the model as
A2435 and describes the supplied accessory as a charging puck. The physical
unit's service interfaces and fitted NAND remain unknown.
[Amazfit product manual](https://support.amazfit.com/us/amazfit_bip_6/imgs/electronic_manual.pdf),
[A2435 certification photos, FCC exhibit 8066732](https://device.report/m/81e1dd377853159e1a1edb0629cdded0572f030daedf582a1499f987476b4996.pdf).

## Signed bootloader replacement

The stock OTA 4.6.0.3 includes a bootloader update declaration and a signed
bootloader 2.0.6. The archive's manifest and metadata identify that version,
and the image signature verifies offline against the archived key. Separate
single-byte changes in the outer wrapper, the executable body and the signed
metadata each caused offline verification to fail. The analysis ELF starts at
the executable body. The watch's bootloader version, the update's effect on
this unit and the trust policy that admits a bootloader at startup remain
unverified on the device.
[Package manifest](PACKAGE_MANIFEST.md), [Signature report](ota-signatures.json).

A fresh query of the public Amazfit catalog for Italy and device source
10158337 offered no OTA from 4.6.0.3. A query from version `0` returned the
same stock 4.6.0.3 package. These are catalog responses for those parameters.
[OTA catalog query](../ota_check.py), [Stock package record](../README.md#ota-catalog).

Amazfit documents the regular update through Zepp. Zepp also documents a
generic system reinstall after a startup failure. The public sources reviewed
give no A2435 procedure that confirms a bootloader-only reinstall or documents
a signed development image. Ask Amazfit service whether it offers either for
A2435 hardware 0.135.23.0, and whether its stock restore works when the
bootloader itself fails to start.
[Bip 6 user manual](https://support.amazfit.com/it/amazfit_bip_6/files/user-manual.pdf.pdf),
[Zepp reinstall guide](https://docs.zepp.com/docs/guides/faq/re-install-system/),
[Amazfit Italy support](https://it.amazfit.com/pages/contact).

## Evidence required before a flash attempt

- **Recoverable physical backup.** Obtain a documented or hardware-verified
  read-only acquisition method. Record the fitted NAND and geometry, read
  independently twice and compare hashes over stable physical data, including
  spare/OOB, factory bad-block markers and translation metadata. Account for
  unreadable pages, ECC mode and any regions outside the NAND required for
  restoration. The archived table provides coverage targets for boot, recovery
  slots, `nvms`, `env`, `envbak`, `userdata` and filesystems. Its offsets need
  runtime geometry and translation. [Archived partition table](STORAGE_MAP_AND_DRIVER_BINDINGS.md).
- **Independent stock recovery.** Zepp documents a generic reinstall through
  its app for a specific failure screen. Ask Amazfit whether it applies to
  A2435 hardware 0.135.23.0 when the stock main firmware fails, whether it can
  reinstall the same signed version and which device-specific data it preserves.
  The analyzed manager returns after a main signature failure. The candidate
  recovery entry and handoff can update persistent records. A restoration
  rehearsal can use an equivalent spare with its own verified backup. Check
  post-restore readback, stock boot and preservation of device-specific state.
  [Zepp reinstall guide](https://docs.zepp.com/docs/guides/faq/re-install-system/),
  [boot manager](MAIN_RECOVERY_GATE.md), [recovery entry](BOOT_RECOVERY_AND_METADATA.md),
  [recovery handoff](RECOVERY_SELECTION_AND_HANDOFF.md).
- **Boot SpellboundOS.** The archived main-image loader requires successful
  signature verification before handoff. Seek a vendor-supported unlock,
  signing program or temporary lab boot path for this hardware revision.
  Zepp's Developer Bridge documents installation and testing of apps and watch
  faces in Zepp OS. Standalone boot requires an accepted image and an observed
  handoff on the target. [Main-image loader](MAIN_BOOT_GATE.md),
  [Zepp Developer Bridge](https://docs.zepp.com/docs/guides/faq/developer-bridge-mode/).

Gadgetbridge can export data already collected by the phone app. Keep any such
archive private. [Gadgetbridge export](https://gadgetbridge.org/internals/development/data-management/#manual-export).
