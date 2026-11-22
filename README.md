# SpellboundOS

SpellboundOS is a new standalone operating system for the Amazfit Bip 6, developed alongside the SpellboundFit Android companion. See [GOAL.md](GOAL.md) for the project goal and [PROGRESS.md](PROGRESS.md) for the work log.

> **Project status: on standby, pending a boot feasibility assessment.**
> Reverse engineering established that the signed boot chain is anchored by a key
> embedded in the bootloader, so booting SpellboundOS reduces to replacing the
> bootloader, which in turn depends on whether the SoC's on-die mask ROM enforces
> a signature on the bootloader. The application processor is captive Zepp
> silicon with no public documentation, and the watch has no wired debug port.
> The only avenue that could admit a custom bootloader is hardware fault
> injection, assessed as expert-level, destructive and low-probability on a
> single undocumented unit — out of scope for now. Standalone-OS work is
> therefore paused until that feasibility question is resolved; companion-app and
> within-signed-system work may continue. See
> [ROOT_OF_TRUST_AND_BOOTLOADER_KEY.md](analysis/ROOT_OF_TRUST_AND_BOOTLOADER_KEY.md)
> and [FAULT_INJECTION_FEASIBILITY.md](analysis/FAULT_INJECTION_FEASIBILITY.md).

Current reverse engineering status: [RE_STATUS.md](analysis/RE_STATUS.md).
Recent evidence links the [62 application modules](analysis/APPLICATION_SERVICES.md)
to the firmware and verifies a [synthetic notification over the live connection](analysis/NOTIFICATION_ACTIONS_AND_ROADSTR.md).
The sections below preserve the initial observations; the work log and linked
reports document subsequent verification and corrections.

# Bip 6: OTA acquisition and initial analysis

For REA/Ghidra analysis, the boot chain and the hardware inventory, see
[analysis/ANALYSIS.md](analysis/ANALYSIS.md).

The RV32 prototype under `kernel/` targets **QEMU virt** and communicates through
its emulated UART. With Clang, LLD, llvm-objcopy and system QEMU available,
`make test` checks boot, serial I/O, scheduling and preemption, the timer, heap boundaries and
trap diagnostics. See [the kernel guide](kernel/README.md) for build options.

The Python analysis suite needs `cryptography` for channel, notification and
signature tests. Run it with `python3 -m unittest discover -s tests` from the
repository root.

Device identified through Gadgetbridge on November 14, 2026: Amazfit Bip 6,
firmware 4.6.0.3, hardware 0.135.23.0, deviceSource 10158337, product ID 155 and
product version 257. No writes were made to the watch.

## OTA catalog

`python3 ota_check.py` queries the public Amazfit endpoint for this variant,
using Zepp 10.9.0-play (151983), from versions 4.6.0.3 and 0, in regions
IT, US, PL, CN and RU. It requires Internet access. The parameters follow the
[Zelp](https://github.com/otaj/zelp/blob/master/lib/services/firmware_client.dart)
client; the [ZeppOS-DevicesList](https://github.com/melianmiko/ZeppOS-DevicesList/blob/main/zepp_devices.json)
catalog maps deviceSource 10158337 to productionId 240. The server responded with
productionSource 257. The two fields must not be assumed interchangeable without
further verification. In the recorded responses, no region offered an update
from 4.6.0.3; from 0, all offered 4.6.0.3 with `diffUpgradeFlag: false`. This does
not establish that the package is a complete flash dump or a recovery procedure.

Official package: [Amazfit download](https://huami-firmware-cdn.huami.com/10158337/fw_4.6.0.3_202609241131_c67028810ecb4084b4adc9f110f6c52d_watch%40mhs003_ota_sign.zip).
Local copy: `firmware/bip6-4.6.0.3.zip` (excluded from Git). Size: 118618487
bytes; MD5 `6bd12c8430b97faaba434127fbee7d37` matches the API response;
SHA-256 `ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
CRC checks pass for all 12885 ZIP entries.

## Initial static observations

- `packageDiscription.json` lists platform `mhs003`, firmware 4.6.0.3,
  bootloader 2.0.6 and a bootloader update command. `META/fw_info` also lists
  recovery 2.3.1.
- `update-script` contains `mkfs("SYSTEM")` and extraction of `META/` and
  `filehash` onto the system filesystem. Do not run it on the device.
- The package contains `firmware_sign.bin`, `bootloader_sign.bin`,
  `recovery_sign.bin`, sensor hub firmware, resources, apps and activity models.
  Their names suggested signatures; the algorithm, actual enforcement and
  ability to boot modified code had not been established at this initial stage.
  See the linked reports for subsequent signature verification.
- `filehash` lists 12882 SHA-256 values: 12881 match; **META/res_info does not
  match** (expected `76b3f5426ff0b6a4843e430c4612de7f945504364fefbcd0d9101cf2d12f9107`,
  actual `56a3ea9f6d1242714e66665d97316ce1b01bdb9c0c9c85711870f9ca0a0898ee`).
  The expected value matches the hash of `META/build_info`. The cause and effect
  on the OTA process are unknown; matching the API checksum establishes neither
  cryptographic authenticity nor the manifest's internal validity.

## Initial next steps

Study headers, signatures, recovery/boot code, app formats and relationships
between the manifest and resources offline; look for mhs003 debug and recovery
documentation. Identify the components responsible for sensors, collection and
transmission before designing changes. No modified privacy image or verified
recovery method is available: removing resources does not establish that
tracking is disabled, and changing the OTA can make it unbootable. See
[PROGRESS.md](PROGRESS.md) for work completed after this initial assessment.
