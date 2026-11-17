# Bip 6 static analysis, OTA 4.6.0.3

Status as of November 14, 2026. These observations concern the OTA identified by
SHA-256 `ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
This is not a readout of the device's flash. Strings establish that the software
references components, not that each component is fitted or used on this unit's
hardware revision. No source code or working drivers had been recovered at this
stage. See [RE_STATUS.md](RE_STATUS.md) for subsequent findings.

## Method and evidence

REA 6.9.0, using Binwalk 3.1.0, inventoried the ZIP and scanned the firmware,
bootloader and recovery. Full evidence is under `firmware/rea-*.json`;
Binwalk signatures are candidates, not validated formats or partitions.
REA does not accept RISC-V raw binaries in its Ghidra workflow. Ghidra 12.1.2
headless was therefore used separately, with language `RISCV:LE:32:default` and
compiler `gcc`. Binwalk and Ghidra were extracted into `/tmp/spellbound-tools`
from Arch packages verified against their signatures using the pacman keyring.
REA ran through its CLI without configuring MCP.

`python3 inventory_firmware.py firmware/bip6-4.6.0.3.zip --output analysis/hardware-strings.json`
regenerates the string inventory, including each member's hash and offsets in
decompressed members. It contains no hardware addresses and establishes no
hardware operation. The search is limited to the four selected executables and
the script's patterns.

## Boot and verification: observations and limits

The bootloader header at offset `0x400` begins with a RISC-V instruction and
contains `HDRZ` and the value `0x80c0022c`. Only the file from `0x400` onward was
imported, assuming base `0x80c00000` and entry `0x80c0022c`. This mapping was a
hypothesis supported by coherent strings and references in Ghidra, not a bus
measurement. Scripts are in `analysis_scripts/`; the project and full log are
in `firmware/ghidra-project/` and `firmware/ghidra-boot.log`.

Under that mapping, code at `0x80c00918` invokes the loader for
`/mnt/system/firmware_sign.bin` at `0x70160000`, then jumps there only if the
loader reports success. The loader at `0x80c00876` calls `0x80c0e2b6`; its error
path references `firmware secure verify failed!!!` at file offset `0x3310c`.
In pseudocode, `0x80c0e2b6` separates the file's last 64 bytes, passes the preceding
bytes to functions associated with the string `SHA256`, and submits the 32-byte
result and final 64 bytes for verification. `0x80c0e144` also passes 64 bytes
embedded in the bootloader to another routine. See `firmware/ghidra-verify2.log`.
An independent check in `analysis_scripts/check_signature.py` establishes that
those 64 bytes form an ECDSA secp256k1 public key and that the `r || s` signature
in the firmware's final 64 bytes verifies against the SHA-256 of all preceding
bytes. `recovery_sign.bin` and `fct_test_sign.bin` verify with the same key and
scheme. Altering one byte causes offline verification to fail for each of the
three files. This confirms their signature scheme, not the actual conditions
on every boot path. Developer modes or other boot paths have not been
established. At this stage, Ghidra reported custom RISC-V instructions and
unmapped accesses, leaving the pseudocode incomplete.

The raw recovery path selects `recovery0`, `recovery1` or `recovery_ota`, checks
a `RECO` header and loads data from offset `0x1000` into `0x80d00000`. A validation
path is visible, but custom instructions not decoded at this stage prevented
establishing its details or a bypass. This is not a verified alternative boot
route. See `firmware/ghidra-recovery-check3.log`.

The OTA cannot be described as a verified restoration image, an unlockable
bootloader has not been established, and changing filehash does not establish
that modified firmware will boot. Do not write the bootloader, recovery, flash
or permanent settings without a tested recovery route.

## Candidate interface inventory

| Subsystem | Static evidence | Still to establish |
|---|---|---|
| SoC/RTOS | `board_mhs003`, `MHS003_A1/A2/A3`, FreeRTOS path `portable/GCC/mhs003`; RISC-V instructions | CPU variant, extensions, MMIO, interrupts, clocks, RAM and memory map |
| Display | `dev_lcd`, `display_panel_read_id`, `hal_display_init`, VGLite | Controller, power supplies, bus and initialization sequence |
| Touch | `dev_ztw622`, `drv_touch_ztw622_probe`, I²C routines | Presence on this unit, address, GPIO, interrupts and protocol |
| Light | `dev_stk31e60`, register reads/writes | Presence, bus, address and calibration |
| Memory | NAND, FTL, flash, PSRAM, partitions, backup | Model, organization, ECC, bad blocks, partitions and unique data |
| Power | PMIC and `cw6305` charger | Actual component, registers and safe operating limits |
| Radio | `rtl8763`, UART, `extfw/pamir/rtl8763_pack.bin` | Exact role, transport, firmware and control commands |
| Motion sensors | Separate sensor hub with `dev_lsm6dso`, `dev_bmi2xx`, SPI/I²C buses; AKM09918C/MMC5603 configurations | Actual fitted variant, buses and registers |
| Audio/GNSS | Speaker/audio references and GNSS firmware | Codec, amplifier, audio routing, GNSS chip and control |

Functions in the blobs can help reconstruct interfaces, but are not reusable
source code or freely redistributable components. The open-source project needs
separate drivers implemented and verified using available specifications and
board measurements.

## Work sequence

1. Map loaders and the verification chain, identify a recovery mode and obtain
   a verifiable backup of flash and device-specific data.
2. Identify the revision, chips, supplies, pins and buses using physical evidence
   and/or non-destructive diagnostics; map initialization and protocols.
3. Prepare a RISC-V environment and HAL with off-device tests; proceed only when
   the boot and recovery route is reproducible.
4. Design the companion protocol with mutual authentication, authenticated
   encryption, replay protection and key management. Study Android notifications,
   calls and each client's reply limits separately. Classic Bluetooth audio/calls
   may require work distinct from BLE notifications; this is not yet established
   for the hardware.

## Additional verification on November 15, 2026

The reproducible check `analysis_scripts/verify_ota_signatures.py` reads the
original archive and also verifies `bootloader_sign.bin` and
`sensorhub@mhs003_sign.bin`: both have valid ECDSA secp256k1 signatures using
the same public key and SHA-256 / `r || s` scheme as the preceding three
executables. For all five, altering one payload byte fails verification.
Results and hashes are in `analysis/ota-signatures.json`.

The key comes from the bootloader in the same archive. Verification establishes
internal cryptographic consistency, not independent package authenticity or
where and when the device checks each image. The bootloader verifying with a
key it contains does not establish how the bootloader itself is authenticated
during startup.
