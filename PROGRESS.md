# SpellboundOS progress

This log records completed work, evidence, and limitations. Dates refer to the
local work session. See [GOAL.md](GOAL.md) for the intended outcome and
[analysis/ANALISI.md](analysis/ANALISI.md) for detailed earlier findings.

## 2026-11-14 — acquisition and initial investigation

1. Identified the connected watch through Gadgetbridge as an Amazfit Bip 6,
   firmware 4.6.0.3, hardware 0.135.23.0. Queried the public OTA catalog and
   downloaded the official 4.6.0.3 archive. This is an OTA package, not a
   verified complete flash backup. Its SHA-256 is
   `ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`.
2. Inventoried the archive, checked ZIP CRCs and compared its file-hash manifest.
   One mismatch was observed for `META/res_info`; its effect is unknown.
3. Scanned selected binaries and recorded candidate hardware strings. These
   names alone do not prove which parts are physically fitted or functional.
4. Investigated the bootloader offline with Ghidra under an explicitly
   hypothetical memory mapping. Observed a firmware verification path and
   independently checked ECDSA secp256k1 signatures for the firmware, recovery,
   and factory-test images. A boot bypass, unlock and recovery path remain
   unproven. No firmware was written to the watch.
5. Created an independently authored RV32 QEMU virt UART/echo prototype. It is
   not specific to the watch and does not implement Bluetooth or a complete OS.

## 2026-11-15 — project direction and reproducible signature analysis

1. Recorded the standalone OS and Android companion goal in [GOAL.md](GOAL.md).
   Preserved the existing MIT license and initial commit from the SpellboundOS
   GitHub repository. Initialized a local repository in the project directory;
   the unrelated Git repository in the parent directory was left untouched.
2. Verified offline that the OTA bootloader and sensor-hub image also validate
   with the public key found in the bootloader, using the same SHA-256 and
   secp256k1 `r || s` scheme as the three images above. This is a mathematical
   check against a key extracted from the same package, not independent
   authentication of the package, proof of runtime enforcement or a bypass.
3. Added `analysis_scripts/verify_ota_signatures.py` and the reproducible output
   [analysis/ota-signatures.json](analysis/ota-signatures.json). It reads the
   archive locally, reports hashes, verifies all five signatures, and checks
   that a modified payload is rejected. Generated-key tests cover valid,
   modified, wrong-key and short inputs. Install `cryptography` in a Python
   environment, then run:

   ```sh
   python analysis_scripts/verify_ota_signatures.py firmware/bip6-4.6.0.3.zip
   python -m unittest discover -s tests -p 'test_*.py' -v
   ```

4. Re-ran the generated-key signature tests and reproduced the JSON output.
   `make test` could not run the QEMU boot test because
   `qemu-system-riscv32` is not installed in the current environment.
5. Inspected the local Roadstr repository at commit
   `1a354ae11c928c625826396e91e8b5c75342def5`. Its Android foreground service
   builds navigation notifications using an instruction and distance. This is a
   potential integration surface, not an established API or an implemented
   SpellboundFit integration. A structured, versioned interface is still needed.

## 2026-11-15 — targeted peripheral-loader decompilation

1. Revisited the prior REA inventory and imported the OTA main firmware into
   Ghidra with a candidate RISC-V mapping. Stopped broad automatic analysis
   after excessive unmapped references, then manually seeded six candidate
   functions and decompiled them without whole-image analysis.
2. Traced the sensor-hub file path, chunked loading and `LCPU` header values,
   followed the candidate validation path to a matching embedded public key,
   and identified a candidate RTL8763 package loading path. The results, exact
   offsets, reproduction command and limitations are in
   [analysis/PERIPHERAL_LOADING.md](analysis/PERIPHERAL_LOADING.md).
   Undecoded custom instructions and unresolved calls prevent a complete driver
   or boot sequence. No device writes or runtime observation were performed.

## 2026-11-15 — integrity and peripheral interface investigation

1. Followed the sensor-hub image validation path to a digest initializer with
   the SHA-256 initial state and to an unresolved public-key operation; the
   separate offline ECDSA check remains the independent signature evidence.
2. Mapped candidate LSM6DSO reset, identification, callback and SPI-like
   transfer paths in the sensor-hub image, and followed the main image's
   RTL8763 send/receive paths into indirect transport callbacks. Findings,
   addresses, assumptions and reproduction instructions are recorded in
   [analysis/DRIVER_INTERFACES.md](analysis/DRIVER_INTERFACES.md). No device
   behavior, physical pinout or reusable working driver is claimed.
3. Added small, tested tools to inspect the observed image headers and find
   candidate RISC-V PC-relative references, plus reproducible JSON evidence.
   All six Python tests passed; JSON was reproduced from the OTA and binaries,
   and the documented Ghidra sensor command succeeded in a fresh project.
   Ghidra still cannot fully decode custom instructions. No hardware was written.

## 2026-11-15 — RTL8763 package prefix

1. Inspected the radio firmware member directly. Recorded its hash, four-byte
   prefix, 0x48-byte initial area, and 15 consecutive candidate 12-byte
   records starting at offset 0x48. These are literal observations; record
   meanings are still unverified. The detailed report and machine-readable
   inventory are [analysis/RADIO_PACKAGE.md](analysis/RADIO_PACKAGE.md) and
   [analysis/radio-package.json](analysis/radio-package.json).
2. Added `analysis_scripts/inspect_radio_package.py` with a synthetic-prefix
   test. All eight Python tests pass in the project analysis environment.
   The existing main-firmware decompilation shows an initial 0x48-byte read
   and a 0x200000 size bound, but custom instructions still obscure the parser.

## 2026-11-15 — AndeStar profile, radio transfer and signed archive

1. Re-imported selected functions with Ghidra's AndeStar v5 profile. Previously
   missing branch and bitfield semantics now produce coherent control flow.
   Recorded comparisons in [analysis/INSTRUCTION_PROFILE.md](analysis/INSTRUCTION_PROFILE.md).
2. Followed the radio package caller and table reader: recovered the bitmap
   count, 12-byte record reads, address and length fields, per-image 512-byte
   prefix skips and block-transfer paths. Carved 15 candidate images locally.
3. Corrected a checksum routine's inferred function signature and matched all
   256 lookup-table entries to reflected polynomial 0xA001. Added a separate
   bitwise checksum model and known-value/streaming tests.
4. Verified the OTA archive's own trailing ECDSA signature against the embedded
   public key, including rejection after a changed archive byte. Documented
   the HMZPSIGN trailer and its recovery-code reference in
   [analysis/OTA_ARCHIVE_SIGNATURE.md](analysis/OTA_ARCHIVE_SIGNATURE.md).
5. Inventoried all top-level OTA members by extension and hashed each binary,
   JavaScript member and nested archive. Added reproducible scripts for bulk
   analysis and local function exports. The archive includes resources,
   bytecode-like app containers, GNSS/radio images and other unclassified data;
   the native exports do not cover all of these.
6. All eleven Python tests pass. The new radio range inventory and archive
   signature checks were regenerated from local original bytes.

## 2026-11-15 — extended native corpus and board-facing paths

1. Completed the AndeStar batch for bootloader, recovery, sensor hub, factory
   firmware, main firmware and ramdump. The main image's first 300-second pass
   timed out; a continuation on the saved project completed with a larger budget.
2. Mapped and analyzed the radio package separately as candidate ARM Thumb code.
   Across these seven targets, 54,804 inferred functions were recognized and
   54,794 emitted pseudocode; ten did not complete. Warnings, unknown calls and
   inferred types remain, so this is not full behavioral coverage. The detailed
   metrics are in [analysis/decompilation-summary.json](analysis/decompilation-summary.json).
3. Followed touch and serial initialization in the larger corpus, finding the
   touch probe's expected 0xE622 identity and a radio serial configuration with
   value 115200. The LSM6DSO expected identity resolves to 0x6C. Findings are in
   [analysis/TOUCH_AND_SERIAL.md](analysis/TOUCH_AND_SERIAL.md).
4. Saved all vendor-derived exports locally under firmware/decompiled/ and all
   Ghidra databases under firmware/. Only tools, reports and metadata are public.
   The investigation scope and remaining formats are tracked in
   [analysis/DECOMPILATION_STATUS.md](analysis/DECOMPILATION_STATUS.md).

## 2026-11-15 — GNSS, touch, app containers, display and radio candidates

1. Inspected the `fw_gps.bin` GNSS container without execution: recorded its
   `AG3352B_V3.1.0` version string, the `55 aa aa 55` marker and five
   little-endian section lengths that, plus the 0x100 header, account for the
   whole file. Mapped the first region as candidate ARM Thumb at `0x04200000`,
   following its startup zero/copy helpers under a bounded, first-region-only
   import. Compared the two 49,152-byte touch payloads: they differ at only
   eight bytes and both carry `22 e6 e6 22` at 0x40, consistent with the main
   firmware's expected `0xE622` touch identity. Findings and reproduction are in
   [analysis/GNSS_AND_TOUCH_BLOBS.md](analysis/GNSS_AND_TOUCH_BLOBS.md) with
   machine-readable output in
   [analysis/gnss-inspection.json](analysis/gnss-inspection.json).
2. Parsed the `Application.bin` GAPP container and the packaged JavaScript as a
   QuickJS-v1-like format without executing it: atom tables and a bounded
   initial-function parser succeed across all 30 members, which share identical
   metadata (flags `0x0600`, stack size 5, 91-byte initial bytecode) and split
   28/2 by bytecode hash. See
   [analysis/APP_FORMATS.md](analysis/APP_FORMATS.md) and
   [analysis/app-format-summary.json](analysis/app-format-summary.json).
3. Followed candidate display and ambient-light paths in the main image:
   a three-byte display read (`0xda`/`0xdb`/`0xdc`), a `display0` driver
   registration, a `dev_stk31e60` light probe rejecting a register `0x3e` value
   other than `0xe0`, and a bulk-vs-targeted comparison showing a mis-inferred
   non-returning logger truncates control flow in the broad export. Recorded in
   [analysis/DISPLAY_AND_LIGHT.md](analysis/DISPLAY_AND_LIGHT.md).
4. Mapped the 15 carved radio images as candidate ARM Thumb at their loader
   record addresses and recovered startup-like copy/zero functions at two
   plausible Thumb starts. See
   [analysis/RADIO_NATIVE.md](analysis/RADIO_NATIVE.md).
5. Added independent, tested inspectors (`app_formats.py`, `gnss_inspect.py`)
   and reproduction helpers for the Ghidra passes. The GNSS and app-format JSON
   regenerate byte-for-byte from the original archive, the decompilation summary
   reproduces from local exports, and all Python tests pass except the
   signature suite, which needs `cryptography` installed. No device was written
   or queried; all vendor-derived exports stay under ignored `firmware/`.

## 2026-11-15 — JS runtime native ABI and BLE application protocol

1. Analyzed the shipped ZeppOS runtime `META/js_apps/framework.js`
   (`device-runtime-core v4.2.0-release.1`, API level 4.2) statically, without
   executing it. Mapped the native module boundary the runtime calls into —
   `hmApp`, `hmUI`, `hmFS`, `hmSetting`, `hmSensor`, `hmBle`, `hmMedia` — with
   every observed method, plus the `device:os.*` permission namespaces and the
   typed `hmFS.SysPro*` property store.
2. Recovered the BLE contract relevant to an Android companion: a 37-method
   GATT master-role surface (`mst*`), connection and transfer channels, and the
   framed message protocol above `ble.send` — a 16-byte little-endian header
   (`flag`, `version`, `type`, `port1`, `port2`, `appId`, `extra`) with a
   3584-byte payload cap, plus the invoke/close predicates and the
   pending→transferring→transferred/canceled file-transfer state machine.
3. Added `analysis_scripts/js_runtime_api.py` (a deterministic, non-executing
   inspector) with synthetic-fixture tests, the report
   [analysis/JS_RUNTIME_API.md](analysis/JS_RUNTIME_API.md) and reproducible
   output [analysis/js-runtime-api.json](analysis/js-runtime-api.json). The JSON
   regenerates byte-for-byte from the archive and all 23 Python tests pass
   (`cryptography` installed for the signature suite). This is the shipped API
   and its wire framing, not the native implementations behind each method.

## 2026-11-15 — GATT identifiers and the notification contract

1. Scanned the main firmware member for 128-bit GATT UUID strings and
   classified all 27: 14 Zepp/Huami custom (base `…-0009af100700`, including the
   `0x1530/1531/1532` firmware-update group), the four Apple ANCS and four Apple
   AMS UUIDs, the classic Serial Port Profile, and four unclassified custom
   UUIDs. The same set also appears in the factory-test image.
2. Established the device-side notification contract: against iOS the watch is
   an ANCS/AMS consumer (with an ANCS context carrying app_id/title/sub_title/
   message/date and positive/negative action labels, a subscribe state machine,
   stored peer address and a quick-reply asset); against the Zepp Android app it
   uses the Huami custom channel that carries the JS runtime's framed messages.
3. Added `analysis_scripts/ble_identifiers.py` with synthetic-input tests, the
   report [analysis/BLE_IDENTIFIERS.md](analysis/BLE_IDENTIFIERS.md) and
   reproducible [analysis/ble-identifiers.json](analysis/ble-identifiers.json).
   JSON regenerates deterministically; all 27 Python tests pass. This is a
   literal string inventory, not proof that a service is advertised or active,
   and the custom UUIDs and native handlers remain unresolved.

## 2026-11-15 — SoC subsystem architecture from symbol families

1. Inventoried embedded C symbol strings in the main firmware to sketch the
   subsystem structure. Found an rpmsg-lite inter-processor RPC layer (`zrpc`
   links and channels with checksummed packets and send/wait-reply), confirming
   a multi-core SoC whose sensor-hub and radio images are separate processors.
2. Mapped an audio DSP IPC command set (play/record/HFP/volume) and a 104-symbol
   `bx_core` dual-mode Bluetooth host: GAP (LE + classic inquiry/sniff), a GATT
   server (`register_service`/`send_notification`) serving the Huami services,
   and a GATT client the JS `ble.mst*` calls map onto. Classic profiles HFP,
   A2DP, AVRCP and RFCOMM/SPP are present, so the watch does call audio and media
   control over classic Bluetooth alongside the BLE data channel.
3. Added `analysis_scripts/firmware_symbols.py` with synthetic-input tests, the
   report [analysis/SYSTEM_ARCHITECTURE.md](analysis/SYSTEM_ARCHITECTURE.md) and
   reproducible [analysis/firmware-symbols.json](analysis/firmware-symbols.json).
   JSON regenerates deterministically; all 30 Python tests pass. These are
   log/assert symbol strings, not a call graph or an architecture spec.

## 2026-11-15 — candidate hardware profile and health capability surface

1. Inventoried `dev_<part>` driver names in the main image and resolved six
   candidate peripheral chips: Zinitix ZTW622 touch, Chipone ICNA3311 AMOLED
   driver, Sensortek STK31e60 light, Airoha AG3335 GNSS, and candidate Awinic
   AW32012 and CellWise CW6305 power parts. Four are corroborated by independent
   findings (0xE622 touch, the display read, the light probe, the GNSS
   container). The SoC tokens `AX861` (application processor) and
   `mhs003` (sensor hub) appear, consistent with an in-house multi-core Andes
   RISC-V design.
2. Counted a fixed health-metric vocabulary: heart rate/PPG, SpO2, HRV, stress,
   sleep, steps/distance/calories, PAI, VO2max, workout, plus weaker AFib, body
   temperature and ECG signals. This is the data surface a standalone OS must
   produce and the companion syncs.
3. Added `analysis_scripts/hardware_profile.py` with synthetic-input tests, the
   report [analysis/HARDWARE_PROFILE.md](analysis/HARDWARE_PROFILE.md) and
   reproducible [analysis/hardware-profile.json](analysis/hardware-profile.json).
   JSON regenerates deterministically; all 34 Python tests pass. Chip roles are
   candidate attributions from driver names, not a confirmed bill of materials.

## 2026-11-15 — app-loading contract and lifecycle model

1. Read the ten readable `META/js_watchfaces/*/*.js` bundles (unlike the minified
   runtime) and recovered the host contract a standalone OS must provide to load
   a ZeppOS app: the native-injected globals `__$$hmAppManager$$__`,
   `__$$app$$__` and `__$$module$$__`, the `DeviceRuntimeCore` entry points the
   apps construct (`App`, `WatchFace`, `WidgetFactory`, `HmDomApi`, `HmLogger`),
   and the lifecycle hooks `onInit`/`onCreate`/`onReady`/`onShow`/`onHide`/
   `onDestory`/`onError`/`onPageNotFound`/`onUnhandledRejection`.
2. Did not publish a runtime export count: the minified `framework.js` reuses the
   exports identifier as an ordinary parameter, so a reliable static export list
   cannot be scanned out. Only entry points the apps actually use are reported.
3. Added `analysis_scripts/app_model.py` with synthetic-fragment tests, the
   report [analysis/APP_MODEL.md](analysis/APP_MODEL.md) and reproducible
   [analysis/app-model.json](analysis/app-model.json). JSON regenerates
   deterministically; all 37 Python tests pass.

## 2026-11-15 — embedded engine identified as QuickJS 2020-07-05

1. Extracted the builtin atom blob (208 atoms, `JS_ATOM_END` 209) from the main
   firmware and compared it, together with the compiled `opcode_info[]` table,
   against nine official QuickJS releases. Only 2020-07-05 (non-bignum, default
   `CONFIG_ATOMICS`/`SHORT_OPCODES`) matches both: identical atoms and the full
   260-entry descriptor table byte-for-byte at member offset `0xb7e008`.
2. Confirmed independently from the 30 packaged app binaries: the debug
   filename atom reference implies the same `JS_ATOM_END` of 209, and the
   top-level function name is builtin atom 80, `<eval>`.
3. This explains the earlier 2020-01-19 reader crash (its opcode numbering
   diverges from the 55th descriptor) and means app bytecode can be read with
   the published 2020-07-05 format. Added `analysis_scripts/quickjs_fingerprint.py`
   (pure Python, nothing compiled or executed) with synthetic tests, the report
   [analysis/QUICKJS_ENGINE.md](analysis/QUICKJS_ENGINE.md) and
   [analysis/quickjs-fingerprint.json](analysis/quickjs-fingerprint.json).

## Next work

- Map the signed image formats and the loaders for the sensor hub and radio;
  distinguish host-side mathematical signature checks from device behavior.
- Identify the PPG/heart-rate analog front end and the exact SoC silicon, buses
  and memory layout with corroborating evidence beyond driver-name strings.
- Research and validate a non-destructive boot/debug and recovery path, including
  a backup of device-specific data, before considering hardware writes.
- Define the Android/watch transport, authentication and notification/navigation
  contracts, and test them on host and emulator before connecting a watch.
