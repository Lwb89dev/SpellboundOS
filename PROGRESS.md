# SpellboundOS progress

This log records completed work, evidence, and limitations. Dates refer to the
local work session. See [GOAL.md](GOAL.md) for the intended outcome and
[analysis/ANALYSIS.md](analysis/ANALYSIS.md) for detailed earlier findings.

Latest recorded state: see the most recent dated entry below and its `Next work` section.

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

## 2026-11-15 — complete app bytecode disassembly and the app sandbox

1. Wrote an independent Python reader and disassembler for the QuickJS
   2020-07-05 bytecode format. It takes builtin atoms and opcode sizes/formats
   from the firmware's own tables, and uses upstream opcode names only after
   the header's table is found byte-for-byte in the firmware.
2. All 30 app members (6 apps) parse completely with no unread bytes: 886
   functions and 75,570 instructions, all passing structural validation
   (exact tiling, branch targets on boundaries, in-range indices). The
   2020-01-19 and 2021-03-27 descriptor tables fail on all 30 as a negative
   control.
3. Recovered the runtime's `ProxySandbox` from `framework.js`: the 16-key app
   scope object, global aliases, hidden native names, the `Symbol.unscopables`
   allow-list (with `Promise` deliberately excluded), the always-true `has`
   trap and a global lockdown routine. Classified all 72 free variables the
   bytecode reads against it, and listed the 16 `@zos/` module specifiers the
   apps load. Their resolver is in neither `framework.js` nor the main image.
4. Added `analysis_scripts/qjs_bytecode.py` and a sandbox extractor in
   `app_model.py`, with synthetic tests, the report
   [analysis/APP_BYTECODE.md](analysis/APP_BYTECODE.md), an updated
   [analysis/APP_MODEL.md](analysis/APP_MODEL.md), and
   [analysis/app-bytecode-summary.json](analysis/app-bytecode-summary.json).
   Full listings stay under ignored `firmware/`. All 49 Python tests pass.
   A later pass added the 14 watchface bytecode members: 44/44 parse with no
   unread bytes (1,072 functions, 87,074 instructions).
   Running the upstream C reader on the vendor bytecode was not permitted in
   this session, so there is no C-side cross-check.

## 2026-11-15 — `@zos/*` API table and native bindings

1. Traced the `__$$R$$__` loader in `framework.js`: it walks an API object built
   from one declarative configuration of 25 modules. Each method entry gives
   its native binding (`{func:["hmApp","newAlarm"], …}`) or a JavaScript
   function, a permission code gated through `hmApp.queryPermission`, and the
   API version.
2. Extracted the table with a conservative JS-literal reader (nothing
   evaluated): 109 methods, 71 bound directly to 70 native targets (`hmApp` 35,
   `hmSetting` 25, `hmFS` 5, `timer` 3, `hmBle` 1, `hmUI` 1), 38 JavaScript
   wrappers, and seven modules reflected at runtime from six native objects
   (`hmUI`, `hmBle`, `hmMedia`, `hmCrypto`, `hmVAD`, `hmSysApi`). Recovered the
   29 sensor classes and the 24-code permission model, including one
   `data:user.hd.*` code per health data type.
3. Added `analysis_scripts/zos_api_table.py` with synthetic tests, the report
   [analysis/ZOS_API.md](analysis/ZOS_API.md) and
   [analysis/zos-api-table.json](analysis/zos-api-table.json). All 54 Python
   tests pass. The method lists of the reflected objects come from native
   registration code in the main image, which is the next target.

## 2026-11-15 — native JS binding tables

1. Found the QuickJS `JSCFunctionListEntry` tables in the main image: 86 runs
   (2,126 entries) that split into 168 tables, with 704 function entries on
   508 distinct C functions, 131 accessors and 1,204 integer constants. 437 of
   those functions already have a local decompiled export.
2. Read the embedded 752-byte bootstrap that imports 12 native C modules and
   assigns each to a global (`timer`, `hmApp`, `hmSetting`, `hmUI`, `hmSensor`,
   `hmFS`, `hmBle`, `hmMedia`, `hmSysApi`, `hmVAD`, `hmUtil`, `hmCrypto`), and
   took exact table lengths from the existing Ghidra exports. One function
   receives exactly 12 tables, one per module.
3. Cross-checked against `framework.js`: every native method it names exists in
   these tables except `hmApp.addSysPageListener`/`removeSysPageListener`. The
   method lists of the runtime-reflected modules are now known (`hmUI` 32,
   `hmBle` 50, `hmVAD` 13, `hmSysApi` 11, `hmCrypto` 3, `hmMedia` 2).
4. Added `analysis_scripts/js_cfunction_tables.py` with synthetic tests, the
   report [analysis/NATIVE_BINDINGS.md](analysis/NATIVE_BINDINGS.md) and
   [analysis/js-cfunction-tables.json](analysis/js-cfunction-tables.json). All
   60 Python tests pass. The pairing of each global name with its create
   function was observed by hand in `jssdk_runtime_init`, which the bulk export
   truncates after a call wrongly marked non-returning; it still needs a
   committed reproduction.

## 2026-11-15 — reproducible native module registration

1. Continued the last native-binding investigation by replacing the manual
   name-to-constructor observation with an independent inspector of the original
   OTA bytes. Recovered one contiguous 12-call registration sequence in
   `jssdk_runtime_init`, matched exactly to the embedded module bootstrap.
2. Reconstructed the initializer callback, export-table address and exact entry
   count from each constructor's bounded argument-setup sequences. All 12
   tables (242 entries), their contents and constructor callers match the prior
   Ghidra-derived inventory. This works without the previous temporary Ghidra
   installation or any local decompiled exports.
3. Added `analysis_scripts/js_module_registration.py`, ten synthetic-fixture
   tests, [analysis/JS_MODULE_REGISTRATION.md](analysis/JS_MODULE_REGISTRATION.md)
   and reproducible
   [analysis/js-module-registration.json](analysis/js-module-registration.json).
   All 70 Python tests pass with the existing signature dependencies loaded
   from the local package cache. The new inspector is standard-library-only.
   The report regenerates byte-for-byte; LLVM disassembly was inspected as a
   separate check of the registration chain and helper call sites.
4. The inspector validates bounded instruction patterns and table data, not
   whole-function reachability or runtime behavior. Helper roles and the image
   mapping remain inferred. No watch access or firmware execution was needed.

## 2026-11-15 — sensor class ownership and capability boundaries

1. Followed the `hmSensor` module constructor and initializer into the sensor
   dispatcher and common class registrar. Joined 28 explicit registration
   calls and sensor-ID assignments in local C exports with original 40-byte
   binary descriptors. Recovered 159 class-specific property entries, their
   nested constants, constructors and candidate cleanup callbacks, plus the
   seven shared sensor prototype entries.
2. Compared these registrations with the public sensor ID namespace: 36
   symbols represent 35 IDs (one spelling alias), of which seven lack a
   registration in the inspected dispatcher. A registered `glucose` class
   exposes record-management methods; it does not establish glucose-sensing
   hardware. No runtime capability or physical sensor is inferred from these
   API registrations alone.
3. Added `analysis_scripts/sensor_classes.py`, eight synthetic tests,
   [analysis/SENSOR_CLASSES.md](analysis/SENSOR_CLASSES.md) and reproducible
   [analysis/sensor-classes.json](analysis/sensor-classes.json), including hashes
   of consumed local C source texts. All 78 Python tests pass with the existing
   signature dependencies available, and the JSON regenerates byte-for-byte.
4. The BLE initializer directly installs the known 50-entry export table.
   Targeted LLVM disassembly of the missing sensor availability export shows
   a registry lookup plus an optional callback at state offset `0x40`; six
   registration functions explicitly assign such callbacks. Availability is
   therefore not necessarily a hardware probe. False non-returning logger
   calls still truncate the sensor factory and glucose-record wrappers.
   No firmware was executed and no device was accessed.

## 2026-11-15 — availability policy, compiler ABI and health backends

1. Inspected all six availability callbacks with local exports and bounded
   LLVM disassembly. Recovered app/service and authority gates, app-type
   exclusions and optional capability-table checks. The glucose callback is
   literally an unconditional true return. These policies are not a physical
   sensor inventory. Details are in
   [analysis/HEALTH_BACKENDS.md](analysis/HEALTH_BACKENDS.md).
2. Traced heart-rate and SpO2 getters into cached values and service wrappers,
   including the SpO2 event callback's accepted value range and cache updates.
   Logger truncation still blocks complete record/algorithm recovery.
3. Identified four alternate-return-register save/restore stub pairs. A bounded
   independent instruction interpreter verifies stack balance, saved-register
   restoration and argument/result preservation. The scan finds 3,961
   candidate save sites, 3,956 restore sites, and 2,064 corpus exports mentioning
   the helpers. These are candidate references, not a count of proven bugs.
   Concrete wrappers have incorrectly inferred void returns or arguments.
4. Added `analysis_scripts/riscv_save_restore.py`, six synthetic tests,
   [analysis/COMPILER_ABI.md](analysis/COMPILER_ABI.md) and reproducible
   [analysis/riscv-save-restore.json](analysis/riscv-save-restore.json). The
   interpreter models only the observed register-save instructions, not
   application code or hardware. The broad Ghidra corpus has not been repaired.

## 2026-11-15 — optical driver and startup RAM reconstruction

1. Found `dev_max8617x` in the sensor-hub member and traced its probe: expected
   register `0xff` value `0x46`, SPI-device lookup, power resources and IRQ setup.
   This identifies a driver family, not an exact fitted silicon suffix.
2. Reconstructed the sensor startup's two copy regions and one zero region.
   Initial board configuration names `sens_spi0_dev0`, `PPG_1V8`, `PPG_VLED`,
   logical IRQ GPIO 39 and a reset field of `0xffff`. The motion bus separately
   names `sens_spi1_dev0`. Probe fields include 8,000,000 and `0x801`;
   electrical modes, timing units and physical pins remain unverified.
3. Recovered six 48-byte optical-operation records and their shared/differing
   callbacks. Followed three-byte read/write register framing and a hibernate
   path. Added `analysis_scripts/sensorhub_memory.py`, synthetic memory tests,
   [analysis/PPG_AND_SENSOR_MEMORY.md](analysis/PPG_AND_SENSOR_MEMORY.md) and
   [analysis/sensorhub-memory.json](analysis/sensorhub-memory.json).

## 2026-11-15 — main RAM code and startup-aware analysis ELFs

1. Reconstructed four main-image copy records and two zero regions. One copy
   has a non-word-sized declaration and is rounded by the actual startup loop;
   another record is empty. Added regression coverage for both cases.
2. Established that code at `0x80c00000` and `0x80d32e00` is copied from bytes
   already in the OTA. Many previously unmapped `SUB_ram_80d...` references are
   therefore recoverable without an external ROM dump. The capability table
   starts zeroed and is not a static declaration of enabled hardware.
3. Added `analysis_scripts/main_memory.py` and `export_startup_elf.py`, a
   [mapping report](analysis/MAIN_MEMORY.md), reproducible
   [analysis/main-memory.json](analysis/main-memory.json) and local main/sensor
   ELF containers with startup destinations mapped. LLVM accepts the ELFs and
   disassembles a previously unmapped allocator-wrapper path at its runtime
   address. They are analysis artifacts under ignored `firmware/`, not
   installable images or recovered MPU configurations.
4. All 92 Python tests pass with the existing signature dependencies available.
   New JSON reports reproduce from the original OTA and local C corpus.
   No watch access, firmware installation or application-code execution was
   performed. See [analysis/RE_STATUS.md](analysis/RE_STATUS.md) for the current
   scope and unresolved completion criteria.

## 2026-11-15 — Ghidra restored and targeted ABI repair verified

1. Reacquired official Ghidra 12.1.2, checked its published SHA-256 before
   extraction, and kept installation/preferences/cache under `/tmp`. Imported
   the startup-aware main ELF into a fresh private project.
2. Added `DecompileWithAbi.java`: byte-hash-guarded program-local p-code fixups
   for all four verified save/restore pairs, restore-tail flow overrides and a
   returning logger. Imported firmware bytes are not patched. Twelve explicit
   targets decompile successfully; the broad corpus remains unchanged.
3. Recovered lost SpO2 arguments/output pointers, HR service inputs and the
   HR today-array loop. The formerly truncated glucose add-record body now
   shows an app-supplied numeric value converted to a float, passed through a
   record-service write, followed by cleanup and a change-event path.
4. Added [analysis/NATIVE_REPAIR.md](analysis/NATIVE_REPAIR.md),
   `summarize_native_repair.py` and
   [analysis/native-repair-summary.json](analysis/native-repair-summary.json).
   Across ten comparable old exports, nine false non-returning warnings and
   five fictitious save-result assignments disappear in this targeted pass.
   These diagnostics do not prove full correctness: inferred return types,
   unseeded callees and injection/unreachable-block warnings still need review.

## 2026-11-15 — optical FIFO and sensor IPC payloads

1. Committed the previous native-runtime, memory and sensor findings as
   `60f2983`. Original firmware and vendor-derived exports remain ignored.
2. Followed the optical IRQ through event kind 1, sensor-hub ID 6, the worker
   queue's command 5, and local/remote ownership routing. The local callback
   reaches the MAX8617X FIFO reader; the remote path emits sensor opcode `0x10`.
3. Recovered FIFO status/count guards, whole-frame reads, `08 80` SPI prefix,
   big-endian tagged sample words, signed low-20-bit values and the 1000-word
   software ring. Preserved the driver's exact weak frame-start test rather
   than inventing additional validation. The read path does not check the SPI
   transfer result before decoding; the host model assumes valid response bytes.
4. Inventoried eight ordered register tables (563 writes). Public evidence
   contains addresses/counts/hashes; full values stay under ignored firmware/.
   Recovered matching serializer/parser layouts for process opcode `0x10` and
   control opcodes 4/6/7, distinct from local queue structures and outer zrpc.
5. Added `ppg_fifo.py`, `sensor_ipc.py`, 13 synthetic tests,
   [analysis/PPG_FIFO_AND_IPC.md](analysis/PPG_FIFO_AND_IPC.md),
   [analysis/ppg-fifo.json](analysis/ppg-fifo.json) and
   [analysis/sensor-ipc.json](analysis/sensor-ipc.json). A fresh startup-aware
   Ghidra sensor pass corroborates the selected paths. All 105 Python tests
   pass with signature dependencies, and both reports regenerate exactly.
   No device access or writes were performed.

## 2026-11-15 — boot/recovery metadata and corrected reset boundary

1. Added structural parsing of the signed metadata: bootloader/recovery/ZIP
   use 48-byte metadata, while main/factory/hub use 64 bytes. The first size
   field matches each object's metadata offset; the second field has
   variant-specific differences and is not universally an image length.
   The archive's second field differs from summed ZIP sizes by 647 bytes;
   its exact scope remains unresolved. Existing ECDSA checks remain separate.
2. Extended the analysis ELF exporter to boot and recovery, reconstructing
   their two copy regions and one zero region, including rounded word copies.
   A fresh boot pass corroborates raw-recovery metadata/header validation and
   its enabled signature branch; no runtime enforcement or unlock is claimed.
3. Raw instructions prove reset helper `0x80c007b0` cannot normally return.
   Added `SeedBootFlow.java` with a terminal-loop byte guard. Corrected exports
   separate the reset wrapper from image handoff `0x80c0084a`, removing an
   apparent boot route created by false fallthrough.
4. Traced keyboard detection, boot environment updates and recovery UI paths.
   These are not a proven non-destructive debug path. Added
   [analysis/BOOT_RECOVERY_AND_METADATA.md](analysis/BOOT_RECOVERY_AND_METADATA.md),
   `signed_metadata.py`, reproducible [analysis/signed-metadata.json](analysis/signed-metadata.json)
   and five synthetic tests. All 110 Python tests pass with signature
   dependencies; no device access, boot-state changes or installation occurred.

## 2026-11-15 — native GATT registrations and transport ownership

1. Committed FIFO/IPC and boot/recovery work as `1d45591`, then continued with
   a separate ABI/logger-corrected native Bluetooth export set. The base GATT
   builder attempts eight services and 31 characteristic specs along its
   all-success branch; the prior broad export lost the last two services at a
   falsely non-returning log call.
2. Added an independent bounded inspector of explicit builder assignments,
   resolving UUID registry pointers from the original bytes. It preserves raw
   properties, permission/length fields and conditional descriptors. Qualified
   strings `2a4d11`/`2a4d21` normalize to wire UUID `2a4d`; raw instructions and
   AndeStar p-code confirm the conversion, while preserving both identifiers.
3. Traced native channel bindings for custom `0016`/`0017`, and established
   that custom `0022` is used by an RFCOMM BT_PORT registration. Corrected the
   earlier string-inventory report's overbroad GATT/phone-contract claims.
   The lower channel packet layer, JS framing, sensor IPC and authentication
   must still be connected and verified rather than assumed interchangeable.
4. Added `gatt_service_builder.py`, `InspectInstructions.java`, five synthetic
   tests, [analysis/GATT_REGISTRATION.md](analysis/GATT_REGISTRATION.md) and
   reproducible [analysis/gatt-service-builder.json](analysis/gatt-service-builder.json).
   All 115 Python tests pass with signature dependencies. The corrected Ghidra
   pass completed six targets; no Bluetooth or device interaction was performed.

## 2026-11-15 — native channel framing and crypto delegate

1. Continued from commit `776b393` with corrected native exports of packet
   parsing, serialization, TX/RX management and the authentication initializer.
   Recovered types 1–4, 5/11-byte data headers, fragmentation, ACK flags,
   sequence wrap and path-specific UUID routing. Preserved the confirmed
   six-byte-write/two-byte-read type-2 asymmetry and module u16-to-u8 conversion.
2. Connected authentication initialization to the 28-byte channel crypto
   delegate and its six key/counter/cipher callbacks. Traced session-byte XOR
   of all 16 key bytes, payload/counter/CRC framing, independent block calls,
   padding length and unsigned forward counter window. Pairing, key derivation,
   padding contents and vendor cipher interoperability remain open.
3. Verified every entry of the native CRC-32 table against polynomial
   `0xedb88320`, inspected custom indexing p-code and raw tail jumps, and fixed
   the inferred void return with a guarded analysis-only signature script.
   The corrected CRC pseudocode retains its accumulator update and return.
4. Added independently authored offline codec, bounded plaintext fragmentation/
   reassembly and pre-encryption-envelope helpers, 14 synthetic tests,
   [analysis/NATIVE_CHANNEL.md](analysis/NATIVE_CHANNEL.md), and reproducible
   [analysis/native-channel.json](analysis/native-channel.json). All 129 Python
   tests pass with signature dependencies. No Bluetooth/device interaction or
   device-secret extraction was performed.

## 2026-11-15 — authentication module, request layouts and key material

1. Documented the authentication component carried as native channel module
   `0x82` (controller `0x7035cb58`, dispatcher `0x7035be3e`). Recovered its
   request opcodes 0–11 with their fixed layouts, the little-endian API-level
   word whose low byte is the effective level, and the opcode-4 authorize mode.
2. Read the five public curve-parameter words from RAM and compared each with
   the sect163r2 parameters taken from the installed OpenSSL's explicit curve
   encoding; all five match. Modelled the observed post-processing after scalar
   multiplication: session key = persistent key XOR shared-point bytes 8..24,
   RX/TX counters from bytes 0..8, `Y` unused; and the
   `SHA-256(address || point)` cloud-binding digest.
3. Modelled the 144-byte persistent key store (eight 18-byte records: validity,
   app ID, 16-byte key) with first-free selection and later-duplicate
   invalidation, plus the eight auth-provider callbacks at `0x70f60f70`.
4. Completed the earlier in-progress `auth_session` work by adding the missing
   report [analysis/AUTH_SESSION.md](analysis/AUTH_SESSION.md) and wiring it into
   the status indexes. Confirmed `analysis/auth-session.json` regenerates from
   the archive and the reviewed exports, and that its ten tests pass. The full
   suite now passes 139 Python tests. No pairing, device-secret extraction or
   crypto execution was performed.

## 2026-11-15 — GAPP compiled UI tree decoded

1. Decoded the node tree inside Application.bin's LAYR, SCEN and ANIM sections,
   extending the earlier top-level RIFF/GAPP walk. Each node is a 4-byte tag, a
   u32 size and a body; a flat scan with size-containment validation recovers
   25,342 nodes nesting to depth 5, and the LAYR/SCEN forests pass an integrity
   check (siblings disjoint, children within parent).
2. Recovered the built-in UI model: 1,058 layers, 460 named screens (SCEN with
   INST instances), 34 animations with STEP keyframes, eight drawable primitive
   types (text/image/fill/circle/rectangle/canvas/gradient/poly), 102 event
   types (gre.press/touch/release/motion/gesture/keypress, scroll_change), and
   an ARGS property system with `${scope:path}` data bindings against app,
   layer, control and cell state.
3. Added `analysis_scripts/gapp_ui.py` with synthetic-GAPP tests (including a
   poisoned-string rejection), the report [analysis/GAPP_UI.md](analysis/GAPP_UI.md)
   and reproducible [analysis/gapp-ui.json](analysis/gapp-ui.json). JSON
   regenerates deterministically. The RATE/DAMR sections and exact header-field
   semantics remain open. Nothing was rendered.

## 2026-11-15 — GAPP container fully decoded, earlier counts corrected

1. Found and fixed two validation errors in the first GAPP tree decode: node
   bodies are padded to even length with a counted zero byte, so a last child
   ends one byte before its parent; and every LIST section ends with an 8-byte
   `LEND` marker that the last root abuts. The corrected parse recovers 37,261
   nodes (previously reported as 25,342), and all 14,295 `ARGS` candidates
   satisfy an exact key/value consumption check.
2. Decoded the remaining sections. APP header: format word, 390×450 and three
   counts that equal the decoded 461 screens, 1,049 layers and 35 animations
   exactly. RATE: five cubic-Bézier easing curves. DAMR: a 7,922-entry typed data
   model (key, value, change event) that consumes its section exactly and
   provides initial values for 275 of the 344 `${app:…}` paths. STEP: six-field
   keyframes whose easings all resolve. INST: all 1,437 instances name a layer.
3. Rewrote [analysis/GAPP_UI.md](analysis/GAPP_UI.md) with a correction note,
   regenerated [analysis/gapp-ui.json](analysis/gapp-ui.json) and extended the
   synthetic tests to eleven. The RIFF size at offset 4 remains unexplained;
   arithmetically it omits the ANIM and RATE chunks plus 2. Some header words
   remain uninterpreted. Nothing was rendered.

## 2026-11-15 — sports-peripheral client and the last custom BLE UUIDs

1. Classified the four custom 128-bit UUIDs left open in BLE_IDENTIFIERS.md by
   their use in the firmware. `7e78aa18`/`7e78aa19` are the Stryd sensor
   service and cadence-sensor measurement characteristic handled by the
   `bx_sport_peripheral` GATT client, alongside Running Speed and Cadence,
   Cycling Power, battery and Device Information. `cc353442`/`c551c36a` occupy
   the service and characteristic slots of the factory-test image's UUID table
   and are unreferenced strings in the main image (no data pointer, no
   `auipc`/`lui` address construction, no export reference).
2. Walked both images' UUID pointer tables (66 and 48 entries), reproduced the
   reviewed service and characteristic classifiers, and modelled the two
   20-byte Stryd measurement layouts (types `0x32`/`0x36`) read by handler
   `0x7039f5c2`; field meanings remain generic.
3. Added `analysis_scripts/sport_peripheral.py` with synthetic tests, the report
   [analysis/SPORT_PERIPHERAL.md](analysis/SPORT_PERIPHERAL.md),
   [analysis/sport-peripheral.json](analysis/sport-peripheral.json), and
   firmware-derived roles in `ble_identifiers.py` (regenerated
   [analysis/ble-identifiers.json](analysis/ble-identifiers.json); no UUID
   remains "custom"). No device was contacted.

## 2026-11-15 — package manifest mismatch explained

1. Verified the `filehash` manifest: 12,881 of 12,882 entries match, none is
   missing, and only `filehash`, `packageDiscription.json` and `update-script`
   are unlisted. Explained the one mismatch recorded since the first inventory:
   `META/res_info` is the build stamp (identical to `build_info`), the version,
   and the SHA-256 of `filehash` itself, which the package description also
   gives as `resourceHash`. The manifest lists the digest of the stamp alone, so
   `res_info` was completed after the manifest was written; the mismatch is by
   construction.
2. Verified `fw_info` sizes and CRC-32 for the firmware, bootloader and recovery
   images, and recorded the platform, bsdiff policy and update-script commands.
3. Corrected HARDWARE_PROFILE.md: the package declares platform `mhs003`, so
   `mhs003` names the platform rather than the sensor-hub processor as stated in
   the earlier entry above.
4. Added `analysis_scripts/package_manifest.py` with synthetic-package tests
   (including tamper detection), the report
   [analysis/PACKAGE_MANIFEST.md](analysis/PACKAGE_MANIFEST.md) and
   [analysis/package-manifest.json](analysis/package-manifest.json). Nothing
   was installed.

## 2026-11-15 — finish Claude's QuickJS cross-check

1. Resumed at commit `6c162f8` with Claude's uncommitted cross-check script and
   JSON. Reused the locally available official QuickJS 2020-07-05 source only
   after rechecking its release tarball SHA-256.
2. Added an independently authored, bounded C reader harness and rebuilt it.
   All 44 bytecode members parse; all nine compared header fields agree for
   1,072 functions. Both readers produce fingerprint
   `2ee208e798e155d899f37f75b6ad8ccc5a8b5513281b8b294db7b155c66da88d`.
   Python additionally verifies complete consumption; the upstream C API does
   not expose its cursor, so C acceptance alone is not an EOF check.
3. Hardened result validation for missing/extra members, malformed records and
   broken function indices, added four tests and
   [analysis/QJS_CROSSCHECK.md](analysis/QJS_CROSSCHECK.md). The report reproduces
   exactly. All 165 Python tests pass with signature dependencies; packaged
   bytecode was parsed and never evaluated.

## 2026-11-15 — first live phone/Gadgetbridge/Bip 6 session

1. Used the user's USB-connected SM-S921B (Android 17/SDK 37), with Gadgetbridge
   2026.11.1. The app initially showed the already-associated Bip 6 disconnected;
   reconnected it through the existing card and observed authentication and
   initialization complete. ADB is access to the phone, not watch shell/flash.
2. Collected 19 logged characteristic UUID/property specs, all matching the
   static builder, MTU 247 and an announcement of 62 Zepp OS application
   services. These layers/counts are separate; the 12 unlogged static specs
   must not be called absent from the actual watch.
3. Temporarily enabled app file logging, captured one normal reconnect, then
   restored logging off and deleted the generated phone log/UI file after
   copying. The association remains connected. Raw captures, including a
   session key printed by Gadgetbridge, stay under ignored firmware/ with
   directory/file modes 0700/0600; only allowlisted metadata is committed.
4. Verified 114 native packets and 103 complete transfers, including 69
   encrypted transfers with AES-128 ECB, all-byte session-key XOR, exact sizes
   and CRC-32. All 67 subsequent encrypted counters are exact successors.
   Confirmed module `0x82`, API 2/mode 2, the session-key challenge proof and
   successful authorization reply. First counters, ECDH generation, persistent
   key provisioning and fresh pairing remain outside this check.
5. Clarified client/server receive directions with two new corrected native
   exports. Added `gadgetbridge_session.py`, `verify_gadgetbridge_channel.py`,
   eight synthetic tests, [analysis/LIVE_GADGETBRIDGE.md](analysis/LIVE_GADGETBRIDGE.md),
   [analysis/gadgetbridge-session.json](analysis/gadgetbridge-session.json) and
   [analysis/gadgetbridge-channel-verification.json](analysis/gadgetbridge-channel-verification.json).
   All 173 Python tests pass; both live reports regenerate exactly. Normal
   Gadgetbridge initialization sent protocol/configuration writes; no firmware,
   recovery, boot or flash-backup operation was attempted.

## 2026-11-15 — all 62 announced modules and selected application payloads

1. Reassembled the module-0 announcement from the private native capture,
   matched it to the decoded log and 62 Gadgetbridge classifications, and
   recovered its exact opcode-4/count/u16-ID/encryption-byte layout. The native
   opcode-3 dispatcher independently corroborates the serializer.
2. Re-exported 46 original registrar callers with ABI/logger corrections. Raw
   call candidates found 14 additional caller paths absent from the old C
   reference search. A separate dynamic registrar supplies world clocks.
   The resulting 61 initializer exports contain 63 candidate descriptors;
   all 62 announced modules match, with no encryption-policy mismatch. One
   assistant branch describes unannounced module `0x10`.
3. Guarded original LI+SH bytes resolve three misleading CSR-symbol/pointer
   expressions as u16 scalar prefixes. The inspector preserves unknown bytes
   and separately labels three source-hash-guarded, reviewed assistant branches.
4. Followed notification (`0x1e`), phone (`0x0b`) and maps (`0x46`) dispatchers.
   Added host-only models for notification opcode 3, phone pairing/settings
   and map-download task opcode 5. Phone pairing and map download must not be
   mistaken for demonstrated call controls or turn-by-turn navigation.
5. Added `application_services.py`, `application_payloads.py`, 16 synthetic
   tests, [analysis/APPLICATION_SERVICES.md](analysis/APPLICATION_SERVICES.md)
   and reproducible module/payload JSON reports. All 189 Python tests pass with
   signature dependencies. Reused the existing private capture; no phone/watch
   interaction, pairing, notification delivery or download was performed.

## 2026-11-15 — notification reverse messages and controlled live test

1. Followed the corrected notification dump helper and identified app ID,
   title, message, app name, category-3 phone number, reply availability and
   flag offsets. Reconstructed the eight-slot Android notification API table,
   separately from the adjacent iOS interface, and followed text-reply, image
   request and control-action serializers. Call UI hangup/ignore use actions
   1/2; only action 3 includes the notification ID. No call or SMS was executed.
2. Used Gadgetbridge's notification diagnostic once with a synthetic title/body.
   The five native transfers include three encrypted notification-service
   messages. The 158-byte opcode-3 payload exactly matches the expected app ID,
   title, body and app name, with no trailing bytes. The watch requests its app
   logo at format 5/128×128; the client completes the icon transfer and replies
   with status 1. Notification rendering and watch interactions were not observed.
3. Reused the continuing connection's session key in memory from the earlier
   private capture. The empty new file log was not treated as evidence; the
   controlled Logcat window supplies the packets. Restored logging off and the
   original diagnostic title, removed temporary phone files and verified the
   watch remains connected. Raw captures stay ignored, with modes 0700/0600.
4. Read two clean Roadstr source files at commit `1a354ae`: instruction maps to
   Android title and distance to body, channel `roadstr_navigation`, ID 42 and
   a 3000 ms distance-update throttle. This is a candidate input surface, not
   an implemented Roadstr/watch integration or proof of an active installed build.
5. Added `notification_protocol.py`, a verified-transfer observer, eight tests,
   [analysis/NOTIFICATION_ACTIONS_AND_ROADSTR.md](analysis/NOTIFICATION_ACTIONS_AND_ROADSTR.md)
   and reproducible [analysis/notification-protocol.json](analysis/notification-protocol.json).
   All 197 Python tests pass with signature/cipher dependencies. The earlier
   native capture report remains byte-identical; public results exclude keys,
   counter values, notification IDs and message contents.

## 2026-11-15 — native notification queue, store and screen request

1. Regenerated selected paths with startup-aware mappings, save/restore fixups
   and returning logger. Initializer `0x7020df76` registers the concrete Android
   message and call listeners. Followed the legacy message consumer's owned
   36-byte asynchronous payload to the add/modify/remove worker and UID lookup.
2. Mapped the 112-byte ordinary records, 400-slot capacity, first-twenty
   per-app eviction rule, clock-rollback clearing and conditional expiration.
   Checked comparison arguments, priority/tie ordering and insertion in raw
   instructions. The internal 400 slots differ from the wire-advertised 100.
   Storage discriminator `+0x12` is distinct from normalized category/type
   `+0x24`; its value-2 branch still has unresolved tail-call/stack analysis.
3. Followed the three-slot subscriber registry and its adapter, then the
   standard alert gates, `NotifyResMgr`, event queue and final request for
   `NotificationNotifyScreen`. Documented concrete exclusions and override
   points without claiming a resource grant, observed rendering or a complete
   rich/sticky notification implementation.
4. Added `notification_pipeline.py`, seven synthetic tests, reproducible
   [analysis/notification-pipeline.json](analysis/notification-pipeline.json)
   and [analysis/NOTIFICATION_PIPELINE.md](analysis/NOTIFICATION_PIPELINE.md).
   All 204 Python tests pass with signature/cipher dependencies. Public output
   contains metadata and evidence hashes only. This pass was entirely offline;
   no phone/watch interaction or firmware write was performed.

## 2026-11-16 — sensor zrpc packet framing and CRC

1. Connected sensor send wrapper `0x80f94c0a` to zrpc sender `0x80f9de06`
   and compared its header construction with main sender `0x704ea184`.
   Local node IDs are 2 and 1 respectively; recovered the separate 16-byte
   data header, 8-byte ACK and 8-byte link envelope. Destination/link selection
   and active device routing remain unverified.
2. Matched all 256 generated reflected-`0xa001` CRC table entries on both
   processors and checked the main CRC loop/header stores in LLVM instructions.
   Recorded fragment descriptor fields, 14-bit chunk sequences, session ACK
   lookup and rpmsg allocation/send/release wrapper targets.
3. Added a bounded independent packet codec, eight synthetic tests and
   [analysis/ZRPC_PACKETS.md](analysis/ZRPC_PACKETS.md) with reproducible
   [analysis/zrpc-packets.json](analysis/zrpc-packets.json). All 212 Python
   tests pass with signature/cipher dependencies. The codec does not emulate
   native fragmentation/retries or run a shared-memory/rpmsg transport.
4. Preserved unresolved AndeStar bit branches explicitly: broad pseudocode
   contains impossible mask comparisons and LLVM leaves those instructions
   undecoded. The temporary Ghidra installation was absent; no corrected fresh
   export is claimed. This pass was offline and performed no device access.

## 2026-11-16 — AndeStar bit-branch defect and rpmsg pools

1. Compared the pinned Ghidra 12.1.2 definition with Renode's independent
   implementation. Ghidra's `bbs` predicate compares the masked result with 1,
   losing taken branches at bit indices above zero. Added a bounded independent
   decoder for RV32 bit/constant branches, with explicit instruction addresses.
   No patched Ghidra export or full corpus audit is claimed.
2. Recovered selected CRC, ACK and fragment branches. Packed-state bit 1 means
   more fragments. Raw sender instructions leave a potential exact-multiple
   termination defect; caller constraints and device behavior remain unknown.
3. Matched three rpmsg pool records on main and sensor hub, calculated their
   sizes and non-overlapping extents below sensor initialized RAM. Physical
   memory/cache behavior, active endpoints and vrings remain open.
4. Added `zrpc_control_flow.py`, five tests, reproducible
   [analysis/zrpc-control-flow.json](analysis/zrpc-control-flow.json) and
   [analysis/ZRPC_BRANCHES_AND_MEMORY.md](analysis/ZRPC_BRANCHES_AND_MEMORY.md).
   All 217 Python tests pass with signature/cipher dependencies. External source
   snapshots remain ignored; no device access or firmware writes occurred.

## 2026-11-16 — consecutive corrected-native, rpmsg and fragment blocks

1. Reacquired official Ghidra 12.1.2 with its published archive hash. Added
   `repair_ghidra_bbs.py`, applied its guarded/idempotent predicate correction
   in the temporary installation and rebuilt Sleigh. A fresh startup-aware
   main project produced 36 targets with ABI/logger fixes in three passes.
   New exports confirm the CRC/more-fragments branches; original groups remain
   intact and a full corpus/sensor regeneration is not claimed.
2. Recovered six queue layouts across the three pools, inverse master/remote
   TX/RX roles, conditional endpoint 0/1 selection, lower 16-byte header and
   descriptor-token ownership. Callback return 1 retains a receive buffer;
   other returns release it. Channel bit 2 selects priority queue 2. Reviewed
   ordering hooks do not establish complete data-cache/coherency behavior.
3. Added `rpmsg_layout.py` and `zrpc_fragments.py`: bounded packet/layout and
   stock chunk-production models, plus a stricter host reassembler. Synthetic
   nonmultiple chunks complete; the stock exact-multiple case stays pending.
   Corrected native ACK RX signals a matching session without inspecting its
   status byte in that branch; receipt alone does not prove app processing.
4. Added eight tests and reproducible
   [analysis/rpmsg-layout.json](analysis/rpmsg-layout.json), documented in
   [analysis/RPMSG_NATIVE_AND_FRAGMENTS.md](analysis/RPMSG_NATIVE_AND_FRAGMENTS.md).
   All 225 Python tests pass with signature/cipher dependencies. The BBS repair
   was also checked for exact-source acceptance, idempotence and rejection of
   altered input. Device-derived code/tool evidence remains ignored. No device
   access, firmware writing or phone configuration change occurred.

## 2026-11-16 — interrupt, volatile MMIO and synchronization blocks

1. Followed queue ID plus one through notify, IRQ 16, token-minus-one lookup
   and callback dispatch. Recovered role-dependent send/receive register pairs,
   echo acknowledgement and the role-0 exception sentinel. Fresh sensor
   exports corroborate the main register/token/wake paths and role-predicate
   instruction bytes. No live interrupt or register was accessed.
2. Found missing/transformed I/O effects caused by nonvolatile MMIO metadata.
   Added guarded `MarkIpcMmio.java`, restored transient wake configuration and
   exception acknowledgement, and preserved old baseline exports. Main passes
   emitted 24 baseline and 26 volatile targets; a fresh sensor pass emitted ten
   targets with the new logger-only exporter. Retained the verified corrected
   Ghidra installation/archive under ignored `firmware/tools/` for later work.
3. Modeled bounded token routes, external IRQ-bank arithmetic, nested IRQ
   reference counts, queue notification suppression and timer rollover. Raw
   bytes confirm three `fence.i` hooks; full data-cache/coherency and physical
   timer units remain unresolved. Timeout can occur after a register write,
   so it does not prove that no notification was published.
4. Added nine tests and reproducible
   [analysis/ipc-doorbell.json](analysis/ipc-doorbell.json), fingerprinting 38
   selected exports, plus [analysis/IPC_DOORBELL_AND_MMIO.md](analysis/IPC_DOORBELL_AND_MMIO.md).
   All 234 Python tests pass with signature/cipher dependencies. Device code,
   databases and tool files remain ignored; no firmware/phone changes occurred.

## 2026-11-16 — wide clock, cache primitives and transfer-contract blocks

1. Added guarded `SeedClockCache.java` to mark CSR/clock registers volatile,
   restore selected 64-bit return/argument pairs and use the compiler's default
   convention. Recovered stable high/low/high counter readers and nominal CPU
   frequency/divider formulas. The timer's wide arithmetic helper still has
   unsupported encodings, so physical timeout units are not claimed closed.
2. Recovered cache commands 0/1/2/6 with independent labels from the pinned
   Zephyr v4.2.0 Andes driver. Confirmed the signed range-address guard skips
   all three shared-memory pool bases, preserved separate startup enable writes,
   and followed selected transfer setup/completion callers. Software skipping
   does not establish physical cacheability, aliases or coherency.
3. Added `clock_cache.py`, nine host tests and reproducible
   [analysis/clock-cache.json](analysis/clock-cache.json), fingerprinting 20
   selected exports. Detailed findings and limits are in
   [analysis/CLOCK_AND_CACHE_CONTRACTS.md](analysis/CLOCK_AND_CACHE_CONTRACTS.md).
   All 243 Python tests pass with signature/cipher dependencies. Vendor-derived
   exports and the reference source remain ignored; no device access or
   firmware, clock, cache or phone configuration change occurred.

## 2026-11-16 — DSP semantics, native arithmetic execution and timeout scale

1. Identified all five previously undecoded sites in the wide timer helper:
   four Andes opcode-0x7f `pkbb16` instructions and one `maddr32`. Added a
   guarded, idempotent local RV32 SLEIGH extension preserving the earlier BBS
   fix, recompiled it and regenerated the helper/reader/selected IPC caller
   into a separate ignored export directory. Opcode references and exact
   tool/source/image hashes are recorded; broader DSP support remains open.
2. Executed the actual helper as corrected SLEIGH p-code against Java's unsigned
   division oracle: 52,294 nonzero-divisor cases and 200 complete synthetic
   reader calls pass, totaling 2,213,837 instruction steps, at most 80 per call.
   Every DSP site executes. Unvisited instructions/conditional edges are
   reported; this is bounded host validation, not exhaustive or silicon proof.
3. Established `floor(raw_unsigned_64/1000)` for the selected reader. The IPC
   limit of 1000 uses separately converted snapshots, so the first numeric
   threshold occurs after 999,001–1,000,000 raw ticks without raw rollover.
   Added phase-aware models and nine tests, including all 1000 initial phases,
   source-repair guards and wrap boundaries. Physical timer frequency, live
   poll duration and shared-memory coherency remain open. No device changes.
4. Added [analysis/TIMER_ARITHMETIC.md](analysis/TIMER_ARITHMETIC.md) and
   reproducible [analysis/timer-arithmetic.json](analysis/timer-arithmetic.json).
   All 252 Python tests pass with signature/cipher dependencies; the public
   report reproduces byte-for-byte. Firmware, vendor-derived exports, tool
   sources and Ghidra databases remain ignored.

## 2026-11-16 — periodic timer, suspension and optical SPI blocks

1. Followed main and sensor periodic setup/interrupt paths. Recovered distinct
   raw intervals (1000 versus 33), compare-store ordering, saved next-deadline
   advancement, initial callback-table entry 7 and unconditional re-enabling
   of `mie` bit 7. Guarded metadata seeding preserves CSR effects and explicit
   debug/IRQ/scheduler boundaries. Native host execution passes 13 setup and
   26 interrupt-prefix cases per processor, before scheduler/registration calls.
   Also followed native trap dispatch: 16-byte callback records, pointer at +0
   and argument at +4; three native dispatch cases pass per processor.
2. Recovered identical main/sensor low/high/low/high readers at a second
   counter bank (`0x910012f8`/`0x910012fc`), restored its volatile window and
   wide signatures, and passed three native retry/read-order/result cases per
   processor. Followed 32768/1000 suspension conversions and preserved their
   integer-width behavior. Selected resume paths write the raw timer itself;
   continuity across power states and physical oscillator frequency remain
   unverified. Report: [analysis/RTOS_TIMER_AND_SUSPEND.md](analysis/RTOS_TIMER_AND_SUSPEND.md),
   with reproducible [analysis/rtos-timer.json](analysis/rtos-timer.json).
3. Followed optical `sens_spi0_dev0` through controller/chip-select records,
   bus operation adapters and polling HAL. Recovered forced width field 8,
   `flags & 6` collapse to control bits 0/3, source/divider/gating formulas,
   four-/five-argument forwarding and layered error conversion. Strict SPI
   timeout checking occurs after data movement; it can follow the final byte.
   Distinguished the probe's cycle busy wait from the RTOS retry delay.
   Eleven native configuration cases and 12 forwarding/return cases pass;
   HAL return values are supplied synthetically, with no live bus execution.
   Report: [analysis/OPTICAL_SPI_AND_TIMING.md](analysis/OPTICAL_SPI_AND_TIMING.md),
   with reproducible [analysis/optical-spi.json](analysis/optical-spi.json).
4. Added 20 meaningful host tests: all 272 Python tests pass with cipher/
   signature dependencies. Across these blocks, 113 new native cases pass.
   Public reports fingerprint 39 corrected exports and private validation
   reports; vendor-derived code, images, databases and tools remain ignored.
   No watch/phone configuration or firmware change occurred.

## 2026-11-16 — SPI ownership, references and integrated register transactions

1. Followed public transmit/full-duplex calls through bus take/release and
   device operations. Confirmed discarded mutex/release outcomes, immediate
   release after selected failures, and deferred release in the generic DMA
   success branch. The complete initial optical bus table has four null
   trailing slots, including every recovered DMA operation/registration slot;
   the reviewed optical binding supplies polling, not a DMA implementation.
   Native completion cases confirm current-flag lookup, release-before-user
   callback, and repeated callback effects without a latch in that body.
2. Followed actual chip-select adapters to separate full-word GPIO stores at
   bank offsets `+0x14`/`+0x10`, mask `0x200`. Recovered the 16-bit resource
   reference field and callback conditions, including increment wrap and
   repeated disable-at-zero behavior. Forty-eight native invocations pass
   across transfer, completion, chip-select and reference paths; mutex,
   operation, critical-section and resource/user outcomes are synthetic.
3. Executed the actual register wrappers, bus/CS adapters and polling HAL
   together with synthetic peripheral status/data and timestamps. Thirteen
   native cases verify exact TX bytes, RX/timestamp counts, result/output,
   event order and ABI preservation. A final-byte timeout leaves the caller's
   output unchanged even after all RX bytes are read. An absent operation or
   unconfigured DMA slot can return zero without a transfer and copy the local
   dummy byte. The tests neither measure a chip ID nor execute a physical bus.
4. Added 15 host tests: all 287 Python tests pass with signature/cipher
   dependencies. Across these blocks, 61 new native invocations pass.
   [analysis/SPI_OWNERSHIP_AND_COMPLETION.md](analysis/SPI_OWNERSHIP_AND_COMPLETION.md)
   and [analysis/SPI_REGISTER_NATIVE_EXECUTION.md](analysis/SPI_REGISTER_NATIVE_EXECUTION.md)
   describe the contracts and limits. Reproducible
   [analysis/spi-ownership.json](analysis/spi-ownership.json) fingerprints 17
   selected exports, complete initial tables, instruction ranges and private
   validation reports. Vendor-derived code/images/tools/databases remain
   ignored; no phone/watch configuration or firmware change occurred.

## 2026-11-16 — native FIFO faults, recovery notification and sample primitives

1. Restored the FIFO reader's kernel-tick return path and the identity helper
   at `0x80f80aa0`. The entry-to-entry guard uses unsigned 32-bit kernel ticks,
   not the SPI HAL's scaled memory counter. Recovered status-error fallback,
   pre-rounding capacity checks, frame-total/auxiliary updates and cache wrap.
   Supplied burst failures can still cache retained bytes or mixed partial
   words, because native decoding discards the transfer's result.
2. Executed actual recovery, metadata reset and register-recovery instructions.
   Confirmed the active-byte gate, fields/buffers not reset, prefix data retained
   on frame errors, and reuse of the prior register byte after a supplied
   recovery read failure. With one synthetic listener registered, the native
   kind-2/sensor-6 event reaches control request `(6,0x81,0,0)`; execution stops
   before allocation, worker queues, ownership routing and IPC.
3. Executed selected cache-pop and signed-sample primitives, including empty
   results, read-index wrap, auxiliary flag handling, signed 20-bit boundaries
   and tag diagnostics that still return a sample. The complete consumer,
   calibration and final health-measurement pipeline remain open.
4. Forty-five native cases pass against an independently authored state/buffer
   model: 28 FIFO, six recovery, one reset, four pop and six sample cases.
   They check complete staging/ring hashes, metadata, call actions, relevant
   returns/flags and ABI preservation. The run has 19,258 bounded steps,
   including intercepted calls. SPI/context/tick inputs are synthetic; no
   physical fault incidence, timing, chip identity or recovery success is claimed.
5. Added 18 host tests: all 305 Python tests pass with cipher/signature
   dependencies. [analysis/PPG_FIFO_LIFECYCLE.md](analysis/PPG_FIFO_LIFECYCLE.md)
   and reproducible [analysis/ppg-fifo-lifecycle.json](analysis/ppg-fifo-lifecycle.json)
   record 16 export fingerprints, exact native ranges, synthetic vectors and
   checked execution results. Vendor images/code/tools/databases remain ignored.
   No phone/watch configuration or firmware change occurred.

## 2026-11-16 — coordinated sensor flush and native optical sample packets

1. Followed command `0x81` into the native sensor backend. Fusion flags select
   coordinated callbacks in order 1, then 6 when group A is active, then 3
   when group B is active. The real optical callback tail-calls recovery
   with notification disabled; the selected path emits no recursive event.
   Full canary-backed fusion memory checks preserve the actual 16-bit versus
   32-bit reset widths, wide timestamp writes and missing-handle/callback
   behavior. The worker/transport gap from the previous request remains open.
2. Executed native sample-packet allocation and pointer reconstruction after
   copying to a new synthetic address. Recovered the 24-byte header,
   40-byte descriptors, payload placement, initial reference value and
   shared timestamp. Checked allocation failure, size wrapping and the
   distinction between full-width allocation arguments and truncated header
   fields. This native object is not a portable wire packet; reference/free
   and asynchronous ownership are not yet covered.
3. Executed mode-1 consumer with prefilled ring, frame width 2 and supplied
   lock/allocator/clock outcomes: optional second stream, signed samples,
   RV32 offset arithmetic, per-rate frame limit, descriptor metadata and
   timestamp borrow. Both words are popped per frame even with one output
   stream; rate-10/20-frame input consumes 12 frames and leaves 16 words.
   Empty/disabled/lock/allocation failures and ring wrap are covered.
4. All 557 native cases pass (517 flush, 23 packet, 17 consumer), totaling
   132,769 bounded steps including synthetic call interception; every case
   checks stack/callee-saved registers and final state/buffer hashes. Added
   21 host tests; all 326 Python tests pass. Reproduction, eleven fresh export
   fingerprints and the complete checked case results are recorded in
   [analysis/SENSOR_FLUSH_AND_PACKETS.md](analysis/SENSOR_FLUSH_AND_PACKETS.md)
   and [analysis/sensor-packets.json](analysis/sensor-packets.json).
   Vendor code/images/tools remain ignored. No device configuration or
   firmware change occurred; other modes, calibration, delivery and physical
   validation remain open.

## 2026-11-16 — packet lifetime, listener/cache delivery and optical modes 2/3

1. Executed null-safe packet retain/release, wrapping reference arithmetic and
   the last-release pointer clear through the pool-4 free-call boundary.
   Executed the selected critical wrappers, current-task nesting and MIE CSR
   operations with supplied context/scheduler state. These helpers balance
   depth rather than restore a saved MIE bit; no concurrent/hardware exclusion
   or complete allocator behavior is claimed.
2. Executed delivery with supplied read/fusion/cache results: original versus
   fusion-result selection, empty-result suppression, normal/private listener
   matching and cleanup of both packets. Dispatch does not implicitly retain
   for callbacks; synthetic retaining listeners call the actual native helper
   and release those references after owner cleanup.
3. Executed cache's all-selected/none-selected paths and native one-node queue
   put/get. The queued eight-byte record owns a packet reference. Successful
   get transfers it to the receiver; a short buffer invokes cleanup inside the
   queue instead. Enqueue failures balance the added reference. Checked cache
   pressure thresholds; actual pressure flush, filtering and IPC are not run.
4. Executed 29 mode-2/3 consumer cases with three words per frame, optional
   third output stream, distinct channel/global adjustments, marked-pop flags,
   sample thresholds and all-out-of-range counter/reset requests. Values are
   native sample integers, not validated health measurements. Postprocess reset
   and OS/peripheral services remain supplied boundaries.
5. All 178 new native cases pass (97 references, 40 listener delivery, 12 cache,
   29 consumer), totaling 42,835 bounded steps including intercepted calls.
   All 557 prior packet/flush/consumer cases replay identically after extending
   the shared harness. Added 28 tests; all 354 Python tests pass. Nineteen fresh
   exports, full checked results and reproduction are recorded in
   [analysis/SENSOR_DELIVERY_AND_MODES.md](analysis/SENSOR_DELIVERY_AND_MODES.md),
   [analysis/sensor-delivery.json](analysis/sensor-delivery.json) and
   [analysis/ppg-three-word.json](analysis/ppg-three-word.json). Vendor material
   remains ignored. No phone/watch settings or firmware were changed.

## 2026-11-16 — cache filtering, packed-buffer flush and opcode-21 send

1. Executed partial 64-bit type filtering through clone allocation, metadata/
   payload copy, native queue put and flush. Selected descriptor copies stop
   before their pointer slots; new pointers remain independent and the last
   word stays zero. Allocation/enqueue failure cases check source/clone cleanup.
2. Executed cache buffer allocation, shallow validity, pointer reconstruction
   and reference/free boundaries. Return 1 from reconstruction does not mean
   every record was valid or rebased: supplied zero/overrun record prefixes
   stop traversal with the outer validity result preserved. Added a stricter
   host parser that treats sender pointers as opaque.
3. Executed native multi-packet queue flush, length-prefix encoding, packet
   release, embedded-pointer rebasing and buffer dispatch. Exact 4000-byte
   capacity and multi-buffer cases pass. A synthetic oversized head remains
   queued while two empty buffers are dispatched without a free call; supplied
   failure on the next allocation terminates the bounded case. No live hang
   or reachability through the full producer is established.
4. Followed actual cache listener/event handler into native opcode `0x15`
   serialization and the send callback: one byte opcode, four-byte packed
   length and complete packed records. Buffer retention across supplied event
   scheduling and cleanup is checked, including send error. Actual event
   scheduler and transport remain boundaries; receiver/rpmsg operation is not
   executed. Copied native pointer fields remain sender-buffer addresses.
5. All 29 native cases pass (11 filter, eight buffer, ten flush), with 25,611
   bounded steps including intercepted calls and preserved stack/registers.
   Added 17 host tests; all 371 Python tests pass. Twenty-five fresh export
   hashes, complete checked results and reproduction are recorded in
   [analysis/CACHE_FILTER_FLUSH_AND_IPC.md](analysis/CACHE_FILTER_FLUSH_AND_IPC.md)
   and [analysis/cache-pipeline.json](analysis/cache-pipeline.json). Vendor
   material remains ignored; no phone/watch configuration or firmware changed.

## 2026-11-16 — main/sensor cache receiver and consumer ownership

1. Executed native decoder/parser counterparts on both cores: borrowed slices,
   little-endian u32, distinct initial/error states and sticky errors that do
   not suppress later fitting reads. Opcode 21 accepts trailing bytes but
   rejects zero/oversized declared payloads. One input hash exactly matches
   the preceding native sender's captured `flush_one` wire.
2. Executed both receive callbacks and opcode-21 handlers through copy into
   a new buffer, native pointer reconstruction, configured consumer bridge
   and listener dispatch. Missing-handler/allocation/error paths are checked.
   Main uses pool 5, sensor pool 4. Borrowed input stays unchanged; its transport
   release is not executed. Main default callback setup is recorded statically.
3. Checked parent-buffer lifetime through actual native reference arithmetic
   and synthetic capturing/retaining listeners. Before-owner/after-owner and
   deferred-release snapshots show retained buffers surviving handler return;
   last release clears magic before the free-service boundary. Critical/OS
   boundaries and registration remain supplied, not live concurrency evidence.
4. Executed bounded zero/overrun/partly valid record cases that still reach
   dispatch. A synthetic inner count of two in a one-descriptor-sized record
   makes both cores write a pointer 28 bytes into a 128-byte guard beyond the
   allocation. Valid cases preserve that guard. No live reachability, allocator
   corruption or device crash is claimed; application callbacks only capture
   opaque bytes and do not dereference malformed pointers.
5. All 66 native cases pass (33 per core: eight decoder, eleven parser,
   fourteen receive), totaling 16,439 bounded steps including intercepted
   calls. Added 21 host tests; all 392 Python tests pass. Thirty-six fresh
   exports, code/fixture/result hashes and reproduction are recorded in
   [analysis/CACHE_RECEIVER_AND_OWNERSHIP.md](analysis/CACHE_RECEIVER_AND_OWNERSHIP.md)
   and [analysis/cache-receiver.json](analysis/cache-receiver.json). Vendor
   material remains ignored. No phone/watch settings or firmware changed.

## 2026-11-16 — engine cache registration, retained events and HR result policy

1. Executed actual main cache callback registration/removal: duplicate and null
   callbacks, absent removal, allocation failure, reinsertion, dispatch order
   and circular-list invariants. Full node hashes check self-links before free.
2. Registered the actual engine cache listener and executed the existing native
   receiver through its default bridge into event creation/retention. Executed
   the real event handler and destructor under supplied scheduling, checking
   reference/magic/buffer/guard state and registration/event allocation failures.
   The initializer-to-registration worker association is static; allocation,
   OS/event post/scheduling and event-object disposal remain boundaries.
3. Executed native packed-record iteration and engine fanout, including exact
   state 2, nonzero enabled/cache flags, 64-bit masks, skipped slot 30 and the
   0..38 iteration bound. The cached branch does not match the packet private
   field. Engine records/masks/states are supplied; no live activation is proved.
4. Followed the actual engine-7 callback through descriptor handling, algorithm
   0x100d enable/record/mask dispatch and HR global updates. Only mathematical
   backend outputs are supplied. Checked ready/error interaction, acceptance
   bounds (quality > 3, pulse 30..220), manual/periodic status/logs, control
   marker and independent 16-bit count/sum wrap. Full 188-byte HR state hashes
   are checked. Non-type-1 descriptors, no auxiliary/wear/reset work; actual
   backend math, motion/minute paths and hardware measurements remain open.
5. All 40 native cases pass (seven registry, 33 receive/event/engine/HR),
   totaling 54,087 bounded steps including intercepted calls. Added 23 host
   tests; all 415 Python tests pass. Twenty-one fresh exports, checked results,
   hashes and reproduction are recorded in
   [analysis/ENGINE_CACHE_AND_HR_POLICY.md](analysis/ENGINE_CACHE_AND_HR_POLICY.md)
   and [analysis/engine-cache.json](analysis/engine-cache.json). Vendor material
   remains ignored; no device access or phone/watch/firmware changes performed.

## 2026-11-16 — actual HR algorithm registration, lifetime and configuration

1. Identified the actual 48-byte algorithm-0x100d record and executed its real
   registration wrapper. Its initial mask is 0x82012 (2/0x10/0x2000/0x80000),
   distinct from the prior broad synthetic mask. Checked raw/operations
   registration, original-pointer identity, duplicates, ID limits, missing
   process callback, default lifecycle callbacks and full table/record hashes.
2. Executed native enable/disable reference ownership: two users share init,
   failed init retains the incremented reference and retries, HR init errors
   normalize to Boolean while generic callback errors retain their value,
   and last disable calls exit regardless of its return. Explicit synthetic
   states check zero refs and 16-bit wrap; no live balancing/concurrency claim.
3. Executed dispatch through the actual HR adapter with the actual record/mask,
   including high-word mask mutation, disabled/mismatched/null cases and
   error-with-ready behavior. Executed the real uninitialized-processing guard;
   mathematical initialization, normal processing and teardown remain supplied.
4. Executed real HR configuration copying, including the 56-byte clear,
   separate source-byte-6 destination, three ten-byte arrays, optional extension
   arguments and exact return-1 branch. Control runs while disabled; the actual
   adapter discards the copier's return. Full 160-byte state hashes and source
   immutability are checked, including repeated control and extension 0/1/7.
5. All 48 native cases pass (14 registration/lookup, eight lifetime, 16 dispatch/
   mask, ten control), totaling 7,672 bounded steps including intercepted calls.
   Stack, saved integer registers and four used saved FP registers are checked.
   Added 23 host checks; all 438 Python tests pass. Twenty-one fresh exports,
   observations, hashes and reproduction are recorded in
   [analysis/ALGORITHM_MANAGER_AND_HR_ADAPTER.md](analysis/ALGORITHM_MANAGER_AND_HR_ADAPTER.md)
   and [analysis/algorithm-manager.json](analysis/algorithm-manager.json).
   Vendor material stays ignored; no device access or firmware/settings changes.

## 2026-11-17 — HR outer workspace, restart and borrowed extension views

1. Executed actual HR outer initialization: 78 successful requests totaling
   89,556 bytes, root/66-child/eleven-scratch pointer layout, rate/mode fields,
   initialized flag and primary-root allocation failure. Numerical setup remains
   a supplied boundary; secondary allocation failures stay open.
2. Executed native outer cleanup through all 78 free boundaries and pointer
   clearing. Repeated init/exit are no-ops. A restart uses different addresses
   and frees both generations' 156 allocations exactly once. Internal cleanup
   and allocator implementation remain supplied; allocation guards are checked.
3. Executed actual initialized unsupported-type processing: preparatory state
   words and eleven scratch arrays clear, return is zero, output is untouched.
   Supported signal normalization and numerical processing remain unexecuted.
4. Executed the actual configuration extension: copies its header and installs
   24 borrowed views before checking both sizes against 0x1a1d0. Invalid sizes
   return zero after modifying metadata; a rejected rebind replaces old views.
   Complete source backing is supplied; no pointed-to data/consumer use tested.
5. All 21 native cases pass (eight workspace, five process, eight extension),
   totaling 16,586 bounded steps including intercepted calls. Stack and twelve
   saved integer/FP registers are checked. Added 14 host checks; all 452 Python
   tests pass. Six fresh export hashes, full observations and reproduction are in
   [analysis/HR_WORKSPACE_AND_EXTENSION.md](analysis/HR_WORKSPACE_AND_EXTENSION.md)
   and [analysis/hr-workspace.json](analysis/hr-workspace.json). Vendor material
   stays ignored. No device access, phone/watch settings or firmware changes.

## 2026-11-17 — native HR setup, component allocations and nested cleanup

1. Executed actual setup's 27 rate-scaled buffer clears, field resets and
   delegation. Standalone padded fixtures cover software rates 0..100 at ten
   selected values; full outer cases retain its fixed rate 25. Integer division
   placement, unchanged tails and guards are checked; no physical rate claim.
2. Executed inner initialization, coefficient/float defaults, three component
   allocation paths, existing-buffer reset and extra-workspace initialization.
   Initializer 0x708a4818 remains supplied; return 7 is ignored by its parent.
   Extra 8188-byte allocation failure logs but outer init still returns zero
   and sets initialized. Other failures and subsequent measurements stay open.
3. Executed actual nested cleanup on fifteen masks over eleven pointer slots.
   First four slots retain their freed addresses, later slots clear; four free
   calls are unconditional even for null pointers. Native ordering and complete
   root/global/allocation state are checked under a supplied free service.
4. Executed outer init/exit with the deeper selected paths: 89 requests totaling
   101,108 bytes and 89 distinct releases; restart balances 178 requests across
   different addresses. This extends the earlier 78-request result, whose
   whole setup/cleanup functions were supplied boundaries.
5. All 37 native cases pass (11 setup, six inner init, 15 cleanup, five outer),
   totaling 27,696 bounded steps including intercepted calls. Added 19 host
   checks; all 471 Python tests pass. Fourteen fresh exports, code/constant
   hashes, full observations and reproduction are in
   [analysis/HR_SETUP_AND_NESTED_CLEANUP.md](analysis/HR_SETUP_AND_NESTED_CLEANUP.md)
   and [analysis/hr-setup.json](analysis/hr-setup.json). Vendor material stays
   ignored; no device/settings access or firmware changes performed.

## 2026-11-17 — native boot recovery validation and signed coverage

1. Recovered and executed both boot CRC forms and independently generated the
   256-entry table. Recovery header compares raw CRC-32, polynomial 0xedb88320,
   seed 0xffffffff, over its first 68 bytes without final complement.
2. Executed selected metadata policy: hardware nibble comparison/unknown value,
   magic/product checks, HMZPSIGN-specific variant requirement and diagnostic-only
   missing OTA property. This fixed 48-byte path does not inspect metadata/body
   size fields; it does not implement the host inspector's variable-size format.
3. Executed image validation and signature-read/hash orchestration through the
   actual key/curve bridge. Checked 4096-byte boundaries, metadata-inclusive
   signed coverage, final-64-byte signature exclusion, buffer cleanup and
   progress. SHA hardware services and ECDSA arithmetic remain supplied. Short
   body/signature read results still reach the verifier; no bypass is claimed.
4. Executed partition selection by input selector, header magic/CRC, image checks,
   version comparison/output and error cleanup. Actual wrapper 0x80c0e9c2 forces
   verification on. Recovery selection/preparation/counter writes/handoff and
   live entry/backup/restoration/standalone boot remain unexecuted/unproved.
5. All 62 native cases pass (seven CRC, 13 metadata, 13 signature, ten image,
   19 partition/wrapper), totaling 24,438 bounded steps including supplied calls.
   Added 24 host checks; all 495 Python tests pass. Ten fresh exports, code/table/
   key hashes, observations and reproduction are in
   [analysis/RECOVERY_VALIDATOR_NATIVE.md](analysis/RECOVERY_VALIDATOR_NATIVE.md)
   and [analysis/recovery-validator.json](analysis/recovery-validator.json).
   Vendor material stays ignored; no device access or firmware/settings writes.

## 2026-11-17 — recovery selection, counter writes and stopped handoff

1. Executed raw header getter/setter, native CRC refresh, all three names and
   open/short-read/short-write cases. Writes affect only synthetic in-memory
   files; complete header/image hashes and descriptor state are checked.
2. Executed OTA priority and normal selection using signed32(bootup-complete)
   < 10. Zero-delta ties use the signed +4 order field and prefer recovery0 on
   equality; other delta ties prefer recovery1. Raw getter status is ignored
   by selection; bounded failure cases expose dependence on supplied backing.
3. Executed preparation/completion and connected counter transitions. Normal
   preparation increments boot-up; OTA preparation writes a zero header plus
   CRC. Mapping-only requests still reach writes. Short preparation reads leave
   the supplied descriptor open; counter reread/write errors can coexist with
   return 1. Completion acknowledges valid normal headers and attempts OTA clear.
4. Executed actual launch and handoff to a stopped PC, including console flag
   handling, emulated mstatus bit-3 clear, supplied BSP teardown and caller-frame
   checks. One independently encoded JAL x0,+0x22c is matched to the OTA entry
   and executed once, stopping before startup at 0x80d0022c. No image body runs.
5. All 64 native cases pass (ten header, 25 selection, 21 prepare/finish/sequence,
   eight handoff/launch), totaling 27,713 bounded steps including supplied calls.
   Added 27 host checks; all 522 Python tests pass. Ten fresh exports, boot/recovery
   hashes, observations and reproduction are in
   [analysis/RECOVERY_SELECTION_AND_HANDOFF.md](analysis/RECOVERY_SELECTION_AND_HANDOFF.md)
   and [analysis/recovery-lifecycle.json](analysis/recovery-lifecycle.json).
   Vendor material stays ignored. No hardware, environment or real flash access.

## 2026-11-17 — boot environment, reason cache and key-policy caller

1. Executed actual environment get/set wrappers with supplied backend callbacks.
   Getter clipping and original length are independent; read status is ignored.
   Setter paths distinguish new/replace/delete, reserve/mark/append/final errors,
   nonnull empty values and maintenance branches. The following commit function
   actually returns zero without other work. Backend persistence is not modeled.
2. Executed actual reason caching and retained-copy wrapper with synthetic bytes.
   Retained magic overrides raw-reason mapping; retained reason 0xffffffff causes
   rereads because it also denotes an uninitialized cache.
3. Executed actual key policy: reason/power guards, initial release loop, up to
   20 press attempts requiring exact 1/1 and 20 hold pairs requiring nonzero
   values. Delay argument 50 and logical indices have no physical calibration.
4. Executed the boot-main prefix through keyboard setup and construction of the
   exact 298-byte upgrade record for /mnt/backup/backup_fw_sign.zip, stopping at
   0x80c005b8 before subsequent dispatch. Caller ignores setter errors; failed
   registration leaves a seeded prior handle intact, while failed initialization
   clears it. Full traces, append payload and stopped caller frame are checked.
5. All 64 native cases pass (ten getter, 16 setter, one commit-only, 12 reason,
   17 key-policy and eight prefix), totaling 11,630 bounded steps. Added 28 host
   checks; all 550 Python tests pass. Eight fresh exports, code/member hashes,
   observations and reproduction are in
   [analysis/BOOT_ENVIRONMENT_AND_KEY_POLICY.md](analysis/BOOT_ENVIRONMENT_AND_KEY_POLICY.md)
   and [analysis/boot-environment.json](analysis/boot-environment.json).
   Vendor material stays ignored; no hardware, real environment or flash access.

## 2026-11-17 — native environment records, cached reads and staged writes

1. Executed actual read/write adapters with supplied device services. The special
   0x4000–0x4fff window uses a rebased dedicated handle or unrevised fallback;
   outside it, even a zero general handle is forwarded. Negative service results
   become read error 2/write error 3; nonnegative short counts become success.
2. Executed actual KV40 append, native CRC, status parser/writer and sector/key
   cache updates. Checked 32/33-byte keys, total record 4076/4077, empty payload,
   reservation sentinel, sector status/free thresholds and unsigned underflow.
   Separate primary/dirty sector markers and exact serialized bytes are recorded.
3. Injected errors into all five record writes and zero-byte results into later
   stages. Key-cache publication occurs before payload/final status, including
   after a failed key write. A failed final status write can coexist with a
   subsequent successful cached read; this does not prove post-reset acceptance.
4. Executed actual cached lookup/descriptor CRC parsing, delete and connected
   get/set replacement. Pending-replacement state preserves the new cache during
   old-record final removal. Connected native storage writes/reads the previously
   checked 298-byte upgrade payload inside a 333-byte KV40 record. Underlying
   arrays impose synthetic NOR-like writes; actual flash semantics remain open.
5. All 57 native cases pass, totaling 136,410 bounded steps. Added 28 host checks;
   all 578 Python tests pass. Eleven fresh exports, guarded code/table/member
   hashes, complete traces and reproduction are in
   [analysis/ENV_RECORDS_AND_STORAGE.md](analysis/ENV_RECORDS_AND_STORAGE.md)
   and [analysis/env-records.json](analysis/env-records.json).
   Reservation, full sector scan and maintenance remain supplied. No hardware,
   real environment, flash or power-loss/reboot operation was accessed/executed.

## 2026-11-17 — empty-cache sector lookup and reservation/retry policy

1. Executed light EF40 header parsing, primary/dirty status decoding and the
   linked next-sector walker over synthetic headers. Covered bad header, next
   boundary and a relative two-sector link that skips an intermediate sector.
2. Executed actual empty-cache lookup, byte-window record search, descriptor
   CRC parsing and comparison filter. State must be 2 with matching key length,
   name and validity. Deleted/CRC-bad first records are skipped for a later
   match; duplicate eligible keys return the first encountered. Connected getter
   returns payload and clipped count with original length. No startup/reset runs.
3. Executed reservation enumeration/callbacks with supplied detailed free-count/
   cursor views. Request must be strictly smaller than free count. Dirty state 2
   depends on the maintenance flag; a last primary-state-1 sector can set the
   flag and fail instead of being selected. Detailed space decoding remains open.
4. Executed maintenance counting and retry scheduling. The GC relocation callback
   remains supplied. Maintenance clears the flag, after which retry may fail and
   rearm it, or select a previously flag-blocked cursor without any compaction.
5. All 41 native cases pass, totaling 503,936 bounded steps. Added 29 host checks;
   all 607 Python tests pass. Twelve fresh exports, code/table/member hashes,
   complete traces, explicit boundaries and reproduction are in
   [analysis/ENV_SCAN_AND_RESERVATION.md](analysis/ENV_SCAN_AND_RESERVATION.md)
   and [analysis/env-scan.json](analysis/env-scan.json).
   No hardware, real environment/flash, relocation/erase or reboot was accessed.

## 2026-11-17 — detailed sector space, tail scan and cached reservation

1. Removed the supplied full/detail-sector boundary. Executed actual EF40
   detailed parser, record walk/CRC, byte-tail scan and sector-end cache handling.
   Tested one/two records, gaps, incomplete/deleted records, primary states,
   programmed tail/hole/chunk-boundary/final-byte patterns and warm cache slots.
2. Confirmed a CRC integrity error can return 2 with positive recomputed free
   count and a cached cursor. Actual reservation can select that cursor; another
   parse uses the cached end and returns zero without rechecking the bad record.
   Exact-size and one-byte-smaller requests preserve the strict size guard.
3. Executed selected invalid-length/state-5 status programming through actual
   parser/status/write-adapter code. An erased first slot is marked and consumed
   in synthetic backing. Injected marker-write failure leaves bytes unchanged
   while parsing/accounting still proceeds. No actual flash writes occur.
4. All 36 native cases pass (30 space-first, six reservation-first, including
   four sequences), totaling 2,484,506 bounded steps. Added 29 host checks;
   all 636 Python tests pass. Nine fresh exports, guarded code/table/member
   hashes, complete observations and reproduction are in
   [analysis/ENV_SPACE_AND_TAIL_SCAN.md](analysis/ENV_SPACE_AND_TAIL_SCAN.md)
   and [analysis/env-space.json](analysis/env-space.json).
   Device services remain synthetic. Startup, GC relocation/erase, physical
   persistence and standalone hardware boot are not established.

## 2026-11-17 — record relocation, sector collection and defaults restoration

1. Executed actual raw relocation, detailed reservation, status/copy/cache/source
   finalization and duplicate-name guard. Positive fixtures provide enough empty
   sectors to perform the copy; independent final-byte checks distinguish those
   from no-space rejection. Errors cover all seven ordinary move writes, short
   copy, already-marked sources and duplicate-present/absent paths.
2. Executed actual collection and maintenance callbacks, including one/two-record
   moves, deleted/CRC-bad filtering and final source reformat. Collection still
   attempts reformat after move failure and returns zero after format failure
   under supplied error cases. Device erase/program services mutate arrays only.
3. Executed the aligned, below-0x4000 sector formatter and four-sector defaults
   restoration. Logical base is zero; earlier arbitrary-base scan models are
   parameterized without changing their existing fixtures. Formatting errors
   propagate; defaults restoration ignores per-entry append errors. Synthetic
   default table covers derived string length and explicit length.
4. Followed initialization caller 0x80c0d58e statically through its repair/default
   fallback and three-attempt scan/maintenance loop. Its export/hash is included;
   it does not execute in these cases. Connected setup/callbacks remain open.
5. All 35 native cases pass (13 move, ten collect, five format, two maintenance,
   five defaults), totaling 874,556 bounded steps. Added 30 independent host
   checks; all 666 Python tests pass. Eight fresh exports, code/table/member
   hashes, complete traces and reproduction are in
   [analysis/ENV_GC_AND_DEFAULTS.md](analysis/ENV_GC_AND_DEFAULTS.md)
   and [analysis/env-gc.json](analysis/env-gc.json).
   No hardware, real environment/flash, physical erase or actual boot was accessed.

## 2026-11-17 — connected environment initialization, readiness and reserve copy

1. Executed actual initializer 0x80c0d58e, invalid-header/dirty/record callbacks,
   GC/default restoration and outer table/readiness binding 0x80c0d67a. Binding
   invalidates cache addresses while preserving other bytes; readiness is set
   only on zero return. Selected unresolved repairs can coexist with zero return.
2. Identified/executed 0x80c0bc28 as diagnostic dump and 0x80c0bd10 as four-block
   reserve-to-active copy, correcting earlier setup/teardown working names.
   Supplied heap/read/rewrite services cover missing handles, allocation/I/O
   errors, short reads and cleanup. Distinct authored source/destination bytes
   verify actual array copying; a short count can still reach full-block rewrite.
3. Executed invalid-sector copy/default fallback, duplicate/incomplete record
   handling, dirty-sector collection, three scan/maintenance attempts followed
   by dump/copy/restart, and repeated binding after an error. Saved copy errors
   survive defaults fallback and can leave valid defaults with readiness clear.
4. All 34 native cases pass (18 initializer-first, five binding, seven copy,
   four dump), totaling 1,232,662 bounded steps. Added 30 host checks; all 696
   Python tests pass. Seven fresh exports, code/table/member hashes and traces
   are in [analysis/ENV_INITIALIZATION_AND_BACKUP.md](analysis/ENV_INITIALIZATION_AND_BACKUP.md)
   and [analysis/env-initialize.json](analysis/env-initialize.json).
   Bounded name-copy semantics were corrected in the harness; the prior 35 GC
   cases rerun unchanged. One record search uses explicit erased adjacent read
   backing beyond the logical four sectors. No device or physical flash access.

## 2026-11-17 — storage registry, environment setup and NVMS bootstrap

1. Executed named registry lookup, owner/range validation and read/program/erase/
   rewrite dispatch against synthetic descriptors. Handles are registry-row
   pointers; requests clip to the partition span. Physical bases, spans and
   callback implementations remain supplied fixture data.
2. Executed environment setup: preferred `easyflash`, optional `envbak`, required
   fallback `nvms` and required `env` selection, mutex creation and partial
   failure state. Recovered the original ROM table publishing `boots=0`.
   Setup ignores the subsequent NVMS mirror-sync return value.
3. Executed the two 160-byte NVMS mirror comparison/repair paths and the actual
   rewrite fallback. Allocation failure leaves an unmatched lock acquisition;
   erase/program failures can be ignored after a successful page read. Fast
   rewrite and page fallback route a crossing request differently in the supplied
   geometry. Real driver alignment, mutex and atomicity rules are unproven.
4. Executed clean bootstrap through actual environment binding/initialization,
   inner/outer readiness gates and the retained magic/low-byte accessor. The
   framework caller restores its ABI and stops before its next startup phase
   at `0x80c0b7b0`, including after setup failure. This is not a complete boot.
5. All 52 native cases pass, totaling 26,784 bounded steps (maximum 4,024).
   Added 33 host checks; all 729 Python tests pass. Thirteen fresh exports,
   32 code-range guards, CRC/default-table hashes and complete traces are in
   [analysis/ENV_STORAGE_SETUP_AND_NVMS.md](analysis/ENV_STORAGE_SETUP_AND_NVMS.md)
   and [analysis/env-storage.json](analysis/env-storage.json).
   Registry population, physical drivers and flash remain outside the fixtures;
   no device was accessed.

## 2026-11-17 — original storage tables and five driver bindings

1. Recovered original startup configuration publishing five backends (`nand`,
   `nandraw`, `eftl`, `disk`, `sftl`) and two identical 16-row partition tables.
   Startup-copy sources and table/descriptor hashes are checked against the
   original boot member; these are image values, not a live device dump.
2. Mapped `env` to `sftl+0xc0000`, `envbak` to `eftl+0x40000`, `nvms` to
   `eftl+0`, and the recovery/backup/dump/log rows. Recovered actual initializer,
   read/program/erase/rewrite callback bindings for all five backends. Offsets
   remain backend-relative; FTL translation and physical NAND placement are open.
3. Inspected device/partition registry population and lazy EFTL initialization.
   Generic EFTL/SFTL initializers defer real setup; initial capacity/base words
   are sentinels, not established runtime geometry. No new native initialization
   cases are claimed. Corrected the board registration tail-jump metadata before
   hashing its fresh export; no image bytes were changed.
4. Added 20 parser/provenance/configuration checks; all 749 Python tests pass.
   Nine fresh export/code-range hashes and complete recovered facts are in
   [analysis/STORAGE_MAP_AND_DRIVER_BINDINGS.md](analysis/STORAGE_MAP_AND_DRIVER_BINDINGS.md)
   and [analysis/storage-map.json](analysis/storage-map.json).
   No watch, phone or physical storage was accessed.

## 2026-11-17 — native original registry population and lazy EFTL

1. Executed device/partition initialization and backend find against the original
   five descriptors and 16 rows. Actual deferred EFTL/SFTL initializers execute;
   NAND/nandraw/disk initialization and the owner heap are supplied services.
   Initializer errors stop setup; allocation failure preserves partial state,
   and a retry reuses initialized devices before populating all owner slots.
2. Verified missing owners leave supplied/stale owner words untouched while
   partition readiness can still be set. The selected signed start comparison
   accepts a high-bit offset; an oversized span is not checked here. These are
   bounded malformed fixtures with no subsequent device access.
3. Executed lazy EFTL descriptor updates from supplied geometry, success/error/
   repeated-ready guards, 32-bit multiplication/subtraction wrap and the read
   wrapper with supplied inner read status/data. Real geometry is not inferred.
4. All 32 native cases pass in 13,890 steps (maximum 1,490); 24 new host checks
   bring the suite to 773 passing tests. Nine fresh exports and 17 code/data
   guards are recorded in
   [analysis/STORAGE_REGISTRY_AND_LAZY_EFTL.md](analysis/STORAGE_REGISTRY_AND_LAZY_EFTL.md)
   and [analysis/storage-registry.json](analysis/storage-registry.json).

## 2026-11-17 — native EFTL translation and page-read routes

1. Executed the actual translation loop, ready read wrapper and generic/alternate
   page adapter over authored geometry/u16 mapping slots. Cross-page/block reads
   select the expected mapped pages; alternate dispatch adds its base page and
   supplies flag 1. Both lower NAND page services remain supplied.
2. Verified missing mappings fill all remaining bytes with `ff` and return the
   processed prefix length; negative page results return `-1` after preserving
   earlier bytes. Nonnegative status does not validate supplied partial copying.
   Selected u16 index/column truncation and base-addition wrap execute too.
3. All 24 native cases pass in 2,159 steps (maximum 199). Twenty new host checks
   bring the full suite to 793 passing tests. Three fresh exports/code guards,
   complete traces and byte checks are in
   [analysis/EFTL_TRANSLATION_AND_PAGE_READ.md](analysis/EFTL_TRANSLATION_AND_PAGE_READ.md)
   and [analysis/eftl-read.json](analysis/eftl-read.json).
   Mapping reconstruction, actual NAND/OOB data, bus/ECC/DMA and physical storage
   remain outside the fixtures. No device was accessed in either pass.

## 2026-11-17 — English documentation

Translated the remaining Italian prose in the README and initial static-analysis
report into English. Renamed the latter to `analysis/ANALYSIS.md` and updated its
links. Preserved the historical dates, commands, identifiers, hashes and evidence
limits; the initial observations point to the current status and work log.

## 2026-11-17 — native EFTL OOB mapping reconstruction

1. Executed actual block scan `0x80c01d8a` and four-byte OOB checksum verifier
   `0x80c01a0a` over authored bad-block, erase and first-page metadata services.
   Verified the `E` tag, modulo-256 checksum and u16 logical-to-block mapping.
2. Covered initial/repair bad-block handling, nonzero OOB errors, partial state,
   invalid tag/checksum, first-mapping-wins duplicate handling and existing slots.
   Initial completion can request retry; repair completion can set ready marker
   even when all blocks remain reserved. The full initializer is not executed.
3. Verified direct repeats accumulating counters, u16 counter wraps, byte flag
   truncation and a logical index beyond the declared block count but inside
   explicitly supplied backing. These are bounded fixtures, not device faults.
4. All 27 native cases pass in 2,988 steps (maximum 426). Twenty-six new host
   checks bring the full suite to 819 passing tests. Two fresh exports/code
   guards, complete traces and state hashes are in
   [analysis/EFTL_OOB_MAPPING_RESUME.md](analysis/EFTL_OOB_MAPPING_RESUME.md)
   and [analysis/eftl-resume.json](analysis/eftl-resume.json).
   Physical NAND/OOB/ECC, real geometry, erase effects and full boot remain open;
   no device was accessed.

## 2026-11-17 — connected EFTL initializer, geometry and buffer lifetime

1. Executed the actual initializer, NAND geometry collector, OOB scan/checksum,
   counter/table reset and second scan together. Supplied ioctl outputs provide
   geometry; statuses are ignored by the selected collector. Direct cases cover
   missing/zero fields, assertion stops, integer division and u16 metadata stores.
2. Executed marker/force cleanup, three allocations and stopped null fills at
   each allocator failure. Scan errors leave buffers live with the marker clear;
   a repeated failed initialization can overwrite their bindings without freeing
   them. Successful repeats skip work. No address-zero writes are performed.
3. Executed four actual generic format-loop cases with supplied lower ioctls;
   nonzero bad-block status skips erase for kind zero, and erase results are
   ignored. Alternate format and physical erase/OOB effects remain open.
4. Connected actual outer lazy initialization to the complete selected inner
   path, verifying readiness/capacity publication and failure preservation.
   Geometry and all lower NAND/heap/clock services remain synthetic.
5. All 38 native cases pass in 10,603 steps (maximum 752). Thirty-four new host
   checks bring the full suite to 853 passing tests. Six fresh exports/code
   guards, complete state/lifetime traces and stopped boundaries are in
   [analysis/EFTL_INITIALIZATION_AND_GEOMETRY.md](analysis/EFTL_INITIALIZATION_AND_GEOMETRY.md)
   and [analysis/eftl-initialize.json](analysis/eftl-initialize.json).
   No device was accessed. Physical geometry, actual NAND/ECC/bus behavior,
   persistence, restoration and full boot remain open.

## 2026-11-17 — NAND partition dispatch and EFTL OOB serialization

1. Executed actual primary/board-fallback lookup using original ROM partition
   rows, driver geometry refresh, NAND partition read/ioctl wrappers and driver
   dispatch. Actual chip-ioctl code reads authored descriptor fields; root/probe
   and physical data remain supplied. A failed query can leave partial refresh.
2. Verified partition-vs-total page counts, block/page rebasing, alignment and
   zero-span derivation. Range requests mutate both caller words before dispatch,
   including on errors; format can ignore erase failures. Selected read requests
   beyond the span still reach the supplied service; physical bounds are open.
3. Connected actual EFTL geometry collection through lookup, partition ioctls
   and descriptor reads. Executed generic/alternate OOB fetch and actual ECC
   extraction/composition, including native round trips in three selected
   layouts. Direct malformed ECC cases and assertion stops remain bounded.
4. All 58 native cases pass in 5,983 steps (maximum 746). Forty-three new host
   checks bring the suite to 896 passing tests. Eleven fresh exports/code guards,
   three original table/configuration guards and complete traces/hashes are in
   [analysis/NAND_PARTITIONS_AND_OOB.md](analysis/NAND_PARTITIONS_AND_OOB.md)
   and [analysis/nand-partition.json](analysis/nand-partition.json).
   The chip descriptor and page/control results are synthetic. No device or
   physical NAND/ECC/bus was accessed; physical persistence and boot remain open.

## 2026-11-17 — original NAND candidate table, probe and driver-root setup

1. Recovered all 11 original candidate descriptors, ID prefixes, geometry,
   feature sequences, ECC positions and bus/driver operation bindings. Their
   128/256/512-MiB geometry values are image facts, not identification of fitted
   hardware. No physical ID or device-specific data was read.
2. Executed actual matching, ID/reset command builders, three-round probe,
   feature write/read/compare paths, error/assertion boundaries and boot counts
   with supplied power/bus/feature/UID/BBT services. Every original supplied ID
   selects its descriptor; no-match exhausts 33 candidate attempts.
3. Executed actual mutex wrapper and outer driver-root initialization, allocation
   and method binding. Object registration remains supplied; injected failures
   preserve partial state and can leave the object allocation live. Verified the
   optional +0x30 match field's fourth-byte comparison on an authored copy;
   all original +0x30 fields are zero.
4. Native probe plus actual OOB compose/extract round trips cover every original
   descriptor's contiguous layout at offsets 16/20/72. Context setup and page
   data remain authored; no NAND is programmed.
5. All 60 native cases pass in 30,716 steps (maximum 1,998). Thirty-six new host
   checks bring the suite to 932 passing tests. Nine fresh exports/code guards,
   40 original data guards and complete inventory/traces are in
   [analysis/NAND_PROBE_AND_CHIP_TABLE.md](analysis/NAND_PROBE_AND_CHIP_TABLE.md),
   [analysis/nand-chips.json](analysis/nand-chips.json) and
   [analysis/nand-probe.json](analysis/nand-probe.json).
   Electrical bus behavior, physical chip identity/ECC, persistence and full boot
   remain open. No watch or phone was accessed.

## 2026-11-17 — NAND QSPI platform, command packets and busy deadlines

1. Executed actual bus initialization, packet conversion and ROM-version query.
   Descriptor word +0x0c selects clock argument 1/2 at threshold 100; emulated
   MMIO, controller fields and both DMA configurations match. Fences are recorded
   ordering markers; lower clock/pin/DMA/HAL services remain supplied.
2. Executed eleven feature/cache/write-enable/program/erase builders through the
   actual bus transfer. Verified packet/frame fields, direct/private-buffer
   selection at 31/32 bytes with ROM policy, input/output copies, reinitialization
   and distinct nonzero-HAL-status assertion stops. Original opcode bytes agree
   across all eleven candidate descriptors; executed builders use the first.
3. Executed both busy loops: deadline checking precedes checking the busy bit.
   A supplied successful feature read at timeout leaves output ff and returns
   zero after logging; an exactly-on-deadline ready response still times out.
   Downstream page/program/erase handling remains to be followed.
4. All 51 native cases pass in 67,695 steps (maximum 30,838). Thirty-four new host
   checks bring the full suite to 966 passing tests. Eighteen fresh exports/code
   guards and five data guards are recorded in
   [analysis/NAND_BUS_AND_COMMANDS.md](analysis/NAND_BUS_AND_COMMANDS.md) and
   [analysis/nand-bus.json](analysis/nand-bus.json).
   No device was accessed. Physical QSPI/DMA completion, chip identity, ECC,
   persistence, restoration and standalone boot remain open.

## 2026-11-17 — NAND page read/program/copy/erase and connected busy policy

1. Executed actual page read/write/copy/copy-with-OOB/erase routines with both
   actual busy loops. Remapping, command builders, status bytes, retry workaround
   and cache data remain supplied; this pass does not execute lower QSPI HAL.
2. Confirmed the previous timeout finding in actual callers: all-busy reads run
   2,000 polls then continue to supplied cache transfer and can return zero.
   Original ECC mask 0x30 compares against 0x20, so ff does not select that error.
   Program instead returns -102; polling/tick erase returns -104 after 4,000/20
   reads. This is software behavior on fixtures, not an observed hardware fault.
3. Verified geometry/spare bounds, supplied remapping outcomes, first-MiB guards,
   ECC/workaround precedence, direct/private-buffer selection, source/destination
   copy ordering, OOB count/column and authored plane-flag behavior. Explicit
   helper-return injections cover outer errors without claiming natural returns
   from actual command builders that normally succeed or assert.
4. All 77 native cases pass in 200,565 steps (maximum 96,107). Thirty-one new host
   tests bring the suite to 997 passing tests. Eight fresh exports/code guards
   and three data guards are recorded in
   [analysis/NAND_PAGE_POLICY.md](analysis/NAND_PAGE_POLICY.md) and
   [analysis/nand-page.json](analysis/nand-page.json).
   No device was accessed. Actual BBT/remapping/retry/UID, lower HAL/ROM, physical
   ECC/persistence, restoration and standalone boot remain open.

## 2026-11-17 — NAND BBT verification/resume and connected page remapping

1. Executed actual BBT verifier/resume, block/page remappers, active query and
   CRC over authored records. Pinned the 140-byte record and 164-byte context;
   acceptance checks magic, reserved-count-minus-two limit and entry CRC.
   Connected verification/mapping accepts bounded unsorted/duplicate records;
   ordering and uniqueness are not validated by this selected verifier.
2. Verified tail good-block selection, primary/backup validation and repair
   requests with mapping temporarily disabled. Reread/erase/write errors log
   repair failure but resume restores the backup-derived RAM table and returns
   zero. Both invalid records return one with mapping inactive. Insufficient
   good reserved blocks stop at an assertion. Physical storage services remain
   supplied; no device repair is performed.
3. All 58 BBT cases pass in 11,561 steps (maximum 2,441). A second set connects
   actual remapping to all five actual page operations and busy loops: 21 cases
   pass in 51,756 steps (maximum 48,179). First-MiB guards inspect mapped
   addresses; reserved mapped blocks fail before issuing page commands.
4. The prior 77-case page native report reproduces byte for byte with the
   extended runner. Fifty new host checks bring the suite to 1,047 passing tests.
   Six/ten export and code-range hashes, eight/thirteen runner guards and all
   traces are in [analysis/NAND_BBT_AND_MAPPING.md](analysis/NAND_BBT_AND_MAPPING.md),
   [analysis/nand-bbt.json](analysis/nand-bbt.json) and
   [analysis/nand-page-mapping.json](analysis/nand-page-mapping.json).
   BBT provenance/creation, lower HAL/ROM, UID/retry, physical persistence,
   restoration and standalone boot remain open. No device was accessed.

## 2026-11-17 — NAND retry levels, UID acquisition and connected ioctl export

1. Executed actual compatibility/level/retry/reset-check/UID routines through
   actual command builders and the actual busy loop over a supplied bus.
   Extracted all eleven original UID configurations: eight flags enabled,
   32-byte copies, 16 attempts, page zero and original feature sequences.
2. Verified that exhausting five level write/readback attempts can still return
   zero; actual unchanged readback confirms this without helper-error injection.
   Retry restores level zero but does not replace a successful result when
   restore fails. Reset-check fallback shares the setter's behavior. Actual
   busy timeout with ff status can be accepted by retry/UID error-mask policy.
3. Executed complement checks and first/second/last-copy selection. Early UID
   errors preserve prior length; cache errors occur after length clearing.
   Seven cases connect acquisition to actual ioctl 0x18: it can export authored
   prior data with return zero after acquisition failure, or return zero with
   length zero. It rejects descriptors whose UID flag is off. No physical UID
   or successful hardware correction is claimed.
4. All 86 cases pass in 334,591 steps (maximum 100,723); the original 79 cases
   remain identical after adding ioctl export. Forty-four new host tests bring
   the suite to 1,091 passing tests. Fifteen code/37 data guards and fourteen
   fresh exports are recorded in
   [analysis/NAND_RETRY_AND_UID.md](analysis/NAND_RETRY_AND_UID.md),
   [analysis/nand-identity.json](analysis/nand-identity.json) and
   [analysis/nand-identity-native.json](analysis/nand-identity-native.json).
   Lower HAL/ROM, physical retry/UID, BBT provenance/creation, persistence,
   restoration and standalone boot remain open. No device was accessed.

## 2026-11-17 — QSPI HAL/FIFO/DMA wrappers and connected NAND commands

1. Executed actual RAM QSPI controller init, command construction, phase/count/
   status helpers, direct FIFO paths, DMA wrappers and clock selection over an
   authored peripheral model and supplied timer/DMA services. Traces pin reset
   self-clear, register masks, aligned-word/byte-tail and unaligned-byte accesses,
   software count updates and completion acknowledgement.
2. Verified timeout quantization/wrap/inclusive boundary and final status recheck.
   Four-iteration zero-FIFO prefixes keep the count unchanged and restart each
   wait even with advancing start times; they stop before the fifth wait and
   claim no normal return. DMA wait errors propagate after clearing enable;
   setup return is ignored in the selected wrappers. Physical DMA is unvalidated.
3. Connected actual feature/cache/write-enable builders through actual NAND bus
   transfer and HAL to the authored FIFO. Actual HAL timeouts now reach distinct
   platform command/receive/transmit assertion boundaries, with logs/diagnostics
   before stopping. These direct-mode cases use a supplied ROM-version result
   and initialized context; complete board/page/private-buffer integration is open.
4. All 90 cases pass in 11,326 steps (maximum 522). The original 81 cases remain
   identical after connected cases were added. Thirty-seven new host checks bring
   the suite to 1,128 passing tests. Nineteen exports/code guards and three data
   guards are recorded in [analysis/QSPI_HAL_AND_FIFO.md](analysis/QSPI_HAL_AND_FIFO.md)
   and [analysis/qspi-hal.json](analysis/qspi-hal.json).
   Actual DMA initialization/setup/wait/IRQ, remaining pin/board services and
   physical timing/coherency/persistence remain open. No device was accessed;
   backup/restoration and standalone boot remain unresolved.

## 2026-11-17 — DMA backend setup/wait/cancel and IRQ dispatch

1. Executed actual DMA initializer, two setup variants, cancellation, count query,
   polling wait and IRQ handler across four authored controller banks. Verified
   channel bounds/registry indexing, NAND-style transmit/receive settings,
   descriptor masks, cache-request direction, transfer-count shifts/truncation
   and partial changes before unknown-base fatal stops.
2. Actual wait can return zero on either tested status bit: A requests cache
   finalization and clears tracking; B preserves tracking without that request.
   Both-bit cases prefer A. Timeout/recheck/wrap cases and common channel-disable
   writes match. Physical meanings of the status bits remain unverified.
3. Executed IRQ registry dispatch, linked/nonlinked behavior, optional/dual
   callbacks and multi-channel ordering. Connected init/setup/wait and
   init/setup/IRQ cases pass. Cache bodies, timestamps and callbacks remain
   supplied; no physical DMA data movement or interrupt delivery is established.
4. All 60 cases pass in 4,898 steps (maximum 280). Thirty-five new host checks
   bring the suite to 1,163 passing tests. Seven code guards/fresh exports and
   full traces are in [analysis/DMA_BACKEND_AND_IRQ.md](analysis/DMA_BACKEND_AND_IRQ.md)
   and [analysis/dma-backend.json](analysis/dma-backend.json).
   QSPI-to-backend integration, live DMA/IRQ/cache coherency, remaining board
   services and physical persistence/restoration/boot remain open. No device
   was accessed.

## 2026-11-17 — connected QSPI/DMA backend and NAND private-buffer path

1. Connected actual QSPI command/DMA wrappers to actual DMA initialization,
   setup and wait over a shared authored peripheral/descriptor model. Both
   NAND-style channel descriptors are initialized and published. Verified
   addresses, zero/unaligned counts, status precedence, residual tracking,
   independent DMA/controller failures and full-counter wrap.
2. Connected actual private-buffer NAND cache read/write builders through actual
   bus, HAL and backend. Supplied copy services verify pre-copy/copy-back ordering
   and exact bytes. DMA payload movement is intentionally not simulated; zero
   results and sentinel read buffers are control-path fixtures, not NAND data.
   Actual failures reach distinct private-buffer assertions without read copy-back.
3. Verified that DMA and controller waits each receive the full timeout budget.
   Authored timestamp sequences can reach both inclusive limits and still return
   zero; no physical time calibration or global transfer deadline is claimed.
4. All 28 cases pass in 11,754 steps (maximum 567). The prior 90-case QSPI native
   report reproduces byte for byte, and both earlier QSPI/backend reports remain
   exactly reproducible. Twenty-two new host checks bring the suite to 1,185
   passing tests. Twenty-four guarded code spans/exports and three data guards
   are recorded in [analysis/QSPI_DMA_INTEGRATION.md](analysis/QSPI_DMA_INTEGRATION.md)
   and [analysis/qspi-dma.json](analysis/qspi-dma.json).
   Complete page/board integration and physical DMA/IRQ/cache coherency,
   persistence/restoration/standalone boot remain open. No device was accessed.

## 2026-11-17 — original NAND platform initialization and pin controls

1. Executed actual grouped six-bit and 23-record table-driven pin helpers.
   Verified shared fields, selector bounds, ignored P1 bit 11, unmasked
   table-helper values and distinct paired read-modify-write sequences. The
   records identify software fields, not physical package/PCB pin mappings.
2. Executed complete selected NAND bus initialization through actual clock,
   pin controls, QSPI and DMA init. Register 0x9a00000c bit 0x200 is cleared
   then set in two operations; fences remain recorded ordering markers.
   Original adjacent DMA descriptors at 0x80de645c/0x80de64a0 use 68-byte observed
   backing and original registry/owner/context links. Startup-zero provenance
   is pinned by the original zero-table record, not unreadable Ghidra BSS bytes.
3. Connected initialization to private-buffer read/write and executed the actual
   bus-triggered reinitialization path before transfer. Lower cache/copy/clock
   inputs and peripheral effects remain authored; no physical DMA or board boot
   is established.
4. All 47 cases pass in 11,934 steps (maximum 1,037). The prior 90/28-case native
   reports remain byte-for-byte identical. Twenty-five new host checks bring
   the suite to 1,210 passing tests. Twenty-eight code guards/exports and five
   data guards are in [analysis/NAND_PLATFORM_AND_PINS.md](analysis/NAND_PLATFORM_AND_PINS.md),
   [analysis/nand-pins.json](analysis/nand-pins.json) and
   [analysis/nand-platform.json](analysis/nand-platform.json).
   Complete page/ECC/board integration, physical pin/DMA/IRQ/coherency,
   persistence/restoration and standalone boot remain open. No device accessed.

## 2026-11-17 — connected NAND page read, BBT, status FIFO and DMA

1. Connected actual page read to actual BBT page/block remapping, page-load,
   status and quad-cache builders, busy loop, bus, QSPI/FIFO/DMA and selected
   full platform initialization. Deferred initialization occurs inside the
   first bus after remapping. No intermediate command helper is replaced.
2. Verified direct/private threshold 31/32, mapped plane-bit changes, reserved
   and geometry boundaries, unsupported-family retry selection, ECC transfer
   before -101, alternate DMA tracking and original failure assertions.
3. Both complete 2,000-poll cases confirm timeout can still lead to read success:
   the busy helper preserves ff and returns zero. An ECC-bad final status is
   discarded before the caller's ECC policy. Physical data delivery is unproven.
4. All 31 cases pass in 1,418,115 steps (maximum 678,807); prior 90/28/47-case
   native reports reproduce byte for byte. Twenty host checks bring the suite
   to 1,230 passing tests. Thirty-seven code/export and eight data ranges are
   pinned in [analysis/NAND_READ_STACK.md](analysis/NAND_READ_STACK.md) and
   [analysis/nand-read-stack.json](analysis/nand-read-stack.json).
   Connected program/erase/copy and supported-family retry, physical chip/BBT/
   ECC/board/DMA/coherency, persistence/restoration and standalone boot remain
   open. All peripheral/service inputs are authored. No device accessed.

## 2026-11-17 — connected NAND page program, guard, FIFO and DMA

1. Connected actual page program to actual BBT mapping, write-enable, quad
   cache-load, program-execute and status builders, platform/bus/QSPI/FIFO/DMA.
   Direct writes capture caller bytes; private writes copy before submission and
   execute original DMA setup/wait. No hardware movement/persistence is claimed.
2. Verified the mapped-page guard boundary (logical 319 -> physical 447 rejected;
   logical 320 -> physical 512 allowed), mapped plane bit and deferred platform
   initialization. Wrapping column+length arithmetic admits column fffffff0 with
   length 64 and submits it to QSPI; physical wire/device effects are unverified.
3. Three complete 2,000-poll cases preserve ff at timeout, including a final ready
   status. Program returns -102, unlike the connected read's possible success.
   Lower failures stop at original bus assertions; failed cache transfer never
   submits program-execute. Status inputs and leaf services remain authored.
4. All 27 cases pass in 2,087,540 steps (maximum 679,083); previous 90/28/47/31-case
   reports reproduce byte for byte. Eighteen new host checks bring the suite to
   1,248 passing tests. Thirty-nine code and eight data ranges, fresh exports,
   model and observations are recorded in
   [analysis/NAND_PROGRAM_STACK.md](analysis/NAND_PROGRAM_STACK.md) and
   [analysis/nand-program-stack.json](analysis/nand-program-stack.json).
   Connected erase/copy/OOB, supported-family retry through the HAL and physical
   corroboration/persistence/restoration/standalone boot remain open.

## 2026-11-17 — connected NAND erase, copy and OOB patch

1. Connected actual erase/page-copy/copy-with-OOB roots to original BBT mapping,
   builders, both busy loops, platform, bus and QSPI/FIFO. OOB uses hardcoded
   opcode 0x34 and forced-direct quad data; the mapped source page selects its
   plane bit. Zero OOB length still submits the patch; count 65 is rejected.
2. Verified mapped source/destination protection, geometry/reserved boundaries,
   deferred initialization, ECC rejection before enable and original assertions.
   Complete erase budgets (4,000 delay or 20 sleep polls) reject final ready
   status at the limit. Both copy phases retain their own 2,000-poll budget.
3. A source timeout can still reach program-execute and return zero if the
   destination later reports ready; destination timeout returns -102. The case
   with both timeouts executes 4,000 actual status transactions. No physical
   cache, copy, erase, persistence or hardware access is claimed.
4. All 64 cases pass in 5,534,722 steps (maximum 1,353,573). Prior 90/28/47/31/27
   native reports reproduce byte for byte. Twenty-seven new host tests bring
   the suite to 1,275 passing tests. Forty-five code ranges/exports and eight
   data ranges are recorded in
   [analysis/NAND_ERASE_COPY_STACK.md](analysis/NAND_ERASE_COPY_STACK.md) and
   [analysis/nand-maintenance-stack.json](analysis/nand-maintenance-stack.json).
   Supported-family retry/UID through the HAL, higher storage and physical
   corroboration/persistence/restoration/standalone boot remain open.

## 2026-11-17 — connected supported-family retry, page recovery and UID export

1. Connected actual retry setter/compatibility/retry/reset check, page-read ECC
   recovery, UID acquisition and selected ioctl export through original platform,
   builders, bus and QSPI/FIFO. A recovered private read also connects actual
   DMA. Eleven original descriptor/name/sequence sets are guarded; only candidate
   3 matches retry compatibility. Feature/UID/peripheral effects remain authored.
2. Confirmed five verification mismatches still return zero, allowing retry/reset
   checks to report success with unchanged level. Real restoration HAL failure
   instead asserts after retry_valid. Complete busy timeouts can still produce
   successful retry or UID publication through the connected stack.
3. Original UID complement selection executes through first/second/sixteenth or
   sixteen invalid FIFO copies. Actual ioctl exports fresh, stale or zero-length
   state. Cache assertion follows length clear/zeroing; earlier failure preserves
   prior bytes. Combined external BBT/UID guards respect their exact adjacency.
4. All 67 cases pass in 1,565,265 steps (maximum 679,078); prior 90/28/47/31/27/64
   native reports reproduce byte for byte. Thirty new host tests bring the suite
   to 1,305 passing tests. Fifty-two code ranges/exports and 39 data ranges are in
   [analysis/NAND_RETRY_UID_STACK.md](analysis/NAND_RETRY_UID_STACK.md) and
   [analysis/nand-identity-stack.json](analysis/nand-identity-stack.json).
   No physical UID/ECC/flash evidence or device access is claimed. Higher storage,
   BBT provenance/repair, concurrency/coherency/IRQ, persistence, device-specific
   backup/restoration and standalone boot remain open.

## 2026-11-17 — connected NAND partition and RTOS-context dispatch

1. Connected original partition read/ioctl and original operation-table read/ioctl
   callbacks through context selection, mutex wrappers and actual lower BBT/page/
   command/platform/QSPI/DMA. IRQ/context leaves and mutex results are supplied;
   actual selection/lock/unlock bodies execute. Root/ops/callback missing paths
   are covered without replacing a valid callback.
2. Confirmed page rebasing before BBT, extent-independent reads, wrapping page
   addition and caller argument rebasing before missing-driver failure. Format
   executes two actual guarded erase calls, ignores both errors and returns zero.
3. All 39 cases pass in 63,953 steps (maximum 7,925); prior 354 native cases
   reproduce byte for byte. Nineteen new host checks bring
   the suite to 1,324 passing tests. Fifty-five code/export and ten data hashes
   are recorded in [analysis/NAND_DISPATCH_STACK.md](analysis/NAND_DISPATCH_STACK.md)
   and [analysis/nand-dispatch-stack.json](analysis/nand-dispatch-stack.json).
   EFTL mapped/page/OOB integration is next. Driver binding/RTOS/peripheral inputs
   remain authored; concurrency, physical persistence/restoration/boot are open.

## 2026-11-17 — connected ready EFTL translation and OOB extraction to QSPI

1. Connected actual ready EFTL read/translation/page/OOB/extraction through
   partition, original callbacks/context/mutex, BBT/page, bus/QSPI/FIFO/DMA.
   Original 2,048-byte/64-page geometry is used with authored eight-slot mapping
   and explicitly identified OOB metadata variants. Ready state is supplied.
2. Verified multi-page/cross-block output offsets, gap ff fill/prefix return,
   missing-driver fast bypass and lower ECC failure after buffer modification.
   OOB scratch reaches actual extraction; page errors skip output extraction
   even after scratch changes. Direct FIFO data and DMA sentinel remain fixtures.
3. All 32 cases pass in 78,825 steps (maximum 4,224); prior 393 native cases
   reproduce byte for byte. Nineteen new host checks bring the suite to 1,343
   passing tests. Sixty code/export and ten data hashes are in
   [analysis/EFTL_QSPI_STACK.md](analysis/EFTL_QSPI_STACK.md) and
   [analysis/eftl-qspi-stack.json](analysis/eftl-qspi-stack.json).
   Higher storage entry/bounds, mapping reconstruction/provenance, physical
   persistence/restoration/boot and concurrency/coherency remain open.

## 2026-11-17 — registered storage read/bounds through ready EFTL and NAND/QSPI

1. Connected original storage read and owner/bounds helper through the original
   EFTL descriptor callback, ready logical map, page/partition/callback/context/
   BBT/page/bus/QSPI/FIFO and selected DMA. Original 16-row partition/backend
   bytes are cloned and verified; nvms/envbak/recovery are selected. Registry
   binding, ready map, one-MiB runtime capacity and span variants are authored.
2. Verified end/overflow count clipping, zero-size interior versus end behavior,
   missing-owner and original handle/output assertions. The upper storage wrapper
   accepts EFTL short/zero returns after gap fill; negative lower errors cross
   both layers and may follow caller-buffer modification.
3. All 24 cases pass in 37,927 steps (maximum 3,765); prior 425 native cases
   reproduce byte for byte. Eighteen new host checks bring the suite to 1,361
   passing tests. Sixty-two code/export and twelve data hashes are in
   [analysis/STORAGE_EFTL_STACK.md](analysis/STORAGE_EFTL_STACK.md) and
   [analysis/storage-eftl-stack.json](analysis/storage-eftl-stack.json).
   Selected storage reads now reach original lower control code. Broader callers,
   registry/map reconstruction, write/repair atomicity and physical corroboration/
   concurrency/coherency/persistence/backup/restoration/standalone boot remain open.

## 2026-11-17 — connected upper storage program/logical erase/rewrite and full pages

1. Connected actual upper storage mutation APIs, original EFTL callbacks/writer,
   OOB packing and free-block selection through NAND partition/callback/context/
   mutex/BBT/program/erase/bus/QSPI/TX DMA. Partial caller data fills a complete
   2,048+64-byte page; direct FIFO captures all bytes and private DMA stages the
   full page. The 2,112-byte private backing is authored, not allocation proof.
2. Verified existing mapping, first-page erase, actual free-block selection and
   mapping publication, sequence/no-free failures and logical erase's one-byte-ff
   writer path. Two-block erase returns caller byte count after two erase/program
   sequences. Rewrite's original four-byte callback branches to program; it adds
   no replacement transaction in the existing-page fixture.
3. Original flag update precedes NAND mutex/transfer and persists after selected
   assertions. Readback and status-error bad-mark/relocation paths remain deferred
   and excluded explicitly. Supplied ready registry/map/flags/counters, peripherals
   and leaf services establish no physical persistence or atomicity.
4. All 36 cases pass in 266,399 steps (maximum 54,825); prior 449 native cases and
   metadata-adjusted mutation execution reproduce byte for byte. Twenty new host
   checks bring the suite to 1,381 passing tests. Seventy-six code/export and
   twelve data hashes are in [analysis/EFTL_MUTATION_STACK.md](analysis/EFTL_MUTATION_STACK.md)
   and [analysis/eftl-mutation-stack.json](analysis/eftl-mutation-stack.json).
   Readback/relocation/bad marking, broader allocator/map reconstruction, complete
   concurrency/coherency/IRQ, physical corroboration/backup/restoration/boot remain open.

## 2026-11-18 — enabled EFTL readback, checksum and mapping publication

1. Connected enabled write readback through original NAND page/OOB extraction
   and checksum, including selected bidirectional DMA control. Tag/checksum pass
   does not compare logical block identity: a valid logical-7 record is accepted
   while writing logical zero. Cache bytes remain authored, not physical data.
2. Failed check after free-block program leaves its flag advanced without new
   RAM mapping publication. Private RX models no movement and exposes stale TX
   bytes in the selected fixture; this is a model boundary, not a device finding.
3. All 16 cases pass in 799,362 steps (maximum 57,438); prior 485 native cases
   reproduce byte for byte. Twelve host checks bring the suite to 1,393 passing
   tests. Seventy-seven code/export and twelve data hashes are recorded in
   [analysis/EFTL_READBACK_STACK.md](analysis/EFTL_READBACK_STACK.md) and
   [analysis/eftl-readback-stack.json](analysis/eftl-readback-stack.json).
   I/O-error relocation/bad marking, prefix copying, atomicity and physical
   corroboration/restoration/standalone boot remain open.

## 2026-11-18 — original bad marking and bounded zero-prefix relocation

1. Connected original repair, bad-mark adapter and three-page NAND marker writes
   through the actual lower stack. Generic ioctl/context/mutex and fast paths
   execute. Marker failure is not propagated by the void EFTL adapter; repair
   can return a selected block while marking the old block failed.
2. Verified no-free retirement, erase-failure mark/reselect and successful first-
   page relocation/retry/publication. Readback I/O error enters real repair, unlike
   tag/checksum rejection. Prefix allocation failure stops at the original assert
   after RAM bad-flag update and new-block erase; successful prefix copy is deferred.
3. All 22 cases pass in 801,098 steps (maximum 112,664); prior 501 native cases
   reproduce byte for byte. Sixteen host checks bring the suite to 1,409 passing
   tests. Eighty code/export and twelve data hashes are in
   [analysis/EFTL_REPAIR_STACK.md](analysis/EFTL_REPAIR_STACK.md) and
   [analysis/eftl-repair-stack.json](analysis/eftl-repair-stack.json).
   Ready maps/flags, statuses/peripherals and leaf services remain authored.
   Successful prefix migration, recursive repair, complete atomicity/concurrency,
   physical marking/persistence/backup/restoration/standalone boot remain open.

## 2026-11-18 — prefix migration, heap lifetime and recursive EFTL repair

1. Executed original one/two-page prefix copying through NAND/QSPI, including
   saving/restoring the pending 2,112-byte page at supplied allocator/copy/free
   boundaries. Prefix mapping publication precedes the caller's pending-page
   retry. Direct FIFO observations preserve distinct copied page bytes/order.
2. Verified prefix logical-ID rejection and selected bad-tag/checksum acceptance;
   this path checks different metadata from ordinary write readback. Read errors
   and second-page mismatches restore/free pending data without new publication.
   Prefix-program failure restores/frees before recursive relocation; selected
   success, no-free and recursive allocation failure preserve precise lifetimes.
3. All 20 native cases pass in 3,211,729 steps (maximum 323,829); prior 523 native
   cases reproduce byte for byte. Eighteen host checks bring the suite to 1,427
   passing tests. Eighty code/export and twelve data hashes are in
   [analysis/EFTL_PREFIX_STACK.md](analysis/EFTL_PREFIX_STACK.md) and
   [analysis/eftl-prefix-stack.json](analysis/eftl-prefix-stack.json).
   Generic RX still models no DMA movement and can copy stale TX bytes. Source
   cache pages, maps/statuses/peripherals and leaf services remain authored.
   Larger/combined readback-repair paths, persistent atomicity/concurrency and
   physical corroboration/backup/restoration/standalone boot remain open.

## 2026-11-18 — combined prefix repair, readback and repeated relocation

1. Connected prefix migration with enabled current-page readback. Bad final
   tag/checksum returns `-2` without rolling back the prefix's already published
   RAM map. Retry I/O/program failure with no free block can leave that map
   naming a block whose flag is now bad. A second free block permits another
   selected outer relocation; inner recursive-prefix repair is covered too.
2. Traced failed OOB readback updating shared scratch before repair saves it:
   captured pending-page retries contain those supplied OOB bytes. Final
   readback inputs are independent authored bytes; this establishes data flow,
   not physical corruption, persistence or a device accepting inconsistent media.
3. All 20 native cases pass in 4,426,280 steps (maximum 381,917). The runner and
   eighty original guarded code ranges are unchanged from the prefix pass.
   Sixteen host checks bring the suite to 1,443 passing tests. Evidence and the
   same code/export plus twelve data hashes are in
   [analysis/EFTL_REPAIR_READBACK.md](analysis/EFTL_REPAIR_READBACK.md) and
   [analysis/eftl-repair-readback.json](analysis/eftl-repair-readback.json).
   Generic DMA still models no movement and can expose stale buffer data.
   Larger/further failure paths, persistent atomicity/concurrency, physical
   corroboration/backup/restoration/standalone boot remain open.

## 2026-11-18 — EFTL map scan through original NAND marker and OOB reads

1. Connected the original scanner and bad-block adapter through ioctl 10, actual
   three-page NAND marker checking, OOB extraction, partition/context/mutex,
   BBT/page/bus/QSPI and selected DMA control. The first non-ff marker pair
   returns 103; negative marker-read errors trigger erase even in first-scan mode.
2. Verified first-encountered duplicate retention through actual OOB transport,
   skipping a marked old candidate, partial mapping after OOB errors, positive
   marker handling in repair mode and erase-failure retry/zero-return behavior.
   Source marker/OOB bytes and erase outcomes are independent authored inputs;
   this is direct scan execution, not persistent reboot recovery.
3. All 22 native cases pass in 156,671 steps (maximum 19,315); all 563 previous
   native cases reproduce byte for byte with the extended runner. Eighteen host
   checks bring the suite to 1,461 passing tests. Eighty-three code/export and
   twelve data hashes are in [analysis/EFTL_SCAN_STACK.md](analysis/EFTL_SCAN_STACK.md)
   and [analysis/eftl-scan-stack.json](analysis/eftl-scan-stack.json).
   Full initializer/geometry/scan/retry connection to this lower stack, physical
   persistence/BBT provenance, concurrency and backup/restoration/boot remain open.

## 2026-11-18 — full selected EFTL initialization through NAND/QSPI

1. Connected original lookup/geometry, context reset, allocation/fill, generic
   format, scan/retry and lazy readiness through original NAND/BBT/QSPI. The
   registry row and eight-block partition are authored; geometry ioctls execute
   against the original chip descriptor. IRQ-context FIFO and normal-context
   stale-DMA cases remain distinct, without invented physical DMA movement.
2. Verified forced marked-buffer cleanup/reuse, all three null-allocation fill
   stops, marker/repeated-call guards, missing-registry assertion and scan-error
   live buffers. Positive first-scan reset reaches actual repair scan. A repair
   returning zero with eight reserved blocks can publish global readiness with
   capacity zero. OOB error leaves an initially clear ready byte clear, while
   failed forced eager reinitialization retains an already-set ready byte and
   the old capacity even though its context marker is zero.
3. All 23 native cases pass in 648,613 steps (maximum 83,438); all 585 previous
   native cases reproduce byte for byte. Nineteen host checks bring the suite to
   1,480 passing tests. Eighty-nine code/export and
   twelve data hashes are in
   [analysis/EFTL_BOOTSTRAP_STACK.md](analysis/EFTL_BOOTSTRAP_STACK.md) and
   [analysis/eftl-bootstrap-stack.json](analysis/eftl-bootstrap-stack.json).
   Registry/probe/BBT startup, wider partitions/heap generations, persistence,
   concurrency, physical backup/restoration and standalone boot remain open.

## 2026-11-18 — original NAND candidate probing through QSPI FIFO

1. Connected original per-candidate platform/clock/pin/DMA setup, five-byte ID
   transport/matching, reset and feature write/readback through the actual bus
   and QSPI HAL. All eleven original candidates are exercised with authored
   FIFO IDs. Candidate bus words 104/83 select different original clock branches;
   these are software selector observations, not physical clock measurements.
2. Distinguished real ID/reset/feature bus assertion stops from earlier supplied
   helper-error returns. Feature mismatch retains descriptor selection without
   setting boot guards. Operation-wrapper mutex creation occurs after successful
   probing; supplied power/workaround/UID/BBT error results remain unpropagated.
3. All 26 native cases pass in 256,313 steps (maximum 38,801, success on the
   33rd/final candidate attempt); all 608 previous native reports reproduce byte
   for byte. Eighteen host checks bring the suite to 1,498 passing tests.
   Native observations and 42 code/export plus 30 data hashes are recorded in
   [analysis/NAND_PROBE_STACK.md](analysis/NAND_PROBE_STACK.md) and
   [analysis/nand-probe-stack.json](analysis/nand-probe-stack.json).
   ID/register/MMIO/timer inputs, power/mutex and auxiliary UID/workaround/BBT
   services remain authored. Actual auxiliary/BBT startup, driver registry,
   physical identification, persistence and backup/restoration/boot remain open.

## 2026-11-18 — BBT recovery and mapped reads through original NAND/QSPI

1. Connected actual BBT verification/CRC, reserved-tail marker scan, backup
   reread/erase/program and following mapped reads through original NAND/bus/QSPI.
   A recovered `[1, 3, 7]` table drives caller page 600 to actual load address 792;
   inactive mapping loads 600. Record/FIFO/status inputs remain authored and
   captured erase/program commands do not mutate persistent cells in this model.
2. Verified zero return and restored active RAM mapping after actual reread ECC,
   erase and program errors; no-good/one-good tail assertions; count limits,
   accepted unsorted/duplicate records and reserved-page rejection. Direct verify
   with an already active map can fail before a NAND read; resume clears it first.
3. All 21 native cases pass in 342,220 steps (maximum 34,562). Sixteen targeted
   host checks are included in the combined 1,525-test passing suite. Eighty-seven
   code/export and fourteen data hashes are in
   [analysis/NAND_BBT_STACK.md](analysis/NAND_BBT_STACK.md) and
   [analysis/nand-bbt-stack.json](analysis/nand-bbt-stack.json).

## 2026-11-18 — original first-chip probe joined to BBT recovery

1. Replaced the selected probe's supplied BBT return with actual recovery through
   NAND/QSPI. Real no-table return 1 is ignored: the probe can return zero, set
   guard counts and let its wrapper create a mutex while BBT magic is inactive.
   Real repair errors can likewise leave active RAM mapping and probe success.
   A BBT assertion stops before guard/mutex publication, after descriptor selection.
2. Executed the actual first-chip unsupported-family workaround branch and its
   compatibility checks. UID/power/mutex and library/peripheral effects remain
   supplied; supported-family workaround and actual UID integration stay open.
3. All 12 native cases pass in 235,814 steps (maximum 37,339). Eleven targeted
   host checks join the same 1,525-test suite. Ninety-three code/export and 36
   data hashes are in [analysis/NAND_PROBE_BBT_STACK.md](analysis/NAND_PROBE_BBT_STACK.md)
   and [analysis/nand-probe-bbt-stack.json](analysis/nand-probe-bbt-stack.json).
   Both macroblocks retain authored read-only record inputs and establish no
   physical table provenance, persistent repair or standalone boot/recovery.
   All 634 previous native reports reproduce byte for byte with the extended
   runner and refactored probe model; both new evidence files reproduce exactly.

## 2026-11-18 — original UID joined to probe and BBT recovery

1. Connected original UID acquisition/verification through platform/QSPI FIFO
   inside the first-chip probe, before ordinary feature programming and actual
   BBT recovery. First, second and sixteenth complement-valid copies publish
   length 16. All-invalid copies clear length while probe/BBT can still succeed.
2. Selected early feature/ECC errors preserve authored prior length 17 and UID
   sentinel bytes. Original ioctl 24 after successful probe exports that retained
   state; successful acquisition exports 16 verified bytes. This establishes
   error-state behavior over authored inputs, not physical UID provenance.
3. Eleven native cases pass in 245,971 steps (maximum 34,710), including backup
   repair, actual erase failure, ignored no-table result and wrapper mutex order.
   Ninety-eight code/export and 37 data hashes accompany
   [analysis/NAND_PROBE_UID_BBT.md](analysis/NAND_PROBE_UID_BBT.md) and
   [analysis/nand-probe-uid-bbt.json](analysis/nand-probe-uid-bbt.json).

## 2026-11-18 — supported-family workaround and UID inside original probe

1. Joined actual candidate-3 compatibility/reset/E0-level and UID bodies to
   original probe/platform/FIFO. Original descriptor/sequence bytes remain
   unchanged. Reset opcodes 66/99 and requested delays precede E0 handling and
   UID; ordinary feature programming subsequently restores B0 to 0x19.
2. E0=2, second-attempt confirmation and five ignored/unconfirmed writes now run
   inside the probe. Five mismatches can leave E0=2 with successful probe and
   valid UID. Early UID errors again permit subsequent export of authored prior
   state. This scope keeps BBT supplied for candidate 3's 4-KiB-page geometry.
3. Ten native cases pass in 131,238 steps (maximum 28,586). Forty-nine code/export
   and 31 data hashes accompany [analysis/NAND_PROBE_AUX.md](analysis/NAND_PROBE_AUX.md)
   and [analysis/nand-probe-aux.json](analysis/nand-probe-aux.json). The two scopes
   share 20 host tests in the 1,545-test suite. All 667 preceding shared-runner
   native cases reproduce byte for byte; both new evidence files reproduce.
   No hardware access or persistent media change occurred. Initial BBT creation,
   wider geometry/registry/startup and safe backup/restoration remain open.

## 2026-11-18 — original object registry lookup and insertion

1. Executed original name/type lookup and registration list bodies over authored
   60-byte objects, including first/seeded/three-node append, duplicate name/type
   and pointer rejection, and actual next/preceding-link-cell publication.
2. Verified the 32-byte comparison/31-byte copy boundary: a 32-byte name can
   register yet miss full-name lookup, and repeated full-name registration can
   publish duplicate stored prefixes. Type 279 is stored as byte 23 but misses
   lookup 279; empty names work while null inputs reach the actual assertion.
3. Existing, retried and failed mutex creation plus returned lock/unlock errors
   exercise original unchecked caller policy. Null-handle lock behavior is
   supplied, without a real RTOS/concurrency claim. All 19 native cases pass in
   16,274 steps (maximum 1,103). Forty-four code/export and 33 data hashes are in
   [analysis/NAND_OBJECT_REGISTRY.md](analysis/NAND_OBJECT_REGISTRY.md) and
   [analysis/nand-object-stack.json](analysis/nand-object-stack.json).

## 2026-11-18 — outer NAND driver root through probe/UID/BBT/registry

1. Joined original root initializer and operation-table callback to actual
   probe/wrapper/platform/QSPI/UID/BBT and object registration. Original tables
   remain unchanged. Real lookup after return retrieves the allocated object
   with its original method table bound; seeded append and other-type coexistence
   also execute. Property/heap/mutex/library/peripheral effects remain supplied.
2. Followed actual inner feature failure to outer -6; property/driver-mutex/BBT
   assertions stop before allocation. Object allocation failure retains completed
   inner state. Duplicate registration returns -11 and leaves the newly allocated
   object live but unlinked, while existing lookup still returns the prior object.
3. Actual no-BBT and backup-repair-error results still allow successful root
   registration. Early UID errors can preserve and later export authored old UID
   bytes even after registration. These are controlled RAM/caller contracts,
   without physical UID, persistent media or standalone boot evidence.
4. All 14 native cases pass in 245,078 steps (maximum 40,092). The two scopes add
   25 host tests to the 1,570-test suite. All 688 preceding shared-runner native
   reports reproduce byte for byte, as do both new evidence files. One hundred
   one code/export and 38 data hashes accompany
   [analysis/NAND_DRIVER_ROOT_STACK.md](analysis/NAND_DRIVER_ROOT_STACK.md) and
   [analysis/nand-root-stack.json](analysis/nand-root-stack.json). Initial BBT
   creation, wider geometry, registry removal/lifetimes/concurrency, broader
   storage/startup, real persistence and safe backup/restoration remain open.

## 2026-11-18 — original object opening, reference counters and ioctl policy

1. Executed original register-and-open/open/ioctl bodies with authored method
   callbacks. Missing open callback/table can return zero without incrementing
   count; subsequent ioctl rejects the unopened object. Repeated positive-count
   open skips the callback. Negative and signed-overflow count fixtures also
   distinguish success from a usable positive reference count.
2. Real registration precedes open: callback error leaves a linked zero-count
   object; duplicate registration's -11 becomes wrapper -1 without reopening.
   Ioctl forwarding preserves supplied callback output even when it returns an
   error. Null object inputs stop at their original assertions.
3. All 17 native cases pass in 12,660 steps (maximum 922). Forty-seven code/export
   and 35 data hashes accompany [analysis/NAND_OBJECT_OPEN.md](analysis/NAND_OBJECT_OPEN.md)
   and [analysis/nand-object-open.json](analysis/nand-object-open.json). Close,
   decrement, removal and concurrent ownership are still outside this pass.

## 2026-11-18 — consumers of the actual registered NAND object

1. Added explicit post-root consumer calls through original generic open/ioctl,
   original NAND methods, context/mutex wrappers and chip geometry/BBT queries.
   Original root/probe/UID/BBT/registration still execute first. Successful root
   return and later consumer returns/assertions are recorded separately.
2. Geometry commands 0x1001/0x1002 issue actual queries 13/2/1/14, publishing the
   selected descriptor ID, page-size times count and actual active-BBT byte.
   No-BBT startup can publish capacity with active byte zero. IRQ/scheduler
   contexts bypass locks; acquire/release assertions leave output unpublished.
3. Commands 0x1003, invalid command and null output cover selected no-op/error
   paths. Original suspend/resume methods return zero without transfers for
   the selected non-null object; original owner strings identify those methods.
   Other NAND partition/data paths remain separate.
   Authored callback/RTOS/peripheral/media inputs do not prove physical operation.
4. All 15 native cases pass in 261,061 steps (maximum 21,629). One hundred eight
   code/export and 44 data hashes accompany
   [analysis/NAND_OBJECT_CONSUMER.md](analysis/NAND_OBJECT_CONSUMER.md) and
   [analysis/nand-object-consumer.json](analysis/nand-object-consumer.json). The
   two scopes add 26 host tests to the 1,596-test suite. All 721 preceding shared-
   runner native reports reproduce byte for byte; both evidence files reproduce.
   Close/removal/reclamation/concurrency, wider startup/storage integration,
   initial BBT provenance, persistence and safe device restoration remain open.

## 2026-11-18 — main-image object close, reference and dispatch policy

1. Followed original owner-name references into the main image and executed its
   generic open/close/write/ioctl/active bodies with authored objects/callbacks.
   Only the last close calls the backend. That close decrements first, so a
   backend error leaves count zero; a missing close callback instead leaves a
   positive count unchanged despite zero return. Active and later operations
   distinguish those states. Negative/overflow counts are explicit fixtures.
2. Verified write/ioctl tail forwarding, supplied status/effect propagation,
   missing methods, null assertions and ABI/buffer guards. Original main owner
   strings identify the APIs; removal, deallocation and RTOS/concurrent ownership
   remain outside this pass. The existing boot runner/vectors are unchanged.
3. All 26 native cases pass in 691 steps (maximum 84). Five code/export and four
   data hashes accompany [analysis/MAIN_OBJECT_LIFECYCLE.md](analysis/MAIN_OBJECT_LIFECYCLE.md)
   and [analysis/main-object-lifecycle.json](analysis/main-object-lifecycle.json).

## 2026-11-18 — original main NAND methods behind object consumers

1. Bound an authored object to the original main NAND method table and executed
   actual main generic consumers plus original NAND open/close/ioctl. Repeated
   references defer close; final close/reopen executes the original methods.
   The original +8 write slot is null and real generic write returns zero without
   a backend transfer. Main probe/registration and physical teardown are unproven.
2. Original geometry ioctl propagates supplied lower-query responses/errors at
   each of four positions, writing output only after all succeed. Covered alias,
   no-op, invalid/null output, zero BBT flag and explicit multiplication wrap.
   Original property/method/operation tables stay unchanged; lower driver query
   behavior remains supplied, unlike the earlier fully joined boot NAND scope.
3. All 15 native cases pass in 1,430 steps (maximum 157). Eight code/export and ten
   data hashes accompany [analysis/MAIN_NAND_OBJECT.md](analysis/MAIN_NAND_OBJECT.md)
   and [analysis/main-nand-object.json](analysis/main-nand-object.json). The two
   scopes add 24 host tests to the 1,620-test suite; both evidence files reproduce.
   Main lower-driver/probe/registry integration, removal/reclamation/concurrency,
   persistence, initial BBT provenance and safe backup/restoration remain open.

## 2026-11-18 — main geometry through actual context/chip/BBT-active bodies

1. Replaced supplied main lower geometry results with original lower/context/
   lock/chip switch and BBT-active code. Two unchanged original descriptors
   yield 2-KiB/128-MiB and 4-KiB/512-MiB software geometry. Selected pointer,
   mutex/RTOS effects and BBT magic remain authored; no probe/media/CRC runs.
2. Checked exact/wrong/inactive magic, no selected chip, normal/IRQ/scheduler/
   absent-mutex paths and acquire/release assertions. Failure leaves geometry
   output unpublished; a real no-chip result still traverses normal release.
3. All 13 native cases pass in 4,213 steps (maximum 499). Fourteen code/export
   and 13 data hashes accompany
   [analysis/MAIN_NAND_QUERY_STACK.md](analysis/MAIN_NAND_QUERY_STACK.md) and
   [analysis/main-nand-query-stack.json](analysis/main-nand-query-stack.json).

## 2026-11-18 — main root/registry/PM publication joined to geometry consumers

1. Executed original main root and operation initializer, actual main registry
   lookup/duplicate/insertion and subsequent object consumers. Probe, BSP
   property/heap/RTOS/library/PM-binding services remain supplied. A supplied
   successful probe publishes an original descriptor; actual candidate search,
   UID, BBT recovery and bus initialization remain outside this scope.
2. Real registration precedes cached-object publication, then a dev_nand_pm
   property lookup and binding call. A supplied -9 return from that call is
   ignored. Missing PM property asserts after registry/cache publication.
   Duplicate registration retains an unlinked allocation but skips cache/PM;
   probe, allocation, driver-mutex and property failures expose earlier stages.
3. All 12 native cases pass in 4,763 steps (maximum 725). Eighteen code/export
   and 16 data hashes accompany [analysis/MAIN_NAND_ROOT_STACK.md](analysis/MAIN_NAND_ROOT_STACK.md)
   and [analysis/main-nand-root-stack.json](analysis/main-nand-root-stack.json).
   The two scopes add 24 host tests to the 1,644-test suite. All 41 prior main-
   object native reports reproduce byte for byte; both new evidence files
   reproduce. Existing guard/log values are preserved. Actual main probe/UID/
   BBT/platform/media, wider storage/startup, PM internals, reclamation/concurrency
   and safe physical backup/restoration/boot remain open.

## 2026-11-18 — actual main candidate probe, ID/reset builders and feature policy

1. Extracted the original main-image eleven-chip table independently of the boot
   table, including descriptor/feature/geometry/UID/reset fields and hashes.
   Actual main probe, matcher and ID/reset builders execute over the unchanged
   descriptors and bus binding. Bus callbacks, regulator/feature services and
   workaround/UID/BBT bodies remain supplied; delay arguments are observed,
   without electrical/timing validation.
2. Selected all eleven candidates, round-two and final-33rd-attempt matches;
   observed real no-match -4, caller/builder assertions and feature write -5,
   read -6 and mismatch -7. Missing regulator continues; selected negative
   supplied power/auxiliary return-register values are ignored. Supplied BBT
   result 1 with zero magic still permits success and actual guard publication.
   UID's status convention and real BBT recovery are not established here.
3. All 24 native cases pass in 13,623 steps (maximum 2,091). Eighteen code/export
   and 35 data hashes accompany [analysis/MAIN_NAND_PROBE.md](analysis/MAIN_NAND_PROBE.md),
   [analysis/main-nand-probe.json](analysis/main-nand-probe.json) and
   [analysis/main-nand-chips.json](analysis/main-nand-chips.json).

## 2026-11-18 — actual main probe joined to root publication and geometry

1. Replaced the supplied probe in a new connected scope with actual candidate
   detection/ID/reset/feature policy, followed by original root/wrapper/registry/
   cache/PM publication and subsequent open/geometry/close callers. Geometry now
   follows the descriptor selected by authored ID responses: first-chip 128 MiB
   and candidate-3 512 MiB. Supplied no-BBT still registers with inactive geometry.
2. Real no-match and feature-mismatch results become outer -6 before allocation;
   only mismatch retains selection. Append/duplicate, existing mutex, allocation
   failure and late PM assertion preserve their distinct original state. A
   successful probe and guard counts do not imply successful object/cache/PM
   publication or active BBT.
3. All 10 native cases pass in 8,732 steps (maximum 2,003). Twenty-two code/export
   and 38 data hashes accompany [analysis/MAIN_NAND_PROBE_ROOT.md](analysis/MAIN_NAND_PROBE_ROOT.md)
   and [analysis/main-nand-probe-root.json](analysis/main-nand-probe-root.json).
   Both evidence files and inventory reproduce; all 66 prior main native cases
   reproduce byte for byte. Existing configuration/guard/log values are preserved.
   The two scopes add 24 host checks; all 1,668 tests pass. Main bus/platform/
   feature transport, actual main UID/workaround/BBT, broader storage/startup,
   PM internals, reclamation/concurrency and physical restoration/boot remain open.

## 2026-11-18 — original main bus/platform and feature packets

1. Executed actual main bus init/transfer and feature read/write builders over
   supplied HAL/revision/DMA/pin/copy services and authored MMIO. Clock-word
   boundaries, original controller/DMA-link publication, ignored initialization
   statuses, normalized direction/dummy fields, direct/bounce thresholds,
   copying and partial receive effects now have main-image native evidence.
2. Disabled flag 0x80c10e39 returns -1 before pending reinitialization is cleared
   or any revision/command call. Otherwise reinitialization flag 0x80c10e38 is
   cleared before actual init. Init itself preserves both flags. HAL failures
   stop at distinct original transport assertions; disabled feature calls reach
   actual builder assertions. No assertion body or physical peripheral runs.
3. All 35 native cases pass in 3,168 steps (maximum 200), with four code/export
   and two original data hashes. The direct fixture clones the first descriptor
   to vary its bus word; original source/binding bytes remain guarded. See
   [analysis/MAIN_NAND_BUS.md](analysis/MAIN_NAND_BUS.md) and
   [analysis/main-nand-bus.json](analysis/main-nand-bus.json).

## 2026-11-18 — main probe/platform/bus/feature path through root consumers

1. Connected actual main bus initialization/packet conversion and feature
   builders to original probe/matcher/ID/reset, root/wrapper/registry/cache/PM
   publication and subsequent open/geometry/close. All eleven unchanged original
   descriptors now drive their own bus clock policy, feature packets and actual
   geometry queries. HAL/FIFO/DMA, revision, power, UID/workaround/BBT and
   BSP/RTOS/heap/library/PM services remain supplied.
2. Real HAL command/data faults stop inside transport. Authored disabled-flag
   transitions after selected commands expose actual feature-builder assertions;
   these cases do not establish an actual asynchronous setter or race. Readback
   mismatch instead returns probe -7 and outer -6 before allocation. Supplied
   no-BBT, duplicate registration and late PM assertion retain their distinct
   successful-probe state; registry publication does not imply active BBT.
3. All 25 native cases pass in 44,902 steps (maximum 4,202), with 26 code/export
   and 38 data hashes. See [analysis/MAIN_NAND_BUS_PROBE.md](analysis/MAIN_NAND_BUS_PROBE.md)
   and [analysis/main-nand-bus-probe.json](analysis/main-nand-bus-probe.json).
   Both new evidence files reproduce; all 100 earlier main native cases
   reproduce byte for byte. Parent configuration/guards/log tags are unchanged;
   narrow inherited harness hooks support the new scope. Twenty-six new host
   checks join the passing 1,694-test suite. Main HAL/FIFO/DMA and revision bodies,
   actual UID/workaround/BBT, wider storage and physical restoration/boot remain open.

## 2026-11-18 — actual main QSPI HAL, FIFO, clock and revision policy

1. Executed original main controller init, command packing/submission, count/
   readiness/completion helpers, aligned/unaligned FIFO receive/transmit, DMA
   wrappers, clock selection and revision policy. MMIO reset/status/FIFO/W1C,
   64-bit ticks/frequency, ROM string and DMA setup/wait/copy remain authored.
   Corrected Ghidra function metadata that attached the independent completion
   entry to command; imported bytes and instruction semantics remain unchanged.
2. Covered command null inputs, empty command completion, FIFO tails/counts,
   direct/data/completion timeouts, deadline rechecks, exact deadline, counter
   wrap, sub-kHz and multiplication-wrap cases. Four zero-FIFO cases stop at a
   non-progress prefix. DMA setup status is ignored while wait propagates;
   request bit is cleared and successful DMA retains count. Actual revision
   recognizes exact v1.1.03/v1.1.16 over the authored string.
3. All 89 native cases pass in 8,704 steps (maximum 410), with 14 code/export
   and two original data hashes. See [analysis/MAIN_QSPI_HAL.md](analysis/MAIN_QSPI_HAL.md)
   and [analysis/main-qspi-hal.json](analysis/main-qspi-hal.json). Actual DMA
   backend/cache, full main probe/root linkage through this HAL and physical
   operation remain open.

## 2026-11-18 — main bus and feature packets through actual HAL/FIFO

1. Joined original main bus transfer, feature builders and revision to actual
   command/FIFO/DMA-wrapper code over an authored initialized controller. This
   scope does not execute platform/probe/root. Original binding/selected source
   descriptor and revision literals remain immutable. Direct, bounce, threshold,
   old/unknown revision, unaligned, feature-byte and timeout cases execute.
2. Actual HAL timeout 3 reaches original bus assertions. Supplied DMA setup -9
   followed by successful wait can still lead to success and copyback of unchanged
   authored bounce bytes. Wait failure instead skips copyback and retains caller
   bytes, even if supplied setup already filled bounce memory. These state/status
   dependencies do not establish real DMA/media behavior.
3. All 24 native cases pass in 14,877 steps (maximum 1,846), with 18 code/export
   and four original data hashes. See [analysis/MAIN_QSPI_BUS.md](analysis/MAIN_QSPI_BUS.md)
   and [analysis/main-qspi-bus.json](analysis/main-qspi-bus.json). Both new evidence
   files and vectors reproduce; all 160 earlier main native cases reproduce byte
   for byte. Twenty-eight new host checks join the passing 1,722-test suite.
   Older shared runners are unchanged. Next: actual main DMA backend/cache,
   then full platform/probe/root through HAL and main UID/workaround/BBT/media.
4. At the user's request, recorded a rough qualitative project RE estimate of
   50–60% in [analysis/RE_STATUS.md](analysis/RE_STATUS.md). This subjective scope
   assessment has substantial uncertainty and does not measure coverage or time
   remaining. Hardware, complete pairing and safe restoration/boot are major gates.

## 2026-11-18 — actual main DMA initialization/setup/cancel/count/wait

1. Executed six original main DMA bodies over authored descriptors/MMIO/status/
   ticks and supplied cache services. Covered four recognized banks, invalid
   channels, NAND TX/RX, masks/widths, setup variants, cancellation, count-query
   null guards, primary/alternate/both status, timeout/recheck and counter wrap.
   Native wait reads both status registers before branching, despite a possible
   short-circuit impression from pseudocode. Primary clears tracking; alternate
   success and timeout retain it.
2. Main initializer differs from boot for an unrecognized base: actual code
   writes slot 28+channel and returns zero instead of calling the boot fatal
   boundary. Authored base 0x93100000/channel 5 publishes slot 33 in explicit
   35-slot guarded backing. No valid fifth bank, production allocation boundary
   or physical memory-corruption claim follows. Main IRQ remains outside scope.
3. All 46 native cases pass in 3,021 steps (maximum 204), with six code/export
   hashes. See [analysis/MAIN_DMA_BACKEND.md](analysis/MAIN_DMA_BACKEND.md) and
   [analysis/main-dma-backend.json](analysis/main-dma-backend.json). Metadata seed
   includes the reviewed complete wait-result tail; image bytes are unchanged.

## 2026-11-18 — main DMA backend joined to QSPI and NAND bounce packets

1. Connected actual main DMA init/setup/wait to original QSPI command/completion/
   DMA wrappers and selected NAND bounce packets. Two authored descriptors are
   initialized and registered at actual main table slots 26/27. Original main
   platform descriptor addresses, full probe/root, IRQ/cache bodies and physical
   DMA movement remain outside this scope.
2. Primary/alternate status preserves distinct tracking while returning zero.
   Backend and QSPI completion waits have separate budgets. Backend timeout or
   later QSPI timeout reaches original NAND bounce assertions. With no physical
   movement modeled, successful direct DMA leaves caller bytes unchanged and
   successful bounce read copies authored sentinel bytes. Software success
   does not establish delivered data or coherency.
3. All 28 native cases pass in 11,758 steps (maximum 574), with 21 code/export
   and four data hashes. See [analysis/MAIN_QSPI_DMA.md](analysis/MAIN_QSPI_DMA.md)
   and [analysis/main-qspi-dma.json](analysis/main-qspi-dma.json). Both new evidence
   files and vectors reproduce; all 273 prior main native cases reproduce byte
   for byte. The shared main HAL adds only a default I/O-filter factory hook.
   Twenty-eight new host checks join the passing 1,750-test suite. Next: actual
   main platform/DMA linkage and reinitialization, full probe/root through this
   backend, main IRQ/cache and UID/workaround/BBT/media, plus physical restoration/boot.

## 2026-11-18 — original main platform and adjacent DMA descriptor publication

1. Executed actual main platform/clock/QSPI/DMA initialization at original
   adjacent TX/RX addresses, with reciprocal controller links and actual main
   registry slots 26/27. Startup-aware facts independently place both observed
   68-byte records in a zero-table region. The record extent is an access
   boundary, not a complete allocation claim; controller initial state remains
   authored and pin/GPIO/cache/copy bodies remain supplied.
2. Covered clock boundaries, original clear-then-set board accesses, ignored
   supplied pin errors, mode-one controller retention, unchanged private bytes,
   tracking cleanup and retained pending/disabled flags. A cloned first chip
   descriptor varies only its bus word; original source/binding bytes are guarded.
3. All eight native cases pass in 2,802 steps (maximum 353), with 21 code/export
   and four data hashes. See [analysis/MAIN_NAND_PLATFORM.md](analysis/MAIN_NAND_PLATFORM.md),
   [analysis/main-nand-platform.json](analysis/main-nand-platform.json) and
   [analysis/main-nand-platform-facts.json](analysis/main-nand-platform-facts.json).

## 2026-11-18 — main platform/DMA links and reinitialized NAND bounce transfers

1. Joined actual main platform initialization and original descriptor addresses
   to NAND bus/revision/QSPI/DMA-backend bounce transfers. Deferred initialization
   follows the actual pending-flag branch. A separate case initializes first,
   then performs real reinitialization at the same addresses with preserved
   private fields. Disabled transfer retains the pending flag both before and
   after an explicit successful initialization.
2. Primary/alternate status, backend/later-QSPI timeout and retained registry/
   tracking/request-bit states execute. Physical movement is not simulated;
   successful receive may copy unchanged authored bounce sentinels. No full
   candidate probe/root, actual UID/BBT/media, IRQ/cache or hardware proof follows.
3. All 14 native cases pass in 9,235 steps (maximum 1,057), with 21 code/export
   and four data hashes. See [analysis/MAIN_NAND_PLATFORM_TRANSFER.md](analysis/MAIN_NAND_PLATFORM_TRANSFER.md)
   and [analysis/main-nand-platform-transfer.json](analysis/main-nand-platform-transfer.json).
   Startup facts, vectors and both evidence files reproduce; all 347 earlier
   main native cases reproduce byte for byte. Existing harness configuration/
   guards remain unchanged through narrow pointer/backing/I/O extension hooks.
   Twenty-four new host checks join the passing 1,774-test suite. Next: full main
   probe/root through this platform/HAL/backend and actual UID/workaround/BBT/media.

## 2026-11-18 — main probe/root through original platform and QSPI FIFO

1. Joined original main root/wrapper, all eleven candidate descriptors, matcher,
   ID/reset/feature builders, actual platform/clock/QSPI FIFO/revision and DMA
   initialization to actual registry/cache/PM publication and later object
   open/geometry/close. Descriptors/bindings are unchanged; original adjacent
   DMA records and registry links now participate in the same caller chain.
2. All eleven selections drive actual FIFO counts/bytes and software geometry.
   Append, duplicate, late PM assertion and supplied no-BBT/inactive geometry
   retain their distinct publication states. Power/pin/GPIO/workaround/UID/BBT,
   BSP/RTOS/heap/library/PM bodies remain supplied. These short forced packets
   do not execute DMA setup/wait or establish physical chip/media behavior.
3. All 15 native cases pass in 98,379 steps (maximum 11,401), with 43 code/export
   and 40 data hashes. See [analysis/MAIN_NAND_FULL_PROBE.md](analysis/MAIN_NAND_FULL_PROBE.md)
   and [analysis/main-nand-full-probe.json](analysis/main-nand-full-probe.json).

## 2026-11-18 — full main FIFO probe retries and real timeout assertions

1. Executed second-round, final-33rd and complete no-match paths with real
   platform reinitialization and ID FIFO on each attempt. All-ff responses
   leave selection/guards zero and produce outer -6 before allocation, while
   actual controller/DMA links remain. A dedicated 30,000-step bound admits
   this joined workload; previous scopes retain their default 10,000 limit.
2. Actual HAL readiness/completion loops produce transport timeout assertions.
   A feature-write completion timeout retains the modeled FIFO byte/feature
   state while guards/publication remain absent. Feature mismatch instead
   returns actual probe -7 then wrapper -6. Disabled ID, absent regulator,
   negative pin service and allocation failure expose earlier/later stages.
   Ticks, status and FIFO responses are authored; no assertion body or physical
   acceptance/recovery is established.
3. All 12 native cases pass in 85,212 steps (maximum 29,185), with the same
   guarded corpus. See [analysis/MAIN_NAND_FULL_PROBE_FAULTS.md](analysis/MAIN_NAND_FULL_PROBE_FAULTS.md)
   and [analysis/main-nand-full-probe-faults.json](analysis/main-nand-full-probe-faults.json).
   Both evidence files/vectors reproduce; all 369 earlier main native cases
   reproduce byte for byte. Parent configuration/guards/log tags are unchanged;
   narrow emulator/bound and model-initialization hooks support this scope.
   Twenty-eight new host checks join the passing 1,802-test suite. Next: actual
   main workaround/UID/BBT and page/media callers, IRQ/cache/pin bodies and physical
   backup/restoration/boot.

## 2026-11-19 — original main workaround/reset/level logic inside probe

1. Executed actual main family comparison, reset-enable/power-reset commands,
   requested delays and E0 level checking/setting inside the original platform/
   FIFO/root chain. Unsupported-family return -1 is ignored by probe. Supported
   first/second confirmation and five unconfirmed writes execute; the real setter
   still returns zero after five mismatches. UID/BBT remain supplied in this scope.
2. Actual HAL reset/completion/E0-read faults stop at original transport assertions
   before workaround return. Family names, descriptor bytes and feature sequences
   are immutable. Main identity inventory independently records all eleven UID
   flag/mode/copy/page/size/config/ECC records. FIFO/register/timing inputs and
   bounded library/power/platform services remain authored or supplied.
3. All eight native cases pass in 51,955 steps (maximum 11,317), with 54 code/export
   and 65 data hashes. See [analysis/MAIN_NAND_WORKAROUND.md](analysis/MAIN_NAND_WORKAROUND.md),
   [analysis/main-nand-aux-workaround.json](analysis/main-nand-aux-workaround.json)
   and [analysis/main-nand-identity.json](analysis/main-nand-identity.json).

## 2026-11-19 — actual main UID setup/load/busy/cache/complement checks

1. Joined original main void UID routine, feature setup/readback, page load, busy
   status and direct 32-byte cache FIFO to actual workaround/probe/root/geometry.
   First/second/sixteenth copy, no complementary copy, feature mismatch, ECC reject,
   two status reads, no-UID flag and selected Winbond/DOSILICON/ESMT descriptors
   execute. UID bytes/status/E0 are authored; BBT and library/platform services
   remain supplied, with no physical identity or media claim.
2. Handled UID errors may return normally while leaving prior UID state or length
   zero; outer probe and registration still succeed. Readiness timeout leaves
   cleared cache backing, while completion timeout retains FIFO bytes with length
   still zero. Actual transport assertions stop before normal UID completion.
   Sixteenth-copy case reads 521 total FIFO bytes; the new scope uses a 1024-byte
   aggregate trace guard, preserving the prior scope's 512-byte default.
3. All 14 native cases pass in 130,133 steps (maximum 24,357). See
   [analysis/MAIN_NAND_UID.md](analysis/MAIN_NAND_UID.md) and
   [analysis/main-nand-aux-uid.json](analysis/main-nand-aux-uid.json). Inventory,
   vectors and both evidence files reproduce; all 396 previous main native cases
   reproduce byte for byte. Narrow auxiliary/model/FIFO hooks preserve prior
   configurations and bounds. Twenty-eight new host checks join the passing
   1,830-test suite. Next: actual main BBT recovery/repair, UID export/consumers,
   page/media paths, IRQ/cache/pin bodies and physical backup/restoration/boot.

## 2026-11-19 — actual main UID export through context/chip locking

1. Joined original context query 24 and chip ioctl to the actual main UID/probe/
   platform/FIFO/root chain. Export writes the current length byte and UID bytes
   without revalidating acquisition freshness. Handled setup/ECC errors expose
   authored prior state; no valid copy exports length zero. The original no-UID
   descriptor returns -201 without writing. Generic object geometry ioctl does
   not forward this direct UID query. Copy and RTOS services remain supplied.
2. Actual context IRQ/scheduler bypass and mutex helper branches execute. Acquire
   failure stops before chip dispatch; release failure stops after bytes have
   already been copied. A geometry/open/close sequence can export repeatedly
   after generic close. Source/output guards and per-operation snapshots hold.
3. All 16 native cases pass in 141,306 steps (maximum 23,961), with 54 code/export
   and 65 data hashes. See [analysis/MAIN_NAND_UID_EXPORT.md](analysis/MAIN_NAND_UID_EXPORT.md)
   and [analysis/main-nand-uid-export.json](analysis/main-nand-uid-export.json).

## 2026-11-19 — actual main BBT verifier/resume/CRC joined to probe and consumers

1. Executed original main BBT verifier, reserved-tail selection, backup recovery
   and CRC against the original main lookup table inside first-chip probe/UID/
   platform/FIFO/root, then actual geometry and UID export. Marker and BBT page
   read/write/erase services are supplied over authored records; no physical
   media or persistent repair is claimed. Empty/count-limit/CRC/read errors,
   malformed ordering/duplicates, alternate tail pairs and assertions execute.
2. Actual recovery restores active RAM magic and returns zero after supplied
   reread/erase/write failures. Neither-record return one is ignored by outer
   probe, which registers the device while geometry reports inactive BBT. Valid
   BBT does not refresh retained UID state. The original 164-byte BBT ends at the
   128-byte UID buffer; combined span guards preserve the adjacent source.
3. All 18 native cases pass in 117,251 steps (maximum 7,082), with 57 code/export
   and 67 data hashes. See [analysis/MAIN_NAND_BBT.md](analysis/MAIN_NAND_BBT.md)
   and [analysis/main-nand-bbt.json](analysis/main-nand-bbt.json). All 434 preceding
   main native cases reproduce byte for byte after narrow operation/BBT/guard
   hooks, preserving original configurations and bounds. The two scopes add
   38 host checks to the passing 1,868-test suite. Next: actual main BBT remapping
   and lower page/DMA integration, further identity/media consumers and physical
   backup/restoration/boot.

## 2026-11-19 — actual main block/page remapping after recovered BBT

1. Joined original main block and page remappers to actual BBT recovery, first-
   chip probe/UID/platform/root and later geometry/UID export. Recovered table
   entries and backup boundary drive translation; page remainder is preserved.
   Reserved-limit errors retain prior output. Inactive tables bypass mapping;
   active maximum-word block input can wrap to zero. Inputs are authored.
2. Accepted duplicate entries advance twice, while an accepted unsorted list
   can stop before a later bad entry. Repair failure can leave active mapping;
   selected final reserved pair changes the exclusive boundary. Recovered BBT,
   UID and object state remain unchanged by remapping. Lower BBT page/marker
   services remain supplied, without physical table or persistent repair claims.
3. All 20 native cases pass in 134,246 steps (maximum 6,858), with 59 code/export
   and 67 data hashes. See [analysis/MAIN_NAND_BBT_MAPPING.md](analysis/MAIN_NAND_BBT_MAPPING.md)
   and [analysis/main-nand-bbt-mapping.json](analysis/main-nand-bbt-mapping.json).

## 2026-11-19 — original main mapped page read through direct QSPI FIFO

1. Executed actual main page read, recovered-BBT remapping, load builder, busy
   status, direct x4 cache builder and QSPI FIFO after original probe/UID/root.
   One-byte/word-tail/128-byte reads, last usable/reserved bounds, exact OOB end,
   wrapping column arithmetic, inactive/duplicate/unsorted tables and repeated
   reads execute. FIFO bytes/peripheral/status/timer inputs remain authored.
2. ECC rejection follows actual unsupported-family retry, still receives cache
   data and then returns -101. Actual transport timeouts distinguish no FIFO
   delivery from retained payload after completion failure. Per-operation runtime
   snapshots preserve pre-read counters and intermediate buffers. BBT recovery's
   own page callbacks remain supplied; this scope does not yet connect those
   callbacks or asynchronous/private DMA/program/erase to the reader.
3. All 23 native cases pass in 186,325 steps (maximum 10,686), with 62 code/export
   and 67 data hashes. See [analysis/MAIN_NAND_PAGE_READ.md](analysis/MAIN_NAND_PAGE_READ.md)
   and [analysis/main-nand-page-read.json](analysis/main-nand-page-read.json).
   All 472 preceding main native cases, including the 20 mapping cases, reproduce
   byte for byte after narrow snapshot/packet-failure/data-line hooks. Fixed
   configurations and bounds remain unchanged. Forty new host checks join the
   passing 1,908-test suite. Next: actual main BBT page callbacks and DMA/program/
   erase integration, further consumers and physical backup/restoration/boot.

## 2026-11-19 — actual main BBT record reads through original NAND/QSPI

1. Connected original BBT verifier and resume's 140-byte record/reread calls to
   actual main remapping/load/busy/direct-x4-cache/QSPI FIFO inside probe/UID/root
   and later geometry/export/mapping consumers. Recovery clears RAM magic before
   these reads, so original remapping passes through the tail pages. Marker and
   repair erase/write services remain supplied in this scope; FIFO bytes are
   authored, with no physical table or persistent repair claim.
2. Actual primary ECC can deliver bytes and then return -101 before verification;
   actual backup reread ECC skips repair and still restores active RAM magic
   with zero recovery return. Original transport timeouts distinguish no delivery
   from all 140 bytes retained before assertion. Fake page/reread return injection
   is excluded. Harness logger routing preserves original transport assertions.
3. All 14 native cases pass in 189,370 steps (maximum 19,562), with 63 code/export
   and 67 data hashes. See [analysis/MAIN_NAND_BBT_RECORD_READ.md](analysis/MAIN_NAND_BBT_RECORD_READ.md)
   and [analysis/main-nand-bbt-record-read.json](analysis/main-nand-bbt-record-read.json).

## 2026-11-19 — original main three-page marker scan through NAND/QSPI

1. Joined actual main bad-marker checker and original reserved-tail selection to
   recovery record reads through actual page/load/status/direct-cache/FIFO. Two
   good candidate blocks require six marker reads before the record. Late bad
   markers repeat partial scans while no primary exists. Final reserved pair
   requires 30 checker calls and 35 page reads; no-good/one-good scans reach the
   original assertion before record/publication. Erase/write remain supplied.
2. A transient first marker ECC failure followed by a successful second check
   can select backup 1023 while primary remains zero, causing original assertion
   despite authored later usable blocks. Two consecutive ECC failures instead
   advance selection to 1022/1021. Native cases and host policy agree. Transport
   failures retain completed marker work or delivered bytes before acceptance.
3. All 13 native cases pass in 285,080 steps (maximum 49,444). Both scopes use a
   200,000-step bound for complete selected scans; prior bounds/configurations
   remain unchanged, as does the 1024-byte aggregate FIFO trace guard. See
   [analysis/MAIN_NAND_BBT_MARKER_READ.md](analysis/MAIN_NAND_BBT_MARKER_READ.md) and
   [analysis/main-nand-bbt-marker-read.json](analysis/main-nand-bbt-marker-read.json).
   All 495 preceding main native cases reproduce byte for byte. Twenty-eight
   new host checks join the passing 1,936-test suite. Next: actual repair erase/
   program, asynchronous/private DMA, wider consumers and physical restoration/boot.

## 2026-11-19 — actual main BBT repair erase through NAND/QSPI

1. Joined original main erase, block remapping, enable/erase command builders,
   busy status and QSPI to actual BBT marker/record/CRC recovery and later root/
   geometry/UID/mapping consumers. RAM magic is zero during repair, so primary
   block 1023 maps directly to erase page 65472. Program remains supplied in this
   scope; peripheral/status inputs remain authored, without physical erasure or
   persistent repair claims.
2. Actual status 4 returns -104 and skips program, but resume restores active RAM
   magic and returns zero. Ready/busy/status-mask and no-repair cases execute.
   Command/status timeouts stop at original transport assertions, retaining
   inactive magic and preventing publication. Erase-status completion timeout
   counts the delivered status byte without a normal erase return.
3. All 11 native cases pass in 278,269 steps (maximum 27,397), with 69 code/export
   and 67 data hashes. See [analysis/MAIN_NAND_BBT_ERASE.md](analysis/MAIN_NAND_BBT_ERASE.md)
   and [analysis/main-nand-bbt-erase.json](analysis/main-nand-bbt-erase.json).

## 2026-11-19 — original main BBT repair program and exact TX FIFO payload

1. Connected original main program, direct cache-load/program builders, enable,
   page remapping and busy loops through actual TX FIFO inside recovery. The
   complete 140-byte backup reread payload is transmitted at column zero before
   programming primary page 65472. Actual marker/read/CRC/erase/program now joins
   first-descriptor probe/UID/root and consumers, over authored peripheral inputs
   and supplied library/platform services. Physical persistence remains unproved.
2. Actual program status 8 returns -102 after full TX; recovery still restores
   active RAM magic and returns zero. Erase failure skips program. Command/TX/
   status timeouts preserve distinct sent-byte/status counts and leave RAM magic
   zero before publication. The selected original recovery does not reread the
   repaired primary. No backend record update or readback is fabricated.
3. All 13 native cases pass in 378,902 steps (maximum 32,348). See
   [analysis/MAIN_NAND_BBT_PROGRAM.md](analysis/MAIN_NAND_BBT_PROGRAM.md) and
   [analysis/main-nand-bbt-program.json](analysis/main-nand-bbt-program.json).
   Both scopes share 69 code/export and 67 data hashes and the 200,000-step bound.
   All 522 preceding main native cases reproduce byte for byte after narrow
   policy-factory/FIFO-write hooks. Prior configurations/bounds remain unchanged.
   Thirty new host checks join the passing 1,966-test suite. Next: complete busy
   exhaustion, asynchronous/private DMA, wider consumers and physical restoration/boot.

## 2026-11-19 — full original main read busy boundaries inside BBT recovery

1. Executed all 2000 original busy polls through actual feature/bus/QSPI FIFO
   inside selected primary-record recovery. Limit checking precedes readiness
   and output publication: persistent busy, last-poll ready and last-poll ECC
   all leave output ff and helper return zero. The reader can still receive and
   accept the authored valid BBT record. Penultimate ready/ECC instead publishes
   its real byte; penultimate ECC causes actual retry and record rejection.
2. Native and host traces stream exact UTF-8 events plus LF into counted SHA-256
   windows, retaining original selected loop execution and supplied leaf services.
   Full read windows have 36,001 events including timeout log; no raw inside-window
   strings are retained in JSON. Surrounding actions and state remain explicit.
   The new scope uses 4,000,000-step and 8192-byte aggregate RX guards; previous
   scope limits/configurations are unchanged. No elapsed-time or physical-ready
   claim is made over authored statuses/peripherals.
3. All five native cases pass in 3,759,349 steps (maximum 754,985), with the same
   69 code/export and 67 data hashes as the prior repair corpus. See
   [analysis/MAIN_NAND_BUSY_READ.md](analysis/MAIN_NAND_BUSY_READ.md) and
   [analysis/main-nand-busy-read.json](analysis/main-nand-busy-read.json).

## 2026-11-19 — complete main erase/program busy limits through repair

1. Executed all 4000 erase and 2000 program polls inside actual marker/read/CRC/
   erase/program/root recovery. Last-poll ready is discarded just like persistent
   busy. Erase caller returns -104 and skips program; program caller returns -102
   after full TX. Both handled errors still restore active RAM magic and return
   zero from recovery. Penultimate ready permits normal successful completion.
2. Full erase windows have 72,001 counted events; ordinary UID/marker/record and
   non-target repair windows keep one-poll behavior. Exact hashes distinguish
   different final FIFO bytes despite identical published output. All firmware
   bytes, exports and constant data are unchanged. RX totals exceed the preceding
   scope's trace guard without changing individual one-byte status packets or
   establishing physical FIFO size, timing or persistence.
3. All six native cases pass in 6,783,698 steps (maximum 1,498,880). See
   [analysis/MAIN_NAND_BUSY_REPAIR.md](analysis/MAIN_NAND_BUSY_REPAIR.md) and
   [analysis/main-nand-busy-repair.json](analysis/main-nand-busy-repair.json).
   All 546 preceding main native cases reproduce byte for byte. Twenty-four new
   host checks join the passing 1,990-test suite. Next: asynchronous/private DMA,
   nonblocking scheduling, wider media/PM consumers and physical restoration/boot.

## 2026-11-19 — main mode-zero reads through original private-buffer DMA

1. Connected original mode-zero page/cache builders to actual QSPI DMA setup/
   wait using the RX record initialized by the full probe, after actual BBT
   recovery/repair/root publication. Lengths up to 31 use direct FIFO; 32/64
   bytes use DMA on the selected revision, while older ROM falls back to FIFO.
   The packet stores the original no-op callback, but this bus path never calls it.
2. Primary completion clears tracking and calls the cache-finish service;
   alternate completion returns zero with tracking retained. Both copy retained
   authored private-buffer bytes: physical DMA movement is not modeled. DMA
   timeout and later QSPI timeout stop before copy with different tracking state.
   ECC rejection can follow delivered data; assertions retain published root/BBT.
3. All 16 native cases pass in 524,188 steps (maximum 33,924). See
   [analysis/MAIN_NAND_ASYNC_READ.md](analysis/MAIN_NAND_ASYNC_READ.md) and
   [analysis/main-nand-async-read.json](analysis/main-nand-async-read.json).

## 2026-11-19 — main mode-zero erase guards and complete sleep-poll limit

1. Connected original mode-zero erase to recovered block mapping and the
   original enabled guard byte. Logical block 4 maps below the published guard
   boundary and returns -250; logical block 5 maps exactly to it and proceeds.
   Original write-enable/erase/status packets execute through actual QSPI FIFO.
2. Original helper requests one-tick sleeps and allows 20 status reads. Ready
   on read 20 is discarded and erase returns -104, like persistent busy; ready
   on read 19 succeeds. Supplied sleeps establish call arguments, not elapsed
   time, scheduling or IRQ-driven completion. Transport assertions occur after
   publication; no physical erase or persistent state change is simulated.
3. All 14 native cases pass in 473,271 steps (maximum 39,369). See
   [analysis/MAIN_NAND_SLEEP_ERASE.md](analysis/MAIN_NAND_SLEEP_ERASE.md) and
   [analysis/main-nand-async-erase.json](analysis/main-nand-async-erase.json).
   Both scopes share 72 code/export and 68 data hashes. All 557 preceding main
   native cases reproduce byte for byte after the narrow DMA-read hook and
   metadata seed. Thirty-four host checks join the passing 2,024-test suite.
   Next: mode-zero program, IRQ/event scheduling, wider media/PM consumers and
   physical data/coherency/persistence/restoration/boot validation.

## 2026-11-19 — main mode-zero program through original initialized TX DMA

1. Connected original mode-zero page program/cache builder to actual bus/QSPI/
   DMA setup/wait over the TX record initialized by the complete probe, after
   full BBT marker/read/CRC/repair/root publication. Recovered mapping and the
   original enabled 512-page guard run before enable/staging. Selected 31-byte
   requests use direct FIFO, while 32/64 use private-buffer DMA on newer ROM.
2. Original bus stages source bytes before DMA. DMA/QSPI faults retain staging
   and stop before program execute. Primary TX completion calls cache finish
   with zero tracking; alternate completion skips it and still permits execute.
   Direct FIFO emits exact source bytes; no DMA FIFO writes, physical program
   or persistence are fabricated. The stored original callback is not invoked.
3. Actual column checks accept the exact end and unsigned wrapping addition;
   mapping/guard/null/zero-size failures precede IO. Program failure status
   returns -102 after execute, and transport assertions retain published state.
   Repeated programs preserve intermediate staging hashes and mapped pages.
   Program mode zero still uses blocking status polling after cache transfer.
4. All 26 native cases pass in 851,318 steps (maximum 34,390), with 71 code/export
   and 68 data hashes and the unchanged 200,000-step bound. See
   [analysis/MAIN_NAND_MODE_ZERO_PROGRAM.md](analysis/MAIN_NAND_MODE_ZERO_PROGRAM.md)
   and [analysis/main-nand-program.json](analysis/main-nand-program.json).
   All 587 preceding main native cases reproduce byte for byte after the
   metadata seed; all 71 exports reproduce byte for byte after the final seed.
   Twenty-six new host checks join the passing 2,050-test suite.
   Actual IRQ/event scheduling, physical DMA/cache/coherency/persistence, wider
   media/PM consumers and safe restoration/standalone boot remain open.

## 2026-11-19 — original main DMA IRQ dispatch and fallback bank

1. Executed original main IRQ handler 0x702a041c by ordinary harness call.
   Complete pending words are acknowledged before channel work. Primary handling
   finalizes/clears tracking before its callback, preserving channel enable for
   any nonzero linked word; alternate handling always stops and retains tracking
   when it runs alone. Both pending groups invoke both callbacks in that order.
2. Four recognized banks walk seven registry slots each. Unknown bases walk
   fallback slots 28–34, matching main initializer publication without the boot
   fatal path. Explicit guarded 35-slot backing establishes computed accesses,
   not a fifth physical bank or production allocation extent. Channel-6 dispatch
   in the initializer-restricted bank and reverse descriptor order also execute.
3. All 26 native cases pass in 3,809 steps (maximum 279), including connected
   init/setup/dispatch and supplied callbacks. All 46 preceding main backend
   cases reproduce byte for byte after narrow configuration/cache/bank hooks.
   See [analysis/MAIN_DMA_IRQ.md](analysis/MAIN_DMA_IRQ.md) and
   [analysis/main-dma-irq.json](analysis/main-dma-irq.json). IRQ vector/trap entry,
   delivery/nesting/scheduling and actual callback consumers remain open.

## 2026-11-19 — actual cache guards through main DMA/IRQ and recovered NAND

1. Executed original cache prepare/finish bodies for selected high-half/zero
   addresses. Their signed nonpositive guard returns zero before interrupt-state
   services, CSR access or fences. This verifies the earlier static/host guard
   contract without proving physical cacheability, maintenance or coherency.
2. All 72 backend/IRQ guard cases pass in 6,936 steps (maximum 283), sharing nine
   code/export hashes with the IRQ scope. This includes all 26 IRQ cases and all
   46 earlier backend cases under the new actual-cache service boundary.
3. Connected the same actual guards to full original recovered BBT/root NAND
   mode-zero reads and programs over original initialized RX/TX records. All 16
   reads pass in 524,220 steps (maximum 33,932); all 26 programs pass in 851,374
   steps (maximum 34,398). All 42 preceding observations/traces remain identical;
   each cache call adds exactly two executed instructions. Code/export hashes
   number 74/73 respectively, with all 68 prior data hashes retained.
4. All four scopes total 140 native cases under distinct service boundaries;
   these are not distinct hardware scenarios or a coverage metric. Thirty new
   host checks join the passing 2,080-test suite and cover native equality,
   guards, callback ordering, fallback slots and cache-call step differences. See
   [analysis/MAIN_DMA_CACHE_GUARDS.md](analysis/MAIN_DMA_CACHE_GUARDS.md),
   [analysis/main-dma-cache-guards.json](analysis/main-dma-cache-guards.json),
   [analysis/main-nand-cache-read.json](analysis/main-nand-cache-read.json) and
   [analysis/main-nand-cache-program.json](analysis/main-nand-cache-program.json).
   Positive-address CSR progress, live IRQ/scheduling, physical DMA/coherency,
   persistence, wider media/PM consumers and restoration/standalone boot remain open.

## 2026-11-19 — original positive-address cache CSR loops and bounded stalls

1. Executed original prepare/finish/invalidate range loops and whole-cache
   command through actual context/save/restore/critical/diagnostic bodies.
   Range commands use control bit 1, aligned start and unsigned wrapped end;
   whole-cache command 6 is unconditional and does not poll address feedback.
2. Explicit CSR readbacks verify multiple commands, backward progress, aligned/
   unaligned zero lengths, wrapped end and last-positive-address comparison.
   No software line stride is invented. Stalled cases stop before another
   command at a marked harness bound, retaining entered state and claiming no
   firmware timeout or normal return. The three hash-guarded fences remain
   recorded no-ops because the emulator lacks that userop; ordering is unproved.
3. All 43 native cases pass in 6,039 steps (maximum 330). See
   [analysis/MAIN_CACHE_CSR_RANGES.md](analysis/MAIN_CACHE_CSR_RANGES.md) and
   [analysis/main-cache-range.json](analysis/main-cache-range.json). Hardware
   cache progression/completion/coherency and production positive-address
   consumers remain open.

## 2026-11-19 — actual main RTOS critical depth, context and diagnostic state

1. Executed original critical entry/exit and wrapper/context/diagnostic code
   over authored RTOS/thread/CSR backing. Entry clears MIE, then increments depth
   when the scheduler gate is nonzero. Exit reenables MIE only on a nonzero-to-
   zero depth transition. A completed pair can enable initially clear MIE; a
   scheduler-off pair leaves MIE clear. Existing depth and unsigned wrap differ.
2. Nonzero context bypasses critical entry/exit and writes zero to the save
   output. Normal-context save leaves the output sentinel unchanged, and selected
   restore ignores its argument; the pair is not a saved-MIE restoration model.
   Actual optional diagnostics record caller/stage/depth values. These supplied
   state combinations do not establish production validity or a live RTOS bug.
3. All 22 native cases pass in 1,922 steps (maximum 165). See
   [analysis/MAIN_RTOS_CRITICAL_SECTIONS.md](analysis/MAIN_RTOS_CRITICAL_SECTIONS.md)
   and [analysis/main-cache-critical.json](analysis/main-cache-critical.json).
   Both scopes pin ten original code/export hashes and a 5,000-step bound.
   All 186 preceding backend/IRQ/cache/NAND native cases reproduce byte for byte
   after the metadata seed. Thirty-two new host checks join the passing
   2,112-test suite, covering complete native observations, CSR/depth/diagnostic
   boundaries and marked nonreturning stops. Both JSON reports reproduce byte
   for byte from the original archive, pinned exports and native observations.
   Live IRQ/scheduler/current-thread concurrency, physical cache/DMA coherence,
   persistence, wider consumers and restoration/standalone boot remain open.

## 2026-11-19 — weekly-credit checkpoint and Claude handoff

1. Prepared `HANDOFF_CLAUDE.md` (local, untracked) at the user's request as weekly
   Codex credits run low. It records the verified analysis baseline `3685f79`,
   recent commits, local ignored inputs/tooling, test/native reproduction,
   selected regression set, evidence limitations and a ready-to-use resume prompt.
   No native analysis or validation job remains unfinished at this checkpoint.
2. Latest verified state remains 2,112 passing host tests; the latest cache/RTOS
   scopes contain 43 + 22 passing native cases, and 186 preceding selected
   backend/IRQ/cache/NAND cases reproduce byte for byte. This handoff changes
   documentation only; those test results belong to the verified analysis commit.
3. Reviewed the subjective whole-project RE planning estimate: retain roughly
   50–60% complete, with 40–50% remaining and substantial uncertainty. This is
   neither measured coverage nor OS implementation progress. Signed-chain boot,
   device backup/restoration, hardware validation, complete pairing and broader
   required application/algorithm behavior remain major work and feasibility gates.
4. The concrete native continuation is to trace context/scheduler/current-thread
   producers and actual interrupt entry/registration before extending callback
   and production DMA/cache/PM consumers. Keep the standalone boot/restoration
   gate prominent. The handoff identifies exact addresses and existing tools;
   older completed matrices need not be rediscovered.

## 2026-11-19 — main trap entry, interrupt dispatch, PLIC API and FreeRTOS port

1. Found the real main trap path, which no analysis project had disassembled: it
   runs from the RAM copy (`.copy2`, image `0x70dce45c` → `0x80d32e00`). Added
   read-only scanners for constant-built references, control flow/CSR sites and
   in-memory disassembly/decompilation. The previous "context" word `0x80c121a4`
   is written only by the C trap handler (1 on entry, 0 on exit), so it is an
   in-trap flag. The scheduler gate and current-thread fields are FreeRTOS
   `xSchedulerRunning`/`pxCurrentTCB`, identified from `core/freertos/tasks.c`
   assertions and the structure of `xTaskIncrementTick`/`vTaskSwitchContext`.
2. Executed natively the original trap entry/frame (`0x198` bytes, integer/FP
   registers, `mstatus`/`mepc`, Andes `0x7c6`/`0x7c7`, `fcsr`), C handler, core
   and PLIC dispatch, PLIC register/enable/disable/mask/restore/init/deinit,
   timer, exception/syscall/yield and first-task/scheduler-start bodies. All
   **57 cases pass in 7,326 steps** over authored memory/CSRs/registers/claims.
   Results include:
   - ID mask `0xefffffff`;
   - local enable wrap at source 16 (`mie` bit 0);
   - default infinite-loop handlers for unregistered or zero claims;
   - an unbounded claim index;
   - an unconditional `mepc` skip after every exception;
   - first-task start without `fcsr`;
   - loss of the in-trap flag after a nested trap.
3. An independent raw decoder recovers **23 interrupt registrations**: 18 far
   calls matching the decompiler, and 5 direct RAM calls that re-register
   sources `0xb`/`0xc`/`0xe`, including one from `vPortSetupTimerInterrupt`.
   The DMA handler `0x702a041c` serves four controllers
   (`0x12`/`0x16`/`0x19`/`0x1c` at `0x92000000`/`0x93000000`/`0x93040000`/
   `0x93080000`). See [analysis/MAIN_TRAP_IRQ_DISPATCH.md](analysis/MAIN_TRAP_IRQ_DISPATCH.md)
   and [analysis/main-trap-irq.json](analysis/main-trap-irq.json); both the
   native report and the evidence regenerate byte for byte. No project metadata
   changed. Twenty new host checks join the passing **2,132-test** suite. Original tick/switch/timer setup, task creation, the remaining device
   handlers, the deep-sleep routine, live preemption/nesting and timer frequency
   remain open.

## 2026-11-19 — FreeRTOS tick, context selection, port timer and task creation

1. Executed natively the original kernel bodies the trap scope still supplied:
   `xTaskIncrementTick`, `vTaskSwitchContext`, the list primitives,
   `prvResetNextTaskUnblockTime`, `vPortSetupTimerInterrupt`, the source-14
   acknowledgement, the run-time counter, `pxPortInitialiseStack`,
   `prvInitialiseNewTask`, `prvAddNewTaskToReadyList` with the task critical
   section, `xTaskCreateStatic` and libgcc `__clzsi2`. All **61 cases pass in
   10,317 steps** over authored kernel state, TCBs, stacks and supplied
   `mtime`/claim reads. Eight connected cases run the original trap entry,
   timer handler, first-task start and scheduler start with the actual tick/
   switch/timer setup instead of stubs.
2. Results include:
   - a tick of 1000 `mtime` counts, with the initial compare written
     low-then-high;
   - PLIC source 14 registered by the port, with a handler that writes 2 or 4
     to `0x91005000`;
   - 10 priorities, 20-byte names, a `0x4c0`-byte TCB, the method-2 stack
     check, 64-bit run-time statistics, newlib reentrancy and per-task
     `errno`;
   - a silent priority clamp to 9;
   - ties before scheduler start won by the newest task;
   - `MIE` kept clear by task creation until the first task starts;
   - a zero priority bitmap that indexes the delayed-list header;
   - new tasks that start with `gp` = `tp` = 0.

   The initial frame writes Andes CSR `0x7c6` = `0x21` and `0x7c7` = stack base
   + `0x198`. These are interpreted as hardware stack-protection control and
   bound under the AndeStar V5 CSR numbering. See
   [analysis/MAIN_FREERTOS_KERNEL.md](analysis/MAIN_FREERTOS_KERNEL.md) and
   [analysis/main-freertos-kernel.json](analysis/main-freertos-kernel.json); the
   vectors, native report and evidence regenerate byte for byte. Seventeen
   new host checks join the suite. Dynamic creation, blocking APIs, deletion,
   timer frequency and live multi-task scheduling remain open.

## 2026-11-19 — power-management wake gate, dynamic IRQ re-registration and wake body

1. Executed the main-image power-management wake path that is ordinary code:
   the configuration gate `0x80d341d8` (custom CSR `0xfc1`, enabled when the
   three-bit field at bits 6-8 is zero), the conditional re-registration
   routine `0x80d4217c` that re-points PLIC sources `0xe`/`0xc`/`0xb` at RAM
   handlers through the original register/enable bodies, the three identical
   RAM handlers, and the wake body `0x80d41fb8` that pokes the `0x90008000`
   clock/PM block and `0x91000004` with a bounded 10-iteration delay and then
   restores them. All **13 cases pass in 457 steps**.
2. Recorded the deep-sleep save/`wfi`/resume twins `0x80d34470`/`0x80d343a0`
   statically: a full integer/FP/CSR save to a dedicated stack, `fence`+`wfi`,
   then a symmetric restore that writes Andes `0x7c6` = `0x21`, matching the
   hardware stack-protection interpretation. `fence`/`wfi` and the sleep stack
   are not executed. See
   [analysis/MAIN_PM_WAKE.md](analysis/MAIN_PM_WAKE.md) and
   [analysis/main-pm-wake.json](analysis/main-pm-wake.json); the vectors, native
   report and evidence regenerate byte for byte. Ten new host checks join the
   suite. The sleep states, CSR `0xfc1` field meaning, the `0x90008000`/
   `0x91000004` registers and the runtime device sources behind `0xe`/`0xc`/
   `0xb` remain open.

## 2026-11-19 — GPIO pad multiplexer, shared IRQ handler and per-pin dispatch

1. Executed three original main-image bodies that form a GPIO/pad controller:
   the pad multiplexer `0x80d42c84` (a 4-bit field per pin into a bank selected
   by the controller base, eight pins per 32-bit register), the GPIO interrupt
   dispatcher `0x80d436b4` (walks the 16-row callback table at `0x80c118c8`,
   acknowledges `controller + 0x30` per pin and calls the registered handler),
   and the shared interrupt handler `0x70293d50` (registered for PLIC sources
   9/10/`0x2a`-`0x2d`), which performs the clock/PM wake poke for two bases and
   then tail-calls the dispatcher. All **18 cases pass in 2,405 steps** over
   authored controller structs, MMIO banks and callback table; registered
   handlers are supplied stubs.
2. Recovered the bank table (`0x91003000`/`0x91004000`/`0x98005000` →
   `0x91000080`/`0x90`/`0xa0`; `0x9a00a000` → `0x910000b0` with the pin bounded
   to <= 4), the row layout {base, bit, arg0, _, handler, arg1}, the
   ascending-bit service order and the trace record order (base then pending).
   See [analysis/MAIN_GPIO_DISPATCH.md](analysis/MAIN_GPIO_DISPATCH.md) and
   [analysis/main-gpio-dispatch.json](analysis/main-gpio-dispatch.json); the
   vectors, native report and evidence regenerate byte for byte. Ten new host
   checks join the suite. The registration that populates the callback table,
   the bulk pad applier at `0x80d42cfc` and the physical pin assignments remain
   open.

## 2026-11-19 — GPIO pull/drive pad writer and interrupt enable/commit

1. Extended the GPIO/pad controller with two more original bodies: the
   pull/drive pad writer `0x80d42fcc` (a 2-bit field per pin, four pins per
   32-bit register, bank table `0x80d4745c` → `0x91000100`/`0x120`/`0x140`,
   direct `0x91000160`) and the interrupt enable/commit routine `0x80d43774`,
   which walks the 16-row callback table at `0x80c118c8`, acknowledges each
   registered pin (`controller + 0x30`), reads gate/scheduler state and commits
   the enable on `controller + 0x20`/`0x2c` through a handshake on `0x900080b0`,
   wrapping the commit in a critical section only when the scheduler state is
   non-zero. All **13 cases pass in 895 steps**.
2. The gate `0x80d341d8`, the scheduler-state reader `0x80d362b0` and the
   critical save/restore wrappers `0x80d379ee`/`0x80d37a1a` are supplied
   sequential-return stubs (their own behavior is covered by MAIN_PM_WAKE and
   MAIN_RTOS_CRITICAL_SECTIONS); the handshake value is 2 when the gate returns
   non-zero, else 1. See
   [analysis/MAIN_GPIO_CONFIG.md](analysis/MAIN_GPIO_CONFIG.md) and
   [analysis/main-gpio-config.json](analysis/main-gpio-config.json); the
   vectors, native report and evidence regenerate byte for byte. Eleven new host
   checks join the suite. The routine that populates the callback table, the
   handshake responder on `0x900080b0` and the physical pin roles remain open.

## 2026-11-19 — GPIO interrupt registration and trigger mode

1. Executed the GPIO interrupt registration routine `0x80d43068`, completing the
   register/enable/dispatch chain. It converts the pin mask to a bit index with
   libgcc `__ctzsi2` (`0x7094514c`), inserts or updates the pin's row in the
   16-row callback table at `0x80c118c8` (layout {base +0, bit +4, arg0 +8,
   mode byte +0xc, handler +0x10, arg1 +0x14}), and programs the controller's
   trigger registers `+0x38`/`+0x34`/`+0x3c` for one of five modes before
   enabling the pin through the `0x900080b0` handshake. All **12 cases pass in
   2,475 steps**.
2. Recovered the five trigger-mode encodings, the in-place row update (no
   duplication), first-free-row placement, the full-table and invalid-mode error
   returns, and the conditional critical wrapping. The gate, scheduler-state
   reader and critical save/restore wrappers are supplied stubs. See
   [analysis/MAIN_GPIO_REGISTER.md](analysis/MAIN_GPIO_REGISTER.md) and
   [analysis/main-gpio-register.json](analysis/main-gpio-register.json); the
   vectors, native report and evidence regenerate byte for byte. Eleven new host
   checks join the suite. The edge/level meaning of the trigger bits, the pin
   registrants and the de-registration path remain open.

## 2026-11-19 — xTaskResumeAll scheduler unlock

Executed the original `xTaskResumeAll` (`0x80d3a720`) over authored kernel
state, reusing the task critical section, list primitives,
`xTaskIncrementTick` and `prvResetNextTaskUnblockTime` as guarded original code
(only `configASSERT`, the diagnostic body and `vPortYield` are stubs). **9 cases
pass in 1,593 steps**: decrement-only, unlock with no work/no tasks, pending-ready
drain at lower/higher/two priorities, pended-tick catch-up and deadline wake,
and the not-suspended assertion. See
[analysis/MAIN_SCHED_RESUME.md](analysis/MAIN_SCHED_RESUME.md) and
[analysis/main-sched-resume.json](analysis/main-sched-resume.json); vectors,
native report and evidence regenerate byte for byte. Eleven new host checks.
`vTaskSuspendAll` and the blocking APIs remain open.

## 2026-11-19 — vTaskDelay, suspend-all and delayed-list insertion

Executed the original `vTaskDelay` (`0x80d3a84c`) end to end, reusing
`vTaskSuspendAll` (`0x80d3969a`), `prvAddCurrentTaskToDelayedList` (`0x80d3927a`),
`vListInsert` (`0x80d37db4`), the list primitives and the whole of
`xTaskResumeAll` as guarded original code (only `configASSERT`, the diagnostic
body and `vPortYield` are stubs). **8 cases pass in 1,337 steps**: zero-tick
yield, move to the delayed list with `xNextTaskUnblockTime` update, ready-bit
clear/keep, ordered insertion before/after an existing sleeper, overflow-list
wrap without an unblock update, and the suspended-at-entry assertion. See
[analysis/MAIN_TASK_DELAY.md](analysis/MAIN_TASK_DELAY.md) and
[analysis/main-task-delay.json](analysis/main-task-delay.json); vectors, native
report and evidence regenerate byte for byte. Nine new host checks.
`xTaskDelayUntil`, event-list block/unblock (queues/semaphores) and task
deletion remain open.

## 2026-11-19 — vTaskDelete and prvDeleteTCB task deletion

1. Executed natively the original `vTaskDelete` (`0x80d3a45c`) and
   `prvDeleteTCB` (`0x80d3939c`) end to end, reusing `vTaskEnterCritical`,
   `vTaskExitCritical`, `uxListRemove`, `vListInsertEnd` and
   `prvResetNextTaskUnblockTime` as guarded original code. All **12 cases pass
   in 1,191 steps** over authored kernel state, TCBs and lists. `configASSERT`,
   the critical diagnostic body, `vPortYield`, newlib `_reclaim_reent` and
   `vPortFree` are supplied.
2. Results include:
   - `prvDeleteTCB` freeing by `ucStaticallyAllocated` (mode 0 frees stack then
     TCB, 1 frees the TCB, 2 frees nothing, else asserts at line `0x10b9`);
   - deleting another task removing it from its state and event lists, clearing
     the priority bit only when that ready list empties, decrementing
     `uxCurrentNumberOfTasks`, recomputing the next unblock time and freeing the
     TCB immediately;
   - deleting the running task appending it to the termination list and
     incrementing `uxDeletedTasksWaitingCleanUp`, deferring the free to the idle
     task, then yielding;
   - a self-delete asserting `uxSchedulerSuspended == 0` (line `0x516`);
   - no yield before the scheduler starts.

   See [analysis/MAIN_TASK_DELETION.md](analysis/MAIN_TASK_DELETION.md) and
   [analysis/main-task-deletion.json](analysis/main-task-deletion.json); the
   vectors, native report and evidence regenerate byte for byte. Ten new host
   checks join the suite. The idle-task termination sweep, the actual heap free
   and live rescheduling after a yield remain open.

## 2026-11-19 — eTaskGetState, uxTaskPriorityGet and vTaskPrioritySet

1. Executed natively the original `eTaskGetState` (`0x80d3a55e`),
   `uxTaskPriorityGet` (`0x80d3a5f4`) and `vTaskPrioritySet` (`0x80d3a61c`),
   reusing `vTaskEnterCritical`, `vTaskExitCritical`, `uxListRemove` and
   `vListInsertEnd` as guarded original code; `vTaskPrioritySet` tail calls the
   original `vTaskExitCritical`. All **19 cases pass in 1,692 steps** over
   authored kernel state, TCBs and lists. `configASSERT`, the critical
   diagnostic body and `vPortYield` are supplied; here the yield returns so the
   priority change completes.
2. Results include:
   - `eTaskGetState` mapping each state list to its code (running 0, ready 1,
     blocked 2, suspended 3, deleted 4), and reporting a suspended task that is
     still waiting on an event or a notification as blocked;
   - `vTaskPrioritySet` clamping above 9 with an assert, reordering the ready
     list, preserving a mutex-inherited active priority, rewriting the unmarked
     event-list value to `10 - newPriority`, and yielding only when a lower
     self-priority or a raised peer reaches the current priority.

   See [analysis/MAIN_TASK_QUERY.md](analysis/MAIN_TASK_QUERY.md) and
   [analysis/main-task-query.json](analysis/main-task-query.json); the vectors,
   native report and evidence regenerate byte for byte. Fourteen new host checks
   join the suite. vTaskSuspend/Resume, mutex inheritance and the queue/
   semaphore/event-group/notification APIs remain open.

## 2026-11-19 — bootloader main-firmware signature gate and handoff

1. Executed the original bootloader boot decision `0x80c00918` and firmware
   loader `0x80c00876` end to end in the `boot-runtime` project, supplying the
   file-system leaves, the signature verifier `0x80c0e2b6` and the image handoff
   `0x80c0084a` as stubs. All **10 cases pass in 460 steps**. This upgrades the
   boot-chain control flow from static reading to bounded execution.
2. Established by execution that the main firmware at `0x70160000` is entered
   **only** when the loader returns success, which happens **only** when the
   signature verifier returns nonzero. A failed verification logs
   `firmware secure verify failed!!!` and `load firmware failed!!!`; an oversize
   image (> `0xe00000`) is rejected before open/verify; a failed open or short
   read skips verification. None of these jump into the loaded bytes.
3. Supplying a passing verifier result is not a bypass: a nonzero result on the
   device still requires a signature valid under the embedded key. The verifier
   internals are already executed for the recovery image in
   [analysis/RECOVERY_VALIDATOR_NATIVE.md](analysis/RECOVERY_VALIDATOR_NATIVE.md).

   See [analysis/MAIN_BOOT_GATE.md](analysis/MAIN_BOOT_GATE.md) and
   [analysis/main-boot-gate.json](analysis/main-boot-gate.json); the vectors,
   native report and evidence regenerate byte for byte. Ten new host checks join
   the suite. A safe boot attempt still requires a verified physical flash
   backup, a tested recovery-entry/restore guarantee and confirmation of
   device-side enforcement — none obtainable offline.

## 2026-11-19 — bootloader recovery-entry gate and boot manager decision

1. Executed the original recovery-entry detector `0x80c00312` end to end in the
   `boot-runtime` project, supplying the boot-reason reader, power check, key
   poll and delay as stubs (a new `store` stub kind writes the scripted button
   states and the power flag into the quiet stack). All **8 cases pass in 1,758
   steps**; the independent model reproduces every call and the return value.
2. Established the recovery-entry conditions: boot reason not 3 or 6, external
   power present, and two keys (poll indices 0 and 1) held together through a
   release wait, a 20-poll both-pressed window and a 20-poll confirmation
   window. Reasons 3/6 skip power and keys; no power skips the keys.
3. Read the boot manager `0x80c00454` statically: it enters recovery only via
   the detector or a pre-written `upgrade` record (state 2), and then
   **unconditionally calls the main-firmware boot `0x80c00918` as its last
   step**. Because the main boot returns on a signature failure (it never jumps
   into unverified bytes), a failed main verification does not fall through to
   recovery — recovery must be requested earlier.

   With no USB/wired port (BLE bridge only), the two-key-plus-power gesture and
   the `upgrade`-record path are therefore the only recovery entries. See
   [analysis/MAIN_RECOVERY_GATE.md](analysis/MAIN_RECOVERY_GATE.md) and
   [analysis/main-recovery-gate.json](analysis/main-recovery-gate.json); the
   vectors, native report and evidence regenerate byte for byte. Eight new host
   checks join the suite. The physical key mapping, the power threshold and a
   demonstrably recoverable over-the-air restore remain open and need the device.

## 2026-11-19 — ICNA3311 display panel DCS read-id, probe and command player

1. Identified the display as a Chipone **ICNA3311 AMOLED** over MIPI DCS
   (strings `drv_display_init`, `icna3311_probe_success`, `icna3311_read_38_gamma`).
   Executed three original main-image bodies in `main-runtime`: the DCS read-id
   `0x702c8238`, the panel probe `0x702c82d8` and the command-table player
   `0x702c8314`. All **9 cases pass in 565 steps**; a `transfer` stub captures
   the command bytes the code emits and injects scripted responses, so the DCS
   framing is verified.
2. Recovered contracts:
   - read-id issues DCS `0xDA/0xDB/0xDC` (RDID1/2/3) and accumulates a 24-bit id;
   - the probe matches that id against nine embedded ICNA3311 variant ids
     (`0x250905`,`0x5a0905`,`0x250906`,`0x1b0909`,`0x4b090d`,`0x5c0913`,
     `0x5b0913`,`0x250914`,`0x2c0914`);
   - the command-table player walks `{type, nargs, payload}` entries, issuing a
     DCS write (type 0, device op `+0xc`) or a `delay(ms)` (type 1), advancing
     `nargs + 2`; a null table or zero length returns `0xfffffff6`.

   The DCS read op is at device `+0x10`, write at `+0xc`, behind handle
   `0x70f8e694`. See [analysis/MAIN_DISPLAY_PANEL.md](analysis/MAIN_DISPLAY_PANEL.md)
   and [analysis/main-display-panel.json](analysis/main-display-panel.json); the
   vectors, native report and evidence regenerate byte for byte. Ten new host
   checks join the suite. This is a driver contract; the rail/reset bring-up
   (`0x702c8c70`), the real init tables, the framebuffer/refresh path, backlight
   and panel timing remain open and need the device.

## 2026-11-19 — ICNA3311 display bring-up and real panel init tables

1. Executed the display power/reset bring-up `0x702c8ae2` and the DCS
   command-table player `0x702c8314` over the **real** ICNA3311 init table from
   a firmware panel descriptor. Both **2 cases pass**; the write stub captures
   the real init bytes, so the init DCS stream is verified.
2. Bring-up sequence: enable 1.8 V rail, 5 ms, enable 3.3 V rail, configure bus,
   reset low, 12 ms, reset high, 12 ms. The real 416×416 init (variant
   `0x1b0909`) issues 25 DCS writes including `35 00` tear-on, `51 ff` max
   brightness, `3a 55` RGB565, `2a 00 12 01 b1` / `2b 00 00 01 9f` (416×416
   window) and the ICNA3311 page-select writes.
3. Decoded all nine embedded variant init tables and their geometry (192×490,
   416×416, 390×450); the device runs one, read at runtime by the panel probe.

   See [analysis/MAIN_DISPLAY_INIT.md](analysis/MAIN_DISPLAY_INIT.md) and
   [analysis/main-display-init.json](analysis/main-display-init.json); vectors,
   native report and evidence regenerate byte for byte. Seven new host checks
   join the suite. Sleep-out/display-on sequencing, the framebuffer/refresh path
   and backlight runtime control remain open and need the device.

## 2026-11-20 — sensor-hub LSM6DSO probe, reset and SPI register framing

1. Executed every original sensor-hub body from the LSM6DSO init/probe
   `0x80f71cb2` down to the SPI read/write callbacks `0x80f6fafa`/`0x80f6fb60`
   in the `sensor-runtime` project. All **12 native cases pass** (5,689 steps).
   Only the SPI transfer helper `0x80f898ae`, memcpy, the delay and the logger
   are supplied. A new `spi` stub captures the transmitted bytes and injects
   scripted receive bytes and statuses.
2. The layer matches ST's public `lsm6dso_reg.c`: the register context
   `0x80fd876c` is `{write_reg, read_reg, handle}`. Reset is a read-modify-write
   of `CTRL3_C` (`0x12`) bit 0, polled up to ten times 1 ms apart. The identity
   read is register `0x0F`, accepted only as `0x6C`, with three attempts 10 ms
   apart (result 0/1/4).
3. Captured SPI framing: a read sends `reg | 0x80` plus dummy bytes (`n + 1`
   bytes, data from `rx[1..]`). A write sends `reg, data[0]`. Both use timeout
   5000. A failed WHO_AM_I read leaves the probe buffer unchanged, so the cached
   id is stale. A failed reset-poll read uses an uninitialized stack byte, and
   the vectors do not exercise it.

   See [analysis/SENSORHUB_IMU_PROBE.md](analysis/SENSORHUB_IMU_PROBE.md) and
   [analysis/sensorhub-imu-probe.json](analysis/sensorhub-imu-probe.json). The
   vectors, native report and evidence regenerate byte for byte, and nine new
   host checks join the suite. Still open: the caller `0x80f726ee` (bus handle,
   chip select, SPI mode/clock, interrupt setup), the transfer helper/controller,
   post-identity configuration and the data path. These need further work or the
   device.

## 2026-11-20 — sensor-hub LSM6DSO attach and hub board records

1. Executed the LSM6DSO attach routine `0x80f726ee` end to end, including the
   original probe chain and the `INTERNAL_FREQ_FINE` accessor, over the real
   `dev_lsm6dso` board record. All **11 native cases pass** (4,308 steps).
   Results: 0 attached, 1 probe failure, 4 missing board record or SPI handle,
   10 cache allocation failure. GPIO failures are only logged.
2. Decoded the hub board-record table registered at `0x80f6257c` from its
   `auipc`/`addi` pairs:
   - board `Pamir` 1.0.0;
   - LSM6DSO and an alternative BMI2xx on `sens_spi1_dev0`, IRQ pin 43, mode 4;
   - AK09918/MMC5603 magnetometers on `sens_i2c2`;
   - MAX8617x on `sens_spi0_dev0` with rails `PPG_1V8`/`PPG_VLED`, pin 39.
3. The SPI device is configured at 8 MHz (`{8000000, 0x807, 0, 0, 0}`
   captured). A 0x605-byte `drivers_sensor` cache is published. The trimmed
   26 Hz ODR `6667 × (1 + 0.0015 × fine) / 256` is stored as binary32. The
   interrupt is installed on pin 43 with handler `0x80f701ba` and left disabled.
   Accelerometer and gyroscope descriptors are then registered.
4. Found and documented a Ghidra RV32 SLEIGH artifact: `c.fsw` stores 8 bytes
   (the full FLEN=64 register) instead of 4. The computed value was checked to
   be the correct IEEE binary32.

   See [analysis/SENSORHUB_IMU_INIT.md](analysis/SENSORHUB_IMU_INIT.md) and
   [analysis/sensorhub-imu-init.json](analysis/sensorhub-imu-init.json). The
   vectors, native report and evidence regenerate byte for byte, and the probe
   report is unchanged under the extended runner.

## 2026-11-20 — sensor-hub LSM6DSO register accessor sweep

1. Executed every accessor in the hub LSM6DSO register block
   `0x80f7291a`–`0x80f72e86` in isolation, through the original context
   dispatch and SPI callbacks. All **95 native cases pass** (7,561 steps). The
   26 accessors match ST `lsm6dso_reg.c` by register and bit field: full scale,
   ODR fields, BDU, power modes, reset/boot, gyro LPF1, I3C disable, FIFO batch
   and mode, FIFO level and overrun, data-ready flags, raw 6-byte output reads
   and the ODR trim.
2. Observed behaviour:
   - masked read-modify-write; a failed read skips the write;
   - unmasked `val << n` in the ODR, boot and gyro power-mode writers;
   - getters store stale stack bytes after a failed read (not exercised);
   - raw reads use the full 7-byte callback buffer.

   The sweep also confirms the AndeStar `bfoz` insert/extract semantics. See
   [analysis/SENSORHUB_IMU_REGS.md](analysis/SENSORHUB_IMU_REGS.md) and
   [analysis/sensorhub-imu-regs.json](analysis/sensorhub-imu-regs.json). The
   vectors, native report and evidence regenerate byte for byte.

## 2026-11-20 — sensor-hub LSM6DSO enable/disable configuration

1. Executed the mode setter `0x80f70da2` with all its callees real:
   configuration, rate, ODR event, register dump, every register accessor and
   the SPI callbacks. All **26 native cases pass** (51,920 steps). Each case
   starts from the original image values of the globals.
2. Gyroscope enable:
   - reset, I3C, high performance, BDU;
   - ±8 g and 2000 dps;
   - gyroscope LPF1 bandwidth 7 with high performance;
   - FIFO batch and ODR code 2–7 for 26–833 Hz (other rates → 2);
   - continuous FIFO;
   - event `{0x103, ODR × 100}` (2604 for 26.04 Hz).
3. Accelerometer-only power follows the selector `0x80f16b1c`: ultra-low power
   for 0, high performance for 2, low/normal otherwise. Disable sets both ODR
   fields to 0.
4. The embedded-function programs (two 380-pair ST UCF FSM programs, selector
   5 or 6) are identified and hashed but not executed or redistributed. The
   image default selector 8 is invalid and is cleared.
5. Found a second Ghidra SLEIGH defect: `fcvt.wu.s` drops its `rd` write. The
   runner repairs only the reviewed site and records each repair. Both FP
   defects are noted in [analysis/NATIVE_REPAIR.md](analysis/NATIVE_REPAIR.md).
   The runner now takes its step bound from the vectors, and earlier scopes
   regenerate byte for byte.

   See [analysis/SENSORHUB_IMU_MODE.md](analysis/SENSORHUB_IMU_MODE.md) and
   [analysis/sensorhub-imu-mode.json](analysis/sensorhub-imu-mode.json).

## Next work

- Sensor-hub IMU: execute the FIFO read/decode path `0x80f710ac`. It checks
  overrun and level, makes one bulk SPI read of `7 × n + 1` bytes through the
  transfer helper (tagged 7-byte FIFO words, at most 160 per pass) and then
  runs the decoder, timestamp and packet path (`0x80f6fc42`, `0x80f6453e`,
  `0x80f63092`, `0x80f64660`). Then do the descriptor callbacks
  (open/close/rate/flush) that call the now-executed mode setter, and the
  handling of IRQ event `0x101`. See
  [analysis/SENSORHUB_IMU_MODE.md](analysis/SENSORHUB_IMU_MODE.md).

- Main kernel: execute `vTaskSuspend`/`vTaskResume`, the idle-task termination
  sweep, dynamic `xTaskCreate`, mutex priority inheritance and the queue/
  semaphore/event-group/notification APIs. `vTaskDelete`/`prvDeleteTCB`,
  `vTaskDelay` and task state/priority query now execute; see
  [analysis/MAIN_TASK_QUERY.md](analysis/MAIN_TASK_QUERY.md),
  [analysis/MAIN_TASK_DELETION.md](analysis/MAIN_TASK_DELETION.md) and
  [analysis/MAIN_TASK_DELAY.md](analysis/MAIN_TASK_DELAY.md).
- Main interrupts: recover the remaining device interrupt handlers (the
  zero-argument sources and the shared `0x70293d50`), execute the deep-sleep
  save/`wfi`/resume twins on hardware, and validate preemption/nesting and
  timer frequency. The power-management wake gate, dynamic re-registration and
  wake body now execute; see [analysis/MAIN_PM_WAKE.md](analysis/MAIN_PM_WAKE.md)
  and [analysis/MAIN_TRAP_IRQ_DISPATCH.md](analysis/MAIN_TRAP_IRQ_DISPATCH.md).
- Keep the standalone boot/backup/recovery feasibility gate a priority alongside
  native subsystem work: the signed boot chain and device-specific restoration
  remain unresolved and cannot be closed by additional HR test counts alone.
  The main-firmware boot gate now executes: the loader enters `0x70160000`
  only on a positive signature verification, and failures/oversize never jump
  into the image; see [analysis/MAIN_BOOT_GATE.md](analysis/MAIN_BOOT_GATE.md).
  The caller `0x80c00454` now shows the main boot is the unconditional final
  step and a failed verification does not auto-enter recovery; recovery is
  gated by the executed two-key-plus-power detector `0x80c00312` or a
  pre-written `upgrade` record. With no USB (BLE-only bridge), those are the
  only recovery entries; see
  [analysis/MAIN_RECOVERY_GATE.md](analysis/MAIN_RECOVERY_GATE.md). Next:
  execute the full boot manager and establish a recoverable OTA restore.
  Selected boot validation, selection, header/counter preparation/completion and
  stopped handoff now execute with supplied board/storage/crypto/BSP services.
  Environment wrappers, cached reason/key policy and the stopped upgrade-record
  caller prefix now execute too. Native environment append/delete, CRC, cached
  lookup/parsing and connected get/set now run with supplied low-level storage.
  Light sector traversal, empty-cache record filters and reservation/maintenance/
  retry policy now execute too. Actual detailed space/record/tail parsing and
  sector-end cache updates now run, including connected reservation after an
  integrity error. Relocation/collection/reformat/default restore, connected
  environment initialization, callbacks, table/readiness binding and dump/reserve
  copying now execute over synthetic services too. Named registry validation,
  handle setup, NVMS mirror repair/rewrite fallback and clean bootstrap now
  execute as well; the ROM table publishes `boots=0`. The original five-backend,
  16-partition configuration and callback bindings are now recovered statically.
  Registry/device population, lazy EFTL descriptor arithmetic and EFTL logical
  translation/page dispatch now execute with supplied lower services. Actual
  QSPI platform initialization/transfer, selected feature/cache/program/erase
  command builders, ROM-version policy and busy deadlines now execute with
  supplied HAL/pin/DMA services and emulated MMIO. Selected actual RAM QSPI HAL
  init/command/direct-FIFO/DMA-wrapper and phase/count/status/clock routines now
  execute too, with supplied timer/DMA internals and authored MMIO. Selected NAND
  feature/cache/write-enable builders connect through actual bus/HAL to the FIFO.
  Actual DMA init/setup/wait/cancel/count/IRQ now execute in a separate guarded
  pass with authored MMIO/cache/timer/callback services. Wait status branches
  differ in tracking cleanup despite both returning zero. Actual QSPI wrappers
  now connect to actual DMA init/setup/wait, including the selected NAND private-
  buffer bus path, with authored statuses/cache/copy services. Each wait retains
  its full timeout budget. Selected full NAND bus initialization now executes
  actual grouped/table-driven pin controls, clock/QSPI/DMA initialization and
  original adjacent descriptor linking, including bus-triggered reinitialization
  followed by transfer. Actual page read now connects BBT remapping, load/status/
  cache builders, busy loops, direct FIFO and private DMA; full timeout and ECC
  failure behavior execute across these layers. Actual program now connects BBT,
  guard, enable/cache/program/status builders and FIFO/DMA too, including complete
  busy timeouts and wrapping column arithmetic. Actual erase/copy/OOB now connect
  both busy loops and original builders through the bus and polling HAL too.
  Source-copy timeout can still return success; destination/erase timeouts fail.
  Supported-family retry/setter/reset checks, page-read recovery and UID/selected
  export now connect through actual bus/HAL/FIFO too, including full timeout and
  stale state cases. Original partition/callback/context/mutex wrappers, ready EFTL
  translation/page/OOB reads and selected registered storage API bounds/read now
  connect through the same lower stack. Follow broader callers/partitions, registry
  and map reconstruction. Selected upper program/logical erase/rewrite now connect
  full-page/OOB staging, original free-block selection and NAND/QSPI/TX DMA too;
  rewrite aliases program and flag updates precede lower assertions. Enabled
  readback, actual bad marking and zero-prefix relocation now connect too; prefix
  allocation failure executes to its original assert. Selected one/two-page
  prefix copying, temporary-buffer lifetime and recursive relocation now execute
  too. Selected combined enabled-readback, repeated outer relocation and scratch
  OOB reuse now execute too. Follow larger migrations, further readback/repair
  branches and complete repair atomicity. The original map scanner now also
  connects three-page bad-marker checking, erase and OOB extraction through
  NAND/BBT/QSPI; duplicate retention and partial scan results are covered with
  authored FIFO records. The selected full initializer/lookup/geometry/format/
  scan/retry and lazy readiness now connect through the lower stack too, over an
  authored eight-block partition and supplied heap/clock services. Follow broader
  registry/probe/BBT startup, distinct heap generations on repeated failures,
  persistent write/retire/reboot reconstruction,
  BBT provenance,
  concurrency and remaining ECC/board integration, physical pin
  mapping, real DMA/IRQ/cache coherency and remaining board services,
  physical retry/UID, BBT provenance/creation and physical ID/geometry
  corroboration. Original candidate matching/probe and driver-root setup now
  execute with supplied services; candidate platform/ID/reset/feature paths now
  also connect through actual QSPI/FIFO for all eleven original descriptors.
  The selected first-chip probe now also joins actual BBT recovery and the
  unsupported-family workaround branch, including real no-table/repair-error
  results. Original UID acquisition and later ioctl export now also join this
  path; actual supported-family reset/E0-level/UID joins candidate 3 with its
  BBT still supplied. Follow wider BBT geometry, initial BBT creation and broader
  startup. Selected root/property/callback/probe/UID/BBT/object registration now
  also connects, including actual lookup/list insertion and retained allocation
  after duplicate rejection. Original object open/reference/ioctl policy and
  post-root NAND geometry/context/BBT consumers now also execute. Main-image
  generic close/reference/write/ioctl and original NAND method consumers now
  execute too. Original main context/chip/BBT-active geometry now also executes,
  with authored selected-descriptor/magic and RTOS state. Main root/wrapper/registry/
  cache/PM publication now joins it with PM/BSP/heap services supplied. Actual
  main probe/matcher/ID/reset builders now also join it over all eleven original
  candidates. Actual main bus/platform/feature packet conversion now also joins
  this path over all eleven descriptors, with HAL/revision/regulator/DMA services
  and auxiliary bodies supplied. Actual main command/FIFO/count/timer/clock/
  revision and DMA wrappers now also execute separately, and original main bus/
  feature packets join them over an authored initialized controller. Follow
  actual main asynchronous/private DMA and nonblocking scheduling, further
  UID/media consumers and alternate chip geometries. Selected full 2000/4000-
  poll read/repair busy limits now execute through actual status FIFO, including
  last-poll ready/ECC discard and ordinary outer recovery after handled errors. Main BBT recovery record/
  reread calls, original three-page marker checks and actual repair erase/program
  now execute through original builders/status and direct QSPI RX/TX FIFO. The
  exact 140-byte backup payload is transmitted without a primary readback; real
  persistence and repair atomicity remain open.
  Actual main block/page remapping now consumes recovered BBT state, and later
  direct page reads execute load/status/x4-cache/FIFO with per-operation state.
  Main BBT verifier/resume/CRC joins the connected repair path; actual context UID
  export also executes, including copied output before mutex release assertion.
  Actual main workaround/reset/level and UID feature/load/
  busy/cache/complement checks now join it, including retained state after UID
  failures and outer probe success without valid acquisition.
  Original main candidate probe/root now joins actual platform/clock/QSPI FIFO/
  revision/DMA initialization and object consumers over all eleven unchanged
  descriptors, including all 33 attempts and actual timeout assertions. DMA
  setup/wait remains separately covered for bounce transfers. Main pin/GPIO
  services, production cache/DMA consumers and live IRQ delivery remain open.
  Main mode-zero reads now connect original private-buffer DMA setup/wait after
  BBT recovery, and mode-zero erase connects original sleep-based polling and
  published guards. DMA data movement and actual scheduling remain unmodeled.
  Main mode-zero program now connects original initialized TX DMA, source staging
  and execute/status with recovered mapping/guards too. Original main IRQ dispatch
  now executes with supplied callbacks and authored pending/registry state;
  original signed cache guards execute inside backend/IRQ and full NAND DMA.
  Original positive-address CSR loops and critical/context/diagnostic bodies now
  execute over explicit register feedback and authored RTOS/thread state too.
  Actual interrupt delivery and physical coherency remain unproved. Follow further main
  UID/BBT consumers and IRQ/events,
  wider storage and PM callers,
  broader close callers, removal/reclamation/concurrency and real property/heap/
  mutex services. Actual retry/
  UID setup/acquisition and UID ioctl export now execute through actual command
  builders and busy loops over a supplied bus. Setter retry exhaustion can return
  zero, and UID ioctl can export prior state after early acquisition errors.
  Physical correction/UID provenance and remaining consumers are open. BBT verifier/resume and block/page remapping now execute with actual CRC
  and supplied storage. Backup repair errors can leave an active RAM table while
  returning zero. Actual remappers also connect to page/program/copy/OOB/erase
  and busy loops over an authored immutable BBT. Actual NAND
  lookup/ioctl/read dispatch, descriptor-backed geometry collection and OOB
  extraction/composition now execute. The selected complete allocation/
  geometry/reset/scan/retry initializer, generic format loops and connected lazy
  publication now execute too, with lower services supplied. Actual page read/
  program/copy/copy-with-OOB/erase now also connect actual BBT remapping, builders,
  busy loops, platform, bus and HAL over authored peripheral inputs; read/source-
  copy timeout can reach success while program/erase reject ff status. Follow lower NAND
  page/ECC/bus transport and physical metadata provenance, alternate format
  handling, remaining
  mapping repair/program/erase paths, SFTL and the concrete physical partition
  map, actual driver callback behavior and rewrite/mutex constraints,
  reserve-image provenance and other factory data,
  broader malformed/stale-cache/concurrency/boundary-read paths,
  real persistence and subsequent boot/recovery/UI
  dispatch, physical reason/gesture behavior, VFS/raw storage/base-address/
  write-atomicity and startup dependencies. Establish a
  physical non-destructive entry/backup/restoration route before device writes.

- Regenerate selected native paths with startup-aware mappings, corrected
  logger return behavior and register-save ABI effects. Current pseudocode
  counts must not be treated as semantic coverage.
- Follow the complete MAX8617X mode/consumer/calibration paths and the health
  IPC pipeline; the selected FIFO fault/recovery/cache primitives, coordinated
  flush, packet allocation/rebinding and mode-1 consumer now have bounded
  native coverage; selected reference/free-call, listener/cache queue and
  mode-2/3 paths now have coverage too. Follow normalized driver reads,
  remaining cache listener registration/application consumers, actual engine
  activation/mask transitions, event scheduling/cleanup and transport beyond
  the now-covered opcode-21 send and main/sensor receive boundaries. Selected
  main registration, retained engine-cache event, engine fanout and engine-7
  non-type-1 HR result handling now have bounded native coverage. Follow real
  algorithm-0x100d initializer 0x708a4818 and other secondary allocation failures,
  supported signal normalization/math and extension
  consumers beyond the now-covered outer allocation/free/restart and borrowed
  view builder. Selected actual setup/component allocation/reset and nested
  cleanup now execute too. Registration/lifetime/dispatch adapters, configuration
  copying and selected guards are covered. Follow motion/minute/reset/wear branches, other
  modes, fusion, malformed input and concurrency paths.
  Validate electrical SPI mode/timing, DMA ownership and live
  sensor operation before implementing hardware code. The selected adapter's
  flag/divider/polling arithmetic and bus/completion/reference contracts are
  now recorded; generic DMA behavior does not prove a configured optical DMA path.
- Audit remaining BBS/volatile-affected exports beyond the selected IPC paths.
  Establish physical timer frequency/continuity across power states and shared-memory attributes/coherency;
  extend guarded DSP support only as required by selected paths. Validate live IRQ/wake/endpoint/
  vring operation and observe exact-multiple fragment behavior.

- Follow population of the capability table and the deeper heart/SpO2 service
  backends; distinguish software records from live hardware measurements.

- Follow the now-reproducible native initializer callbacks to associate nested
  constants and class prototypes with their modules, especially sensor classes
  and BLE callbacks; see the latest report for the 12 callback addresses.

- Map the signed image formats and the loaders for the sensor hub and radio;
  distinguish host-side mathematical signature checks from device behavior.
- Identify the PPG/heart-rate analog front end and the exact SoC silicon, buses
  and memory layout with corroborating evidence beyond driver-name strings.
- Research and validate a non-destructive boot/debug and recovery path, including
  a backup of device-specific data, before considering hardware writes.
- Define the Android/watch transport, authentication and notification/navigation
  contracts, and test them on host and emulator before connecting a watch.
- Follow the native authentication provider/session setup and registered
  callbacks to recover pairing/key provisioning and counter lifecycle; connect
  native module payloads to JS framing before claiming an end-to-end protocol.
- Follow call/audio backends beyond the now-matched application descriptors;
  distinguish map download from the still-unverified Roadstr navigation contract.
- Observe notification rendering and validate a permitted Roadstr handoff.
  The selected legacy listener/store path now reaches a screen request; special
  storage-class/rich/sticky paths and complete UI policy remain open. Reverse
  action serializers are recovered; executing replies/call actions is untested.
