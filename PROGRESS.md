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

## Next work

- Regenerate selected native paths with startup-aware mappings, corrected
  logger return behavior and register-save ABI effects. Current pseudocode
  counts must not be treated as semantic coverage.
- Follow MAX8617X initialization/FIFO paths, interrupt handling and the health
  IPC pipeline; validate electrical SPI mode/timing, DMA ownership and live
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
