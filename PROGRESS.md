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

## Next work

- Regenerate selected native paths with startup-aware mappings, corrected
  logger return behavior and register-save ABI effects. Current pseudocode
  counts must not be treated as semantic coverage.
- Follow MAX8617X initialization/FIFO paths, interrupt handling and the health
  IPC pipeline; verify HAL flags and timing before implementing hardware code.

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
