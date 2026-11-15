# Decompilation scope and remaining work

The current investigation operates on the Bip 6 OTA 4.6.0.3 archive, not a
complete physical flash dump. `ota-workload.json` inventories every top-level
member by extension and records hashes of binary members, JavaScript and
nested ZIPs. Filename extensions and literal headers are classifications,
not executable-format validation.

## Local native corpus

The batch workflow imports six candidate RISC-V images using Ghidra's AndeStar
v5 profile and exports inferred function bodies to `firmware/decompiled/`:
bootloader payload, recovery, sensor hub, factory firmware, main firmware and
the ramdump diagnostic executable. Each folder has a `functions.tsv` index
with individual decompiler status. Both the exported vendor-derived code and
the Ghidra databases remain local under ignored firmware/.

`decompilation-summary.json` records the recognized functions and the number
for which the decompiler emitted output, as well as warning/comment counts.
These numbers measure the inferred function set, not coverage of all bytes,
correctness, or understanding of every function. The main image initially hit
its 300-second analysis budget; that first export is retained separately as
`main-initial`, and a continuation uses the saved project with a larger budget.

Reproduce the batch in a fresh project directory with:

```sh
python3 analysis_scripts/decompile_ota.py --ghidra /absolute/path/to/analyzeHeadless
python3 analysis_scripts/summarize_decompilation.py > analysis/decompilation-summary.json
```

The script prepares its local inputs directly from the OTA. Candidate mapping
assumptions are recorded in the script. Physical placement, relocated sections,
external ROM functions and device-specific data still need corroboration.

## Export results

The completed seven-target pass recognized 54,804 functions and emitted
pseudocode for 54,794. Ten functions did not complete. Many emitted functions
also carry warnings, so these counts do not establish semantic correctness.

| Target | Recognized | Pseudocode emitted | Functions with warning comments |
| --- | ---: | ---: | ---: |
| boot | 1221 | 1221 | 401 |
| recovery | 1568 | 1568 | 534 |
| sensor | 2593 | 2593 | 981 |
| factory | 9843 | 9840 | 3296 |
| main | 31394 | 31387 | 16691 |
| ramdump | 1106 | 1106 | 339 |
| radio | 7079 | 7079 | 433 |

The main continuation completed analysis without timeout. Its inferred function
set differs from the preliminary export because further analysis changes function
boundaries and merges or removes candidates. Both runs remain local.

## Other payloads

The OTA includes 11 readable JavaScript members, a RIFF/GAPP application
container, a radio package carved into 15 candidate images and given a separate experimental
ARM Thumb analysis (see RADIO_NATIVE.md), a GNSS image
whose prefix reads `AG3352B_V3.1.0_20250120,S,H`, touch-firmware candidates,
models and other opaque binary resources. These have not all been decompiled.
The RIFF declaration in Application.bin does not account for all trailing
bytes; standard RIFF chunk walking also encounters an unexplained boundary.
A speculative parser would not establish the app format.

The remaining work therefore includes identifying those executable/bytecode
formats and their mappings, validating the native function boundaries and
signatures, resolving indirect calls and external routines, and turning
selected hardware paths into independently tested drivers. No complete dump
decompilation, boot unlock or functional device port is claimed.

The readable `META/js_apps/framework.js` declares device-runtime-core version
`v4.2.0-release.1`, API level 4.2. Its SHA-256 is recorded in ota-workload.json.
A fuller static pass over this runtime now maps the whole native ABI surface it
calls (`hmApp`, `hmUI`, `hmFS`, `hmSetting`, `hmSensor`, `hmBle`, `hmMedia`), the
`device:os.*` permission namespaces, the 37-method BLE master-role surface, and
the 16-byte framed message-protocol header used above `ble.send`. See
[JS_RUNTIME_API.md](JS_RUNTIME_API.md) and
[js-runtime-api.json](js-runtime-api.json). This is the shipped JavaScript API
and its wire framing, not the native implementations behind each method or a
standalone transport. The framework and watchface sources remain local in the
original archive.

## Finding reports

| Area | Report |
| --- | --- |
| CPU decoding and inferred control flow | [INSTRUCTION_PROFILE.md](INSTRUCTION_PROFILE.md) |
| Whole-archive signature and recovery reference | [OTA_ARCHIVE_SIGNATURE.md](OTA_ARCHIVE_SIGNATURE.md) |
| Image loading and sensor-hub header | [PERIPHERAL_LOADING.md](PERIPHERAL_LOADING.md) |
| Motion sensor, integrity routines and transport | [DRIVER_INTERFACES.md](DRIVER_INTERFACES.md) |
| Touch probe and radio serial abstraction | [TOUCH_AND_SERIAL.md](TOUCH_AND_SERIAL.md) |
| Radio package, transfer loop and checksum | [RADIO_PACKAGE.md](RADIO_PACKAGE.md) |
| Candidate ARM mapping of radio images | [RADIO_NATIVE.md](RADIO_NATIVE.md) |
| Application container and packaged JS bytecode | [APP_FORMATS.md](APP_FORMATS.md) |
| JS runtime native ABI and BLE application protocol | [JS_RUNTIME_API.md](JS_RUNTIME_API.md) |
| GATT identifiers and the notification contract | [BLE_IDENTIFIERS.md](BLE_IDENTIFIERS.md) |
| SoC subsystem architecture from symbol families | [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md) |
| Candidate hardware profile and health metrics | [HARDWARE_PROFILE.md](HARDWARE_PROFILE.md) |
| App-loading contract and lifecycle model | [APP_MODEL.md](APP_MODEL.md) |
| Embedded JS engine release (QuickJS 2020-07-05) | [QUICKJS_ENGINE.md](QUICKJS_ENGINE.md) |
| App bytecode read and disassembly, free variables, `@zos/` modules | [APP_BYTECODE.md](APP_BYTECODE.md) |

A concrete quality check found truncated control flow in some bulk exports
around calls inferred as non-returning. Targeted noanalysis imports restore
normal returns in the display ID and ambient-light paths. See
[DISPLAY_AND_LIGHT.md](DISPLAY_AND_LIGHT.md) for that comparison and the
additional candidate register observations. Bulk completion counts must not be
used as a claim that every function has been reconstructed correctly.
