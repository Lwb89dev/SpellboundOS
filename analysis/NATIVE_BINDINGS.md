# Native JS binding tables: from `hm*` methods to C function addresses

Static investigation on 2026-11-15 of `META/firmware_sign.bin` (SHA-256
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`) in the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The tool is
`analysis_scripts/js_cfunction_tables.py`; its output is
[js-cfunction-tables.json](js-cfunction-tables.json). The tool reads data
tables and existing local Ghidra exports. Nothing was executed.

## Result

The native objects behind `hmUI`, `hmApp`, `hmBle` and the others are QuickJS C
modules. Their properties are stored in the firmware as QuickJS
`JSCFunctionListEntry` tables, so every native method has a name, an arity and
the address of the C function that implements it.

| Measure | Value |
| --- | ---: |
| Runs of well-formed entries found | 86 (2,126 entries) |
| Tables after splitting | 168 |
| Tables with an exact length from a call site | 43 |
| Tables with an exact length from a parent entry | 60 |
| Function entries | 704, on 508 distinct C functions |
| Getter/setter entries | 131 |
| Integer constants | 1,204 |

Of the 508 function addresses, 437 already have a decompiled export in the
local Ghidra corpus. 46 of the tables belong to the QuickJS standard library
(`Math`, `Reflect`, `Promise`, `Date` and so on, around `0x70cdc000`). They
were not filtered out, because they confirm that the scanner finds real tables.

## Table format

An entry is 16 bytes on this 32-bit target and tables are 8-byte aligned:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | pointer to the property name |
| 4 | 1 | property flags (configurable, writable, enumerable) |
| 5 | 1 | definition type: 0 function, 1 getter/setter, 2 getter/setter with magic, 3 string, 4 int32, 5 int64, 6 double, 7 undefined, 8 nested object, 9 alias |
| 6 | 2 | magic |
| 8 | 8 | union: arity, C prototype and function pointer; or getter and setter; or nested table pointer and length; or the constant |

This is the layout of the QuickJS 2020-07-05 header
([QUICKJS_ENGINE.md](QUICKJS_ENGINE.md)). Eight property names checked by hand
are each referenced by exactly one pointer, at `0x70160000` plus the string's
file offset. That independently supports the image base used by the earlier
passes.

## How modules are registered

The firmware contains a 752-byte JavaScript bootstrap, one pair of lines per
module:

```js
import * as hmUI from 'hmUI';
globalThis.hmUI = hmUI;
```

It lists 12 modules: `timer`, `hmApp`, `hmSetting`, `hmUI`, `hmSensor`, `hmFS`,
`hmBle`, `hmMedia`, `hmSysApi`, `hmVAD`, `hmUtil` and `hmCrypto`. Each global is
therefore a module namespace object, and its properties are the module's
export table.

In the local Ghidra exports, three functions receive a table address and a
count as their last two arguments. Their roles are inferred from the call
shape and the QuickJS API, not from symbols:

| Function | Tables | Inferred QuickJS role |
| --- | ---: | --- |
| `0x7079ea40` | 12 | `JS_AddModuleExportList`, called right after the module is created |
| `0x707aa5c2` | 24 | `JS_SetModuleExportList`, called from the module's init function |
| `0x707aa354` | 18 | `JS_SetPropertyFunctionList`, used for class prototypes |

`0x7079ea40` is used for exactly 12 tables, one per bootstrap module.

## Modules and their export tables

| Global | Create function | Export table | Entries | Contents |
| --- | --- | --- | ---: | --- |
| `timer` | `0x7044d94e` | `0x70be0678` | 4 | `createTimer`, `createSysTimer`, `clearTimer`, `stopTimer` |
| `hmApp` | `0x70437ece` | `0x70bd9ab8` | 56 | 56 functions |
| `hmSetting` | `0x7044bd6e` | `0x70bdfc80` | 31 | 31 functions |
| `hmUI` | `0x7046ca24` | `0x70be96c8` | 32 | 32 functions; widget prototype at `0x70be9548` (24) |
| `hmSensor` | `0x7045c8dc` | `0x70be5070` | 2 | `createSensor`, `checkAvailable` |
| `hmFS` | `0x7043ffd6` | `0x70bdc158` | 36 | 26 functions, 10 `O_*`/`SEEK_*` constants |
| `hmBle` | `0x7043274a` | `0x70bd7fa0` | 50 | 50 functions |
| `hmMedia` | `0x70453570` | `0x70be1ea8` | 2 | `create`, `checkAvailable` |
| `hmCrypto` | `0x70450e0a` | `0x70be13e8` | 3 | `createCrypto`, `encryptKey`, `checkAvailable` |
| `hmSysApi` | `0x7044cf00` | `0x70be0318` | 11 | `checkAvailable`, `launchApp`, `exitApp`, `startApp`, `setApp`, `controlApp`, `queryApp`, `addAppData`, `delAppData`, `subscribeEvent`, `unsubscribeEvent` |
| `hmVAD` | `0x70442534` | `0x70bdd208` | 13 | `checkAvailable`, `startSession`, `stopSession`, `restartSession`, `next`, `replyCommand`, `stopAudioPlay`, `startListening`, `setFirstState`, `getMicStatus`, `requestAIGC`, `enterIdleState`, `addStatistic` |
| `hmUtil` | `0x7044daf6` | `0x70be0728` | 2 | `stringToBuffer`, `bufferToString` |

The export table and its length for each create function come from the Ghidra
exports and are in the JSON (`callers`). A subsequent independent byte-level
inspector reproduces all twelve name-to-create-function pairings and their
table addresses/counts directly from the OTA; see
[JS_MODULE_REGISTRATION.md](JS_MODULE_REGISTRATION.md). In
`jssdk_runtime_init` (`0x7044e1fc`) each module-name string address is
built immediately before a call to that create function, and the bootstrap
source is evaluated right after the twelfth call. For `hmApp`, `hmBle`, `hmFS`,
`hmSetting`, `hmUI`, `hmSensor` and `timer` the table contents confirm the
pairing independently (see the cross-check below). Module init functions add
further exports, mostly nested constant objects such as `hmUI.widget`,
`hmUI.prop`, `hmApp.key` and `hmApp.gesture`.

`hmUtil` is registered natively but is never referenced by `framework.js`.

## Cross-check against the JavaScript runtime

`framework.js` names native methods in two places: its own call sites
([JS_RUNTIME_API.md](JS_RUNTIME_API.md)) and the declarative `@zos/*` table
([ZOS_API.md](ZOS_API.md)). Every one of those names is present in the firmware
tables, with two exceptions: `hmApp.addSysPageListener` and
`hmApp.removeSysPageListener`. The runtime declares them under `_internals`
since API 3.6, but this firmware's tables do not contain them.

The best-matching table per module is the module's export table in each case:
`hmFS` 30 of 30 known names, `hmSetting` 28 of 28, `hmApp` 38 of 40, `hmBle`
37 of 37, `timer` 3 of 3. For `hmUI` and `hmSensor` the remaining known names
are nested objects added by the init function.

This also settles the open point in [ZOS_API.md](ZOS_API.md). The modules that
the runtime reflects from native objects (`hmUI`, `hmBle`, `hmMedia`,
`hmCrypto`, `hmVAD`, `hmSysApi`) get their method lists from these tables.

## Why Ghidra missed the registration code

`jssdk_runtime_init` is 44 bytes long in the bulk export. Its first call goes
to the logger at `0x702b38a2`, which the bulk analysis marks as non-returning,
so everything after that call was dropped. This is the same defect recorded in
[DISPLAY_AND_LIGHT.md](DISPLAY_AND_LIGHT.md). The create functions themselves
were exported normally.

## Reproduction

```sh
python3 analysis_scripts/js_cfunction_tables.py firmware/bip6-4.6.0.3.zip \
  --decompiled firmware/decompiled/main \
  --known analysis/js-runtime-api.json analysis/zos-api-table.json \
  > analysis/js-cfunction-tables.json
python3 -m unittest tests/test_js_cfunction_tables.py -v
```

Without `--decompiled` the tool still finds the 86 runs and the nested tables,
but adjacent tables stay merged because their lengths are unknown. The tests
build a synthetic image and a synthetic export file.

## Limitations

Tables give names, arities, constants and addresses. They do not say what a
function does, what arguments it expects, or which class a prototype table
belongs to. Table lengths taken from runs are upper bounds, since two tables
stored back to back look like one. A run can also be cut short by an entry the
scanner rejects. Function roles for the three table-consuming functions are
inferred. The name-to-create-function pairing now has a committed reproduction
in `analysis_scripts/js_module_registration.py`; its bounded instruction
patterns and limitations are documented in the linked report.
No function was executed or tested on a device.
