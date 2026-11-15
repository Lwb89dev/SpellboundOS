# App bytecode: complete read and disassembly

Static investigation on 2026-11-15 of the 30 `META/js_apps/*.bin` members (6
apps) in the Bip 6 OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The tool is
`analysis_scripts/qjs_bytecode.py`, an independent Python implementation of the
QuickJS 2020-07-05 bytecode reader (see [QUICKJS_ENGINE.md](QUICKJS_ENGINE.md)).
Its summary is [app-bytecode-summary.json](app-bytecode-summary.json). Nothing
was executed.

## Result

All 30 members parse completely as QuickJS 2020-07-05 serialized objects and
disassemble without a single validation failure:

| Measure | Value |
| --- | ---: |
| Members parsed | 30 / 30 |
| Functions (including nested closures) | 886 |
| Instructions | 75,570 |
| Distinct opcodes used | 142 of 244 |
| Unread bytes after the root object | 0 in every member |

This extends [APP_FORMATS.md](APP_FORMATS.md), which stopped after the
atom table and the first function's metadata. The reader now follows the whole
object tree: function bytecode, local and closure variable records, debug
information, and constant pools with strings, numbers, nested functions,
objects, arrays and template objects.

## How the result is checked

The tool takes builtin atoms from the firmware's own `js_atom_init` blob, and
opcode sizes and formats from the firmware's own `opcode_info[]` table. Opcode
names are taken from the upstream 2020-07-05 `quickjs-opcode.h`, and only after
the table built from that header has been found byte-for-byte in the firmware.

Each function's disassembly must pass these checks:

- instructions tile the declared bytecode length exactly;
- every branch target lands on an instruction boundary or at the end;
- every local, argument, closure-variable and constant-pool index is in range;
- every atom operand resolves to a builtin atom, a file atom or a tagged
  integer;
- local count equals arguments plus variables, and no read passes the end.

As a negative control, the same 30 members were disassembled with the
descriptor tables of other releases. With 2020-01-19 and 2021-03-27, all 30
fail. 2020-09-06 also passes, as expected: it differs from 2020-07-05 only in
the last short-opcode descriptor, which these apps do not use. The release is
pinned by the firmware table, not by this control.

The disassembly is semantically coherent where it can be compared with readable
source. Each member's top-level `<eval>` function is the same
`try { … } catch (e) { console.log('Mini Program Error', …) }` wrapper seen in
the readable watchface bundles ([APP_MODEL.md](APP_MODEL.md)). The next
function declares `beforeAppCreate`, `afterAppCreate` and `__$$G$$__`.

## What the bytecode shows about the host contract

- **Sandboxed `with` scope.** There are 570 `with_get_var`, 178
  `with_get_ref` and 10 `with_make_ref` instructions. Free identifiers in app
  code are resolved through a `with` object, which matches the runtime's
  `ProxySandbox` described in [APP_MODEL.md](APP_MODEL.md).
- **Free variables.** 72 distinct names are read as free variables. Against
  the sandbox lists recovered from `framework.js` they split into:
  - 9 app-scope members (`App`, `Page`, `AppEvent`, `AppWidget`,
    `SecondaryWidget`, `getApp`, `__$$R$$__`, `__$$app$$__`, `__$$module$$__`);
  - 6 sandbox-hidden native names (`hmUI`, `hmApp`, `hmSetting`, `timer`,
    `DeviceRuntimeCore`, `__$$hmAppManager$$__`);
  - 14 builtins that the sandbox marks unscopable, so they resolve directly
    (`Array`, `Math`, `Object`, `setTimeout`, `console`, …), plus `Promise`,
    which is explicitly not unscopable and goes through the proxy;
  - 5 names the apps assign themselves;
  - 4 standard builtins outside the unscopables list (`Date`, `JSON`,
    `encodeURIComponent`, `decodeURIComponent`), which fall back to the real
    global;
  - 33 app-level names that no global-write opcode in these bundles assigns.
    Because the sandbox's `has` trap always returns true, such a read inside the
    `with` scope yields `undefined` instead of throwing `ReferenceError`.
- **`@zos/` modules.** The apps load 16 module specifiers through
  `__$$R$$__`: `@zos/ui`, `@zos/utils`, `@zos/i18n`, `@zos/device`,
  `@zos/router`, `@zos/settings`, `@zos/sensor`, `@zos/interaction`,
  `@zos/app-access`, `@zos/unsafe`, `@zos/app`, `@zos/fs`, `@zos/storage`,
  `@zos/alarm`, `@zos/ble` and `@zos/page`. Per-module reference and app counts
  are in the JSON. This is the module surface a host would have to resolve.
  The loader is built in `framework.js` from a declarative module table,
  which strips the `@zos/` prefix, so the full specifiers appear only in the
  apps. See [ZOS_API.md](ZOS_API.md).

## Reproduction

```sh
python3 analysis_scripts/qjs_bytecode.py firmware/bip6-4.6.0.3.zip \
  --opcode-header quickjs-src/quickjs-2020-07-05/quickjs-opcode.h \
  > analysis/app-bytecode-summary.json
# optional private listings, one file per member (vendor-derived; keep local):
python3 analysis_scripts/qjs_bytecode.py firmware/bip6-4.6.0.3.zip \
  --opcode-header quickjs-src/quickjs-2020-07-05/quickjs-opcode.h \
  --listing-dir firmware/NEW_PRIVATE_LISTING_DIR > /dev/null
python3 -m unittest tests/test_qjs_bytecode.py -v
```

The release tarball and its SHA-256 are listed in
[QUICKJS_ENGINE.md](QUICKJS_ENGINE.md). The tests build synthetic bytecode with
an invented descriptor table. They check decoding, branch and constant-index
rejection, truncation, invalid opcodes, the version byte, zig-zag `sleb128`, and
refusal of a header table that is absent from the firmware. Full listings stay
under ignored `firmware/`.

## Limitations

A structurally valid disassembly is not a decompilation to JavaScript, and
opcode semantics are taken from upstream rather than from the vendor
interpreter. Vendor changes to instruction behavior would not show up as a
format error. The upstream C reader was not run against these members in this
pass, so there is no independent C-side confirmation. Typed arrays, array
buffers, dates and boxed object values are rejected by this reader. None of
them occur in these members. `pc2line` debug tables are kept but not decoded
into line numbers.
