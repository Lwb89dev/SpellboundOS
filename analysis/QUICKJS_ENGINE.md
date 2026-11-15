# Embedded JavaScript engine: QuickJS 2020-07-05

Static investigation on 2026-11-15 of `META/firmware_sign.bin` (SHA-256
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`) in the Bip 6
OTA 4.6.0.3, archive SHA-256
`ee06079610eaf9b4ffbe35c7a6ddc604ee2aba00c3a66d85101ed2a6556d6df4`. The tool is
`analysis_scripts/quickjs_fingerprint.py`; its output is
[quickjs-fingerprint.json](quickjs-fingerprint.json). Nothing was compiled or
executed for this result.

## Result

The main firmware embeds the QuickJS engine from the official **2020-07-05**
release, built without `CONFIG_BIGNUM`, with the upstream defaults
`CONFIG_ATOMICS` and `SHORT_OPCODES`. Two independent compiled tables in the
firmware match that release exactly:

1. **Builtin atoms.** The `js_atom_init` string blob at member offset
   `0xb7e67c` holds 208 atoms, so `JS_ATOM_END` is 209. The list is identical,
   entry for entry, to the 2020-07-05 `quickjs-atom.h` under the default build.
2. **Opcode descriptors.** The firmware contains the complete 260-entry
   `opcode_info[]` table of that release (four bytes per entry: size, pops,
   pushes, operand format) byte-for-byte at member offset `0xb7e008`.

The packaged apps agree with this independently. In all 30
`META/js_apps/*.bin` members the debug filename's encoded atom reference (428,
index 214) points at the atom table entry holding the source path (entry 5),
which gives `JS_ATOM_END = 214 - 5 = 209`. The top-level function name is
builtin atom 80, which is `<eval>` in this table.

## Comparison with the other official releases

| Release | `JS_ATOM_END` | Atoms identical | `opcode_info[]` found | Longest matching prefix |
| --- | ---: | :---: | :---: | ---: |
| 2020-01-19 | 208 | no | no | 54 / 261 |
| **2020-07-05** | **209** | **yes** | **yes, `0xb7e008`** | **260 / 260** |
| 2020-09-06 | 209 | yes | no | 260 / 261 |
| 2020-11-08 | 210 | no | no | 129 / 259 |
| 2021-03-27 | 210 | no | no | 129 / 259 |
| 2023-12-09 | 214 | no | no | 129 / 259 |
| 2024-01-13 | 216 | no | no | 101 / 265 |
| 2025-04-26 | 223 | no | no | 44 / 267 |
| 2025-09-13 | 230 | no | no | 44 / 267 |

2020-09-06 has the same atoms but replaces the last short-opcode descriptor
with `typeof_is_undefined` and `typeof_is_function`, so its table is not in the
firmware. Compared with 2020-01-19, the firmware adds the `errors` atom
(AggregateError) at id 52, and its opcode numbering diverges from the 55th
descriptor.

That divergence explains the earlier failed experiment recorded in
[APP_FORMATS.md](APP_FORMATS.md). The 2020-01-19 reader re-maps the atom
operands inside each function's bytecode by walking opcodes with its own
descriptor table. With a different numbering it takes wrong instruction
lengths, and the reader then crashed in `free_function_bytecode`. The
container header itself (version byte 1, `BC_TAG_FUNCTION_BYTECODE` = 14) is the
same in both releases, which is why the atom-table parse succeeded anyway.

## Consequences

- The app bytecode format, opcode numbering and builtin atom IDs can now be
  taken from a specific, published source release instead of being guessed. A
  disassembler can use the upstream 2020-07-05 descriptors. Their sizes are the
  ones the firmware itself uses.
- A standalone OS could in principle embed stock QuickJS 2020-07-05 to load
  these apps, provided it also supplies the native modules and host globals in
  [JS_RUNTIME_API.md](JS_RUNTIME_API.md) and [APP_MODEL.md](APP_MODEL.md).
  This has not been demonstrated. Vendor changes outside these two tables, such
  as interpreter behavior, extra builtins or object-serialization tags, are not
  excluded by this check.

## Reproduction

Download the official source releases from `https://bellard.org/quickjs/`,
extract each into its own directory, and pass the directories:

```sh
python3 analysis_scripts/quickjs_fingerprint.py firmware/bip6-4.6.0.3.zip \
  quickjs-src/quickjs-2020-01-19 quickjs-src/quickjs-2020-07-05 ... \
  > analysis/quickjs-fingerprint.json
python3 -m unittest tests/test_quickjs_fingerprint.py -v
```

Release tarball SHA-256 values used here:

| Release | SHA-256 |
| --- | --- |
| 2020-01-19 | `4ae4c20c4ed7c201d72c228d5e8768314950914ba60d759f3df23d59037f2b85` |
| 2020-07-05 | `63e9f77a4283cede6b37b75dbbe85cb57edc7dd646367650ac2901d9ef268a99` |
| 2020-09-06 | `0021a3e8cdc6b61e225411d05e2841d2437e1ccf4b4cabb9a5f7685ebfb57717` |
| 2020-11-08 | `2e9d63dab390a95ed365238f21d8e9069187f7ed195782027f0ab311bb64187b` |
| 2021-03-27 | `a45bface4c3379538dea8533878d694e289330488ea7028b105f72572fe7fe1a` |
| 2023-12-09 | `e8afe386f875d0e52310ea91aa48e2b0e04182e821f19147794e3e272f4c8d8c` |
| 2024-01-13 | `3c4bf8f895bfa54beb486c8d1218112771ecfc5ac3be1036851ef41568212e03` |
| 2025-04-26 | `2f20074c25166ef6f781f381c50d57b502cb85d470d639abccebbef7954c83bf` |
| 2025-09-13 | `6f1f322aea3bb3a90858db85c9fe717013fde4df7dfcafe2f57e78f5bb4b4a0c` |

The headers are evaluated by a small conditional preprocessor in the tool, not
by a compiler. For all nine releases its counts and table matches agree with a
separate `gcc -E` evaluation run during this investigation. The tests use
synthetic headers and blobs. Upstream sources are not stored in this
repository.

## Limitations

Matching tables identify the release and build options of these two tables,
not the whole engine. Patches elsewhere in the interpreter, the object reader
or the native bindings would not show up here. The upstream C reader was not
re-run against the vendor bytecode with the 2020-07-05 release in this pass.
