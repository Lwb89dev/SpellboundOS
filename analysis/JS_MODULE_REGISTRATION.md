# Reproducible native module registration

Static investigation on 2026-11-15 of `META/firmware_sign.bin` in Bip 6 OTA
4.6.0.3, member SHA-256
`a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa`.
The independent inspector is
[`js_module_registration.py`](../analysis_scripts/js_module_registration.py);
its deterministic output is [js-module-registration.json](js-module-registration.json).
It reads the original archive without executing firmware or JavaScript and
does not require Ghidra, its databases, or the prior C exports.

## Result

All 12 module-name-to-constructor pairings previously observed by hand in
[`NATIVE_BINDINGS.md`](NATIVE_BINDINGS.md) are reproducible from the machine
instructions. Their export tables contain 242 entries in total. Each table's
address, exact count, decoded contents and constructor caller agree with the
earlier Ghidra-derived inventory. This closes the reproduction gap left by the
truncated bulk export of `jssdk_runtime_init`.

The same inspection recovers the initializer callback passed as the third
argument to the candidate module-creation helper at `0x7079461e`:

| Module | Constructor | Initializer callback | Export table | Entries |
| --- | --- | --- | --- | ---: |
| `timer` | `0x7044d94e` | `0x7044cfa6` | `0x70be0678` | 4 |
| `hmApp` | `0x70437ece` | `0x70435aa2` | `0x70bd9ab8` | 56 |
| `hmSetting` | `0x7044bd6e` | `0x7044a360` | `0x70bdfc80` | 31 |
| `hmUI` | `0x7046ca24` | `0x70467e34` | `0x70be96c8` | 32 |
| `hmSensor` | `0x7045c8dc` | `0x7045bc20` | `0x70be5070` | 2 |
| `hmFS` | `0x7043ffd6` | `0x7043e414` | `0x70bdc158` | 36 |
| `hmBle` | `0x7043274a` | `0x70431ac6` | `0x70bd7fa0` | 50 |
| `hmMedia` | `0x70453570` | `0x70452aa6` | `0x70be1ea8` | 2 |
| `hmCrypto` | `0x70450e0a` | `0x70450700` | `0x70be13e8` | 3 |
| `hmSysApi` | `0x7044cf00` | `0x7044bf2a` | `0x70be0318` | 11 |
| `hmVAD` | `0x70442534` | `0x70441644` | `0x70bdd208` | 13 |
| `hmUtil` | `0x7044daf6` | `0x7044da72` | `0x70be0728` | 2 |

The 242 entries are the constructor export lists. Initializers can add further
exports, including nested constant objects; this is not a complete count of
all module properties.

## What is checked

The candidate image base remains `0x70160000`. Starting at the previously
identified `jssdk_runtime_init` entry (`0x7044e1fc`), the inspector tiles a
bounded region by 16/32-bit instruction lengths. It finds one contiguous
168-byte sequence at `0x7044e3a8` through `0x7044e450` (exclusive), made of
twelve 14-byte blocks. Each block must contain:

1. `AUIPC a1` and `ADDI a1,a1,imm`, resolving to a bootstrap module-name string;
2. `C.MV a0,s0`, supplying the same context register;
3. `JAL ra,constructor`, resolving to an aligned address inside the image.

The module-name set must match the embedded import/global bootstrap exactly,
without duplicates or missing modules. The order above is the native
registration order; it need not equal the order of the bootstrap imports.

For each constructor, the inspector examines its first `0x180` bytes. It
requires one `AUIPC ra` / `JALR ra,ra,imm` call to each of the candidate
helpers `0x7079461e` (create module) and `0x7079ea40` (add export list), in that
order. It reconstructs constants in short straight-line argument-setup
suffixes: `a2` for the initializer; `a2` and `a3` for the table and its count.
Only `AUIPC`, `ADDI`, `C.LI`, `C.MV` and integer stores are accepted in those
suffixes. Register values start unknown; loads, calls, branches and unsupported
instructions reject a suffix. Table entries are independently decoded with
the existing `JSCFunctionListEntry` reader, with bounds and alignment checks.

The JSON records the setup and call addresses as well as the resolved values.
LLVM's RISC-V disassembly was also inspected for the registration chain and
helper call sites. No Ghidra metadata was changed.

## Reproduction and validation

```sh
python3 analysis_scripts/js_module_registration.py firmware/bip6-4.6.0.3.zip \
  > analysis/js-module-registration.json
python3 -m unittest discover -s tests -p 'test_js_module_registration.py' -v
# Full suite; requires cryptography for the existing signature tests:
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The report regenerates byte-for-byte. All 70 Python tests pass, including ten
new synthetic-fixture tests covering complete and ambiguous chains, missing
modules, altered context/call registers, signed PC-relative offsets, truncated
instructions, branches and loads in argument setup, and malformed tables.
The existing signature-test dependencies were loaded from the local package
cache for this session; the new inspector needs only Python's standard library.

## Limits and next target

This is a bounded pattern check for the observed firmware layout. The routine
start, search bounds and helper addresses are explicit assumptions from the
earlier investigation. Instruction-length tiling is not whole-function
control-flow analysis. The constructor window can include bytes of a following
function; ambiguous helper matches cause an error. Unsupported instruction
patterns also cause an error rather than guessed results.

The helper roles remain inferred from call shapes and the QuickJS API. These
results do not prove that initialization succeeds at runtime, that every
registered export is reachable by an app, or that the callback code implements
working hardware support. The next native-runtime target is the initializer
callbacks: map the extra constant objects and class prototypes to their owning
modules, particularly the sensor classes and the BLE callbacks. The separate
boot/debug/recovery obstacle remains unresolved.
