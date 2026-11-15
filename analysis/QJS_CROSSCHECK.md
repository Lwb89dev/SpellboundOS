# Official QuickJS reader cross-check

All 44 packaged app/watchface bytecode members are accepted by the official
QuickJS 2020-07-05 `JS_ReadObject`, compiled without `CONFIG_BIGNUM` as identified
in [QUICKJS_ENGINE.md](QUICKJS_ENGINE.md). For all 1,072 functions, the independent
Python reader agrees with C on nine header fields in constant-pool depth-first
order: argument/variable/defined-argument counts, stack size, closure count,
constant-pool count, bytecode length, JS mode and debug flag.

The shared fingerprint is
`2ee208e798e155d899f37f75b6ad8ccc5a8b5513281b8b294db7b155c66da88d`.
[qjs-crosscheck.json](qjs-crosscheck.json) records each member's result, both
fingerprints, the OTA hash, the C output hash and harness hash. This completes
the independent header-reader comparison left uncommitted in Claude's session.

The small independently authored harness includes upstream `quickjs.c` to
inspect internal function structures. It calls `JS_ReadObject` and frees the
parsed objects; it never evaluates bytecode. Inputs are limited to 32 MiB and
each runtime to 256 MiB. Upstream source, binaries, extracted bytecode and raw
output stay under ignored `firmware/qjs-crosscheck/`.

## Reproduction

Use the official 2020-07-05 source archive whose SHA-256 is
`63e9f77a4283cede6b37b75dbbe85cb57edc7dd646367650ac2901d9ef268a99`.
The existing local copy was rehashed before reuse. Extract verified source into
`firmware/qjs-crosscheck/upstream`, then compile from the repository root:

```sh
gcc -O1 -D_GNU_SOURCE -DCONFIG_VERSION='"2020-07-05"' \
  -I firmware/qjs-crosscheck/upstream \
  analysis_scripts/qjs_reader_crosscheck.c \
  firmware/qjs-crosscheck/upstream/libregexp.c \
  firmware/qjs-crosscheck/upstream/libunicode.c \
  firmware/qjs-crosscheck/upstream/cutils.c \
  -lm -ldl -lpthread -o firmware/qjs-crosscheck/reader
```

Extract and run only the selected OTA members without executing their bytecode:

```sh
python3 - <<'PY'
from pathlib import Path
import subprocess
import zipfile
root = Path('firmware/qjs-crosscheck')
directory = root / 'bc'
directory.mkdir(exist_ok=True)
paths = []
with zipfile.ZipFile('firmware/bip6-4.6.0.3.zip') as archive:
    for name in sorted(archive.namelist()):
        if name.startswith(('META/js_apps/', 'META/js_watchfaces/')) and name.endswith('.bin'):
            path = directory / name.replace('/', '__')
            path.write_bytes(archive.read(name))
            paths.append(str(path))
with (root / 'reader-output.tsv').open('w') as output:
    subprocess.run([str(root / 'reader'), *paths], stdout=output, check=True, timeout=60)
PY
python3 analysis_scripts/qjs_crosscheck.py firmware/bip6-4.6.0.3.zip \
  --c-output firmware/qjs-crosscheck/reader-output.tsv \
  > analysis/qjs-crosscheck.json
python3 -m unittest discover -s tests -p 'test_qjs_crosscheck.py' -v
```

Without `--c-output`, the Python fingerprint regenerates using only the OTA.
The comparison fails on missing/extra members, mismatched counts/fields, broken
function indices and malformed records. The Python side additionally requires
exact input consumption. The upstream C API does not expose its final cursor;
C acceptance alone is not evidence of exact consumption or execution validity.
The report therefore establishes agreement on the nine listed header fields,
not complete interpreter equivalence or successful app execution. Atom operands
are relocated by the C reader, so raw post-read bytecode hashes are not compared.

Four synthetic tests exercise comparison failures, record/index validation and
fingerprints. The full Python suite passes 165 tests with signature dependencies.
