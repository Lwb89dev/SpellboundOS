#!/usr/bin/env python3
"""Cross-check the Python app-bytecode reader against the official QuickJS C reader.

The independent Python reader in ``qjs_bytecode.py`` recovers each packaged
function's header fields. This tool compares them, function by function in the
same depth-first order, with the output of the upstream QuickJS 2020-07-05
``JS_ReadObject``. The C side is produced by a small read-only harness that
parses each member and prints one ``FN`` line per function; it never evaluates
bytecode. See QJS_CROSSCHECK.md for the harness and build commands.

The Python side needs only the archive (builtin atoms come from the firmware),
so its fingerprints regenerate without the C toolchain. The comparison needs
the harness output, passed with ``--c-output``.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import zipfile

if __package__:
    from .qjs_bytecode import Reader, functions
    from .quickjs_fingerprint import FIRMWARE, firmware_atoms
else:
    from qjs_bytecode import Reader, functions
    from quickjs_fingerprint import FIRMWARE, firmware_atoms

FIELDS = ('arg_count', 'var_count', 'defined_arg_count', 'stack_size',
          'closure_var_count', 'cpool_count', 'bytecode_length', 'js_mode',
          'has_debug')


def python_records(archive):
    """member -> list of per-function field tuples, in read (DFS) order."""
    firmware = archive.read(FIRMWARE)
    builtin = [None] + firmware_atoms(firmware)[1]
    records = {}
    for name in sorted(archive.namelist()):
        if not ((name.startswith('META/js_apps/')
                 or name.startswith('META/js_watchfaces/')) and name.endswith('.bin')):
            continue
        reader = Reader(archive.read(name), builtin)
        root = reader.read_file()
        if reader.pos != len(reader.data):
            raise ValueError(f'unconsumed bytecode bytes in {name}')
        records[name] = [tuple(int(fn['has_debug']) if field == 'has_debug' else fn[field]
                               for field in FIELDS)
                         for fn in functions(root)]
    return records


def parse_c_output(text):
    """member (archive path) -> list of per-function field tuples.

    Each ``FN`` line is: FN, file, index, then the nine fields in FIELDS order.
    The file column is the on-disk name with '/' replaced by '__'.
    """
    records = collections.defaultdict(list)
    for line in text.splitlines():
        parts = line.split('\t')
        if parts[0] != 'FN':
            continue
        if len(parts) != 3 + len(FIELDS):
            raise ValueError('malformed C function record')
        name = pathlib.Path(parts[1]).name.replace('__', '/')
        if not name.startswith(('META/js_apps/', 'META/js_watchfaces/')) or not name.endswith('.bin'):
            raise ValueError('unexpected C input member')
        if int(parts[2]) != len(records[name]):
            raise ValueError(f'nonconsecutive C function index for {name}')
        values = tuple(int(x) for x in parts[3:])
        if any(value < 0 for value in values) or values[-1] not in (0, 1):
            raise ValueError('invalid C function fields')
        records[name].append(values)
    return dict(records)


def digest(records):
    data = ''.join(f'{name}:' + ';'.join(','.join(map(str, rec)) for rec in records[name])
                   for name in sorted(records))
    return hashlib.sha256(data.encode()).hexdigest()


def compare(python, c):
    members, functions_compared, mismatches = [], 0, []
    if not python:
        raise ValueError('no Python bytecode members')
    for name in sorted(set(c) - set(python)):
        mismatches.append({'member': name, 'status': 'unexpected_c_member'})
    for name in sorted(python):
        py = python[name]
        cc = c.get(name)
        entry = {'member': name, 'functions': len(py), 'c_functions': len(cc or [])}
        if cc is None:
            entry['status'] = 'missing_from_c'
            mismatches.append(entry)
        elif len(py) != len(cc):
            entry['status'] = 'count_mismatch'
            mismatches.append(entry)
        else:
            diffs = [i for i, (a, b) in enumerate(zip(py, cc)) if a != b]
            functions_compared += len(py)
            if diffs:
                entry['status'] = 'field_mismatch'
                entry['mismatched_indices'] = diffs
                mismatches.append(entry)
            else:
                entry['status'] = 'match'
        members.append(entry)
    return {
        'members': len(python),
        'functions_compared': functions_compared,
        'mismatches': mismatches,
        'agree': not mismatches,
    }, members


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--c-output', type=pathlib.Path,
                        help='harness output; without it, only Python fingerprints are emitted')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        python = python_records(archive)
    report = {'fields': list(FIELDS),
              'archive_sha256': hashlib.sha256(pathlib.Path(args.archive).read_bytes()).hexdigest(),
              'python_member_count': len(python),
              'python_function_count': sum(len(v) for v in python.values()),
              'python_fingerprint_sha256': digest(python)}
    if args.c_output:
        c = parse_c_output(args.c_output.read_text())
        summary, members = compare(python, c)
        report['c_reader'] = 'QuickJS 2020-07-05 JS_ReadObject'
        report['harness_sha256'] = hashlib.sha256(
            pathlib.Path(__file__).with_name('qjs_reader_crosscheck.c').read_bytes()).hexdigest()
        report['c_fingerprint_sha256'] = digest(c)
        report['c_output_sha256'] = hashlib.sha256(args.c_output.read_bytes()).hexdigest()
        report['comparison'] = summary
        report['per_member'] = members
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.c_output and not summary['agree']:
        parser.exit(1)


if __name__ == '__main__':
    main()
