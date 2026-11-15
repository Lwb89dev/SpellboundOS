#!/usr/bin/env python3
"""Identify the QuickJS release embedded in the main firmware.

QuickJS initializes its builtin atoms from one NUL-separated string blob
(``js_atom_init``) and describes every opcode in a constant ``opcode_info[]``
array of four bytes per entry (size, n_pop, n_push, format) when built without
``DUMP_BYTECODE``. Both are compiled from ``quickjs-atom.h`` and
``quickjs-opcode.h``, so they fingerprint the engine release and build options.

This tool extracts the atom blob from the firmware, and for each supplied
upstream QuickJS source directory evaluates those two headers with a minimal
conditional preprocessor (``CONFIG_ATOMICS`` defined, ``SHORT_OPCODES=1``, no
``CONFIG_BIGNUM`` — the upstream defaults for a non-bignum build), then checks
whether the firmware contains the identical atom list and the identical
``opcode_info`` bytes. Upstream sources are read only; nothing is compiled or
executed, and no upstream or vendor bytes are written to the output.
"""
import argparse
import hashlib
import json
import pathlib
import re
import zipfile

FIRMWARE = 'META/firmware_sign.bin'
ATOM_BLOB_START = b'null\0false\0true\0if\0else\0return\0'
DEFAULT_DEFINES = {'CONFIG_ATOMICS': '1', 'SHORT_OPCODES': '1',
                   'FMT': '1', 'DEF': '1'}


def _condition(expr, defines):
    """Evaluate the only ``#if`` form these headers use: a single macro or int."""
    expr = expr.split('/*')[0].split('//')[0].strip()
    if re.fullmatch(r'\d+', expr):
        return int(expr) != 0
    if re.fullmatch(r'[A-Za-z_]\w*', expr):
        value = defines.get(expr, '0')
        return value.isdigit() and int(value) != 0
    raise ValueError(f'unsupported preprocessor expression: {expr!r}')


def active_lines(text, defines):
    """Yield source lines whose enclosing conditionals are all true."""
    stack = []  # entries: [currently_active, any_branch_taken]
    for line in text.splitlines():
        stripped = line.strip()
        directive = re.match(r'#\s*(\w+)\s*(.*)', stripped)
        parent = all(entry[0] for entry in stack)
        if directive:
            name, rest = directive.groups()
            if name in ('ifdef', 'ifndef'):
                word = rest.split()[0]
                value = (word in defines) == (name == 'ifdef')
                stack.append([value, value])
                continue
            if name == 'if':
                value = _condition(rest, defines)
                stack.append([value, value])
                continue
            if name == 'elif':
                taken = stack[-1][1]
                value = not taken and _condition(rest, defines)
                stack[-1] = [value, taken or value]
                continue
            if name == 'else':
                stack[-1][0] = not stack[-1][1]
                stack[-1][1] = True
                continue
            if name == 'endif':
                stack.pop()
                continue
            continue  # define/undef/include do not affect these tables
        if parent:
            yield line


def upstream_atoms(atom_header, defines=DEFAULT_DEFINES):
    atoms = []
    for line in active_lines(atom_header, defines):
        match = re.match(r'\s*DEF\(\s*\w+\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)', line)
        if match:
            atoms.append(match.group(1))
    return atoms


def upstream_opcodes(opcode_header, defines=DEFAULT_DEFINES):
    """Return (format names, entries) in ``opcode_info[]`` order.

    Temporary opcodes (``def``) are included where the header lists them,
    because ``opcode_info[]`` includes them in header order.
    """
    formats, entries = [], []
    for line in active_lines(opcode_header, defines):
        fmt = re.match(r'\s*FMT\(\s*(\w+)\s*\)', line)
        if fmt:
            formats.append(fmt.group(1))
            continue
        op = re.match(r'\s*(DEF|def)\(\s*(\w+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,'
                      r'\s*(\d+)\s*,\s*(\w+)\s*\)', line)
        if op:
            kind, name, size, pop, push, fmt_name = op.groups()
            entries.append({'name': name, 'temporary': kind == 'def',
                            'size': int(size), 'n_pop': int(pop),
                            'n_push': int(push), 'format': fmt_name})
    return formats, entries


def opcode_table_bytes(formats, entries):
    return bytes(b for e in entries for b in
                 (e['size'], e['n_pop'], e['n_push'], formats.index(e['format'])))


def firmware_atoms(data):
    """Atoms from the firmware's ``js_atom_init`` blob.

    The blob ends where NUL padding starts: a run of two or more empty strings
    (a single empty string is the legitimate ``""`` atom).
    """
    start = data.find(ATOM_BLOB_START)
    if start < 0:
        raise ValueError('QuickJS atom blob not found')
    parts = data[start:start + 0x4000].split(b'\0')
    atoms = []
    for index, part in enumerate(parts):
        if part == b'' and index + 1 < len(parts) and parts[index + 1] == b'':
            break
        atoms.append(part.decode('latin1'))
    return start, atoms


def compare(data, source_dir):
    source = pathlib.Path(source_dir)
    atoms = upstream_atoms((source / 'quickjs-atom.h').read_text('latin1'))
    formats, entries = upstream_opcodes(
        (source / 'quickjs-opcode.h').read_text('latin1'))
    table = opcode_table_bytes(formats, entries)
    _, fw_atoms = firmware_atoms(data)
    offset = data.find(table)
    prefix = 0
    low, high = 0, len(entries)
    while low < high:  # longest matching table prefix, in entries
        mid = (low + high + 1) // 2
        if data.find(table[:4 * mid]) >= 0:
            low = mid
        else:
            high = mid - 1
    prefix = low
    version = (source / 'VERSION')
    return {
        'source': source.name,
        'declared_version': version.read_text().strip() if version.exists() else None,
        'builtin_atoms': len(atoms),
        'js_atom_end': len(atoms) + 1,
        'atoms_identical': fw_atoms == atoms,
        'opcode_entries': len(entries),
        'opcode_formats': len(formats),
        'opcode_table_sha256': hashlib.sha256(table).hexdigest(),
        'opcode_table_offset': offset if offset >= 0 else None,
        'opcode_table_longest_prefix': prefix,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('sources', nargs='*',
                        help='extracted upstream QuickJS source directories')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(FIRMWARE)
    start, atoms = firmware_atoms(data)
    result = {
        'member': FIRMWARE,
        'member_sha256': hashlib.sha256(data).hexdigest(),
        'atom_blob_offset': start,
        'firmware_builtin_atoms': len(atoms),
        'firmware_js_atom_end': len(atoms) + 1,
        'firmware_atom_index': {name: atoms.index(name) + 1 for name in
                                ('<eval>', 'errors', 'not-equal')
                                if name in atoms},
        'releases': [compare(data, source) for source in sorted(args.sources)],
    }
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
