#!/usr/bin/env python3
"""Inspect observed GAPP chunks and QuickJS-v1-like atom tables without execution."""
import argparse
import hashlib
import json
import pathlib
import struct
import zipfile


def uleb128(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError('truncated ULEB128')
        byte = data[offset]
        offset += 1
        if shift == 28 and byte > 15:
            raise ValueError('ULEB128 exceeds uint32')
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError('overlong ULEB128')


def inspect_atoms(data):
    if not data or data[0] != 1:
        raise ValueError('only observed version-byte 1 is supported')
    count, offset = uleb128(data, 1)
    if count > len(data) - offset:
        raise ValueError('atom count cannot fit in remaining bytes')
    atoms = []
    for _ in range(count):
        descriptor, offset = uleb128(data, offset)
        length, wide = descriptor >> 1, descriptor & 1
        end = offset + length * (2 if wide else 1)
        if end > len(data):
            raise ValueError('truncated atom string')
        atoms.append(data[offset:end].decode('utf-16le' if wide else 'latin1', errors='surrogatepass'))
        offset = end
    if offset >= len(data):
        raise ValueError('no serialized object follows atom table')
    return {'version_byte': data[0], 'atom_count': count, 'atom_table_end': offset,
            'following_object_tag': data[offset], 'remaining_object_bytes': len(data) - offset}, atoms


def inspect_initial_function(data, offset):
    """Read a bounded initial function prefix following the 2020 reader layout.

    Atom numbers are preserved raw: vendor built-in atom numbering is unknown.
    Constant-pool objects and bytecode instruction semantics are not decoded.
    """
    start = offset
    if offset + 4 > len(data) or data[offset] != 14:
        raise ValueError(f'missing/truncated function tag/header at {offset:#x}')
    flags = struct.unpack_from('<H', data, offset + 1)[0]
    mode = data[offset + 3]
    offset += 4
    name_ref, offset = uleb128(data, offset)
    names = ('arg_count', 'var_count', 'defined_arg_count', 'stack_size',
             'closure_var_count', 'constant_pool_count', 'bytecode_length', 'local_count')
    result = {'object_offset': start, 'flags_word': flags, 'js_mode': mode,
              'function_name_encoded_atom_ref': name_ref,
              'function_name_atom_index_or_integer': name_ref >> 1,
              'function_name_is_tagged_integer': bool(name_ref & 1)}
    for name in names:
        result[name], offset = uleb128(data, offset)
    result['fixed_metadata_end'] = offset
    for name in names[:4]:
        if result[name] > 65535:
            raise ValueError(f'{name} exceeds uint16 at {offset:#x}')
    if result['local_count'] not in (0, result['arg_count'] + result['var_count']):
        raise ValueError(f'local count differs from upstream layout at {offset:#x}')
    minimum = result['local_count'] * 4 + result['closure_var_count'] * 3
    if minimum > len(data) - offset:
        raise ValueError(f'local/closure records cannot fit at {offset:#x}')
    for _ in range(result['local_count']):
        for _ in range(3):
            _, offset = uleb128(data, offset)
        if offset >= len(data):
            raise ValueError(f'truncated local flags at {offset:#x}')
        offset += 1
    for _ in range(result['closure_var_count']):
        for _ in range(2):
            _, offset = uleb128(data, offset)
        if offset >= len(data):
            raise ValueError(f'truncated closure flags at {offset:#x}')
        offset += 1
    result['bytecode_offset'] = offset
    end = offset + result['bytecode_length']
    if end > len(data):
        raise ValueError(f'bytecode extends past member at {offset:#x}')
    result['bytecode_end'] = end
    result['bytecode_sha256'] = hashlib.sha256(data[offset:end]).hexdigest()
    offset = end
    if flags & (1 << 10):
        result['debug_filename_encoded_atom_ref'], offset = uleb128(data, offset)
        result['debug_line'], offset = uleb128(data, offset)
        result['debug_pc2line_length'], offset = uleb128(data, offset)
        result['debug_pc2line_offset'] = offset
        offset += result['debug_pc2line_length']
        if offset > len(data):
            raise ValueError('debug line table extends past member')
    result['prefix_end_before_constant_pool'] = offset
    if result['constant_pool_count']:
        if offset >= len(data):
            raise ValueError('missing first constant-pool object')
        result['first_constant_pool_tag'] = data[offset]
    return result


def inspect_gapp(data):
    if len(data) < 12 or data[:4] != b'RIFF' or data[8:12] != b'GAPP':
        raise ValueError('missing RIFF/GAPP header')
    sections = []
    offset = 12
    while offset < len(data):
        if offset + 8 > len(data):
            raise ValueError('truncated section header')
        tag = data[offset:offset + 4]
        size = struct.unpack_from('<I', data, offset + 4)[0]
        extra = 4 if tag == b'LIST' else 0
        end = offset + 8 + extra + size
        if end > len(data):
            raise ValueError('section extends past physical EOF')
        if tag not in (b'APP\0', b'LIST', b'DAMR'):
            raise ValueError(f'unrecognized top-level section at {offset:#x}')
        section = {'offset': offset, 'tag_hex': tag.hex(), 'declared_size': size,
                   'physical_end': end}
        if tag == b'LIST':
            section['list_type_hex'] = data[offset + 8:offset + 12].hex()
        sections.append(section)
        offset = end
    return {'riff_declared_size': struct.unpack_from('<I', data, 4)[0],
            'physical_size': len(data), 'sections': sections,
            'top_level_walk_reaches_eof': offset == len(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--atoms-dir', type=pathlib.Path, help='new private directory for complete atom strings')
    args = parser.parse_args()
    if args.atoms_dir:
        args.atoms_dir.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(args.archive) as archive:
        app = archive.read('META/resources/Application.bin')
        gapp = inspect_gapp(app)
        gapp['sha256'] = hashlib.sha256(app).hexdigest()
        bytecode = []
        for name in archive.namelist():
            if not (name.startswith('META/js_apps/') and name.endswith('.bin')):
                continue
            data = archive.read(name)
            info, atoms = inspect_atoms(data)
            info['initial_function'] = inspect_initial_function(data, info['atom_table_end'])
            info.update(member=name, size=len(data), sha256=hashlib.sha256(data).hexdigest())
            bytecode.append(info)
            if args.atoms_dir:
                (args.atoms_dir / (info['sha256'] + '.json')).write_text(json.dumps(atoms, ensure_ascii=True, indent=2) + '\n')
    print(json.dumps({'application': gapp, 'bytecode_members': bytecode}, indent=2))


if __name__ == '__main__':
    main()
