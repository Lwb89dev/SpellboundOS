#!/usr/bin/env python3
"""Map candidate hmSensor class registrations using OTA data and local C exports.

Reads vendor bytes and text without executing either. Registration IDs come
from explicit assignments in existing Ghidra exports; names, constructors and
property tables are read independently from the OTA descriptor structures.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import zipfile

if __package__:
    from .js_cfunction_tables import BASE, FIRMWARE, Image
else:
    from js_cfunction_tables import BASE, FIRMWARE, Image

DISPATCHER = 0x7045cb54
REGISTRAR = 0x7045c792
COMMON_TABLE = 0x70be5000
NAMESPACE_TABLE = 0x70be50c0
CALL = re.compile(r'\bFUN_ram_([0-9a-f]{8})\s*\(')
SITE = re.compile(r'\bFUN_ram_7045c792\(\s*param_1\s*,\s*(0x[0-9a-f]+)\s*,\s*'
                  r'&PTR_\w*_ram_([0-9a-f]{8})\s*\)')


def called_functions(source):
    # The first occurrence is the function definition, not a call.
    matches = CALL.findall(source)
    return [int(value, 16) for value in matches[1:]]


def expand_table(image, address, count, ancestors=()):
    if address in ancestors or not 0 < count < 2048 or len(ancestors) >= 8:
        raise ValueError('cyclic or invalid property table')
    entries = image.table(address, count)
    if entries is None:
        raise ValueError(f'invalid property table at {address:#x}')
    for entry in entries:
        if entry['kind'] == 'object':
            entry['entries'] = expand_table(image, entry['table'], entry['count'],
                                            ancestors + (address,))
    return entries


def descriptor(image, address):
    offset = address - image.base
    if offset < 0 or offset + 40 > len(image.data):
        raise ValueError('descriptor outside image')
    fields = struct.unpack_from('<10I', image.data, offset)
    name, finalizer, _, _, _, table, count, _, _, constructor = fields
    if (not image.name(name) or not image.inside(finalizer) or finalizer % 2 or
            not image.inside(constructor) or constructor % 2):
        raise ValueError(f'invalid class descriptor at {address:#x}')
    return {'descriptor_address': address, 'name': image.name(name),
            'constructor': constructor, 'finalizer': finalizer,
            'property_table': table, 'property_count': count,
            'properties': expand_table(image, table, count)}


def registration(image, source):
    matches = list(SITE.finditer(source))
    if len(matches) != 1:
        raise ValueError(f'expected one explicit sensor registration, found {len(matches)}')
    match = matches[0]
    state, address = int(match[1], 16), int(match[2], 16)
    assignments = re.findall(r'\b_DAT_ram_' + f'{state + 8:08x}' +
                             r'\s*=\s*(0x[0-9a-f]+|\d+)\s*;', source)
    if len(assignments) != 1:
        raise ValueError('missing or ambiguous sensor ID assignment')
    result = descriptor(image, address)
    result.update(state_address=state, sensor_id=int(assignments[0], 0))
    callbacks = re.findall(r'\b_DAT_ram_' + f'{state + 0x40:08x}' +
                           r'\s*=\s*(?:FUN|&LAB)_ram_([0-9a-f]{8})\s*;', source)
    if len(callbacks) > 1:
        raise ValueError('ambiguous availability callback assignment')
    # None means no explicit assignment was found, not a proven null pointer.
    result['availability_callback_assignment'] = int(callbacks[0], 16) if callbacks else None
    return result


def enum_coverage(classes, entries):
    if any(e['kind'] != 'int32' for e in entries):
        raise ValueError('sensor ID enumeration must contain integer constants')
    names = collections.defaultdict(list)
    for entry in entries:
        names[entry['value']].append(entry['name'])
    registered = [c['sensor_id'] for c in classes]
    if len(set(registered)) != len(registered):
        raise ValueError('duplicate sensor registration ID')
    if set(registered) - names.keys():
        raise ValueError('registered ID absent from public enumeration')
    for item in classes:
        item['enum_names'] = names[item['sensor_id']]
    return [{'sensor_id': key, 'enum_names': value} for key, value in sorted(names.items())
            if key not in registered]


def analyze(data, directory):
    image, sources = Image(data), {}

    def read(address):
        text = (pathlib.Path(directory) / f'ram_{address:08x}.c').read_text()
        sources[f'ram_{address:08x}.c'] = hashlib.sha256(text.encode()).hexdigest()
        return text

    # Keep the provenance anchors explicit: module init -> namespaces, module
    # constructor -> dispatcher, and registrar -> shared seven-property table.
    for address in (0x7045c8dc, 0x7045bc20, 0x7045cc08, REGISTRAR):
        read(address)
    if DISPATCHER not in called_functions(read(0x7045c8dc)):
        raise ValueError('module constructor no longer calls sensor dispatcher')
    namespace = expand_table(image, NAMESPACE_TABLE, 3)
    ids = [e for e in namespace if e['name'] == 'id' and e['kind'] == 'object']
    if len(ids) != 1:
        raise ValueError('missing sensor ID namespace')
    classes = []
    for address in called_functions(read(DISPATCHER)):
        item = registration(image, read(address))
        item['registration_function'] = address
        classes.append(item)
    missing = enum_coverage(classes, ids[0]['entries'])
    return {'member': FIRMWARE, 'member_sha256': hashlib.sha256(data).hexdigest(),
            'image_base': BASE, 'dispatcher': DISPATCHER, 'registrar': REGISTRAR,
            'common_property_table': COMMON_TABLE,
            'common_properties': expand_table(image, COMMON_TABLE, 7),
            'namespace': namespace, 'classes': classes,
            'ids_without_dispatcher_registration': missing,
            'source_sha256': dict(sorted(sources.items())),
            'summary': {'registered_classes': len(classes),
                        'id_symbols': len(ids[0]['entries']),
                        'unique_public_ids': len({e['value'] for e in ids[0]['entries']}),
                        'ids_without_registration': len(missing),
                        'class_property_entries': sum(c['property_count'] for c in classes)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = analyze(archive.read(FIRMWARE), args.decompiled)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect sensor classes: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
