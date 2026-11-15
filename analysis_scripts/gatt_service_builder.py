#!/usr/bin/env python3
"""Recover the observed GATT builder's all-success registration branch.

Reads a bounded subset of explicit assignments in a targeted Ghidra C export.
It is not a C evaluator. Unknown expressions and uninitialized bytes fail.
UUID pointers are independently resolved from original main-image bytes.
"""
import argparse
import hashlib
import json
import pathlib
import re
import struct
import zipfile

if __package__:
    from .js_cfunction_tables import Image, BASE, FIRMWARE
else:
    from js_cfunction_tables import Image, BASE, FIRMWARE

VARIABLE = r'(?:pu|u)Stack_[0-9a-f]+'
UUID = re.compile(r'(?:[0-9a-fA-F]{4}(?:[0-9a-fA-F]{2})?|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})')
EVENT = re.compile(
    r'(?P<assign>\b(?P<var>' + VARIABLE + r')(?P<part>\._\d+_\d+_)?\s*=\s*(?P<expr>[^;]+);)'
    r'|(?P<zero>0x70947ce8\)\(\s*&(?P<zvar>' + VARIABLE + r'),\s*0,\s*(?P<length>0x[0-9a-f]+|\d+)\s*\);)'
    r'|(?P<register>candidate_703b2236\(\s*&(?P<spec>' + VARIABLE + r')\s*\))')


class Builder:
    def __init__(self, data, source, base=BASE):
        self.image, self.memory = Image(data, base), {}
        self.widths = {name: int(width) for width, name in re.findall(
            r'\bundefined([1248])\s+(' + VARIABLE + r')\s*;', source)}

    def address(self, name):
        return 0x100000 - int(name.rsplit('_', 1)[1], 16)

    def store(self, address, value, width):
        for index in range(width):
            self.memory[address + index] = value >> (8 * index) & 255

    def load(self, address, width):
        if any(address + index not in self.memory for index in range(width)):
            raise ValueError(f'uninitialized builder bytes at {address:#x}')
        return sum(self.memory[address + index] << (8 * index) for index in range(width))

    def expression(self, text):
        text = text.strip()
        if re.fullmatch(r'0x[0-9a-f]+|\d+', text):
            return int(text, 0)
        if re.fullmatch('&' + VARIABLE, text):
            return self.address(text[1:])
        if match := re.fullmatch(r'uRam([0-9a-f]{8})', text):
            offset = int(match[1], 16) - self.image.base
            if not 0 <= offset <= len(self.image.data) - 4:
                raise ValueError('UUID registry pointer outside image')
            return struct.unpack_from('<I', self.image.data, offset)[0]
        if match := re.fullmatch('(' + VARIABLE + r')\._(\d+)_(\d+)_', text):
            return self.load(self.address(match[1]) + int(match[2]), int(match[3]))
        if match := re.fullmatch(r'CONCAT22\(([^,]+),([^,]+)\)', text):
            return (self.expression(match[1]) & 65535) << 16 | self.expression(match[2]) & 65535
        raise ValueError(f'unsupported builder expression: {text}')

    def uuid(self, address):
        value = self.image.text(address)
        if value is None or not UUID.fullmatch(value):
            raise ValueError(f'invalid UUID string pointer {address:#x}')
        return value.lower()

    def snapshot(self, spec):
        address = self.address(spec)
        service = self.uuid(self.load(address, 4))
        count, table = self.load(address + 4, 4), self.load(address + 8, 4)
        if not 0 < count <= 256:
            raise ValueError('invalid characteristic count')
        characteristics = []
        for index in range(count):
            record = table + index * 12
            properties = self.load(record + 4, 2)
            descriptors = []
            if properties & 0x30:
                descriptors.append('2902')
            if properties & 0x400:
                descriptors.append('2908')
            identifier = self.uuid(self.load(record, 4))
            characteristics.append({'uuid': identifier[:4] if len(identifier) == 6 else identifier,
                'internal_identifier': identifier,
                'properties_raw': properties, 'permissions_raw': self.load(record + 6, 2),
                'max_length_field': self.load(record + 8, 2),
                'extra_bytes': [self.load(record + 10, 1), self.load(record + 11, 1)],
                'conditional_descriptor_uuids': descriptors})
        return {'uuid': service, 'characteristic_count': count, 'characteristics': characteristics}


def recover(data, source, base=BASE):
    builder, services = Builder(data, source, base), []
    code = re.sub(r'/\*.*?\*/', '', source, flags=re.S)
    if re.search(r'\b(?:else|for|while|switch|goto)\b', code):
        raise ValueError('unsupported builder control flow')
    if any(not re.fullmatch(r'\s*iVar\d+\s*==\s*0\s*', condition)
           for condition in re.findall(r'\bif\s*\(([^)]*)\)', code)):
        raise ValueError('unsupported builder branch condition')
    # Interpret only explicit straight-line setups along nested success branches.
    for event in EVENT.finditer(code):
        if event['assign']:
            width, offset = builder.widths.get(event['var'], 4), 0
            if event['part']:
                offset, width = map(int, re.findall(r'\d+', event['part']))
            builder.store(builder.address(event['var']) + offset,
                          builder.expression(event['expr']), width)
        elif event['zero']:
            length = int(event['length'], 0)
            if not 0 <= length <= 4096:
                raise ValueError('unbounded builder memset')
            for index in range(length):
                builder.memory[builder.address(event['zvar']) + index] = 0
        else:
            services.append(builder.snapshot(event['spec']))
    if not services:
        raise ValueError('no recognized registration calls')
    return services


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--source', required=True, help='targeted export of 0x7035e766')
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            data = archive.read(FIRMWARE)
        source = pathlib.Path(args.source).read_text()
        services = recover(data, source)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot recover GATT builder: {error}\n')
    print(json.dumps({'member': FIRMWARE, 'member_sha256': hashlib.sha256(data).hexdigest(),
        'builder': 0x7035e766, 'registrar': 0x703b2236,
        'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'branch': 'all preceding registrations succeed', 'services': services,
        'summary': {'services': len(services),
                    'characteristics': sum(s['characteristic_count'] for s in services)}},
        indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
