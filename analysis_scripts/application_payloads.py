#!/usr/bin/env python3
"""Host-only layouts for selected notification, phone-pairing and map commands.

No Bluetooth/ADB access or device writes. Strings remain byte strings because
the native reader uses NUL termination, not a verified character encoding.
This covers selected commands, not the full modules or a companion app.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .native_channel import MEMBER, uint
else:
    from native_channel import MEMBER, uint


class Reader:
    def __init__(self, data):
        self.data, self.pos = bytes(data), 0
        if len(self.data) > 1024 * 1024:
            raise ValueError('host payload size bound exceeded')

    def integer(self, size):
        if self.pos + size > len(self.data):
            raise ValueError('truncated field')
        value = int.from_bytes(self.data[self.pos:self.pos + size], 'little')
        self.pos += size
        return value

    def string(self):
        end = self.data.find(b'\0', self.pos)
        if end < 0:
            raise ValueError('unterminated string')
        value, self.pos = self.data[self.pos:end], end + 1
        return value

    def remaining(self):
        return self.data[self.pos:]


def string(value):
    if not isinstance(value, bytes) or b'\0' in value:
        raise ValueError('requires bytes without an embedded NUL')
    return value + b'\0'


def decode_notification(data):
    reader = Reader(data)
    if reader.integer(1) != 3:
        raise ValueError('only notification opcode 3 is modeled')
    identifier, kind, subtype = reader.integer(4), reader.integer(1), reader.integer(1)
    fields = tuple(reader.string() for _ in range(5 if kind == 3 else 4))
    boolean0 = bool(reader.integer(1))
    optional_byte = reader.integer(1) if reader.remaining() else None
    optional_bool = bool(reader.integer(1)) if reader.remaining() else None
    optional_string = reader.string() if reader.remaining() else None
    return {'identifier': identifier, 'kind': kind, 'subtype': subtype, 'fields': fields,
            'boolean0': boolean0, 'optional_byte': optional_byte, 'optional_bool': optional_bool,
            'optional_string': optional_string, 'ignored_trailing': reader.remaining()}


def encode_notification(identifier, kind, subtype, fields, boolean0, *, optional_byte=None,
                        optional_bool=None, optional_string=None):
    fields = tuple(fields)
    if len(fields) != (5 if kind == 3 else 4):
        raise ValueError('incorrect string field count for notification kind')
    data = struct.pack('<BIBB', 3, uint(identifier, 32), uint(kind, 8), uint(subtype, 8))
    data += b''.join(string(value) for value in fields) + bytes((bool(boolean0),))
    if optional_byte is not None:
        data += bytes((uint(optional_byte, 8),))
    elif optional_bool is not None or optional_string is not None:
        raise ValueError('optional fields must be consecutive')
    if optional_bool is not None:
        data += bytes((bool(optional_bool),))
    elif optional_string is not None:
        raise ValueError('optional string requires the preceding boolean')
    if optional_string is not None:
        data += string(optional_string)
    return data


def decode_phone_request(data):
    reader = Reader(data)
    opcode = reader.integer(1)
    result = {'opcode': opcode}
    if opcode in (3, 5):
        result['peer_identifier'] = reader.string()
    elif opcode == 8:
        count = reader.integer(1)
        if count == 0:
            raise ValueError('empty settings update rejected by native branch')
        entries = []
        for _ in range(count):
            kind, value = reader.integer(1), reader.integer(1)
            if kind != 1:
                raise ValueError('unknown phone setting type')
            entries.append((kind, value))
        result.update(settings=tuple(entries), effective_boolean=bool(entries[-1][1]))
    elif opcode not in (1, 6):
        raise ValueError('unsupported phone opcode')
    result['ignored_trailing'] = reader.remaining()
    return result


def decode_map_download(data, *, max_files=256):
    reader = Reader(data)
    if reader.integer(1) != 5:
        raise ValueError('only map-download opcode 5 is modeled')
    total, count = reader.integer(4), reader.integer(2)
    if not total or not 0 < count <= max_files:
        raise ValueError('invalid total/count or host file-count bound exceeded')
    files = tuple(reader.string() for _ in range(count))
    if any(not value for value in files):
        raise ValueError('empty map file identifier')
    explicit_mode = reader.integer(1) if reader.remaining() else None
    if explicit_mode is not None and explicit_mode > 1:
        raise ValueError('unknown map mode')
    return {'total_size': total, 'files': files, 'mode': 1 if explicit_mode is None else explicit_mode,
            'mode_explicit': explicit_mode is not None, 'ignored_trailing': reader.remaining()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=Path, required=True)
    args = parser.parse_args()
    sources = {'runtime-service-dispatch': ['7036a4b6', '7036c636', '7036c834', '7038946a', '7035ed4a', '7038d1e2'],
               'runtime-service-payload': ['703d066c', '7036cab2', '703bc1f8', '7035ec7c', '7038d568', '7038d458', '7038d506']}
    try:
        with zipfile.ZipFile(args.archive) as archive:
            image = archive.read(MEMBER)
        hashes = {f'{directory}/{address}.c': hashlib.sha256(
            (args.decompiled / directory / f'{address}.c').read_bytes()).hexdigest()
            for directory, addresses in sources.items() for address in addresses}
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inventory application payloads: {error}\n')
    print(json.dumps({'member': MEMBER, 'member_sha256': hashlib.sha256(image).hexdigest(),
        'reviewed_modules': {'0x00': {'receive': 0x7036a4b6, 'query_opcode': 3, 'reply_opcode': 4},
            '0x0b': {'receive': 0x7035ed4a, 'modeled_requests': [1, 3, 5, 6, 8], 'role': 'pairing and settings'},
            '0x1e': {'receive': 0x7038946a, 'modeled_requests': [3], 'role': 'notification'},
            '0x46': {'receive': 0x7038d1e2, 'modeled_requests': [5], 'role': 'map download task'}},
        'string_reader': {'address': 0x703d066c, 'terminator': 0,
                          'encoding': 'unverified; host preserves raw bytes'},
        'source_sha256': hashes,
        'synthetic_notification_hex': encode_notification(0x12345678, 1, 0, (b'A', b'B', b'C', b'D'), True).hex(),
        'scope': 'offline selected payload models; no delivery, calls, map download or turn-by-turn navigation performed'},
        indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
