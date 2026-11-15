#!/usr/bin/env python3
"""Offline authentication layouts and static provider/curve evidence.

This does not pair, generate private scalars, invoke firmware crypto, access
stored device keys or send Bluetooth packets. Store helpers accept only bytes
supplied by the caller; examples/tests use synthetic material.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .native_channel import BASE, MEMBER, uint
    from .sensorhub_memory import StartupMemory
else:
    from native_channel import BASE, MEMBER, uint
    from sensorhub_memory import StartupMemory

PROVIDER = 0x70f60f70
PROVIDER_ROLES = ('initialize', 'save_key', 'load_key', 'query_app_ids',
                  'insert_context', 'remove_connection', 'lookup_app_context', 'list_contexts')
# Public sect163r2 parameters, independently compared with installed OpenSSL's
# explicit parameters. The firmware uses six little-endian u32 words per value.
CURVE_PARAMETERS = {
    'order': (0x709e8b10, 0x040000000000000000000292fe77e70c12a4234c33),
    'generator_y': (0x709e8b28, 0x00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1),
    'generator_x': (0x709e8b40, 0x03f0eba16286a2d57ea0991168d4994637e8343e36),
    'b': (0x709e8b58, 0x020a601907b8c953ca1481eb10512f78744a3205fd),
    'field_polynomial': (0x709e8b70, (1 << 163) | (1 << 7) | (1 << 6) | (1 << 3) | 1),
}
REQUEST_LAYOUTS = {
    0: (), 1: (16,), 2: (48,), 3: (64,), 4: (48,), 5: (16, 16),
    6: (), 7: (16, 16), 8: (), 9: (), 10: (), 11: (),
}


@dataclass(frozen=True)
class Request:
    opcode: int
    api_level_wire: int | None
    api_level: int | None
    mode: int | None
    values: tuple[bytes, ...]
    ignored_trailing: bytes


def decode_request(payload):
    payload = bytes(payload)
    if not payload or payload[0] not in REQUEST_LAYOUTS:
        raise ValueError('empty or unsupported auth opcode')
    opcode, offset = payload[0], 1
    api_wire = mode = None
    if opcode in (1, 2, 4):
        if len(payload) < offset + 2:
            raise ValueError('truncated API level')
        api_wire = struct.unpack_from('<H', payload, offset)[0]
        offset += 2
    if opcode == 4:
        if len(payload) <= offset:
            raise ValueError('truncated authorize mode')
        mode = payload[offset]
        offset += 1
    values = []
    for size in REQUEST_LAYOUTS[opcode]:
        if len(payload) < offset + size:
            raise ValueError('truncated auth value')
        values.append(payload[offset:offset + size])
        offset += size
    # Unknown modes are retained; the controller rejects values other than 1/2.
    return Request(opcode, api_wire, None if api_wire is None else api_wire & 255,
                   mode, tuple(values), payload[offset:])


def encode_request(opcode, *, api_level=None, mode=None, values=()):
    if opcode not in REQUEST_LAYOUTS:
        raise ValueError('unsupported auth opcode')
    prefix = bytes((opcode,))
    if opcode in (1, 2, 4):
        prefix += struct.pack('<H', uint(api_level, 16))
    elif api_level is not None:
        raise ValueError('API level not present in this request')
    if opcode == 4:
        prefix += bytes((uint(mode, 8),))
    elif mode is not None:
        raise ValueError('mode not present in this request')
    values = tuple(bytes(value) for value in values)
    if tuple(map(len, values)) != REQUEST_LAYOUTS[opcode]:
        raise ValueError('incorrect auth value sizes')
    return prefix + b''.join(values)


def derive_material(persistent_key, shared_point):
    """Observed slicing/XOR after scalar multiplication, not ECDH itself.

    The native scalar multiplier writes X || Y, each 24-byte little endian.
    Only the first 24 bytes (X) enter the resulting channel context.
    """
    persistent_key, shared_point = bytes(persistent_key), bytes(shared_point)
    if len(persistent_key) != 16 or len(shared_point) != 48:
        raise ValueError('requires a 16-byte persistent key and 48-byte shared point')
    rx, tx = struct.unpack_from('<II', shared_point)
    key = bytes(left ^ right for left, right in zip(persistent_key, shared_point[8:24]))
    return key, rx, tx


def cloud_binding_digest(device_address, watch_public_point):
    device_address, watch_public_point = bytes(device_address), bytes(watch_public_point)
    if len(device_address) != 6 or len(watch_public_point) != 48:
        raise ValueError('requires raw 6-byte address and 48-byte point')
    # Address bytes are supplied in firmware order; display/MAC reversal is unresolved.
    return hashlib.sha256(device_address + watch_public_point).digest()


def checked_store(store):
    store = bytes(store)
    if len(store) != 144:
        raise ValueError('requires eight 18-byte records')
    return store


def load_key(store, app_id):
    store, app_id = checked_store(store), uint(app_id, 8)
    for offset in range(0, 144, 18):
        if store[offset] and store[offset + 1] == app_id:
            return store[offset + 2:offset + 18]
    return None


def save_key(store, app_id, key):
    store, app_id, key = bytearray(checked_store(store)), uint(app_id, 8), bytes(key)
    if len(key) != 16:
        raise ValueError('requires a 16-byte key')
    selected = next((offset for offset in range(0, 144, 18)
                     if store[offset + 1] == app_id or not store[offset]), None)
    if selected is None:
        raise ValueError('persistent key table full')
    for offset in range(0, 144, 18):
        if offset != selected and store[offset + 1] == app_id:
            store[offset:offset + 2] = b'\x00\xff'
    # Invalidated duplicate records retain their sixteen previous key bytes.
    store[selected:selected + 18] = bytes((1, app_id)) + key
    return bytes(store)


def inspect_image(image):
    memory = StartupMemory(image, BASE, 0x270, 4, 0x2a0, 2)
    pointers = struct.unpack('<8I', memory.read(PROVIDER, 32))
    if any(value & 1 or not BASE <= value < BASE + len(image) for value in pointers):
        raise ValueError('unexpected auth provider callback')
    curves = {}
    for name, (address, expected) in CURVE_PARAMETERS.items():
        raw = memory.read(address, 24)
        curves[name] = {'address': address, 'size': 24,
                        'sha256': hashlib.sha256(raw).hexdigest(),
                        'matches_sect163r2': int.from_bytes(raw, 'little') == expected}
    return {'provider': {'address': PROVIDER, 'size': 32,
                         'callbacks': dict(zip(PROVIDER_ROLES, pointers))},
            'public_curve_parameters': curves,
            'all_parameters_match_sect163r2': all(v['matches_sect163r2'] for v in curves.values())}


SOURCES = {
    'runtime-auth-context': ['70215884', '7021581a', '70215588', '7021563c', '702160bc',
                             '702163a0', '70216176', '702173e4', '70216f5c'],
    'runtime-auth-lifecycle': ['702153f6', '70215364', '70215774', '70216274', '702163e6',
                               '702164be', '70216b12', '7021631e', '70216e40', '70215da6', '70216112'],
    'runtime-auth-proof': ['70215234', '702152b6', '7021657c', '702160cc', '704ee552'],
    'runtime-auth-module': ['7035cb58', '7035be3e', '7035bcf6', '7035bcce', '7035bce0',
                            '70214d8c', '70214d72', '70214ed0'],
    'runtime-auth-wire': ['7035bd28', '7035caec', '7035ca80', '7035ca14', '703d057a'],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=Path, required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            image = archive.read(MEMBER)
        report = inspect_image(image)
        if not report['all_parameters_match_sect163r2']:
            raise ValueError('unexpected ECDH public curve parameters')
        sources = {f'{directory}/{address}.c': hashlib.sha256(
            (args.decompiled / directory / f'{address}.c').read_bytes()).hexdigest()
            for directory, addresses in SOURCES.items() for address in addresses}
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect auth session: {error}\n')
    report.update({'member': MEMBER, 'member_sha256': hashlib.sha256(image).hexdigest(),
        'source_sha256': sources, 'reviewed_module_id': 0x82, 'reviewed_api_level': 2,
        'reviewed_controller': 0x7035cb58, 'reviewed_dispatcher': 0x7035be3e,
        'synthetic_requests': {'query_version': encode_request(0).hex(),
            'request_authorize': encode_request(4, api_level=2, mode=1, values=(bytes(range(48)),)).hex(),
            'authorize': encode_request(5, values=(bytes(range(16)), bytes(range(16, 32)))).hex()},
        'scope': 'static metadata and synthetic host models; no pairing or vendor crypto execution'})
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
