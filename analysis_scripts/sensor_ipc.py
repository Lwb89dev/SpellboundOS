#!/usr/bin/env python3
"""Host-only model of two observed sensor IPC payload families and IRQ layouts.

This does not implement the outer zrpc framing, pairing or a live transport.
Schema interpretations are supported by matching serializer/parser paths.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import zipfile

MEMBER = 'META/extfw/sensorhub@mhs003_sign.bin'
SOURCES = (0x80f72f60, 0x80f63886, 0x80fa40d4, 0x80fa2cea, 0x80fa3ff8,
           0x80fa3e84, 0x80f86414, 0x80f9914e, 0x80f9a5e6, 0x80f99ea8,
           0x80fa5dd2, 0x80fa5e1c, 0x80fa5e6a, 0x80f99c26)


def unsigned(value, bits):
    if not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise ValueError(f'expected unsigned {bits}-bit value')
    return value


def encode_process(sensor_id, reason):
    return struct.pack('<BBH', 0x10, unsigned(sensor_id, 8), unsigned(reason, 16))


def encode_control(opcode, sensor_id, command, payload=b''):
    if opcode not in (4, 6, 7) or not isinstance(payload, bytes) or len(payload) > 65535:
        raise ValueError('invalid control opcode or payload')
    return struct.pack('<BBHH', opcode, unsigned(sensor_id, 8), unsigned(command, 16), len(payload)) + payload


def decode_payload(data):
    if not isinstance(data, bytes) or not data:
        raise ValueError('empty or non-byte payload')
    if data[0] == 0x10:
        if len(data) != 4:
            raise ValueError('process payload must be exactly four bytes')
        opcode, sensor_id, reason = struct.unpack('<BBH', data)
        return {'opcode': opcode, 'sensor_id': sensor_id, 'reason': reason}
    if data[0] in (4, 6, 7):
        if len(data) < 6:
            raise ValueError('short control header')
        opcode, sensor_id, command, length = struct.unpack_from('<BBHH', data)
        if len(data) != 6 + length:
            raise ValueError('control payload length mismatch')
        return {'opcode': opcode, 'sensor_id': sensor_id, 'command': command,
                'payload': data[6:]}
    raise ValueError('unsupported sensor packet opcode')


def local_irq_message(sensor_id, reason=0):
    return struct.pack('<BBHHH', 1, unsigned(sensor_id, 8), 0, unsigned(reason, 16), 0)


def worker_process_message(sensor_id, reason=0):
    return struct.pack('<II', 5, unsigned(sensor_id, 8) | unsigned(reason, 16) << 16)


def analyze(data, directory):
    hashes = {}
    for address in SOURCES:
        path = pathlib.Path(directory) / f'ram_{address:08x}.c'
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'member': MEMBER, 'member_sha256': hashlib.sha256(data).hexdigest(),
            'serializer': 0x80f9a5e6, 'parser': 0x80f99ea8,
            'integer_byte_order': 'little-endian',
            'process_packet': {'opcode': 16, 'size': 4,
                               'fields': ['opcode:u8', 'sensor_id:u8', 'reason:u16']},
            'control_packets': {'opcodes': [4, 6, 7], 'fixed_header_size': 6,
                                'fields': ['opcode:u8', 'sensor_id:u8', 'command:u16', 'length:u16', 'payload:length']},
            'optical_irq_example': {'sensor_id': 6, 'reason': 0,
                'local_irq_hex': local_irq_message(6).hex(),
                'worker_message_hex': worker_process_message(6).hex(),
                'remote_process_payload_hex': encode_process(6, 0).hex()},
            'source_sha256': hashes,
            'outer_zrpc_transport_implemented': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = analyze(archive.read(MEMBER), args.decompiled)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect sensor IPC: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
