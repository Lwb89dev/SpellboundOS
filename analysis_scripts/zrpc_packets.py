#!/usr/bin/env python3
"""Bounded host codec for reviewed zrpc link/data/ACK packets, OTA 4.6.0.3.

This does not implement rpmsg, fragment reassembly, retries or live hardware.
Unknown/reserved fields are retained. Native error and ownership behavior is
not reproduced by the stricter host length and checksum checks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
else:
    from sensorhub_memory import StartupMemory

MAIN = 'META/firmware_sign.bin'
SENSOR = 'META/extfw/sensorhub@mhs003_sign.bin'
MAIN_HASH = 'a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa'
SENSOR_HASH = '06f07541e8bb22b6118f081e791c3a4e40cbff2decd8ee478a7e82df826e9d0f'
SOURCES = {
    'main': (0x704e9580, 0x704ea184, 0x704ea8f2, 0x704eb056, 0x704eb946, 0x704e8f28,
             0x704e9a48, 0x704eb350, 0x704eb422, 0x704eb476, 0x704eb4c0, 0x704eb7dc),
    'sensor': (0x80f99c26, 0x80f94c0a, 0x80f9d4c6, 0x80f9de06, 0x80f9cfa8, 0x80f9f022),
}


def uint(value, bits):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f'expected unsigned {bits}-bit integer')
    return value


def crc16(data):
    """Reflected polynomial A001, initial FFFF, no final XOR."""
    value = 0xffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xa001 if value & 1 else 0)
    return value


def encode_data(payload, *, source, destination, flags, request, session,
                module, packed=1, reserved=0):
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 65511:
        raise ValueError('data must fit a nonempty link packet')
    if not 0 <= flags <= 7:
        raise ValueError('native data flags must fit three bits')
    return struct.pack('<BBBB6H', 1, uint(source, 8), uint(destination, 8), flags,
        uint(request, 16), uint(session, 16), uint(packed, 16), uint(reserved, 16),
        uint(module, 16), len(payload) + 16) + payload


def encode_ack(*, source, destination, status, session, reserved=0):
    return struct.pack('<4B2H', 2, uint(source, 8), uint(destination, 8),
                       uint(status, 8), uint(session, 16), uint(reserved, 16))


def decode_channel(data):
    if not isinstance(data, bytes) or not data:
        raise ValueError('empty or non-byte channel packet')
    if data[0] == 2:
        if len(data) != 8:
            raise ValueError('ACK must be eight bytes')
        _, source, destination, status, session, reserved = struct.unpack('<4B2H', data)
        return dict(type=2, source=source, destination=destination, status_raw=status,
                    session=session, reserved=reserved)
    if data[0] != 1 or len(data) < 16:
        raise ValueError('unknown type or truncated data header')
    _, source, destination, flags, request, session, packed, reserved, module, size = struct.unpack_from('<4B6H', data)
    if size != len(data) or len(data) <= 16 or flags > 7:
        raise ValueError('invalid data length or flags')
    result = dict(type=1, source=source, destination=destination, flags=flags,
        request=request, session=session, packed=packed, sequence=packed >> 2,
        complete=bool(packed & 1), bit1_raw=bool(packed & 2), reserved=reserved,
        module_raw=module, payload=data[16:])
    if not packed & 1 and packed >> 2 == 0 and len(data) == 28:
        total, count, checksum, spare, timeout = struct.unpack('<4HI', data[16:])
        result['fragment_descriptor'] = dict(total=total, count=count, crc16=checksum,
                                             reserved=spare, timeout_raw=timeout)
    return result


def encode_link(channel, *, checksum):
    decode_channel(channel)
    if len(channel) + 8 > 65535:
        raise ValueError('link length overflows u16')
    return struct.pack('<4H', 0x7a72, crc16(channel) if checksum else 0, 0,
                       len(channel) + 8) + channel


def decode_link(data):
    if not isinstance(data, bytes) or len(data) < 8:
        raise ValueError('truncated link header')
    magic, checksum, reserved, size = struct.unpack_from('<4H', data)
    if magic != 0x7a72 or size != len(data):
        raise ValueError('link magic or length mismatch')
    channel = decode_channel(data[8:])
    required = channel['type'] == 1 and bool(channel['flags'] & 2)
    if required and crc16(data[8:]) != checksum:
        raise ValueError('link checksum mismatch')
    return dict(checksum_raw=checksum, reserved=reserved,
                checksum_required=required, channel=channel)


def evidence(archive, decompiled):
    images = {MAIN: archive.read(MAIN), SENSOR: archive.read(SENSOR)}
    if any(hashlib.sha256(images[member]).hexdigest() != expected
           for member, expected in ((MAIN, MAIN_HASH), (SENSOR, SENSOR_HASH))):
        raise ValueError('annotations require the reviewed main and sensor images')
    memory = StartupMemory(images[MAIN], 0x70160000, 0x270, 4, 0x2a0, 2)
    high, low = memory.read(0x70c0e944, 256), memory.read(0x70c0ea44, 256)
    sensor_memory = StartupMemory(images[SENSOR])
    if sensor_memory.read(0x80fe3900, 256) != high or sensor_memory.read(0x80fe3a00, 256) != low:
        raise ValueError('main and sensor CRC tables differ')
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (0xa001 if value & 1 else 0)
        if high[index] != value >> 8 or low[index] != value & 255:
            raise ValueError('CRC table differs from reflected A001')
    packet = encode_data(bytes.fromhex('10060000'), source=2, destination=1,
                         flags=2, request=7, session=9, module=2)
    return dict(member_sha256={member: hashlib.sha256(data).hexdigest() for member, data in images.items()},
        source_sha256={f'{group}/ram_{address:08x}.c': hashlib.sha256(
            (decompiled / group / f'ram_{address:08x}.c').read_bytes()).hexdigest()
            for group, addresses in SOURCES.items() for address in addresses},
        crc=dict(polynomial_reflected=0xa001, initial=0xffff, final_xor=0,
                 vector_123456789=f'{crc16(b"123456789"):04x}',
                 all_256_table_entries_match=True, main_sensor_tables_identical=True,
                 table_sha256=hashlib.sha256(high + low).hexdigest()),
        reviewed_instruction_ranges_sha256={f'{start:08x}_{end:08x}': hashlib.sha256(
            memory.read(start, end - start)).hexdigest() for start, end in
            ((0x704eb946, 0x704eb986), (0x704ea9ee, 0x704eaa3e), (0x704ea652, 0x704ea6bc))},
        link_header_bytes=8, data_header_bytes=16, ack_bytes=8,
        source_node=dict(main=1, sensor_hub=2),
        synthetic_optical_process_link_hex=encode_link(packet, checksum=True).hex(),
        synthetic_scope='chosen request/session/destination values; not a device capture',
        limitations=['No rpmsg execution, shared-memory/vring implementation or device access.',
            'No native fragment reassembly/retry emulation; AndeStar bit branches need corrected decoding.',
            'CRC and packet fields are independently modeled; endpoint and active routing remain unverified.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=Path, required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = evidence(archive, args.decompiled)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect zrpc packets: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
