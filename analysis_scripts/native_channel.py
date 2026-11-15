#!/usr/bin/env python3
"""Offline models of the observed Bip 6 native channel, not a Bluetooth client.

Wire decoding preserves the watch parser's ignored tails and u16-to-u8 module
conversion. Reassembly is deliberately limited to one plaintext transfer; it
does not implement authentication, dispatch, timeouts or the vendor task queue.
Crypto helpers describe the bytes *before* encryption, using caller-supplied
padding. No device keys, cipher implementation or pairing are included.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

BASE = 0x70160000
MEMBER = 'META/firmware_sign.bin'
CRC_TABLE = 0x709bc4fc
START, END, ACK, ENCRYPTED = 1, 2, 4, 8


def uint(value, bits):
    if not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise ValueError(f'expected unsigned {bits}-bit integer')
    return value


@dataclass(frozen=True)
class Packet:
    kind: int
    flags: int = 0
    app_id: int = 0
    session_id: int = 0
    sequence: int = 0
    total_size: int | None = None
    module_id: int | None = None
    module_id_wire: int | None = None
    status: int | None = None
    control_value: int | None = None
    payload: bytes = b''
    ignored_trailing: bytes = b''


def decode(wire):
    """Observed parser, including acceptance of empty type-3 payloads."""
    wire = bytes(wire)
    if not wire:
        raise ValueError('empty packet')
    kind = wire[0]
    minimum = {1: 1, 2: 2, 3: 5, 4: 5}.get(kind)
    if minimum is None:
        raise ValueError('unknown packet type')
    if len(wire) < minimum:
        raise ValueError('truncated header')
    if kind == 1:
        return Packet(kind, ignored_trailing=wire[1:])
    if kind == 2:
        # Serializer writes six bytes; this parser consumes only two.
        return Packet(kind, control_value=wire[1], ignored_trailing=wire[2:])
    if kind == 4:
        return Packet(kind, app_id=wire[1], session_id=wire[2],
                      status=wire[3], sequence=wire[4], ignored_trailing=wire[5:])
    flags, app, session, sequence = wire[1:5]
    total = module = module_wire = None
    offset = 5
    if flags & START:
        if len(wire) < 11:
            raise ValueError('truncated extended header')
        total, module_wire = struct.unpack_from('<IH', wire, 5)
        module = module_wire & 255
        offset = 11
    return Packet(kind, flags=flags, app_id=app, session_id=session, sequence=sequence,
                  total_size=total, module_id=module, module_id_wire=module_wire,
                  payload=wire[offset:])


def encode_probe():
    return b'\x01'


def encode_control(field1, field2, field3, word):
    """Type 2 serializer; field names stay neutral pending full negotiation RE."""
    return bytes((2, uint(field1, 8), uint(field2, 8), uint(field3, 8))) + struct.pack('<H', uint(word, 16))


def encode_ack(app_id, session_id, status, sequence):
    return bytes((4, uint(app_id, 8), uint(session_id, 8), uint(status, 8), uint(sequence, 8)))


def encode_data(flags, app_id, session_id, sequence, payload, *, total_size=None, module_id=None):
    header = bytes((3, uint(flags, 8), uint(app_id, 8), uint(session_id, 8), uint(sequence, 8)))
    if flags & START:
        # The serializer zero-extends an in-memory byte into a u16 wire field.
        header += struct.pack('<IH', uint(total_size, 32), uint(module_id, 8))
    elif total_size is not None or module_id is not None:
        raise ValueError('extended fields require START')
    payload = bytes(payload)
    if not payload:
        raise ValueError('serializer requires a nonempty payload')
    return header + payload


def transmit_uuid(kind, *, client=False):
    """Short custom UUID for the observed local server/client TX path."""
    if kind not in (1, 2, 3, 4):
        raise ValueError('unknown packet type')
    data = kind in (1, 3)
    return '0016' if data == client else '0017'


def accepts_uuid(uuid, kind):
    return (uuid == '0016' and kind in (2, 4)) or (uuid == '0017' and kind in (1, 3))


def fragment_plaintext(payload, app_id, module_id, session_id, capacity, *, final_ack=True):
    """Model the observed header budget and periodic ACK-request policy.

    Capacity is a native transport callback result, not an ATT MTU. Host
    validation excludes underflow/non-progress cases; it is not a firmware fix.
    """
    payload = bytes(payload)
    if not payload or len(payload) > 0xffffffff:
        raise ValueError('invalid payload length')
    if not 12 <= capacity <= 65535:
        raise ValueError('capacity must allow an extended header and payload')
    packets, offset, sequence = [], 0, 0
    while offset < len(payload):
        first = offset == 0
        count = min(capacity - (11 if first else 5), len(payload) - offset)
        flags = START if first else 0
        if offset + count == len(payload):
            flags |= END | (ACK if final_ack else 0)
        elif (sequence + 1) % (7808 // capacity if capacity < 244 else 32) == 0:
            flags |= ACK
        packets.append(encode_data(flags, app_id, session_id, sequence, payload[offset:offset + count],
                                   total_size=len(payload) if first else None,
                                   module_id=module_id if first else None))
        sequence = (sequence + 1) & 255
        offset += count
    return packets


class PlaintextTransfer:
    """Strict host inspector for one transfer; errors invalidate its state.

    Each feed accepts a wire packet. Missing/extra/reordered chunks fail. A
    caller can inspect ACK flags separately; this class never transmits ACKs.
    """
    def __init__(self, max_size=1024 * 1024):
        if not 0 < max_size <= 0xffffffff:
            raise ValueError('invalid host size bound')
        self.max_size = max_size
        self.state = None

    def feed(self, wire):
        try:
            return self._feed(decode(wire))
        except ValueError:
            self.state = None
            raise

    def _feed(self, packet):
        if packet.kind != 3 or packet.flags & ENCRYPTED:
            raise ValueError('requires plaintext type 3')
        if not packet.payload or len(packet.payload) > 65535:
            raise ValueError('invalid host chunk length')
        if packet.flags & START:
            if self.state is not None:
                raise ValueError('overlapping transfer')
            if packet.sequence != 0 or not 0 < packet.total_size <= self.max_size:
                raise ValueError('invalid start sequence or declared size')
            self.state = (packet.app_id, packet.session_id, packet.total_size, 0, bytearray())
        if self.state is None:
            raise ValueError('continuation without START')
        app, session, total, sequence, data = self.state
        if (packet.app_id, packet.session_id, packet.sequence) != (app, session, sequence):
            raise ValueError('app, session or sequence mismatch')
        if len(data) + len(packet.payload) > total:
            raise ValueError('payload exceeds declared size')
        data.extend(packet.payload)
        self.state = (app, session, total, (sequence + 1) & 255, data)
        if packet.flags & END:
            if len(data) != total:
                raise ValueError('END before declared size')
            self.state = None
            return bytes(data)
        return None


def mix_key(key, session_id):
    key = bytes(key)
    if len(key) != 16:
        raise ValueError('requires a 16-byte key')
    session_id = uint(session_id, 8)
    return bytes(value ^ session_id for value in key)


def padding_size(size):
    uint(size, 32)
    return -size % 16


def counter_accepted(received, expected):
    return ((uint(received, 32) - uint(expected, 32)) & 0xffffffff) <= 100000


def make_envelope(payload, counter, *, padding):
    """Construct pre-encryption bytes. Padding is explicit, never inferred."""
    body = bytes(payload) + struct.pack('<I', uint(counter, 32))
    padding = bytes(padding)
    if len(padding) != padding_size(len(body) + 4):
        raise ValueError('incorrect explicit padding length')
    return body + struct.pack('<I', zlib.crc32(body)) + padding


def inspect_envelope(plaintext, payload_size, expected_counter):
    """Inspect externally decrypted bytes using the declared plaintext size."""
    plaintext = bytes(plaintext)
    uint(payload_size, 32)
    uint(expected_counter, 32)
    if len(plaintext) != payload_size + 8 + padding_size(payload_size + 8):
        raise ValueError('incorrect envelope size')
    counter, crc = struct.unpack_from('<II', plaintext, payload_size)
    if crc != zlib.crc32(plaintext[:payload_size + 4]):
        raise ValueError('CRC mismatch')
    if not counter_accepted(counter, expected_counter):
        raise ValueError('counter outside acceptance window')
    return plaintext[:payload_size], counter, plaintext[payload_size + 8:]


def crc_table():
    table = []
    for value in range(256):
        for _ in range(8):
            value = value >> 1 ^ (0xedb88320 if value & 1 else 0)
        table.append(value)
    return struct.pack('<256I', *table)


def crc_evidence(image, base=BASE, address=CRC_TABLE):
    offset = address - base
    if not 0 <= offset <= len(image) - 1024:
        raise ValueError('CRC table outside image')
    actual = image[offset:offset + 1024]
    return {'address': address, 'size': len(actual), 'sha256': hashlib.sha256(actual).hexdigest(),
            'all_256_entries_match': actual == crc_table(), 'reflected_polynomial': 0xedb88320}


SOURCES = {
    'runtime-channel': ['7036d0ae', '7036d368', '7036d9e4', '7036e1da', '703d0418', '703d044a', '703d047e'],
    'runtime-channel-policy': ['7021766c', '7036b430', '7036b8be', '7036c3ce', '7036cac0', '7036d672'],
    'runtime-channel-crypto': ['70215946', '70215c9c', '702158e0', '70215902', '702159ac', '7021624c',
                               '70215b60', '702838de'],
    'runtime-channel-aes': ['70282c9c', '70282ef8', '7036d64a'],
    'runtime-channel-crc': ['70161360', '703d0fe0', '703bf368'],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', required=True, type=Path)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            image = archive.read(MEMBER)
        evidence = crc_evidence(image)
        if not evidence['all_256_entries_match']:
            raise ValueError('unexpected CRC table')
        sources = {f'{directory}/{address}.c': hashlib.sha256(
            (args.decompiled / directory / f'{address}.c').read_bytes()).hexdigest()
            for directory, addresses in SOURCES.items() for address in addresses}
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect native channel: {error}\n')
    # Function roles are reviewed findings, not machine-inferred from the C.
    print(json.dumps({'member': MEMBER, 'member_sha256': hashlib.sha256(image).hexdigest(),
        'source_sha256': sources, 'crc_table': evidence,
        'reviewed_functions': {'parser': 0x7036d0ae, 'serializer': 0x7036d368,
            'tx_manager': 0x7036b430, 'rx_manager': 0x7036b8be, 'auth_initializer': 0x7021766c,
            'crypto_registrar': 0x7036c3ce, 'key_mixing': 0x7036d64a, 'counter_window': 0x7036d672,
            'crc_wrapper': 0x703d0fe0, 'crc_update': 0x70161360},
        'reviewed_crypto_delegate': {'size': 28, 'enabled_byte_offset': 0,
            'callbacks': {'4': 0x70215946, '8': 0x70215c9c, '12': 0x702158e0,
                          '16': 0x70215902, '20': 0x702159ac, '24': 0x7021624c}},
        'synthetic_vectors': {'probe': encode_probe().hex(),
            'control_enabled': encode_control(2, 1, 1, 1).hex(),
            'single_plaintext': encode_data(7, 0x12, 0x34, 0, b'abc', total_size=3, module_id=0x56).hex(),
            'ack': encode_ack(0x12, 0x34, 1, 0).hex(),
            'crc_123456789': f'{zlib.crc32(b"123456789"):08x}'},
        'scope': 'offline host models; no pairing, device execution or cipher interoperability proof'},
        indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
