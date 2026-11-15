#!/usr/bin/env python3
"""Compare a captured module-0 service announcement with reviewed native specs.

Only service IDs, policy bytes, callback addresses and input hashes are emitted.
Private traffic is processed locally. The bounded C inspector understands one
zeroed 76-byte descriptor with explicit stack assignments; branches and unknown
expressions are rejected or recorded as unknown, never evaluated as C.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

if __package__:
    from .native_channel import BASE, MEMBER, PlaintextTransfer, decode
    from .sensorhub_memory import StartupMemory
    from .verify_gadgetbridge_channel import WIRE, SUFFIX
else:
    from native_channel import BASE, MEMBER, PlaintextTransfer, decode
    from sensorhub_memory import StartupMemory
    from verify_gadgetbridge_channel import WIRE, SUFFIX

CALL = re.compile(r'(?:func_0x|candidate_)7036(?P<registrar>c636|c834)\((?P<argument>[^)]*)\)')
STACK = r'[a-zA-Z]+Stack_[0-9a-f]+'
ASSIGN = re.compile(r'\b(' + STACK + r')(?:\[(\d+)\]|\._(\d+)_(\d+)_)?\s*=\s*([^;]+);')
LABEL = re.compile(r'Zepp OS Service: endpoint=([0-9a-fA-F]{4}) encrypted=(true|false) name=(unknown|ZeppOs[A-Za-z0-9]+Service)\s*$')
PREFIX_STORES = {
    0x7035a3d2: (0x7035a5be, '930720142312f100', '&scause', 0x142),
    0x7038549e: (0x70385704, '930750102312f100', '&scounteren', 0x105),
    0x7038dc06: (0x7038ddfa, '930740142312f100', '&sip', 0x144),
}


def prefix_store_proof(image, initializer):
    if initializer not in PREFIX_STORES:
        return None
    address, expected, expression, value = PREFIX_STORES[initializer]
    offset = address - BASE
    if image[offset:offset + 8].hex() != expected:
        raise ValueError('module prefix instruction guard failed')
    return {'instruction': address, 'instruction_bytes': expected,
            'expression': expression, 'value': value, 'store_width': 2}


def parse_announcement(payload):
    payload = bytes(payload)
    if len(payload) < 3 or payload[0] != 4:
        raise ValueError('expected module-0 opcode 4')
    count = struct.unpack_from('<H', payload, 1)[0]
    if count > 256 or len(payload) != 3 + count * 3:
        raise ValueError('invalid service count or exact size')
    records, seen = [], set()
    for index in range(count):
        endpoint, encrypted = struct.unpack_from('<HB', payload, 3 + index * 3)
        if endpoint in seen or encrypted not in (0, 1):
            raise ValueError('duplicate endpoint or unknown encryption byte')
        seen.add(endpoint)
        records.append({'module_id': endpoint, 'announced_encrypted': bool(encrypted)})
    return records


def captured_announcement(text):
    transfer, payloads, logged = None, [], []
    for line in text.splitlines():
        if match := re.search(r'Plaintext data 0x0000: ([0-9A-Fa-f]+)\b', line):
            logged.append(bytes.fromhex(match[1]))
        match = WIRE.search(line)
        if not match or match[2] != '<@' or match[1].lower() != '00000017' + SUFFIX:
            continue
        wire = bytes.fromhex(match[3])
        packet = decode(wire)
        if packet.kind != 3:
            continue
        if packet.flags & 1:
            if transfer is not None:
                raise ValueError('interleaved module-0 capture')
            if packet.module_id_wire != 0:
                continue
            transfer = PlaintextTransfer()
        if transfer is not None:
            payload = transfer.feed(wire)
            if payload is not None:
                payloads.append(payload)
                transfer = None
    if transfer is not None or len(payloads) != 1 or logged != payloads:
        raise ValueError('expected one complete native announcement matching decoded log')
    records = parse_announcement(payloads[0])
    labels = [LABEL.search(line) for line in text.splitlines()]
    labels = [match for match in labels if match]
    if len(labels) != len(records):
        raise ValueError('service label/count mismatch')
    for record, match in zip(records, labels):
        if (record['module_id'], record['announced_encrypted']) != (int(match[1], 16), match[2] == 'true'):
            raise ValueError('native announcement differs from Gadgetbridge classification')
        record['gadgetbridge_label'] = None if match[3] == 'unknown' else match[3]
    return records


def descriptor_record(raw):
    if len(raw) != 76:
        raise ValueError('expected 76-byte module descriptor')
    read = lambda offset: None if any(value is None for value in raw[offset:offset + 4]) else int.from_bytes(bytes(raw[offset:offset + 4]), 'little')
    if raw[0] is None:
        raise ValueError('unknown module ID')
    callbacks = {f'{offset:#04x}': read(offset) for offset in range(4, 76, 4) if read(offset)}
    return {'module_id': raw[0], 'require_authorization_raw': raw[1],
            'require_encryption_raw': raw[2], 'reserved_byte': raw[3],
            'callbacks': callbacks,
            'receive_callbacks': {f'{offset:#04x}': read(offset) for offset in (64, 68, 72) if read(offset)},
            'unknown_byte_offsets': [offset for offset, value in enumerate(raw) if value is None]}


def reviewed_assistant_variants(source):
    """Three manually reviewed branches, tied to the exact corrected export.

    This is declared review metadata, not evaluation of conditional C. Only
    branches 1 and 2 are observed in the live announcement.
    """
    if hashlib.sha256(source.encode()).hexdigest() != '818f8763f4e7ca77e51088b96a4cce6b34cfdcd0e16ef774de578d7f531b1ee2':
        raise ValueError('assistant branch review requires the exact reviewed export')
    records = []
    for selector, module, hook, receive in ((1, 0x11, 0x703a4a74, 0x703a4940),
            (2, 0x4a, 0x703a4a64, 0x703a4920), (0, 0x10, 0x703a4a84, 0x703a4960)):
        raw = bytearray(76)
        struct.pack_into('<I', raw, 0, 0x10100 | module)
        for offset, value in ((4, 0x703a4a94), (44, hook), (64, receive)):
            struct.pack_into('<I', raw, offset, value)
        record = descriptor_record(list(raw))
        record.update(initializer=0x703a4aca, registrar=0x7036c636,
                      review='manually reviewed branch', selector_byte=selector)
        records.append(record)
    return records


def recover_descriptor(source, memory=None, prefix_override=None):
    calls = list(CALL.finditer(source))
    if len(calls) != 1:
        raise ValueError('expected one registration call')
    argument = calls[0]['argument'].strip()
    registrar = int('7036' + calls[0]['registrar'], 16)
    if re.fullmatch(r'0x[0-9a-f]+', argument):
        if memory is None:
            raise ValueError('constant descriptor requires mapped image')
        record = descriptor_record(list(memory.read(int(argument, 16), 76)))
        record['registrar'] = registrar
        return record
    root = argument.lstrip('&')
    if not re.fullmatch(STACK, root):
        raise ValueError('unsupported registration argument')
    address = lambda name: 0x100000 - int(name.rsplit('_', 1)[1], 16)
    zeros = list(re.finditer(r'0x70947ce8\)\(\s*&?' + re.escape(root) + r'\s*,\s*0\s*,\s*0x4c\s*\)', source[:calls[0].start()]))
    if not zeros:
        raise ValueError('no explicit descriptor zeroing')
    block = source[zeros[-1].end():calls[0].start()]
    if re.search(r'\b(?:if|else|for|while|switch|goto)\b', block):
        raise ValueError('branching descriptor setup needs separate review')
    if re.search(r'\(\*|\*\s*\(', block):
        raise ValueError('unsupported indirect descriptor mutation')
    if any(name != 'CONCAT22' for name in re.findall(r'\b([A-Za-z_]\w*)\s*\(', block)):
        raise ValueError('unsupported call in descriptor setup')
    widths = {}
    for match in re.finditer(r'\b(undefined[1248]?|code|int|uint|char|byte|short|ushort)\s+(\*)?\s*(' + STACK + r')', source):
        kind, pointer, name = match.groups()
        width = (int(kind[-1]) if kind.startswith('undefined') and kind[-1].isdigit()
                 else {'int': 4, 'uint': 4, 'char': 1, 'byte': 1, 'short': 2, 'ushort': 2}.get(kind))
        if pointer:
            width = 4
        if width:
            widths[name] = width
    raw = [0] * 76
    for match in ASSIGN.finditer(block):
        name, index, partial_offset, partial_width, expression = match.groups()
        if name not in widths:
            raise ValueError('unsupported stack variable type')
        width = int(partial_width) if partial_width else widths[name]
        offset = address(name) - address(root) + (int(partial_offset or 0)) + (int(index or 0) * widths[name])
        if offset >= 76 or offset + width <= 0:
            continue
        if offset < 0 or offset + width > 76:
            raise ValueError('descriptor assignment crosses boundary')
        expression = expression.strip()
        value = None
        if re.fullmatch(r'0x[0-9a-f]+|\d+', expression):
            value = int(expression, 0)
        elif callback := re.fullmatch(r'(?:candidate_|func_0x)([0-9a-f]{8})', expression):
            value = int(callback[1], 16)
        elif (prefix_override and offset == 0 and expression == prefix_override['expression']):
            # Ghidra can label scalar constants as CSR addresses and infer a
            # pointer array. Original LI+SH instructions prove the low-u16 store.
            value, width = prefix_override['value'], prefix_override['store_width']
        elif concat := re.fullmatch(r'CONCAT22\(\s*' + re.escape(name) +
                (r'\[' + index + r'\]' if index is not None else '') + r'\._2_2_,\s*(0x[0-9a-f]+|\d+)\)', expression):
            if width != 4:
                raise ValueError('unsupported CONCAT22 width')
            low = int(concat[1], 0)
            raw[offset:offset + 2] = [low & 255, low >> 8 & 255]
            continue
        raw[offset:offset + width] = ([None] * width if value is None else
                                     [(value >> (8 * index)) & 255 for index in range(width)])
    record = descriptor_record(raw)
    record['registrar'] = registrar
    if prefix_override:
        record['raw_prefix_store'] = prefix_override
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--registrations', type=Path, required=True)
    args = parser.parse_args()
    try:
        capture = args.capture.read_bytes()
        live = captured_announcement(capture.decode())
        with zipfile.ZipFile(args.archive) as archive:
            image = archive.read(MEMBER)
        memory = StartupMemory(image, BASE, 0x270, 4, 0x2a0, 2)
        recovered, unresolved, hashes = [], [], {}
        for path in sorted(args.registrations.glob('*.c')):
            source = path.read_text()
            initializer = int(path.stem, 16)
            hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
            try:
                if initializer == 0x703a4aca:
                    recovered.extend(reviewed_assistant_variants(source))
                    continue
                record = recover_descriptor(source, memory, prefix_store_proof(image, initializer))
                record['initializer'] = initializer
                recovered.append(record)
            except ValueError as error:
                unresolved.append({'initializer': int(path.stem, 16), 'reason': str(error)})
        by_id = {}
        for record in recovered:
            by_id.setdefault(record['module_id'], []).append(record)
        for record in live:
            specs = by_id.get(record['module_id'], [])
            record['static_candidates'] = specs
            known = [spec for spec in specs if spec['require_encryption_raw'] is not None]
            record['encryption_policy_match'] = None if not known else any(
                bool(spec['require_encryption_raw']) == record['announced_encrypted'] for spec in known)
        report = {'member': MEMBER, 'member_sha256': hashlib.sha256(image).hexdigest(),
                  'private_capture_sha256': hashlib.sha256(capture).hexdigest(),
                  'registration_source_sha256': hashes, 'services': live,
                  'static_descriptors': recovered, 'unresolved_initializers': unresolved,
                  'summary': {'announced_services': len(live), 'static_descriptors_recovered': len(recovered),
                    'live_services_with_static_candidate': sum(bool(record['static_candidates']) for record in live),
                    'live_encryption_mismatches': sum(record['encryption_policy_match'] is False for record in live)},
                  'scope': 'one native module-0 announcement and bounded explicit descriptor setups; no phone/watch access'}
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect application services: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
