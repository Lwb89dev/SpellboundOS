#!/usr/bin/env python3
"""Verify captured native framing/crypto locally; emit counts and booleans only.

The private debug log contains an ephemeral session key printed by Gadgetbridge.
It is used in memory to check captured packets. Neither it, key hashes, counters,
plaintext, padding nor raw packet bytes enter the report. No device is accessed.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

if __package__:
    from .native_channel import (decode, mix_key, inspect_envelope, padding_size,
                                 counter_accepted, transmit_uuid)
else:
    from native_channel import (decode, mix_key, inspect_envelope, padding_size,
                                counter_accepted, transmit_uuid)

WIRE = re.compile(r'(?:WriteAction |onCharacteristicChanged: )([0-9a-fA-F-]{36}) (>@|<@) ([0-9a-fA-F]+)\b')
KEY = re.compile(r'Shared Session Key: ([0-9a-fA-F]+)\b')
SUFFIX = '-0000-3512-2118-0009af100700'


def aes_ecb(key, data, *, encrypt=False):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    context = cipher.encryptor() if encrypt else cipher.decryptor()
    return context.update(data) + context.finalize()


def verify(text, *, on_transfer=None):
    """Verify a capture; an optional local observer receives private payloads.

    The observer is called only after each transfer's framing/CRC checks. The
    returned public report continues to exclude payloads and key material.
    """
    keys = {bytes.fromhex(value) for value in KEY.findall(text)}
    if len(keys) != 1 or len(next(iter(keys))) != 16:
        raise ValueError('requires one captured 16-byte session key')
    key = next(iter(keys))
    tasks, finished, next_counters = {}, [], {}
    packet_types, flags, directions = Counter(), Counter(), Counter()
    route_checks = encrypted_count = counter_checks = exact_successors = 0
    auth = []
    for line in text.splitlines():
        match = WIRE.search(line)
        if not match:
            continue
        uuid, direction = match[1].lower(), match[2]
        if uuid not in ('00000016' + SUFFIX, '00000017' + SUFFIX):
            continue
        packet = decode(bytes.fromhex(match[3]))
        if uuid[4:8] != transmit_uuid(packet.kind, client=direction == '>@'):
            raise ValueError('UUID direction mismatch')
        route_checks += 1
        packet_types[packet.kind] += 1
        if packet.kind != 3:
            continue
        flags[packet.flags] += 1
        task_id = direction, packet.app_id
        if packet.flags & 1:
            if task_id in tasks or packet.sequence != 0 or not 0 < packet.total_size <= 1024 * 1024:
                raise ValueError('invalid or overlapping transfer start')
            tasks[task_id] = [packet, bytearray(), 0]
        if task_id not in tasks:
            raise ValueError('continuation without start')
        first, body, sequence = tasks[task_id]
        if packet.session_id != first.session_id or packet.sequence != sequence:
            raise ValueError('session or sequence mismatch')
        if bool(packet.flags & 8) != bool(first.flags & 8) or not packet.payload:
            raise ValueError('encryption flag mismatch or empty payload')
        expected = first.total_size
        encrypted = bool(first.flags & 8)
        if encrypted:
            expected += 8 + padding_size(expected + 8)
        if len(body) + len(packet.payload) > expected:
            raise ValueError('transfer exceeds declared size')
        body.extend(packet.payload)
        tasks[task_id][2] = (sequence + 1) & 255
        if not packet.flags & 2:
            continue
        if len(body) != expected:
            raise ValueError('incomplete transfer at END')
        del tasks[task_id]
        if encrypted:
            plaintext = aes_ecb(mix_key(key, first.session_id), bytes(body))
            counter = struct.unpack_from('<I', plaintext, first.total_size)[0]
            # Initial counter values are not available independently in this log.
            # CRC/length validation is separate from subsequent counter checks.
            payload, _, _ = inspect_envelope(plaintext, first.total_size, counter)
            if task_id in next_counters:
                counter_checks += 1
                previous = next_counters[task_id]
                if not counter_accepted(counter, previous):
                    raise ValueError('counter outside forward window')
                exact_successors += counter == previous
            next_counters[task_id] = (counter + 1) & 0xffffffff
            encrypted_count += 1
        else:
            payload = bytes(body)
        if on_transfer is not None:
            on_transfer(module_id=first.module_id_wire, direction=direction,
                        encrypted=encrypted, payload=payload)
        if first.module_id_wire == 0x82:
            auth.append((direction, payload))
        directions[direction] += 1
        finished.append({'direction': 'phone_to_watch' if direction == '>@' else 'watch_to_phone',
                         'module_id': first.module_id_wire, 'encrypted': encrypted})
    if tasks or not finished:
        raise ValueError('empty or incomplete capture')
    challenge = next((data[3:19] for direction, data in auth
                      if direction == '<@' and len(data) == 67 and data[:3] == b'\x10\x04\x01'), None)
    proof = next((data[17:33] for direction, data in auth
                 if direction == '>@' and len(data) == 33 and data[0] == 5), None)
    request = next((data for direction, data in auth
                    if direction == '>@' and len(data) == 52 and data[0] == 4), None)
    proof_matches = challenge is not None and proof is not None and aes_ecb(key, challenge, encrypt=True) == proof
    success = any(direction == '<@' and data == b'\x10\x05\x01' for direction, data in auth)
    return {'native_packet_count': sum(packet_types.values()), 'packet_types': dict(packet_types),
            'flags_histogram': dict(flags), 'route_checks_passed': route_checks,
            'completed_transfers': len(finished), 'pending_transfers': len(tasks),
            'encrypted_transfers_verified': encrypted_count,
            'plaintext_transfers_verified': len(finished) - encrypted_count,
            'transfer_directions': dict(directions),
            'subsequent_counter_checks_passed': counter_checks,
            'exact_counter_successors': exact_successors,
            'independent_initial_counter_check': False,
            'auth_success_response_observed': success,
            'auth_session_key_proof_matches': proof_matches,
            'auth_api_level_wire': struct.unpack_from('<H', request, 1)[0] if request else None,
            'auth_mode': request[3] if request else None,
            'modules_seen': sorted({entry['module_id'] for entry in finished}),
            'crypto': 'AES-128 ECB; session-byte XOR of all 16 key bytes; CRC-32 and explicit sizes',
            'scope': 'one captured Gadgetbridge session, not pairing/key-derivation or replay-security proof',
            'privacy': 'counts and booleans; no key/key hash, counters, plaintext, padding or raw packets'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    try:
        raw = args.log.read_bytes()
        report = verify(raw.decode())
        report['private_log_sha256'] = hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, ImportError) as error:
        parser.exit(2, f'Cannot verify captured channel: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
