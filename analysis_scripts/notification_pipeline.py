#!/usr/bin/env python3
"""Inspect stock notification listeners and model one reviewed eviction rule.

Offline only. Startup RAM is reconstructed, never sampled from a device. The
selector models the ordinary list's per-app eviction, not the complete native
notification service, allocation behavior, UI, or special storage/sticky paths.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .native_channel import BASE, MEMBER
    from .sensorhub_memory import StartupMemory
else:
    from native_channel import BASE, MEMBER
    from sensorhub_memory import StartupMemory

REVIEWED_SHA256 = 'a751910b1a4fdbe75f7e4a5cf38c8992f99e2de02c74283125a62f72ed8abafa'
LISTENERS = 0x709e4e28
LISTENER_ROLES = ('legacy_message', 'reply_result', 'logo_result', 'message_image_result', 'rich_message')
SOURCES = {
    'runtime-service-dispatch': ('7038946a',),
    'runtime-notification-listeners': ('7020df76',),
    'runtime-notification-consumers': ('704dae72', '704d613e', '704d1eb2', '704d8eb0', '704d46cc', '70278c7e'),
    'runtime-notification-worker': ('704dcf18', '704d1cc0'),
    'runtime-notification-store': ('704dc928', '704db476', '704db5fe', '704d1c34', '704db37c'),
    'runtime-notification-admission': ('704dc528', '704d9dc0', '704d1aa8'),
    'runtime-notification-ui': ('704d18f8', '704d9204', '704d9250'),
    'runtime-notification-screen': ('704d1516',),
    'runtime-notification-resource': ('704d18a6', '704d1878', '704d184a', '704d1820', '704d17f6'),
    'runtime-notification-render': ('704d16b2', '704d1754', '704d1424'),
    'runtime-notification-alert': ('704d98c6', '704d967a'),
}
BLOCKED_SCREENS = (0x70a49afc, 0x70a49b7c, 0x70a362e8, 0x70c08c7c,
                   0x70c08c9c, 0x70c08cb0, 0x70a1a9e8, 0x70c08cc4)


def inspect_listeners(memory, address=LISTENERS, count=2):
    """Read the Android array of pointers to 24-byte records; not the iOS ABI."""
    if not 1 <= count <= 16 or address % 4:
        raise ValueError('invalid Android listener array')
    pointers = struct.unpack('<' + 'I' * count, memory.read(address, count * 4))
    result = []
    for pointer in pointers:
        if not pointer or pointer % 4:
            raise ValueError('null or unaligned Android listener record')
        name, *callbacks = struct.unpack('<6I', memory.read(pointer, 24))
        label = memory.string(name)
        if not label:
            raise ValueError('empty Android listener name')
        for callback in callbacks:
            if callback:
                if callback % 2:
                    raise ValueError('unaligned RISC-V callback')
                memory.read(callback, 2)
        result.append({'address': pointer, 'name': label,
                       'callbacks': dict(zip(LISTENER_ROLES, callbacks))})
    return result


@dataclass(frozen=True)
class EvictionRecord:
    app_id: bytes | None
    timestamp_raw: int
    priority_word_raw: int = 0

    def __post_init__(self):
        if self.app_id is not None and not isinstance(self.app_id, bytes):
            raise ValueError('app ID must be bytes or None')
        if self.app_id is not None and b'\0' in self.app_id:
            raise ValueError('app ID must exclude its native terminator')
        for value in (self.timestamp_raw, self.priority_word_raw):
            if type(value) is not int or not 0 <= value <= 0xffffffff:
                raise ValueError('record words must be unsigned 32-bit integers')


def select_app_eviction(records, app_id):
    """Return index among the first 20 matching records, or None below 20.

    Zero at record +0x20 wins over nonzero, then smaller timestamp +0x1c;
    ties choose the later scanned record. This is before global capacity and
    after expiration/clock-rollback handling. The word's UI meaning is unknown.
    """
    EvictionRecord(app_id, 0)
    if app_id is None:
        return None
    matches = []
    for index, record in enumerate(records):
        if record.app_id == app_id:
            matches.append((bool(record.priority_word_raw), record.timestamp_raw, -index, index))
            if len(matches) == 20:
                return min(matches)[3]
    return None


def evidence(image, decompiled):
    digest = hashlib.sha256(image).hexdigest()
    if digest != REVIEWED_SHA256:
        raise ValueError('native route annotations require the reviewed OTA main image')
    memory = StartupMemory(image, BASE, 0x270, 4, 0x2a0, 2)
    sources = {f'{group}/{address}.c': hashlib.sha256(
        (decompiled / group / f'{address}.c').read_bytes()).hexdigest()
        for group, addresses in SOURCES.items() for address in addresses}
    return {
        'member': MEMBER, 'member_sha256': digest,
        'listener_array': {'address': LISTENERS, 'count': 2, 'records': inspect_listeners(memory)},
        'legacy_route': {'initializer': 0x7020df76, 'dispatcher': 0x7038946a,
            'listener': 0x704dae72, 'queue_payload_bytes': 36, 'worker': 0x704dcf18,
            'construct_record': 0x704dc928, 'admit_record': 0x704dc528,
            'notify_subscribers_and_gate_alert': 0x704d9dc0,
            'request_resource': 0x704d18f8, 'resource_start': 0x704d18a6,
            'resource_event_worker': 0x704d16b2, 'alert_entry': 0x704d98c6,
            'screen_name': memory.string(0x709c1334), 'screen_argument_bytes': 16},
        'ordinary_store': {'base': 0x70fc2e80, 'count_address': 0x70f8f7c0,
            'record_bytes': 112, 'capacity': 400, 'per_app_eviction_threshold': 20,
            'uid_offset': 0x28, 'app_id_pointer_offset': 0x30,
            'timestamp_offset': 0x1c, 'priority_word_offset': 0x20,
            'expiry_comparison': 'type byte +0x12 == 1 and word +0x18 < current time; units unverified'},
        'subscriber_registry': {'base': 0x70fc2840, 'slots': 3, 'slot_bytes': 8,
            'register': 0x704d9204, 'unregister': 0x704d9250,
            'adapter_callbacks': list(struct.unpack('<3I', memory.read(0x70f697e4, 12))),
            'event_kinds': {'0': 'arrival', '1': 'removed (zeroed record)',
                            '2': 'modified', '3': 'pre-change callback'}},
        'wire_events': {'0': 'add', '1': 'modify existing UID', '2': 'remove existing UID'},
        'alert_screen_exclusions': {str(address): memory.string(address) for address in BLOCKED_SCREENS},
        'canonical_app_ids': {'category_5': memory.string(0x70c09954),
                              'category_1': memory.string(0x70c09960)},
        'resource_manager_name': memory.string(0x70c06cf0),
        'source_sha256': sources,
        'limitations': [
            'Static control flow, not device execution or observed rendering.',
            'Per-app selector models only ordinary admission after expiration and clock rollback.',
            'Storage-class byte +0x12 == 2 admission has unresolved tail-call/stack decompilation; distinct from category/type +0x24.',
            'Sticky/rich notifications, allocation failure and all UI gate semantics are not fully modeled.',
            'The advertised wire maximum 100 is distinct from the 400-slot internal store.',
        ],
        'reviewed_instruction_ranges_sha256': {
            'per_app_scan_704dc5fe_704dc62e': hashlib.sha256(memory.read(0x704dc5fe, 0x30)).hexdigest(),
            'per_app_choice_704dc89a_704dc8e2': hashlib.sha256(memory.read(0x704dc89a, 0x48)).hexdigest(),
            'capacity_insert_704dc7ea_704dc836': hashlib.sha256(memory.read(0x704dc7ea, 0x4c)).hexdigest(),
            'screen_launch_704d9aa4_704d9abc': hashlib.sha256(memory.read(0x704d9aa4, 0x18)).hexdigest(),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', required=True, type=Path)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            image = archive.read(MEMBER)
        report = evidence(image, args.decompiled)
    except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect notification pipeline: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
