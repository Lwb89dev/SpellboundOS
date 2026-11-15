#!/usr/bin/env python3
"""Extract and classify Bluetooth GATT UUID strings from the main firmware.

The inspector scans a firmware member of the OTA archive for 128-bit UUID
string literals and classifies each one against well-known bases and the
published Apple ANCS/AMS assignments. Huami/Zepp custom UUIDs share the base
``-0000-3512-2118-0009af100700``; the leading 32-bit field is reported as the
short id.

This is a literal string scan of vendor firmware, not proof that a service is
advertised, enabled, or reachable at runtime. The classification of the
non-standard custom UUIDs beyond ANCS/AMS is left open.
"""
import argparse
import hashlib
import json
import re
import zipfile

FIRMWARE = 'META/firmware_sign.bin'

UUID_RE = re.compile(
    rb'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    rb'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')

HUAMI_BASE = '-0000-3512-2118-0009af100700'
BT_SIG_BASE = '-0000-1000-8000-00805f9b34fb'

# Published Apple Notification Center Service and Apple Media Service UUIDs.
ANCS = {
    '7905f431-b5ce-4e99-a40f-4b1e122d00d0': 'ANCS service',
    '9fbf120d-6301-42d9-8c58-25e699a21dbd': 'ANCS Notification Source (notify)',
    '69d1d8f3-45e1-49a8-9821-9bbdfdaad9d9': 'ANCS Control Point (write)',
    '22eac6e9-24d6-4bb5-be44-b36ace7c7bfb': 'ANCS Data Source (notify)',
}
AMS = {
    '89d3502b-0f36-433a-8ef4-c502ad55f8dc': 'AMS service',
    '9b3c81d8-57b1-4a8a-b8df-0e56f7ca51c2': 'AMS Remote Command',
    '2f7cabce-808d-411f-9a0c-bb92ba96c102': 'AMS Entity Update',
    'c6b2f38c-23ab-46d8-a6ab-a3a870bbd5d7': 'AMS Entity Attribute',
}


# Roles established from the firmware's own use, not from a public registry
# (see SPORT_PERIPHERAL.md).
FIRMWARE_ROLES = {
    '7e78aa18-72cd-d3b8-a81f-5b7e589bea0f':
        ('peripheral', 'Stryd sensor service (watch as client, bx_sport_peripheral)'),
    '7e78aa19-72cd-d3b8-a81f-5b7e589bea0f':
        ('peripheral', 'Stryd cadence-sensor measurement characteristic (client)'),
    'cc353442-be58-4ea2-876e-11d8d6976366':
        ('factory', 'service slot in the factory-test UUID table; unreferenced in main'),
    'c551c36a-0377-4a29-9657-74ffb655a188':
        ('factory', 'characteristic slot in the factory-test UUID table; unreferenced in main'),
}


def classify(uuid):
    """Return ``(category, label, short_id)`` for a lowercase UUID string."""
    if uuid in ANCS:
        return 'ancs', ANCS[uuid], None
    if uuid in AMS:
        return 'ams', AMS[uuid], None
    if uuid.endswith(HUAMI_BASE):
        short = uuid.split('-', 1)[0]
        value = int(short, 16)
        if value in (0x1530, 0x1531, 0x1532):
            return 'huami', 'Huami firmware-update service/char', short
        return 'huami', 'Huami custom service/characteristic', short
    if uuid.endswith(BT_SIG_BASE):
        short = uuid.split('-', 1)[0]
        if int(short, 16) == 0x1101:
            return 'bt-sig', 'Serial Port Profile (SPP)', short
        return 'bt-sig', 'Bluetooth SIG assigned', short
    if uuid in FIRMWARE_ROLES:
        return FIRMWARE_ROLES[uuid] + (None,)
    return 'custom', 'unclassified custom UUID', None


def inspect(data):
    found = sorted({m.group().decode('ascii').lower()
                    for m in UUID_RE.finditer(data)})
    entries = []
    for uuid in found:
        category, label, short = classify(uuid)
        entry = {'uuid': uuid, 'category': category, 'label': label}
        if short is not None:
            entry['short_id'] = short
        entries.append(entry)
    counts = {}
    for entry in entries:
        counts[entry['category']] = counts.get(entry['category'], 0) + 1
    return {'uuid_count': len(entries), 'category_counts': counts,
            'uuids': entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--member', default=FIRMWARE,
                        help='archive member to scan (default: main firmware)')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(args.member)
    result = inspect(data)
    result['member'] = args.member
    result['member_size'] = len(data)
    result['member_sha256'] = hashlib.sha256(data).hexdigest()
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
