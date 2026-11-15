#!/usr/bin/env python3
"""Extract an allowlisted connection summary from private Gadgetbridge captures.

Raw log lines, device names/addresses, identifiers, notification bodies and
packet payloads never enter the report. This is not a general log redactor.
Logged characteristic coverage is partial and must not be treated as a full
GATT discovery or proof that unlogged services are absent.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from xml.etree import ElementTree as ET

UUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
CHARACTERISTIC = re.compile(r'characteristic:.*:\s*(' + UUID + r')\s*\(([^)]*)\)')
PROPERTIES = {'broadcast': 1, 'read': 2, 'writeNoResponse': 4, 'write': 8,
              'notify': 16, 'indicate': 32, 'signedWrite': 64, 'extendedProperties': 128}
STATES = {'Connesso': 'connected', 'Non connesso': 'disconnected',
          'In autenticazione': 'authenticating', 'Connected': 'connected',
          'Not connected': 'disconnected'}


def full_uuid(value):
    return f'0000{value}-0000-1000-8000-00805f9b34fb' if len(value) == 4 else value.lower()


def summarize(log, ui, package, builder):
    characteristics, mtus, service_counts, flags = {}, [], [], {}
    for line in log.splitlines():
        if 'ZeppOsBtleSupport:' in line and (match := CHARACTERISTIC.search(line)):
            values = tuple(part.strip() for part in match[2].split(','))
            if any(value not in PROPERTIES for value in values):
                raise ValueError('unknown characteristic property')
            characteristics[match[1].lower()] = {
                'uuid': match[1].lower(), 'properties': sorted(set(values)),
                'properties_mask': sum(PROPERTIES[value] for value in set(values))}
        if match := re.search(r'onConfigureMTU\([^,]+,\s*(\d+),\s*(\d+)\)', line):
            mtu, status = map(int, match.groups())
            if status == 0 and 23 <= mtu <= 517:
                mtus.append(mtu)
        if 'ZeppOsServicesService:' in line and (match := re.search(r'Number of services: (\d+)\b', line)):
            service_counts.append(int(match[1]))
        if match := re.search(r'Replacing encrypted flag for (ZeppOs[A-Za-z]+Service), (true|false) -> (true|false)\b', line):
            flags[match[1]] = {'previous': match[2] == 'true', 'announced': match[3] == 'true'}
    states = {STATES[node.get('text')] for node in ET.fromstring(ui).iter('node')
              if node.get('text') in STATES}
    version = re.search(r'^\s*versionName=(\d+(?:\.\d+)+)\s*$', package, re.M)
    sdk = re.search(r'\btargetSdk=(\d+)\b', package)
    owners, unlogged = {}, []
    for service in builder['services']:
        for characteristic in service['characteristics']:
            uuid = full_uuid(characteristic['uuid'])
            spec = {'service_uuid': service['uuid'],
                    'internal_identifier': characteristic['internal_identifier'],
                    'properties_raw': characteristic['properties_raw']}
            owners.setdefault(uuid, []).append(spec)
            if uuid not in characteristics:
                unlogged.append({'service_uuid': service['uuid'], 'uuid': uuid})
    for uuid, characteristic in characteristics.items():
        specs = owners.get(uuid, [])
        characteristic['static_builder_candidates'] = specs
        characteristic['properties_match_static_low_byte'] = any(
            spec['properties_raw'] & 255 == characteristic['properties_mask'] for spec in specs)
    return {'gadgetbridge_version': version[1] if version else None,
            'gadgetbridge_target_sdk': int(sdk[1]) if sdk else None,
            'ui_connection_states': sorted(states), 'successful_mtu_events': mtus,
            'announced_application_service_counts': service_counts,
            'announced_encryption_flag_changes': flags,
            'logged_characteristics': list(characteristics.values()),
            'logged_characteristic_count': len(characteristics),
            'all_logged_characteristics_match_static_properties': bool(characteristics) and all(
                c['properties_match_static_low_byte'] for c in characteristics.values()),
            'unlogged_static_characteristics': unlogged,
            'coverage': 'Gadgetbridge log subset, not a complete live GATT database',
            'privacy': 'allowlisted metadata only; no raw lines, names, addresses, keys or payloads'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logcat', type=Path, required=True)
    parser.add_argument('--ui', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--builder', type=Path, default=Path('analysis/gatt-service-builder.json'))
    args = parser.parse_args()
    try:
        inputs = {key: getattr(args, key).read_bytes() for key in ('logcat', 'ui', 'package', 'builder')}
        report = summarize(inputs['logcat'].decode(), inputs['ui'].decode(), inputs['package'].decode(),
                           json.loads(inputs['builder']))
        report['input_sha256'] = {key: hashlib.sha256(value).hexdigest() for key, value in inputs.items()}
    except (OSError, ValueError, KeyError, ET.ParseError) as error:
        parser.exit(2, f'Cannot summarize Gadgetbridge capture: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
