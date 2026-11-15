#!/usr/bin/env python3
"""Inventory candidate chip identifiers and health metrics from firmware strings.

The firmware names its device drivers as ``dev_<part>`` and logs health
algorithm tokens. This collects the part-number-shaped driver names, maps the
recognized ones to a candidate vendor and role, and counts a fixed vocabulary of
health/biometric metric tokens.

The chip roles are candidate attributions from the driver name plus corroborating
findings elsewhere in this repo, not a confirmed bill of materials or a readout
of fitted silicon. A metric token's presence does not prove the feature is
enabled or accurate.
"""
import argparse
import hashlib
import json
import re
import zipfile

FIRMWARE = 'META/firmware_sign.bin'

# Recognized driver part -> (vendor, candidate role, corroboration).
KNOWN_PARTS = {
    'ag3335': ('Airoha', 'GNSS receiver',
               'matches AG3352B GNSS container in GNSS_AND_TOUCH_BLOBS.md'),
    'icna3311': ('Chipone', 'AMOLED display driver IC',
                 'matches the 0xda/0xdb/0xdc display read in DISPLAY_AND_LIGHT.md'),
    'stk31e60': ('Sensortek', 'ambient light / proximity sensor',
                 'matches the dev_stk31e60 light probe in DISPLAY_AND_LIGHT.md'),
    'ztw622': ('Zinitix', 'capacitive touch controller',
               'matches the expected 0xE622 touch identity in TOUCH_AND_SERIAL.md'),
    'aw32012': ('Awinic', 'candidate charger / LED driver', None),
    'cw6305': ('CellWise', 'candidate battery fuel gauge / charger', None),
}

# Fixed health/biometric vocabulary counted as whole words (case-insensitive).
HEALTH_TOKENS = ('heart rate', 'hr', 'ppg', 'hrv', 'spo2', 'stress', 'sleep',
                 'step', 'steps', 'distance', 'calorie', 'pai', 'vo2max',
                 'ecg', 'afib', 'body temp', 'workout', 'sport', 'activity')

# SoC-level identifiers observed as literal strings.
SOC_TOKENS = ('AX861', 'MHS002', 'MHS003', 'mhs003')


def driver_parts(text):
    """Part-number-shaped ``dev_<part>`` driver names (letters then >=2 digits)."""
    return sorted(set(re.findall(r'dev_([a-z]+[0-9]{2,}[a-z0-9]*)', text)))


def health_counts(text):
    low = text.lower()
    counts = {}
    for token in HEALTH_TOKENS:
        counts[token] = len(re.findall(r'\b' + re.escape(token) + r'\b', low))
    return {k: v for k, v in counts.items() if v}


def soc_identifiers(text):
    return sorted({t for t in SOC_TOKENS if t in text})


def inspect(text):
    parts = driver_parts(text)
    drivers = []
    for part in parts:
        entry = {'part': part}
        if part in KNOWN_PARTS:
            vendor, role, note = KNOWN_PARTS[part]
            entry.update(vendor=vendor, candidate_role=role)
            if note:
                entry['corroboration'] = note
        else:
            entry['candidate_role'] = 'unidentified driver'
        drivers.append(entry)
    return {
        'soc_identifiers': soc_identifiers(text),
        'drivers': drivers,
        'identified_driver_count': sum(1 for d in drivers if 'vendor' in d),
        'health_metric_counts': health_counts(text),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--member', default=FIRMWARE)
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(args.member)
    result = inspect(data.decode('latin1'))
    result['member'] = args.member
    result['member_size'] = len(data)
    result['member_sha256'] = hashlib.sha256(data).hexdigest()
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
