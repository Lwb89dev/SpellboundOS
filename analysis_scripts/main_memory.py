#!/usr/bin/env python3
"""Reconstruct main-image startup mappings, including relocated executable code."""
import argparse
import hashlib
import json
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
else:
    from sensorhub_memory import StartupMemory

BASE = 0x70160000
MEMBER = 'META/firmware_sign.bin'


def analyze(data):
    memory = StartupMemory(data, BASE, 0x270, 4, 0x2a0, 2)
    targets = []
    for address in (0x80d361fc, 0x80d364fa, 0x80d365a6, 0x80d366ae,
                    0x80d3c2f4, 0x80d411ac, 0x80d45a18, 0x80d47b37):
        for region in memory.regions:
            if region['kind'] == 'copy' and region['destination'] <= address < region['destination'] + region['size']:
                offset = region['source'] - BASE + address - region['destination']
                targets.append({'runtime_address': address, 'file_offset': offset,
                                'original_mapping_address': BASE + offset})
                break
        else:
            raise ValueError(f'relocated target not covered: {address:#x}')
    capabilities = memory.read(0x70fd6078, 36 * 4)
    return {'member': MEMBER, 'member_sha256': hashlib.sha256(data).hexdigest(),
            'image_base': BASE, 'startup_function': 0x701637ec,
            'copy_table_address': BASE + 0x270, 'zero_table_address': BASE + 0x2a0,
            'regions': memory.regions, 'relocated_target_examples': targets,
            'capability_table_initial_address': 0x70fd6078,
            'capability_table_initial_bytes': len(capabilities),
            'capability_table_initially_zero': not any(capabilities)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = analyze(archive.read(MEMBER))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot reconstruct main memory: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
