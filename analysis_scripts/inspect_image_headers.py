#!/usr/bin/env python3
"""Inspect only the observed Bip 6 OTA LCPU and HDRZ header fields."""
import argparse
import hashlib
import json
import struct
import sys
import zipfile

MAIN = 'META/firmware_sign.bin'
SENSOR = 'META/extfw/sensorhub@mhs003_sign.bin'


def inspect_main(data):
    if len(data) < 16 or data[4:8] != b'HDRZ':
        raise ValueError('missing or truncated main HDRZ header')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'hdrz_offset': 4, 'entry_word': struct.unpack_from('<I', data, 12)[0]}


def inspect_sensor(data):
    if len(data) < 0x30 or data[:4] != b'LCPU' or data[0x24:0x28] != b'HDRZ':
        raise ValueError('missing or truncated LCPU/HDRZ header')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'lcpu_offset': 0, 'destination_word': struct.unpack_from('<I', data, 4)[0],
            'entry_word': struct.unpack_from('<I', data, 8)[0],
            'nested_hdrz_offset': 0x24,
            'nested_entry_word': struct.unpack_from('<I', data, 0x2c)[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    try:
        with open(args.archive, 'rb') as source:
            archive_hash = hashlib.file_digest(source, 'sha256').hexdigest()
        with zipfile.ZipFile(args.archive) as archive:
            result = {'archive_sha256': archive_hash,
                      'main': inspect_main(archive.read(MAIN)),
                      'sensorhub': inspect_sensor(archive.read(SENSOR))}
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as error:
        print(f'Cannot inspect headers: {error}', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
