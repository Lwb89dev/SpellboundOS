#!/usr/bin/env python3
"""Inventory the observed RTL8763 package prefix without assuming its format."""
import argparse
import hashlib
import json
import struct
import zipfile

MEMBER = 'META/extfw/pamir/rtl8763_pack.bin'


def inspect(data):
    if len(data) < 0x48 or data[:4] != b'GM\xbc\xdb':
        raise ValueError('unknown or truncated radio package prefix')
    records = []
    offset = 0x48
    while offset + 12 <= len(data):
        first, second, third = struct.unpack_from('<III', data, offset)
        if not (0x02000000 <= first < 0x03000000 and 0 < second < len(data)
                and third == 0):
            break
        records.append({'file_offset': offset, 'word_0': first,
                        'word_1': second, 'word_2': third})
        offset += 12
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'prefix_hex': data[:4].hex(), 'word_at_0x04': struct.unpack_from('<I', data, 4)[0],
            'word_at_0x24': struct.unpack_from('<I', data, 0x24)[0],
            'record_start': 0x48, 'candidate_records': records,
            'first_nonmatching_offset': offset,
            'first_nonmatching_bytes_hex': data[offset:offset + 12].hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        result = inspect(archive.read(MEMBER))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
