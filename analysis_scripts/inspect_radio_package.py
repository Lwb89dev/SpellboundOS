#!/usr/bin/env python3
"""Inventory the observed RTL8763 package prefix without assuming its format."""
import argparse
import hashlib
import json
import pathlib
import struct
import zipfile

MEMBER = 'META/extfw/pamir/rtl8763_pack.bin'


def inspect(data):
    if len(data) < 0x48 or data[:2] != b'GM':
        raise ValueError('unknown or truncated radio package prefix')
    bitmap = struct.unpack_from('<I', data, 0x28)[0]
    count = bitmap.bit_count()
    declared_end = struct.unpack_from('<I', data, 2)[0]
    table_end = 0x48 + count * 12
    if not (table_end <= declared_end <= len(data)):
        raise ValueError('record table or declared end exceeds package bounds')
    records = []
    payload_offset = table_end
    for offset in range(0x48, table_end, 12):
        first, second, third = struct.unpack_from('<III', data, offset)
        if second > declared_end - payload_offset:
            raise ValueError('candidate payload exceeds declared package end')
        records.append({'file_offset': offset, 'word_0': first,
                        'word_1': second, 'word_2': third,
                        'candidate_payload_offset': payload_offset,
                        'candidate_payload_sha256': hashlib.sha256(data[payload_offset:payload_offset + second]).hexdigest()})
        payload_offset += second
    offset = table_end
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'prefix_hex': data[:4].hex(), 'word_at_0x04': struct.unpack_from('<I', data, 4)[0],
            'declared_end_word_at_0x02': declared_end,
            'bitmap_at_0x28': bitmap, 'bitmap_popcount': count,
            'candidate_payload_end': payload_offset,
            'payload_lengths_match_declared_end': payload_offset == declared_end,
            'trailing_bytes': len(data) - declared_end,
            'word_at_0x24': struct.unpack_from('<I', data, 0x24)[0],
            'record_start': 0x48, 'candidate_records': records,
            'first_nonmatching_offset': offset,
            'first_nonmatching_bytes_hex': data[offset:offset + 12].hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--extract', type=pathlib.Path, help='new output directory for candidate payloads')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(MEMBER)
        result = inspect(data)
    if args.extract is not None:
        args.extract.mkdir(parents=True, exist_ok=False)
        for index, record in enumerate(result['candidate_records']):
            start = record['candidate_payload_offset']
            (args.extract / f'{index:02d}.bin').write_bytes(data[start:start + record['word_1']])
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
