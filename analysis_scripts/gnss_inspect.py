#!/usr/bin/env python3
"""Inspect the observed AG3352B container and compare two touch payloads."""
import argparse
import hashlib
import json
import pathlib
import struct
import zipfile

GNSS = 'META/extfw/fw_gps.bin'
TOUCH = ('META/extfw/00151501_005c0913_0000009b_tp.bin',
         'META/extfw/00161501_005B0913_0000009b_tp.bin')


def inspect_gnss(data):
    if len(data) < 0x100 or data[0x20:0x24] != b'\x55\xaa\xaa\x55':
        raise ValueError('unrecognized GNSS header')
    lengths = struct.unpack_from('<5I', data, 0x24)
    if sum(lengths) + 0x100 != len(data):
        raise ValueError('candidate section lengths do not account for file size')
    regions = []
    offset = 0x100
    for length in lengths:
        regions.append({'file_offset': offset, 'length': length,
                        'sha256': hashlib.sha256(data[offset:offset+length]).hexdigest()})
        offset += length
    return regions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--first-region', type=pathlib.Path,
                        help='new output file for the first candidate GNSS region')
    parser.add_argument('--extract-regions', type=pathlib.Path, help='new directory for all candidate regions')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(GNSS)
        touch = [archive.read(name) for name in TOUCH]
    regions = inspect_gnss(data)
    lengths = [region["length"] for region in regions]
    if args.first_region:
        with args.first_region.open('xb') as source:
            source.write(data[0x100:0x100+lengths[0]])
    if args.extract_regions:
        args.extract_regions.mkdir(exist_ok=False)
        for index, region in enumerate(regions):
            start = region['file_offset']
            (args.extract_regions/f'{index}.bin').write_bytes(data[start:start+region['length']])
    differences = [{'offset': index, 'first': first, 'second': second}
                   for index, (first, second) in enumerate(zip(*touch)) if first != second]
    print(json.dumps({'gnss_member': GNSS, 'gnss_size': len(data),
                      'gnss_sha256': hashlib.sha256(data).hexdigest(),
                      'declared_version': data[:0x20].split(b'\0')[0].decode('ascii'),
                      'candidate_regions': regions,
                      'touch': [{'member': name, 'length': len(payload),
                                 'sha256': hashlib.sha256(payload).hexdigest()}
                                for name, payload in zip(TOUCH, touch)],
                      'touch_differing_bytes': differences,
                      'touch_equal_length': len(touch[0]) == len(touch[1])}, indent=2))


if __name__ == '__main__':
    main()
