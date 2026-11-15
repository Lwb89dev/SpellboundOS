#!/usr/bin/env python3
"""Find adjacent RISC-V AUIPC/ADDI candidate references to file offsets.

Scans every two-byte boundary, including data; results require disassembly and
control-flow validation. Does not find non-adjacent, compressed or other forms.
"""
import argparse
import hashlib
import json
import struct


def candidate_references(data, base, offsets):
    targets = {(base + offset) & 0xffffffff: offset for offset in offsets}
    hits = []
    for pos in range(0, len(data) - 7, 2):
        first, second = struct.unpack_from('<II', data, pos)
        if first & 0x7f != 0x17 or second & 0x707f != 0x13:
            continue
        register = (first >> 7) & 31
        if register == 0 or (second >> 15) & 31 != register:
            continue
        immediate = second >> 20
        if immediate & 0x800:
            immediate -= 0x1000
        address = (base + pos + (first & 0xfffff000) + immediate) & 0xffffffff
        if address in targets:
            hits.append({'instruction_file_offset': pos,
                         'candidate_address': (base + pos) & 0xffffffff,
                         'target_file_offset': targets[address],
                         'target_address': address,
                         'auipc_word': f'{first:08x}', 'addi_word': f'{second:08x}'})
    return hits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--base', type=lambda x: int(x, 0), required=True)
    parser.add_argument('offsets', nargs='+', type=lambda x: int(x, 0))
    args = parser.parse_args()
    if not 0 <= args.base <= 0xffffffff:
        parser.error('base must be a 32-bit unsigned value')
    with open(args.image, 'rb') as source:
        data = source.read()
    if any(offset < 0 or offset >= len(data) for offset in args.offsets):
        parser.error('target offsets must be within the image')
    print(json.dumps({'image_sha256': hashlib.sha256(data).hexdigest(),
                      'base': args.base, 'offsets': args.offsets,
                      'hits': candidate_references(data, args.base, args.offsets)}, indent=2))


if __name__ == '__main__':
    main()
