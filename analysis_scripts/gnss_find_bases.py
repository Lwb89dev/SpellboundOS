#!/usr/bin/env python3
"""Rank aligned candidate bases from literal pointers to NUL-terminated strings.

This is a heuristic; duplicated strings and unrelated data produce false hits.
"""
import argparse
import collections
import json
import pathlib
import re
import struct


def find(data, low, high):
    strings = collections.defaultdict(list)
    for match in re.finditer(rb'[\x20-\x7e]{8,}\x00', data):
        strings[match.start() & 0x3ff].append(match.start())
    counts = collections.Counter()
    examples = collections.defaultdict(list)
    for offset in range(0, len(data)-3, 4):
        word = struct.unpack_from('<I', data, offset)[0]
        if not low <= word < high: continue
        for target in strings[word & 0x3ff]:
            base = word-target
            if not low <= base < high: continue
            counts[base] += 1
            if len(examples[base]) < 3:
                examples[base].append({'pointer_file_offset': offset,
                                       'pointer_value': word, 'string_file_offset': target})
    return [{'candidate_base': base, 'match_count': count, 'examples': examples[base]}
            for base,count in counts.most_common(8)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=pathlib.Path)
    parser.add_argument('--low', type=lambda x:int(x,0), required=True)
    parser.add_argument('--high', type=lambda x:int(x,0), required=True)
    args = parser.parse_args()
    print(json.dumps(find(args.image.read_bytes(),args.low,args.high),indent=2))

if __name__ == '__main__': main()
