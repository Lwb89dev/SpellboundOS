#!/usr/bin/env python3
"""Repair the reviewed Ghidra 12.1.2 AndeStar BBS source predicate locally.

Requires an explicit path and exact known source hash. Recompile the associated
andestar_v5.slaspec with Ghidra's support/sleigh after applying this change.
No firmware or project database is modified by this script.
"""
import argparse
import hashlib
from pathlib import Path

ORIGINAL_SHA256 = '2ac0f478b9222768994ef5d27a0a72379744ee869ace9c71a25b437057b82a89'
OLD = b'tst:1 = (rs1 & (1 << cimm)) == 1;'
NEW = b'tst:1 = (rs1 & (1 << cimm)) != 0;'


def repair(data):
    expected = ORIGINAL_SHA256
    if data.count(NEW) == 1 and data.count(OLD) == 0:
        if hashlib.sha256(data.replace(NEW, OLD)).hexdigest() == expected:
            return data
    if hashlib.sha256(data).hexdigest() != expected or data.count(OLD) != 1:
        raise ValueError('source differs from the reviewed Ghidra 12.1.2 definition')
    return data.replace(OLD, NEW)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('instruction_source', type=Path)
    args = parser.parse_args()
    try:
        before = args.instruction_source.read_bytes()
        after = repair(before)
        if after != before:
            args.instruction_source.write_bytes(after)
    except (ValueError, OSError) as error:
        parser.exit(2, f'Cannot repair BBS: {error}\n')
    print('Corrected source SHA-256:', hashlib.sha256(after).hexdigest())
    print('Recompile andestar_v5.slaspec before reopening the Ghidra program.')


if __name__ == '__main__':
    main()
