#!/usr/bin/env python3
"""Decode selected RV32 AndeStar branches and initial rpmsg pools offline.

Explicit instruction addresses only: this is not a general disassembler or a
firmware execution model. BBS tests nonzero, correcting the reviewed Ghidra
12.1.2 SLEIGH predicate. External source files are fingerprinted, not copied.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import MAIN, SENSOR, MAIN_HASH, SENSOR_HASH, uint
else:
    from sensorhub_memory import StartupMemory
    from zrpc_packets import MAIN, SENSOR, MAIN_HASH, SENSOR_HASH, uint

BRANCHES = (0x704e8f3e, 0x704e8f54, 0x704ea2a2, 0x704ea2a6,
            0x704e9bc0, 0x704e9bee, 0x704e9d92, 0x704e9f86, 0x704ea71c)


def decode_branch(word, pc):
    uint(word, 32)
    uint(pc, 32)
    family = word >> 12 & 7
    if pc & 1 or word & 127 != 0x5b or family not in (5, 6, 7):
        raise ValueError('not a supported aligned AndeStar branch')
    immediate = word >> 20 & 31
    if family == 7:
        if word & 128:
            raise ValueError('RV32 bit index extension must be zero')
        mnemonic = 'bbs' if word >> 30 & 1 else 'bbc'
    else:
        mnemonic = 'beqc' if family == 5 else 'bnec'
        immediate |= (word >> 30 & 1) << 6 | (word >> 7 & 1) << 5
    offset = (word >> 31) * -1024 + (word >> 25 & 31) * 32 + (word >> 8 & 15) * 2
    return dict(mnemonic=mnemonic, register=word >> 15 & 31, immediate=immediate,
                target=(pc + offset) & 0xffffffff, offset=offset)


def branch_taken(instruction, value):
    uint(value, 32)
    kind, immediate = instruction['mnemonic'], instruction['immediate']
    if kind in ('bbc', 'bbs'):
        return bool(value & (1 << immediate)) == (kind == 'bbs')
    return (value == immediate) == (kind == 'beqc')


def pool_size(count, payload):
    """Reviewed rpmsg manager arithmetic, for valid non-overflowing inputs."""
    uint(count, 16)
    uint(payload, 16)
    if not count or count & (count - 1) or (payload + 16) & (payload + 15):
        raise ValueError('count and payload+16 must be powers of two')
    ring = ((count & ~1) + 23) & ~15
    ring += ((count >> 1) * 8 + 29) & ~15
    ring += (count >> 1) * 16
    return dict(ring_bytes=ring, buffer_stride=payload + 16,
                total_bytes=2 * ring + (payload + 16) * count)


def evidence(archive, ghidra_sinc, renode_source):
    main, sensor = archive.read(MAIN), archive.read(SENSOR)
    if hashlib.sha256(main).hexdigest() != MAIN_HASH or hashlib.sha256(sensor).hexdigest() != SENSOR_HASH:
        raise ValueError('requires reviewed OTA images')
    gm, rn = ghidra_sinc.read_bytes(), renode_source.read_bytes()
    if hashlib.sha256(gm).hexdigest() != '2ac0f478b9222768994ef5d27a0a72379744ee869ace9c71a25b437057b82a89':
        raise ValueError('requires reviewed Ghidra 12.1.2 instruction definition')
    if hashlib.sha256(rn).hexdigest() != '004afe64fbbf815ac1af369753024750e6f8f3c61828fb4b7f066814d5c5373b':
        raise ValueError('requires reviewed Renode source snapshot')
    m = StartupMemory(main, 0x70160000, 0x270, 4, 0x2a0, 2)
    s = StartupMemory(sensor)
    pools = []
    for index in range(3):
        raw = m.read(0x70c0e8f4 + index * 16, 16)
        if raw != s.read(0x80fe38d0 + index * 16, 16):
            raise ValueError('main/sensor rpmsg pool tables differ')
        identifier, base, count, payload = struct.unpack('<4I', raw)
        dimensions = pool_size(count, payload)
        pools.append(dict(id=identifier, base=base, count=count, payload_bytes=payload,
                          end=base + dimensions['total_bytes'], **dimensions))
    return dict(main_sha256=MAIN_HASH, sensor_sha256=SENSOR_HASH,
        external_source_sha256=dict(ghidra_12_1_2=hashlib.sha256(gm).hexdigest(),
                                    renode_snapshot=hashlib.sha256(rn).hexdigest()),
        selected_branches=[dict(address=pc, word=f'{struct.unpack("<I", m.read(pc, 4))[0]:08x}',
            **decode_branch(struct.unpack('<I', m.read(pc, 4))[0], pc)) for pc in BRANCHES],
        rpmsg_pools=pools, main_sensor_pool_tables_identical=True,
        limitations=['No patched Ghidra re-export or complete corpus audit performed.',
                     'Initial shared-memory pool configuration; active routing and physical memory unverified.',
                     'Exact-multiple fragment termination remains a native compatibility question.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--ghidra-sinc', type=Path, required=True)
    parser.add_argument('--renode-source', type=Path, required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = evidence(archive, args.ghidra_sinc, args.renode_source)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect zrpc control flow: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
