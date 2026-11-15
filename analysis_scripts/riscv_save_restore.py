#!/usr/bin/env python3
"""Inspect the main image's register-save ABI stubs and candidate call sites.

The bounded interpreter accepts only the stack/register instructions observed
in these stubs. It does not emulate application code, peripherals or arbitrary
firmware. Candidate call sites are byte scans, not control-flow proof.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import zipfile

BASE = 0x70160000
MEMBER = 'META/firmware_sign.bin'
PAIRS = ((0x70946264, 0x709462a0), (0x7094626c, 0x709462a4),
         (0x7094627a, 0x709462ae), (0x70946294, 0x709462b8))


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def run_stub(data, base, entry, registers, memory, max_steps=64):
    """Interpret only integer stack saves/restores, small jumps and JR exits."""
    values, stack, pc, touched = list(registers), dict(memory), entry, set()
    for step in range(max_steps):
        offset = pc - base
        if pc % 2 or not 0 <= offset <= len(data) - 2:
            raise ValueError('stub PC outside image')
        half = struct.unpack_from('<H', data, offset)[0]
        rd = half >> 7 & 31
        if half & 3 == 3:
            if offset + 4 > len(data):
                raise ValueError('truncated instruction')
            instruction = struct.unpack_from('<I', data, offset)[0]
            if instruction != 0x40610133:  # SUB sp,sp,t1
                raise ValueError(f'unsupported stub instruction at {pc:#x}')
            values[2] = (values[2] - values[6]) & 0xffffffff
            pc += 4
        elif half & 0xe003 == 0xc002:  # C.SWSP
            displacement = ((half >> 9 & 15) << 2) | ((half >> 7 & 3) << 6)
            address = (values[2] + displacement) & 0xffffffff
            stack[address] = values[half >> 2 & 31]
            touched.add(address)
            pc += 2
        elif half & 0xe003 == 0x4002 and rd:  # C.LWSP
            displacement = ((half >> 12 & 1) << 5) | ((half >> 4 & 7) << 2) | ((half >> 2 & 3) << 6)
            address = (values[2] + displacement) & 0xffffffff
            if address not in stack:
                raise ValueError('restore reads an unknown stack slot')
            values[rd] = stack[address]
            pc += 2
        elif half & 0xe003 == 0x6001 and rd == 2:  # C.ADDI16SP
            immediate = ((half >> 12 & 1) << 9) | ((half >> 6 & 1) << 4) | (
                (half >> 5 & 1) << 6) | ((half >> 3 & 3) << 7) | ((half >> 2 & 1) << 5)
            values[2] = (values[2] + signed(immediate, 10)) & 0xffffffff
            pc += 2
        elif half & 0xe003 in (0x0001, 0x4001) and rd:  # C.ADDI / C.LI
            immediate = signed(((half >> 12 & 1) << 5) | (half >> 2 & 31), 6)
            values[rd] = ((values[rd] if half & 0xe003 == 1 else 0) + immediate) & 0xffffffff
            pc += 2
        elif half & 0xe003 == 0xa001:  # C.J
            immediate = ((half >> 12 & 1) << 11) | ((half >> 11 & 1) << 4) | (
                (half >> 9 & 3) << 8) | ((half >> 8 & 1) << 10) | ((half >> 7 & 1) << 6) | (
                (half >> 6 & 1) << 7) | ((half >> 3 & 7) << 1) | ((half >> 2 & 1) << 5)
            pc = (pc + signed(immediate, 12)) & 0xffffffff
        elif half & 0xf07f == 0x8002 and rd:  # C.JR, including RET
            return {'registers': values, 'memory': stack, 'stored_addresses': sorted(touched),
                    'exit_register': rd, 'exit_address': values[rd] & 0xfffffffe,
                    'steps': step + 1}
        else:
            raise ValueError(f'unsupported stub instruction at {pc:#x}')
        values[0] = 0
    raise ValueError('stub step budget exceeded')


def check_pair(data, base, save, restore):
    before = [0x10000000 + i * 0x1010 for i in range(32)]
    before[0], before[2] = 0, 0x10000
    saved = run_stub(data, base, save, before, {})
    if saved['exit_register'] != 5:
        raise ValueError('save stub must return through t0')
    changed = list(saved['registers'])
    # Simulate a body changing the saved registers and producing a new result.
    saved_values = set(saved['memory'].values())
    saved_registers = [i for i, value in enumerate(before) if value in saved_values]
    for register in saved_registers:
        changed[register] ^= 0x55555555
    changed[10], changed[11] = 0x12345678, 0x76543210
    restored = run_stub(data, base, restore, changed, saved['memory'])
    if restored['exit_register'] != 1 or restored['registers'][2] != before[2]:
        raise ValueError('restore must balance sp and return through ra')
    if any(restored['registers'][r] != before[r] for r in saved_registers):
        raise ValueError('saved registers did not round-trip')
    if saved['registers'][10:18] != before[10:18] or restored['registers'][10:12] != changed[10:12]:
        raise ValueError('stub unexpectedly changes arguments or results')
    return {'save': save, 'restore': restore, 'saved_registers': saved_registers,
            'frame_bytes': before[2] - saved['registers'][2],
            'save_steps': saved['steps'], 'restore_steps': restored['steps'],
            'arguments_a0_a7_preserved': True, 'results_a0_a1_preserved': True,
            'round_trip_passed': True}


def candidate_sites(data, base, targets):
    sites = collections.defaultdict(list)
    for offset in range(0, len(data) - 7, 2):
        first, second = struct.unpack_from('<II', data, offset)
        # AUIPC t1; JALR (t0 or zero),t1,imm.
        if first & 0xfff != 0x317 or second & 0xff07f != 0x30067:
            continue
        link = second >> 7 & 31
        if link not in (0, 5):
            continue
        target = (base + offset + (first & 0xfffff000) + signed(second >> 20, 12)) & 0xfffffffe
        if (target, link) in targets:
            sites[(target, link)].append(base + offset)
    return sites


def analyze(data, directory=None):
    pairs = [check_pair(data, BASE, save, restore) for save, restore in PAIRS]
    targets = {(a, 5) for a, _ in PAIRS} | {(b, 0) for _, b in PAIRS}
    sites = candidate_sites(data, BASE, targets)
    corpus = []
    if directory:
        pattern = re.compile(r'\b(?:FUN_ram_|0x)(709462(?:64|6c|7a|94|a0|a4|ae|b8))\b')
        for path in sorted(pathlib.Path(directory).glob('*.c')):
            text = path.read_text()
            if pattern.search(text):
                corpus.append({'file': path.name,
                               'source_sha256': hashlib.sha256(text.encode()).hexdigest()})
    return {'member': MEMBER, 'member_sha256': hashlib.sha256(data).hexdigest(),
            'image_base': BASE, 'stub_region_sha256': hashlib.sha256(
                data[0x70946264 - BASE:0x709462c4 - BASE]).hexdigest(),
            'pairs': pairs,
            'candidate_sites': [{'target': target, 'link_register': link, 'count': len(values),
                                 'addresses': values} for (target, link), values in sorted(sites.items())],
            'summary': {'candidate_save_sites': sum(len(v) for (t, r), v in sites.items() if r == 5),
                        'candidate_restore_sites': sum(len(v) for (t, r), v in sites.items() if r == 0),
                        'corpus_exports_mentioning_stubs': len(corpus) if directory else None},
            'corpus_exports': corpus}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled')
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = analyze(archive.read(MEMBER), args.decompiled)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect save/restore ABI: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
