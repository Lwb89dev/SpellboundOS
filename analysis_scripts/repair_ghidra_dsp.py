#!/usr/bin/env python3
"""Add two reviewed RV32 Andes DSP semantics to the BBS-corrected local language.

Requires the exact Ghidra 12.1.2 source after repair_ghidra_bbs.py. Recompile
andestar_v5.slaspec afterwards. Does not patch firmware or broadly enable DSP.
"""
import argparse
import hashlib
from pathlib import Path

BBS_SHA256 = 'b88e19a2ed21e641c683a1780aa739e1d9662106234a02b37fb4e949b4827a03'
ADDITION = b'''
# SpellboundFit: reviewed RV32 opcode-0x7f forms only; see TIMER_ARITHMETIC.md.
@if XLEN == "4"
:pkbb16 rd,rs1,rs2 is op0006=0x7f & rd & rs1 & rs2 & funct3=1 & funct7=0x07 {
    local packed:4 = (rs1 << 16) | (rs2 & 0xffff);
    rd = packed;
}
:maddr32 rd,rs1,rs2 is op0006=0x7f & rd & rs1 & rs2 & funct3=1 & funct7=0x62 {
    local accumulated:4 = rd + (rs1 * rs2);
    rd = accumulated;
}
@endif
'''


def repair(data):
    original = data[:-len(ADDITION)] if data.endswith(ADDITION) else data
    if hashlib.sha256(original).hexdigest() != BBS_SHA256:
        raise ValueError('requires the reviewed BBS-corrected Ghidra 12.1.2 source')
    return original + ADDITION


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
        parser.exit(2, f'Cannot add DSP semantics: {error}\n')
    print('DSP source SHA-256:', hashlib.sha256(after).hexdigest())
    print('Recompile andestar_v5.slaspec and redisassemble affected functions.')


if __name__ == '__main__':
    main()
