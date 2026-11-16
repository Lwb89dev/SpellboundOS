#!/usr/bin/env python3
"""Review timer/DSP evidence and model the scaled IPC timeout on synthetic values.

The host models do not execute hardware or infer the counter's physical rate.
ValidateTimerArithmetic.java separately executes the actual guarded native code
through corrected SLEIGH p-code against an independent unsigned division oracle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

if __package__:
    from .ipc_doorbell import wait_expired
    from .repair_ghidra_dsp import ADDITION, repair
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import MAIN, MAIN_HASH, uint
else:
    from ipc_doorbell import wait_expired
    from repair_ghidra_dsp import ADDITION, repair
    from sensorhub_memory import StartupMemory
    from zrpc_packets import MAIN, MAIN_HASH, uint

ENTRY, SIZE = 0x70945b3c, 0x3a4
HELPER_HASH = 'fb9c031f6bd2d49123fc951bdb2dc1aa7446c55fb356a3a18ef385a761440717'
REFERENCE_HASH = 'fbf427bbf3b64c034d79956adbb3661afe246beee235d412086ba36951edab4d'
LANGUAGE_HASH = 'aee5ee54eef0c31a8cba18035596de361be7caf253dca63f38727b5ef97f4fc9'
COMPILED_HASH = 'aca3cd4069bc22d200a8c5dcf79839a9cbe78de56416b0abe2b635f855cb60fa'


def dsp_decode(word):
    uint(word, 32)
    """Decode only the two reviewed opcode-0x7f, funct3=1 RV32 forms."""
    uint(word, 32)
    operation = {0x0e00107f: 'pkbb16', 0xc400107f: 'maddr32'}.get(word & 0xfe00707f)
    if operation is None:
        raise ValueError('not a reviewed DSP encoding')
    return dict(operation=operation, rd=word >> 7 & 31, rs1=word >> 15 & 31, rs2=word >> 20 & 31)


def scaled_counter(raw):
    return uint(raw, 64) // 1000


def ipc_wait_from_raw(start_raw, now_raw):
    """Convert each snapshot before unsigned subtraction, as the native caller."""
    return wait_expired(scaled_counter(start_raw), scaled_counter(now_raw))


def first_timeout_raw_delta(start_raw):
    """First possible threshold crossing without raw-counter wrap or poll delay."""
    uint(start_raw, 64)
    delta = 1000000 - start_raw % 1000
    if start_raw + delta > 0xffffffffffffffff:
        raise ValueError('threshold crosses raw-counter wrap; excluded from this interval model')
    return delta


def evidence(archive, decompiled, language, validation, reference):
    data = archive.read(MAIN)
    if hashlib.sha256(data).hexdigest() != MAIN_HASH:
        raise ValueError('requires reviewed main image')
    memory = StartupMemory(data, 0x70160000, 0x270, 4, 0x2a0, 2)
    body = memory.read(ENTRY, SIZE)
    if hashlib.sha256(body).hexdigest() != HELPER_HASH:
        raise ValueError('reviewed arithmetic body differs')
    source = (language / 'andestar_v5.instr.sinc').read_bytes()
    compiled = (language / 'andestar_v5.sla').read_bytes()
    if not source.endswith(ADDITION) or repair(source) != source:
        raise ValueError('requires corrected BBS and DSP semantics')
    if hashlib.sha256(source).hexdigest() != LANGUAGE_HASH or hashlib.sha256(compiled).hexdigest() != COMPILED_HASH:
        raise ValueError('requires reviewed compiled DSP language')
    if hashlib.sha256(reference.read_bytes()).hexdigest() != REFERENCE_HASH:
        raise ValueError('requires reviewed DSP opcode reference snapshot')
    exports = {f'{a:08x}.c': (decompiled / f'{a:08x}.c').read_bytes()
               for a in (ENTRY, 0x80d45464, 0x707bf7e0)}
    for address in (ENTRY, 0x80d45464):
        if any(marker in exports[f'{address:08x}.c'] for marker in (b'halt_baddata', b'WARNING:')):
            raise ValueError('arithmetic/reader export remains truncated or warned')
    execution = json.loads(validation.read_bytes())
    if (execution['division_cases'] != 52294 or execution['reader_cases'] != 200
            or not 0 < execution['max_steps_per_case'] <= 512):
        raise ValueError('unexpected bounded execution run')
    instructions, dsp_sites = [], []
    offset = 0
    while offset < len(body):
        half = int.from_bytes(body[offset:offset + 2], 'little')
        size = 4 if half & 3 == 3 else 2
        if offset + size > len(body):
            raise ValueError('truncated instruction in bounded helper')
        address = ENTRY + offset
        instructions.append(f'{address:08x}')
        if size == 4:
            word = int.from_bytes(body[offset:offset + 4], 'little')
            if word & 0x7f == 0x7f:
                dsp_sites.append(dict(address=f'{address:08x}', word=f'{word:08x}', **dsp_decode(word)))
        offset += size
    sites = {site['address'] for site in dsp_sites}
    if sites != set(execution['dsp_execution_counts']) or any(v <= 0 for v in execution['dsp_execution_counts'].values()):
        raise ValueError('not every DSP site was exercised')
    return dict(main_sha256=MAIN_HASH, helper_sha256=HELPER_HASH,
        language_source_sha256=LANGUAGE_HASH, language_compiled_sha256=COMPILED_HASH,
        reference=dict(url='https://github.com/hpmicro-rs/andes-riscv/blob/main/src/dsp.rs', sha256=REFERENCE_HASH),
        export_sha256={name: hashlib.sha256(raw).hexdigest() for name, raw in exports.items()},
        emulation_report_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        execution=execution, dsp_sites=dsp_sites,
        unvisited_helper_instruction_addresses=sorted(set(instructions) - set(execution['covered_addresses'])),
        reader=dict(address=0x80d45464, formula='floor(raw_unsigned_64 / 1000)', physical_rate='unmeasured'),
        timeout=dict(limit_reader_units=1000, no_raw_wrap_threshold_delta_min=999001,
                     no_raw_wrap_threshold_delta_max=1000000,
                     samples=[dict(start_raw=n, first_threshold_delta=first_timeout_raw_delta(n))
                              for n in (0, 1, 998, 999, 1000, 123456789)]),
        limitations=['Corrected SLEIGH execution uses the authored DSP semantics; no silicon conformance claim.',
            'Bounded vectors are not exhaustive; unvisited instructions are listed; zero divisors excluded.',
            'Physical counter frequency, asynchronous snapshots and scheduler/poll latency remain unmeasured.',
            'Scaled-reader wrap is not raw-counter wrap; unsigned subtraction reproduces native behavior.',
            'Timeout caller pseudocode still exposes extraout register pairs; raw instructions govern that contract.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=Path, required=True)
    parser.add_argument('--language', type=Path, required=True)
    parser.add_argument('--validation', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            result = evidence(archive, args.decompiled, args.language, args.validation, args.reference)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect timer arithmetic: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
