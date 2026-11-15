#!/usr/bin/env python3
"""Recover native JS module registrations directly from the Bip 6 OTA bytes.

This is a bounded instruction-pattern inspector, not an emulator or a general
RISC-V disassembler. It checks a contiguous registration sequence inside the
previously identified jssdk_runtime_init, then checks argument setup at calls
to the candidate QuickJS module/export helpers in each constructor. Unsupported
instructions in argument setup are rejected. No vendor code is executed.
"""
import argparse
import hashlib
import json
import struct
import zipfile

if __package__:
    from .js_cfunction_tables import BASE, FIRMWARE, Image, bootstrap_modules
else:
    from js_cfunction_tables import BASE, FIRMWARE, Image, bootstrap_modules

RUNTIME_INIT = 0x7044e1fc
REGISTRATION_END = 0x7044e478
NEW_MODULE = 0x7079461e
ADD_EXPORTS = 0x7079ea40
CONSTRUCTOR_WINDOW = 0x180


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def word(image, address):
    offset = address - image.base
    if not 0 <= offset <= len(image.data) - 4:
        raise ValueError(f'word outside image at {address:#x}')
    return struct.unpack_from('<I', image.data, offset)[0]


def boundaries(image, start, end, allow_partial_end=False):
    """Tile a bounded region by RV32 16/32-bit instruction lengths only."""
    if start % 2 or end % 2 or not image.base <= start < end <= image.base + len(image.data):
        raise ValueError('invalid instruction range')
    result, address = [], start
    while address < end:
        half = struct.unpack_from('<H', image.data, address - image.base)[0]
        if half & 0x1f == 0x1f:
            raise ValueError(f'unsupported instruction length at {address:#x}')
        size = 4 if half & 3 == 3 else 2
        if address + size > end and allow_partial_end:
            return result
        result.append(address)
        address += size
    if address != end:
        raise ValueError('range ends inside an instruction')
    return result


def relative_pointer(image, address, register):
    first, second = word(image, address), word(image, address + 4)
    if (first & 0xfff != (register << 7) | 0x17 or
            second & 0xfffff != (register << 15) | (register << 7) | 0x13):
        return None
    return (address + (first & 0xfffff000) + signed(second >> 20, 12)) & 0xffffffff


def jal_target(instruction, address):
    if instruction & 0xfff != 0xef:  # JAL ra, immediate
        return None
    immediate = ((instruction >> 31) << 20 | ((instruction >> 12) & 255) << 12 |
                 ((instruction >> 20) & 1) << 11 | ((instruction >> 21) & 1023) << 1)
    return (address + signed(immediate, 21)) & 0xffffffff


def long_call_target(image, address):
    first, second = word(image, address), word(image, address + 4)
    if first & 0xfff != 0x97 or second & 0xfffff != 0x80e7:
        return None  # AUIPC ra; JALR ra, ra, immediate
    return (address + (first & 0xfffff000) + signed(second >> 20, 12)) & 0xfffffffe


def setup_arguments(image, points, call, registers):
    """Read constant register setup in a short straight-line call suffix.

    Accept only AUIPC, ADDI, C.LI, C.MV and integer stores. Stores cannot change
    register constants; loads, calls, branches and every other opcode reject
    that suffix. Values start unknown, so no state crosses a call or branch.
    """
    for start in reversed([p for p in points if call - 48 <= p < call]):
        values, address = [None] * 32, start
        values[0] = 0
        while address < call:
            half = struct.unpack_from('<H', image.data, address - image.base)[0]
            if half & 3 == 3:
                instruction = word(image, address)
                rd, rs = (instruction >> 7) & 31, (instruction >> 15) & 31
                if instruction & 0x7f == 0x17:  # AUIPC
                    values[rd] = (address + (instruction & 0xfffff000)) & 0xffffffff
                elif instruction & 0x707f == 0x13:  # ADDI
                    values[rd] = None if values[rs] is None else (
                        values[rs] + signed(instruction >> 20, 12)) & 0xffffffff
                elif instruction & 0x707f != 0x2023:  # SW
                    break
                address += 4
            else:
                rd, rs = (half >> 7) & 31, (half >> 2) & 31
                if half & 0xe003 == 0x4001 and rd:  # C.LI
                    values[rd] = signed(((half >> 12) & 1) << 5 | rs, 6) & 0xffffffff
                elif half & 0xf003 == 0x8002 and rd and rs:  # C.MV
                    values[rd] = values[rs]
                elif half & 0xe003 not in (0xc000, 0xc002):  # C.SW / C.SWSP
                    break
                address += 2
            values[0] = 0
        if address == call and all(values[r] is not None for r in registers):
            return start, {r: values[r] for r in registers}
    raise ValueError(f'cannot reconstruct call arguments at {call:#x}')


def registrations(image, modules, start=RUNTIME_INIT, end=REGISTRATION_END):
    """Require one contiguous chain containing every bootstrap module once."""
    expected = [m['module'] for m in modules]
    if not expected or len(set(expected)) != len(expected):
        raise ValueError('bootstrap module names must be nonempty and unique')
    points = set(boundaries(image, start, end))
    candidates = {}
    for address in sorted(points):
        if address + 14 > end:
            continue
        pointer = relative_pointer(image, address, 11)  # a1 = module name
        if pointer is None or image.name(pointer) not in expected:
            continue
        # C.MV a0,s0 followed by JAL ra,constructor, with verified boundaries.
        if (address + 8 not in points or address + 10 not in points or
                struct.unpack_from('<H', image.data, address + 8 - image.base)[0] != 0x8522):
            continue
        target = jal_target(word(image, address + 10), address + 10)
        if target is None or target % 2 or not image.inside(target):
            continue
        candidates[address] = {
            'module': image.name(pointer), 'name_address': pointer,
            'setup_address': address, 'call_address': address + 10,
            'create_function': target,
        }
    chains = []
    for address in sorted(candidates):
        chain = [candidates.get(address + 14 * i) for i in range(len(expected))]
        if all(chain) and {r['module'] for r in chain} == set(expected):
            chains.append(chain)
    if len(chains) != 1:
        raise ValueError(f'expected one complete registration chain, found {len(chains)}')
    globals_by_module = {m['module']: m['global'] for m in modules}
    return [dict(r, **{'global': globals_by_module[r['module']]}) for r in chains[0]]


def constructor(image, address, new_module=NEW_MODULE, add_exports=ADD_EXPORTS,
                window=CONSTRUCTOR_WINDOW):
    points = boundaries(image, address, address + window, allow_partial_end=True)
    calls = [(p, long_call_target(image, p)) for p in points if p + 8 <= address + window
             and p + 4 in points]
    creates = [p for p, target in calls if target == new_module]
    exports = [p for p, target in calls if target == add_exports]
    if len(creates) != 1 or len(exports) != 1 or creates[0] >= exports[0]:
        raise ValueError(f'ambiguous module/export calls in constructor {address:#x}')
    init_start, init_args = setup_arguments(image, points, creates[0], (12,))
    table_start, table_args = setup_arguments(image, points, exports[0], (12, 13))
    table, count = table_args[12], table_args[13]
    if not 0 < count < 2048 or table % 8:
        raise ValueError(f'invalid export table/count in constructor {address:#x}')
    entries = image.table(table, count)
    if entries is None or not image.inside(init_args[12]) or init_args[12] % 2:
        raise ValueError(f'invalid table/initializer in constructor {address:#x}')
    return {'init_function': init_args[12], 'init_setup_address': init_start,
            'new_module_call': creates[0], 'export_setup_address': table_start,
            'add_exports_call': exports[0], 'table_address': table, 'count': count,
            'entries': entries}


def analyze(data):
    image = Image(data)
    modules = registrations(image, bootstrap_modules(data))
    for module in modules:
        module.update(constructor(image, module['create_function']))
    return {'member': FIRMWARE, 'member_sha256': hashlib.sha256(data).hexdigest(),
            'image_base': BASE, 'runtime_init': RUNTIME_INIT,
            'registration_search_end': REGISTRATION_END,
            'new_module_helper': NEW_MODULE, 'add_exports_helper': ADD_EXPORTS,
            'constructor_window_bytes': CONSTRUCTOR_WINDOW,
            'summary': {'modules': len(modules),
                        'export_entries': sum(m['count'] for m in modules)},
            'modules': modules}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = analyze(archive.read(FIRMWARE))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot recover registrations: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
