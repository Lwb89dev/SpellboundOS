#!/usr/bin/env python3
"""Main-image board records: the named hardware descriptors registered at boot.

``0x701632c4`` registers every main-side board record through
``0x702b4dba(name, data, size)``.  This tool decodes that function with a small
RV32C instruction scanner (``auipc``/``addi`` pairs for the name and data
pointers, ``li``/``c.li a2`` for the size, ``auipc ra``/``jalr`` or a tail
``jr`` to the registration call), then reads each record from the
startup-aware image memory and resolves string pointers.

Field meanings are given only where an executed or disassembled consumer uses
the field (the ZTW622 attach/power code, the display bring-up); every record is
also reported as raw words.
"""
import argparse
import hashlib
import json
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
else:
    import main_freertos_kernel as kernel

REGISTER_ALL = 0x701632c4
REGISTER_END = 0x7016351a
REGISTER = 0x702b4dba

EXPECTED_NAMES = (
    'system_info', 'gpio_key', 'dev_aw32012', 'dev_cw6305', 'dev_virtual_pm', 'dev_adc_volt', 'dev_NL_motor',
    'dev_ztw622', 'dev_stk31e60', 'dev_gpu', 'dev_ag3335', 'dev_flash', 'dev_psram0', 'dev_psram1', 'dev_psram',
    'dev_bt_log', 'dev_bluebox', 'dev_nand', 'nand_partition', 'dev_nand_pm', 'dev_lcd', 'dev_icna3311',
)


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def scan(memory, start=REGISTER_ALL, end=REGISTER_END):
    """Return [(name_ptr, data_ptr, size, call_site)] for each registration call."""
    regs, out, pc = {}, [], start
    while pc < end:
        half = struct.unpack('<H', memory.read(pc, 2))[0]
        if half & 3 != 3:                                   # compressed
            op, f3 = half & 3, half >> 13
            rd = (half >> 7) & 31
            if op == 1 and f3 == 2 and rd:                  # c.li
                imm = sx(((half >> 12) & 1) << 5 | (half >> 2) & 31, 6)
                regs[rd] = ('val', imm)
            elif op == 2 and f3 == 4 and (half >> 12) & 1 == 0 and (half >> 2) & 31 == 0 and rd:   # c.jr
                if regs.get(rd, ('',))[0] == 'ptr' and regs[rd][1] == REGISTER:
                    out.append(_row(regs, pc))
            pc += 2
            continue
        w = struct.unpack('<I', memory.read(pc, 4))[0]
        op, rd, f3, rs1 = w & 0x7f, (w >> 7) & 31, (w >> 12) & 7, (w >> 15) & 31
        if op == 0x17:                                      # auipc
            regs[rd] = ('ptr', (pc + (w & 0xfffff000)) & 0xffffffff)
        elif op == 0x13 and f3 == 0:                        # addi / li
            imm = sx(w >> 20, 12)
            if rs1 == 0:
                regs[rd] = ('val', imm)
            elif regs.get(rs1, ('',))[0] == 'ptr':
                regs[rd] = ('ptr', (regs[rs1][1] + imm) & 0xffffffff)
            else:
                regs.pop(rd, None)
        elif op == 0x67:                                    # jalr / jr
            imm = sx(w >> 20, 12)
            if regs.get(rs1, ('',))[0] == 'ptr' and (regs[rs1][1] + imm) & 0xffffffff == REGISTER:
                out.append(_row(regs, pc))
            regs.pop(rd, None) if rd else None
        elif op == 0x37:                                    # lui
            regs[rd] = ('val', sx(w & 0xfffff000, 32))
        pc += 4
    return out


def _row(regs, pc):
    def get(r, kind):
        v = regs.get(r)
        if not v or v[0] != kind:
            raise ValueError(f'registration operand x{r} unresolved at {pc:#x}')
        return v[1]
    return get(10, 'ptr'), get(11, 'ptr'), get(12, 'val'), pc


def cstr(memory, address):
    try:
        raw = memory.read(address, 48).split(b'\0')[0]
    except (ValueError, IndexError):
        return None
    if len(raw) >= 2 and all(32 <= c < 127 for c in raw):
        return raw.decode()
    return None


def describe(name, raw, memory):
    words = struct.unpack('<%dI' % (len(raw) // 4), raw[:len(raw) // 4 * 4])
    s = lambda i: cstr(memory, words[i])
    u16 = lambda off: struct.unpack_from('<H', raw, off)[0]
    if name == 'system_info':
        return dict(firmware=s(0), product=s(1))
    if name == 'dev_ztw622':
        return dict(reset_pin=u16(0), interrupt_pin=u16(2), bus=s(2), vdda_rail=s(3), vddd_rail=s(4),
                    bytes_4_7=raw[4:8].hex(),
                    evidence='pins and rails used by the attach/power code 0x701eb88a/0x701eb4dc')
    if name == 'dev_stk31e60':
        return dict(bus=s(0), rail=s(1))
    if name in ('dev_aw32012', 'dev_cw6305'):
        return dict(bus=s(0), word1=f'{words[1]:#010x}', word2=words[2])
    if name == 'dev_ag3335':
        return dict(bus=s(0), rails=[s(1), s(2)], u16_fields=[u16(o) for o in range(12, 28, 2)])
    if name == 'dev_bluebox':
        return dict(bus=s(0), fields=list(words[1:5]), callbacks=[f'{w:#010x}' for w in words[5:7]])
    if name.startswith('dev_psram'):
        return dict(interface=s(0), word2_hz=words[2], base=f'{words[3]:#010x}')
    if name in ('dev_lcd', 'dev_icna3311'):
        return dict(rails=[s(0), s(1)], word2=words[2], word3=f'{words[3]:#010x}')
    if name == 'dev_NL_motor':
        return dict(word0=words[0], word1=words[1])
    if name == 'dev_flash' or name == 'nand_partition':
        return dict(strings=[x for x in (cstr(memory, w) for w in words) if x])
    return {}


def records(memory):
    out = []
    for name_ptr, data, size, site in scan(memory):
        name = cstr(memory, name_ptr)
        raw = memory.read(data, size)
        out.append(dict(name=name, data=f'{data:#010x}', size=size, call_site=f'{site:#010x}',
                        sha256=hashlib.sha256(raw).hexdigest(), words=[f'{w:#010x}' for w in
                                                                        struct.unpack('<%dI' % (size // 4), raw)],
                        strings={f'+{4 * i:#x}': cstr(memory, w) for i, w in
                                 enumerate(struct.unpack('<%dI' % (size // 4), raw)) if cstr(memory, w)},
                        decoded=describe(name, raw, memory)))
    return out


def evidence(archive):
    memory = kernel.image_memory(archive)
    rows = records(memory)
    if tuple(r['name'] for r in rows) != EXPECTED_NAMES:
        raise ValueError('unexpected registration sequence')
    code = memory.read(REGISTER_ALL, REGISTER_END - REGISTER_ALL)
    return dict(
        image='main firmware (OTA 4.6.0.3)', register_all=f'{REGISTER_ALL:#010x}', register=f'{REGISTER:#010x}',
        code_sha256=hashlib.sha256(code).hexdigest(), record_count=len(rows), records=rows,
        limitations=[
            'Records are decoded statically from the original registration function and startup-aware image '
            'memory; runtime code may change them before use.',
            'Pin numbers are the main GPIO driver numbering; physical pads, bus speeds and regulator voltages '
            'are not decoded here. Field meanings are given only where a consumer was examined.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            result = evidence(archive)
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, IndexError, struct.error) as error:
        parser.exit(2, f'Cannot inspect board records: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
