#!/usr/bin/env python3
"""Build a local analysis ELF with observed startup destinations mapped.

The output embeds vendor bytes: keep it under ignored firmware/. It is an
analysis container, not a flashable image or a proven runtime memory layout.
Segment permissions are analysis conveniences, not recovered MPU settings.
"""
import argparse
import pathlib
import struct
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
else:
    from sensorhub_memory import StartupMemory


def build_elf(memory, entry):
    sections = [('.image', memory.base, memory.data, len(memory.data), False)]
    for index, region in enumerate(memory.regions):
        if region['size']:
            zero = region['kind'] == 'zero'
            contents = b'' if zero else memory.read(region['destination'], region['size'])
            sections.append((f'.{region["kind"]}{index}', region['destination'], contents, region['size'], zero))
    if not any(address <= entry < address + size and not zero
               for _, address, _, size, zero in sections):
        raise ValueError('entry outside initialized sections')
    count = len(sections)
    output = bytearray(52 + count * 32)
    programs, headers, strings = [], [(0,) * 10], bytearray(b'\0')
    for name, address, contents, size, zero in sections:
        output.extend(bytes(-len(output) % 16))
        offset = len(output)
        output.extend(contents)
        name_offset = len(strings)
        strings.extend(name.encode() + b'\0')
        flags = 6 if zero else 7  # Conservative analysis permissions (PF_R/PF_W/PF_X).
        programs.append((1, offset, address, address, len(contents), size, flags, 4))
        headers.append((name_offset, 8 if zero else 1, 3 if zero else 7,
                        address, offset, size, 0, 0, 4, 0))
    name_offset = len(strings)
    strings.extend(b'.shstrtab\0')
    strings_offset = len(output)
    output.extend(strings)
    headers.append((name_offset, 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0))
    output.extend(bytes(-len(output) % 4))
    section_offset = len(output)
    for header in headers:
        output.extend(struct.pack('<10I', *header))
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIIIIIHHHHHH', output, 0, ident, 2, 243, 1, entry,
                     52, section_offset, 1, 52, 32, count, 40, len(headers), len(headers) - 1)
    for index, program in enumerate(programs):
        struct.pack_into('<8I', output, 52 + index * 32, *program)
    return bytes(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--image', choices=('main', 'sensor'), required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    member, base, entry, options = (
        ('META/firmware_sign.bin', 0x70160000, 0x7016022c, (0x270, 4, 0x2a0, 2))
        if args.image == 'main' else
        ('META/extfw/sensorhub@mhs003_sign.bin', 0x80f62000, 0x80f6224c, (0x280, 2, 0x298, 1)))
    try:
        with zipfile.ZipFile(args.archive) as archive:
            memory = StartupMemory(archive.read(member), base, *options)
        pathlib.Path(args.output).write_bytes(build_elf(memory, entry))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot build analysis ELF: {error}\n')


if __name__ == '__main__':
    main()
