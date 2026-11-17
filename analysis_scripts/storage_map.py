#!/usr/bin/env python3
"""Recover boot storage tables from startup data, without device access.

Offsets belong to named backend address spaces. FTL translation, runtime
capacity changes and physical NAND placement are not reconstructed here.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH, digest, image_memory
else:
    from recovery_validator import BOOT_HASH, digest, image_memory

CONFIG = 0x80d805b0
BOARD_PARTITIONS = 0x80d81b48
DESCRIPTOR_SIZE = 76
PARTITION_SIZE = 60
CALLBACKS = ('initialize', 'read', 'program', 'erase', 'rewrite', 'deinitialize',
             'unclassified_40', 'unclassified_44', 'ioctl')
EXPORTS = (0x80c01098, 0x80c23bd0, 0x80c23cee, 0x80c24106, 0x80c24140,
           0x80c24340, 0x80c231b2, 0x80c231d6, 0x80c229ec)
STATIC_RANGES = ((0x80c01098, 0x106), (0x80c23bd0, 0x11e), (0x80c23cee, 0xaa),
                 (0x80c24106, 0x3a), (0x80c24140, 0xd8), (0x80c24340, 0x96),
                 (0x80c231b2, 0x24), (0x80c231d6, 0x7c), (0x80c229ec, 0x24))


def words(memory, address, count):
    return struct.unpack('<' + 'I' * count, memory.read(address, count * 4))


def name(field):
    if len(field) != 24 or b'\0' not in field:
        raise ValueError('storage name must terminate within 24 bytes')
    value = field.split(b'\0', 1)[0]
    if not value or any(b < 32 or b > 126 for b in value):
        raise ValueError('invalid storage name')
    return value.decode('ascii')


def devices(memory, address, count):
    if address % 4 or not 1 <= count <= 32:
        raise ValueError('device table bounds')
    result = []
    for pointer in words(memory, address, count):
        if pointer % 4:
            raise ValueError('unaligned device descriptor')
        raw = memory.read(pointer, DESCRIPTOR_SIZE)
        data = struct.unpack_from('<13I', raw, 24)
        if any(not data[i] for i in (5, 6, 7)):
            raise ValueError('required storage callback missing')
        result.append(dict(address=pointer, name=name(raw[:24]),
                           initial_base_word=data[0], initial_capacity_word=data[1],
                           initial_block_word=data[2], initial_word_24=data[3],
                           callbacks=dict(zip(CALLBACKS, data[4:])),
                           sha256=digest(raw)))
    if len({d['name'] for d in result}) != count:
        raise ValueError('duplicate device name')
    return result


def partitions(memory, address, count, device_rows):
    if address % 4 or not 1 <= count <= 64:
        raise ValueError('partition table bounds')
    owners = {row['name']: row['address'] for row in device_rows}
    result = []
    for index in range(count):
        pointer = address + index * PARTITION_SIZE
        raw = memory.read(pointer, PARTITION_SIZE)
        owner = name(raw[24:48])
        if owner not in owners:
            raise ValueError('partition owner absent from device table')
        offset, span, extra = struct.unpack_from('<III', raw, 48)
        if offset + span > 0xffffffff:
            raise ValueError('partition extent overflow')
        result.append(dict(address=pointer, name=name(raw[:24]), backend=owner,
                           backend_descriptor=owners[owner], offset=offset,
                           declared_span=span, derives_span_from_runtime_capacity=span == 0,
                           unclassified_word_38=extra))
    if len({p['name'] for p in result}) != count:
        raise ValueError('duplicate partition name')
    return result


def source_address(memory, address, size):
    for region in memory.regions:
        if (region['kind'] == 'copy' and
                region['destination'] <= address <= address + size <= region['destination'] + region['size']):
            return region['source'] + address - region['destination']
    raise ValueError('storage configuration must have startup-copy provenance')


def extract(memory):
    table, count, rows, length = words(memory, CONFIG, 4)
    board_rows, board_count = words(memory, BOARD_PARTITIONS, 2)
    dev = devices(memory, table, count)
    parts = partitions(memory, rows, length, dev)
    board = partitions(memory, board_rows, board_count, dev)
    if memory.read(rows, length * PARTITION_SIZE) != memory.read(board_rows, board_count * PARTITION_SIZE):
        raise ValueError('boot device and named NAND partition tables differ')
    return dict(configuration_address=CONFIG,
                configuration_source_address=source_address(memory, CONFIG, 16),
                device_pointer_table=table, device_count=count,
                device_pointer_table_source_address=source_address(memory, table, count * 4),
                devices=dev, partition_table=rows, partition_count=length,
                partition_table_sha256=digest(memory.read(rows, length * PARTITION_SIZE)),
                partitions=parts, board_partition_configuration=BOARD_PARTITIONS,
                board_configuration_source_address=source_address(memory, BOARD_PARTITIONS, 8),
                board_partition_table=board_rows, board_partition_count=board_count,
                board_tables_equal=True,
                descriptor_function_word_address=0x80d810fc,
                descriptor_function_word=words(memory, 0x80d810fc, 1)[0])


def evidence(archive, exports):
    memory = image_memory(archive)
    result = extract(memory)
    # The copied method word links the published device to registry setup.
    if result['descriptor_function_word'] != 0x80c24106:
        raise ValueError('unexpected flash initialization method')
    return dict(boot_sha256=BOOT_HASH, hardware_execution=False,
                storage=result,
                byte_range_sha256={f'{at:08x}_{size:x}': digest(memory.read(at, size))
                                   for at, size in STATIC_RANGES},
                export_sha256={f'{at:08x}.c': digest((exports / f'{at:08x}.c').read_bytes()) for at in EXPORTS},
                limitations=[
                    'This is original boot ROM/startup configuration, not a live RAM or physical flash dump.',
                    'Partition offsets are relative to nand/nandraw/eftl/sftl backend address spaces; FTL translation is not a physical linear map.',
                    'Descriptor base/capacity/block words are initial values; lazy initialization and runtime geometry can change them.',
                    'The five driver callback addresses are recovered bindings, not independently implemented or electrically validated drivers.',
                    'Registry population and driver control flow are inspected statically here; prior native dispatch tests use synthetic descriptors.',
                    'The extra partition word and two descriptor callbacks remain unclassified; runtime storage availability and persistence are unproven.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled', type=Path, required=True)
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = evidence(archive, args.decompiled)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect boot storage map: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
