#!/usr/bin/env python3
"""Reconstruct sensor-hub initial RAM from observed startup copy/zero tables.

No startup code is executed. Table offsets and board addresses are specific to
the investigated OTA. Initial data is not a live RAM dump or measured pinout.
"""
import argparse
import hashlib
import json
import pathlib
import re
import struct
import zipfile

BASE = 0x80f62000
MEMBER = 'META/extfw/sensorhub@mhs003_sign.bin'


class StartupMemory:
    def __init__(self, data, base=BASE, copy_offset=0x280, copy_count=2,
                 zero_offset=0x298, zero_count=1):
        self.data, self.base, self.regions = data, base, []
        for offset, count, stride, kind in ((copy_offset, copy_count, 12, 'copy'),
                                             (zero_offset, zero_count, 8, 'zero')):
            if offset < 0 or count < 0 or offset + count * stride > len(data):
                raise ValueError('startup table outside image')
            for index in range(count):
                fields = struct.unpack_from('<' + 'I' * (stride // 4), data, offset + index * stride)
                source, destination, size = fields if kind == 'copy' else (None, *fields)
                declared_size = size
                # Startup loops compare offset < size and copy/zero whole words.
                size = (size + 3) & ~3
                if not 0 <= size <= 0x800000 or destination + size > 0x100000000:
                    raise ValueError('invalid startup region size')
                if destination % 4:
                    raise ValueError('startup region must be word aligned')
                if source is not None and (source % 4 or not base <= source <= source + size <= base + len(data)):
                    raise ValueError('copy source outside image or unaligned')
                if size and any(destination < r['destination'] + r['size'] and
                       r['destination'] < destination + size for r in self.regions):
                    raise ValueError('overlapping startup destinations')
                if size and destination < base + len(data) and base < destination + size:
                    raise ValueError('startup destination overlaps mapped image')
                self.regions.append({'kind': kind, 'source': source,
                                     'destination': destination, 'size': size})
                if size != declared_size:
                    self.regions[-1]['declared_size'] = declared_size

    def read(self, address, size):
        if size < 0:
            raise ValueError('negative read size')
        if self.base <= address <= address + size <= self.base + len(self.data):
            return self.data[address - self.base:address - self.base + size]
        for region in self.regions:
            if region['destination'] <= address <= address + size <= region['destination'] + region['size']:
                if region['kind'] == 'zero':
                    return bytes(size)
                offset = region['source'] - self.base + address - region['destination']
                return self.data[offset:offset + size]
        raise ValueError(f'read outside reconstructed regions at {address:#x}')

    def string(self, address):
        result = bytearray()
        for index in range(128):
            value = self.read(address + index, 1)[0]
            if not value:
                return result.decode('ascii')
            if not 32 <= value < 127:
                raise ValueError('non-ASCII string')
            result.append(value)
        raise ValueError('unterminated string')


def board_configuration(memory, address=0x80f153dc):
    bus, core_power, led_power, unknown, irq, reset, trigger = struct.unpack(
        '<4IHHI', memory.read(address, 24))
    return {'state_address': address, 'bus': memory.string(bus),
            'power_names': [memory.string(core_power), memory.string(led_power)],
            'unclassified_word_0c': unknown, 'logical_irq_gpio': irq,
            'reset_gpio_raw': reset, 'irq_configuration_word': trigger}


def operation_records(memory, start=0x80f15568, count=6):
    if not 0 < count <= 128:
        raise ValueError('invalid operation record count')
    records = []
    for index in range(count):
        address = start + index * 48
        words = struct.unpack('<12I', memory.read(address, 48))
        name = memory.string(words[0])
        if not name.startswith('MAX8617X '):
            raise ValueError('unexpected optical sensor record name')
        if any(value and (value % 2 or not memory.base <= value < memory.base + len(memory.data))
               for value in (words[4], words[5], words[7], words[8], words[9], words[10])):
            raise ValueError('callback outside mapped image')
        records.append({'state_address': address, 'name': name,
                        'words': list(words), 'callbacks': {
                            'start_candidate': words[4], 'stop_candidate': words[5],
                            'read_candidate': words[7], 'control_candidate': words[8],
                            'flush_candidate': words[9], 'power_candidate': words[10]}})
    return records


def analyze(data, directory=None):
    memory = StartupMemory(data)
    configuration = board_configuration(memory)
    records = operation_records(memory)
    report = {'member': MEMBER, 'member_sha256': hashlib.sha256(data).hexdigest(),
              'image_base': BASE, 'copy_table_address': BASE + 0x280,
              'zero_table_address': BASE + 0x298, 'regions': memory.regions,
              'ppg_board_configuration': configuration, 'optical_sensor_records': records,
              'motion_bus': memory.string(struct.unpack('<I', memory.read(0x80f16ae8, 4))[0])}
    if directory:
        sources = {}
        for address in (0x80f6295a, 0x80f6257c, 0x80f76ae6, 0x80f7304c, 0x80f73152):
            text = (pathlib.Path(directory) / f'ram_{address:08x}.c').read_text()
            sources[f'ram_{address:08x}.c'] = hashlib.sha256(text.encode()).hexdigest()
            if address == 0x80f76ae6:
                register = re.search(r'FUN_ram_80f7304c\((0x[0-9a-f]+),acStack_50\)', text)
                expected = re.search(r"acStack_50\[0\] == '(.)'", text)
                frequency = re.search(r'uStack_64 = (\d+);', text)
                flags = re.search(r'uStack_60 = (0x[0-9a-f]+);', text)
                if not all((register, expected, frequency, flags)):
                    raise ValueError('unresolved probe constants in export')
                report['probe_export_observations'] = {
                    'function': address, 'identity_register': int(register[1], 0),
                    'expected_identity': ord(expected[1]),
                    'bus_frequency_field': int(frequency[1]), 'bus_configuration_word': int(flags[1], 0)}
        report['source_sha256'] = sources
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--decompiled')
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = analyze(archive.read(MEMBER), args.decompiled)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot reconstruct sensor memory: {error}\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
