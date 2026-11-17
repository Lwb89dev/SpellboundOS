import copy
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.storage_map import devices, name, partitions, source_address


class Memory:
    def __init__(self, segments):
        self.segments = segments
        self.regions = []

    def read(self, at, size):
        for base, data in self.segments.items():
            if base <= at <= at + size <= base + len(data):
                return data[at - base:at - base + size]
        raise ValueError('unmapped fixture')


def field(value):
    return value.encode('ascii').ljust(24, b'\0')


def fixture():
    descriptor = field('mock') + struct.pack('<13I', 0xffffffff, 0x7fffffff,
        0x1000, 1, 0x2000, 0x2004, 0x2008, 0x200c, 0, 0x2014, 0, 0, 0x2020)
    row = field('env') + field('mock') + struct.pack('<III', 0xc0000, 0x20000, 1)
    return Memory({0x1000: struct.pack('<I', 0x1100), 0x1100: descriptor,
                   0x1200: row})


class StorageMapParsingTest(unittest.TestCase):
    def setUp(self):
        self.memory = fixture()
        self.devices = devices(self.memory, 0x1000, 1)

    def test_callback_offsets_keep_optional_rewrite_zero(self):
        row = self.devices[0]
        self.assertEqual(row['name'], 'mock')
        self.assertEqual(row['callbacks']['read'], 0x2004)
        self.assertEqual(row['callbacks']['program'], 0x2008)
        self.assertEqual(row['callbacks']['erase'], 0x200c)
        self.assertEqual(row['callbacks']['rewrite'], 0)
        self.assertEqual(row['callbacks']['ioctl'], 0x2020)
        self.assertEqual(row['initial_capacity_word'], 0x7fffffff)

    def test_partition_offset_is_not_added_to_initial_device_base(self):
        row = partitions(self.memory, 0x1200, 1, self.devices)[0]
        self.assertEqual((row['backend_descriptor'], row['offset'], row['declared_span']),
                         (0x1100, 0xc0000, 0x20000))
        self.assertFalse(row['derives_span_from_runtime_capacity'])

    def test_zero_span_is_preserved_for_runtime_derivation(self):
        raw = bytearray(self.memory.segments[0x1200])
        struct.pack_into('<I', raw, 52, 0)
        self.memory.segments[0x1200] = raw
        row = partitions(self.memory, 0x1200, 1, self.devices)[0]
        self.assertTrue(row['derives_span_from_runtime_capacity'])
        self.assertEqual(row['declared_span'], 0)

    def test_device_table_rejects_zero_oversize_and_unaligned(self):
        for address, count in ((0x1000, 0), (0x1000, 33), (0x1001, 1)):
            with self.assertRaises(ValueError):
                devices(self.memory, address, count)

    def test_unaligned_descriptor_rejects(self):
        self.memory.segments[0x1000] = struct.pack('<I', 0x1101)
        with self.assertRaises(ValueError):
            devices(self.memory, 0x1000, 1)

    def test_required_read_program_erase_callbacks_reject_zero(self):
        for offset in (44, 48, 52):
            memory = copy.deepcopy(self.memory)
            raw = bytearray(memory.segments[0x1100])
            struct.pack_into('<I', raw, offset, 0)
            memory.segments[0x1100] = raw
            with self.assertRaises(ValueError):
                devices(memory, 0x1000, 1)

    def test_duplicate_device_name_rejects(self):
        self.memory.segments[0x1000] = struct.pack('<II', 0x1100, 0x1100)
        with self.assertRaises(ValueError):
            devices(self.memory, 0x1000, 2)

    def test_missing_partition_owner_rejects(self):
        with self.assertRaises(ValueError):
            partitions(self.memory, 0x1200, 1, [])

    def test_partition_table_rejects_zero_oversize_and_unaligned(self):
        for address, count in ((0x1200, 0), (0x1200, 65), (0x1201, 1)):
            with self.assertRaises(ValueError):
                partitions(self.memory, address, count, self.devices)

    def test_duplicate_partition_name_rejects(self):
        self.memory.segments[0x1200] *= 2
        with self.assertRaises(ValueError):
            partitions(self.memory, 0x1200, 2, self.devices)

    def test_partition_extent_overflow_rejects(self):
        raw = bytearray(self.memory.segments[0x1200])
        struct.pack_into('<II', raw, 48, 0xfffffff0, 32)
        self.memory.segments[0x1200] = raw
        with self.assertRaises(ValueError):
            partitions(self.memory, 0x1200, 1, self.devices)

    def test_invalid_fixed_width_names_reject(self):
        for value in (b'a' * 24, b'\0' * 24, b'\xff\0' + b'\0' * 22,
                      b'bad\n\0' + b'\0' * 19, b'short\0'):
            with self.assertRaises(ValueError):
                name(value)

    def test_source_address_requires_covering_startup_copy(self):
        self.memory.regions = [dict(kind='copy', source=0x8000, destination=0x1000, size=16)]
        self.assertEqual(source_address(self.memory, 0x1004, 8), 0x8004)
        for at, size in ((0x100c, 8), (0x1010, 1), (0x900, 1)):
            with self.assertRaises(ValueError):
                source_address(self.memory, at, size)
        self.memory.regions[0]['kind'] = 'zero'
        with self.assertRaises(ValueError):
            source_address(self.memory, 0x1000, 4)


class RecoveredStorageConfigurationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((Path(__file__).resolve().parents[1] / 'analysis/storage-map.json').read_text())
        cls.storage = cls.report['storage']
        cls.rows = {row['name']: row for row in cls.storage['partitions']}
        cls.devices = {row['name']: row for row in cls.storage['devices']}

    def test_startup_provenance_and_duplicate_tables(self):
        self.assertFalse(self.report['hardware_execution'])
        self.assertEqual((self.storage['configuration_source_address'],
                          self.storage['board_configuration_source_address']), (0x80c40268, 0x80c41800))
        self.assertEqual((self.storage['device_count'], self.storage['partition_count']), (5, 16))
        self.assertTrue(self.storage['board_tables_equal'])
        self.assertEqual(self.storage['descriptor_function_word'], 0x80c24106)
        self.assertEqual(len(self.report['export_sha256']), 9)

    def test_environment_uses_sftl_and_mirrors_reserve_use_eftl(self):
        for key, backend, offset, span in (('env', 'sftl', 0xc0000, 0x20000),
                ('envbak', 'eftl', 0x40000, 0x40000), ('nvms', 'eftl', 0, 0x40000)):
            row = self.rows[key]
            self.assertEqual((row['backend'], row['offset'], row['declared_span']), (backend, offset, span))
        self.assertNotIn('easyflash', self.rows)

    def test_recovery_labels_belong_to_two_backend_spaces(self):
        self.assertEqual((self.rows['recovery']['backend'], self.rows['recovery']['offset']), ('eftl', 0x80000))
        self.assertEqual((self.rows['recovery0']['backend'], self.rows['recovery0']['offset']), ('sftl', 0))
        self.assertEqual((self.rows['recovery1']['backend'], self.rows['recovery1']['offset']), ('sftl', 0x60000))

    def test_fs_size_needs_runtime_capacity(self):
        row = self.rows['fs']
        self.assertEqual((row['backend'], row['offset'], row['declared_span']), ('nand', 0x2a00000, 0))
        self.assertTrue(row['derives_span_from_runtime_capacity'])

    def test_initial_geometry_words_are_sentinels(self):
        self.assertEqual(set(self.devices), {'nand', 'nandraw', 'eftl', 'disk', 'sftl'})
        for row in self.devices.values():
            self.assertEqual((row['initial_base_word'], row['initial_capacity_word']), (0xffffffff, 0x7fffffff))

    def test_eftl_and_sftl_callback_bindings(self):
        self.assertEqual(self.devices['eftl']['callbacks']['read'], 0x80c23252)
        self.assertEqual(self.devices['eftl']['callbacks']['rewrite'], 0x80c23384)
        self.assertEqual(self.devices['sftl']['callbacks']['read'], 0x80c22e12)
        self.assertEqual(self.devices['sftl']['callbacks']['rewrite'], 0x80c22ffa)

    def test_unclassified_partition_word_is_retained(self):
        self.assertEqual(self.rows['raw']['unclassified_word_38'], 0)
        self.assertEqual(self.rows['env']['unclassified_word_38'], 1)
        self.assertEqual(self.rows['raw']['offset'], self.rows['boot']['offset'])
        self.assertNotEqual(self.rows['raw']['backend'], self.rows['boot']['backend'])


if __name__ == '__main__':
    unittest.main()
