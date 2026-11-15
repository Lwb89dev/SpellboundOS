import struct
import unittest

from analysis_scripts.sensorhub_memory import StartupMemory, board_configuration, operation_records


def fixture():
    data = bytearray(0x400)
    struct.pack_into('<3I', data, 0, 0x1100, 0x2000, 0x100)
    struct.pack_into('<2I', data, 12, 0x2100, 0x40)
    for offset, text in ((0x300, b'synthetic_spi'), (0x310, b'CORE'),
                         (0x320, b'LED'), (0x340, b'MAX8617X TEST')):
        data[offset:offset + len(text) + 1] = text + b'\0'
    struct.pack_into('<4IHHI', data, 0x120, 0x1300, 0x1310, 0x1320, 0, 39, 65535, 4)
    struct.pack_into('<12I', data, 0x180, 0x1340, 0, 0, 0, 0x1200, 0x1202,
                     0, 0x1204, 0x1206, 0x1208, 0, 0)
    return data


def memory(data):
    return StartupMemory(data, base=0x1000, copy_offset=0, copy_count=1,
                         zero_offset=12, zero_count=1)


class StartupMemoryTest(unittest.TestCase):
    def test_copy_zero_and_unmapped_reads(self):
        data = fixture()
        image = memory(data)
        self.assertEqual(image.read(0x2000, 0x100), bytes(data[0x100:0x200]))
        self.assertEqual(image.read(0x2100, 64), bytes(64))
        self.assertEqual(image.string(0x1300), 'synthetic_spi')
        for address, size in ((0x2200, 1), (0x20fc, 8), (0x2100, -1)):
            with self.subTest(address=address), self.assertRaises(ValueError):
                image.read(address, size)

    def test_board_configuration_from_relocated_initial_data(self):
        config = board_configuration(memory(fixture()), 0x2020)
        self.assertEqual(config['bus'], 'synthetic_spi')
        self.assertEqual(config['power_names'], ['CORE', 'LED'])
        self.assertEqual(config['logical_irq_gpio'], 39)
        self.assertEqual(config['reset_gpio_raw'], 65535)

    def test_optical_record_and_callback_validation(self):
        data = fixture()
        record = operation_records(memory(data), 0x2080, 1)[0]
        self.assertEqual(record['name'], 'MAX8617X TEST')
        self.assertEqual(record['callbacks']['read_candidate'], 0x1204)
        struct.pack_into('<I', data, 0x190, 0xffffffff)
        with self.assertRaisesRegex(ValueError, 'callback'):
            operation_records(memory(data), 0x2080, 1)
        with self.assertRaises(ValueError):
            operation_records(memory(data), 0x2080, 0)

    def test_invalid_and_overlapping_regions_rejected(self):
        for offset, value in ((0, 0x1400), (4, 0x2001),
                              (8, 0xfffffffc), (12, 0x2080), (4, 0x1100)):
            data = fixture()
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                memory(data)
        with self.assertRaisesRegex(ValueError, 'table outside'):
            memory(bytes(10))

    def test_strings_must_terminate_and_be_ascii(self):
        for replacement in (b'\xff', b'a' * 128):
            data = fixture()
            data[0x300:0x300 + len(replacement)] = replacement
            with self.assertRaises(ValueError):
                memory(data).string(0x1300)

    def test_startup_loops_round_partial_words_and_allow_empty_records(self):
        data = fixture()
        struct.pack_into('<I', data, 8, 5)
        image = memory(data)
        self.assertEqual(image.regions[0]['size'], 8)
        self.assertEqual(image.regions[0]['declared_size'], 5)
        self.assertEqual(image.read(0x2000, 8), bytes(data[0x100:0x108]))
        struct.pack_into('<I', data, 8, 0)
        self.assertEqual(memory(data).regions[0]['size'], 0)


if __name__ == '__main__':
    unittest.main()
