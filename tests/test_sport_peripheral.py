import struct
import unittest
from analysis_scripts.sport_peripheral import (
    CHARACTERISTIC_CLASSIFIER, SERVICE_CLASSIFIER, classify, decode_stryd,
    layout_sizes, uuid_table)


class StrydTest(unittest.TestCase):
    def test_both_layouts_are_twenty_bytes(self):
        self.assertEqual(layout_sizes(), {'0x32': 20, '0x36': 20})

    def test_type_32_fields(self):
        payload = struct.pack('<BBBBHHHBBIHH', 0x32, 1, 2, 0xaa, 3, 4, 5, 6, 0xbb, 7, 8, 9)
        self.assertEqual(decode_stryd(payload + b'tail'),
                         {'type': 0x32, 'b1': 1, 'b2': 2, 'w1': 3, 'w2': 4, 'w3': 5,
                          'b3': 6, 'd1': 7, 'w4': 8, 'w5': 9})

    def test_type_36_skips_padding_and_u64(self):
        payload = struct.pack('<BBHHHHHQ', 0x36, 0xff, 10, 11, 12, 13, 14, 2**63)
        self.assertEqual(decode_stryd(payload),
                         {'type': 0x36, 'w1': 10, 'w2': 11, 'w3': 12, 'w4': 13, 'w5': 14})

    def test_ignored_and_short_messages(self):
        self.assertIsNone(decode_stryd(b'\x33' + bytes(19)))
        with self.assertRaises(ValueError):
            decode_stryd(b'\x32' + bytes(18))
        with self.assertRaises(ValueError):
            decode_stryd(b'')


class TableTest(unittest.TestCase):
    def image(self):
        base, data = 0x1000, bytearray(0x200)
        strings = {}
        for offset, text in ((0x10, '2902'), (0x20, '180d'),
                             (0x30, '00001530-0000-3512-2118-0009af100700')):
            data[offset:offset + len(text)] = text.encode()
            strings[text] = base + offset
        for index, text in enumerate(('2902', '180d', '00001530-0000-3512-2118-0009af100700')):
            struct.pack_into('<I', data, 0x100 + 4 * index, strings[text])
        struct.pack_into('<I', data, 0x10c, 0xdeadbeef)  # table ends at a non-string
        return bytes(data), base

    def test_walk_from_anchor(self):
        data, base = self.image()
        table = uuid_table(data, base)
        self.assertEqual([e['uuid'] for e in table],
                         ['2902', '180d', '00001530-0000-3512-2118-0009af100700'])
        self.assertEqual(table[0]['slot'], base + 0x100)

    def test_missing_anchor(self):
        with self.assertRaises(ValueError):
            uuid_table(bytes(64), 0)

    def test_classifiers(self):
        self.assertEqual(classify(SERVICE_CLASSIFIER, '180A'), 6)
        self.assertEqual(classify(SERVICE_CLASSIFIER, '7e78aa18-72cd-d3b8-a81f-5b7e589bea0f'), 1)
        self.assertEqual(classify(SERVICE_CLASSIFIER, '180d'), 0)
        self.assertEqual(classify(CHARACTERISTIC_CLASSIFIER, '2a63'), 1)
        self.assertEqual(classify(CHARACTERISTIC_CLASSIFIER, '2a37'), 0)


if __name__ == '__main__':
    unittest.main()
