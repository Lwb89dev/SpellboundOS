import struct
import unittest
from analysis_scripts.inspect_radio_package import inspect


class RadioPrefixTest(unittest.TestCase):
    def test_record_run_stops_at_nonmatching_tuple(self):
        data = bytearray(0x70)
        data[:4] = b'GM\xbc\xdb'
        struct.pack_into('<III', data, 0x48, 0x2002000, 0x100, 0)
        struct.pack_into('<III', data, 0x54, 0x2054000, 0x200, 0)
        struct.pack_into('<III', data, 0x60, 0x20001, 0x4000201, 0x5760006)
        # Lengths must be below total size for this bounded scanner.
        struct.pack_into('<I', data, 0x4c, 0x20)
        struct.pack_into('<I', data, 0x58, 0x30)
        result = inspect(data)
        self.assertEqual(len(result['candidate_records']), 2)
        self.assertEqual(result['first_nonmatching_offset'], 0x60)
        self.assertEqual(result['candidate_records'][1]['word_0'], 0x2054000)

    def test_rejects_unknown_prefix(self):
        with self.assertRaises(ValueError):
            inspect(bytes(0x70))


if __name__ == '__main__':
    unittest.main()
