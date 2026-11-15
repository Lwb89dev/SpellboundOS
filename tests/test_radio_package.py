import struct
import unittest
from analysis_scripts.inspect_radio_package import inspect

class RadioPrefixTest(unittest.TestCase):
    def image(self):
        data = bytearray(0x80)
        data[:2] = b'GM'
        struct.pack_into('<I', data, 2, 0x80)
        struct.pack_into('<I', data, 0x28, 0x12)
        struct.pack_into('<III', data, 0x48, 0x2002000, 0x10, 0)
        struct.pack_into('<III', data, 0x54, 0x2054000, 0x10, 0)
        return data

    def test_bitmap_and_payload_accounting(self):
        data = self.image()
        # Observed package signature has a variable size embedded at offset 2.
        result = inspect(data)
        self.assertEqual(result['bitmap_popcount'], 2)
        self.assertEqual(result['candidate_records'][0]['candidate_payload_offset'], 0x60)
        self.assertTrue(result['payload_lengths_match_declared_end'])

    def test_rejects_payload_overflow(self):
        data = self.image()
        struct.pack_into('<I', data, 0x4c, 0x1000)
        with self.assertRaises(ValueError): inspect(data)

    def test_rejects_unknown_prefix(self):
        with self.assertRaises(ValueError): inspect(bytes(0x70))
