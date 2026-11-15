import struct
import unittest

from analysis_scripts.inspect_image_headers import inspect_main, inspect_sensor


class HeaderTest(unittest.TestCase):
    def test_sensor_fields_and_missing_magic(self):
        image = bytearray(0x30)
        image[:4] = b'LCPU'
        struct.pack_into('<II', image, 4, 0x80f62000, 0x80f62020)
        image[0x24:0x28] = b'HDRZ'
        struct.pack_into('<I', image, 0x2c, 0x80f6224c)
        result = inspect_sensor(image)
        self.assertEqual(result['destination_word'], 0x80f62000)
        self.assertEqual(result['entry_word'], 0x80f62020)
        self.assertEqual(result['nested_entry_word'], 0x80f6224c)
        image[0x24] = 0
        with self.assertRaises(ValueError):
            inspect_sensor(image)

    def test_main_and_truncated(self):
        image = bytearray(16)
        image[4:8] = b'HDRZ'
        struct.pack_into('<I', image, 12, 0x7016022c)
        self.assertEqual(inspect_main(image)['entry_word'], 0x7016022c)
        with self.assertRaises(ValueError):
            inspect_main(image[:8])
        with self.assertRaises(ValueError):
            inspect_sensor(b'LCPU')


if __name__ == '__main__':
    unittest.main()
