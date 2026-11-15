import unittest
from analysis_scripts.radio_checksum import checksum

class RadioChecksumTest(unittest.TestCase):
    def test_standard_check_value(self):
        self.assertEqual(checksum(b'123456789'), 0xbb3d)
        self.assertEqual(checksum(b''), 0)

    def test_streaming(self):
        data = bytes(range(256))
        self.assertEqual(checksum(data), checksum(data[100:], checksum(data[:100])))

if __name__ == '__main__': unittest.main()
