import struct
import unittest

from analysis_scripts.signed_metadata import inspect


def fixture(length=48, magic=b'HMRVYSIG', prefix=16):
    metadata = bytearray(length)
    metadata[:8] = magic
    struct.pack_into('<HIHH', metadata, 8, length, prefix, 155, 256)
    metadata[18:23] = b'2.3.1'
    struct.pack_into('<I', metadata, 34, prefix)
    if length == 64:
        metadata[38:57] = b'2026-09-24 11:54:48'
    return bytes(prefix) + metadata + bytes(64)


class SignedMetadataTest(unittest.TestCase):
    def test_self_sized_48_and_64_byte_variants(self):
        for size in (48, 64):
            with self.subTest(size=size):
                result = inspect(fixture(size))
                self.assertEqual(result['metadata_bytes'], size)
                self.assertEqual(result['signature_offset'], 16 + size)
                self.assertTrue(result['body_size_matches_offset'])
                self.assertEqual((result['product_field'], result['variant_field']), (155, 256))
                self.assertEqual(result['version'], '2.3.1')
        self.assertEqual(inspect(fixture(64))['build_text_candidate'], '2026-09-24 11:54:48')

    def test_secondary_size_difference_is_observation(self):
        data = bytearray(fixture(prefix=0x410))
        struct.pack_into('<I', data, 0x410 + 34, 0x10)
        self.assertEqual(inspect(data)['size_field_difference'], 0x400)

    def test_incorrect_body_size_is_reported_not_authenticated(self):
        data = bytearray(fixture())
        struct.pack_into('<I', data, 16 + 10, 999)
        self.assertFalse(inspect(data)['body_size_matches_offset'])

    def test_wrong_length_missing_signature_or_marker_rejected(self):
        data = bytearray(fixture())
        struct.pack_into('<H', data, 24, 64)
        for blob in (data, fixture()[:-1], bytes(128), b''):
            with self.subTest(size=len(blob)), self.assertRaises(ValueError):
                inspect(blob)

    def test_magic_must_terminate_at_the_signature_boundary(self):
        data = bytearray(fixture())
        data[:8] = b'HMBZSIGN'  # incidental magic outside the terminal metadata
        self.assertEqual(inspect(data)['magic'], 'HMRVYSIG')


if __name__ == '__main__':
    unittest.main()
