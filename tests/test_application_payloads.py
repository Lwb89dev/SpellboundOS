import unittest
from analysis_scripts.application_payloads import (
    decode_map_download, decode_notification, decode_phone_request, encode_notification,
)


class ApplicationPayloadsTest(unittest.TestCase):
    def test_golden_notification(self):
        wire = bytes.fromhex('03 78 56 34 12 01 00 41 00 42 00 43 00 44 00 01')
        self.assertEqual(encode_notification(0x12345678, 1, 0, (b'A', b'B', b'C', b'D'), True), wire)
        parsed = decode_notification(wire)
        self.assertEqual((parsed['identifier'], parsed['kind'], parsed['fields']),
                         (0x12345678, 1, (b'A', b'B', b'C', b'D')))
        self.assertTrue(parsed['boolean0'])
        self.assertIsNone(parsed['optional_byte'])

    def test_type_three_and_optional_fields(self):
        fields = (b'', b'one', 'caffè'.encode(), b'\xff', b'extra')
        wire = encode_notification(1, 3, 2, fields, False, optional_byte=7,
                                   optional_bool=True, optional_string=b'suffix')
        parsed = decode_notification(wire + b'tail')
        self.assertEqual(parsed['fields'], fields)
        self.assertEqual((parsed['optional_byte'], parsed['optional_bool'], parsed['optional_string']),
                         (7, True, b'suffix'))
        self.assertEqual(parsed['ignored_trailing'], b'tail')
        for arguments in ({'optional_bool': True}, {'optional_byte': 1, 'optional_string': b'x'}):
            with self.assertRaises(ValueError):
                encode_notification(1, 3, 0, fields, True, **arguments)

    def test_missing_notification_fields_and_nul_are_rejected(self):
        wire = encode_notification(1, 1, 0, (b'A', b'B', b'C', b'D'), True)
        for size in range(len(wire)):
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_notification(wire[:size])
        for fields in ((b'a',), (b'A\0B', b'', b'', b'')):
            with self.assertRaises(ValueError):
                encode_notification(1, 1, 0, fields, False)

    def test_phone_pairing_commands_use_raw_identifiers(self):
        self.assertEqual(decode_phone_request(b'\x03peer\0tail'),
                         {'opcode': 3, 'peer_identifier': b'peer', 'ignored_trailing': b'tail'})
        self.assertEqual(decode_phone_request(b'\x05peer\0')['peer_identifier'], b'peer')
        self.assertEqual(decode_phone_request(b'\x01')['opcode'], 1)
        self.assertEqual(decode_phone_request(b'\x06')['opcode'], 6)

    def test_phone_duplicate_setting_last_value_wins(self):
        parsed = decode_phone_request(bytes.fromhex('08 02 01 00 01 02'))
        self.assertEqual(parsed['settings'], ((1, 0), (1, 2)))
        self.assertTrue(parsed['effective_boolean'])
        for wire in (b'\x08\x00', b'\x08\x01\x02\x00', b'\x08\x01\x01', b'\x03peer', b'\xff'):
            with self.assertRaises(ValueError):
                decode_phone_request(wire)

    def test_map_download_default_and_explicit_mode(self):
        wire = bytes.fromhex('05 00 10 00 00 02 00') + b'a.bin\0b.bin\0'
        parsed = decode_map_download(wire)
        self.assertEqual((parsed['total_size'], parsed['files'], parsed['mode'], parsed['mode_explicit']),
                         (4096, (b'a.bin', b'b.bin'), 1, False))
        parsed = decode_map_download(wire + b'\x00tail')
        self.assertEqual((parsed['mode'], parsed['mode_explicit'], parsed['ignored_trailing']), (0, True, b'tail'))
        with self.assertRaises(ValueError):
            decode_map_download(wire, max_files=1)

    def test_map_bounds_counts_strings_and_mode_fail(self):
        wire = bytes.fromhex('05 00 10 00 00 01 00') + b'a.bin\0'
        for changed in (wire[:3], wire[:-1], wire + b'\x02',
                        bytes.fromhex('05 00 00 00 00 01 00') + b'a.bin\0',
                        bytes.fromhex('05 00 10 00 00 01 00') + b'\0',
                        bytes.fromhex('05 00 10 00 00 00 00')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                decode_map_download(changed)


if __name__ == '__main__':
    unittest.main()
