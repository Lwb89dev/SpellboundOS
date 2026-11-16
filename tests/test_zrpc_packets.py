import struct
import unittest

from analysis_scripts.zrpc_packets import crc16, decode_channel, decode_link, encode_ack, encode_data, encode_link


class ZrpcPacketsTest(unittest.TestCase):
    def packet(self, **changed):
        fields = dict(source=2, destination=1, flags=2, request=0x1234,
                      session=0xabcd, module=2)
        fields.update(changed)
        return encode_data(bytes.fromhex('10060000'), **fields)

    def test_crc_reference_vector_and_empty_seed(self):
        self.assertEqual(crc16(b'123456789'), 0x4b37)
        self.assertEqual(crc16(b''), 0xffff)

    def test_data_header_golden_offsets_and_complete_bit(self):
        expected = bytes.fromhex('01 02 01 02 34 12 cd ab 01 00 00 00 02 00 14 00 10 06 00 00')
        self.assertEqual(self.packet(), expected)
        decoded = decode_channel(expected)
        self.assertTrue(decoded['complete'])
        self.assertEqual((decoded['request'], decoded['session'], decoded['module_raw']), (0x1234, 0xabcd, 2))
        self.assertEqual(decoded['payload'], bytes.fromhex('10060000'))

    def test_link_magic_length_and_checksum_corruption(self):
        link = encode_link(self.packet(), checksum=True)
        self.assertEqual(link[:2], b'rz')
        self.assertEqual(link[4:8], bytes.fromhex('00 00 1c 00'))
        self.assertTrue(decode_link(link)['checksum_required'])
        for offset in (0, 6, len(link) - 1):
            damaged = bytearray(link)
            damaged[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decode_link(bytes(damaged))

    def test_disabled_checksum_is_not_inferred_from_zero_value(self):
        link = encode_link(self.packet(flags=0), checksum=False)
        self.assertFalse(decode_link(link)['checksum_required'])
        with self.assertRaises(ValueError):
            decode_link(encode_link(self.packet(), checksum=False))

    def test_ack_uses_session_at_four_not_data_session_offset(self):
        ack = encode_ack(source=1, destination=2, status=6, session=0x1234)
        self.assertEqual(ack, bytes.fromhex('02 01 02 06 34 12 00 00'))
        decoded = decode_link(encode_link(ack, checksum=False))['channel']
        self.assertEqual((decoded['session'], decoded['status_raw']), (0x1234, 6))

    def test_fragment_descriptor_and_sequence_fields_stay_raw(self):
        info = struct.pack('<4HI', 1000, 3, 0xabcd, 0, 400)
        descriptor = encode_data(info, source=2, destination=1, flags=2,
                                 request=7, session=9, module=2, packed=2)
        value = decode_channel(descriptor)
        self.assertFalse(value['complete'])
        self.assertEqual(value['fragment_descriptor'],
            dict(total=1000, count=3, crc16=0xabcd, reserved=0, timeout_raw=400))
        chunk = decode_channel(self.packet(packed=(0x3fff << 2) | 2))
        self.assertEqual(chunk['sequence'], 0x3fff)
        self.assertTrue(chunk['bit1_raw'])
        self.assertNotIn('fragment_descriptor', chunk)

    def test_truncation_and_mismatched_channel_lengths_fail(self):
        packet = self.packet()
        for size in range(len(packet)):
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_channel(packet[:size])
        for packet in (packet + b'tail', b'\x03', encode_ack(source=1, destination=2, status=0, session=1) + b'\0'):
            with self.assertRaises(ValueError):
                decode_channel(packet)

    def test_host_limit_and_native_word_ranges(self):
        fields = dict(source=2, destination=1, flags=0, request=0, session=0, module=2)
        maximum = encode_data(bytes(65511), **fields)
        self.assertEqual(len(encode_link(maximum, checksum=False)), 65535)
        for size in (0, 65512):
            with self.assertRaises(ValueError):
                encode_data(bytes(size), **fields)
        for changed in (dict(source=256), dict(session=-1), dict(packed=65536), dict(flags=8)):
            with self.assertRaises(ValueError):
                self.packet(**changed)


if __name__ == '__main__':
    unittest.main()
