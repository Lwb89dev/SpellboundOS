import struct
import unittest
import zlib

from analysis_scripts.native_channel import (
    ACK, END, ENCRYPTED, START, PlaintextTransfer, accepts_uuid, counter_accepted,
    crc_evidence, crc_table, decode, encode_ack, encode_control, encode_data,
    encode_probe, fragment_plaintext, inspect_envelope, make_envelope, mix_key,
    padding_size, transmit_uuid,
)


class NativeChannelTest(unittest.TestCase):
    def test_golden_data_and_ack(self):
        wire = bytes.fromhex('03 07 12 34 00 03 00 00 00 56 00 61 62 63')
        self.assertEqual(encode_data(7, 0x12, 0x34, 0, b'abc', total_size=3, module_id=0x56), wire)
        packet = decode(wire)
        self.assertEqual((packet.flags, packet.app_id, packet.session_id, packet.sequence), (7, 0x12, 0x34, 0))
        self.assertEqual((packet.total_size, packet.module_id, packet.payload), (3, 0x56, b'abc'))
        self.assertEqual(encode_ack(0x12, 0x34, 1, 0), bytes.fromhex('04 12 34 01 00'))

    def test_control_asymmetry_and_ignored_tails(self):
        self.assertEqual(encode_probe(), b'\x01')
        wire = encode_control(2, 1, 1, 1)
        self.assertEqual(wire, bytes.fromhex('02 02 01 01 01 00'))
        packet = decode(wire)
        self.assertEqual((packet.control_value, packet.ignored_trailing), (2, bytes.fromhex('01 01 01 00')))
        self.assertEqual(decode(b'\x02\x02').control_value, 2)
        self.assertEqual(decode(b'\x01tail').ignored_trailing, b'tail')
        self.assertEqual(decode(bytes.fromhex('04 12 34 01 00 ff')).ignored_trailing, b'\xff')

    def test_module_field_is_truncated_by_parser(self):
        packet = decode(bytes.fromhex('03 01 12 34 00 01 00 00 00 56 ab ff'))
        self.assertEqual((packet.module_id_wire, packet.module_id), (0xab56, 0x56))
        with self.assertRaises(ValueError):
            encode_data(START, 1, 2, 0, b'x', total_size=1, module_id=0xab56)

    def test_malformed_headers_and_serializer_empty_guard(self):
        for wire in (b'', b'\x00', b'\x05', b'\x02', b'\x03\x00',
                     b'\x03\x01\x01\x01\x00', b'\x04\x00\x00\x01'):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                decode(wire)
        self.assertEqual(decode(b'\x03\x00\x01\x02\x03').payload, b'')
        with self.assertRaises(ValueError):
            encode_data(0, 1, 2, 3, b'')
        with self.assertRaises(ValueError):
            encode_data(0, 1, 2, 3, b'x', total_size=1)

    def test_uuid_mapping_depends_on_transport_role(self):
        for kind in (1, 2, 3, 4):
            self.assertEqual(transmit_uuid(kind), '0017' if kind in (1, 3) else '0016')
            self.assertNotEqual(transmit_uuid(kind), transmit_uuid(kind, client=True))
            self.assertTrue(accepts_uuid(transmit_uuid(kind), kind))
            self.assertFalse(accepts_uuid(transmit_uuid(kind, client=True), kind))
        self.assertFalse(accepts_uuid('0022', 3))

    def test_fragment_budget_and_reassembly(self):
        packets = fragment_plaintext(b'abcdefghijklmnopqrstuvwxyz', 0x12, 0x56, 0x34, 20)
        self.assertEqual([len(wire) for wire in packets], [20, 20, 7])
        self.assertEqual([decode(wire).flags for wire in packets], [START, 0, END | ACK])
        transfer = PlaintextTransfer()
        self.assertIsNone(transfer.feed(packets[0]))
        self.assertIsNone(transfer.feed(packets[1]))
        self.assertEqual(transfer.feed(packets[2]), b'abcdefghijklmnopqrstuvwxyz')
        single = fragment_plaintext(b'x', 1, 2, 3, 20, final_ack=False)
        self.assertEqual(decode(single[0]).flags, START | END)

    def test_ack_schedule_and_sequence_wrap(self):
        for capacity, first_ack in ((100, 78), (244, 32)):
            packets = fragment_plaintext(b'x' * (capacity * 270), 1, 2, 3, capacity)
            ack_indices = [index for index, wire in enumerate(packets) if decode(wire).flags & ACK]
            self.assertEqual(ack_indices[0], first_ack - 1)
            self.assertEqual(decode(packets[255]).sequence, 255)
            self.assertEqual(decode(packets[256]).sequence, 0)
            transfer, result = PlaintextTransfer(), None
            for wire in packets:
                result = transfer.feed(wire)
            self.assertEqual(result, b'x' * (capacity * 270))

    def test_reassembly_rejects_sequence_session_and_size_errors(self):
        packets = fragment_plaintext(b'a' * 30, 1, 2, 3, 20)
        for position, value in ((2, 9), (3, 9), (4, 9)):
            transfer = PlaintextTransfer()
            transfer.feed(packets[0])
            changed = bytearray(packets[1])
            changed[position] = value
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                transfer.feed(changed)
            self.assertIsNone(transfer.state)
        with self.assertRaisesRegex(ValueError, 'without START'):
            PlaintextTransfer().feed(packets[1])
        for total in (0, 1, 40):
            wire = encode_data(START | END, 1, 3, 0, b'abc', total_size=total, module_id=2)
            with self.subTest(total=total), self.assertRaises(ValueError):
                PlaintextTransfer().feed(wire)

    def test_host_bounds_and_encryption_are_explicit(self):
        for capacity in (0, 5, 11, 65536):
            with self.assertRaises(ValueError):
                fragment_plaintext(b'x', 1, 2, 3, capacity)
        for flags in (START, START | ENCRYPTED):
            wire = encode_data(flags, 1, 2, 0, b'x', total_size=101, module_id=3)
            with self.assertRaises(ValueError):
                PlaintextTransfer(max_size=100).feed(wire)

    def test_key_mixing_uses_all_sixteen_bytes(self):
        self.assertEqual(mix_key(bytes(range(16)), 0xa5), bytes.fromhex('a5 a4 a7 a6 a1 a0 a3 a2 ad ac af ae a9 a8 ab aa'))
        with self.assertRaises(ValueError):
            mix_key(b'short', 0)
        with self.assertRaises(ValueError):
            mix_key(bytes(16), 256)

    def test_crc_envelope_golden_and_explicit_padding(self):
        # Empty payload and 0x04030201 counter isolate the known 01 02 03 04 CRC.
        wire = make_envelope(b'', 0x04030201, padding=b'padding!')
        self.assertEqual(wire, bytes.fromhex('01 02 03 04 cd fb 3c b6') + b'padding!')
        self.assertEqual(inspect_envelope(wire, 0, 0x04030201), (b'', 0x04030201, b'padding!'))
        self.assertEqual([padding_size(n) for n in (0, 1, 15, 16, 17)], [0, 15, 1, 0, 15])
        self.assertEqual(len(make_envelope(b'12345678', 0, padding=b'')), 16)
        with self.assertRaises(ValueError):
            make_envelope(b'12345678', 0, padding=bytes(16))

    def test_envelope_rejects_corruption_length_and_counter(self):
        wire = make_envelope(b'abcdefgh', 42, padding=b'')
        for index in (0, 8, 12):
            changed = bytearray(wire)
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'CRC'):
                inspect_envelope(changed, 8, 42)
        with self.assertRaisesRegex(ValueError, 'size'):
            inspect_envelope(wire[:-1], 8, 42)
        with self.assertRaisesRegex(ValueError, 'window'):
            inspect_envelope(wire, 8, 43)

    def test_counter_window_boundaries_and_wrap(self):
        for received, expected, accepted in ((42, 42, True), (100042, 42, True),
                (100043, 42, False), (41, 42, False), (0, 0xffffffff, True),
                (0x20, 0xfffffff0, True), (0xffffffff, 0, False)):
            with self.subTest(received=received, expected=expected):
                self.assertEqual(counter_accepted(received, expected), accepted)

    def test_crc_table_matches_independent_bitwise_vectors(self):
        table = struct.unpack('<256I', crc_table())
        self.assertEqual((table[0], table[1], table[255]), (0, 0x77073096, 0x2d02ef8d))
        crc = 0xffffffff
        for value in b'123456789':
            crc = crc >> 8 ^ table[(crc ^ value) & 255]
        self.assertEqual(crc ^ 0xffffffff, 0xcbf43926)
        self.assertEqual(zlib.crc32(b'123456789'), 0xcbf43926)
        data = bytearray(b'prefix' + crc_table())
        self.assertTrue(crc_evidence(data, 0, 6)['all_256_entries_match'])
        data[17] ^= 1
        self.assertFalse(crc_evidence(data, 0, 6)['all_256_entries_match'])
        with self.assertRaises(ValueError):
            crc_evidence(data[:100], 0, 6)


if __name__ == '__main__':
    unittest.main()
