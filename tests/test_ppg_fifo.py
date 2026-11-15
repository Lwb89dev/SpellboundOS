import struct
import unittest

from analysis_scripts.ppg_fifo import decode_response, decode_word, register_table, transfer_plan


class OpticalFifoTest(unittest.TestCase):
    def test_fifo_status_and_complete_frame_rounding(self):
        plan = transfer_plan(0x40, 3, 5)
        self.assertEqual(plan, {'action': 'read', 'available_words': 259,
                                'read_words': 255, 'transfer_bytes': 1022})
        self.assertEqual(transfer_plan(0, 3, 5)['action'], 'wait')
        self.assertEqual(transfer_plan(0, 5, 5)['transfer_bytes'], 22)

    def test_fifo_and_cache_overflow_guards(self):
        self.assertEqual(transfer_plan(0x80, 0, 1)['action'], 'flush')
        self.assertEqual(transfer_plan(0x40, 255, 1)['read_words'], 511)
        self.assertEqual(transfer_plan(0, 10, 2, 990)['action'], 'read')
        self.assertEqual(transfer_plan(0, 11, 2, 990)['action'], 'flush')

    def test_invalid_plan_parameters(self):
        for args in ((256, 0, 1), (0, -1, 1), (0, 0, 0), (0, 0, 33), (0, 0, 1, 1001)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                transfer_plan(*args)

    def test_tagged_signed_samples_and_unclassified_bits(self):
        for raw, expected in ((0x0007ffff, 524287), (0x00080000, -524288), (0x000fffff, -1)):
            self.assertEqual(decode_word(raw)['sample'], expected)
        word = decode_word(0xd5a00001)
        self.assertEqual((word['channel'], word['measurement'], word['sample']), (2, 21, 1))
        self.assertEqual((word['unclassified_bits_20_23'], word['unclassified_bit_31']), (10, 1))

    def test_wire_endianness_and_skipped_prefix(self):
        packet = b'\xab\xcd' + struct.pack('>II', 0x21080000, 0x2207ffff)
        decoded = decode_response(packet, 2)
        self.assertEqual([e['sample'] for e in decoded], [-524288, 524287])
        self.assertEqual([e['measurement'] for e in decoded], [1, 2])

    def test_frame_guard_is_exact_and_optional(self):
        packet = bytes(2) + struct.pack('>I', 0x22000001)
        with self.assertRaisesRegex(ValueError, 'frame-start'):
            decode_response(packet, 1)
        self.assertEqual(len(decode_response(packet, 1, False)), 1)
        # Channel zero passes even if measurement is not one, as in the driver.
        self.assertEqual(len(decode_response(bytes(6), 1)), 1)

    def test_truncated_partial_frames_and_oversized_words_rejected(self):
        for packet, frame in ((b'', 1), (bytes(3), 1), (bytes(6), 2), (bytes(2 + 512 * 4), 1)):
            with self.subTest(length=len(packet)), self.assertRaises(ValueError):
                decode_response(packet, frame)
        with self.assertRaises(ValueError):
            decode_word(0x100000000)

    def test_register_write_order_and_duplicates_are_preserved(self):
        table = register_table(b'\x01\x02\x01\x03', 0x1000, 2, 0x1000)
        self.assertEqual(table['writes'], [{'register': 1, 'value': 2}, {'register': 1, 'value': 3}])
        for address, count in ((0x1000, 3), (0xfff, 1), (0x1000, 0)):
            with self.subTest(address=address, count=count), self.assertRaises(ValueError):
                register_table(bytes(4), address, count, 0x1000)


if __name__ == '__main__':
    unittest.main()
