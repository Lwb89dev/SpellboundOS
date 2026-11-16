import struct
import unittest

from analysis_scripts.rpmsg_layout import decode_rpmsg, encode_rpmsg, layout
from analysis_scripts.zrpc_fragments import Reassembler, stock_channels
from analysis_scripts.zrpc_packets import decode_channel


class RpmsgTransportTest(unittest.TestCase):
    def packets(self, payload, mtu=40):
        return stock_channels(payload, mtu=mtu, source=2, destination=1,
                              request=7, session=9, module=2)

    def test_golden_rpmsg_header_and_reserved_token_preservation(self):
        packet = encode_rpmsg(b'ab', source=1, destination=0, reserved=0x12345678)
        self.assertEqual(packet, bytes.fromhex('01000000 00000000 78563412 0200 0000 6162'))
        self.assertEqual(decode_rpmsg(packet)['reserved'], 0x12345678)
        self.assertEqual(struct.unpack_from('<H', packet, 10)[0], 0x1234)
        for wire in (packet[:15], packet[:-1], packet + b'x'):
            with self.assertRaises(ValueError):
                decode_rpmsg(wire)

    def test_pool_zero_ring_offsets_and_inverse_roles(self):
        value = layout(0x80f00000, 64, 240, 0)
        self.assertEqual(value['buffers'], 0x80f006c0)
        q0, q1 = value['queues']
        self.assertEqual((q0['entries'], q0['descriptors'], q0['available'], q0['used']),
                         (32, 0x80f00000, 0x80f00200, 0x80f00250))
        self.assertEqual(q1['descriptors'], 0x80f00360)
        self.assertEqual((q0['master_role'], q0['remote_role']), ('rx', 'tx'))
        self.assertLessEqual(q1['used_end'], value['buffers'])
        for base, count in ((0x80f00001, 64), (0xfffffff0, 64), (0x1000, 1)):
            with self.assertRaises(ValueError):
                layout(base, count, 240, 0)

    def test_unfragmented_boundary_and_nonmultiple_stream(self):
        data = bytes(range(16))
        self.assertEqual(len(self.packets(data)), 1)
        self.assertEqual(Reassembler().feed(self.packets(data)[0]), data)
        payload = bytes(range(35))
        packets = self.packets(payload)
        self.assertEqual([decode_channel(p)['sequence'] for p in packets], [0, 1, 2, 3])
        receiver = Reassembler()
        self.assertEqual([receiver.feed(p) for p in packets], [None, None, None, payload])
        self.assertIsNone(receiver.state)

    def test_exact_multiple_remains_pending_in_stock_rule(self):
        packets = self.packets(bytes(32))
        self.assertTrue(decode_channel(packets[-1])['bit1_raw'])
        receiver = Reassembler()
        self.assertTrue(all(receiver.feed(p) is None for p in packets))
        self.assertEqual(receiver.state['size'], 32)

    def test_duplicate_out_of_order_and_wrong_session_clear_state(self):
        packets = self.packets(bytes(range(35)))
        wrong = bytearray(packets[1])
        wrong[6] ^= 1
        for sequence in ((packets[0], packets[2]), (packets[0], bytes(wrong)),
                         (packets[0], packets[1], packets[1])):
            receiver = Reassembler()
            with self.assertRaises(ValueError):
                for p in sequence:
                    receiver.feed(p)
            self.assertIsNone(receiver.state)

    def test_crc_and_final_size_validation(self):
        packets = self.packets(bytes(range(35)))
        damaged = bytearray(packets[-1])
        damaged[-1] ^= 1
        receiver = Reassembler()
        for p in packets[:-1]:
            receiver.feed(p)
        with self.assertRaises(ValueError):
            receiver.feed(bytes(damaged))
        self.assertIsNone(receiver.state)
        receiver = Reassembler(maximum=34)
        with self.assertRaises(ValueError):
            receiver.feed(packets[0])

    def test_limits_and_early_terminal_chunk(self):
        for size, mtu in ((0, 40), (65512, 40), (20, 35)):
            with self.assertRaises(ValueError):
                self.packets(bytes(size), mtu)
        packets = self.packets(bytes(range(35)))
        early = bytearray(packets[1])
        early[8] &= ~2
        receiver = Reassembler()
        receiver.feed(packets[0])
        with self.assertRaises(ValueError):
            receiver.feed(bytes(early))
        self.assertIsNone(receiver.state)

    def test_native_descriptor_rejects_zero_whole_payload_crc(self):
        descriptor = bytearray(self.packets(bytes(range(35)))[0])
        descriptor[20:22] = b'\0\0'
        with self.assertRaises(ValueError):
            Reassembler().feed(bytes(descriptor))


if __name__ == '__main__':
    unittest.main()
