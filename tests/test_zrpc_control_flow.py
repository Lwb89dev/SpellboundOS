import unittest

from analysis_scripts.zrpc_control_flow import branch_taken, decode_branch, pool_size


class ZrpcControlFlowTest(unittest.TestCase):
    def test_bbs_bit_one_regression(self):
        branch = decode_branch(0xf417fe5b, 0x704e9f86)
        self.assertEqual(branch, dict(mnemonic='bbs', register=15, immediate=1,
            target=0x704e9ee2, offset=-164))
        self.assertTrue(branch_taken(branch, 2))
        self.assertTrue(branch_taken(branch, 3))
        self.assertFalse(branch_taken(branch, 1))

    def test_bbc_bit_zero_and_bbs_bit_two(self):
        clear = decode_branch(0x1407f35b, 0x704ea71c)
        self.assertEqual(clear['target'], 0x704ea862)
        self.assertTrue(branch_taken(clear, 2))
        self.assertFalse(branch_taken(clear, 3))
        set_bit = decode_branch(0x5027f35b, 0x704ea2a2)
        self.assertEqual((set_bit['immediate'], set_bit['target']), (2, 0x704ea3a8))
        self.assertTrue(branch_taken(set_bit, 4))

    def test_constant_comparisons_and_unsigned_value(self):
        equal = decode_branch(0xba87db5b, 0x704ea14a)
        self.assertEqual((equal['mnemonic'], equal['immediate'], equal['target']), ('beqc', 8, 0x704ea100))
        self.assertTrue(branch_taken(equal, 8))
        unequal = decode_branch(0xbe54e45b, 0x704e9bf2)
        self.assertTrue(branch_taken(unequal, 0xffffffff))
        self.assertFalse(branch_taken(unequal, 5))

    def test_decode_guards_and_pc_wrap(self):
        self.assertEqual(decode_branch(0x1407f35b, 0xfffffffe)['target'], 0x144)
        for word, pc in ((0x13, 0), (0xf417fedb, 0), (0xf417fe5b, 1)):
            with self.assertRaises(ValueError):
                decode_branch(word, pc)

    def test_three_reviewed_pool_sizes(self):
        self.assertEqual(pool_size(64, 240)['total_bytes'], 0x46c0)
        self.assertEqual(pool_size(16, 1008)['total_bytes'], 0x41e0)
        self.assertEqual(pool_size(2, 4080), dict(ring_bytes=64, buffer_stride=4096, total_bytes=0x2080))
        for count, payload in ((0, 240), (3, 240), (16, 1000)):
            with self.assertRaises(ValueError):
                pool_size(count, payload)


if __name__ == '__main__':
    unittest.main()
