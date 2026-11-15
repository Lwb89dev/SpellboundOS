import struct
import unittest

from analysis_scripts.riscv_pc_references import candidate_references


def pair(register, upper, low, source=None):
    if source is None:
        source = register
    return struct.pack('<II', (upper & 0xfffff000) | register << 7 | 0x17,
                       (low & 0xfff) << 20 | source << 15 | register << 7 | 0x13)


class PcReferenceTest(unittest.TestCase):
    def test_positive_and_negative_immediate_at_halfword_boundary(self):
        data = b'\0\0' + pair(5, 0x2000, -16) + pair(7, 0, 8)
        hits = candidate_references(data, 0x10000, [0x1ff2, 18])
        self.assertEqual([(x['instruction_file_offset'], x['target_file_offset']) for x in hits],
                         [(2, 0x1ff2), (10, 18)])

    def test_mismatched_and_zero_register_do_not_match(self):
        data = pair(5, 0, 4, source=6) + pair(0, 0, 4)
        self.assertEqual(candidate_references(data, 0, [4, 12]), [])


if __name__ == '__main__':
    unittest.main()
