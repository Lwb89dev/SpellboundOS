import struct
import unittest

from analysis_scripts.riscv_save_restore import check_pair, candidate_sites, run_stub


class SaveRestoreTest(unittest.TestCase):
    def test_stack_round_trip_and_result_registers(self):
        # Independently assembled synthetic helpers, saving only ra and s0.
        code = struct.pack('<8H', 0x1141, 0xc606, 0xc422, 0x8282,
                           0x4422, 0x40b2, 0x0141, 0x8082)
        report = check_pair(code, 0x1000, 0x1000, 0x1008)
        self.assertEqual(report['saved_registers'], [1, 8])
        self.assertEqual(report['frame_bytes'], 16)
        self.assertTrue(report['arguments_a0_a7_preserved'])
        self.assertTrue(report['results_a0_a1_preserved'])

    def test_unbalanced_restore_is_rejected(self):
        code = struct.pack('<8H', 0x1141, 0xc606, 0xc422, 0x8282,
                           0x4422, 0x40b2, 0x0121, 0x8082)  # add sp,8
        with self.assertRaisesRegex(ValueError, 'balance'):
            check_pair(code, 0x1000, 0x1000, 0x1008)

    def test_missing_stack_slot_and_unsupported_instruction(self):
        for half in (0x4422, 0x9002):
            with self.subTest(half=half), self.assertRaises(ValueError):
                run_stub(struct.pack('<H', half), 0, 0, [0] * 32, {})

    def test_truncated_or_outside_pc_and_step_limit(self):
        for code, entry in ((b'\x33\x01', 0), (b'\x82\x80', 2)):
            with self.assertRaises(ValueError):
                run_stub(code, 0, entry, [0] * 32, {})
        with self.assertRaisesRegex(ValueError, 'budget'):
            run_stub(b'\x01\xa0', 0, 0, [0] * 32, {}, max_steps=3)  # C.J self

    def test_addi16sp_and_signed_li(self):
        values = [0] * 32
        values[2] = 0x1000
        result = run_stub(struct.pack('<4H', 0x7139, 0x5341, 0x0141, 0x8282),
                          0, 0, values, {})
        self.assertEqual(result['registers'][2], 0xfd0)
        self.assertEqual(result['registers'][6], 0xfffffff0)
        self.assertEqual(result['exit_register'], 5)

    def test_candidate_sites_require_correct_link_register_and_target(self):
        data = bytearray(32)
        # AUIPC t1 at 0x1002; JALR t0,t1,-2 => target 0x1000.
        struct.pack_into('<II', data, 2, 0x317, 0xffe302e7)
        hits = candidate_sites(data, 0x1000, {(0x1000, 5)})
        self.assertEqual(dict(hits), {(0x1000, 5): [0x1002]})
        self.assertEqual(dict(candidate_sites(data, 0x1000, {(0x1000, 0)})), {})
        struct.pack_into('<I', data, 6, 0xffe312e7)  # invalid JALR funct3
        self.assertEqual(dict(candidate_sites(data, 0x1000, {(0x1000, 5)})), {})
        struct.pack_into('<I', data, 6, 0xffe080e7)  # ordinary ra call
        self.assertEqual(dict(candidate_sites(data, 0x1000, {(0x1000, 5)})), {})


if __name__ == '__main__':
    unittest.main()
