import hashlib
import unittest
from unittest.mock import patch

from analysis_scripts import repair_ghidra_dsp as dsp
from analysis_scripts.timer_arithmetic import (
    dsp_decode, first_timeout_raw_delta, ipc_wait_from_raw, scaled_counter,
)


class TimerArithmeticTest(unittest.TestCase):
    def test_actual_pack_instruction_aliases(self):
        for word, registers in ((0x0fc8187f, (16, 16, 28)), (0x0fc797ff, (15, 15, 28)),
                                (0x0ee6177f, (14, 12, 14)), (0x0f07187f, (16, 14, 16))):
            result = dsp_decode(word)
            self.assertEqual(result['operation'], 'pkbb16')
            self.assertEqual((result['rd'], result['rs1'], result['rs2']), registers)

    def test_actual_accumulate_encoding(self):
        self.assertEqual(dsp_decode(0xc4c69fff), dict(operation='maddr32', rd=31, rs1=13, rs2=12))

    def test_other_dsp_draft_opcodes_and_functions_are_rejected(self):
        for word in (0x0fc8183f, 0x0fc81877, 0x0fc8287f, 0x1fc8187f, 0xc6c69fff,
                     0x10fc8187f, -1, True):
            with self.assertRaises(ValueError):
                dsp_decode(word)

    def test_source_guard_rejects_unreviewed_and_altered_sources(self):
        for data in (b'', b'unreviewed source', dsp.ADDITION, dsp.ADDITION + b'\n'):
            with self.assertRaises(ValueError):
                dsp.repair(data)

    def test_guarded_append_is_idempotent_and_preserves_source(self):
        # Synthetic base exercises the guard without redistributing Ghidra source.
        source = b'synthetic BBS-corrected language fixture\n'
        with patch.object(dsp, 'BBS_SHA256', hashlib.sha256(source).hexdigest()):
            expected = source + dsp.ADDITION
            self.assertEqual(dsp.repair(source), expected)
            self.assertEqual(dsp.repair(expected), expected)
            for altered in (expected + b'\n', expected.replace(b'rs1 << 16', b'rs1 << 15'),
                            expected + dsp.ADDITION, source[:-1]):
                with self.assertRaises(ValueError):
                    dsp.repair(altered)

    def test_scaled_reader_boundaries_and_unsigned_high_word(self):
        for raw, expected in ((0, 0), (999, 0), (1000, 1), (1001, 1),
                              (0x100000000, 4294967), (2**64 - 1, 18446744073709551)):
            self.assertEqual(scaled_counter(raw), expected)

    def test_conversion_precedes_subtraction_at_all_counter_phases(self):
        # floor((now-start)/1000) is wrong whenever the snapshot phases differ.
        for phase in range(1000):
            start = 10000000 + phase
            delta = first_timeout_raw_delta(start)
            self.assertEqual(delta, 1000000 - phase)
            self.assertFalse(ipc_wait_from_raw(start, start + delta - 1))
            self.assertTrue(ipc_wait_from_raw(start, start + delta))
        self.assertEqual(first_timeout_raw_delta(999), 999001)

    def test_raw_wrap_is_not_a_scaled_reader_wrap(self):
        # This matches unsigned native subtraction; it is not elapsed time.
        self.assertTrue(ipc_wait_from_raw(2**64 - 1, 0))
        with self.assertRaises(ValueError):
            first_timeout_raw_delta(2**64 - 1)

    def test_unsigned_inputs_reject_negative_oversized_bool_and_float(self):
        for invalid in (-1, 2**64, True, 1.0):
            for function in (scaled_counter, first_timeout_raw_delta):
                with self.assertRaises(ValueError):
                    function(invalid)
            with self.assertRaises(ValueError):
                ipc_wait_from_raw(0, invalid)


if __name__ == '__main__':
    unittest.main()
