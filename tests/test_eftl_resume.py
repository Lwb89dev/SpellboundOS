import copy
import json
from pathlib import Path
import unittest

from analysis_scripts.eftl_resume import contract, native_vectors, record


class EftlResumeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name): return self.cases[name]['expected']
    def row(self, name): return self.result(name)['rows'][-1]

    def test_mixed_scan_reconstructs_logical_to_physical_block_map(self):
        row = self.row('resume_mixed')
        self.assertEqual((row['returned'], row['marker'], row['free'], row['used'], row['reserved']), (0, 0xa5, 1, 2, 1))
        self.assertEqual(row['mapping'], [2, 0xffff, 0] + [0xffff] * 5)
        self.assertEqual(row['flags'], bytes([8, 0xfe, 8, 0xff] + [0] * 4).hex())

    def test_positive_bad_status_skips_erase_in_first_scan(self):
        actions = self.result('resume_mixed')['actions']
        self.assertIn('bad:3:1', actions)
        self.assertFalse(any(a.startswith('erase:') for a in actions))
        self.assertFalse(any(a.startswith('oob:12:') for a in actions))

    def test_negative_bad_status_attempts_erase_then_reads_oob(self):
        actions = self.result('resume_negative_bad_erased')['actions']
        self.assertEqual(actions[:3], ['bad:0:-9', 'log:bad_block', 'erase:0:0'])
        self.assertTrue(actions[3].startswith('oob:0:0:'))
        self.assertEqual(self.row('resume_negative_bad_erased')['mapping'][1], 0)

    def test_nonzero_erase_result_marks_reserved_and_requests_retry(self):
        for name in ('resume_negative_bad_erase_error', 'resume_negative_bad_positive_erase'):
            row = self.row(name)
            self.assertEqual((row['returned'], row['reserved'], row['marker']), (1, 1, 0))
            self.assertEqual(bytes.fromhex(row['flags'])[0], 0xff)
            self.assertFalse(any(a.startswith('oob:') for a in self.result(name)['actions']))

    def test_repair_scan_attempts_erase_even_for_positive_bad_status(self):
        actions = self.result('resume_repair_positive_bad')['actions']
        self.assertIn('erase:0:0', actions)
        self.assertEqual((self.row('resume_repair_positive_bad')['used'], self.row('resume_repair_positive_bad')['reserved']), (1, 0))

    def test_no_free_blocks_with_reserved_blocks_requests_retry_without_marker(self):
        row = self.row('resume_all_reserved_retry')
        self.assertEqual((row['returned'], row['free'], row['used'], row['reserved'], row['marker']), (1, 0, 0, 4, 0))

    def test_repair_completion_sets_marker_even_when_all_blocks_remain_reserved(self):
        row = self.row('resume_all_reserved_repair')
        self.assertEqual((row['returned'], row['free'], row['used'], row['reserved'], row['marker']), (0, 0, 0, 4, 0xa5))

    def test_empty_scan_sets_marker_without_services(self):
        self.assertEqual(self.result('resume_empty_count')['actions'], [])
        self.assertEqual((self.row('resume_empty_count')['returned'], self.row('resume_empty_count')['marker']), (0, 0xa5))

    def test_erased_records_count_as_free(self):
        row = self.row('resume_all_unmapped')
        self.assertEqual((row['free'], row['used'], row['reserved']), (4, 0, 0))
        self.assertEqual(row['mapping'], [0xffff] * 8)

    def test_any_nonzero_oob_read_status_stops_with_minus_one(self):
        for name in ('resume_first_oob_error', 'resume_positive_oob_error'):
            row = self.row(name)
            self.assertEqual((row['returned'], row['marker'], row['free'], row['used'], row['reserved']), (0xffffffff, 0, 0, 0, 0))
            self.assertEqual(self.result(name)['actions'][-1], 'log:oob_read_error')

    def test_later_oob_failure_preserves_prior_mapping_and_pending_flag(self):
        row = self.row('resume_later_oob_error')
        self.assertEqual((row['returned'], row['used']), (0xffffffff, 1))
        self.assertEqual(row['mapping'][2], 0)
        self.assertEqual(bytes.fromhex(row['flags'])[:2], bytes([8, 0xfe]))

    def test_bad_checksum_logs_and_counts_as_free(self):
        self.assertIn('log:checksum_error', self.result('resume_bad_checksum')['actions'])
        self.assertEqual((self.row('resume_bad_checksum')['free'], self.row('resume_bad_checksum')['used']), (1, 0))

    def test_wrong_tag_skips_checksum_even_when_checksum_is_bad(self):
        for name in ('resume_wrong_tag', 'resume_wrong_tag_bad_checksum'):
            self.assertNotIn('log:checksum_error', self.result(name)['actions'])
            self.assertEqual((self.row(name)['free'], self.row(name)['used']), (1, 0))

    def test_duplicate_mapping_keeps_first_block_and_does_not_count_second_as_free(self):
        row = self.row('resume_duplicate_mapping')
        self.assertEqual((row['mapping'][2], row['used'], row['free']), (0, 1, 0))
        self.assertEqual(bytes.fromhex(row['flags'])[:2], bytes([8, 0xfe]))

    def test_existing_mapping_is_not_replaced_or_counted(self):
        row = self.row('resume_existing_mapping')
        self.assertEqual((row['mapping'][1], row['used'], row['free']), (7, 0, 0))
        self.assertEqual(bytes.fromhex(row['flags'])[0], 0xfe)

    def test_logical_index_can_exceed_block_count_within_supplied_backing(self):
        row = self.row('resume_logical_beyond_count')
        self.assertEqual((row['mapping'][7], row['used']), (0, 1))
        self.assertEqual(row['returned'], 0)

    def test_mapped_flag_preserves_low_bit(self):
        self.assertEqual(bytes.fromhex(self.row('resume_preserve_low_flag')['flags'])[0], 9)

    def test_used_counter_wraps_to_zero(self):
        self.assertEqual((self.row('resume_used_counter_wrap')['used'], self.row('resume_used_counter_wrap')['returned']), (0, 0))

    def test_free_counter_wrap_can_change_retry_decision(self):
        row = self.row('resume_free_counter_wrap')
        self.assertEqual((row['free'], row['reserved'], row['returned'], row['marker']), (0, 1, 1, 0))

    def test_reserved_counter_wrap_can_change_completion_decision(self):
        row = self.row('resume_reserved_counter_wrap')
        self.assertEqual((row['reserved'], row['returned'], row['marker']), (0, 0, 0xa5))

    def test_page_count_encoding_wraps_to_byte(self):
        row = self.row('resume_page_count_flag_wrap')
        self.assertEqual((bytes.fromhex(row['flags'])[0], row['used']), (0, 1))

    def test_checksum_accepts_high_bytes_modulo_256(self):
        data = record(self.cases['checksum_valid']['blocks'][0])
        self.assertEqual(data, bytes.fromhex('ff8045c4'))
        self.assertEqual(self.row('checksum_valid')['returned'], 1)

    def test_checksum_itself_does_not_check_tag(self):
        self.assertEqual(self.row('checksum_other_tag')['returned'], 1)
        self.assertEqual(self.row('checksum_invalid')['returned'], 0)
        self.assertEqual(self.result('checksum_invalid')['actions'], ['log:checksum_error'])

    def test_direct_repeat_accumulates_free_and_reserved_counts(self):
        rows = self.result('resume_repeat')['rows']
        self.assertEqual([(r['free'], r['used'], r['reserved']) for r in rows], [(1, 2, 1), (2, 2, 2)])
        self.assertEqual(rows[0]['mapping'], rows[1]['mapping'])

    def test_probe_rejects_backing_overruns(self):
        case = copy.deepcopy(self.cases['resume_mixed']); case['block_count'] = 9
        with self.assertRaises(ValueError): contract(case)
        case = copy.deepcopy(self.cases['resume_mixed']); case['blocks'][0]['logical'] = 8
        with self.assertRaises(ValueError): contract(case)

    def test_public_native_observations_match_all_cases(self):
        report = json.loads((Path(__file__).resolve().parents[1] / 'analysis/eftl-resume.json').read_bytes())
        execution = report['native_validation']
        self.assertIs(execution['hardware_execution'], False)
        self.assertEqual(execution['case_count'], 27)
        self.assertEqual(len(execution['cases']), len(self.cases))
        for row, case in zip(execution['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= execution['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['export_sha256']), len(report['byte_range_sha256'])), (2, 2))


if __name__ == '__main__':
    unittest.main()
