import copy
import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.eftl_read import contract, native_vectors


def page_bytes(page, column, count):
    return bytes((page * 19 + (column + i) * 3) & 255 for i in range(count))


def output_hash(prefix):
    return hashlib.sha256(prefix + b'\xa5' * (1024 - len(prefix))).hexdigest()


class EftlReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name): return self.cases[name]['expected']
    def row(self, name): return self.result(name)['rows'][-1]

    def test_single_page_translation_and_data(self):
        self.assertEqual(self.result('map_single')['actions'], ['physical:generic:12:4:16:0:16'])
        self.assertEqual(self.row('map_single'), dict(returned=16, buffer_sha256=output_hash(page_bytes(12, 4, 16))))

    def test_unaligned_read_splits_at_page_boundary(self):
        self.assertEqual(self.result('map_unaligned')['actions'], ['physical:generic:12:29:3:0:3', 'physical:generic:13:0:5:0:5'])
        self.assertEqual(self.row('map_unaligned')['buffer_sha256'], output_hash(page_bytes(12, 29, 3) + page_bytes(13, 0, 5)))

    def test_block_crossing_uses_next_translation_entry(self):
        self.assertEqual(self.result('map_multiblock')['actions'], ['physical:generic:15:24:8:0:8', 'physical:generic:4:0:32:0:32', 'physical:generic:5:0:8:0:8'])
        expected = page_bytes(15, 24, 8) + page_bytes(4, 0, 32) + page_bytes(5, 0, 8)
        self.assertEqual(self.row('map_multiblock')['buffer_sha256'], output_hash(expected))

    def test_longer_page_sequence_copies_full_requested_count(self):
        self.assertEqual(self.row('map_three_pages')['returned'], 96)
        self.assertEqual(len(self.result('map_three_pages')['actions']), 4)

    def test_zero_read_has_no_backend_calls(self):
        self.assertEqual(self.result('map_zero')['actions'], [])
        self.assertEqual(self.row('map_zero'), dict(returned=0, buffer_sha256=output_hash(b'')))

    def test_first_unmapped_block_fills_remaining_ff_and_returns_zero(self):
        self.assertEqual(self.result('map_first_unmapped')['actions'], ['log:unmapped_block'])
        self.assertEqual(self.row('map_first_unmapped'), dict(returned=0, buffer_sha256=output_hash(b'\xff' * 16)))

    def test_gap_after_prefix_stops_without_reading_later_mapped_blocks(self):
        self.assertEqual(self.result('map_gap_after_prefix')['actions'], ['physical:generic:15:24:8:0:8', 'log:unmapped_block'])
        self.assertEqual(self.row('map_gap_after_prefix'), dict(returned=8, buffer_sha256=output_hash(page_bytes(15, 24, 8) + b'\xff' * 40)))

    def test_unmapped_fill_can_span_multiple_logical_pages(self):
        self.assertEqual(self.row('map_all_unmapped')['buffer_sha256'], output_hash(b'\xff' * 96))
        self.assertEqual(self.row('map_all_unmapped')['returned'], 0)

    def test_first_page_error_is_mapped_to_minus_one(self):
        self.assertEqual(self.row('map_first_error'), dict(returned=0xffffffff, buffer_sha256=output_hash(b'')))
        self.assertEqual(self.result('map_first_error')['actions'][-1], 'log:page_read_error')

    def test_later_page_error_preserves_already_copied_prefix(self):
        self.assertEqual(self.row('map_second_error')['returned'], 0xffffffff)
        self.assertEqual(self.row('map_second_error')['buffer_sha256'], output_hash(page_bytes(12, 29, 3)))

    def test_nonnegative_backend_status_is_not_a_byte_count(self):
        self.assertEqual(self.row('map_positive_status')['returned'], 16)
        self.assertEqual(self.row('map_positive_status')['buffer_sha256'], self.row('map_single')['buffer_sha256'])

    def test_supplied_partial_copy_is_not_detected_by_translation_loop(self):
        self.assertEqual(self.row('map_short_supplied_data'), dict(returned=16, buffer_sha256=output_hash(page_bytes(12, 4, 3))))

    def test_fast_adapter_adds_base_page_and_passes_flag_one(self):
        self.assertEqual(self.result('map_fast')['actions'], ['physical:fast:20:4:16:0:16'])
        self.assertEqual(self.row('map_fast')['buffer_sha256'], output_hash(page_bytes(20, 4, 16)))
        self.assertEqual(self.result('map_fast_multiblock')['actions'][0], 'physical:fast:23:24:8:0:8')

    def test_fast_error_and_direct_adapter_error_have_distinct_return_contracts(self):
        self.assertEqual(self.row('map_fast_error')['returned'], 0xffffffff)
        self.assertEqual(self.row('page_backend_error')['returned'], 0xfffffff7)

    def test_ready_wrapper_executes_same_translation_loop(self):
        self.assertEqual(self.result('wrapper_read'), self.result('map_multiblock'))
        self.assertEqual(self.row('wrapper_gap'), dict(returned=4, buffer_sha256=output_hash(page_bytes(19, 28, 4) + b'\xff' * 12)))

    def test_direct_adapter_returns_supplied_status_and_base_addition_wraps(self):
        self.assertEqual(self.row('page_generic')['returned'], 0)
        self.assertEqual(self.row('page_fast')['returned'], 0)
        self.assertEqual(self.result('page_fast_base_wrap')['actions'], ['physical:fast:11:4:16:0:16'])

    def test_repeat_does_not_change_read_only_mapping(self):
        result = self.result('map_repeat')
        self.assertEqual(result['rows'][0], result['rows'][1])
        self.assertEqual(result['actions'], ['physical:generic:12:4:16:0:16'] * 2)

    def test_logical_block_index_and_column_are_truncated_to_u16(self):
        self.assertEqual(self.result('map_logical_block_alias')['actions'], ['physical:generic:12:0:16:0:16'])
        self.assertEqual(self.result('map_column_u16')['actions'], ['physical:generic:12:0:16:0:16'])

    def test_probe_rejects_invalid_geometry_and_mapping_backing_overrun(self):
        for changes in (dict(page_size=0), dict(pages_per_block=0), dict(size=513), dict(offset=1024)):
            case = copy.deepcopy(self.cases['map_single']) | changes
            with self.assertRaises(ValueError): contract(case)

    def test_public_native_observations_match_all_cases(self):
        report = json.loads((Path(__file__).resolve().parents[1] / 'analysis/eftl-read.json').read_bytes())
        execution = report['native_validation']
        self.assertIs(execution['hardware_execution'], False)
        self.assertEqual(execution['case_count'], 24)
        for row, case in zip(execution['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= execution['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['export_sha256']), len(report['byte_range_sha256'])), (3, 3))


if __name__ == '__main__':
    unittest.main()
