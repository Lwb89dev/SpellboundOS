import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.env_space import BASE, Model, contract, native_vectors


def sha(data):
    return hashlib.sha256(data).hexdigest()


class EnvironmentSpaceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def row(self, name, index=-1):
        return self.result(name)['rows'][index]

    def test_complete_record_space_and_cursor(self):
        row = self.row('space_one')
        self.assertEqual((row['returned'], row['free'], row['cursor']), (0, 4034, BASE + 62))

    def test_full_header_matches_independently_assembled_bytes(self):
        header = bytearray(24)
        header[:3] = bytes([1, 2, 1])
        struct.pack_into('<I', header, 4, BASE)
        header[8:12] = b'EF40'
        struct.pack_into('<III', header, 12, 0xffffffff, 4034, BASE + 62)
        self.assertEqual(self.row('space_one')['header_sha256'], sha(header))
        cache = struct.pack('<II', BASE, BASE + 62) + b'\xff' * 24
        self.assertEqual(self.row('space_one')['sector_cache_sha256'], sha(cache))

    def test_second_full_parse_uses_cached_end(self):
        first_actions = self.result('space_one')['actions']
        repeated = self.result('space_twice')
        self.assertEqual(repeated['actions'], first_actions + [f'read:{BASE}:20'])
        self.assertEqual(repeated['rows'][0], repeated['rows'][1])

    def test_real_space_parser_feeds_reservation(self):
        rows = self.result('space_then_reserve')['rows']
        self.assertEqual(rows[0]['returned'], 0)
        self.assertEqual(rows[1]['returned'], BASE + 62)
        self.assertEqual(rows[0]['sector_cache_sha256'], rows[1]['sector_cache_sha256'])

    def test_two_records_consume_both_extents(self):
        row = self.row('space_two')
        self.assertEqual((row['free'], row['cursor']), (3992, BASE + 104))

    def test_tail_pass_corrects_cursor_after_gap(self):
        row = self.row('space_gap')
        self.assertEqual((row['returned'], row['free'], row['cursor']), (0, 3954, BASE + 142))

    def test_erased_first_slot_is_marked_and_consumed(self):
        case = self.cases['space_erased_open']
        model = Model(case)
        before = bytearray(model.flash)
        before[24] = 0
        row = self.row('space_erased_open')
        self.assertEqual((row['returned'], row['free'], row['cursor']), (0, 4048, BASE + 48))
        self.assertEqual(row['flash_sha256'], sha(before))
        self.assertIn('diagnostic:283', self.result('space_erased_open')['actions'])

    def test_invalid_marker_write_error_does_not_change_parser_status(self):
        model = Model(self.cases['space_erased_write_error'])
        row = self.row('space_erased_write_error')
        self.assertEqual(row['flash_sha256'], sha(model.flash))
        self.assertEqual((row['returned'], row['free']), (0, 4048))
        self.assertIn('log:write_error', self.result('space_erased_write_error')['actions'])

    def test_selected_invalid_lengths_mark_state_five(self):
        for name in ('space_invalid_length_0', 'space_invalid_length_4294967295'):
            model = Model(self.cases[name])
            model.result()
            self.assertEqual(model.flash[24], 0)
            self.assertEqual(self.row(name)['returned'], 0)
            self.assertEqual(self.row(name)['cursor'], BASE + 62)
            self.assertIn('diagnostic:283', self.result(name)['actions'])

    def test_primary_zero_and_three_do_not_scan_records(self):
        for name in ('space_primary_0', 'space_primary_3'):
            row = self.row(name)
            self.assertEqual((row['returned'], row['free'], row['cursor']), (0, 0, BASE + 20))
            self.assertEqual(self.result(name)['actions'], [f'read:{BASE}:20'])

    def test_primary_one_reports_full_record_area(self):
        row = self.row('space_primary_1')
        self.assertEqual((row['free'], row['cursor']), (4076, BASE + 20))
        self.assertEqual(self.result('space_primary_1')['actions'], [f'read:{BASE}:20'])

    def test_bad_header_stops_before_full_fields(self):
        row = self.row('space_bad_header')
        self.assertEqual((row['returned'], row['free'], row['cursor']), (7, 0, 0))
        self.assertEqual(self.result('space_bad_header')['actions'], [f'read:{BASE}:20'])

    def test_crc_error_can_coexist_with_positive_free_space(self):
        row = self.row('space_bad_crc_state_2')
        self.assertEqual((row['returned'], row['free'], row['cursor']), (2, 4034, BASE + 62))
        self.assertIn('warn:record_integrity', self.result('space_bad_crc_state_2')['actions'])

    def test_bad_crc_marked_and_deleted_records_also_report_error(self):
        for name in ('space_bad_crc_state_3', 'space_bad_crc_state_4'):
            self.assertEqual(self.row(name)['returned'], 2)
            self.assertEqual(self.row(name)['free'], 4034)

    def test_bad_crc_in_states_one_and_five_is_consumed(self):
        for name in ('space_bad_crc_state_1', 'space_bad_crc_state_5'):
            self.assertEqual((self.row(name)['returned'], self.row(name)['free']), (0, 4034))
            self.assertNotIn('warn:record_integrity', self.result(name)['actions'])

    def test_valid_incomplete_and_deleted_records_consume_space(self):
        for name in ('space_incomplete', 'space_deleted'):
            self.assertEqual((self.row(name)['returned'], self.row(name)['cursor']), (0, BASE + 62))

    def test_error_status_is_not_replayed_from_cached_end(self):
        rows = self.result('space_bad_crc_twice')['rows']
        self.assertEqual([r['returned'] for r in rows], [2, 0])
        self.assertEqual(rows[0]['cursor'], rows[1]['cursor'])
        self.assertEqual(self.result('space_bad_crc_twice')['actions'].count('warn:record_integrity'), 1)

    def test_warm_cache_skips_corrupt_record_check(self):
        self.assertEqual(self.row('space_warm_bad_crc')['returned'], 0)
        self.assertEqual(self.result('space_warm_bad_crc')['actions'], [f'read:{BASE}:20'])

    def test_all_tested_cache_slots_and_sector_end_boundary(self):
        for slot, cursor in ((0, BASE + 20), (2, BASE + 100), (3, BASE + 4096)):
            name = 'space_warm_slot_' + str(slot)
            self.assertEqual(self.row(name)['cursor'], cursor)
            self.assertEqual(self.row(name)['free'], BASE + 4096 - cursor)
            self.assertEqual(self.result(name)['actions'], [f'read:{BASE}:20'])

    def test_trailing_programmed_bytes_advance_cursor(self):
        row = self.row('space_tail_noise')
        self.assertEqual((row['cursor'], row['free']), (BASE + 104, 3992))

    def test_erased_holes_do_not_hide_last_programmed_byte(self):
        row = self.row('space_tail_holes')
        self.assertEqual((row['cursor'], row['free']), (BASE + 107, 3989))

    def test_last_sector_byte_programmed_leaves_zero_free(self):
        row = self.row('space_tail_last_byte')
        self.assertEqual((row['cursor'], row['free']), (BASE + 4096, 0))
        self.assertEqual(row['sector_cache_sha256'], sha(b'\xff' * 32))

    def test_tail_transition_across_read_chunk_boundary(self):
        row = self.row('space_tail_chunk_boundary')
        self.assertEqual((row['cursor'], row['free']), (BASE + 94, 4002))

    def test_reservation_uses_actual_cold_parse(self):
        row = self.row('reserve_cold')
        self.assertEqual(row['returned'], BASE + 62)
        self.assertIn(f'read:{BASE + 20}:28', self.result('reserve_cold')['actions'])
        self.assertFalse(any(a.startswith('details:') for a in self.result('reserve_cold')['actions']))

    def test_real_free_count_preserves_strict_size_guard(self):
        self.assertEqual(self.row('reserve_exact')['returned'], 0xffffffff)
        self.assertEqual(self.row('reserve_below')['returned'], BASE + 62)

    def test_reservation_can_select_cursor_after_parser_error(self):
        self.assertEqual(self.row('reserve_bad_crc')['returned'], BASE + 62)
        self.assertIn('warn:record_integrity', self.result('reserve_bad_crc')['actions'])
        rows = self.result('space_bad_then_reserve')['rows']
        self.assertEqual([r['returned'] for r in rows], [2, BASE + 62])
        self.assertEqual(rows[0]['sector_cache_sha256'], rows[1]['sector_cache_sha256'])

    def test_reservation_skips_full_tail_for_next_sector(self):
        self.assertEqual(self.row('reserve_tail_full')['returned'], 0xffffffff)
        self.assertEqual(self.row('reserve_second_sector')['returned'], BASE + 4096 + 62)

    def test_bounded_host_fixtures(self):
        for changes in (dict(sectors=[]), dict(request=0), dict(space_sector=4), dict(operations=[]),
                        dict(warm_cache=[dict(slot=4, sector=0, cursor=BASE + 20)]),
                        dict(warm_cache=[dict(slot=0, sector=0, cursor=BASE + 4097)])):
            with self.assertRaises(ValueError):
                contract(copy.deepcopy(self.cases['space_one']) | changes)

    def test_all_public_native_observations_agree(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/env-space.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertIs(native['hardware_execution'], False)
        self.assertEqual((native['case_count'], len(native['cases'])), (36, 36))
        for row, case in zip(native['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= native['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))
        self.assertEqual(len(report['export_sha256']), 9)


if __name__ == '__main__':
    unittest.main()
