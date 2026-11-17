import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.env_scan import BASE, contract, native_vectors, sector


def sha(data):
    return hashlib.sha256(data).hexdigest()


class EnvironmentScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def test_header_fields_match_independent_bytes(self):
        header = bytearray(24)
        header[:3] = b'\x01\x01\x01'
        struct.pack_into('<I', header, 4, BASE)
        header[8:12] = b'EF40'
        struct.pack_into('<I', header, 12, 0xffffffff)
        self.assertEqual(self.result('header_valid')['header_sha256'], sha(header))
        self.assertEqual(self.result('header_valid')['returned'], 0)

    def test_invalid_header_reports_seven_and_preserves_observed_magic(self):
        header = bytearray(24)
        struct.pack_into('<I', header, 4, BASE)
        header[8:12] = b'BAD!'
        struct.pack_into('<I', header, 12, 0xffffffff)
        self.assertEqual(self.result('header_bad')['returned'], 7)
        self.assertEqual(self.result('header_bad')['header_sha256'], sha(header))

    def test_header_light_mode_does_not_compute_free_space(self):
        header = bytearray(24)
        header[:3] = bytes([1, 3, 2])
        struct.pack_into('<I', header, 4, BASE)
        header[8:12] = b'EF40'
        struct.pack_into('<I', header, 12, 2)
        self.assertEqual(self.result('header_link')['header_sha256'], sha(header))
        self.assertEqual(self.result('header_link')['actions'], [f'read:{BASE}:20'])

    def test_sector_walker_start_sequential_and_stop(self):
        self.assertEqual(self.result('next_first')['returned'], BASE)
        self.assertEqual(self.result('next_sequential')['returned'], BASE + 4096)
        self.assertEqual(self.result('next_last')['returned'], 0xffffffff)
        self.assertEqual(self.result('next_last')['actions'], [])

    def test_sector_link_is_relative_to_current_sector(self):
        self.assertEqual(self.result('next_link2')['returned'], BASE + 8192)

    def test_first_record_descriptor_matches_independent_layout(self):
        descriptor = bytearray(56)
        descriptor[:3] = bytes([2, 1, 7])
        struct.pack_into('<II', descriptor, 8, 42, 7)
        descriptor[16:23] = b'upgrade'
        struct.pack_into('<II', descriptor, 48, BASE + 20, BASE + 55)
        row = self.result('find_first')
        self.assertEqual(row['returned'], 1)
        self.assertEqual(row['descriptor_sha256'], sha(descriptor))
        self.assertEqual(row['key_cache_record'], BASE + 20)

    def test_get_populates_cache_from_synthetic_records(self):
        row = self.result('get_empty_cache')
        self.assertEqual((row['returned'], row['length_output']), (7, 7))
        self.assertEqual(row['output_sha256'], sha(b'payload' + b'\xa5' * 249))
        self.assertEqual(row['key_cache_record'], BASE + 20)

    def test_get_clips_copy_but_keeps_original_size(self):
        row = self.result('get_clip')
        self.assertEqual((row['returned'], row['length_output']), (3, 7))
        self.assertEqual(row['output_sha256'], sha(b'pay' + b'\xa5' * 253))

    def test_state_one_is_rejected_without_cached_record_pointer(self):
        row = self.result('find_state_1')
        self.assertEqual(row['returned'], 0)
        self.assertEqual(row['key_cache_record'], 0xffffffff)

    def test_marked_and_deleted_record_states_are_rejected(self):
        for name in ('find_state_3', 'find_state_4'):
            self.assertEqual(self.result(name)['returned'], 0)

    def test_bad_crc_wrong_name_and_length_do_not_match(self):
        for name in ('find_bad_crc', 'find_wrong_name', 'find_wrong_length'):
            self.assertEqual(self.result(name)['returned'], 0)
            self.assertEqual(self.result(name)['key_cache_record'], 0xffffffff)

    def test_record_search_finds_later_record(self):
        row = self.result('find_second')
        self.assertEqual(row['returned'], 1)
        self.assertEqual(row['key_cache_record'], BASE + 62)

    def test_magic_search_resynchronizes_after_gap(self):
        row = self.result('find_gap')
        self.assertEqual(row['returned'], 1)
        self.assertEqual(row['key_cache_record'], BASE + 100)
        self.assertGreater(sum(a.endswith(':32') for a in row['actions']), 1)

    def test_search_continues_after_deleted_or_crc_bad_record(self):
        for name in ('find_deleted_then_live', 'find_bad_crc_then_live'):
            self.assertEqual(self.result(name)['returned'], 1)
            self.assertEqual(self.result(name)['key_cache_record'], BASE + 62)

    def test_duplicate_name_uses_first_eligible_record(self):
        self.assertEqual(self.result('find_duplicate_first')['key_cache_record'], BASE + 20)

    def test_full_sector_and_invalid_header_handling(self):
        self.assertEqual(self.result('find_full_sector')['returned'], 1)
        row = self.result('find_skip_bad_header')
        self.assertEqual(row['key_cache_record'], BASE + 4096 + 20)
        self.assertEqual(row['actions'][:2], [f'read:{BASE}:20', f'read:{BASE + 4096}:20'])

    def test_linked_traversal_skips_intermediate_sector_header(self):
        row = self.result('find_link2')
        self.assertEqual(row['key_cache_record'], BASE + 8192 + 20)
        self.assertNotIn(f'read:{BASE + 4096}:20', row['actions'])
        self.assertIn(f'read:{BASE + 8192}:20', row['actions'])

    def test_unused_sectors_do_not_yield_record_candidates(self):
        row = self.result('find_no_open_sectors')
        self.assertEqual(row['returned'], 0)
        self.assertEqual(row['actions'], [f'read:{BASE + i * 4096}:20' for i in range(4)])

    def test_reservation_requires_strictly_more_than_request(self):
        self.assertEqual(self.result('reserve_open')['returned'], BASE + 20)
        self.assertEqual(self.result('reserve_equal_rejected')['returned'], 0xffffffff)
        self.assertIn(f'details:{BASE}', self.result('reserve_equal_rejected')['actions'])

    def test_reservation_without_eligible_sectors_fails(self):
        self.assertEqual(self.result('reserve_none')['returned'], 0xffffffff)
        self.assertEqual(self.result('reserve_none')['maintenance_flag'], 0)
        self.assertFalse(any(a.startswith('details:') for a in self.result('reserve_none')['actions']))

    def test_last_empty_sector_guard_sets_maintenance_flag(self):
        row = self.result('reserve_last_empty_guard')
        self.assertEqual(row['returned'], 0xffffffff)
        self.assertEqual(row['maintenance_flag'], 1)
        self.assertEqual(row['actions'][-1], 'diagnostic:506')
        self.assertEqual(self.result('reserve_last_empty_flagged')['returned'], BASE + 20)
        self.assertEqual(self.result('reserve_two_empty')['returned'], BASE + 20)

    def test_dirty_state_two_depends_on_maintenance_flag(self):
        self.assertEqual(self.result('reserve_dirty2_flag_0')['returned'], BASE + 20)
        self.assertEqual(self.result('reserve_dirty2_flag_1')['returned'], 0xffffffff)
        self.assertEqual(self.result('reserve_dirty3')['returned'], 0xffffffff)

    def test_reservation_continues_to_second_candidate(self):
        row = self.result('reserve_second_candidate')
        self.assertEqual(row['returned'], BASE + 4096 + 20)
        self.assertEqual([a for a in row['actions'] if a.startswith('details:')],
                         [f'details:{BASE}', f'details:{BASE + 4096}'])

    def test_maintenance_threshold_controls_gc_boundary(self):
        enough = self.result('maintenance_enough_empty')
        few = self.result('maintenance_few_empty')
        self.assertFalse(any(a.startswith('gc_boundary:') for a in enough['actions']))
        self.assertEqual([a for a in few['actions'] if a.startswith('gc_boundary:')],
                         [f'gc_boundary:{BASE + i * 4096}' for i in range(4)])
        self.assertEqual((enough['maintenance_flag'], few['maintenance_flag']), (0, 0))

    def test_retry_last_empty_can_fail_and_rearm_flag(self):
        row = self.result('retry_last_empty')
        self.assertEqual(row['returned'], 0xffffffff)
        self.assertEqual(row['maintenance_flag'], 1)
        self.assertEqual(row['actions'].count('diagnostic:506'), 2)
        self.assertEqual(row['actions'].count('diagnostic:5b4'), 1)
        self.assertEqual(row['actions'].count('diagnostic:603'), 1)

    def test_retry_requires_failure_and_pending_flag(self):
        unflagged = self.result('retry_none_unflagged')
        flagged = self.result('retry_flagged_failure')
        self.assertNotIn('diagnostic:603', unflagged['actions'])
        self.assertIn('diagnostic:603', flagged['actions'])
        self.assertEqual(flagged['returned'], 0xffffffff)
        self.assertEqual(flagged['maintenance_flag'], 0)

    def test_retry_success_can_follow_flag_clear_without_relocation(self):
        row = self.result('retry_flag_clear_enables_dirty')
        self.assertEqual(row['returned'], BASE + 20)
        self.assertEqual(row['maintenance_flag'], 0)
        self.assertIn('diagnostic:603', row['actions'])
        self.assertEqual(row['actions'].count(f'details:{BASE}'), 2)

    def test_host_fixture_bounds_and_invalid_policy_headers(self):
        for changes in (dict(capacity=257), dict(request=0), dict(key='a\0b'), dict(sectors=[]),
                        dict(operation='reserve', sectors=[sector(valid=False)] + [sector() for _ in range(3)])):
            with self.assertRaises(ValueError):
                contract(copy.deepcopy(self.cases['find_first']) | changes)

    def test_public_native_observations_match_complete_contract(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/env-scan.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertIs(native['hardware_execution'], False)
        self.assertEqual((native['case_count'], len(native['cases'])), (41, 41))
        for row, case in zip(native['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= native['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))
        self.assertEqual(len(report['export_sha256']), 12)


if __name__ == '__main__':
    unittest.main()
