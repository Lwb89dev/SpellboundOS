import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.env_storage import BASES, MUTEX, STOP, Model, handle, native_vectors


def sha(data):
    return hashlib.sha256(data).hexdigest()


class EnvironmentStorageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def row(self, name, index=-1):
        return self.result(name)['rows'][index]

    def executed(self, name):
        model = Model(copy.deepcopy(self.cases[name]))
        model.result()
        return model

    def test_setup_returns_real_table_and_preferred_handles(self):
        row = self.row('setup_preferred')
        self.assertEqual((row['returned'], row['table_output'], row['count_output']), (0, 0x80c36518, 1))
        self.assertEqual(row['handles'], dict(active=handle('env'), backup=handle('easyflash'), special=0, fallback=handle('easyflash')))
        self.assertEqual((row['mutex'], row['lock_depth']), (MUTEX, 0))

    def test_fallback_requires_nvms_and_uses_optional_envbak(self):
        row = self.row('setup_fallback')
        self.assertEqual(row['handles'], dict(active=handle('env'), backup=handle('envbak'), special=handle('nvms'), fallback=0))
        self.assertEqual(row['returned'], 0)
        self.assertIn('read:40960:160:160', self.result('setup_fallback')['actions'])

    def test_missing_optional_reserve_handle_does_not_fail_setup(self):
        self.assertEqual(self.row('setup_without_backup')['returned'], 0)
        self.assertEqual(self.row('setup_without_backup')['handles']['backup'], 0)

    def test_mutex_failure_still_populates_output_table(self):
        row = self.row('setup_mutex_error')
        self.assertEqual((row['returned'], row['table_output'], row['count_output']), (7, 0x80c36518, 1))
        self.assertEqual(self.result('setup_mutex_error')['actions'], ['mutex:create:0'])
        self.assertNotIn('mutex:create:1', self.result('setup_existing_mutex')['actions'])

    def test_required_lookup_failure_keeps_partial_state(self):
        self.assertEqual(self.row('setup_missing_nvms')['returned'], 7)
        self.assertEqual(self.row('setup_missing_nvms')['handles']['backup'], handle('envbak'))
        self.assertEqual(self.row('setup_missing_env')['returned'], 7)
        self.assertEqual(self.row('setup_missing_env')['handles']['fallback'], handle('easyflash'))

    def test_unready_registry_rejects_setup_lookup(self):
        result = self.result('setup_registry_unready')
        self.assertEqual(result['rows'][0]['returned'], 7)
        self.assertEqual(result['actions'].count('log:registry_unready'), 3)

    def test_preferred_branch_preserves_preexisting_special_handle(self):
        row = self.row('setup_stale_special')
        self.assertEqual(row['handles']['special'], handle('nvms'))
        self.assertEqual(row['handles']['backup'], handle('easyflash'))
        self.assertIn('read:40960:160:160', self.result('setup_stale_special')['actions'])

    def test_setup_ignores_nv_sync_error(self):
        result = self.result('setup_ignores_sync_error')
        self.assertEqual(result['rows'][0]['returned'], 0)
        self.assertIn('log:fdb_read_error', result['actions'])

    def test_equal_mirrors_skip_rewrite(self):
        result = self.result('sync_equal')
        self.assertEqual(result['rows'][0]['returned'], 0)
        self.assertIn('log:mirrors_equal', result['actions'])
        self.assertFalse(any(a.startswith('rewrite:') for a in result['actions']))

    def test_valid_primary_overwrites_secondary_without_other_page_changes(self):
        initial = Model(self.cases['sync_primary'])
        model = self.executed('sync_primary')
        self.assertEqual(model.data[0x10000:0x100a0], initial.data[0x4000:0x40a0])
        self.assertEqual(model.data[0x100a0:0x11000], initial.data[0x100a0:0x11000])
        self.assertEqual(self.row('sync_primary')['returned'], 0)

    def test_valid_secondary_repairs_primary(self):
        initial = Model(self.cases['sync_secondary'])
        model = self.executed('sync_secondary')
        self.assertEqual(model.data[0x4000:0x40a0], initial.data[0x10000:0x100a0])
        self.assertIn('log:primary_repaired', self.result('sync_secondary')['actions'])

    def test_two_invalid_mirrors_return_minus_fourteen(self):
        result = self.result('sync_invalid')
        self.assertEqual(result['rows'][0]['returned'], 0xfffffff2)
        self.assertIn('log:no_valid_mirror', result['actions'])
        self.assertFalse(any(a.startswith('rewrite:') for a in result['actions']))

    def test_first_mirror_read_failure_stops_before_writing(self):
        result = self.result('sync_primary_read_error')
        self.assertEqual(result['rows'][0]['returned'], 0xfffffff2)
        self.assertFalse(any(a.startswith('rewrite:') for a in result['actions']))

    def test_secondary_read_failure_can_be_repaired_from_primary(self):
        self.assertEqual(self.row('sync_secondary_read_error')['returned'], 0)
        self.assertIn('log:read_error', self.result('sync_secondary_read_error')['actions'])
        self.assertIn('log:secondary_repaired', self.result('sync_secondary_read_error')['actions'])

    def test_fallback_preserves_bytes_outside_record(self):
        initial = Model(self.cases['sync_fallback'])
        model = self.executed('sync_fallback')
        self.assertEqual(model.data[0x10000:0x100a0], initial.data[0x4000:0x40a0])
        self.assertEqual(model.data[0x100a0:0x11000], initial.data[0x100a0:0x11000])
        self.assertIn('erase:65536:4096:0', self.result('sync_fallback')['actions'])
        self.assertEqual((self.row('sync_fallback')['lock_depth'], self.row('sync_fallback')['heap_active']), (0, False))

    def test_fallback_read_failure_frees_and_unlocks(self):
        result = self.result('sync_fallback_read_error')
        self.assertEqual(result['rows'][0]['returned'], 0xfffffff2)
        self.assertIn('free:4096', result['actions'])
        self.assertEqual(result['rows'][0]['lock_depth'], 0)
        self.assertFalse(any(a.startswith('erase:') for a in result['actions']))

    def test_fallback_erase_failure_is_ignored_by_caller_status(self):
        initial = Model(self.cases['sync_fallback_erase_error'])
        model = self.executed('sync_fallback_erase_error')
        expected = bytes(x & y for x, y in zip(initial.data[0x10000:0x100a0], initial.data[0x4000:0x40a0]))
        self.assertEqual(model.data[0x10000:0x100a0], expected)
        self.assertEqual(self.row('sync_fallback_erase_error')['returned'], 0)
        self.assertIn('log:secondary_repaired', self.result('sync_fallback_erase_error')['actions'])

    def test_fallback_program_failure_can_report_success_after_erase(self):
        model = self.executed('sync_fallback_program_error')
        self.assertEqual(model.data[0x10000:0x11000], b'\xff' * 4096)
        self.assertEqual(self.row('sync_fallback_program_error')['returned'], 0)
        self.assertIn('log:program_error', self.result('sync_fallback_program_error')['actions'])

    def test_allocation_failure_leaves_lock_depth_one(self):
        row = self.row('sync_fallback_alloc_error')
        self.assertEqual((row['returned'], row['lock_depth'], row['heap_active']), (0xfffffff2, 1, False))
        actions = self.result('sync_fallback_alloc_error')['actions']
        self.assertEqual(actions.count('lock') - actions.count('unlock'), 1)
        self.assertNotIn('free:4096', actions)

    def test_missing_rewrite_callback_uses_fallback(self):
        model = self.executed('nv_write_missing_callback')
        self.assertEqual(model.data[0x4000:0x40a0], bytes(range(160)))
        self.assertIn('log:rewrite_missing', self.result('nv_write_missing_callback')['actions'])
        self.assertEqual(self.row('nv_write_missing_callback')['returned'], 0)

    def test_two_page_fallback_splits_special_and_active_routes(self):
        initial = Model(self.cases['nv_write_two_pages'])
        model = self.executed('nv_write_two_pages')
        self.assertEqual(model.data[0x4ff0:0x5000], bytes(range(16)))
        self.assertEqual(model.data[0x10000:0x10010], bytes(range(16, 32)))
        self.assertEqual(model.data[0x5000:0x5010], initial.data[0x5000:0x5010])

    def test_fast_cross_boundary_write_routes_entire_request_by_start(self):
        initial = Model(self.cases['nv_write_cross_fast'])
        model = self.executed('nv_write_cross_fast')
        self.assertEqual(model.data[0x4ff0:0x5010], bytes(range(32)))
        self.assertEqual(model.data[0x10000:0x10010], initial.data[0x10000:0x10010])
        self.assertNotIn('alloc:4096:1', self.result('nv_write_cross_fast')['actions'])

    def test_nv_zero_and_out_of_range_requests_skip_driver(self):
        for name, returned in (('nv_read_zero', 0), ('nv_write_zero', 0), ('nv_read_range_error', 2), ('nv_write_range_error', 3)):
            self.assertEqual(self.row(name)['returned'], returned)
            self.assertEqual(self.result(name)['actions'], [])

    def test_partition_validation_clips_all_four_operation_lengths(self):
        for op in ('read', 'program', 'erase', 'rewrite'):
            result = self.result(op + '_clip')
            self.assertEqual(result['actions'][0], 'check:3:24560:64')
            driver = next(a for a in result['actions'] if a.startswith(op + ':'))
            self.assertEqual(driver.split(':')[1:3], [str(BASES[3] + 0x5ff0), '16'])
            self.assertEqual(result['rows'][0]['returned'], 16 if op in ('read', 'program') else 0)

    def test_negative_driver_results_are_forwarded_by_generic_wrappers(self):
        for op in ('read', 'program', 'erase', 'rewrite'):
            self.assertEqual(self.row(op + '_error')['returned'], 0xffffffff)
            self.assertIn('log:' + op + '_error', self.result(op + '_error')['actions'])

    def test_owner_lookup_failure_rejects_without_callback(self):
        self.assertEqual(self.row('read_owner_missing')['returned'], 0xffffffff)
        self.assertEqual(self.result('read_owner_missing')['actions'], ['check:3:0:32', 'log:no_owner'])

    def test_zero_span_derives_remaining_device_capacity(self):
        self.assertEqual(self.row('read_derived_span')['returned'], 16)
        self.assertIn('read:69632:16:16', self.result('read_derived_span')['actions'])
        self.assertEqual(self.row('read_at_end')['returned'], 0xffffffff)
        self.assertIn('log:bounds', self.result('read_at_end')['actions'])

    def test_registry_lookup_returns_entry_pointer_or_zero(self):
        self.assertEqual(self.row('lookup_hit')['returned'], handle('env'))
        self.assertEqual(self.row('lookup_missing')['returned'], 0)
        self.assertEqual(self.row('lookup_unready')['returned'], 0)

    def test_bootstrap_executes_clean_binding_with_recovered_default_table(self):
        row = self.row('bootstrap')
        self.assertEqual((row['returned'], row['outer_ready'], row['inner_ready']), (0, 1, 1))
        self.assertEqual((row['bound_pointer'], row['bound_count']), (0x80c36518, 1))
        self.assertIn('diagnostic:8fe', self.result('bootstrap')['actions'])
        self.assertEqual(sum(a.startswith('check:3:') and a.endswith(':20') for a in self.result('bootstrap')['actions']), 12)

    def test_bootstrap_fallback_and_two_readiness_guards(self):
        self.assertEqual(self.row('bootstrap_fallback')['inner_ready'], 1)
        self.assertEqual(self.result('bootstrap_already_outer')['actions'], [])
        self.assertNotIn('diagnostic:8fe', self.result('bootstrap_already_inner')['actions'])
        self.assertEqual((self.row('bootstrap_setup_error')['returned'], self.row('bootstrap_setup_error')['outer_ready']), (7, 0))

    def test_framework_caller_stops_before_next_phase_even_on_error(self):
        for name, status in (('caller', 0), ('caller_setup_error', 7)):
            self.assertIsNone(self.row(name)['returned'])
            self.assertEqual(self.row(name)['stopped'], dict(pc=STOP, status=status))

    def test_retained_gate_initializes_magic_or_returns_low_byte(self):
        rows = self.result('retained_magic_missing')['rows']
        self.assertEqual([r['returned'] for r in rows], [0, 0])
        self.assertEqual((rows[0]['retained_magic'], rows[0]['retained_value']), (0xabcd1234, 0))
        self.assertEqual((self.row('retained_low_byte')['returned'], self.row('retained_low_byte')['retained_value']), (0x78, 0x12345678))

    def test_public_native_observations_and_default_provenance(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/env-storage.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertIs(native['hardware_execution'], False)
        self.assertEqual((native['case_count'], len(native['cases'])), (52, 52))
        for row, case in zip(native['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= native['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))
        self.assertEqual((report['default_table']['key'], report['default_table']['value'], report['default_table']['length']), ('boots', '0', 0))
        self.assertEqual(len(report['export_sha256']), 13)


if __name__ == '__main__':
    unittest.main()
