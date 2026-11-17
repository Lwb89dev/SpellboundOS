import copy
import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.storage_registry import HEAP, PARTS, TABLE, contract, facts, native_vectors


class StorageRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name): return self.cases[name]['expected']
    def row(self, name, index=-1): return self.result(name)['rows'][index]

    def test_original_table_populates_all_sixteen_owner_slots(self):
        row = self.row('setup_original')
        self.assertEqual(row['returned'], 0)
        self.assertEqual((row['device_table'], row['device_count'], row['device_ready']), (TABLE, 5, 1))
        self.assertEqual((row['partition_table'], row['partition_count'], row['partition_ready']), (PARTS, 16, 1))
        self.assertEqual(row['owners'], [p['backend_descriptor'] for p in facts()['partitions']])
        self.assertEqual((row['outer_table'], row['outer_count']), (TABLE, 5))

    def test_repeat_setup_skips_initializers_and_allocation(self):
        result = self.result('setup_repeat')
        self.assertEqual(result['rows'][0], result['rows'][1])
        self.assertEqual(sum(a.startswith('initialize:') for a in result['actions']), 3)
        self.assertEqual(result['actions'].count('alloc:64:1'), 1)

    def test_owner_allocation_failure_leaves_device_ready_and_partition_partial(self):
        row = self.row('setup_alloc_error')
        self.assertEqual((row['returned'], row['device_ready'], row['partition_ready']), (0xffffffff, 1, 0))
        self.assertEqual((row['partition_table'], row['partition_count']), (PARTS, 16))
        self.assertEqual((row['owner_pointer'], row['outer_table']), (0, 0))
        self.assertIsNone(row['owners'])

    def test_retry_after_allocation_failure_reuses_initialized_devices(self):
        rows = self.result('setup_alloc_retry')['rows']
        self.assertEqual([r['returned'] for r in rows], [0xffffffff, 0])
        self.assertEqual(rows[-1]['owner_pointer'], HEAP)
        actions = self.result('setup_alloc_retry')['actions']
        self.assertEqual(sum(a.startswith('initialize:') for a in actions), 3)
        self.assertEqual([a for a in actions if a.startswith('alloc:')], ['alloc:64:0', 'alloc:64:1'])

    def test_initializer_failures_stop_before_partition_publication(self):
        for index in (0, 1, 3):
            row = self.row(f'setup_driver_{index}_error')
            self.assertEqual((row['returned'], row['device_ready'], row['partition_table']), (0xffffffff, 0, 0))
            self.assertFalse(any(a.startswith('alloc:') for a in self.result(f'setup_driver_{index}_error')['actions']))

    def test_device_initializer_status_is_preserved_before_outer_mapping(self):
        self.assertEqual(self.row('device_backend_status')['returned'], 0xfffffff7)
        self.assertEqual(self.row('setup_driver_1_error')['returned'], 0xffffffff)

    def test_ready_device_guard_skips_all_callbacks(self):
        self.assertEqual(self.result('device_already_ready')['actions'], [])
        self.assertEqual(self.row('device_already_ready')['returned'], 0)

    def test_deferred_initializers_do_not_set_eftl_readiness(self):
        result = self.result('device_original')
        self.assertIn('log:eftl_deferred', result['actions'])
        self.assertIn('log:sftl_deferred', result['actions'])
        self.assertEqual((result['rows'][0]['device_ready'], result['rows'][0]['eftl_ready']), (1, 0))

    def test_existing_owner_array_is_reused(self):
        result = self.result('partition_existing_owners')
        self.assertFalse(any(a.startswith('alloc:') for a in result['actions']))
        self.assertEqual(result['rows'][0]['owners'], self.row('partition_original')['owners'])

    def test_partition_ready_guard_preserves_supplied_stale_owner_array(self):
        self.assertEqual(self.result('partition_already_ready')['actions'], [])
        self.assertEqual(self.row('partition_already_ready')['owners'], [0x55555555] * 16)

    def test_missing_owner_leaves_new_allocation_contents_untouched(self):
        row = self.row('partition_missing_owner')
        self.assertEqual((row['returned'], row['partition_ready']), (0, 1))
        self.assertEqual(row['owners'][5:12], [0xa5a5a5a5] * 7)
        self.assertEqual(self.result('partition_missing_owner')['actions'].count('log:owner_missing'), 7)

    def test_missing_owner_leaves_existing_stale_contents_untouched(self):
        self.assertEqual(self.row('partition_missing_stale_owner')['owners'][5:12], [0x55555555] * 7)

    def test_capacity_equal_start_rejects_and_keeps_partial_owner_array(self):
        row = self.row('partition_capacity_equal')
        self.assertEqual((row['returned'], row['partition_ready'], row['partition_count']), (0xffffffff, 0, 0))
        self.assertEqual(row['owners'][:6], [p['backend_descriptor'] for p in facts()['partitions'][:6]])
        self.assertEqual(row['owners'][6:], [0xa5a5a5a5] * 10)

    def test_signed_start_and_unchecked_span_are_accepted_by_selected_initializer(self):
        for name in ('partition_signed_offset', 'partition_span_not_checked'):
            self.assertEqual((self.row(name)['returned'], self.row(name)['partition_ready']), (0, 1))

    def test_backend_find_returns_real_descriptor_or_zero(self):
        self.assertEqual(self.row('find_original')['returned'], 0x80d80fb8)
        self.assertEqual(self.row('find_missing')['returned'], 0)

    def test_lazy_geometry_updates_descriptor_capacity_and_block_size(self):
        row = self.row('lazy_original')
        self.assertIsNone(row['returned'])
        self.assertEqual((row['blocks'][2], row['capacities'][2], row['eftl_ready']), (131072, 16252928, 1))
        self.assertEqual(row['device_ready'], 0)

    def test_lazy_repeat_and_ready_guards_skip_geometry_discovery(self):
        result = self.result('lazy_repeat')
        self.assertEqual(result['actions'], ['geometry:0', 'log:eftl_ready'])
        self.assertEqual(result['rows'][0], result['rows'][1])
        self.assertEqual(self.result('lazy_already_ready')['actions'], [])

    def test_lazy_negative_status_keeps_initial_descriptor_words(self):
        row = self.row('lazy_error')
        self.assertEqual((row['eftl_ready'], row['capacities'][2], row['blocks'][2]), (0, 0x7fffffff, 0x20000))
        self.assertEqual(self.result('lazy_error')['actions'], ['geometry:-14'])

    def test_positive_geometry_result_is_success(self):
        self.assertEqual(self.row('lazy_positive_status')['capacities'], self.row('lazy_original')['capacities'])

    def test_geometry_multiply_wrap_and_reserved_underflow(self):
        self.assertEqual((self.row('lazy_arithmetic_wrap')['blocks'][2], self.row('lazy_arithmetic_wrap')['capacities'][2]), (0, 0))
        self.assertEqual(self.row('lazy_reserved_underflow')['capacities'][2], (-3 * 131072) & 0xffffffff)
        self.assertEqual(self.row('lazy_reserved_underflow')['eftl_ready'], 1)

    def test_read_runs_lazy_setup_then_forwards_supplied_data(self):
        row = self.row('read_lazy')
        data = bytes((32 + j * 7) & 255 for j in range(32)) + b'\xa5' * 992
        self.assertEqual((row['returned'], row['eftl_ready']), (32, 1))
        self.assertEqual(row['buffer_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.result('read_lazy')['actions'][-1], 'ftl_read:32:32:32')

    def test_read_init_failure_and_backend_statuses(self):
        self.assertEqual(self.row('read_lazy_error')['returned'], 0xfffffff2)
        self.assertFalse(any(a.startswith('ftl_read:') for a in self.result('read_lazy_error')['actions']))
        self.assertEqual(self.row('read_backend_error')['returned'], 0xfffffff7)
        self.assertEqual(self.row('read_short')['returned'], 7)
        self.assertEqual(self.result('read_already_ready')['actions'], ['ftl_read:32:32:32'])

    def test_contract_bounds_reject_uninitialized_lookup(self):
        case = copy.deepcopy(self.cases['find_original']); case['device_ready'] = False
        with self.assertRaises(ValueError): contract(case)

    def test_public_native_observations_match_all_cases(self):
        report = json.loads((Path(__file__).resolve().parents[1] / 'analysis/storage-registry.json').read_bytes())
        execution = report['native_validation']
        self.assertIs(execution['hardware_execution'], False)
        self.assertEqual(execution['case_count'], 32)
        for row, case in zip(execution['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= execution['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(row['steps'] for row in execution['cases']))
        self.assertEqual(len(report['export_sha256']), 9)


if __name__ == '__main__': unittest.main()
