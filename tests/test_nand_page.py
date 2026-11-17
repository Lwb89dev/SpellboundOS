import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.nand_page import contract,native_vectors


def initial_buffer():return bytes((i*3+1)&255 for i in range(512))


class NandPageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def status(self,name):
        value=self.row(name)['returned'];return value-(1<<32) if value&(1<<31) else value
    def actions(self,name):return self.result(name)['actions']

    def test_all_five_operations_have_successful_ready_cases(self):
        for name in ('read_direct','write_ready','copy_page_ready','copy_oob_ready','erase_ready'):
            self.assertEqual(self.status(name),0)
            self.assertFalse(any(a.startswith('log:') for a in self.actions(name)))

    def test_missing_chip_is_rejected_before_remapping(self):
        for name in ('read_missing_chip','write_missing_chip','copy_page_missing_chip','copy_oob_missing_chip','erase_missing_chip'):
            self.assertEqual(self.status(name),-2)
            self.assertEqual(len(self.actions(name)),1)

    def test_read_and_write_require_a_buffer(self):
        for name in ('read_null_buffer','write_null_buffer'):
            self.assertEqual(self.status(name),-1)
            self.assertFalse(any(a.startswith(('load:','enable:')) for a in self.actions(name)))

    def test_page_and_block_upper_bounds_are_exclusive(self):
        for name in ('read_page_boundary','write_out_of_range','copy_page_out_of_range','copy_oob_out_of_range','erase_out_of_range','copy_dest_range'):
            self.assertEqual(self.status(name),-1)

    def test_column_plus_count_includes_the_spare_area(self):
        self.assertEqual(self.status('read_column_boundary'),-1)
        self.assertEqual(self.status('read_exact_end'),0)
        self.assertIn('cache_read_direct:2048:64:0',self.actions('read_exact_end'))

    def test_zero_length_read_is_rejected(self):self.assertEqual(self.status('read_zero_length'),-1)

    def test_remapped_page_is_used_for_load(self):
        self.assertIn('remap_page:600:664:0',self.actions('read_remapped'))
        self.assertIn('load:664:0',self.actions('read_remapped'))

    def test_remap_failures_have_distinct_page_and_block_statuses(self):
        for name in ('read_remap_error','write_remap_error','copy_page_remap_error','copy_oob_remap_error','copy_dest_remap_error'):
            self.assertEqual(self.status(name),-150)
        self.assertEqual(self.status('erase_remap_error'),-151)
        self.assertEqual(len(self.actions('read_remap_error')),1)

    def test_guard_blocks_mutation_below_first_mib(self):
        for name in ('write_guarded','copy_page_guarded','copy_oob_guarded','erase_guarded','copy_dest_guarded'):
            self.assertEqual(self.status(name),-250)
            self.assertFalse(any(a.startswith(('load:','enable:')) for a in self.actions(name)))

    def test_guard_allows_boundary_or_disabled_flag(self):
        for mode in ('write','copy_page','copy_oob','erase'):
            self.assertEqual(self.status(mode+'_guard_boundary'),0)
            self.assertEqual(self.status(mode+'_guard_disabled'),0)

    def test_read_direct_and_private_buffer_modes_deliver_same_fixture(self):
        expected=bytes((0x5a+i*7)&255 for i in range(64))+initial_buffer()[64:]
        self.assertEqual(self.row('read_direct')['buffer_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.row('read_bounce')['buffer_sha256'],self.row('read_direct')['buffer_sha256'])
        self.assertIn('cache_read_bounce:16:64:0',self.actions('read_bounce'))

    def test_read_ecc_workaround_success_clears_error(self):
        self.assertEqual(self.status('read_ecc_recovered'),0)
        actions=self.actions('read_ecc_recovered')
        self.assertLess(actions.index('workaround:600:0'),actions.index('cache_read_direct:16:64:0'))
        self.assertIn('log:workaround_ok',actions)

    def test_unrecovered_ecc_still_reads_cache_then_returns_error(self):
        self.assertEqual(self.status('read_ecc_unrecovered'),-101)
        self.assertIn('cache_read_direct:16:64:0',self.actions('read_ecc_unrecovered'))
        self.assertEqual(self.row('read_ecc_unrecovered')['buffer_sha256'],self.row('read_direct')['buffer_sha256'])

    def test_ecc_error_overrides_cache_error(self):
        self.assertEqual(self.status('read_ecc_overrides_cache_error'),-101)
        self.assertIn('cache_read_direct:16:64:-9',self.actions('read_ecc_overrides_cache_error'))

    def test_read_command_and_cache_error_statuses(self):
        for name,value in (('read_load_fault',-52),('read_cache_fault',-53),('read_bounce_cache_fault',-54)):
            self.assertEqual(self.status(name),value)

    def test_feature_read_faults_propagate_as_outer_busy_error(self):
        for name in ('read_feature_fault','write_feature_fault','copy_second_feature_fault','erase_feature_fault'):
            self.assertEqual(self.status(name),-100)
            self.assertIn('log:feature_error',self.actions(name))

    def test_read_continues_after_actual_busy_timeout_with_ff_status(self):
        self.assertEqual(self.status('read_busy_timeout'),0)
        self.assertEqual(self.row('read_busy_timeout')['feature_reads'],2000)
        self.assertEqual(self.actions('read_busy_timeout')[-2:],['log:busy_timeout','cache_read_direct:16:64:0'])
        self.assertEqual(self.row('read_busy_timeout')['buffer_sha256'],self.row('read_direct')['buffer_sha256'])

    def test_program_translates_busy_timeout_ff_to_program_failure(self):
        self.assertEqual(self.status('write_busy_timeout'),-102)
        self.assertEqual(self.row('write_busy_timeout')['feature_reads'],2000)
        self.assertIn('log:busy_timeout',self.actions('write_busy_timeout'))

    def test_erase_translates_both_busy_timeouts_to_erase_failure(self):
        for name,count in (('erase_poll_timeout',4000),('erase_tick_timeout',20)):
            self.assertEqual(self.status(name),-104)
            self.assertEqual(self.row(name)['feature_reads'],count)
            self.assertIn('log:busy_timeout',self.actions(name))

    def test_write_enable_fault_is_rejected_by_all_mutators(self):
        for mode in ('write','copy_page','copy_oob','erase'):
            self.assertEqual(self.status(mode+'_enable_fault'),-55)

    def test_write_cache_and_program_error_statuses(self):
        for name,value in (('write_cache_fault',-56),('write_bounce_cache_fault',-57),('write_program_fault',-58)):
            self.assertEqual(self.status(name),value)

    def test_write_orders_enable_cache_program_then_status(self):
        actions=self.actions('write_ready')
        positions=[next(i for i,a in enumerate(actions) if a.startswith(prefix)) for prefix in ('enable:','cache_write_direct:','program:','feature:')]
        self.assertEqual(positions,sorted(positions))
        self.assertEqual(self.row('write_ready')['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())

    def test_program_and_erase_failure_bits_map_to_distinct_errors(self):
        self.assertEqual(self.status('write_failed_status'),-102)
        self.assertEqual(self.status('copy_program_failed'),-102)
        self.assertEqual(self.status('erase_failed_status'),-104)

    def test_copy_uses_source_for_load_and_destination_for_program(self):
        actions=self.actions('copy_page_ready')
        self.assertIn('load:600:0',actions);self.assertIn('program:700:0',actions)
        self.assertEqual(self.row('copy_page_ready')['feature_reads'],2)
        self.assertFalse(any(a.startswith('cache_') for a in actions))

    def test_copy_ecc_error_stops_before_programming_without_workaround(self):
        self.assertEqual(self.status('copy_ecc_error'),-101)
        self.assertFalse(any(a.startswith(('enable:','program:','workaround:')) for a in self.actions('copy_ecc_error')))

    def test_copy_load_and_program_failures_are_mapped(self):
        self.assertEqual(self.status('copy_load_fault'),-52)
        self.assertEqual(self.status('copy_program_fault'),-58)

    def test_copy_oob_enforces_spare_length_and_uses_page_size_as_column(self):
        self.assertEqual(self.status('copy_oob_excess'),-1)
        expected=hashlib.sha256(initial_buffer()[:64]).hexdigest()
        self.assertIn('cache_write_oob:2048:64:'+expected+':0',self.actions('copy_oob_ready'))
        self.assertEqual(self.status('copy_oob_cache_fault'),-56)

    def test_authored_plane_flag_inserts_column_bit_from_source_page(self):
        self.assertIn('cache_read_direct:4112:64:0',self.actions('read_plane'))
        self.assertTrue(any(a.startswith('cache_write_direct:4112:64:') for a in self.actions('write_plane')))
        self.assertTrue(any(a.startswith('cache_write_oob:6144:64:') for a in self.actions('copy_oob_plane')))

    def test_erase_command_fault_and_tick_mode(self):
        self.assertEqual(self.status('erase_command_fault'),-60)
        self.assertEqual(self.status('erase_tick_ready'),0)
        self.assertIn('sleep:1',self.actions('erase_tick_ready'))
        self.assertNotIn('delay:5',self.actions('erase_tick_ready'))

    def test_fixture_bounds(self):
        for changes in (dict(size=513),dict(responses=[]),dict(map_status=[]),dict(feature_status=[])):
            with self.assertRaises(ValueError):contract(self.cases['read_direct']|changes)

    def test_all_public_native_observations_match(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-page.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(77,77))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['export_sha256']),len(report['byte_range_sha256'])),(8,8))


if __name__=='__main__':unittest.main()
