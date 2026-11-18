import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.eftl_repair_stack import contract,native_vectors


class EftlRepairStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def flags(self,name):return bytes.fromhex(self.row(name)['write_flags_hex'])
    def mapping(self,name):return struct.unpack('<8H',bytes.fromhex(self.row(name)['mapping_hex']))
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]

    def test_no_free_repair_executes_three_real_marker_programs(self):
        name='repair_direct_no_free';self.result(name,-1)
        self.assertEqual(self.opcodes(name),[6,0x32,0x10,15]*3)
        self.assertEqual(self.row(name)['tx_hex'],'000000000000');self.assertIn('log:bad_mark_set',self.actions(name))

    def test_generic_marker_path_executes_original_ioctl_and_mutex_wrapper(self):
        name='repair_direct_no_free_generic';self.result(name,-1)
        self.assertIn('driver_ioctl:11',self.actions(name));self.assertIn('chip_ioctl:11',self.actions(name))
        self.assertIn('mutex_acquire:0',self.actions(name));self.assertIn('mutex_release:0',self.actions(name))

    def test_marker_pages_follow_partition_and_bbt_rebasing(self):
        actions=self.actions('repair_direct_no_free')
        for page in (704,705,706):self.assertIn('native_remap_page:'+str(page),actions)
        for page in (896,897,898):self.assertIn('w:0:4:'+str(page),actions)

    def test_zero_prefix_repair_returns_selected_block_without_publishing_map(self):
        name='repair_direct_free';self.result(name,5)
        self.assertEqual(self.mapping(name)[0],3);self.assertEqual(self.flags(name)[3],1);self.assertEqual(self.flags(name)[5],0)
        self.assertEqual(self.row(name)['repair_allocations'],0)

    def test_upper_writer_retries_selected_block_and_publishes_after_success(self):
        for name in ('program_relocate_zero_prefix','program_relocate_generic','rewrite_relocate'):
            self.result(name,32);self.assertEqual(self.mapping(name)[0],5)
            self.assertEqual(self.flags(name)[3],1);self.assertEqual(self.flags(name)[5],2)
            self.assertIn('log:eftl_repair_selected',self.actions(name))

    def test_no_free_upper_failure_keeps_old_mapping_and_marks_ram_bad(self):
        for name in ('program_no_free','program_no_free_generic'):
            self.result(name,-2);self.assertEqual(self.mapping(name)[0],3);self.assertEqual(self.flags(name)[3],1)
            self.assertIn('log:eftl_repair_start',self.actions(name));self.assertEqual(self.actions(name)[-1],'log:storage_program_error')

    def test_bad_marker_return_does_not_change_repair_selected_block_return(self):
        for name in ('repair_direct_free_mark_failure','repair_generic_free_mark_failure'):
            self.result(name,5);self.assertIn('log:bad_mark_error',self.actions(name));self.assertEqual(self.flags(name)[3],1)
            self.assertEqual(self.opcodes(name).count(0x10),1);self.assertEqual(self.mapping(name)[0],3)
        self.assertIn('log:chip_error',self.actions('repair_generic_free_mark_failure'))

    def test_no_free_marker_failure_still_returns_original_no_free_result(self):
        self.result('repair_direct_mark_failure',-1);self.result('program_no_free_mark_failure',-2)
        self.assertIn('log:bad_mark_error',self.actions('repair_direct_mark_failure'))
        self.assertEqual(self.row('repair_direct_mark_failure')['tx_hex'],'0000')
        self.result('repair_generic_mark_failure',-1);self.assertIn('log:chip_error',self.actions('repair_generic_mark_failure'))

    def test_failed_erase_marks_old_candidate_and_selects_another(self):
        name='erase_failed_reselect';self.result(name,32)
        self.assertIn('log:eftl_erase_bad',self.actions(name));self.assertEqual(self.mapping(name)[0],5)
        self.assertEqual(self.flags(name)[3],1);self.assertEqual(self.flags(name)[5],2)

    def test_failed_marker_during_erase_reselection_is_ignored(self):
        name='erase_failed_mark_failed_reselect';self.result(name,32)
        self.assertIn('log:bad_mark_error',self.actions(name));self.assertEqual(self.mapping(name)[0],5)

    def test_exhausted_erase_candidates_leave_bad_flags_without_map_replacement(self):
        name='erase_all_candidates_fail';self.result(name,-2)
        self.assertEqual(self.flags(name)[3],1);self.assertEqual(self.flags(name)[5],255)
        self.assertEqual(self.mapping(name)[0],3);self.assertIn('log:eftl_map_full',self.actions(name))

    def test_readback_io_error_enters_repair_not_checksum_rejection(self):
        name='readback_io_no_free';self.result(name,-2)
        self.assertIn('log:eftl_readback_io_failed',self.actions(name));self.assertIn('log:eftl_repair_start',self.actions(name))
        self.assertFalse(any(a.startswith('readback_checksum:') for a in self.actions(name)))
        self.assertEqual(self.flags(name)[3],1)

    def test_prefix_allocation_failure_occurs_after_flag_and_free_selection_changes(self):
        for name in ('program_prefix_alloc_failure','readback_io_alloc_failure','repair_direct_alloc_failure'):
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c3436c,line=0xa3))
            self.assertEqual(self.row(name)['repair_allocations'],1);self.assertEqual(self.flags(name)[5],0)
            self.assertNotIn('log:bad_mark_set',self.actions(name));self.assertEqual(self.mapping(name)[0],3)
        self.assertEqual(self.flags('program_prefix_alloc_failure')[3],5)

    def test_logical_erase_can_relocate_zero_prefix_through_original_program(self):
        name='logical_erase_relocate';self.result(name,32)
        self.assertEqual(self.mapping(name)[0],5);self.assertIn('log:eftl_repair_selected',self.actions(name))

    def test_contract_excludes_successful_prefix_copy_and_unbounded_repairs(self):
        base=self.cases['program_prefix_alloc_failure']
        for change in (dict(repair_alloc_fail=False),dict(repair_old=8),dict(responses=[1]),dict(repair_prefix=64)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_all_regenerated_fixtures(self):
        report=json.loads(Path('analysis/eftl-repair-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:self.assertEqual(row['observed'],self.cases[row['name']]['expected'])


if __name__=='__main__':unittest.main()
