import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.eftl_initialize import HEAP, OLD, contract, native_vectors


class EftlInitializeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases={c['name']:c for c in native_vectors()['cases']}

    def result(self,name):return self.cases[name]['expected']
    def row(self,name,index=-1):return self.result(name)['rows'][index]
    def active(self,name):return [a for a in self.row(name)['allocations'] if a['active']]

    def test_connected_geometry_allocation_scan_and_summary(self):
        row=self.row('initialize_mixed')
        self.assertEqual((row['returned'],row['marker'],row['read_behavior']),(0,0xa5,1))
        self.assertEqual((row['page_size'],row['pages_per_block'],row['block_count'],row['base_page']),(32,4,4,32768))
        self.assertEqual(row['counters'],[1,2,1])
        self.assertEqual([a['size'] for a in row['allocations']],[4,8,48])
        self.assertEqual(self.result('initialize_mixed')['actions'][-2:],['log:capacity_summary','log:block_summary'])

    def test_buffers_contain_reconstructed_flags_mapping_and_erased_scratch(self):
        allocations=self.row('initialize_mixed')['allocations']
        for allocation,data in zip(allocations,(bytes.fromhex('08fe08ff'),struct.pack('<4H',2,0xffff,0,0xffff),b'\xff'*48)):
            self.assertEqual(allocation['sha256'],hashlib.sha256(data).hexdigest())

    def test_repeat_after_success_uses_marker_guard(self):
        rows=self.result('initialize_repeat')['rows']
        self.assertEqual(rows[0],rows[1])
        self.assertEqual(sum(a.startswith('alloc:') for a in self.result('initialize_repeat')['actions']),3)

    def test_marker_guard_skips_even_geometry_validation(self):
        self.assertEqual(self.result('initialize_marker_guard')['actions'],[])
        self.assertEqual(self.row('initialize_marker_guard')['returned'],0)
        self.assertEqual(len(self.active('initialize_marker_guard')),3)

    def test_forced_reinitialize_frees_three_old_buffers_in_order(self):
        actions=self.result('initialize_force_cleanup')['actions']
        self.assertEqual(actions[:3],[f'free:{p}' for p in OLD])
        heap=self.row('initialize_force_cleanup')['allocations']
        self.assertEqual([a['active'] for a in heap],[False]*3+[True]*3)
        self.assertEqual(self.row('initialize_force_cleanup')['pointers'],[HEAP+i*4096 for i in range(3)])

    def test_forced_cleanup_skips_zero_pointer(self):
        frees=[a for a in self.result('initialize_force_partial_cleanup')['actions'] if a.startswith('free:')]
        self.assertEqual(frees,[f'free:{OLD[0]}',f'free:{OLD[2]}'])

    def test_format_error_after_cleanup_does_not_allocate(self):
        row=self.row('initialize_force_format_error')
        self.assertEqual((row['returned'],row['marker'],row['read_behavior']),(0xffffffff,0,1))
        self.assertEqual(row['pointers'],[0,0,0])
        self.assertEqual(self.active('initialize_force_format_error'),[])
        self.assertFalse(any(a.startswith('alloc:') for a in self.result('initialize_force_format_error')['actions']))

    def test_positive_format_status_also_maps_to_minus_one(self):
        self.assertEqual(self.row('initialize_force_positive_format_error')['returned'],0xffffffff)

    def test_unmarked_old_buffers_are_not_freed(self):
        self.assertEqual(len(self.active('initialize_unmarked_old_buffers')),6)
        self.assertFalse(any(a.startswith('free:') for a in self.result('initialize_unmarked_old_buffers')['actions']))

    def test_first_allocation_failure_stops_before_null_write(self):
        row=self.row('initialize_alloc_1_error')
        self.assertIsNone(row['returned'])
        self.assertEqual(row['stopped'],dict(kind='null_memset',size=4,fill=0))
        self.assertEqual(row['allocations'],[])

    def test_second_allocation_failure_keeps_first_buffer_live(self):
        row=self.row('initialize_alloc_2_error')
        self.assertEqual(row['stopped'],dict(kind='null_memset',size=8,fill=255))
        self.assertEqual(row['pointers'],[HEAP,0,0])
        self.assertEqual(len(self.active('initialize_alloc_2_error')),1)

    def test_third_allocation_failure_keeps_first_two_buffers_live(self):
        row=self.row('initialize_alloc_3_error')
        self.assertEqual(row['stopped'],dict(kind='null_memset',size=48,fill=255))
        self.assertEqual(row['pointers'],[HEAP,HEAP+4096,0])
        self.assertEqual(len(self.active('initialize_alloc_3_error')),2)

    def test_oob_failure_returns_with_three_live_buffers_and_no_marker(self):
        row=self.row('initialize_oob_error')
        self.assertEqual((row['returned'],row['marker']),(0xffffffff,0))
        self.assertEqual(len(self.active('initialize_oob_error')),3)
        self.assertNotIn('log:capacity_summary',self.result('initialize_oob_error')['actions'])

    def test_repeating_failed_initialization_loses_earlier_buffer_bindings(self):
        rows=self.result('initialize_error_repeat_leaks')['rows']
        self.assertEqual([len([a for a in r['allocations'] if a['active']]) for r in rows],[3,6])
        self.assertNotEqual(rows[0]['pointers'],rows[1]['pointers'])
        self.assertFalse(any(a.startswith('free:') for a in self.result('initialize_error_repeat_leaks')['actions']))

    def test_retry_resets_both_tables_and_all_three_counters(self):
        row=self.row('initialize_retry_rebuild')
        self.assertEqual((row['returned'],row['marker'],row['counters']),(0,0xa5,[0,4,0]))
        self.assertEqual(row['allocations'][0]['sha256'],hashlib.sha256(b'\x08'*4).hexdigest())
        self.assertEqual(row['allocations'][1]['sha256'],hashlib.sha256(struct.pack('<4H',0,1,2,3)).hexdigest())
        self.assertEqual([a for a in self.result('initialize_retry_rebuild')['actions'] if a.startswith('scan:')],['scan:0','scan:1'])

    def test_retry_can_report_success_with_all_blocks_reserved(self):
        row=self.row('initialize_retry_all_reserved')
        self.assertEqual((row['returned'],row['marker'],row['counters']),(0,0xa5,[0,0,4]))
        self.assertIn('log:capacity_summary',self.result('initialize_retry_all_reserved')['actions'])

    def test_retry_read_failure_keeps_only_second_scan_partial_state(self):
        row=self.row('initialize_retry_read_error')
        self.assertEqual((row['returned'],row['marker'],row['counters']),(0xffffffff,0,[0,1,0]))

    def test_geometry_ioctl_status_is_ignored_when_outputs_are_supplied(self):
        self.assertEqual(self.row('initialize_ioctl_status_ignored')['context_hex'],self.row('initialize_mixed')['context_hex'])
        self.assertEqual(self.row('geometry_ioctl_status_ignored')['context_hex'],self.row('geometry_original')['context_hex'])

    def test_lazy_wrapper_executes_initializer_and_publishes_capacity(self):
        row=self.row('lazy_connected')
        self.assertIsNone(row['returned'])
        self.assertEqual((row['eftl_ready'],row['capacity_word'],row['block_word']),(1,384,128))
        self.assertEqual((row['marker'],row['counters']),(0xa5,[1,2,1]))
        self.assertEqual(self.result('lazy_connected')['actions'][-1],'log:eftl_ready')

    def test_connected_lazy_repeat_skips_initialized_work(self):
        rows=self.result('lazy_connected_repeat')['rows']
        self.assertEqual(rows[0],rows[1])
        self.assertEqual(sum(a.startswith('alloc:') for a in self.result('lazy_connected_repeat')['actions']),3)

    def test_lazy_initializer_failure_preserves_initial_descriptor_and_live_heap(self):
        row=self.row('lazy_connected_error')
        self.assertEqual((row['eftl_ready'],row['capacity_word'],row['block_word']),(0,0x7fffffff,0x20000))
        self.assertEqual(len(self.active('lazy_connected_error')),3)
        self.assertNotIn('log:eftl_ready',self.result('lazy_connected_error')['actions'])

    def test_outer_lazy_ready_guard_skips_entire_initializer(self):
        self.assertEqual(self.result('lazy_already_ready')['actions'],[])
        self.assertEqual(self.row('lazy_already_ready')['allocations'],[])

    def test_generic_format_checks_bad_blocks_before_erasing(self):
        actions=self.result('initialize_native_format')['actions']
        self.assertIn('format_bad:3:1',actions)
        self.assertNotIn('format_erase:3:0',actions)
        self.assertEqual(len([a for a in actions if a.startswith('format_erase:')]),3)

    def test_generic_format_ignores_erase_errors_when_forcing_all_blocks(self):
        actions=self.result('initialize_native_format_erase_errors')['actions']
        self.assertFalse(any(a.startswith('format_bad:') for a in actions))
        self.assertEqual([a for a in actions if a.startswith('format_erase:')],[f'format_erase:{i}:-9' for i in range(4)])
        self.assertEqual(self.row('initialize_native_format_erase_errors')['returned'],0)

    def test_format_negative_bad_status_skips_erase_but_resume_attempts_it(self):
        actions=self.result('initialize_native_format_negative_bad')['actions']
        self.assertIn('format_bad:0:-9',actions)
        self.assertNotIn('format_erase:0:0',actions)
        self.assertIn('erase:0:0',actions)

    def test_native_format_then_retry_can_still_finish_all_reserved(self):
        self.assertEqual((self.row('initialize_native_format_all_reserved')['returned'],self.row('initialize_native_format_all_reserved')['counters']),(0,[0,0,4]))

    def test_geometry_collects_page_and_spare_metadata(self):
        row=self.row('geometry_original');data=bytes.fromhex(row['context_hex'])
        self.assertEqual(struct.unpack_from('<7H',data,28),(16,8,2,2,4,8,12))
        self.assertEqual((row['returned'],row['marker'],row['read_behavior']),(0,0,0))

    def test_existing_geometry_handle_skips_lookup(self):
        self.assertFalse(any(a.startswith('find:') for a in self.result('geometry_existing_handle')['actions']))
        self.assertEqual(self.row('geometry_existing_handle')['context_hex'],self.row('geometry_original')['context_hex'])

    def test_geometry_divisions_truncate_partial_pages_and_blocks(self):
        self.assertEqual(self.row('geometry_unaligned_partition')['base_page'],32768)
        self.assertEqual(self.row('geometry_page_count_truncation')['block_count'],4)

    def test_metadata_words_are_stored_as_u16(self):
        self.assertEqual(self.row('geometry_metadata_u16')['context_hex'],self.row('geometry_original')['context_hex'])

    def test_missing_handle_stops_at_assertion(self):
        row=self.row('geometry_find_error')
        self.assertIsNone(row['returned'])
        self.assertEqual(row['stopped'],dict(kind='assertion',line=0x1a))

    def test_zero_geometry_fields_stop_at_distinct_assertions(self):
        for key,line in (('page_size',0x21),('pages_per_block',0x22),('pages',0x23),('spare',0x35),('ecc_total',0x36),('ecc_unit',0x37)):
            row=self.row('geometry_zero_'+key)
            self.assertIsNone(row['returned'])
            self.assertEqual(row['stopped'],dict(kind='assertion',line=line))

    def test_fixture_bounds_reject_oversized_allocations(self):
        case=copy.deepcopy(self.cases['initialize_mixed']);case['page_size']=1024
        with self.assertRaises(ValueError):contract(case)
        case=copy.deepcopy(self.cases['initialize_mixed']);case['pages']=40
        with self.assertRaises(ValueError):contract(case)

    def test_public_native_observations_match_all_cases(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/eftl-initialize.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(38,38))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['export_sha256']),len(report['byte_range_sha256'])),(6,6))


if __name__=='__main__':unittest.main()
