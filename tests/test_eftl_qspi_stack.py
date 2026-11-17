import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.eftl_qspi_stack import contract,native_vectors


class EftlQspiStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def expected_buffer(self,data):
        b=bytearray((i*3+1)&255 for i in range(512));b[:len(data)]=data;return hashlib.sha256(b).hexdigest()
    def pattern(self,n,start=0):return bytes((0x5a+(i+start)*7)&255 for i in range(n))

    def test_logical_translation_reaches_partition_callback_and_bbt(self):
        name='eftl_map_normal';self.result(name,32)
        self.assertIn('driver_read:704:16:32',self.actions(name));self.assertIn('native_remap_page:704',self.actions(name))
        self.assertIn('w:0:4:896',self.actions(name))

    def test_fast_adapter_bypasses_driver_but_preserves_address_result(self):
        self.result('eftl_map_fast',32);self.assertEqual(self.row('eftl_map_fast')['driver_calls'],0)
        self.assertIn('native_remap_page:704',self.actions('eftl_map_fast'))
        self.assertFalse(any(a.startswith(('irq_context:','mutex_')) for a in self.actions('eftl_map_fast')))

    def test_two_page_read_writes_both_output_segments(self):
        for name in ('eftl_two_pages','eftl_two_pages_fast'):
            self.result(name,32);self.assertEqual(self.row(name)['buffer_sha256'],self.expected_buffer(self.pattern(32)))
            self.assertEqual(self.row(name)['feature_reads'],2)
        self.assertEqual(self.row('eftl_two_pages')['driver_calls'],2)

    def test_two_private_dma_copies_reach_distinct_caller_offsets(self):
        name='eftl_two_dma_pages';self.result(name,64)
        self.assertEqual(self.actions(name).count('copy_from_bounce:32'),2)
        self.assertEqual(self.row(name)['buffer_sha256'],self.expected_buffer(b'\xa5'*64))
        self.assertEqual(self.row('eftl_two_dma_pages_fast')['buffer_sha256'],self.expected_buffer(self.pattern(64)))

    def test_cross_block_selects_new_logical_mapping_slot(self):
        name='eftl_cross_block';self.result(name,32)
        self.assertIn('driver_read:767:2040:8',self.actions(name));self.assertIn('driver_read:576:0:24',self.actions(name))

    def test_unmapped_first_block_fills_ff_and_returns_zero(self):
        name='eftl_first_gap';self.result(name,0);self.assertEqual(self.row(name)['driver_calls'],0)
        self.assertEqual(self.row(name)['buffer_sha256'],self.expected_buffer(b'\xff'*32))
        self.assertEqual(self.actions(name)[-1],'log:unmapped_block')

    def test_gap_after_prefix_returns_prefix_length_and_fills_remaining_bytes(self):
        name='eftl_gap_after_prefix';self.result(name,8);self.assertEqual(self.row(name)['driver_calls'],1)
        self.assertEqual(self.row(name)['buffer_sha256'],self.expected_buffer(self.pattern(8)+b'\xff'*24))

    def test_zero_logical_read_avoids_driver_while_zero_page_read_fails_lower_policy(self):
        self.result('eftl_zero',0);self.assertEqual(self.row('eftl_zero')['driver_calls'],0)
        self.result('eftl_page_zero',-1);self.assertEqual(self.row('eftl_page_zero')['driver_calls'],1)

    def test_ready_wrapper_connects_actual_translation_without_initializer(self):
        self.result('eftl_wrapper',32)
        self.assertEqual(self.row('eftl_wrapper')['buffer_sha256'],self.row('eftl_two_pages')['buffer_sha256'])
        self.result('eftl_wrapper_gap',0);self.assertIn('log:unmapped_block',self.actions('eftl_wrapper_gap'))

    def test_missing_driver_fails_generic_but_fast_adapter_bypasses_it(self):
        self.result('eftl_lower_missing_driver',-1);self.assertIn('log:page_read_error',self.actions('eftl_lower_missing_driver'))
        self.result('eftl_fast_bypasses_missing_driver',32);self.assertEqual(self.row('eftl_fast_bypasses_missing_driver')['driver_calls'],0)

    def test_lower_mapping_failure_reaches_logical_read_error(self):
        self.result('eftl_lower_mapping_rejected',-1);self.assertIn('log:page_read_error',self.actions('eftl_lower_mapping_rejected'))

    def test_second_page_ecc_error_can_leave_full_buffer_modified_before_failure(self):
        name='eftl_second_ecc_error';self.result(name,-1)
        self.assertEqual(self.row(name)['buffer_sha256'],self.expected_buffer(self.pattern(32)))
        self.assertEqual(self.actions(name)[-1],'log:page_read_error');self.assertIn('log:page_result',self.actions(name))

    def test_fast_base_addition_wraps_before_bbt(self):
        self.result('eftl_fast_base_wrap',0);self.assertIn('native_remap_page:6',self.actions('eftl_fast_base_wrap'))

    def test_oob_generic_dma_and_fast_fifo_feed_original_extractor(self):
        self.result('eftl_oob_generic',0);self.result('eftl_oob_fast',0)
        self.assertEqual(self.row('eftl_oob_generic')['buffer_sha256'],self.expected_buffer(b'\xa5'*4))
        self.assertEqual(self.row('eftl_oob_fast')['buffer_sha256'],self.expected_buffer(self.pattern(4,20)))
        self.assertEqual(self.row('eftl_oob_irq')['buffer_sha256'],self.row('eftl_oob_fast')['buffer_sha256'])

    def test_segmented_and_marker_skipping_oob_use_original_copy_boundaries(self):
        self.assertEqual(self.row('eftl_oob_segmented')['buffer_sha256'],self.expected_buffer(self.pattern(2,4)+self.pattern(2,20)))
        self.assertIn('oob_copy:0:4:2',self.actions('eftl_oob_segmented'))
        self.assertEqual(self.row('eftl_oob_skip_marker')['buffer_sha256'],self.expected_buffer(self.pattern(2,20)+self.pattern(2,36)))
        self.assertIn('oob_copy:0:2:0',self.actions('eftl_oob_skip_marker'))

    def test_oob_failures_skip_extraction_and_metadata_assertion_is_original(self):
        self.result('eftl_oob_ecc_error',-101)
        self.assertEqual(self.row('eftl_oob_ecc_error')['buffer_sha256'],self.expected_buffer(b''))
        name='eftl_oob_ecc_metadata_assertion';self.assertIsNone(self.row(name)['returned'])
        self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c3446c,line=0x48))
        self.result('eftl_oob_missing_driver',-6)

    def test_zero_unit_leaves_output_unchanged_after_successful_oob_read(self):
        name='eftl_oob_zero_unit';self.result(name,0)
        self.assertEqual(self.row(name)['buffer_sha256'],self.expected_buffer(b''))
        self.assertEqual(sum(a.startswith('oob_copy:') for a in self.actions(name)),4)

    def test_contract_rejects_unbacked_map_and_output(self):
        base=self.cases['eftl_map_normal']
        for change in (dict(count=65),dict(offset=8*131072),dict(mapping=[]),dict(ecc_unit=1),dict(positions=[64]*4),dict(responses=[])):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_regenerated_fixtures(self):
        report=json.loads(Path('analysis/eftl-qspi-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases))
        self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:self.assertEqual(row['observed'],self.cases[row['name']]['expected'])


if __name__=='__main__':unittest.main()
