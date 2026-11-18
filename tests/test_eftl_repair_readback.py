import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.eftl_repair_readback import contract,metadata,native_vectors
from analysis_scripts.eftl_prefix_stack import HEAP


class EftlRepairReadbackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def mapping(self,name):return struct.unpack('<8H',bytes.fromhex(self.row(name)['mapping_hex']))[0]
    def flags(self,name):return bytes.fromhex(self.row(name)['write_flags_hex'])
    def pending(self,variant='valid'):
        b=bytearray(b'\xff'*2112);b[:32]=bytes((i*3+1)&255 for i in range(32));b[2048:]=metadata(variant);return bytes(b)

    def test_successful_prefix_repair_reaches_enabled_readback(self):
        name='combined_program_repair';self.result(name,32);self.assertEqual(self.mapping(name),5)
        self.assertIn('readback_checksum:00004545',self.actions(name));self.assertEqual(self.flags(name)[5],4)
        self.assertEqual(self.row(name)['prefix_frees'],1);self.assertEqual(self.row(name)['prefix_live_heap'],[])

    def test_failed_final_tag_or_checksum_keeps_already_published_prefix_mapping(self):
        for name in ('combined_bad_tag','combined_bad_crc'):
            self.result(name,-2);self.assertEqual(self.mapping(name),5);self.assertEqual(self.flags(name)[5],4)
            self.assertIn('log:eftl_readback_check_failed',self.actions(name));self.assertEqual(self.row(name)['prefix_frees'],1)
        self.assertNotIn('log:checksum_error',self.actions('combined_bad_tag'))
        self.assertIn('log:checksum_error',self.actions('combined_bad_crc'))

    def test_final_readback_accepts_valid_checksum_for_different_logical_id(self):
        name='combined_wrong_logical';self.result(name,32);self.assertEqual(self.mapping(name),5)
        self.assertIn('readback_checksum:0700454c',self.actions(name))

    def test_two_page_prefix_advances_progress_before_final_check(self):
        name='combined_two_pages';self.result(name,32);self.assertEqual(self.flags(name)[5],6)
        self.assertEqual(self.row(name)['repair_allocations'],1);self.assertEqual(self.row(name)['prefix_frees'],1)

    def test_initial_readback_io_error_enters_prefix_repair(self):
        name='combined_initial_io_valid';self.result(name,32)
        self.assertIn('log:eftl_readback_io_failed',self.actions(name));self.assertNotIn('log:eftl_program_failed',self.actions(name))
        self.assertEqual(bytes.fromhex(self.row(name)['tx_hex'])[-2112:],self.pending())

    def test_initial_failed_readback_oob_is_saved_and_programmed_on_retry(self):
        for variant in ('wrong_logical','bad_tag'):
            name='combined_initial_io_'+variant;self.result(name,32);row=self.row(name)
            expected=self.pending(variant);self.assertEqual(bytes.fromhex(row['tx_hex'])[-2112:],expected)
            self.assertEqual(row['prefix_heap_sha256'],{str(HEAP):hashlib.sha256(expected).hexdigest()})
            self.assertEqual(row['scratch_sha256'],hashlib.sha256(self.pending()).hexdigest())

    def test_no_free_after_retry_io_error_keeps_mapping_to_now_bad_block(self):
        name='combined_retry_io_no_free';self.result(name,-2);self.assertEqual(self.mapping(name),5)
        self.assertEqual(self.flags(name)[5],1);self.assertEqual(self.row(name)['repair_allocations'],1)
        self.assertEqual(self.row(name)['prefix_frees'],1);self.assertEqual(self.row(name)['prefix_live_heap'],[])

    def test_second_repair_preserves_oob_written_by_failed_retry_readback(self):
        name='combined_retry_io_relocate';self.result(name,32);row=self.row(name)
        self.assertEqual(self.mapping(name),6);self.assertEqual(self.flags(name)[5],1);self.assertEqual(self.flags(name)[6],4)
        self.assertEqual((row['repair_allocations'],row['prefix_frees'],row['prefix_live_heap']),(2,2,[]))
        self.assertEqual(len(set(row['prefix_heap_sha256'].values())),2)
        self.assertEqual(bytes.fromhex(row['tx_hex'])[-2112:],self.pending('wrong_logical'))

    def test_retry_program_failure_can_exhaust_free_blocks_or_relocate_again(self):
        name='combined_retry_program_no_free';self.result(name,-2);self.assertEqual(self.mapping(name),5);self.assertEqual(self.flags(name)[5],1)
        name='combined_retry_program_relocate';self.result(name,32);self.assertEqual(self.mapping(name),6)
        self.assertEqual(self.row(name)['prefix_frees'],2);self.assertEqual(len(set(self.row(name)['prefix_heap_sha256'].values())),1)
        self.assertEqual(self.actions(name).count('log:eftl_repair_start'),2)

    def test_recursive_prefix_failure_reaches_final_readback_after_one_outer_repair(self):
        name='combined_recursive_prefix';self.result(name,32);self.assertEqual(self.mapping(name),6)
        self.assertEqual(self.actions(name).count('log:eftl_repair_start'),1)
        self.assertIn('log:repair_copy_write_failed',self.actions(name));self.assertIn('readback_checksum:00004545',self.actions(name))
        self.assertEqual(self.row(name)['prefix_frees'],2)

    def test_generic_stale_rx_rejects_check_while_irq_direct_path_succeeds(self):
        name='combined_generic';self.result(name,-2);self.assertEqual(self.mapping(name),5)
        self.assertIn('copy_from_bounce:2112',self.actions(name));self.assertIn('copy_from_bounce:64',self.actions(name))
        self.assertNotIn('readback_checksum:00004545',self.actions(name));self.result('combined_irq',32)

    def test_rewrite_and_program_share_observed_repair_and_readback(self):
        self.assertEqual(self.row('combined_rewrite'),self.row('combined_program_repair'))
        self.assertEqual(self.actions('combined_rewrite'),self.actions('combined_program_repair'))

    def test_prefix_rejection_still_prevents_publication_and_frees_buffer(self):
        for name in ('combined_prefix_wrong_logical','combined_second_prefix_wrong_logical'):
            self.result(name,-2);self.assertEqual(self.mapping(name),3);self.assertEqual(self.flags(name)[5],0)
            self.assertIn('log:repair_logical_mismatch',self.actions(name));self.assertEqual(self.row(name)['prefix_frees'],1)

    def test_allocation_and_final_readback_assertions_keep_distinct_heap_states(self):
        r=self.row('combined_alloc_failure');self.assertIsNone(r['returned'])
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c3436c,line=0xa3));self.assertEqual(r['prefix_frees'],0)
        name='combined_final_readback_assertion';r=self.row(name);self.assertIsNone(r['returned'])
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=0x12a))
        self.assertEqual(self.mapping(name),5);self.assertEqual(r['prefix_frees'],1);self.assertEqual(r['prefix_live_heap'],[])

    def test_contract_rejects_unbounded_or_incompatible_combined_inputs(self):
        base=self.cases['combined_program_repair']
        for change in (dict(write_readback=False),dict(repair_entry=True),dict(cache_payloads=['00'*32]),dict(responses=[4]),dict(responses=[0]*25)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_fixtures_and_keeps_caller_input_immutable(self):
        report=json.loads(Path('analysis/eftl-repair-readback.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for row in report['cases']:
            self.assertEqual(row['observed'],self.cases[row['name']]['expected']);self.assertEqual(row['observed']['rows'][0]['buffer_sha256'],expected)


if __name__=='__main__':unittest.main()
