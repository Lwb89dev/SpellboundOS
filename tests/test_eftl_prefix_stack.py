import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.eftl_prefix_stack import HEAP,contract,native_vectors,page_bytes


class EftlPrefixStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def flags(self,name):return bytes.fromhex(self.row(name)['write_flags_hex'])
    def mapping(self,name):return struct.unpack('<8H',bytes.fromhex(self.row(name)['mapping_hex']))
    def pending(self):
        b=bytearray(b'\xff'*2112);b[:32]=bytes((i*3+1)&255 for i in range(32));b[2068:2072]=bytes([0,0,69,69]);return bytes(b)

    def test_one_prefix_page_is_copied_before_pending_page_retry(self):
        name='prefix_one';self.result(name,32);self.assertEqual(self.mapping(name)[0],5)
        self.assertEqual(self.flags(name)[3],1);self.assertEqual(self.flags(name)[5],4)
        tx=bytes.fromhex(self.row(name)['tx_hex']);self.assertEqual(tx[2112:4224],page_bytes(0));self.assertEqual(tx[-2112:],self.pending())

    def test_two_prefix_pages_keep_order_and_advance_current_page_progress(self):
        name='prefix_two';self.result(name,32);self.assertEqual(self.flags(name)[5],6)
        tx=bytes.fromhex(self.row(name)['tx_hex']);self.assertEqual(tx[2112:4224],page_bytes(0));self.assertEqual(tx[4224:6336],page_bytes(1))

    def test_heap_save_restore_preserves_pending_payload_and_frees_once(self):
        name='prefix_one';row=self.row(name)
        self.assertEqual(row['repair_allocations'],1);self.assertEqual(row['prefix_frees'],1);self.assertEqual(row['prefix_live_heap'],[])
        expected=hashlib.sha256(self.pending()).hexdigest();self.assertEqual(row['prefix_heap_sha256'],{str(HEAP):expected})
        self.assertEqual(row['scratch_sha256'],expected)

    def test_direct_repair_publishes_prefix_mapping_without_current_page_write(self):
        for name,prefix in (('prefix_direct',1),('prefix_direct_two',2)):
            self.result(name,5);self.assertEqual(self.mapping(name)[0],5);self.assertEqual(self.flags(name)[5],prefix*2)
            self.assertEqual(self.row(name)['storage_backend_calls'],0)

    def test_recursive_copy_failure_restores_before_next_allocation_and_retries(self):
        name='prefix_recursive';self.result(name,32);row=self.row(name)
        self.assertEqual(self.mapping(name)[0],6);self.assertEqual(self.flags(name)[3],1);self.assertEqual(self.flags(name)[5],1);self.assertEqual(self.flags(name)[6],4)
        self.assertEqual((row['repair_allocations'],row['prefix_frees'],row['prefix_live_heap']),(2,2,[]))
        self.assertEqual(len(set(row['prefix_heap_sha256'].values())),1);self.assertIn('log:repair_copy_write_failed',self.actions(name))

    def test_direct_recursive_repair_returns_new_prefix_block(self):
        name='prefix_direct_recursive';self.result(name,6);self.assertEqual(self.mapping(name)[0],6)
        self.assertEqual(self.flags(name)[6],2);self.assertEqual(self.row(name)['prefix_frees'],2)

    def test_no_free_after_copy_failure_has_no_live_heap_or_new_mapping(self):
        name='prefix_recursive_no_free';self.result(name,-2);self.assertEqual(self.mapping(name)[0],3)
        self.assertEqual(self.flags(name)[3],1);self.assertEqual(self.flags(name)[5],1)
        self.assertEqual(self.row(name)['prefix_live_heap'],[]);self.assertEqual(self.row(name)['prefix_frees'],1)

    def test_repair_checks_logical_identity_but_accepts_bad_tag_and_checksum(self):
        name='prefix_bad_tag_crc_accepted';self.result(name,32)
        self.assertFalse(any(a.startswith('readback_checksum:') for a in self.actions(name)))
        self.assertEqual(bytes.fromhex(self.row(name)['tx_hex'])[2112:4224],page_bytes(0,'bad_tag_crc'))

    def test_logical_mismatch_propagates_distinct_direct_and_upper_errors(self):
        self.result('prefix_direct_wrong_logical',-3);self.result('prefix_wrong_logical',-2)
        for name in ('prefix_direct_wrong_logical','prefix_wrong_logical'):
            self.assertIn('log:repair_logical_mismatch',self.actions(name));self.assertEqual(self.mapping(name)[0],3)
            self.assertEqual(self.row(name)['prefix_frees'],1)

    def test_second_page_mismatch_leaves_partial_target_unpublished(self):
        name='prefix_second_logical_mismatch';self.result(name,-2)
        self.assertEqual(self.mapping(name)[0],3);self.assertEqual(self.flags(name)[5],0)
        self.assertEqual(self.row(name)['prefix_live_heap'],[])

    def test_prefix_read_errors_restore_payload_and_return_without_publication(self):
        for name in ('prefix_read_error','prefix_second_read_error'):
            self.result(name,-2);self.assertIn('log:repair_read_failed',self.actions(name))
            self.assertEqual(self.row(name)['scratch_sha256'],hashlib.sha256(self.pending()).hexdigest())
            self.assertEqual(self.mapping(name)[0],3);self.assertEqual(self.row(name)['prefix_frees'],1)

    def test_initial_and_recursive_allocation_failure_keep_precise_lifetimes(self):
        for name,allocations,frees in (('prefix_alloc_failure',1,0),('prefix_recursive_alloc_failure',2,1)):
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c3436c,line=0xa3))
            self.assertEqual(self.row(name)['repair_allocations'],allocations);self.assertEqual(self.row(name)['prefix_frees'],frees)
            self.assertEqual(self.row(name)['prefix_live_heap'],[])

    def test_bus_assertion_keeps_live_heap_at_original_stop(self):
        name='prefix_cache_assertion';self.assertIsNone(self.row(name)['returned'])
        self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=0x12a))
        self.assertEqual(self.row(name)['prefix_live_heap'],[HEAP]);self.assertEqual(self.row(name)['prefix_frees'],0)

    def test_generic_dma_copies_full_stale_buffer_without_manufactured_movement(self):
        for name,n in (('prefix_generic',1),('prefix_two_generic',2)):
            self.result(name,32);self.assertEqual(self.actions(name).count('copy_from_bounce:2112'),n)
            self.assertEqual(self.row(name)['prefix_live_heap'],[])
        self.result('prefix_irq',32);self.assertNotIn('copy_from_bounce:2112',self.actions('prefix_irq'))

    def test_rewrite_reuses_same_prefix_repair_behavior(self):
        self.assertEqual(self.row('prefix_rewrite'),self.row('prefix_one'))
        self.assertEqual(self.actions('prefix_rewrite'),self.actions('prefix_one'))

    def test_caller_input_is_immutable_in_all_prefix_fixtures(self):
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for name in self.cases:self.assertEqual(self.row(name)['buffer_sha256'],expected)

    def test_contract_rejects_unbounded_prefix_and_heap_models(self):
        base=self.cases['prefix_one']
        for change in (dict(repair_prefix=3),dict(storage_offset=8192),dict(cache_payloads=['00'*64]),dict(prefix_fail_alloc_at=4),dict(write_readback=True),dict(native_prefix=False)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_all_regenerated_fixtures(self):
        report=json.loads(Path('analysis/eftl-prefix-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:self.assertEqual(row['observed'],self.cases[row['name']]['expected'])


if __name__=='__main__':unittest.main()
