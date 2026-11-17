import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_read_stack import BOUND,contract,native_vectors
from analysis_scripts.qspi_dma import BOUNCE


class NandReadStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]
    def tracked(self,name):return struct.unpack_from('<II',bytes.fromhex(self.row(name)['dma_contexts_hex'][1]),60)
    def payload_hash(self,data):
        buffer=bytearray((i*3+1)&255 for i in range(512));buffer[:len(data)]=data
        return hashlib.sha256(buffer).hexdigest()

    def test_original_commands_bridge_page_load_status_and_quad_cache(self):
        self.assertEqual(self.opcodes('read_direct'),[0x13,0x0f,0x6b])
        self.assertEqual(self.opcodes('read_private_dma'),[0x13,0x0f,0x6b])
        self.assertFalse(any(a.startswith(('load:','feature:','cache_read:','dma_setup:','dma_wait:')) for a in self.actions('read_private_dma')))

    def test_original_remap_changes_load_address_before_bus_submission(self):
        actions=self.actions('read_direct')
        self.assertIn('native_remap_page:600',actions);self.assertIn('native_remap_block:9',actions)
        self.assertIn('w:0:4:792',actions)
        self.assertLess(actions.index('native_remap_block:9'),actions.index('w:0:4:792'))

    def test_inactive_bbt_preserves_requested_page(self):
        actions=self.actions('read_inactive_bbt');self.assertIn('w:0:4:600',actions)
        self.assertFalse(any(a.startswith('native_remap_block:') for a in actions))

    def test_direct_status_byte_does_not_consume_payload_pattern(self):
        for name,n in (('read_one_byte',1),('read_direct_word_tail',13),('read_direct',64)):
            self.assertEqual(self.row(name)['buffer_sha256'],self.payload_hash(bytes((0x5a+i*7)&255 for i in range(n))))
            self.assertEqual(self.row(name)['rx_bytes'],n+1)

    def test_busy_reads_precede_payload_and_do_not_change_it(self):
        name='read_busy_then_ready';self.assertEqual(self.opcodes(name),[0x13,0x0f,0x0f,0x0f,0x6b])
        self.assertEqual(self.actions(name).count('delay:5'),3)
        self.assertEqual(self.row(name)['buffer_sha256'],self.row('read_direct')['buffer_sha256'])

    def test_private_dma_threshold_is_strictly_greater_than_31(self):
        low='read_private_threshold_31';high='read_private_threshold_32'
        self.assertEqual(self.row(low)['rx_bytes'],32);self.assertEqual(self.row(high)['rx_bytes'],1)
        self.assertFalse(any(a.startswith('copy_from_bounce:') for a in self.actions(low)))
        self.assertIn('copy_from_bounce:32',self.actions(high))

    def test_dma_success_copies_authored_sentinel_without_manufactured_data(self):
        name='read_private_dma';self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(self.row(name)['buffer_sha256'],self.payload_hash(b'\xa5'*64))
        self.assertNotEqual(self.row(name)['buffer_sha256'],self.row('read_direct')['buffer_sha256'])
        self.assertIn(f'dma_cache_prepare:{BOUNCE}:64',self.actions(name))
        self.assertIn(f'dma_cache_finish:{BOUNCE}:64',self.actions(name))

    def test_correctable_status_does_not_enter_retry(self):
        name='read_corrected_ecc';self.assertEqual(self.row(name)['returned'],0)
        self.assertFalse(any(a.startswith('compare20:') for a in self.actions(name)))

    def test_uncorrectable_status_still_transfers_before_minus_101(self):
        for name in ('read_uncorrectable_direct','read_uncorrectable_private'):
            self.assertEqual(self.row(name)['returned'],(-101)&0xffffffff)
            self.assertEqual(self.actions(name).count('compare20:-1'),2)
            self.assertLess(self.actions(name).index('compare20:-1'),next(i for i,a in enumerate(self.actions(name)) if a.startswith('w:12:4:') and int(a.split(':')[-1])>>24==0x6b))
            self.assertEqual(self.actions(name)[-1],'log:page_result')

    def test_plane_bit_uses_mapped_page(self):
        self.assertIn('w:0:4:4112',self.actions('read_plane'))
        self.assertIn('w:0:4:16',self.actions('read_plane_cleared_by_mapping'))
        self.assertEqual(self.cases['read_plane']['page']&64,0)
        self.assertNotEqual(self.cases['read_plane_cleared_by_mapping']['page']&64,0)
        self.assertEqual(self.opcodes('read_plane'),[0x13,0x0f,0x6b])

    def test_early_validation_errors_do_not_submit_nand_commands(self):
        for name,value in (('read_no_chip',-2),('read_null_buffer',-1),('read_zero_length',-1),('read_page_boundary',-1),('read_column_boundary',-1),('read_reserved_limit',-150)):
            self.assertEqual(self.row(name)['returned'],value&0xffffffff);self.assertEqual(self.opcodes(name),[])
        self.assertNotIn('log:page_result',self.actions('read_reserved_limit'))

    def test_spare_area_exact_end_and_last_usable_page_are_accepted(self):
        self.assertEqual(self.row('read_exact_end')['returned'],0);self.assertIn('w:0:4:2048',self.actions('read_exact_end'))
        self.assertEqual(self.row('read_last_usable')['returned'],0);self.assertIn('w:0:4:65407',self.actions('read_last_usable'))

    def test_bbt_preserves_existing_unsorted_and_duplicate_semantics(self):
        self.assertIn('w:0:4:64',self.actions('read_unsorted_bbt'))
        self.assertIn('w:0:4:192',self.actions('read_duplicate_bbt'))

    def test_timeout_logs_but_page_read_continues_to_success(self):
        for name in ('read_busy_timeout','read_ecc_at_timeout'):
            self.assertEqual(self.row(name)['returned'],0);self.assertEqual(self.row(name)['feature_reads'],2000)
            self.assertEqual(self.actions(name).count('delay:5'),2000);self.assertIn('log:busy_timeout',self.actions(name))
            self.assertNotIn('log:page_result',self.actions(name));self.assertEqual(self.opcodes(name)[-1],0x6b)

    def test_status_at_timeout_is_discarded_before_ecc_policy(self):
        name='read_ecc_at_timeout';self.assertIn('r:256:1:32',self.actions(name))
        self.assertFalse(any(a.startswith('compare20:') for a in self.actions(name)))
        self.assertEqual(self.row(name)['buffer_sha256'],self.row('read_direct')['buffer_sha256'])

    def test_load_feature_and_dma_failures_stop_at_original_assertions(self):
        for name,owner,line in (('read_load_assertion',0x80c37b7c,0x11f),('read_feature_assertion',0x80c37b7c,0x12a),('read_dma_assertion',0x80c37b98,0x16f),('read_cache_completion_assertion',0x80c37b98,0x16f)):
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertNotIn('log:page_result',self.actions(name));self.assertFalse(any(a.startswith('copy_from_bounce:') for a in self.actions(name)))

    def test_alternate_dma_status_can_return_success_with_tracking_live(self):
        self.assertEqual(self.row('read_dma_alternate_status')['returned'],0)
        self.assertEqual(self.tracked('read_dma_alternate_status'),(BOUNCE,64))
        self.assertEqual(self.tracked('read_private_dma'),(0,0))

    def test_deferred_platform_initializes_inside_first_bus_after_remapping(self):
        name='read_deferred_platform';actions=self.actions(name)
        self.assertLess(actions.index('native_remap_page:600'),next(i for i,a in enumerate(actions) if a.startswith('clock_read:')))
        self.assertEqual(self.row(name)['reinit_flag'],0);self.assertEqual(self.row(name)['returned'],0)

    def test_contract_rejects_unbounded_status_and_payload_inputs(self):
        base=self.cases['read_direct']
        for change in (dict(count=65),dict(alignment=1),dict(responses=[]),dict(responses=[256]),dict(responses=[0]*2001),dict(bbt_hex='00')):
            with self.assertRaises(ValueError):contract(base|change)

    def test_committed_native_evidence_matches_all_regenerated_fixtures(self):
        report=json.loads(Path('analysis/nand-read-stack.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False);self.assertEqual(execution['bound_per_case'],BOUND)
        self.assertEqual(execution['case_count'],len(self.cases));self.assertEqual(len(execution['cases']),len(self.cases))
        for case in execution['cases']:
            self.assertEqual(case['observed'],self.cases[case['name']]['expected']);self.assertTrue(0<case['steps']<=BOUND)


if __name__=='__main__':unittest.main()
