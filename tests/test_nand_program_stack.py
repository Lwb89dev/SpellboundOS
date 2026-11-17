import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_program_stack import contract,native_vectors
from analysis_scripts.nand_read_stack import BOUND
from analysis_scripts.qspi_dma import BOUNCE


class NandProgramStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]
    def initial(self,n=512):return bytes((i*3+1)&255 for i in range(n))

    def test_program_sequence_reaches_original_enable_cache_execute_and_status(self):
        for name in ('program_direct','program_private_dma'):
            self.assertEqual(self.opcodes(name),[0x06,0x32,0x10,0x0f]);self.assertEqual(self.row(name)['returned'],0)
            self.assertFalse(any(a.startswith(('enable:','cache_write:','program:','feature:','dma_setup:','dma_wait:')) for a in self.actions(name)))

    def test_direct_fifo_writes_capture_exact_caller_bytes_including_tail(self):
        for name,n in (('program_direct',64),('program_word_tail',13),('program_private_threshold_31',31)):
            self.assertEqual(bytes.fromhex(self.row(name)['tx_hex']),self.initial(n))
            self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(self.initial()).hexdigest())

    def test_dma_copies_caller_bytes_to_private_buffer_before_submission(self):
        name='program_private_dma';actions=self.actions(name)
        self.assertIn('copy_to_bounce:64',actions)
        copy=actions.index('copy_to_bounce:64');cache=next(i for i,a in enumerate(actions) if a.startswith('w:12:4:') and int(a.split(':')[-1])>>24==0x32)
        self.assertLess(copy,cache);self.assertEqual(self.row(name)['tx_hex'],'')
        self.assertEqual(self.row(name)['bounce_sha256'],hashlib.sha256(self.initial(64)+b'\xa5'*448).hexdigest())
        self.assertIn(f'dma_cache_prepare:{BOUNCE}:64',actions)

    def test_private_threshold_changes_transport_at_32(self):
        self.assertEqual(len(bytes.fromhex(self.row('program_private_threshold_31')['tx_hex'])),31)
        self.assertEqual(self.row('program_private_threshold_32')['tx_hex'],'')
        self.assertIn('copy_to_bounce:32',self.actions('program_private_threshold_32'))

    def test_guard_checks_mapped_page_before_any_command(self):
        name='program_below_mapped_guard';self.assertEqual(self.row(name)['returned'],(-250)&0xffffffff)
        self.assertEqual(self.opcodes(name),[]);self.assertIn('log:page_guard',self.actions(name))
        name='program_mapped_guard_boundary';self.assertEqual(self.row(name)['returned'],0)
        self.assertIn('w:0:4:512',self.actions(name));self.assertNotIn('log:page_guard',self.actions(name))

    def test_disabled_guard_allows_authored_low_page(self):
        self.assertEqual(self.row('program_guard_disabled')['returned'],0)
        self.assertIn('w:0:4:0',self.actions('program_guard_disabled'))

    def test_plane_bit_follows_remapping_before_cache_write(self):
        self.assertIn('w:0:4:4112',self.actions('program_plane'))
        self.assertIn('w:0:4:728',self.actions('program_plane'))

    def test_busy_polling_follows_program_execute(self):
        name='program_busy_then_ready';self.assertEqual(self.opcodes(name),[0x06,0x32,0x10,0x0f,0x0f,0x0f])
        self.assertEqual(self.actions(name).count('delay:5'),3);self.assertEqual(self.row(name)['returned'],0)

    def test_failure_bit_returns_minus_102_and_ecc_bits_do_not(self):
        self.assertEqual(self.row('program_failed_status')['returned'],(-102)&0xffffffff)
        self.assertIn('log:page_result',self.actions('program_failed_status'))
        self.assertEqual(self.row('program_ecc_bits_ignored')['returned'],0)

    def test_timeout_is_rejected_even_when_last_status_is_ready(self):
        for name in ('program_busy_timeout','program_failure_at_timeout','program_ready_at_timeout'):
            self.assertEqual(self.row(name)['returned'],(-102)&0xffffffff)
            self.assertEqual(self.row(name)['feature_reads'],2000)
            self.assertEqual(self.actions(name)[-1],'log:page_result');self.assertIn('log:busy_timeout',self.actions(name))
        self.assertIn('r:256:1:0',self.actions('program_ready_at_timeout'))

    def test_validation_and_remapping_failures_do_not_submit(self):
        for name,value in (('program_no_chip',-2),('program_null_buffer',-1),('program_zero_length',-1),('program_column_boundary',-1),('program_reserved_limit',-150)):
            self.assertEqual(self.row(name)['returned'],value&0xffffffff);self.assertEqual(self.opcodes(name),[])
            self.assertIn('log:page_result',self.actions(name))

    def test_column_addition_wrap_is_accepted_and_reaches_controller(self):
        name='program_column_wrap';self.assertEqual(self.row(name)['returned'],0)
        self.assertIn('w:0:4:4294967280',self.actions(name))

    def test_failures_stop_at_original_assertions_without_outer_error_return(self):
        for name,owner,line in (('program_enable_assertion',0x80c37b7c,0x11f),('program_fifo_assertion',0x80c37b7c,0x132),('program_dma_assertion',0x80c37b98,0x17b),('program_execute_assertion',0x80c37b7c,0x11f)):
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertNotIn('log:page_result',self.actions(name))

    def test_failed_cache_transfer_never_issues_program_execute(self):
        for name in ('program_fifo_assertion','program_dma_assertion'):
            self.assertNotIn(0x10,self.opcodes(name));self.assertEqual(self.row(name)['feature_reads'],0)

    def test_alternate_transmit_status_returns_success(self):
        name='program_dma_alternate_status';self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(struct.unpack_from('<II',bytes.fromhex(self.row(name)['dma_contexts_hex'][0]),60),(0,0))
        self.assertEqual(self.opcodes(name),[0x06,0x32,0x10,0x0f])

    def test_deferred_platform_runs_after_remap_and_before_enable(self):
        name='program_deferred_platform';actions=self.actions(name)
        self.assertLess(actions.index('native_remap_page:600'),next(i for i,a in enumerate(actions) if a.startswith('clock_read:')))
        self.assertEqual(self.row(name)['reinit_flag'],0)

    def test_contract_rejects_unbounded_program_inputs(self):
        base=self.cases['program_direct']
        for change in (dict(count=65),dict(alignment=1),dict(responses=[]),dict(responses=[256]),dict(bbt_hex='00'),dict(mode='platform_page_read')):
            with self.assertRaises(ValueError):contract(base|change)

    def test_committed_native_evidence_matches_all_regenerated_fixtures(self):
        execution=json.loads(Path('analysis/nand-program-stack.json').read_bytes())['native_validation']
        self.assertIs(execution['hardware_execution'],False);self.assertEqual(execution['bound_per_case'],BOUND)
        self.assertEqual(execution['case_count'],len(self.cases));self.assertEqual(len(execution['cases']),len(self.cases))
        for case in execution['cases']:
            self.assertEqual(case['observed'],self.cases[case['name']]['expected']);self.assertTrue(0<case['steps']<=BOUND)


if __name__=='__main__':unittest.main()
