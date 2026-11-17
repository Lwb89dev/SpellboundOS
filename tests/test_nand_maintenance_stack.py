import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.nand_maintenance_stack import contract,native_vectors
from analysis_scripts.nand_read_stack import BOUND


class NandMaintenanceStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]
    def addresses(self,name):return [int(a.split(':')[-1]) for a in self.actions(name) if a.startswith('w:0:4:')]

    def test_erase_uses_mapped_block_times_original_pages_per_block(self):
        name='erase_ready';self.assertEqual(self.opcodes(name),[0x06,0xd8,0x0f])
        self.assertEqual(self.addresses(name),[0,15*64,192]);self.assertEqual(self.row(name)['returned'],0)
        self.assertIn('native_remap_block:12',self.actions(name))

    def test_inactive_bbt_preserves_erase_block_address(self):
        self.assertEqual(self.addresses('erase_inactive_bbt'),[0,12*64,192])

    def test_copy_maps_source_and_destination_before_submitting(self):
        name='copy_page_ready';actions=self.actions(name)
        self.assertEqual(self.opcodes(name),[0x13,0x0f,0x06,0x10,0x0f])
        self.assertEqual(self.addresses(name),[792,192,0,892,192])
        self.assertLess(actions.index('native_remap_page:700'),next(i for i,a in enumerate(actions) if a.startswith('w:12:4:')))

    def test_oob_uses_original_34_command_between_enable_and_execute(self):
        name='copy_oob_ready';self.assertEqual(self.opcodes(name),[0x13,0x0f,0x06,0x34,0x10,0x0f])
        self.assertEqual(self.addresses(name),[792,192,0,2048,892,192])
        self.assertNotIn(0x32,self.opcodes(name))

    def test_oob_payload_runs_through_direct_fifo_even_at_64_bytes(self):
        for name,n in (('copy_oob_ready',64),('copy_oob_word_tail',13)):
            self.assertEqual(bytes.fromhex(self.row(name)['tx_hex']),bytes((i*3+1)&255 for i in range(n)))
            self.assertFalse(any(a.startswith(('copy_to_bounce:','dma_cache_prepare:','dma_tick:')) for a in self.actions(name)))
            self.assertEqual(self.row(name)['rx_bytes'],2)

    def test_oob_patch_does_not_mutate_caller_buffer(self):
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for name in ('copy_oob_ready','copy_oob_word_tail','copy_page_ready','erase_ready'):
            self.assertEqual(self.row(name)['buffer_sha256'],expected)

    def test_oob_plane_uses_mapped_source_rather_than_destination(self):
        self.assertEqual(self.addresses('copy_oob_source_plane'),[728,192,0,6144,892,192])
        self.assertEqual(self.addresses('copy_oob_dest_plane_only'),[792,192,0,2048,728,192])

    def test_zero_length_oob_still_submits_patch_and_executes_program(self):
        name='copy_oob_zero_length';self.assertEqual(self.row(name)['returned'],0)
        self.assertIn(0x34,self.opcodes(name));self.assertIn(0x10,self.opcodes(name));self.assertEqual(self.row(name)['tx_hex'],'')

    def test_oob_over_spare_size_stops_before_source_load(self):
        name='copy_oob_too_long';self.assertEqual(self.row(name)['returned'],0xffffffff)
        self.assertEqual(self.opcodes(name),[]);self.assertIn('log:copy_result',self.actions(name))

    def test_source_guard_uses_mapped_address_before_any_commands(self):
        for operation in ('erase','copy_page','copy_oob'):
            name=operation+'_guarded_source';self.assertEqual(self.row(name)['returned'],(-250)&0xffffffff)
            self.assertEqual(self.opcodes(name),[])
            self.assertIn('log:block_guard' if operation=='erase' else 'log:page_guard',self.actions(name))
            self.assertEqual(self.row(operation+'_guard_boundary')['returned'],0)

    def test_destination_guard_is_also_checked_before_source_load(self):
        for operation in ('copy_page','copy_oob'):
            name=operation+'_guarded_dest';self.assertEqual(self.row(name)['returned'],(-250)&0xffffffff)
            self.assertEqual(self.opcodes(name),[])

    def test_disabling_guard_allows_authored_low_source(self):
        for operation in ('erase','copy_page','copy_oob'):
            self.assertEqual(self.row(operation+'_guard_disabled')['returned'],0)

    def test_reserved_mappings_and_inactive_geometry_limits_are_distinct(self):
        for operation in ('erase','copy_page','copy_oob'):
            name=operation+'_reserved_source';self.assertEqual(self.row(name)['returned'],(-151 if operation=='erase' else -150)&0xffffffff)
            self.assertEqual(self.opcodes(name),[])
            name=operation+'_out_of_range';self.assertEqual(self.row(name)['returned'],0xffffffff);self.assertEqual(self.opcodes(name),[])
        for operation in ('copy_page','copy_oob'):
            self.assertEqual(self.row(operation+'_reserved_dest')['returned'],(-150)&0xffffffff)
            self.assertEqual(self.row(operation+'_dest_out_of_range')['returned'],0xffffffff)

    def test_missing_chip_returns_minus_two_without_remapping(self):
        for operation in ('erase','copy_page','copy_oob'):
            name=operation+'_missing_chip';self.assertEqual(self.row(name)['returned'],(-2)&0xffffffff)
            self.assertFalse(any(a.startswith('native_remap_') for a in self.actions(name)))

    def test_erase_delay_and_sleep_modes_use_distinct_original_leaf_services(self):
        self.assertIn('delay:5',self.actions('erase_ready'));self.assertNotIn('sleep:1',self.actions('erase_ready'))
        self.assertIn('sleep:1',self.actions('erase_sleep_ready'));self.assertNotIn('delay:5',self.actions('erase_sleep_ready'))

    def test_erase_status_checks_bit_four_not_program_bit_eight(self):
        self.assertEqual(self.row('erase_failed_status')['returned'],(-104)&0xffffffff)
        self.assertEqual(self.row('erase_program_bit_ignored')['returned'],0)

    def test_erase_timeout_runs_full_20_or_4000_poll_budget(self):
        for name,n in (('erase_sleep_timeout',20),('erase_delay_timeout',4000)):
            self.assertEqual(self.row(name)['feature_reads'],n);self.assertEqual(self.row(name)['returned'],(-104)&0xffffffff)
            self.assertIn('log:busy_timeout',self.actions(name));self.assertEqual(self.actions(name)[-1],'log:erase_result')

    def test_erase_rejects_even_ready_status_at_last_poll(self):
        for name,n in (('erase_sleep_ready_at_limit',20),('erase_delay_ready_at_limit',4000)):
            self.assertEqual(self.row(name)['feature_reads'],n);self.assertEqual(self.row(name)['returned'],(-104)&0xffffffff)
            self.assertIn('r:256:1:0',self.actions(name));self.assertIn('log:busy_timeout',self.actions(name))

    def test_copy_ecc_bad_stops_before_enable_without_read_retry(self):
        for operation in ('copy_page','copy_oob'):
            name=operation+'_ecc_bad';self.assertEqual(self.row(name)['returned'],(-101)&0xffffffff)
            self.assertEqual(self.opcodes(name),[0x13,0x0f]);self.assertFalse(any(a.startswith('compare20:') for a in self.actions(name)))

    def test_source_timeout_can_still_execute_copy_and_return_success(self):
        name='copy_source_timeout_then_success';self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(self.row(name)['feature_reads'],2001);self.assertIn('log:busy_timeout',self.actions(name))
        self.assertIn(0x10,self.opcodes(name));self.assertNotIn('log:copy_result',self.actions(name))

    def test_program_timeout_and_both_timeouts_reject_copy(self):
        for name,n,logs in (('copy_program_timeout',2001,1),('copy_both_timeouts',4000,2)):
            self.assertEqual(self.row(name)['returned'],(-102)&0xffffffff);self.assertEqual(self.row(name)['feature_reads'],n)
            self.assertEqual(self.actions(name).count('log:busy_timeout'),logs);self.assertEqual(self.actions(name)[-1],'log:copy_result')

    def test_program_failure_bit_rejects_both_copy_variants(self):
        for operation in ('copy_page','copy_oob'):
            self.assertEqual(self.row(operation+'_program_failed')['returned'],(-102)&0xffffffff)

    def test_same_source_destination_is_not_rejected_by_copy_policy(self):
        name='copy_same_source_dest';self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(self.addresses(name),[792,192,0,792,192])

    def test_lower_failures_stop_at_original_bus_assertions(self):
        cases={'erase_enable_assertion':0x11f,'erase_command_assertion':0x11f,'erase_status_assertion':0x12a,
            'copy_page_load_assertion':0x11f,'copy_page_status_assertion':0x12a,
            'copy_oob_load_assertion':0x11f,'copy_oob_status_assertion':0x12a,'copy_oob_fifo_assertion':0x132}
        for name,line in cases.items():
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=line))
            self.assertFalse(any(a in ('log:copy_result','log:erase_result') for a in self.actions(name)))
        self.assertNotIn(0x10,self.opcodes('copy_oob_fifo_assertion'))

    def test_deferred_init_occurs_after_all_required_remapping(self):
        for operation in ('erase','copy_page','copy_oob'):
            name=operation+'_deferred_init';actions=self.actions(name)
            clock=next(i for i,a in enumerate(actions) if a.startswith('clock_read:'))
            self.assertTrue(all(i<clock for i,a in enumerate(actions) if a.startswith('native_remap_')))
            self.assertEqual(self.row(name)['reinit_flag'],0);self.assertEqual(self.row(name)['returned'],0)

    def test_contract_rejects_unbounded_or_unbacked_inputs(self):
        base=self.cases['copy_oob_ready']
        for change in (dict(count=66),dict(buffer=False),dict(responses=[]),dict(responses=[256]),dict(responses=[0]*4001),dict(bbt_hex='00'),dict(operation='read')):
            with self.assertRaises(ValueError):contract(base|change)

    def test_committed_native_evidence_matches_all_regenerated_fixtures(self):
        execution=json.loads(Path('analysis/nand-maintenance-stack.json').read_bytes())['native_validation']
        self.assertIs(execution['hardware_execution'],False);self.assertEqual(execution['bound_per_case'],BOUND)
        self.assertEqual(execution['case_count'],len(self.cases));self.assertEqual(len(execution['cases']),len(self.cases))
        for case in execution['cases']:
            self.assertEqual(case['observed'],self.cases[case['name']]['expected']);self.assertTrue(0<case['steps']<=BOUND)


if __name__=='__main__':unittest.main()
