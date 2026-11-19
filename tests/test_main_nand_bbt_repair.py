import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

from analysis_scripts import main_nand_bbt_repair as repair


class MainNandBbtRepairTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={s:{c['name'].removeprefix('main_bbt_repair_'):c for c in repair.native_vectors(s)['cases']} for s in ('erase','program')}
    def case(self,name):return self.cases['erase'][name] if name in self.cases['erase'] else self.cases['program'][name]
    def row(self,name):return self.case(name)['expected']['rows'][0]
    def actions(self,name):return self.case(name)['expected']['actions']
    def payload(self):return repair.read.recovery.policy.record(dict(bad=[1,3,7]))

    def test_original_erase_uses_primary_block_with_inactive_magic(self):
        r=self.row('erase_ready');self.assertEqual((r['returned'],r['repair_erase_calls'],r['repair_erase_return']),(0,1,0))
        a=self.actions('erase_ready');start=a.index('main_repair_erase_native:1023:0')
        chain=['main_remap_block:1023','probe_packet:6:0:0:1','probe_packet:216:65472:0:1','probe_packet:15:192:1:0','main_repair_erase_return:0']
        for item in chain:start=a.index(item,start)+1
        self.assertEqual(r['main_bbt_magic'],repair.read.recovery.policy.MAGIC)

    def test_erase_failure_returns_minus_104_but_recovery_still_returns_zero(self):
        r=self.row('erase_failed');self.assertEqual((r['returned'],r['bbt_resume_return'],r['repair_erase_return']),(0,0,(-104)&0xffffffff))
        self.assertIn('log:main_repair_erase_result:-104',self.actions('erase_failed'));self.assertIn('log:bbt_repair_failed',self.actions('erase_failed'))
        self.assertFalse(any(x.startswith('bbt_write:') for x in self.actions('erase_failed')))

    def test_erase_busy_then_ready_uses_two_actual_status_packets(self):
        r=self.row('erase_busy_ready');self.assertEqual((r['repair_erase_status_reads'],r['repair_erase_return']),(2,0))
        self.assertEqual(r['full_commands'],self.row('erase_ready')['full_commands']+1)

    def test_erase_ignores_status_bits_outside_original_failure_mask(self):
        self.assertEqual(self.row('erase_other_bits')['repair_erase_return'],0)
        self.assertNotIn('log:main_repair_erase_result:-104',self.actions('erase_other_bits'))

    def test_erase_scope_preserves_supplied_program_boundary(self):
        r=self.row('supplied_write_failed');self.assertEqual((r['repair_erase_return'],r['repair_program_calls'],r['repair_tx_hex']),(0,0,''))
        self.assertIn('log:bbt_repair_failed',self.actions('supplied_write_failed'))
        self.assertTrue(any(x.startswith('bbt_write:') and x.endswith(':-9') for x in self.actions('supplied_write_failed')))
        self.assertEqual(r['main_bbt_magic'],repair.read.recovery.policy.MAGIC)

    def test_accepted_primary_skips_erase_and_supplied_write(self):
        r=self.row('primary_no_repair');self.assertEqual((r['repair_erase_calls'],r['repair_program_calls']),(0,0))
        self.assertFalse(any(x.startswith(('main_repair_erase_native:','bbt_write:')) for x in self.actions('primary_no_repair')))

    def test_no_table_skips_repair_and_still_registers_inactive_geometry(self):
        r=self.row('no_table_no_repair');self.assertEqual((r['returned'],r['bbt_resume_return'],r['repair_erase_calls'],r['main_bbt_magic']),(0,1,0,0))
        self.assertTrue(r['main_heap_live'])

    def test_erase_enable_timeout_preserves_cleared_magic_and_stops_before_erase_command(self):
        r=self.row('erase_enable_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294))
        self.assertIsNone(r['repair_erase_return']);self.assertEqual(r['main_bbt_magic'],0);self.assertFalse(r['main_heap_live'])
        self.assertNotIn('probe_packet:216:65472:0:1',self.actions('erase_enable_timeout'))

    def test_erase_command_timeout_stops_before_status(self):
        r=self.row('erase_command_timeout');self.assertEqual(r['stopped']['line'],294)
        self.assertEqual(r['repair_erase_status_reads'],0);self.assertIsNone(r['bbt_resume_return'])

    def test_erase_status_readiness_timeout_has_no_completed_status_read(self):
        r=self.row('erase_status_ready_timeout');self.assertEqual(r['stopped']['line'],305)
        self.assertEqual(r['repair_erase_status_reads'],0);self.assertIsNone(r['repair_erase_return'])

    def test_erase_status_completion_timeout_keeps_read_count_without_normal_return(self):
        r=self.row('erase_status_done_timeout');self.assertEqual(r['stopped']['line'],305)
        self.assertEqual(r['repair_erase_status_reads'],1);self.assertIsNone(r['repair_erase_return']);self.assertEqual(r['main_bbt_magic'],0)

    def test_program_transmits_exact_backup_record_after_original_erase(self):
        r=self.row('program_ready');self.assertEqual((r['repair_erase_return'],r['repair_program_return'],r['returned']),(0,0,0))
        self.assertEqual(bytes.fromhex(r['repair_tx_hex']),self.payload())
        self.assertTrue(bytes.fromhex(r['full_tx_hex']).endswith(self.payload()));self.assertEqual(r['main_bbt_magic'],repair.read.recovery.policy.MAGIC)

    def test_program_command_order_uses_untranslated_primary_tail_page(self):
        a=self.actions('program_ready');marker='main_repair_program_native:65472:140:0:'+hashlib.sha256(self.payload()).hexdigest();start=a.index(marker)
        for item in ('main_remap_page:65472','probe_packet:6:0:0:1','probe_packet:50:0:140:1','probe_packet:16:65472:0:1','probe_packet:15:192:1:0','main_repair_program_return:0'):start=a.index(item,start)+1
        self.assertNotIn('main_remap_block:1023',a[a.index(marker):])

    def test_program_failure_status_returns_minus_102_after_full_transmission(self):
        r=self.row('program_failed');self.assertEqual((r['returned'],r['repair_program_return']),(0,(-102)&0xffffffff))
        self.assertEqual(bytes.fromhex(r['repair_tx_hex']),self.payload());self.assertIn('log:main_repair_program_result:-102',self.actions('program_failed'))
        self.assertIn('log:bbt_repair_failed',self.actions('program_failed'));self.assertEqual(r['main_bbt_magic'],repair.read.recovery.policy.MAGIC)

    def test_program_busy_then_ready_uses_original_status_loop(self):
        r=self.row('program_busy_ready');self.assertEqual((r['repair_program_status_reads'],r['repair_program_return']),(2,0))
        self.assertEqual(r['full_commands'],self.row('program_ready')['full_commands']+1)

    def test_program_ignores_ecc_bits_outside_program_failure_mask(self):
        self.assertEqual(self.row('program_other_bits')['repair_program_return'],0)
        self.assertNotIn('log:main_repair_program_result:-102',self.actions('program_other_bits'))

    def test_program_is_skipped_after_actual_erase_failure(self):
        r=self.row('program_after_erase_failed');self.assertEqual((r['repair_erase_return'],r['repair_program_calls'],r['repair_tx_hex']),((-104)&0xffffffff,0,''))
        self.assertEqual(r['main_bbt_magic'],repair.read.recovery.policy.MAGIC);self.assertIn('log:bbt_repair_failed',self.actions('program_after_erase_failed'))

    def test_both_repair_loops_can_poll_busy_before_ready(self):
        r=self.row('program_both_busy');self.assertEqual((r['repair_erase_status_reads'],r['repair_program_status_reads']),(2,2))
        self.assertEqual(r['full_commands'],self.row('program_ready')['full_commands']+2)

    def test_valid_primary_avoids_entire_program_path(self):
        r=self.row('program_primary_no_repair');self.assertEqual((r['repair_erase_calls'],r['repair_program_calls'],r['repair_tx_hex']),(0,0,''))
        self.assertEqual(r['bbt_reads'],1)

    def test_program_enable_timeout_occurs_after_successful_erase(self):
        r=self.row('program_enable_timeout');self.assertEqual((r['repair_erase_return'],r['repair_program_calls'],r['repair_tx_hex']),(0,1,''))
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294));self.assertIsNone(r['repair_program_return']);self.assertEqual(r['main_bbt_magic'],0)

    def test_program_cache_readiness_timeout_delivers_no_bytes(self):
        r=self.row('program_cache_ready_timeout');self.assertEqual(r['stopped']['line'],313);self.assertEqual(r['repair_tx_hex'],'')
        self.assertNotIn('probe_packet:16:65472:0:1',self.actions('program_cache_ready_timeout'))

    def test_program_cache_completion_timeout_keeps_transmitted_payload(self):
        r=self.row('program_cache_done_timeout');self.assertEqual(r['stopped']['line'],313)
        self.assertEqual(bytes.fromhex(r['repair_tx_hex']),self.payload());self.assertNotIn('probe_packet:16:65472:0:1',self.actions('program_cache_done_timeout'))

    def test_program_execute_timeout_preserves_payload_but_skips_status(self):
        r=self.row('program_execute_timeout');self.assertEqual(r['stopped']['line'],294)
        self.assertEqual(bytes.fromhex(r['repair_tx_hex']),self.payload());self.assertEqual(r['repair_program_status_reads'],0)

    def test_program_status_readiness_timeout_has_no_completed_status(self):
        r=self.row('program_status_ready_timeout');self.assertEqual(r['stopped']['line'],305)
        self.assertEqual(r['repair_program_status_reads'],0);self.assertIsNone(r['repair_program_return']);self.assertEqual(r['main_bbt_magic'],0)

    def test_program_status_completion_timeout_keeps_read_count_without_publication(self):
        r=self.row('program_status_done_timeout');self.assertEqual(r['stopped']['line'],305)
        self.assertEqual(r['repair_program_status_reads'],1);self.assertIsNone(r['bbt_resume_return']);self.assertEqual(r['main_bbt_magic'],0)

    def test_native_evidence_matches_models_and_original_body_hashes(self):
        text=Path('analysis_scripts/ValidateMainNandBbtRepair.java').read_text();cfg=json.loads(json.loads(re.search(r'REPAIR_CONFIG=(".*?");',text).group(1)))
        previous=json.loads(Path('analysis/main-nand-bbt-marker-read.json').read_bytes())
        for scope,stem in (('erase','main-nand-bbt-erase'),('program','main-nand-bbt-program')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False)
            self.assertEqual(e['scope'],scope);self.assertEqual((r['case_count'],len(r['cases'])),(len(self.cases[scope]),len(self.cases[scope])))
            self.assertEqual(r['bound_per_case'],repair.read.BOUND)
            for row in r['cases']:
                self.assertEqual(row['observed'],self.cases[scope][row['name'].removeprefix('main_bbt_repair_')]['expected']);self.assertTrue(0<row['steps']<=repair.read.BOUND)
            self.assertTrue(previous['byte_range_sha256'].items()<=e['byte_range_sha256'].items());self.assertEqual(previous['data_range_sha256'],e['data_range_sha256'])
            for g in cfg['guards']:self.assertEqual(e['byte_range_sha256'][f'{g["address"]:08x}_{g["size"]:x}'],g['sha256'])
            self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(69,67))

    def test_contract_excludes_fake_native_statuses_and_busy_exhaustion(self):
        c=self.case('program_ready')
        for change in (dict(native_main_bbt_repair=False),dict(native_main_bbt_program=False),dict(bbt_erase_status=-9),dict(bbt_write_status=-9),dict(program_statuses=[1]),dict(erase_statuses=[256]),dict(repair_fault_phase='program'),dict(repair_ready_fail_at=9)):
            with self.subTest(change=change),self.assertRaises(ValueError):repair.contract(c|change,'program')
        with self.assertRaises(ValueError):repair.contract(self.case('erase_ready')|dict(repair_fault_phase='program',repair_done_fail_at=1),'erase')

    def test_repair_preserves_uid_source_and_dma_initialization_records(self):
        old=json.loads(Path('analysis/main-nand-bbt-marker-read.json').read_bytes())
        baseline=next(c['observed']['rows'][0] for c in old['native_validation']['cases'] if c['name']=='main_bbt_io_markers_backup')
        for cases in self.cases.values():
            for c in cases.values():
                r=c['expected']['rows'][0]
                for key in ('aux_uid_length','aux_uid_sha256','full_dma_contexts_hex','full_dma_registry','full_dma_mmio'):self.assertEqual(r[key],baseline[key])

    def test_returned_failure_and_transport_assertion_have_different_ram_magic(self):
        normal=self.row('program_failed');stopped=self.row('program_cache_done_timeout')
        self.assertEqual(normal['repair_tx_hex'],stopped['repair_tx_hex']);self.assertEqual(normal['main_bbt_magic'],repair.read.recovery.policy.MAGIC)
        self.assertEqual(stopped['main_bbt_magic'],0);self.assertIsNone(stopped['returned']);self.assertEqual(normal['returned'],0)

    def test_success_does_not_read_back_primary_or_fabricate_media_updates(self):
        c=self.case('program_ready');before=copy.deepcopy(c);result=repair.contract(c,'program');self.assertEqual(c,before)
        self.assertEqual(result['rows'][0]['bbt_reads'],3);self.assertEqual(result['rows'][0]['io_page_calls'],9)
        self.assertNotIn('1023',c['bbt_record_hex']);self.assertEqual(result['rows'][0]['returned'],0)


if __name__=='__main__':unittest.main()
