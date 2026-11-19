import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_nand_bbt_read as io


class MainNandBbtReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={s:{c['name'].removeprefix('main_bbt_io_'):c for c in io.native_vectors(s)['cases']} for s in ('records','markers')}
    def case(self,name):return self.cases['records'][name] if name in self.cases['records'] else self.cases['markers'][name]
    def row(self,name):return self.case(name)['expected']['rows'][0]
    def actions(self,name):return self.case(name)['expected']['actions']
    def record(self,bad):return io.recovery.policy.record(dict(bad=bad))
    def geometry(self,name):return struct.unpack_from('<6I',bytes.fromhex(self.row(name)['bbt_state_hex']),140)

    def test_primary_record_reaches_fifo_before_crc_and_publication(self):
        r=self.row('primary');self.assertEqual((r['returned'],r['bbt_reads'],r['io_page_calls'],r['io_cache_bytes']),(0,1,1,140))
        self.assertEqual(bytes.fromhex(r['io_last_fifo_hex']),self.record([1,3,7]));a=self.actions('primary')
        self.assertLess(a.index('probe_packet:107:0:140:0'),a.index('bbt_publish:140'))

    def test_record_read_executes_remap_load_status_and_direct_cache(self):
        a=self.actions('primary');chain=['bbt_record_read_native:65472:0','main_recovery_page_native:65472:0:140','main_remap_page:65472','probe_packet:19:65472:0:1','probe_packet:15:192:1:0','probe_packet:107:0:140:0','recovery_read_return:0']
        for x,y in zip(chain,chain[1:]):self.assertLess(a.index(x),a.index(y,a.index(x)))
        self.assertEqual(self.row('primary')['io_marker_calls'],0)

    def test_crc_covers_entry_bytes_from_delivered_record(self):
        data=struct.pack('<3H',1,3,7);self.assertIn('bbt_crc:6:'+hashlib.sha256(data).hexdigest(),self.actions('primary'))
        self.assertEqual(bytes.fromhex(self.row('primary')['bbt_state_hex'])[:140],self.record([1,3,7]))

    def test_empty_and_missing_records_follow_actual_crc_or_no_table_paths(self):
        self.assertIn('bbt_crc:0:'+hashlib.sha256(b'').hexdigest(),self.actions('empty'))
        r=self.row('no_records');self.assertEqual((r['returned'],r['bbt_resume_return'],r['bbt_reads'],r['io_cache_bytes']),(0,1,2,280))
        self.assertEqual(r['main_bbt_magic'],0);self.assertTrue(r['main_heap_live'])

    def test_backup_reread_uses_transport_and_exact_repair_payload(self):
        r=self.row('backup_repair');self.assertEqual((r['bbt_reads'],r['io_page_calls'],r['io_cache_bytes']),(3,3,420))
        digest=hashlib.sha256(self.record([1,3,7])).hexdigest()
        self.assertIn('bbt_write:65472:140:0:'+digest+':0',self.actions('backup_repair'))
        self.assertEqual(r['main_bbt_magic'],io.recovery.policy.MAGIC)

    def test_reread_ecc_delivers_bytes_then_skips_repair_and_restores_magic(self):
        r=self.row('reread_ecc');a=self.actions('reread_ecc');self.assertEqual((r['bbt_resume_return'],r['io_cache_bytes']),(0,420))
        self.assertIn('recovery_read_return:-101',a);self.assertIn('log:bbt_repair_failed',a)
        self.assertFalse(any(x.startswith(('bbt_erase:','bbt_write:')) for x in a));self.assertEqual(r['main_bbt_magic'],io.recovery.policy.MAGIC)

    def test_primary_ecc_skips_verification_and_falls_back_to_backup(self):
        a=self.actions('primary_ecc');self.assertEqual(a.count('log:bbt_record'),1);self.assertEqual(self.row('primary_ecc')['bbt_reads'],3)
        self.assertIn('main_page_retry:65472',a);self.assertEqual(self.row('primary_ecc')['bbt_resume_return'],0)

    def test_supplied_erase_and_write_failures_preserve_active_ram_table(self):
        for name in ('erase_error','write_error'):
            r=self.row(name);self.assertEqual((r['returned'],r['bbt_resume_return'],r['main_bbt_magic']),(0,0,io.recovery.policy.MAGIC))
            self.assertIn('log:bbt_repair_failed',self.actions(name));self.assertEqual(r['io_cache_bytes'],420)

    def test_busy_then_ready_uses_two_actual_status_reads(self):
        r=self.row('busy_ready');self.assertEqual((r['io_status_reads'],r['aux_status_reads']),(2,3))
        self.assertEqual(r['full_rx_bytes'],self.row('primary')['full_rx_bytes']+1)

    def test_bad_crc_fails_after_cache_delivery_without_publication(self):
        r=self.row('bad_crc');a=self.actions('bad_crc');self.assertIn('log:bbt_crc_error',a)
        self.assertNotIn('bbt_publish:140',a);self.assertEqual((r['bbt_resume_return'],r['main_bbt_magic'],r['io_cache_bytes']),(1,0,280))

    def test_load_timeout_stops_recovery_before_status_or_fifo_data(self):
        r=self.row('load_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294))
        self.assertIsNone(r['bbt_resume_return']);self.assertFalse(r['main_heap_live']);self.assertEqual((r['io_status_reads'],r['io_cache_bytes']),(0,0))

    def test_status_timeout_reaches_transport_assertion_without_read_return(self):
        r=self.row('status_timeout');self.assertEqual(r['stopped']['line'],305);self.assertEqual(r['io_status_reads'],0)
        self.assertNotIn('recovery_read_return:0',self.actions('status_timeout'));self.assertEqual(r['io_last_fifo_hex'],'')

    def test_cache_readiness_timeout_has_no_delivered_record_bytes(self):
        r=self.row('cache_ready_timeout');self.assertEqual(r['stopped']['line'],305)
        self.assertEqual((r['bbt_reads'],r['io_cache_packets'],r['io_status_reads'],r['io_cache_bytes']),(1,1,1,0));self.assertEqual(r['io_last_fifo_hex'],'')

    def test_cache_completion_timeout_keeps_full_delivery_without_crc_publication(self):
        r=self.row('cache_done_timeout');self.assertEqual(r['stopped']['line'],305);self.assertEqual(r['io_cache_bytes'],140)
        self.assertEqual(bytes.fromhex(r['io_last_fifo_hex']),self.record([1,3,7]));self.assertEqual(r['main_bbt_magic'],0)
        self.assertNotIn('bbt_publish:140',self.actions('cache_done_timeout'))

    def test_actual_markers_read_three_pages_of_each_good_tail_block(self):
        r=self.row('markers_primary');self.assertEqual((r['io_marker_calls'],r['io_page_calls'],r['io_cache_bytes']),(2,7,152))
        a=self.actions('markers_primary')
        for address in (65472,65473,65474,65408,65409,65410):self.assertIn(f'main_recovery_page_native:{address}:2048:2',a)
        self.assertFalse(any(x.startswith('bbt_bad_check:') for x in a))

    def test_late_marker_failures_skip_initial_block_after_partial_page_scan(self):
        self.assertEqual((self.row('third_marker_bad')['io_page_calls'],self.row('second_marker_bad')['io_page_calls']),(13,11))
        for name in ('third_marker_bad','second_marker_bad'):
            self.assertEqual(self.geometry(name)[-2:],(1022,1021));self.assertIn('main_marker_return:103',self.actions(name))

    def test_marker_ecc_propagates_read_error_to_tail_selection(self):
        r=self.row('marker_ecc');a=self.actions('marker_ecc');self.assertIn('log:main_marker_error:-101',a)
        self.assertIn('main_marker_return:-101',a);self.assertEqual(self.geometry('marker_ecc')[-2:],(0,1023))
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30e6c,line=196));self.assertEqual(r['io_page_calls'],4)
        repeated=self.row('marker_ecc_repeat');self.assertEqual(self.geometry('marker_ecc_repeat')[-2:],(1022,1021));self.assertEqual(repeated['returned'],0)

    def test_markers_and_backup_record_transport_share_recovery(self):
        r=self.row('markers_backup');self.assertEqual((r['io_page_calls'],r['bbt_reads'],r['io_cache_bytes']),(9,3,432))
        r=self.row('markers_no_records');self.assertEqual((r['io_page_calls'],r['bbt_resume_return'],r['main_bbt_magic']),(8,1,0))

    def test_last_reserved_pair_executes_complete_selected_tail_scan(self):
        r=self.row('markers_last_pair');self.assertEqual((r['io_marker_calls'],r['io_page_calls'],r['io_cache_bytes']),(30,35,208))
        self.assertEqual(self.geometry('markers_last_pair')[-2:],(1009,1008));self.assertEqual(r['returned'],0)

    def test_no_good_and_one_good_stop_before_record_read_or_publication(self):
        for name in ('markers_no_good','markers_one_good'):
            r=self.row(name);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30e6c,line=196))
            self.assertEqual(r['bbt_reads'],0);self.assertFalse(r['main_heap_live']);self.assertEqual(r['export_calls'],0)
        self.assertEqual(self.row('markers_no_good')['io_page_calls'],32);self.assertEqual(self.row('markers_one_good')['io_page_calls'],18)

    def test_marker_load_timeout_has_no_cache_delivery(self):
        r=self.row('marker_load_timeout');self.assertEqual(r['stopped']['line'],294)
        self.assertEqual((r['io_marker_calls'],r['io_page_calls'],r['io_cache_bytes']),(1,1,0));self.assertEqual(r['bbt_reads'],0)

    def test_marker_completion_timeout_keeps_bytes_before_marker_decision(self):
        r=self.row('marker_cache_done_timeout');self.assertEqual(r['stopped']['line'],305);self.assertEqual(r['io_last_fifo_hex'],'ffff')
        self.assertNotIn('main_marker_return:0',self.actions('marker_cache_done_timeout'));self.assertEqual(r['bbt_reads'],0)

    def test_record_timeout_after_markers_retains_prior_marker_work(self):
        r=self.row('record_after_markers_timeout');self.assertEqual((r['io_page_calls'],r['io_marker_calls'],r['bbt_reads'],r['io_cache_bytes']),(7,2,1,12))
        self.assertEqual(r['stopped']['line'],305);self.assertEqual(r['io_last_fifo_hex'],'');self.assertEqual(r['main_bbt_magic'],0)

    def test_scope_and_status_limits_exclude_fake_read_returns(self):
        c=self.case('primary')
        for change in (dict(native_main_bbt_read=False),dict(bbt_reread_status=-9),dict(recovery_statuses=[1]),dict(recovery_fault_read=1),dict(recovery_ready_fail_at=4),dict(marker_bad_pages={'1023':[2]})):
            with self.subTest(change=change),self.assertRaises(ValueError):io.contract(c|change,'records')
        bad=copy.deepcopy(c);bad['bbt_records']['1023']['read_status']=-9
        with self.assertRaises(ValueError):io.contract(bad,'records')

    def test_contract_preserves_original_records_magic_and_operations(self):
        for scope,name in (('records','reread_ecc'),('markers','markers_no_good')):
            c=self.cases[scope][name];before=copy.deepcopy(c);io.contract(c,scope);self.assertEqual(c,before)

    def test_native_evidence_matches_policy_and_original_main_guard_hashes(self):
        text=Path('analysis_scripts/ValidateMainNandBbtRead.java').read_text();cfg=json.loads(json.loads(re.search(r'IO_CONFIG=(".*?");',text).group(1)))
        old=json.loads(Path('analysis/main-nand-page-read.json').read_bytes())
        for scope,stem in (('records','main-nand-bbt-record-read'),('markers','main-nand-bbt-marker-read')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False)
            self.assertEqual(e['scope'],scope);self.assertEqual((r['case_count'],len(r['cases'])),(len(self.cases[scope]),len(self.cases[scope])))
            self.assertEqual(r['bound_per_case'],io.BOUND)
            for row in r['cases']:
                self.assertEqual(row['observed'],self.cases[scope][row['name'].removeprefix('main_bbt_io_')]['expected']);self.assertTrue(0<row['steps']<=io.BOUND)
            self.assertTrue(old['byte_range_sha256'].items()<=e['byte_range_sha256'].items());self.assertEqual(old['data_range_sha256'],e['data_range_sha256'])
            for g in cfg['guards']:self.assertEqual(e['byte_range_sha256'][f'{g["address"]:08x}_{g["size"]:x}'],g['sha256'])
            self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(63,67))

    def test_fifo_work_does_not_modify_uid_source_or_dma_initialization(self):
        expected=hashlib.sha256(io.aux.policy.uid_bytes(0,True)+b'\xa5'*96).hexdigest()
        for cases in self.cases.values():
            for c in cases.values():
                rows=c['expected']['rows'];self.assertTrue(all(r['aux_uid_sha256']==expected and r['aux_uid_length']==16 for r in rows))
                self.assertTrue(all(r['full_dma_contexts_hex']==rows[0]['full_dma_contexts_hex'] for r in rows))

    def test_both_scopes_keep_peripheral_trace_bounded_and_report_authored_execution(self):
        for cases in self.cases.values():
            for c in cases.values():
                r=c['expected']['rows'][0];self.assertLess(r['full_rx_bytes'],1024);self.assertLessEqual(r['io_page_calls'],100)
                self.assertEqual(r['io_cache_packets'],r['io_page_calls']-(1 if c['recovery_done_fail_at']==1 or c['recovery_ready_fail_at']==2 else 0))


if __name__=='__main__':unittest.main()
