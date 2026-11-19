import copy
import json
from pathlib import Path
import re
import unittest

from analysis_scripts import main_nand_page_read as page


class MainNandPageReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name'].removeprefix('main_page_read_'):c for c in page.native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][-1]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def buffer(self,name):return bytes.fromhex(self.row(name)['page_buffer_hex'])

    def test_read_uses_recovered_mapping_before_page_load(self):
        r=self.row('mapped');self.assertEqual((r['returned'],r['page_loaded']),(0,129))
        a=self.actions('mapped');self.assertLess(a.index('main_remap_page:65'),a.index('probe_packet:19:129:0:1'))

    def test_direct_x4_payload_reaches_original_output_buffer(self):
        self.assertEqual(self.buffer('mapped'),page.payload(129,16,32)+b'\xa5'*96)
        self.assertIn('probe_packet:107:16:32:0',self.actions('mapped'))

    def test_byte_word_tail_and_full_backing_respect_requested_length(self):
        for name,n in (('one_byte',1),('word_tail',13),('max_backing',128)):
            self.assertEqual(self.buffer(name),page.payload(129,16,n)+b'\xa5'*(128-n));self.assertEqual(self.row(name)['returned'],0)

    def test_last_usable_page_reaches_mapped_physical_page(self):
        self.assertEqual((self.row('last_usable')['returned'],self.row('last_usable')['page_loaded']),(0,65407))

    def test_reserved_limit_returns_minus_150_before_any_page_io(self):
        r=self.row('reserved_limit');self.assertEqual((r['returned'],r['page_cache_packets'],r['page_status_reads']),((-150)&0xffffffff,0,0))
        self.assertEqual(self.buffer('reserved_limit'),b'\xa5'*128);self.assertNotIn('log:main_page_result:-150',self.actions('reserved_limit'))

    def test_large_page_is_rejected_by_mapping(self):
        self.assertEqual(self.row('wrap_page')['returned'],(-150)&0xffffffff);self.assertEqual(self.row('wrap_page')['page_loaded'],0)

    def test_inactive_bbt_read_passes_original_page_to_load(self):
        r=self.row('inactive_bbt');self.assertEqual((r['returned'],r['page_loaded'],r['main_bbt_magic']),(0,65,0))
        self.assertEqual(self.buffer('inactive_bbt')[:32],page.payload(65,16,32))

    def test_malformed_accepted_lists_change_physical_data_source(self):
        self.assertEqual(self.row('unsorted')['page_loaded'],65);self.assertEqual(self.row('duplicates')['page_loaded'],193)
        self.assertEqual(self.buffer('unsorted')[:32],page.payload(65,16,32));self.assertEqual(self.buffer('duplicates')[:32],page.payload(193,16,32))

    def test_repair_error_does_not_prevent_read_via_active_ram_table(self):
        r=self.row('repair_error');self.assertEqual((r['returned'],r['bbt_resume_return'],r['page_loaded']),(0,0,129))
        self.assertIn('log:bbt_repair_failed',self.actions('repair_error'))

    def test_ecc_error_runs_original_unsupported_retry_then_still_reads_cache(self):
        r=self.row('ecc_reject');self.assertEqual((r['returned'],r['page_cache_packets']),((-101)&0xffffffff,1))
        self.assertEqual(self.buffer('ecc_reject')[:32],page.payload(129,16,32));a=self.actions('ecc_reject')
        self.assertLess(a.index('main_page_retry:129'),a.index('probe_packet:107:16:32:0'))

    def test_busy_then_ready_polls_actual_feature_fifo_twice(self):
        r=self.row('busy_then_ready');self.assertEqual((r['returned'],r['page_status_reads']),(0,2))
        self.assertEqual(r['aux_status_reads'],3)

    def test_zero_length_and_null_buffer_reject_before_load(self):
        for name in ('zero_length','null_buffer'):
            r=self.row(name);self.assertEqual((r['returned'],r['page_loaded'],r['page_cache_packets']),(0xffffffff,0,0))
            self.assertEqual(self.buffer(name),b'\xa5'*128)

    def test_exact_page_plus_oob_end_is_accepted(self):
        self.assertEqual(self.row('exact_end')['returned'],0)
        self.assertEqual(self.buffer('exact_end')[:32],page.payload(129,2080,32))

    def test_one_byte_past_end_is_rejected(self):
        self.assertEqual(self.row('past_end')['returned'],0xffffffff);self.assertEqual(self.row('past_end')['page_loaded'],0)

    def test_wrapping_column_sum_passes_original_unsigned_check(self):
        r=self.row('wrapping_column');self.assertEqual((r['returned'],r['page_cache_packets']),(0,1))
        self.assertEqual(self.buffer('wrapping_column')[:16],page.payload(129,0xfffffff8,16))

    def test_load_timeout_stops_before_status_and_cache(self):
        r=self.row('load_done_timeout');self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294))
        self.assertEqual((r['page_loaded'],r['page_status_reads'],r['page_cache_packets']),(129,0,0))

    def test_status_read_timeout_keeps_uid_status_and_buffer_unchanged(self):
        r=self.row('status_ready_timeout');self.assertEqual(r['stopped']['line'],305);self.assertEqual((r['page_status_reads'],r['aux_status_reads']),(0,1))
        self.assertEqual(self.buffer('status_ready_timeout'),b'\xa5'*128)

    def test_cache_readiness_timeout_delivers_no_payload(self):
        r=self.row('cache_ready_timeout');self.assertEqual(r['stopped']['line'],305);self.assertEqual(r['page_cache_packets'],1)
        self.assertEqual(self.buffer('cache_ready_timeout'),b'\xa5'*128)

    def test_cache_completion_timeout_retains_already_delivered_payload(self):
        r=self.row('cache_done_timeout');self.assertIsNone(r['returned']);self.assertEqual(r['stopped']['line'],305)
        self.assertEqual(self.buffer('cache_done_timeout')[:32],page.payload(129,16,32))

    def test_per_operation_snapshots_keep_pre_read_counters_and_buffer(self):
        rows=self.cases['mapped']['expected']['rows'];self.assertEqual(rows[0]['page_buffer_hex'],'a5'*128)
        self.assertEqual(rows[0]['aux_status_reads'],1);self.assertEqual(rows[-1]['aux_status_reads'],2)
        self.assertEqual(rows[-1]['full_rx_bytes']-rows[0]['full_rx_bytes'],33)

    def test_repeated_reads_capture_each_intermediate_payload(self):
        rows=self.cases['repeated']['expected']['rows'];first,last=rows[-2:]
        self.assertEqual(bytes.fromhex(first['page_buffer_hex'])[:32],page.payload(129,16,32))
        self.assertEqual(bytes.fromhex(last['page_buffer_hex'])[:32],page.payload(321,2080,32))
        self.assertEqual((first['page_calls'],last['page_calls']),(1,2));self.assertEqual(last['full_commands']-first['full_commands'],3)

    def test_reads_preserve_bbt_uid_source_and_dma_initialization_records(self):
        for c in self.cases.values():
            rows=c['expected']['rows'];first,last=rows[0],rows[-1]
            for key in ('bbt_state_hex','aux_uid_sha256','aux_uid_length','full_dma_contexts_hex','full_dma_registry','full_dma_mmio'):
                self.assertEqual(first[key],last[key])

    def test_contract_excludes_unbounded_busy_and_oversized_reads_without_mutation(self):
        c=self.cases['mapped'];before=copy.deepcopy(c)
        for change in (dict(native_main_page_read=False),dict(page_statuses=[1]),dict(page_statuses=[256]),dict(page_done_fail_at=21)):
            with self.subTest(change=change),self.assertRaises(ValueError):page.contract(c|change)
        bad=copy.deepcopy(c);bad['operations'][-1]['size']=129
        with self.assertRaises(ValueError):page.contract(bad)
        page.contract(c);self.assertEqual(c,before)

    def test_native_evidence_matches_policy_and_original_instruction_guards(self):
        e=json.loads(Path('analysis/main-nand-page-read.json').read_bytes());r=e['native_validation']
        self.assertIs(r['hardware_execution'],False);self.assertEqual(r['case_count'],23);self.assertEqual(len(r['cases']),23)
        for row in r['cases']:
            self.assertEqual(row['observed'],self.cases[row['name'].removeprefix('main_page_read_')]['expected']);self.assertTrue(0<row['steps']<=page.aux.joined.BOUND)
        previous=json.loads(Path('analysis/main-nand-bbt-mapping.json').read_bytes());self.assertTrue(previous['byte_range_sha256'].items()<=e['byte_range_sha256'].items());self.assertEqual(previous['data_range_sha256'],e['data_range_sha256'])
        text=Path('analysis_scripts/ValidateMainNandPageRead.java').read_text();cfg=json.loads(json.loads(re.search(r'PAGE_CONFIG=(".*?");',text).group(1)))
        for g in cfg['guards']:self.assertEqual(e['byte_range_sha256'][f'{g["address"]:08x}_{g["size"]:x}'],g['sha256'])
        self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(62,67))


if __name__=='__main__':unittest.main()
