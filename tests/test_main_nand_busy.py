import copy
import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts import main_nand_busy as busy


class MainNandBusyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={s:{c['name'].removeprefix('main_busy_'):c for c in busy.native_vectors(s)['cases']} for s in ('read','repair')}
    def case(self,name):return self.cases['read'][name] if name in self.cases['read'] else self.cases['repair'][name]
    def row(self,name):return self.case(name)['expected']['rows'][0]
    def windows(self,name):
        result=[]
        for action in self.case(name)['expected']['actions']:
            if action.startswith('busy_window:'):
                p=action.split(':');result.append(dict(kind=p[1],ordinal=int(p[2]),limit=int(p[3]),polls=int(p[4]),out=int(p[5]),returned=int(p[6]),events=int(p[7]),sha256=p[8]))
        return result
    def selected(self,name):
        c=self.case(name);return next(w for w in self.windows(name) if w['kind']==c['busy_stage'] and w['ordinal']==c['busy_call'])

    def test_trace_uses_exact_utf8_event_lines_and_count(self):
        trace=busy.Trace();trace.extend(['delay:5','r:256:1:0'])
        self.assertEqual(trace.count,2);self.assertEqual(trace.digest.hexdigest(),hashlib.sha256(b'delay:5\nr:256:1:0\n').hexdigest())

    def test_stream_chunk_boundaries_do_not_change_digest(self):
        one=busy.Trace();one.extend(['alpha','beta','gamma']);two=busy.Trace();two.append('alpha');two.extend(['beta']);two.append('gamma')
        self.assertEqual((one.count,one.digest.digest()),(two.count,two.digest.digest()))
        for bad in ('a\nb',42):
            with self.assertRaises(ValueError):one.append(bad)

    def test_exhausted_read_runs_all_polls_and_returns_zero_with_ff(self):
        w=self.selected('read_exhausted');self.assertEqual((w['limit'],w['polls'],w['out'],w['returned'],w['events']),(2000,2000,255,0,36001))

    def test_read_timeout_does_not_prevent_record_acceptance_or_registration(self):
        r=self.row('read_exhausted');self.assertEqual((r['returned'],r['bbt_resume_return'],r['main_bbt_magic']),(0,0,busy.repair.read.recovery.policy.MAGIC))
        self.assertTrue(r['main_heap_live']);self.assertEqual((r['io_status_reads'],r['io_cache_bytes']),(2006,152))

    def test_last_poll_ready_is_discarded_despite_different_fifo_trace(self):
        last=self.selected('read_ready_at_limit');exhausted=self.selected('read_exhausted')
        self.assertEqual((last['polls'],last['out'],last['returned']),(2000,255,0));self.assertNotEqual(last['sha256'],exhausted['sha256'])
        self.assertEqual(self.row('read_ready_at_limit')['main_bbt_magic'],self.row('read_exhausted')['main_bbt_magic'])

    def test_penultimate_ready_is_published_and_avoids_timeout_event(self):
        w=self.selected('read_ready_before_limit');self.assertEqual((w['polls'],w['out'],w['events']),(1999,0,35982))
        self.assertEqual(self.row('read_ready_before_limit')['returned'],0)

    def test_ecc_on_final_poll_is_discarded_and_record_still_accepted(self):
        w=self.selected('read_ecc_at_limit');r=self.row('read_ecc_at_limit');self.assertEqual((w['polls'],w['out']),(2000,255))
        self.assertEqual(r['main_bbt_magic'],busy.repair.read.recovery.policy.MAGIC)
        self.assertNotIn('main_page_retry:65472',self.case('read_ecc_at_limit')['expected']['actions'])

    def test_ecc_on_penultimate_poll_triggers_retry_and_record_rejection(self):
        w=self.selected('read_ecc_before_limit');r=self.row('read_ecc_before_limit');self.assertEqual((w['polls'],w['out']),(1999,32))
        self.assertIn('main_page_retry:65472',self.case('read_ecc_before_limit')['expected']['actions'])
        self.assertEqual((r['returned'],r['bbt_resume_return'],r['main_bbt_magic']),(0,1,0))

    def test_erase_exhaustion_runs_all_4000_polls_and_skips_program(self):
        w=self.selected('erase_exhausted');r=self.row('erase_exhausted')
        self.assertEqual((w['limit'],w['polls'],w['out'],w['events']),(4000,4000,255,72001))
        self.assertEqual((r['repair_erase_return'],r['repair_program_calls']),((-104)&0xffffffff,0))

    def test_late_erase_ready_still_produces_minus_104(self):
        self.assertEqual(self.selected('erase_ready_at_limit')['out'],255)
        self.assertEqual(self.row('erase_ready_at_limit')['repair_erase_return'],(-104)&0xffffffff)
        self.assertNotEqual(self.selected('erase_ready_at_limit')['sha256'],self.selected('erase_exhausted')['sha256'])

    def test_erase_ready_before_limit_allows_exact_program_payload(self):
        w=self.selected('erase_ready_before_limit');r=self.row('erase_ready_before_limit')
        self.assertEqual((w['polls'],w['out'],r['repair_erase_return'],r['repair_program_return']),(3999,0,0,0))
        self.assertEqual(bytes.fromhex(r['repair_tx_hex']),busy.repair.read.recovery.policy.record(dict(bad=[1,3,7])))

    def test_program_exhaustion_has_full_tx_before_minus_102(self):
        w=self.selected('program_exhausted');r=self.row('program_exhausted')
        self.assertEqual((w['polls'],w['out'],r['repair_program_return']),(2000,255,(-102)&0xffffffff))
        self.assertEqual(len(bytes.fromhex(r['repair_tx_hex'])),140)

    def test_last_program_ready_is_ignored_by_original_check_order(self):
        w=self.selected('program_ready_at_limit');self.assertEqual((w['polls'],w['out']),(2000,255))
        self.assertEqual(self.row('program_ready_at_limit')['repair_program_return'],(-102)&0xffffffff)
        self.assertNotEqual(w['sha256'],self.selected('program_exhausted')['sha256'])

    def test_program_ready_before_limit_returns_zero(self):
        w=self.selected('program_ready_before_limit');r=self.row('program_ready_before_limit')
        self.assertEqual((w['polls'],w['out'],r['repair_program_return']),(1999,0,0))

    def test_handled_repair_timeouts_still_publish_active_table(self):
        for name in ('erase_exhausted','erase_ready_at_limit','program_exhausted','program_ready_at_limit'):
            r=self.row(name);self.assertEqual((r['returned'],r['bbt_resume_return'],r['main_bbt_magic']),(0,0,busy.repair.read.recovery.policy.MAGIC))
            self.assertIsNone(r['stopped']);self.assertTrue(r['main_heap_live'])

    def test_non_target_uid_marker_and_repair_windows_remain_one_poll(self):
        for cases in self.cases.values():
            for c in cases.values():
                name=c['name'].removeprefix('main_busy_')
                for w in self.windows(name):
                    if (w['kind'],w['ordinal'])==(c['busy_stage'],c['busy_call']):continue
                    self.assertEqual((w['polls'],w['out'],w['returned'],w['events']),(1,0,0,18))

    def test_aggregate_fifo_work_exceeds_old_guard_within_new_bound(self):
        self.assertGreater(self.row('erase_exhausted')['full_rx_bytes'],4000)
        for cases in self.cases.values():
            for c in cases.values():self.assertLess(c['expected']['rows'][0]['full_rx_bytes'],busy.FIFO_BOUND)

    def test_all_windows_have_canonical_digest_and_bounded_poll_counts(self):
        for cases in self.cases.values():
            for c in cases.values():
                for w in self.windows(c['name'].removeprefix('main_busy_')):
                    self.assertRegex(w['sha256'],r'^[0-9a-f]{64}$');self.assertTrue(0<w['polls']<=w['limit']);self.assertEqual(w['returned'],0)
                    self.assertEqual(w['events'],18*w['polls']+int(w['polls']==w['limit']))

    def test_busy_status_exhaustion_does_not_invent_transport_assertions(self):
        for cases in self.cases.values():
            for c in cases.values():self.assertTrue(all(r['stopped'] is None for r in c['expected']['rows']))

    def test_contract_rejects_wrong_stage_call_and_boundary_inputs(self):
        c=self.case('read_exhausted')
        for change in (dict(native_main_busy=False),dict(busy_stage='erase'),dict(busy_call=6),dict(busy_ready_at=2001),dict(busy_final_status=255),dict(recovery_fault_read=1),dict(repair_fault_phase='program')):
            with self.subTest(change=change),self.assertRaises(ValueError):busy.contract(c|change,'read')

    def test_contract_keeps_fixture_records_and_operations_unchanged(self):
        c=self.case('read_ecc_before_limit');before=copy.deepcopy(c);busy.contract(c,'read');self.assertEqual(c,before)

    def test_native_evidence_matches_counted_full_trace_models(self):
        for scope,stem in (('read','main-nand-busy-read'),('repair','main-nand-busy-repair')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False)
            self.assertEqual((r['case_count'],len(r['cases'])),(len(self.cases[scope]),len(self.cases[scope])));self.assertEqual(r['bound_per_case'],busy.BOUND)
            for row in r['cases']:
                self.assertEqual(row['observed'],self.cases[scope][row['name'].removeprefix('main_busy_')]['expected']);self.assertTrue(200000<row['steps']<=busy.BOUND)

    def test_original_code_data_and_exports_are_unchanged_from_repair_scope(self):
        previous=json.loads(Path('analysis/main-nand-bbt-program.json').read_bytes())
        for stem in ('main-nand-busy-read','main-nand-busy-repair'):
            e=json.loads(Path('analysis',stem+'.json').read_bytes())
            for key in ('byte_range_sha256','data_range_sha256','export_sha256'):self.assertEqual(e[key],previous[key])
            self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(69,67))

    def test_uid_source_and_dma_contexts_remain_intact(self):
        expected=hashlib.sha256(busy.repair.read.aux.policy.uid_bytes(0,True)+b'\xa5'*96).hexdigest()
        old=json.loads(Path('analysis/main-nand-bbt-program.json').read_bytes());baseline=old['native_validation']['cases'][0]['observed']['rows'][0]
        for cases in self.cases.values():
            for c in cases.values():
                r=c['expected']['rows'][0];self.assertEqual((r['aux_uid_length'],r['aux_uid_sha256']),(16,expected))
                for key in ('full_dma_contexts_hex','full_dma_registry','full_dma_mmio'):self.assertEqual(r[key],baseline[key])


if __name__=='__main__':unittest.main()
