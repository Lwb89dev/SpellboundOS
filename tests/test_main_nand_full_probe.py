import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_nand_full_probe as full


class MainNandFullProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={scope:{c['name'].removeprefix('main_full_'):c for c in full.native_vectors(scope)['cases']} for scope in ('root','faults')}
    def case(self,n):return self.cases['root'][n] if n in self.cases['root'] else self.cases['faults'][n]
    def rows(self,n):return self.case(n)['expected']['rows']
    def row(self,n):return self.rows(n)[0]
    def actions(self,n):return self.case(n)['expected']['actions']
    def output(self,n):return bytes.fromhex(self.rows(n)[-1]['output_hex'])

    def test_all_eleven_original_descriptors_are_selected_through_fifo(self):
        for i,chip in enumerate(full.probe.facts()['chips']):
            r=self.row('chip_'+str(i));self.assertEqual((r['returned'],r['main_selected'],r['probe_id_reads'],r['probe_bus_calls']),(0,chip['address'],i+1,i+1))
            self.assertEqual(r['full_commands'],i+2+2*len(chip['features']))

    def test_actual_fifo_read_and_write_counts_follow_candidate_and_features(self):
        for i,chip in enumerate(full.probe.facts()['chips']):
            r=self.row('chip_'+str(i));self.assertEqual((r['full_reads'],r['full_writes']),(i+1+len(chip['features']),len(chip['features'])))
            self.assertEqual(r['full_rx_bytes'],5*(i+1)+len(chip['features']))
            self.assertEqual(bytes.fromhex(r['full_tx_hex']),bytes(value for reg,value in chip['features']))

    def test_original_adjacent_dma_records_are_published_by_each_probe_attempt(self):
        r=self.row('chip_10');self.assertEqual(r['full_dma_registry'][26:28],list(full.platform.DMA))
        c=bytes.fromhex(r['full_controller_hex']);self.assertEqual(struct.unpack_from('<II',c,32),full.platform.DMA)
        for raw in r['full_dma_contexts_hex']:
            b=bytes.fromhex(raw);self.assertEqual(len(b),68);self.assertEqual(struct.unpack_from('<I',b,44)[0],full.hal.CTRL)

    def test_clock_policy_runs_for_rejected_candidates_as_well_as_selected_chip(self):
        a=self.actions('chip_10');self.assertEqual(sum(x.startswith('clock_read:') for x in a),11)
        values=[int(x.split(':')[1]) for x in a if x.startswith('clock_write:')]
        self.assertEqual([(value>>12)&15 for value in values],[1,2,1,2])

    def test_each_attempt_runs_actual_platform_and_supplied_pin_boundaries(self):
        a=self.actions('chip_10');self.assertEqual(a.count('fence'),22)
        self.assertEqual(a.count('platform_pinmux:0'),11);self.assertEqual(a.count('platform_gpio:0'),11)
        self.assertTrue(any(x.startswith('dma_w:') for x in a));self.assertFalse(any(x.startswith('dma_init:') for x in a))

    def test_packets_reach_actual_registers_without_supplied_hal_result_calls(self):
        a=self.actions('chip_0');self.assertIn('probe_packet:159:0:5:0',a)
        self.assertTrue(any(x.startswith('r:256:4:') for x in a));self.assertTrue(any(x.startswith('w:256:1:') for x in a))
        self.assertFalse(any(x.startswith(('command:','receive_poll:','transmit_poll:')) for x in a))

    def test_all_selected_descriptors_drive_actual_registered_object_geometry(self):
        for i,chip in enumerate(full.probe.facts()['chips']):
            n='chip_'+str(i);out=self.output(n)
            self.assertEqual(struct.unpack_from('<I',out)[0],chip['id'][0]|chip['id'][1]<<8)
            self.assertEqual(struct.unpack_from('<I',out,8)[0],chip['pages']*chip['page_size']);self.assertEqual(out[12],1)
            self.assertEqual(len(self.rows(n)),4)

    def test_probe_success_precedes_driver_mutex_registry_pm_and_consumer(self):
        a=self.actions('chip_0');chain=['main_probe_native','log:probe_guard','main_driver_mutex_create:'+str(full.probe.stack.HANDLE),
            'main_register_native','main_pm_register:0','native:open']
        for x,y in zip(chain,chain[1:]):self.assertLess(a.index(x),a.index(y))

    def test_close_drops_reference_count_while_retaining_registry_and_cache(self):
        r=self.rows('chip_0')[-1];self.assertEqual(struct.unpack_from('<I',bytes.fromhex(r['object_hex']),48)[0],0)
        self.assertEqual((r['main_cache'],r['main_head']),(full.base.OBJECT,full.base.OBJECT))

    def test_actual_registry_append_and_duplicate_preserve_distinct_publication(self):
        r=self.row('append');self.assertEqual(r['main_head'],full.probe.stack.SEED)
        self.assertEqual(struct.unpack_from('<I',bytes.fromhex(r['main_seed_hex']),52)[0],full.base.OBJECT)
        r=self.row('duplicate');self.assertEqual((r['returned'],r['main_cache'],r['main_pm_calls']),(0xfffffff5,0,0))
        self.assertTrue(r['main_heap_live']);self.assertEqual(r['probe_guard_pages'],512)

    def test_missing_pm_asserts_after_full_probe_and_object_publication(self):
        r=self.row('no_pm');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30c60,line=31))
        self.assertEqual((r['main_head'],r['main_cache'],r['probe_guard_pages']),(full.base.OBJECT,full.base.OBJECT,512))

    def test_supplied_no_bbt_registers_object_with_inactive_geometry(self):
        r=self.row('no_bbt');self.assertEqual((r['returned'],r['main_bbt_magic'],r['main_cache']),(0,0,full.base.OBJECT))
        self.assertEqual(self.output('no_bbt')[12],0);self.assertEqual(r['probe_guard_pages'],512)

    def test_retry_reinitializes_platform_before_second_round_match(self):
        r=self.row('second_round');self.assertEqual((r['returned'],r['probe_id_reads'],r['probe_bus_calls']),(0,12,12))
        self.assertEqual(self.actions('second_round').count('fence'),24)

    def test_last_33rd_candidate_matches_through_real_platform_and_fifo(self):
        r=self.row('last_33rd');self.assertEqual((r['returned'],r['probe_id_reads'],r['probe_bus_calls']),(0,33,33))
        self.assertEqual(r['main_selected'],full.probe.facts()['chips'][10]['address']);self.assertEqual(self.actions('last_33rd').count('fence'),66)

    def test_three_no_match_rounds_return_minus_six_without_allocation(self):
        r=self.row('no_match');self.assertEqual((r['returned'],r['main_selected'],r['probe_id_reads'],r['full_commands']),(0xfffffffa,0,33,33))
        self.assertEqual((r['probe_guard_pages'],r['main_cache']),(0,0));self.assertFalse(r['main_heap_live'])
        self.assertEqual(r['full_dma_registry'][26:28],list(full.platform.DMA))

    def test_disabled_bus_asserts_in_id_builder_after_actual_platform_init(self):
        r=self.row('disabled');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30fa4,line=383))
        self.assertEqual((r['full_commands'],r['full_rx_bytes'],r['probe_id_reads']),(0,0,1))
        self.assertEqual(r['full_dma_registry'][26:28],list(full.platform.DMA))

    def test_id_readiness_timeout_is_produced_by_actual_hal_wait(self):
        n='id_ready_timeout';r=self.row(n);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=305))
        self.assertEqual((r['full_commands'],r['full_rx_bytes'],r['main_selected']),(1,0,0));self.assertIn('log:receive_poll_error',self.actions(n))

    def test_reset_completion_timeout_retains_selection_without_feature_writes(self):
        r=self.row('reset_done_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294))
        self.assertEqual(r['main_selected'],full.probe.facts()['chips'][0]['address']);self.assertEqual(r['probe_features'],{})
        self.assertEqual((r['full_commands'],r['full_rx_bytes'],r['probe_guard_pages']),(2,5,0))

    def test_feature_write_completion_timeout_retains_fifo_feature_state(self):
        r=self.row('feature_write_done_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=313))
        self.assertEqual((r['full_tx_hex'],r['probe_features'],r['probe_guard_pages']),('00',{'160':0},0))
        self.assertFalse(r['main_heap_live'])

    def test_feature_read_timeout_retains_write_but_does_not_return_outer_error(self):
        r=self.row('feature_read_ready_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=305));self.assertIsNone(r['returned'])
        self.assertEqual((r['probe_features'],r['full_rx_bytes'],r['full_commands']),({'160':0},5,4))

    def test_successful_mismatched_readback_returns_outer_minus_six(self):
        r=self.row('feature_mismatch');self.assertEqual(r['returned'],0xfffffffa);self.assertIsNone(r['stopped'])
        self.assertEqual((r['probe_features'],r['full_rx_bytes'],r['probe_guard_pages']),({'160':0},6,0))
        self.assertFalse(r['main_heap_live']);self.assertIn('log:probe_feature_mismatch',self.actions('feature_mismatch'))

    def test_missing_regulator_and_negative_pin_status_do_not_stop_full_path(self):
        self.assertEqual(self.row('missing_regulator')['returned'],0);self.assertEqual(self.row('missing_regulator')['probe_regulator'],0)
        self.assertIn('log:probe_regulator_missing',self.actions('missing_regulator'))
        self.assertEqual(self.row('pin_status_ignored')['returned'],0);self.assertIn('platform_pinmux:-9',self.actions('pin_status_ignored'))

    def test_allocation_failure_retains_successful_probe_and_original_dma_links(self):
        r=self.row('allocation_error');self.assertEqual((r['returned'],r['probe_guard_pages'],r['main_cache']),(0xfffffffa,512,0))
        self.assertEqual(r['full_dma_registry'][26:28],list(full.platform.DMA));self.assertFalse(r['main_heap_live'])

    def test_short_probe_packets_do_not_claim_dma_setup_wait_or_actual_uid_bbt(self):
        a=self.actions('chip_0');self.assertIn('probe_uid:0',a);self.assertTrue(any(x.startswith('probe_bbt:') for x in a))
        self.assertFalse(any(x.startswith(('dma_tick:','dma_cache_prepare:','dma_cache_finish:')) for x in a))

    def test_contract_rejects_supplied_hal_faults_and_unbounded_full_inputs(self):
        c=self.case('chip_0')
        for change in (dict(native_main_full_probe=False),dict(bus_command_fail_at=1),dict(bus_init_status=-9),dict(full_ready_fail_at=101),dict(full_done_fail_at=-1),dict(full_rom_version='v-other'),dict(full_clock_word=1<<32)):
            with self.subTest(change=change),self.assertRaises(ValueError):full.contract(c|change)
        with self.assertRaises(ValueError):full.native_vectors('foreign')

    def test_captured_reports_match_models_preserve_data_and_use_separate_bound(self):
        digest=hashlib.sha256(bytes((i*3+1)&255 for i in range(64))).hexdigest()
        for scope,stem in (('root','main-nand-full-probe'),('faults','main-nand-full-probe-faults')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False)
            self.assertEqual((r['case_count'],r['bound_per_case']),(len(self.cases[scope]),full.BOUND));self.assertEqual(len(r['cases']),len(self.cases[scope]))
            for c in r['cases']:
                self.assertEqual(c['observed'],self.cases[scope][c['name'].removeprefix('main_full_')]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],full.BOUND)
                for row in c['observed']['rows']:self.assertEqual(row['data_sha256'],digest)
        r=json.loads(Path('analysis/main-nand-full-probe-faults.json').read_bytes())['native_validation']
        self.assertGreater(next(c['steps'] for c in r['cases'] if c['name']=='main_full_last_33rd'),full.base.BOUND)

    def test_evidence_code_data_and_fact_hashes_match_fixed_native_configuration(self):
        def config(path):return json.loads(json.loads(re.search(r'CONFIG=(".*?");',Path(path).read_text()).group(1)))
        parent=config('analysis_scripts/ValidateMainObjects.java');code={};data={}
        for key in ('guards','main_stack_guards','main_probe_guards'):code.update({(g['address'],g['size']):g['sha256'] for g in parent[key]})
        data.update({(g['address'],g['size']):g['sha256'] for g in parent['main_probe_data_guards']})
        for path in ('analysis_scripts/ValidateMainQspiHal.java','analysis_scripts/ValidateMainNandBus.java','analysis_scripts/ValidateMainDmaBackend.java'):
            cfg=config(path);code.update({(g['address'],g['size']):g['sha256'] for g in cfg['guards']})
            data.update({(g['address'],g['size']):g['sha256'] for g in cfg.get('data_guards',[])})
        for stem in ('main-nand-full-probe','main-nand-full-probe-faults'):
            e=json.loads(Path('analysis',stem+'.json').read_bytes())
            for key,spans,guards in (('byte_range_sha256',full.ranges(),code),('data_range_sha256',full.data_ranges(),data)):
                self.assertEqual(e[key],{f'{a:08x}_{n:x}':guards[(a,n)] for a,n in spans})
            self.assertEqual(e['startup_facts_sha256'],hashlib.sha256(full.platform.FACTS.read_bytes()).hexdigest())

    def test_model_preserves_input_vectors_and_original_descriptors(self):
        c=self.case('chip_0');before=copy.deepcopy(c);full.contract(c);self.assertEqual(c,before)


if __name__=='__main__':unittest.main()
