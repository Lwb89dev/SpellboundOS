import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.nand_probe_stack import BUS_WORDS,CHIPS,contract,inventory,native_vectors


class NandProbeStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]

    def test_each_original_candidate_is_selected_from_received_fifo_id(self):
        for i,chip in enumerate(CHIPS):
            name=f'fifo_probe_candidate_{i}';r=self.row(name);self.result(name,0)
            self.assertEqual(r['probe_selected'],chip['address']);self.assertEqual(r['probe_id_reads'],i+1)
            self.assertEqual(r['probe_bus_calls'],i+1);self.assertEqual(r['rx_bytes'],5*(i+1)+len(chip['features']))

    def test_first_candidate_executes_id_reset_and_feature_command_sequence(self):
        self.assertEqual(self.opcodes('fifo_probe_candidate_0'),[0x9f,0xff,0x1f,0x0f,0x1f,0x0f])

    def test_original_bus_word_changes_selector_and_geometry_changes_boot_guard(self):
        for i,chip in enumerate(CHIPS):
            r=self.row(f'fifo_probe_candidate_{i}')
            self.assertEqual((r['clock_word']>>12)&15,2 if BUS_WORDS[i]<100 else 1)
            self.assertEqual(r['probe_guard_pages'],1048576//chip['page_size'])
            self.assertEqual(r['probe_guard_blocks'],1048576//chip['page_size']//64)

    def test_no_match_exhausts_three_complete_candidate_rounds(self):
        name='fifo_probe_no_match';r=self.row(name);self.result(name,-4)
        self.assertEqual((r['probe_bus_calls'],r['probe_id_reads'],r['probe_selected']),(33,33,0))
        self.assertEqual(r['probe_guard_pages'],0);self.assertEqual(r['tx_hex'],'');self.assertEqual(r['rx_bytes'],165)
        self.assertEqual([a for a in self.actions(name) if a.startswith('probe_bus:')],['probe_bus:'+str(i) for i in range(11)]*3)
        self.assertIn('log:no_chip_match',self.actions(name))

    def test_delayed_id_can_succeed_in_second_or_third_round(self):
        for name,attempts in (('fifo_probe_second_round',12),('fifo_probe_third_round',23)):
            self.result(name,0);self.assertEqual(self.row(name)['probe_id_reads'],attempts)
            self.assertEqual(self.row(name)['probe_selected'],CHIPS[0]['address'])

    def test_last_candidate_in_last_round_can_still_succeed(self):
        name='fifo_probe_last_allowed_attempt';self.result(name,0);r=self.row(name)
        self.assertEqual(r['probe_id_reads'],33);self.assertEqual(r['probe_selected'],CHIPS[10]['address'])
        self.assertEqual((r['probe_guard_pages'],r['probe_guard_blocks']),(256,4))

    def test_optional_received_tail_does_not_change_first_candidate_match(self):
        name='fifo_probe_optional_tail';self.result(name,0);self.assertEqual(self.row(name)['probe_selected'],CHIPS[0]['address'])
        self.assertEqual(self.row(name)['probe_id_reads'],1)

    def test_missing_regulator_continues_without_power_callback_sequence(self):
        name='fifo_probe_no_regulator';self.result(name,0);self.assertEqual(self.row(name)['probe_regulator'],0)
        self.assertIn('log:regulator_missing',self.actions(name))
        self.assertEqual([a for a in self.actions(name) if a.startswith('probe_delay:')],['probe_delay:11'])

    def test_supplied_power_callback_errors_are_ignored(self):
        name='fifo_probe_power_error_ignored';self.result(name,0)
        self.assertIn('probe_disable:-9',self.actions(name));self.assertIn('probe_enable:-9',self.actions(name))
        self.assertEqual(self.row(name)['probe_guard_blocks'],8)

    def test_supplied_auxiliary_results_are_not_propagated(self):
        name='fifo_probe_aux_errors_ignored';self.result(name,0)
        for action in ('probe_workaround:-9','probe_uid:-9','probe_bbt:1024:2048:64:-9'):
            self.assertIn(action,self.actions(name))
        self.assertEqual(self.row(name)['probe_guard_pages'],512)

    def test_feature_mismatch_keeps_selection_but_does_not_set_boot_counts(self):
        name='fifo_probe_feature_mismatch';self.result(name,-7);r=self.row(name)
        self.assertEqual(r['probe_selected'],CHIPS[0]['address']);self.assertEqual(r['probe_guard_pages'],0)
        self.assertEqual(r['probe_features'],{'160':0,'176':24});self.assertIn('r:256:1:25',self.actions(name))
        self.assertIn('log:feature_mismatch',self.actions(name));self.assertFalse(any(a.startswith('probe_bbt:') for a in self.actions(name)))

    def test_feature_transmit_bytes_and_register_state_match_original_tables(self):
        for i,chip in enumerate(CHIPS):
            r=self.row(f'fifo_probe_candidate_{i}')
            self.assertEqual(bytes.fromhex(r['tx_hex']),bytes(value for register,value in chip['features']))
            self.assertEqual(r['probe_features'],{str(register):value for register,value in chip['features']})
            self.assertEqual(r['feature_reads'],len(chip['features']))

    def test_uid_callback_follows_selected_descriptor_flag(self):
        for i,chip in enumerate(CHIPS):
            self.assertEqual('probe_uid:0' in self.actions(f'fifo_probe_candidate_{i}'),chip['uid'])

    def test_wrapper_creates_mutex_only_after_success_and_retains_existing_mutex(self):
        name='fifo_probe_wrapper';self.result(name,0);self.assertEqual(self.row(name)['probe_mutex'],inventory.MUTEX)
        self.assertIn('probe_mutex_create:1',self.actions(name))
        name='fifo_probe_wrapper_existing';self.result(name,0);self.assertEqual(self.row(name)['probe_id_reads'],1)
        self.assertFalse(any(a.startswith('probe_mutex_create:') for a in self.actions(name)))

    def test_failed_mutex_creation_stops_after_selection_and_boot_guard_publication(self):
        name='fifo_probe_wrapper_mutex_failure';r=self.row(name);self.assertIsNone(r['returned'])
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c3d434,line=0x1e))
        self.assertEqual((r['probe_selected'],r['probe_guard_pages'],r['probe_mutex']),(CHIPS[0]['address'],512,0))

    def test_actual_bus_assertions_stop_before_outer_helper_error_returns(self):
        for name,line,selected in (('fifo_probe_id_assertion',0x12a,0),('fifo_probe_reset_assertion',0x11f,CHIPS[0]['address']),('fifo_probe_feature_assertion',0x132,CHIPS[0]['address'])):
            r=self.row(name);self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=line))
            self.assertEqual(r['probe_selected'],selected);self.assertEqual(r['probe_guard_pages'],0)
            self.assertNotIn('log:probe_error',self.actions(name))

    def test_contract_rejects_unbounded_ids_modes_and_service_inputs(self):
        base=self.cases['fifo_probe_candidate_0']
        for change in (dict(mode='platform_init'),dict(probe_id=[1]*4),dict(probe_id=[256]*5),dict(probe_delayed_rounds=3),dict(probe_entry='register'),dict(probe_feature_mismatch_at=4),dict(defer_reinit=True),dict(probe_power_status=-101)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_all_cases_and_preserves_caller_buffer(self):
        report=json.loads(Path('analysis/nand-probe-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for row in report['cases']:
            self.assertEqual(row['observed'],self.cases[row['name']]['expected']);self.assertEqual(row['observed']['rows'][0]['buffer_sha256'],expected)


if __name__=='__main__':unittest.main()
