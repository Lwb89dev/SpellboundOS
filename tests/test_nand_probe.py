import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_probe import HEAP,MUTEX,facts,contract,native_vectors


class NandProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table=facts();cls.chips=cls.table['chips'];cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]

    def test_original_table_has_eleven_unique_candidates(self):
        self.assertFalse(self.table['hardware_execution'])
        self.assertEqual(len(self.chips),11)
        self.assertEqual(len({c['address'] for c in self.chips}),11)
        self.assertEqual(len({tuple(c['id']) for c in self.chips}),11)
        self.assertTrue(all(c['id'][4]==0 for c in self.chips))

    def test_original_geometry_fields_are_consistent(self):
        for chip in self.chips:
            self.assertEqual(chip['blocks']*chip['pages_per_block'],chip['pages'])
            self.assertIn(chip['pages']*chip['page_size'],(128<<20,256<<20,512<<20))
            if chip['capacity_word']:self.assertEqual(chip['capacity_word'],chip['pages']*chip['page_size'])

    def test_all_original_oob_layouts_use_contiguous_branch(self):
        for chip in self.chips:
            self.assertGreaterEqual(chip['ecc_unit'],4)
            self.assertLessEqual(chip['positions'][1]+4,chip['spare'])
        self.assertEqual({c['positions'][1] for c in self.chips},{16,20,72})

    def test_original_bus_and_driver_bindings_are_recovered(self):
        self.assertEqual(self.table['bus_callbacks'][0],0x80c10580)
        self.assertEqual(self.table['bus_callbacks'][3],0x80c106f0)
        self.assertEqual(self.table['driver_callbacks'][0],0x80c27aac)
        self.assertEqual(self.table['driver_callbacks'][2],0x80c27c70)

    def test_every_original_id_selects_its_descriptor(self):
        for i,chip in enumerate(self.chips):
            row=self.row(f'probe_candidate_{i}')
            self.assertEqual((row['returned'],row['selected']),(0,chip['address']))
            self.assertEqual(row['guard_pages'],0x100000//chip['page_size'])
            self.assertEqual(row['guard_blocks'],row['guard_pages']//chip['pages_per_block'])

    def test_candidate_order_is_observed_until_first_match(self):
        for i in range(11):
            actions=self.result(f'probe_candidate_{i}')['actions']
            self.assertEqual([a for a in actions if a.startswith('bus_init:')],[f'bus_init:{j}:0' for j in range(i+1)])
            self.assertEqual(len([a for a in actions if a.startswith('read_id:')]),i+1)

    def test_every_original_feature_sequence_is_written_and_verified(self):
        for i,chip in enumerate(self.chips):
            actions=self.result(f'probe_candidate_{i}')['actions']
            self.assertEqual([a for a in actions if a.startswith('set_feature:')],[f'set_feature:{r}:{v}:0' for r,v in chip['features']])
            self.assertEqual([a for a in actions if a.startswith('get_feature:')],[f'get_feature:{r}:{v}:0' for r,v in chip['features']])

    def test_uid_service_is_conditional_on_original_descriptor_flag(self):
        for i,chip in enumerate(self.chips):
            actions=self.result(f'probe_candidate_{i}')['actions']
            self.assertEqual('uid:0' in actions,chip['uid'])

    def test_all_original_layouts_roundtrip_four_oob_bytes(self):
        for i,chip in enumerate(self.chips):
            row=self.row(f'layout_candidate_{i}');data=bytearray(b'\xff'*chip['spare']);at=chip['positions'][1]
            data[at:at+4]=bytes.fromhex('01004546')
            self.assertEqual((row['returned'],row['layout_record']),(0,'01004546'))
            self.assertEqual(row['layout_sha256'],hashlib.sha256(data).hexdigest())

    def test_unmatched_id_exhausts_three_rounds_then_returns_minus_four(self):
        actions=self.result('probe_no_match')['actions']
        self.assertEqual(len([a for a in actions if a.startswith('read_id:')]),33)
        self.assertEqual((self.row('probe_no_match')['returned'],self.row('probe_no_match')['selected']),(0xfffffffc,0))
        self.assertEqual(actions[-2:],['log:no_chip_match','log:probe_error'])

    def test_later_rounds_can_find_a_chip(self):
        for name,count in (('probe_second_round',15),('probe_third_round',26)):
            self.assertEqual(self.row(name)['returned'],0)
            self.assertEqual(len([a for a in self.result(name)['actions'] if a.startswith('read_id:')]),count)

    def test_missing_regulator_logs_but_continues_with_supplied_bus(self):
        self.assertEqual(self.row('probe_no_regulator')['regulator'],0)
        self.assertEqual(self.row('probe_no_regulator')['returned'],0)
        self.assertIn('log:regulator_missing',self.result('probe_no_regulator')['actions'])
        self.assertNotIn('delay:20',self.result('probe_no_regulator')['actions'])

    def test_power_statuses_are_ignored_by_selected_probe(self):
        actions=self.result('probe_power_status_ignored')['actions']
        self.assertEqual(actions[:5],['regulator:1','disable:-9','delay:20','enable:-9','delay:20'])
        self.assertEqual(self.row('probe_power_status_ignored')['returned'],0)

    def test_bus_init_failure_stops_before_read_id(self):
        row=self.row('probe_bus_error')
        self.assertEqual(row['stopped'],dict(kind='assertion',owner=0x80c3dc70,line=0x57))
        self.assertIsNone(row['returned'])
        self.assertFalse(any(a.startswith('read_id:') for a in self.result('probe_bus_error')['actions']))

    def test_read_and_reset_transport_errors_stop_at_distinct_assertions(self):
        for name,owner,line in (('probe_id_transfer_assert',0x80c3d4e8,0x17f),('probe_reset_transfer_assert',0x80c3d4d8,0x192)):
            self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertIsNone(self.row(name)['returned'])

    def test_explicit_helper_errors_have_separate_outer_statuses(self):
        self.assertEqual(self.row('probe_injected_read_error')['returned'],0xffffffce)
        self.assertEqual(self.row('probe_injected_reset_error')['returned'],0xffffffcd)

    def test_feature_write_error_skips_its_readback(self):
        actions=self.result('probe_feature_write_error')['actions']
        self.assertEqual(self.row('probe_feature_write_error')['returned'],0xfffffffb)
        self.assertEqual(len([a for a in actions if a.startswith('get_feature:')]),1)
        self.assertEqual(actions[-2:],['log:feature_write_error','log:probe_error'])

    def test_feature_read_error_and_mismatch_return_distinct_status(self):
        self.assertEqual(self.row('probe_feature_read_error')['returned'],0xfffffffa)
        self.assertEqual(self.row('probe_feature_mismatch')['returned'],0xfffffff9)

    def test_feature_failure_preserves_selected_chip_but_not_final_guards(self):
        row=self.row('probe_feature_mismatch')
        self.assertEqual(row['selected'],self.chips[3]['address'])
        self.assertEqual((row['guard_pages'],row['guard_blocks']),(0,0))

    def test_workaround_uid_and_bbt_statuses_do_not_abort_probe(self):
        for name,action in (('probe_workaround_status_ignored','workaround:-9'),('probe_uid_status_ignored','uid:-9'),('probe_bbt_status_ignored','bbt:2048:4096:64:-9')):
            self.assertIn(action,self.result(name)['actions'])
            self.assertEqual(self.row(name)['returned'],0)

    def test_success_wrapper_creates_mutex_after_probe(self):
        self.assertEqual(self.row('wrapper_success')['mutex'],MUTEX)
        self.assertEqual(self.result('wrapper_success')['actions'][-1],'mutex:create:1')

    def test_existing_mutex_skips_creation_but_still_runs_probe(self):
        actions=self.result('wrapper_existing_mutex')['actions']
        self.assertFalse(any(a.startswith('mutex:') for a in actions))
        self.assertTrue(any(a.startswith('read_id:') for a in actions))

    def test_mutex_failure_stops_after_successful_chip_setup(self):
        row=self.row('wrapper_mutex_assert')
        self.assertEqual(row['stopped'],dict(kind='assertion',owner=0x80c3d434,line=0x1e))
        self.assertEqual(row['selected'],self.chips[3]['address'])
        self.assertEqual(row['mutex'],0)

    def test_wrapper_does_not_create_mutex_after_probe_failure(self):
        self.assertEqual(self.row('wrapper_probe_error')['returned'],0xfffffffc)
        self.assertFalse(any(a.startswith('mutex:') for a in self.result('wrapper_probe_error')['actions']))

    def test_driver_registration_publishes_original_root_and_method_table(self):
        row=self.row('register_success');data=bytearray(60);struct.pack_into('<I',data,40,0x80d811d8)
        self.assertEqual((row['returned'],row['root'],row['mutex'],row['heap_active']),(0,0x80d81b28,MUTEX,True))
        self.assertEqual(row['heap_sha256'],hashlib.sha256(data).hexdigest())
        self.assertEqual(self.result('register_success')['actions'][-1],'object_register:dev_nand:23:0')

    def test_missing_driver_property_stops_before_any_probe(self):
        self.assertEqual(self.row('register_missing_property')['stopped'],dict(kind='assertion',owner=0x80c3d208,line=0x31))
        self.assertEqual(self.result('register_missing_property')['actions'],['property:dev_nand:0'])

    def test_missing_operation_table_or_init_callback_returns_minus_six(self):
        for name in ('register_missing_operations','register_missing_init'):
            self.assertEqual((self.row(name)['returned'],self.row(name)['root']),(0xfffffffa,0x80d81b28))
            self.assertEqual(self.result(name)['actions'],['property:dev_nand:1'])

    def test_object_allocation_failure_preserves_completed_probe_and_mutex(self):
        row=self.row('register_alloc_error')
        self.assertEqual((row['returned'],row['selected'],row['mutex'],row['heap_active']),(0xfffffffa,self.chips[3]['address'],MUTEX,False))

    def test_object_registration_error_leaves_allocation_live(self):
        row=self.row('register_object_error')
        self.assertEqual((row['returned'],row['heap_active']),(0xfffffff5,True))
        self.assertEqual(row['heap_sha256'],self.row('register_success')['heap_sha256'])

    def test_outer_registration_maps_probe_failure_to_minus_six(self):
        row=self.row('register_probe_error')
        self.assertEqual((row['returned'],row['root'],row['heap_active']),(0xfffffffa,0x80d81b28,False))

    def test_matcher_reports_first_mandatory_mismatch(self):
        self.assertEqual(self.row('match_manufacturer')['returned'],0xffffffff)
        self.assertEqual(self.row('match_device')['returned'],0xfffffffe)
        self.assertEqual(self.row('match_third')['returned'],0xfffffffd)
        self.assertEqual(self.row('match_fourth')['returned'],0xfffffffc)

    def test_zero_optional_fields_accept_other_returned_bytes(self):
        self.assertEqual(self.row('match_optional_zero')['returned'],0)
        self.assertEqual(self.row('match_received_fifth_ignored')['returned'],0)

    def test_fifth_candidate_field_compares_received_fourth_byte(self):
        self.assertEqual(self.row('match_fifth_field')['returned'],0xfffffffb)
        self.assertEqual(self.row('match_fifth_uses_fourth_byte')['returned'],0)

    def test_workaround_compatibility_gate_uses_selected_name(self):
        self.assertEqual(self.row('compat_allowed')['returned'],0)
        self.assertEqual(self.row('compat_rejected')['returned'],0xffffffff)
        self.assertEqual(self.row('compat_absent')['returned'],0xffffffff)

    def test_probe_fixture_bounds_reject_wrong_id_lengths(self):
        for changes in (dict(read_id=[1,2]),dict(delayed_pass=3),dict(expected_id=[1,2])):
            with self.assertRaises(ValueError):contract(copy.deepcopy(self.cases['probe_candidate_0'])|changes)

    def test_public_native_observations_match_all_cases(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-probe.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(60,60))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['export_sha256']),len(report['byte_range_sha256'])),(9,9))


if __name__=='__main__':unittest.main()
