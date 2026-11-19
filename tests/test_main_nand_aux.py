import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

from analysis_scripts import main_nand_aux as aux


class MainNandAuxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={s:{c['name'].removeprefix('main_aux_'):c for c in aux.native_vectors(s)['cases']} for s in ('workaround','uid')}
    def case(self,n):return self.cases['workaround'][n] if n in self.cases['workaround'] else self.cases['uid'][n]
    def row(self,n):return self.case(n)['expected']['rows'][0]
    def actions(self,n):return self.case(n)['expected']['actions']
    def digest(self,data):return hashlib.sha256(data).hexdigest()

    def test_main_uid_inventory_matches_all_original_descriptor_hashes(self):
        facts=aux.facts();chips=aux.joined.probe.facts()['chips'];self.assertEqual(len(facts),11)
        for p,c in zip(facts,chips):self.assertEqual((p['address'],p['sha256'],p['name']),(c['address'],c['sha256'],c['name']))
        self.assertTrue(all(p['uid_mode']==1 and p['uid_size']==32 and p['uid_copies']==16 for p in facts))

    def test_original_uid_sequences_and_ecc_fields_are_distinct(self):
        p=aux.facts();self.assertEqual(p[0]['sequence'],[[176,72]]);self.assertEqual(p[5]['sequence'],[[176,64]])
        self.assertEqual((p[0]['ecc_mask'],p[0]['ecc_bad']),(48,32));self.assertEqual((p[5]['ecc_mask'],p[5]['ecc_bad']),(112,32))

    def test_unsupported_workaround_returns_minus_one_but_probe_continues(self):
        r=self.row('unsupported');self.assertEqual((r['returned'],r['aux_workaround_return']),(0,0xffffffff))
        a=self.actions('unsupported');self.assertEqual(sum(x.startswith('aux_compare:') for x in a),2)
        self.assertFalse(any(x.startswith('probe_packet:102:') for x in a))

    def test_supported_workaround_runs_actual_enable_reset_and_delay_sequence(self):
        a=self.actions('supported_zero');chain=['probe_workaround_native','probe_packet:102:0:0:1','delay:1000','probe_packet:153:0:0:1','delay:5000','log:level_register','aux_workaround_return:0']
        for x,y in zip(chain,chain[1:]):self.assertLess(a.index(x),a.index(y))
        self.assertEqual(self.row('supported_zero')['aux_workaround_return'],0)

    def test_workaround_scope_preserves_supplied_uid_boundary(self):
        r=self.row('supported_zero');self.assertFalse(r['aux_uid_entered']);self.assertFalse(r['aux_uid_completed'])
        self.assertEqual((r['aux_uid_length'],r['aux_uid_sha256']),(17,self.digest(b'\xa5'*128)));self.assertIn('probe_uid:0',self.actions('supported_zero'))

    def test_nonzero_level_is_cleared_and_read_back_through_fifo(self):
        n='supported_level_reset';r=self.row(n);self.assertEqual((r['returned'],r['aux_e0_reads'],r['probe_features']['224']),(0,3,0))
        self.assertEqual(self.actions(n).count('probe_packet:31:224:1:1'),1);self.assertIn('log:check_level',self.actions(n))

    def test_five_unconfirmed_level_writes_still_return_success(self):
        n='supported_unconfirmed';a=self.actions(n);r=self.row(n)
        self.assertEqual((r['returned'],r['aux_workaround_return'],r['probe_features']['224']),(0,0,2))
        self.assertEqual(a.count('probe_packet:31:224:1:1'),5);self.assertEqual(a.count('log:level_mismatch'),5)

    def test_scripted_second_write_can_confirm_level(self):
        n='supported_second_write';self.assertEqual(self.actions(n).count('probe_packet:31:224:1:1'),2)
        self.assertEqual(self.actions(n).count('log:level_mismatch'),1);self.assertEqual(self.row(n)['aux_workaround_return'],0)

    def test_enable_and_power_reset_timeouts_stop_before_workaround_return(self):
        for n,delay in (('reset_enable_timeout','delay:1000'),('power_reset_timeout','delay:5000')):
            r=self.row(n);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294));self.assertIsNone(r['aux_workaround_return'])
            self.assertNotIn(delay,self.actions(n));self.assertEqual(r['probe_guard_pages'],0)

    def test_e0_read_timeout_records_no_completed_e0_fifo_read(self):
        r=self.row('level_read_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=305))
        self.assertEqual(r['aux_e0_reads'],0);self.assertIsNone(r['aux_workaround_return'])

    def test_first_uid_copy_is_verified_and_published_in_original_globals(self):
        r=self.row('first_copy');data=aux.policy.uid_bytes(0,True)
        self.assertEqual((r['returned'],r['aux_uid_length'],r['aux_uid_caches']),(0,16,1))
        self.assertEqual(r['aux_uid_sha256'],self.digest(data+b'\xa5'*96));self.assertTrue(r['aux_uid_entered']);self.assertTrue(r['aux_uid_completed'])

    def test_second_and_last_uid_copies_follow_complement_validation(self):
        for n,index in (('second_copy',1),('last_copy',15)):
            r=self.row(n);self.assertEqual((r['returned'],r['aux_uid_length'],r['aux_uid_caches']),(0,16,index+1))
            self.assertEqual(r['aux_uid_sha256'],self.digest(aux.policy.uid_bytes(index,True)+b'\xa5'*96))

    def test_uid_workload_uses_larger_total_fifo_bound_without_changing_packet_size(self):
        r=self.row('last_copy');self.assertEqual(r['full_rx_bytes'],521);self.assertGreater(r['full_rx_bytes'],512)
        self.assertTrue(all(':32:0' in x for x in self.actions('last_copy') if x.startswith('probe_packet:3:')))

    def test_no_valid_copy_leaves_length_zero_and_last_invalid_payload(self):
        r=self.row('no_valid_copy');self.assertEqual((r['returned'],r['aux_uid_length'],r['aux_uid_caches']),(0,0,16))
        self.assertEqual(r['aux_uid_sha256'],self.digest(aux.policy.uid_bytes(15,False)+b'\xa5'*96))
        self.assertIn('log:uid_error:-200',self.actions('no_valid_copy'));self.assertTrue(r['aux_uid_completed'])

    def test_uid_feature_mismatch_retains_prior_length_and_buffer(self):
        r=self.row('feature_mismatch');self.assertEqual((r['returned'],r['aux_uid_length'],r['aux_uid_caches']),(0,17,0))
        self.assertEqual(r['aux_uid_sha256'],self.digest(b'\xa5'*128));self.assertIn('log:uid_feature_error:-7',self.actions('feature_mismatch'))
        self.assertIn('log:uid_error:-5',self.actions('feature_mismatch'))

    def test_ecc_reject_keeps_prior_uid_state_while_outer_probe_succeeds(self):
        r=self.row('ecc_reject');self.assertEqual((r['returned'],r['aux_uid_length'],r['aux_uid_caches']),(0,17,0))
        self.assertEqual(r['aux_uid_sha256'],self.digest(b'\xa5'*128));self.assertIn('log:uid_error:-101',self.actions('ecc_reject'))

    def test_uid_error_void_return_does_not_block_registration_or_geometry(self):
        for n in ('feature_mismatch','ecc_reject','no_valid_copy'):
            r=self.row(n);self.assertEqual(r['main_cache'],aux.base.OBJECT);self.assertEqual(r['probe_guard_pages'],512)
            self.assertTrue(r['aux_uid_completed']);self.assertEqual(len(self.case(n)['expected']['rows']),4)

    def test_uid_mismatch_is_scoped_to_uid_phase_and_regular_features_are_restored(self):
        r=self.row('feature_mismatch');self.assertEqual(r['probe_features']['176'],24)
        a=self.actions('feature_mismatch');self.assertLess(a.index('log:uid_error:-5'),a.index('probe_bbt:1024:2048:64:0'))

    def test_busy_second_read_runs_original_delay_and_status_packets(self):
        r=self.row('busy_second_read');self.assertEqual((r['returned'],r['aux_status_reads']),(0,2))
        self.assertEqual(self.actions('busy_second_read').count('delay:5'),2)
        self.assertEqual(r['full_rx_bytes'],self.row('first_copy')['full_rx_bytes']+1)

    def test_uid_not_requested_leaves_original_uid_state_untouched(self):
        r=self.row('uid_not_requested');self.assertFalse(r['aux_uid_entered']);self.assertFalse(r['aux_uid_completed'])
        self.assertEqual((r['returned'],r['aux_uid_length'],r['aux_uid_sha256']),(0,17,self.digest(b'\xa5'*128)))

    def test_dosilicon_and_esmt_use_original_uid_feature_sequence(self):
        for n in ('dosilicon_uid','esmt_uid'):
            r=self.row(n);self.assertEqual((r['returned'],r['aux_uid_length']),(0,16))
            self.assertIn('w:256:1:64',self.actions(n))
        self.assertEqual(self.row('dosilicon_uid')['probe_features']['176'],17)
        self.assertEqual(self.row('esmt_uid')['probe_features']['176'],16)

    def test_supported_workaround_and_real_uid_share_the_probe_chain(self):
        r=self.row('supported_family');self.assertEqual((r['returned'],r['aux_workaround_return'],r['aux_uid_length']),(0,0,16))
        a=self.actions('supported_family');self.assertLess(a.index('aux_workaround_return:0'),a.index('probe_uid_native'))
        self.assertEqual(r['aux_e0_reads'],3)

    def test_cache_readiness_timeout_retains_cleared_buffer_and_zero_length(self):
        r=self.row('cache_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=305))
        self.assertEqual((r['aux_uid_length'],r['aux_uid_caches']),(0,1));self.assertEqual(r['aux_uid_sha256'],self.digest(bytes(32)+b'\xa5'*96))
        self.assertTrue(r['aux_uid_entered']);self.assertFalse(r['aux_uid_completed'])

    def test_cache_completion_timeout_retains_received_payload_before_publication(self):
        r=self.row('cache_done_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=305))
        self.assertEqual(r['aux_uid_length'],0);self.assertEqual(r['aux_uid_sha256'],self.digest(aux.policy.uid_bytes(0,True)+b'\xa5'*96))
        self.assertFalse(r['aux_uid_completed']);self.assertEqual(r['main_cache'],0)

    def test_uid_feature_transport_timeout_retains_prior_state_without_uid_error_return(self):
        r=self.row('feature_read_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=305))
        self.assertEqual((r['aux_uid_length'],r['aux_uid_caches']),(17,0));self.assertFalse(r['aux_uid_completed'])
        self.assertEqual(r['aux_uid_sha256'],self.digest(b'\xa5'*128));self.assertEqual(r['probe_features']['176'],72)

    def test_uid_formatting_is_bounded_and_uses_uppercase_byte_text(self):
        data=aux.policy.uid_bytes(0,True);a=self.actions('first_copy')
        self.assertEqual([x for x in a if x.startswith('format:')],['format:'+str(v) for v in data[:16]])
        self.assertIn('log:uid_ok:0:'+data[:16].hex().upper(),a)

    def test_contract_rejects_fake_helper_faults_busy_exhaustion_and_invalid_bounds(self):
        c=self.case('first_copy')
        for change in (dict(native_main_aux=False),dict(native_main_uid=False),dict(cache_error_at=1),dict(first_good=16),dict(initial_uid_length=129),dict(statuses=[1]),dict(e0_reads=[256])):
            with self.subTest(change=change),self.assertRaises(ValueError):aux.contract(c|change,'uid')
        before=copy.deepcopy(c);aux.contract(c,'uid');self.assertEqual(c,before)

    def test_captured_native_evidence_and_fixed_guards_match_models(self):
        def cfg(path):return json.loads(json.loads(re.search(r'CONFIG=(".*?");',Path(path).read_text()).group(1)))
        parent=cfg('analysis_scripts/ValidateMainObjects.java');guards={}
        for key in ('guards','main_stack_guards','main_probe_guards','main_probe_data_guards'):guards.update({(g['address'],g['size']):g['sha256'] for g in parent[key]})
        for path in ('analysis_scripts/ValidateMainQspiHal.java','analysis_scripts/ValidateMainNandBus.java','analysis_scripts/ValidateMainDmaBackend.java','analysis_scripts/ValidateMainNandAux.java'):
            config=cfg(path)
            for key in ('guards','data_guards'):guards.update({(g['address'],g['size']):g['sha256'] for g in config.get(key,[])})
        for scope,stem in (('workaround','main-nand-aux-workaround'),('uid','main-nand-aux-uid')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False);self.assertEqual(r['case_count'],len(self.cases[scope]));self.assertEqual(len(r['cases']),len(self.cases[scope]))
            for c in r['cases']:
                self.assertEqual(c['observed'],self.cases[scope][c['name'].removeprefix('main_aux_')]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],aux.joined.BOUND)
            for key,spans in (('byte_range_sha256',aux.ranges()),('data_range_sha256',aux.data_ranges())):
                self.assertEqual(e[key],{f'{a:08x}_{n:x}':guards[(a,n)] for a,n in spans})
            self.assertEqual(e['inventory_sha256'],self.digest(aux.FACTS.read_bytes()))


if __name__=='__main__':unittest.main()
