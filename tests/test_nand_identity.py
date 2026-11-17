import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.nand_identity import contract,facts,native_vectors,uid_bytes


class NandIdentityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def actions(self,name):return self.result(name)['actions']
    def status(self,name):
        value=self.row(name)['returned'];return value-(1<<32) if value is not None and value&(1<<31) else value
    def packets(self,name,opcode):return [a for a in self.actions(name) if a.startswith('packet:'+str(opcode)+':')]

    def test_original_inventory_has_eleven_descriptors_and_eight_uid_flags(self):
        chips=facts();self.assertEqual(len(chips),11)
        self.assertEqual([i for i,c in enumerate(chips) if c['uid_flag']],[0,1,2,3,5,8,9,10])
        for c in chips:
            self.assertEqual((c['uid_mode'],c['uid_copies'],c['uid_page'],c['uid_size']),(1,16,0,32))
            self.assertEqual(len(c['sequence']),1)

    def test_compatibility_selects_one_original_candidate(self):
        for i in range(11):self.assertEqual(self.status('compat_candidate_'+str(i)),0 if i==3 else -1)
        self.assertEqual(self.status('compat_absent'),-1)

    def test_compatibility_compares_only_first_twenty_bytes(self):
        self.assertEqual(self.status('compat_02_name'),0)
        self.assertEqual(self.status('compat_suffix'),0)

    def test_already_matching_level_skips_write(self):
        self.assertEqual(self.status('level_already_set'),0)
        self.assertEqual(self.row('level_already_set')['e0'],0xa1)
        self.assertEqual(self.packets('level_already_set',0x1f),[])

    def test_level_update_preserves_upper_bits_for_normal_level(self):
        self.assertEqual(self.row('level_write_verify')['e0'],0xa1)
        self.assertIn('set:224:161',self.actions('level_write_verify'))
        self.assertEqual(self.actions('level_write_verify')[-1],'get:224:161')

    def test_level_three_is_rejected_before_any_bus_access(self):
        self.assertEqual(self.status('level_3'),-1)
        self.assertEqual(self.actions('level_3'),[])

    def test_selected_other_level_arguments_are_not_rejected(self):
        for level,written in ((0,0xa0),(2,0xa2),(4,0xa4),(8,0xa8),(256,0xa0),(0xffffffff,0xff)):
            self.assertEqual(self.status('level_'+str(level)),0)
            self.assertEqual(self.row('level_'+str(level))['e0'],written)

    def test_initial_level_read_error_is_propagated(self):
        self.assertEqual(self.status('level_initial_read_error'),-9)
        self.assertEqual(self.actions('level_initial_read_error'),['inject_get:224:-9','log:feature_error'])

    def test_five_mismatches_still_return_zero_without_applying_level(self):
        name='level_mismatch_exhausted'
        self.assertEqual((self.status(name),self.row(name)['e0']),(0,0))
        self.assertEqual(self.actions(name).count('log:level_mismatch'),5)
        self.assertEqual(len(self.packets(name,0x1f)),5)

    def test_five_write_failures_still_return_zero(self):
        name='level_write_errors_exhausted'
        self.assertEqual((self.status(name),self.row(name)['e0']),(0,0))
        self.assertEqual(self.actions(name).count('inject_set:224:1:-9'),5)

    def test_five_readback_failures_still_return_zero(self):
        name='level_verify_errors_exhausted'
        self.assertEqual(self.status(name),0)
        self.assertEqual(self.actions(name).count('inject_get:224:-9'),5)
        self.assertEqual(len(self.packets(name,0x1f)),5)

    def test_successful_second_level_write_attempt_stops_retries(self):
        self.assertEqual(self.status('level_second_attempt'),0)
        self.assertEqual(len(self.packets('level_second_attempt',0x1f)),2)
        self.assertEqual(self.actions('level_second_attempt').count('log:level_mismatch'),1)

    def test_page_retry_reaches_levels_zero_one_two_and_restores_zero(self):
        for name,loads in (('retry_first_level',1),('retry_second_level',2),('retry_third_level',3)):
            self.assertEqual(self.status(name),0)
            self.assertEqual(len(self.packets(name,0x13)),loads)
            self.assertEqual(self.row(name)['e0'],0)
            self.assertIn('log:retry_valid',self.actions(name))

    def test_all_bad_page_levels_fail_after_three_loads(self):
        self.assertEqual(self.status('retry_all_bad'),-1)
        self.assertEqual(len(self.packets('retry_all_bad',0x13)),3)
        self.assertIn('log:retry_invalid',self.actions('retry_all_bad'))

    def test_retry_unsupported_or_absent_chip_skips_bus(self):
        for name in ('retry_unsupported','retry_absent'):
            self.assertEqual(self.status(name),-1);self.assertEqual(self.actions(name),[])

    def test_initial_level_or_load_errors_still_attempt_cleanup(self):
        self.assertEqual(self.status('retry_set_initial_error'),-1)
        self.assertEqual(self.status('retry_load_error'),-1)
        self.assertGreaterEqual(self.actions('retry_set_initial_error').count('get:224:0'),1)
        self.assertIn('inject_load:600:-9',self.actions('retry_load_error'))

    def test_busy_feature_error_makes_retry_fail(self):
        self.assertEqual(self.status('retry_busy_feature_error'),-1)
        self.assertIn('log:busy_feature_error',self.actions('retry_busy_feature_error'))

    def test_restore_failure_does_not_change_success_result(self):
        self.assertEqual(self.status('retry_restore_error'),0)
        self.assertIn('log:restore_failed',self.actions('retry_restore_error'))

    def test_unconfirmed_level_can_continue_to_load(self):
        self.assertEqual((self.status('retry_unconfirmed_level'),self.row('retry_unconfirmed_level')['e0']),(0,1))
        self.assertEqual(self.actions('retry_unconfirmed_level').count('log:level_mismatch'),10)
        self.assertEqual(len(self.packets('retry_unconfirmed_level',0x13)),1)

    def test_retry_busy_timeout_ff_can_be_accepted(self):
        self.assertEqual(self.status('retry_busy_timeout'),0)
        self.assertEqual(self.actions('retry_busy_timeout').count('get:192:1'),2000)
        self.assertIn('log:busy_timeout',self.actions('retry_busy_timeout'))
        self.assertIn('log:retry_valid',self.actions('retry_busy_timeout'))

    def test_reset_check_sends_66_then_99_with_requested_delays(self):
        name='check_level_zero';actions=self.actions(name)
        self.assertEqual(self.status(name),0)
        self.assertTrue(actions[0].startswith('packet:102:0:0:1:0:1:0:'))
        self.assertEqual(actions[1],'delay:1000')
        self.assertTrue(actions[2].startswith('packet:153:0:0:1:0:1:0:'))
        self.assertEqual(actions[3],'delay:5000')

    def test_reset_check_falls_back_to_actual_level_setter(self):
        self.assertEqual(self.status('check_level_nonzero'),0)
        self.assertEqual(self.row('check_level_nonzero')['e0'],0)
        self.assertIn('log:check_level',self.actions('check_level_nonzero'))
        self.assertEqual(self.status('check_initial_get_error'),0)
        self.assertEqual(self.status('check_fallback_get_error'),-1)

    def test_reset_check_can_succeed_after_unconfirmed_level_change(self):
        self.assertEqual((self.status('check_unconfirmed_level'),self.row('check_unconfirmed_level')['e0']),(0,2))
        self.assertEqual(self.actions('check_unconfirmed_level').count('log:level_mismatch'),5)

    def test_reset_check_unsupported_chip_skips_commands(self):
        self.assertEqual(self.status('check_unsupported'),-1)
        self.assertEqual(self.actions('check_unsupported'),[])

    def test_reset_bus_faults_stop_at_distinct_assertions(self):
        for name,owner,line in (('check_enable_bus_error',0x80c3d4c0,0x1a5),('check_reset_bus_error',0x80c3d4ac,0x1b8)):
            self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertIsNone(self.status(name))

    def test_original_uid_flags_control_execution(self):
        for i,chip in enumerate(facts()):
            name='uid_candidate_'+str(i)
            self.assertIsNone(self.status(name))
            self.assertIsNone(self.row(name)['stopped'])
            if chip['uid_flag']:
                self.assertEqual(self.row(name)['uid_length'],16)
                self.assertEqual(len(self.packets(name,3)),1)
            else:
                self.assertEqual(self.actions(name),[])
                self.assertEqual(self.row(name)['uid_length'],165)

    def test_uid_uses_original_feature_sequence(self):
        self.assertIn('set:176:72',self.actions('uid_candidate_0'))
        self.assertIn('set:176:64',self.actions('uid_candidate_5'))

    def test_uid_accepts_first_second_or_last_valid_complement_pair(self):
        for name,index in (('uid_candidate_3',0),('uid_second_copy',1),('uid_last_copy',15)):
            self.assertEqual(self.row(name)['uid_length'],16)
            self.assertEqual(len(self.packets(name,3)),index+1)
            expected=uid_bytes(index,True)+b'\xa5'*96
            self.assertEqual(self.row(name)['uid_sha256'],hashlib.sha256(expected).hexdigest())
            text=expected[:16].hex().upper()
            self.assertEqual(self.actions(name)[-1],f'log:uid_ok:{index*32}:{text}')

    def test_uid_validates_last_complement_byte_too(self):
        self.assertEqual(self.row('uid_no_valid_copy')['uid_length'],0)
        self.assertEqual(len(self.packets('uid_no_valid_copy',3)),16)
        self.assertEqual(self.actions('uid_no_valid_copy')[-1],'log:uid_error:-200')

    def test_uid_feature_failures_keep_prior_length_and_collapse_outer_error(self):
        for name,code in (('uid_feature_write_error',-5),('uid_feature_read_error',-6),('uid_feature_mismatch',-7)):
            self.assertEqual(self.row(name)['uid_length'],16)
            self.assertIn('log:uid_feature_error:'+str(code),self.actions(name))
            self.assertEqual(self.actions(name)[-1],'log:uid_error:-5')

    def test_uid_load_busy_and_ecc_failures_occur_before_length_clear(self):
        for name,code in (('uid_load_error',-52),('uid_busy_feature_error',-100),('uid_ecc_error',-101)):
            self.assertEqual(self.row(name)['uid_length'],165)
            self.assertEqual(self.actions(name)[-1],'log:uid_error:'+str(code))

    def test_uid_cache_error_occurs_after_length_and_buffer_clear(self):
        self.assertEqual(self.row('uid_cache_error')['uid_length'],0)
        self.assertEqual(self.row('uid_cache_error')['uid_sha256'],hashlib.sha256(bytes(32)+b'\xa5'*96).hexdigest())
        self.assertEqual(self.actions('uid_cache_error')[-1],'log:uid_error:-53')

    def test_uid_bus_errors_stop_at_actual_command_builder_assertions(self):
        for name,owner,line in (('uid_get_bus_error',0x80c3d670,0x37),('uid_cache_bus_error',0x80c3d604,0x96)):
            self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))

    def test_uid_busy_timeout_can_continue_to_authored_valid_bytes(self):
        self.assertEqual(self.actions('uid_busy_timeout').count('get:192:1'),2000)
        self.assertIn('log:busy_timeout',self.actions('uid_busy_timeout'))
        self.assertEqual(self.row('uid_busy_timeout')['uid_length'],16)
        self.assertTrue(self.actions('uid_busy_timeout')[-1].startswith('log:uid_ok:'))

    def test_uid_size_limit_and_only_32_byte_validation_path(self):
        for size in (0,64,128):
            name='uid_size_'+str(size)
            self.assertEqual(self.row(name)['uid_length'],0)
            self.assertEqual(self.packets(name,3),[])
            self.assertEqual(self.actions(name)[-1],'log:uid_ok:0:')
        self.assertEqual(self.row('uid_size_129')['uid_length'],165)
        self.assertEqual(self.actions('uid_size_129'),['log:uid_error:-1'])

    def test_uid_mode_and_zero_copy_cases(self):
        self.assertEqual(self.actions('uid_mode_zero'),[])
        self.assertEqual(self.row('uid_mode_zero')['uid_length'],165)
        self.assertEqual(self.row('uid_zero_copies')['uid_length'],0)
        self.assertEqual(self.actions('uid_zero_copies')[-1],'log:uid_ok:0:')

    def test_authored_two_feature_sequence_uses_full_byte_values(self):
        actions=self.actions('uid_two_features')
        self.assertIn('set:160:128',actions);self.assertIn('get:160:128',actions)
        self.assertEqual(self.row('uid_two_features')['uid_length'],16)

    def test_uid_ioctl_exports_length_and_exact_uid_bytes(self):
        rows=self.result('uid_export_valid')['rows'];expected=bytes([16])+uid_bytes(0,True)[:16]+b'\xa5'*112
        self.assertIsNone(rows[0]['returned'])
        self.assertEqual(rows[1]['returned'],0)
        self.assertEqual(rows[1]['export_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.actions('uid_export_valid')[-1],'copy_uid:16')

    def test_uid_ioctl_can_return_previous_bytes_after_feature_failure(self):
        name='uid_export_feature_error';rows=self.result(name)['rows'];expected=bytes([16])+b'\xa5'*128
        self.assertEqual(rows[0]['uid_length'],16)
        self.assertIn('log:uid_error:-5',self.actions(name))
        self.assertEqual(rows[1]['returned'],0)
        self.assertEqual(rows[1]['export_sha256'],hashlib.sha256(expected).hexdigest())

    def test_uid_ioctl_can_succeed_with_zero_length_after_uid_failures(self):
        for name in ('uid_export_invalid_copies','uid_export_cache_error','uid_export_non32'):
            row=self.result(name)['rows'][1]
            self.assertEqual((row['returned'],row['uid_length']),(0,0))
            self.assertEqual(row['export_sha256'],hashlib.sha256(b'\0'+b'\xa5'*128).hexdigest())
            self.assertEqual(self.actions(name)[-1],'copy_uid:0')

    def test_uid_ioctl_unsupported_chip_rejects_without_writing_output(self):
        row=self.result('uid_export_unsupported')['rows'][1]
        self.assertEqual(row['returned'],(-201)&0xffffffff)
        self.assertEqual(row['export_sha256'],hashlib.sha256(b'\xa5'*129).hexdigest())
        self.assertEqual(self.actions('uid_export_unsupported'),['log:ioctl_error'])

    def test_uid_ioctl_exports_simulated_uid_after_busy_timeout(self):
        rows=self.result('uid_export_busy_timeout')['rows']
        self.assertEqual(rows[1]['returned'],0)
        self.assertEqual(rows[1]['export_sha256'],self.result('uid_export_valid')['rows'][1]['export_sha256'])
        self.assertIn('log:busy_timeout',self.actions('uid_export_busy_timeout'))

    def test_fixture_bounds_and_null_uid_precondition(self):
        c=self.cases['uid_candidate_3']
        for changes in (dict(statuses=[]),dict(present=False),dict(overrides=dict(uid_size=130)),dict(level=-1)):
            with self.assertRaises(ValueError):contract(c|changes)

    def test_public_native_observations_match_all_cases(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-identity-native.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(86,86))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['byte_range_sha256']),len(report['export_sha256'])),(15,14))


if __name__=='__main__':unittest.main()
