import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.nand_identity import uid_bytes
from analysis_scripts.nand_identity_stack import contract,native_vectors
from analysis_scripts.nand_read_stack import BOUND


class NandIdentityStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]
    def e0(self,name):return self.row(name)['feature_registers']['224']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)

    def test_only_original_candidate_three_matches_supported_retry_family(self):
        for index in range(11):
            name='compat_original_'+str(index);self.result(name,0 if index==3 else -1)
            self.assertEqual(self.opcodes(name),[])
        self.result('compat_absent',-1)

    def test_level_write_uses_actual_feature_fifo_and_preserves_upper_bits(self):
        name='level_write_verify';self.result(name,0);self.assertEqual(self.e0(name),0xa1)
        self.assertEqual(self.opcodes(name),[15,31,15]);self.assertEqual(self.row(name)['tx_hex'],'a1')

    def test_matching_level_avoids_feature_write(self):
        name='level_already_set';self.assertEqual(self.opcodes(name),[15]);self.assertEqual(self.row(name)['tx_hex'],'')

    def test_five_unconfirmed_writes_still_return_zero(self):
        name='level_unconfirmed';self.result(name,0);self.assertEqual(self.e0(name),0)
        self.assertEqual(self.opcodes(name).count(31),5);self.assertEqual(self.actions(name).count('log:level_mismatch'),5)
        self.assertEqual(self.row(name)['e0_reads'],6)

    def test_scripted_readback_can_make_second_attempt_succeed(self):
        name='level_second_attempt';self.result(name,0);self.assertEqual(self.opcodes(name).count(31),2)
        self.assertEqual(self.actions(name).count('log:level_mismatch'),1);self.assertEqual(self.e0(name),1)

    def test_level_three_is_rejected_before_bus_access(self):
        self.result('level_3',-1);self.assertEqual(self.opcodes('level_3'),[])

    def test_other_outside_levels_are_not_rejected_and_can_spill_upper_bits(self):
        for name,expected in (('level_4',0xa4),('level_8',0xa8),('level_256',0xa0),('level_4294967295',255)):
            self.result(name,0);self.assertEqual(self.e0(name),expected)

    def test_retry_reloads_page_for_each_level_and_restores_zero(self):
        for name,loads in (('retry_first',1),('retry_second',2),('retry_third',3)):
            self.result(name,0);self.assertEqual(self.opcodes(name).count(19),loads)
            self.assertEqual(self.e0(name)&7,0);self.assertIn('log:retry_valid',self.actions(name))

    def test_all_bad_retry_returns_minus_one_after_restoring_level_zero(self):
        name='retry_all_bad';self.result(name,-1);self.assertEqual(self.opcodes(name).count(19),3)
        self.assertEqual(self.e0(name)&7,0);self.assertEqual(self.actions(name)[-1],'log:retry_invalid')

    def test_unsupported_retry_never_submits_a_command(self):
        self.result('retry_unsupported',-1);self.assertEqual(self.opcodes('retry_unsupported'),[])

    def test_retry_accepts_unchanged_register_after_setter_exhaustion(self):
        name='retry_unconfirmed_level';self.result(name,0);self.assertEqual(self.e0(name),1)
        self.assertEqual(self.actions(name).count('log:level_mismatch'),10)

    def test_complete_busy_timeout_can_become_successful_retry(self):
        name='retry_busy_timeout';self.result(name,0);self.assertEqual(self.row(name)['status_reads'],2000)
        self.assertIn('log:busy_timeout',self.actions(name));self.assertIn('log:retry_valid',self.actions(name))

    def test_reset_check_uses_original_reset_builders_then_optional_setter(self):
        self.assertEqual(self.opcodes('check_zero'),[0x66,0x99,15])
        self.assertIn('delay:1000',self.actions('check_zero'));self.assertIn('delay:5000',self.actions('check_zero'))
        self.assertEqual(self.e0('check_nonzero'),0);self.result('check_nonzero',0)
        self.result('check_unconfirmed',0);self.assertEqual(self.e0('check_unconfirmed'),2)

    def test_read_recovery_reloads_mapped_page_then_transfers_and_returns_zero(self):
        name='read_retry_success';self.result(name,0);self.assertEqual(self.opcodes(name).count(19),2)
        self.assertIn('w:0:4:792',self.actions(name));self.assertIn('log:workaround_ok',self.actions(name))
        self.assertEqual(self.opcodes(name)[-1],0x6b)

    def test_read_can_recover_at_last_retry_level_or_return_minus_101(self):
        self.result('read_retry_last_level',0);self.assertEqual(self.opcodes('read_retry_last_level').count(19),4)
        name='read_retry_all_bad';self.result(name,-101);self.assertEqual(self.opcodes(name)[-1],0x6b)
        self.assertNotIn('log:workaround_ok',self.actions(name));self.assertEqual(self.actions(name)[-1],'log:page_result')

    def test_private_read_recovery_connects_dma_without_inventing_payload(self):
        name='read_retry_private';self.result(name,0);self.assertIn('copy_from_bounce:64',self.actions(name))
        buffer=bytearray((i*3+1)&255 for i in range(512));buffer[:64]=b'\xa5'*64
        self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(buffer).hexdigest())

    def test_all_original_uid_flags_and_feature_sequences_execute_through_fifo(self):
        for index in range(11):
            name='uid_original_'+str(index);c=self.cases[name];p=c['identity_descriptor']
            self.assertIsNone(self.row(name)['returned'])
            if p['uid_flag']:
                self.assertEqual(self.opcodes(name),[31,15,19,15,3]);self.assertEqual(self.row(name)['uid_length'],16)
                reg,value=p['sequence'][0];self.assertEqual(self.row(name)['feature_registers'][str(reg)],value)
            else:self.assertEqual(self.opcodes(name),[]);self.assertEqual(self.row(name)['uid_length'],16)

    def test_uid_complement_validation_selects_first_second_or_last_copy(self):
        for name,index in (('uid_original_3',0),('uid_second',1),('uid_last',15)):
            self.assertEqual(self.row(name)['uid_length'],16);self.assertEqual(self.opcodes(name).count(3),index+1)
            self.assertEqual(self.row(name)['uid_sha256'],hashlib.sha256(uid_bytes(index,True)+b'\xa5'*96).hexdigest())
            self.assertEqual(sum(a.startswith('format:') for a in self.actions(name)),16)

    def test_invalid_uid_copies_clear_length_but_leave_last_invalid_data(self):
        name='uid_invalid';self.assertEqual(self.row(name)['uid_length'],0);self.assertEqual(self.opcodes(name).count(3),16)
        self.assertEqual(self.row(name)['uid_sha256'],hashlib.sha256(uid_bytes(15,False)+b'\xa5'*96).hexdigest())
        self.assertIn('log:uid_error:-200',self.actions(name))

    def test_uid_early_errors_preserve_prior_length_and_data(self):
        for name in ('uid_mismatch','uid_ecc_bad','uid_size_overflow','uid_mode_other'):
            self.assertEqual(self.row(name)['uid_length'],16);self.assertEqual(self.row(name)['uid_sha256'],hashlib.sha256(b'\xa5'*128).hexdigest())
            self.assertNotIn(3,self.opcodes(name))

    def test_uid_full_busy_timeout_can_still_publish_authored_uid(self):
        name='uid_busy_timeout';self.assertEqual(self.row(name)['uid_length'],16)
        self.assertEqual(self.row(name)['status_reads'],2000);self.assertIn('log:busy_timeout',self.actions(name))
        self.assertTrue(any(a.startswith('log:uid_ok:') for a in self.actions(name)))

    def test_nonstandard_uid_size_and_zero_copies_report_success_with_zero_length(self):
        for name in ('uid_size_other','uid_zero_copies'):
            self.assertEqual(self.row(name)['uid_length'],0);self.assertNotIn(3,self.opcodes(name))
            self.assertIn('log:uid_ok:0:',self.actions(name))

    def test_uid_ioctl_copies_acquired_length_and_bytes(self):
        name='uid_export';self.result(name,0);self.assertIn('copy_uid:16',self.actions(name))
        buffer=bytearray((i*3+1)&255 for i in range(512));buffer[0]=16;buffer[1:17]=uid_bytes(0,True)[:16]
        self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(buffer).hexdigest())

    def test_uid_ioctl_can_export_stale_data_after_early_acquisition_failure(self):
        name='uid_export_stale';self.result(name,0);self.assertIn('log:uid_error:-5',self.actions(name))
        self.assertIn('copy_uid:16',self.actions(name))
        buffer=bytearray((i*3+1)&255 for i in range(512));buffer[0]=16;buffer[1:17]=b'\xa5'*16
        self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(buffer).hexdigest())

    def test_uid_ioctl_rejects_disabled_descriptor_and_exports_zero_after_invalid_data(self):
        self.result('uid_export_disabled',-201);self.assertIn('log:ioctl_error',self.actions('uid_export_disabled'))
        self.result('uid_export_invalid',0);self.assertIn('copy_uid:0',self.actions('uid_export_invalid'))

    def test_lower_errors_stop_at_original_assertions(self):
        for name,line in (('retry_get_assertion',0x12a),('uid_feature_assertion',0x132),('uid_verify_assertion',0x12a),('uid_load_assertion',0x11f),('uid_cache_assertion',0x12a),('retry_restore_assertion',0x12a)):
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=line))

    def test_restore_assertion_overrides_prior_retry_success(self):
        name='retry_restore_assertion';self.assertIn('log:retry_valid',self.actions(name))
        self.assertIsNone(self.row(name)['returned']);self.assertNotIn('log:restore_failed',self.actions(name))

    def test_cache_assertion_occurs_after_uid_length_clear_and_zeroing(self):
        name='uid_cache_assertion';self.assertEqual(self.row(name)['uid_length'],0)
        self.assertIn('zero_uid:32',self.actions(name));self.assertEqual(self.row(name)['uid_sha256'],hashlib.sha256(bytes(32)+b'\xa5'*96).hexdigest())

    def test_contract_rejects_unbounded_or_inconsistent_identity_backing(self):
        base=self.cases['uid_export']
        for change in (dict(chip=False),dict(initial_uid_length=129),dict(responses=[]),dict(e0_reads=[256]),dict(identity_descriptor={}),dict(count=65),dict(bbt_hex='00'),dict(first_good=16),dict(native_platform=False)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_committed_native_evidence_matches_all_regenerated_fixtures(self):
        execution=json.loads(Path('analysis/nand-identity-stack.json').read_bytes())['native_validation']
        self.assertIs(execution['hardware_execution'],False);self.assertEqual(execution['bound_per_case'],BOUND)
        self.assertEqual(execution['case_count'],len(self.cases));self.assertEqual(len(execution['cases']),len(self.cases))
        for case in execution['cases']:
            self.assertEqual(case['observed'],self.cases[case['name']]['expected']);self.assertTrue(0<case['steps']<=BOUND)


if __name__=='__main__':unittest.main()
