import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import nand_probe_uid_stack as aux


class NandProbeUidStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases={scope:{c['name']:c for c in aux.native_vectors(scope)['cases']} for scope in ('bbt','supported')}

    def case(self,name):return self.cases['bbt' if name.startswith('uid_bbt') else 'supported'][name]
    def row(self,name):return self.case(name)['expected']['rows'][0]
    def actions(self,name):return self.case(name)['expected']['actions']
    def uid_digest(self,index,valid=True):
        return hashlib.sha256(aux.identity.identity.uid_bytes(index,valid)+b'\xa5'*96).hexdigest()
    def exported_digest(self,length,data):
        b=bytearray((i*3+1)&255 for i in range(512));b[0]=length;b[1:1+length]=data[:length]
        return hashlib.sha256(b).hexdigest()

    def test_first_second_and_sixteenth_copies_verify_in_probe_before_bbt(self):
        for suffix,index in (('primary',0),('second_copy',1),('last_copy',15)):
            name='uid_bbt_'+suffix;r=self.row(name);a=self.actions(name)
            self.assertEqual((r['returned'],r['uid_length'],r['bbt_resume_result']),(0,16,0))
            self.assertEqual(r['uid_sha256'],self.uid_digest(index))
            self.assertEqual(a.count('zero_uid:32'),index+1)
            self.assertLess(a.index('probe_uid_native'),a.index('bbt_resume:1024:2048:64'))
            self.assertTrue(any(v.startswith(f'log:uid_ok:{index*32}:') for v in a))

    def test_all_invalid_copies_clear_length_but_keep_last_read_bytes(self):
        name='uid_bbt_no_valid_copy';r=self.row(name)
        self.assertEqual((r['returned'],r['uid_length'],r['bbt_resume_result']),(0,0,0))
        self.assertEqual(r['uid_sha256'],self.uid_digest(15,False));self.assertIn('log:uid_error:-200',self.actions(name))
        self.assertEqual(self.actions(name).count('zero_uid:32'),16)

    def test_empty_uid_export_writes_only_length_after_probe(self):
        name='uid_bbt_no_valid_copy';r=self.row(name)
        self.assertEqual(r['aux_export_return'],0);self.assertEqual(r['buffer_sha256'],self.exported_digest(0,b''))
        self.assertLess(self.actions(name).index('log:bbt_loaded'),self.actions(name).index('copy_uid:0'))

    def test_feature_and_ecc_errors_preserve_authored_prior_uid_and_export_it(self):
        for name,log in (('uid_bbt_feature_error','log:uid_error:-5'),('uid_bbt_ecc_error','log:uid_error:-101')):
            r=self.row(name);self.assertEqual((r['returned'],r['uid_length'],r['aux_export_return']),(0,17,0))
            self.assertEqual(r['uid_sha256'],hashlib.sha256(b'\xa5'*128).hexdigest())
            self.assertEqual(r['buffer_sha256'],self.exported_digest(17,b'\xa5'*17))
            self.assertIn(log,self.actions(name));self.assertNotIn('zero_uid:32',self.actions(name))
            self.assertEqual(r['bbt_resume_result'],0)

    def test_successful_export_contains_half_of_verified_complement_pair(self):
        name='uid_bbt_export';r=self.row(name)
        self.assertEqual(r['buffer_sha256'],self.exported_digest(16,aux.identity.identity.uid_bytes(0,True)))
        self.assertEqual((r['uid_length'],r['aux_export_return']),(16,0))

    def test_probe_restores_feature_table_after_uid_sequence(self):
        for name,value,tx in (('uid_bbt_primary',24,'480018'),('aux_supported_zero',25,'48001900')):
            r=self.row(name);self.assertEqual(r['probe_features']['176'],value)
            self.assertEqual(r['feature_registers'],r['probe_features']);self.assertEqual(r['tx_hex'],tx)

    def test_actual_no_table_result_is_ignored_even_after_valid_uid(self):
        r=self.row('uid_bbt_no_table');self.assertEqual((r['returned'],r['uid_length'],r['bbt_resume_result']),(0,16,1))
        self.assertEqual(struct.unpack_from('<I',bytes.fromhex(r['bbt_state_hex']))[0],0)
        self.assertEqual(r['probe_guard_pages'],512)

    def test_backup_repair_payload_follows_uid_and_probe_feature_bytes(self):
        r=self.row('uid_bbt_backup')
        self.assertEqual(bytes.fromhex(r['tx_hex']),bytes.fromhex('480018')+aux.joined.recovery.bbt.record(dict(bad=[1,3,7])))
        self.assertEqual(r['bbt_resume_result'],0)

    def test_repair_error_still_keeps_backup_magic_and_probe_success(self):
        name='uid_bbt_erase_error';r=self.row(name)
        self.assertEqual((r['returned'],r['uid_length'],r['bbt_resume_result']),(0,16,0))
        self.assertEqual(struct.unpack_from('<I',bytes.fromhex(r['bbt_state_hex']))[0],aux.joined.recovery.bbt.MAGIC)
        self.assertIn('log:bbt_repair_failed',self.actions(name));self.assertEqual(r['tx_hex'],'480018')

    def test_wrapper_publishes_mutex_after_uid_and_bbt(self):
        name='uid_bbt_wrapper';a=self.actions(name)
        self.assertLess(a.index('probe_uid_native'),a.index('log:bbt_loaded'))
        self.assertLess(a.index('log:bbt_loaded'),a.index('probe_mutex_create:1'))
        self.assertEqual(self.row(name)['probe_mutex'],aux.probe.inventory.MUTEX)

    def test_supported_workaround_reset_pair_and_delays_precede_uid(self):
        name='aux_supported_zero';a=self.actions(name);r=self.row(name)
        self.assertEqual(r['probe_selected'],aux.probe.CHIPS[3]['address'])
        self.assertLess(a.index('compare20:1'),a.index('compare20:0'))
        self.assertLess(a.index('delay:1000'),a.index('delay:5000'))
        self.assertLess(a.index('delay:5000'),a.index('probe_uid_native'))
        opcodes=[(int(v.rsplit(':',1)[1])>>24) for v in a if v.startswith('w:12:4:')]
        self.assertLess(opcodes.index(0x66),opcodes.index(0x99));self.assertEqual(r['e0_reads'],1)

    def test_supported_level_reset_is_written_and_read_back(self):
        r=self.row('aux_supported_level_reset');self.assertEqual(r['e0_reads'],3)
        self.assertEqual(r['probe_features']['224'],0);self.assertEqual(r['tx_hex'],'0048001900')
        r=self.row('aux_supported_second_level_attempt');self.assertEqual(r['e0_reads'],4)
        self.assertEqual(r['tx_hex'],'000048001900');self.assertEqual(r['returned'],0)

    def test_five_unconfirmed_level_writes_do_not_prevent_probe_or_uid_success(self):
        name='aux_supported_unconfirmed';r=self.row(name)
        self.assertEqual((r['returned'],r['uid_length'],r['e0_reads']),(0,16,7))
        self.assertEqual(r['probe_features']['224'],2);self.assertEqual(r['tx_hex'],'000000000048001900')
        self.assertEqual(self.actions(name).count('log:level_mismatch'),5)

    def test_supported_second_uid_copy_uses_original_descriptor(self):
        name='aux_supported_uid_second';r=self.row(name)
        self.assertEqual(r['uid_sha256'],self.uid_digest(1));self.assertEqual(r['uid_length'],16)
        self.assertEqual(self.case(name)['identity_descriptor'],aux.identity.identity.facts()[3])

    def test_supported_uid_errors_preserve_prior_state(self):
        for name,status_reads in (('aux_supported_uid_ecc',1),('aux_supported_uid_feature_error',0)):
            r=self.row(name);self.assertEqual((r['returned'],r['uid_length'],r['status_reads']),(0,17,status_reads))
            self.assertEqual(r['buffer_sha256'],self.exported_digest(17,b'\xa5'*17))
            self.assertEqual(r['aux_export_return'],0)

    def test_supported_invalid_uid_and_valid_export_are_distinct(self):
        r=self.row('aux_supported_no_uid_copy');self.assertEqual((r['returned'],r['uid_length']),(0,0))
        self.assertEqual(r['uid_sha256'],self.uid_digest(15,False))
        r=self.row('aux_supported_export');self.assertEqual(r['buffer_sha256'],self.exported_digest(16,aux.identity.identity.uid_bytes(0,True)))

    def test_supported_bbt_remains_supplied_and_its_error_is_ignored(self):
        name='aux_supported_bbt_error_ignored';r=self.row(name)
        self.assertEqual(r['returned'],0);self.assertNotIn('bbt_resume_result',r)
        self.assertIn('probe_bbt:2048:4096:64:-9',self.actions(name))
        self.assertFalse(self.case(name).get('native_bbt_stack',False))

    def test_probe_does_not_change_caller_buffer_without_explicit_export(self):
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for cases in self.cases.values():
            for c in cases.values():
                if not c['aux_export_uid']:
                    self.assertEqual(c['expected']['rows'][0]['buffer_sha256'],expected)
                    self.assertIsNone(c['expected']['rows'][0]['aux_export_return'])

    def test_contract_rejects_changed_chip_descriptor_state_and_foreign_scopes(self):
        base=self.case('uid_bbt_primary')
        for change in (dict(probe_id=aux.probe.CHIPS[3]['id']),dict(probe_delayed_rounds=1),dict(native_probe_aux=False),
                       dict(native_identity=False),dict(initial_uid_length=129),dict(first_good=16),dict(e0=256),
                       dict(e0_reads=[0]*17),dict(uid_feature_write_error=True),dict(identity_descriptor={})):
            with self.subTest(change=change),self.assertRaises(ValueError):aux.contract(base|change,'bbt')
        for fn in (aux.ranges,aux.data_ranges,aux.native_vectors):
            with self.assertRaises(ValueError):fn('unknown')
        with self.assertRaises(ValueError):aux.contract(base,'unknown')

    def test_captured_native_reports_match_both_independent_models(self):
        for scope,stem in (('bbt','nand-probe-uid-bbt'),('supported','nand-probe-aux')):
            evidence=json.loads(Path('analysis',stem+'.json').read_bytes());report=evidence['native_validation']
            self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases[scope]))
            self.assertEqual(len(report['cases']),len(self.cases[scope]))
            for c in report['cases']:
                self.assertEqual(c['observed'],self.cases[scope][c['name']]['expected'])
                self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],report['bound_per_case'])
            self.assertEqual(len(evidence['byte_range_sha256']),len(aux.ranges(scope)))
            self.assertEqual(len(evidence['data_range_sha256']),len(aux.data_ranges(scope)))


if __name__=='__main__':unittest.main()
