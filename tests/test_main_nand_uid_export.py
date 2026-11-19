import copy
import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts import main_nand_uid_export as export


class MainNandUidExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name'].removeprefix('main_uid_export_'):c for c in export.native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][-1]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def output(self,name):return bytes.fromhex(self.row(name)['export_hex'])

    def test_valid_export_has_length_byte_and_sixteen_uid_bytes(self):
        data=export.aux.policy.uid_bytes(0,True);self.assertEqual(self.output('first_copy'),b'\x10'+data[:16]+b'\xa5'*112)
        self.assertEqual(self.row('first_copy')['returned'],0)

    def test_last_valid_copy_exports_selected_identity_bytes(self):
        data=export.aux.policy.uid_bytes(15,True);self.assertEqual(self.output('last_copy')[1:17],data[:16])
        self.assertEqual(self.row('last_copy')['aux_uid_caches'],16)

    def test_context_lock_and_chip_dispatch_surround_copy(self):
        a=self.actions('first_copy');start=a.index('main_uid_export_native')
        self.assertEqual(a[start:],['main_uid_export_native','main_lower_native:24','main_irq:0','main_scheduler:0','main_acquire:0','main_chip_native:24','copy_uid:16','main_release:0'])

    def test_feature_error_exports_retained_prior_state_successfully(self):
        r=self.row('stale_mismatch');self.assertEqual((r['returned'],r['aux_uid_length']),(0,17))
        self.assertEqual(self.output('stale_mismatch'),b'\x11'+b'\xa5'*128)
        self.assertIn('log:uid_feature_error:-7',self.actions('stale_mismatch'))

    def test_ecc_error_also_exports_prior_state(self):
        self.assertEqual(self.output('stale_ecc'),self.output('stale_mismatch'));self.assertEqual(self.row('stale_ecc')['returned'],0)
        self.assertIn('log:uid_error:-101',self.actions('stale_ecc'))

    def test_invalid_copies_return_zero_length_without_copying_bad_payload(self):
        self.assertEqual(self.output('no_valid_copy'),b'\0'+b'\xa5'*128);self.assertEqual(self.row('no_valid_copy')['returned'],0)
        self.assertIn('copy_uid:0',self.actions('no_valid_copy'));self.assertEqual(self.row('no_valid_copy')['aux_uid_caches'],16)

    def test_original_no_uid_flag_returns_minus_201_without_writing(self):
        r=self.row('disabled');self.assertEqual(r['returned'],(-201)&0xffffffff);self.assertEqual(self.output('disabled'),b'\xa5'*129)
        self.assertFalse(r['aux_uid_entered']);self.assertNotIn('copy_uid:17',self.actions('disabled'))

    def test_zero_prior_length_is_exported_after_handled_feature_error(self):
        self.assertEqual(self.output('stale_empty'),b'\0'+b'\xa5'*128);self.assertIn('copy_uid:0',self.actions('stale_empty'))

    def test_maximum_authored_prior_backing_is_bounded_but_not_revalidated(self):
        self.assertEqual(self.output('stale_full_backing'),b'\x80'+b'\xa5'*128);self.assertIn('copy_uid:128',self.actions('stale_full_backing'))
        self.assertEqual(self.row('stale_full_backing')['returned'],0)

    def test_successful_export_preserves_uid_source_hash(self):
        for c in self.cases.values():
            rows=c['expected']['rows'];self.assertTrue(all(r['aux_uid_sha256']==rows[0]['aux_uid_sha256'] for r in rows))
            self.assertTrue(all(r['aux_uid_length']==rows[0]['aux_uid_length'] for r in rows))

    def test_export_after_geometry_and_close_does_not_require_open_reference(self):
        rows=self.cases['geometry_and_repeat']['expected']['rows'];self.assertEqual(len(rows),6)
        self.assertEqual(int.from_bytes(bytes.fromhex(rows[3]['object_hex'])[48:52],'little'),0)
        self.assertEqual((rows[4]['returned'],rows[5]['returned']),(0,0));self.assertEqual(rows[4]['export_hex'],rows[5]['export_hex'])
        self.assertEqual((rows[4]['export_calls'],rows[5]['export_calls']),(1,2))

    def test_context_irq_and_scheduler_paths_bypass_mutex(self):
        for name in ('irq','scheduler'):
            a=self.actions(name);a=a[a.index('main_uid_export_native'):];self.assertNotIn('main_acquire:0',a);self.assertNotIn('main_release:0',a)
            self.assertEqual(self.row(name)['returned'],0)
        a=self.actions('irq');self.assertNotIn('main_scheduler:1',a)

    def test_acquire_error_stops_before_copy_or_chip_dispatch(self):
        r=self.row('acquire_error');self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30f20,line=36))
        self.assertEqual(self.output('acquire_error'),b'\xa5'*129);self.assertNotIn('main_chip_native:24',self.actions('acquire_error'))

    def test_release_error_keeps_already_exported_bytes_without_normal_return(self):
        r=self.row('release_error');self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30f08,line=42))
        self.assertEqual(self.output('release_error'),self.output('first_copy'));self.assertIn('copy_uid:16',self.actions('release_error'))

    def test_selected_original_families_reach_same_uid_export_contract(self):
        for name in ('supported_family','dosilicon','esmt'):
            self.assertEqual(self.output(name),self.output('first_copy'));self.assertEqual(self.row(name)['returned'],0)

    def test_export_rows_distinguish_preexport_buffer_from_copied_buffer(self):
        rows=self.cases['first_copy']['expected']['rows'];self.assertEqual(rows[0]['export_hex'],'a5'*129)
        self.assertEqual((rows[0]['export_calls'],rows[1]['export_calls']),(0,1));self.assertNotEqual(rows[0]['export_hex'],rows[1]['export_hex'])

    def test_contract_rejects_null_destination_transport_injection_and_oversized_prior(self):
        c=self.cases['first_copy'];before=copy.deepcopy(c)
        for change in (dict(native_main_uid_export=False),dict(full_ready_fail_at=7),dict(initial_uid_length=129),dict(main_alloc_fail=True)):
            with self.subTest(change=change),self.assertRaises(ValueError):export.contract(c|change)
        bad=copy.deepcopy(c);bad['operations'][-1]['output']=False
        with self.assertRaises(ValueError):export.contract(bad)
        export.contract(c);self.assertEqual(c,before)

    def test_native_evidence_matches_independent_model_and_guards(self):
        e=json.loads(Path('analysis/main-nand-uid-export.json').read_bytes());report=e['native_validation'];self.assertIs(report['hardware_execution'],False)
        self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:
            self.assertEqual(row['observed'],self.cases[row['name'].removeprefix('main_uid_export_')]['expected']);self.assertTrue(0<row['steps']<=export.aux.joined.BOUND)
        previous=json.loads(Path('analysis/main-nand-aux-uid.json').read_bytes())
        for key in ('byte_range_sha256','data_range_sha256'):self.assertEqual(e[key],previous[key])
        self.assertEqual(e['inventory_sha256'],hashlib.sha256(export.aux.FACTS.read_bytes()).hexdigest())


if __name__=='__main__':unittest.main()
