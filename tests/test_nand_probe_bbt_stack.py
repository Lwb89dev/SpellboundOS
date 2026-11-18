import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_probe_bbt_stack import contract,native_vectors,probe,recovery


class NandProbeBbtStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def magic(self,name):return struct.unpack_from('<I',bytes.fromhex(self.row(name)['bbt_state_hex']))[0]
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)

    def test_probe_executes_actual_unsupported_family_workaround_and_primary_bbt(self):
        name='probe_bbt_primary';self.result(name,0);r=self.row(name)
        self.assertEqual(r['probe_selected'],probe.CHIPS[0]['address']);self.assertEqual(r['bbt_resume_result'],0)
        self.assertEqual(self.magic(name),recovery.bbt.MAGIC);self.assertEqual(r['probe_guard_pages'],512)
        self.assertIn('probe_workaround_native',self.actions(name));self.assertEqual(self.actions(name).count('compare20:-1'),2)

    def test_actual_no_bbt_return_one_is_ignored_by_probe_and_wrapper(self):
        for name in ('probe_bbt_no_records','probe_bbt_no_records_wrapper'):
            self.result(name,0);r=self.row(name);self.assertEqual(r['bbt_resume_result'],1)
            self.assertEqual(self.magic(name),0);self.assertEqual(r['probe_guard_pages'],512)
        self.assertEqual(self.row('probe_bbt_no_records_wrapper')['probe_mutex'],probe.inventory.MUTEX)

    def test_probe_backup_repair_captures_feature_bytes_followed_by_record(self):
        name='probe_bbt_backup';self.result(name,0)
        self.assertEqual(bytes.fromhex(self.row(name)['tx_hex']),bytes([0,24])+recovery.bbt.record(dict(bad=[1,3,7])))
        self.assertEqual(self.magic(name),recovery.bbt.MAGIC)

    def test_actual_bbt_repair_failures_still_allow_probe_success_and_guard_counts(self):
        for name in ('probe_bbt_erase_error','probe_bbt_program_error','probe_bbt_reread_error'):
            self.result(name,0);r=self.row(name);self.assertEqual(r['bbt_resume_result'],0)
            self.assertEqual(self.magic(name),recovery.bbt.MAGIC);self.assertEqual(r['probe_guard_blocks'],8)
            self.assertIn('log:bbt_repair_failed',self.actions(name));self.assertNotIn('log:probe_error',self.actions(name))

    def test_bbt_assertion_stops_probe_before_guard_and_mutex_publication(self):
        name='probe_bbt_no_good';r=self.row(name);self.assertIsNone(r['returned']);self.assertIsNone(r['bbt_resume_result'])
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c3d3b0,line=0xac))
        self.assertEqual(r['probe_selected'],probe.CHIPS[0]['address']);self.assertEqual((r['probe_guard_pages'],r['probe_mutex']),(0,0))
        self.assertFalse(any(a.startswith('probe_mutex_create:') for a in self.actions(name)))

    def test_feature_mismatch_does_not_enter_bbt_resume(self):
        name='probe_bbt_feature_mismatch';self.result(name,-7);self.assertIsNone(self.row(name)['bbt_resume_result'])
        self.assertEqual(self.row(name)['probe_guard_pages'],0)
        self.assertFalse(any(a.startswith('bbt_resume:') for a in self.actions(name)))

    def test_supplied_uid_error_remains_ignored_with_actual_bbt(self):
        name='probe_bbt_uid_error_ignored';self.result(name,0);self.assertIn('probe_uid:-9',self.actions(name))
        self.assertEqual(self.row(name)['bbt_resume_result'],0)

    def test_explicit_supplied_workaround_case_keeps_service_boundary(self):
        name='probe_bbt_workaround_supplied';self.result(name,0)
        self.assertIn('probe_workaround:-9',self.actions(name));self.assertNotIn('probe_workaround_native',self.actions(name))

    def test_wrapper_mutex_creation_follows_actual_bbt_completion(self):
        name='probe_bbt_wrapper';self.result(name,0);a=self.actions(name)
        self.assertLess(a.index('log:bbt_loaded'),a.index('probe_mutex_create:1'))
        self.assertEqual(self.row(name)['probe_mutex'],probe.inventory.MUTEX)

    def test_contract_rejects_other_chip_and_incompatible_entry_scopes(self):
        base=self.cases['probe_bbt_primary']
        for change in (dict(probe_id=probe.CHIPS[1]['id']),dict(probe_delayed_rounds=1),dict(native_dispatch=True),dict(bbt_follow_read=True),dict(native_probe=False)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_and_keeps_main_caller_buffer_immutable(self):
        report=json.loads(Path('analysis/nand-probe-bbt-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for row in report['cases']:
            self.assertEqual(row['observed'],self.cases[row['name']]['expected']);self.assertEqual(row['observed']['rows'][0]['buffer_sha256'],expected)


if __name__=='__main__':unittest.main()
