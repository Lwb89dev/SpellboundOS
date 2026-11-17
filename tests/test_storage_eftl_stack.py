import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.storage_eftl_stack import contract,native_vectors


class StorageEftlStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def buffer_hash(self,data):
        b=bytearray((i*3+1)&255 for i in range(512));b[:len(data)]=data;return hashlib.sha256(b).hexdigest()
    def pattern(self,n):return bytes((0x5a+i*7)&255 for i in range(n))

    def test_original_nvms_envbak_recovery_rows_reach_actual_eftl_callback(self):
        for name,address in (('storage_nvms',16),('storage_envbak',262160),('storage_recovery',524304)):
            self.result(name,32);self.assertIn(f'storage_backend_read:{address}:32',self.actions(name))
            self.assertEqual(self.row(name)['storage_backend_calls'],1);self.assertEqual(self.row(name)['driver_calls'],1)

    def test_registry_row_and_backend_inputs_remain_identical_across_selected_handles(self):
        for name in ('storage_envbak','storage_recovery'):
            for field in ('storage_table_sha256','storage_backend_sha256','storage_owners_sha256'):
                self.assertEqual(self.row(name)[field],self.row('storage_nvms')[field])

    def test_end_clamp_returns_delivered_prefix_and_not_requested_count(self):
        name='storage_end_clamp';self.result(name,8)
        self.assertIn('storage_backend_read:262136:8',self.actions(name))
        self.assertEqual(self.row(name)['buffer_sha256'],self.buffer_hash(self.pattern(8)))

    def test_unsigned_request_overflow_is_clamped_before_backend(self):
        name='storage_request_overflow_clamp';self.result(name,8)
        self.assertEqual(self.row(name)['buffer_sha256'],self.row('storage_end_clamp')['buffer_sha256'])
        self.assertIn('storage_backend_read:262136:8',self.actions(name))

    def test_offset_at_or_after_end_fails_before_backend(self):
        for name in ('storage_at_end','storage_after_end','storage_zero_at_end'):
            self.result(name,-1);self.assertEqual(self.row(name)['storage_backend_calls'],0)
            self.assertIn('log:storage_bounds',self.actions(name));self.assertNotIn('log:storage_read_error',self.actions(name))

    def test_zero_request_at_valid_offset_still_calls_eftl_wrapper(self):
        name='storage_zero';self.result(name,0);self.assertEqual(self.row(name)['storage_backend_calls'],1)
        self.assertEqual(self.row(name)['driver_calls'],0);self.assertIn('storage_backend_read:16:0',self.actions(name))

    def test_zero_declared_span_uses_authored_runtime_capacity(self):
        self.result('storage_derived_span',32);self.result('storage_derived_end',8)
        self.assertIn('storage_backend_read:1048568:8',self.actions('storage_derived_end'))
        self.assertNotEqual(self.row('storage_derived_span')['storage_table_sha256'],self.row('storage_nvms')['storage_table_sha256'])

    def test_explicit_small_span_is_clamped_at_byte_granularity(self):
        name='storage_small_span';self.result(name,4)
        self.assertIn('storage_backend_read:60:4',self.actions(name));self.assertEqual(self.row(name)['buffer_sha256'],self.buffer_hash(self.pattern(4)))

    def test_missing_owner_fails_check_without_backend_error_log(self):
        name='storage_owner_missing';self.result(name,-1);self.assertEqual(self.row(name)['storage_backend_calls'],0)
        self.assertIn('log:storage_no_owner',self.actions(name));self.assertNotIn('log:storage_read_error',self.actions(name))

    def test_null_and_outside_handles_stop_at_original_assertions(self):
        for name,line,owner in (('storage_handle_null',0xd0,0x80c3c378),('storage_handle_below',0x7d,0x80c3c340),('storage_handle_above',0x7e,0x80c3c340),('storage_null_output',0xd1,0x80c3c378)):
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertIn('storage_diagnostic:'+str(line),self.actions(name));self.assertEqual(self.row(name)['storage_backend_calls'],0)

    def test_unmapped_read_returns_zero_after_filling_ff_without_outer_error(self):
        name='storage_unmapped';self.result(name,0)
        self.assertEqual(self.row(name)['buffer_sha256'],self.buffer_hash(b'\xff'*32))
        self.assertIn('log:unmapped_block',self.actions(name));self.assertNotIn('log:storage_read_error',self.actions(name))

    def test_gap_returns_short_count_and_outer_read_accepts_it(self):
        name='storage_gap_after_prefix';self.result(name,8)
        self.assertEqual(self.row(name)['buffer_sha256'],self.buffer_hash(self.pattern(8)+b'\xff'*24))
        self.assertNotIn('log:storage_read_error',self.actions(name))

    def test_negative_lower_error_crosses_both_eftl_and_storage_error_logs(self):
        name='storage_lower_error';self.result(name,-1)
        self.assertIn('log:page_read_error',self.actions(name));self.assertEqual(self.actions(name)[-1],'log:storage_read_error')

    def test_fast_context_can_bypass_missing_driver_under_upper_storage(self):
        name='storage_fast_bypass';self.result(name,32);self.assertEqual(self.row(name)['driver_calls'],0)
        self.assertEqual(self.row(name)['buffer_sha256'],self.buffer_hash(self.pattern(32)))

    def test_ecc_failure_can_modify_buffer_before_upper_storage_error(self):
        name='storage_ecc_error';self.result(name,-1)
        self.assertEqual(self.row(name)['buffer_sha256'],self.buffer_hash(self.pattern(32)))
        self.assertEqual(self.actions(name)[-1],'log:storage_read_error')

    def test_two_page_and_deferred_paths_reach_lower_stack(self):
        self.result('storage_two_pages',32);self.assertEqual(self.row('storage_two_pages')['driver_calls'],2)
        self.result('storage_deferred',32);self.assertEqual(self.row('storage_deferred')['reinit_flag'],0)

    def test_contract_rejects_unbacked_storage_reads(self):
        base=self.cases['storage_nvms']
        for change in (dict(storage_name='backup'),dict(storage_handle='middle'),dict(storage_size=65),dict(storage_offset=-1),dict(storage_capacity=1048577),dict(storage_span=-2)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_regenerated_fixtures(self):
        report=json.loads(Path('analysis/storage-eftl-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases))
        self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:self.assertEqual(row['observed'],self.cases[row['name']]['expected'])


if __name__=='__main__':unittest.main()
