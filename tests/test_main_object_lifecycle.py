import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_object_lifecycle as main


class MainObjectLifecycleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={scope:{c['name']:c for c in main.native_vectors(scope)['cases']} for scope in ('callbacks','nand')}
    def case(self,name):return self.cases['nand' if name.startswith('nand_main') else 'callbacks'][name]
    def rows(self,name):return self.case(name)['expected']['rows']
    def actions(self,name):return self.case(name)['expected']['actions']
    def returns(self,name):return [r['returned'] for r in self.rows(name)]
    def refs(self,name):return [struct.unpack_from('<I',bytes.fromhex(r['object_hex']),48)[0] for r in self.rows(name)]
    def output(self,name,index=-1):return bytes.fromhex(self.rows(name)[index]['output_hex'])
    def geometry(self,flag=1,capacity=0x08000000):
        b=bytearray(b'\xa5'*32);struct.pack_into('<I',b,0,0xbaef);struct.pack_into('<I',b,8,capacity);b[12]=flag;return bytes(b)

    def test_open_close_active_and_closed_ioctl(self):
        name='main_open_close';self.assertEqual(self.returns(name),[0,1,0,0,0xfffffff2]);self.assertEqual(self.refs(name),[1,1,0,0,0])
        self.assertEqual(self.actions(name).count('callback:close:0'),1)

    def test_only_last_close_calls_backend(self):
        name='main_two_refs';self.assertEqual(self.refs(name),[1,2,1,1,0,0])
        self.assertEqual(self.actions(name).count('callback:open:4660:0'),1);self.assertEqual(self.actions(name).count('callback:close:0'),1)

    def test_close_error_retains_zero_count_and_blocks_retry_and_ioctl(self):
        name='main_close_error';self.assertEqual(self.returns(name),[0xfffffff7,0,0xfffffff2,0xfffffff2]);self.assertEqual(self.refs(name),[0]*4)
        self.assertEqual(self.actions(name).count('callback:close:-9'),1)

    def test_reopening_after_close_error_calls_open_again(self):
        name='main_reopen_after_close_error';self.assertEqual(self.returns(name),[0xfffffff7,0,1]);self.assertEqual(self.refs(name),[0,1,1])
        self.assertIn('callback:open:4660:0',self.actions(name))

    def test_absent_close_callback_or_table_keeps_positive_count(self):
        for name in ('main_missing_close','main_no_table'):
            self.assertEqual(self.returns(name),[0,1]);self.assertEqual(self.refs(name),[1,1])
            self.assertFalse(any(a.startswith('callback:close:') for a in self.actions(name)))

    def test_zero_and_negative_counts_reject_close(self):
        for name,refs in (('main_close_zero',0),('main_close_negative',0xffffffff)):
            self.assertEqual(self.returns(name),[0xfffffff2,0]);self.assertEqual(self.refs(name),[refs,refs])

    def test_missing_or_failed_open_does_not_publish_positive_count(self):
        for name,returned in (('main_open_missing',0),('main_open_error',0xfffffff7)):
            self.assertEqual(self.returns(name),[returned,0]);self.assertEqual(self.refs(name),[0,0])

    def test_negative_and_overflow_open_states_match_signed_active_query(self):
        self.assertEqual(self.returns('main_open_negative'),[0,0]);self.assertEqual(self.refs('main_open_negative'),[0,0])
        self.assertEqual(self.returns('main_open_overflow'),[0,0,0xfffffff2]);self.assertEqual(self.refs('main_open_overflow'),[0x80000000]*3)

    def test_write_propagates_backend_count_or_error_without_changing_references(self):
        for name,returned in (('main_write',8),('main_write_error',0xfffffff7)):
            self.assertEqual(self.returns(name),[returned]);self.assertEqual(self.refs(name),[1])
            self.assertTrue(any(a.startswith('callback:write:5:8:') for a in self.actions(name)))

    def test_closed_and_missing_write_paths_skip_backend(self):
        for name,returned in (('main_write_closed',0xfffffff2),('main_write_missing',0)):
            self.assertEqual(self.returns(name),[returned]);self.assertFalse(any(a.startswith('callback:write:') for a in self.actions(name)))

    def test_ioctl_error_preserves_authored_callback_output(self):
        self.assertEqual(self.returns('main_ioctl_error'),[0xfffffff7]);b=self.output('main_ioctl_error')
        self.assertEqual(struct.unpack_from('<I',b)[0],0x1001);self.assertEqual(b[4:],b'\xa5'*28)
        self.assertEqual(self.output('main_ioctl_missing'),b'\xa5'*32);self.assertEqual(self.returns('main_ioctl_closed'),[0xfffffff2])

    def test_null_pointers_assert_except_null_active_query(self):
        for kind,owner,line in (('open',0x70a441dc,297),('close',0x70a441bc,331),('write',0x70a4419c,400),('ioctl',0x70a4417c,491)):
            row=self.rows('main_null_'+kind)[0];self.assertIsNone(row['returned']);self.assertEqual(row['stopped'],dict(kind='assertion',owner=owner,line=line))
        self.assertEqual(self.returns('main_null_active'),[0]);self.assertEqual(self.rows('main_null_write_data')[0]['stopped']['line'],400)

    def test_original_main_nand_open_geometry_close_cycle(self):
        name='nand_main_cycle';self.assertEqual(self.returns(name),[0,0,0,0,0xfffffff2]);self.assertEqual(self.refs(name),[1,1,0,0,0])
        self.assertEqual(self.output(name),self.geometry());self.assertEqual(self.actions(name).count('nand:close'),1)

    def test_main_nand_multiple_references_delay_original_close(self):
        name='nand_main_two_refs';self.assertEqual(self.refs(name),[1,2,1,1,0,0]);self.assertEqual(self.actions(name).count('nand:close'),1)
        self.assertEqual(self.actions(name).count('nand:open'),1)

    def test_main_nand_can_reopen_after_original_close(self):
        name='nand_main_reopen';self.assertEqual(self.refs(name),[1,0,1,1]);self.assertEqual(self.actions(name).count('nand:open'),2)
        self.assertEqual(self.output(name),self.geometry())

    def test_unopened_main_nand_skips_method_and_lower_queries(self):
        name='nand_main_closed';self.assertEqual(self.returns(name),[0xfffffff2]);self.assertEqual(self.rows(name)[0]['lower_calls'],0)
        self.assertNotIn('nand:ioctl:4097',self.actions(name))

    def test_original_null_write_slot_returns_zero_without_callback(self):
        name='nand_main_write_slot';self.assertEqual(self.returns(name),[0,0,0]);self.assertEqual(self.output(name),b'\xa5'*32)
        self.assertFalse(any(a.startswith('callback:write:') for a in self.actions(name)))

    def test_authored_bbt_flag_and_geometry_alias(self):
        self.assertEqual(self.output('nand_main_no_bbt'),self.geometry(0));self.assertEqual(self.output('nand_main_alias'),self.geometry())

    def test_each_lower_query_failure_prevents_geometry_publication(self):
        for i in range(1,5):
            name='nand_main_query_error_'+str(i);self.assertEqual(self.returns(name),[0,0xfffffff7,0])
            self.assertEqual(self.output(name),b'\xa5'*32);self.assertEqual(self.rows(name)[1]['lower_calls'],i)
            self.assertEqual(self.refs(name),[1,1,0])

    def test_noop_invalid_and_null_output_commands_skip_lower_queries(self):
        for name,ret in (('nand_main_noop',0),('nand_main_invalid',0xfffffff6),('nand_main_null_output',0xfffffff6)):
            self.assertEqual(self.returns(name),[0,ret]);self.assertEqual(self.rows(name)[1]['lower_calls'],0)
            self.assertEqual(self.output(name),b'\xa5'*32)

    def test_geometry_multiplication_wraps_for_explicit_large_values(self):
        self.assertEqual(self.output('nand_main_wrapping_capacity'),self.geometry(capacity=0))

    def test_contract_rejects_unbounded_counts_data_and_foreign_scope(self):
        base=self.case('main_open_close')
        for change in (dict(count=-1),dict(count=1<<32),dict(operations=[]),dict(geometry=[1]*3),dict(lower_fail_at=5),dict(callbacks={}),dict(operations=base['operations']*3)):
            with self.subTest(change=change),self.assertRaises(ValueError):main.contract(base|change,'callbacks')
        bad=base['operations'][0]|dict(size=65)
        with self.assertRaises(ValueError):main.contract(base|dict(operations=[bad]),'callbacks')
        for fn in (main.names,main.ranges,main.data_ranges,main.native_vectors):
            with self.assertRaises(ValueError):fn('foreign')

    def test_original_names_and_nand_method_pointer_remain_in_captured_evidence(self):
        r=json.loads(Path('analysis/main-nand-object.json').read_bytes())
        self.assertEqual(r['function_names']['70a441bc'],'dev_obj_close');self.assertEqual(r['function_names']['70a30bac'],'dev_nand_close')
        for c in self.cases['nand'].values():
            for row in c['expected']['rows']:self.assertEqual(struct.unpack_from('<I',bytes.fromhex(row['object_hex']),40)[0],main.METHODS)

    def test_captured_native_reports_match_and_input_data_stays_immutable(self):
        digest=hashlib.sha256(bytes((i*3+1)&255 for i in range(64))).hexdigest()
        for scope,stem in (('callbacks','main-object-lifecycle'),('nand','main-nand-object')):
            evidence=json.loads(Path('analysis',stem+'.json').read_bytes());report=evidence['native_validation']
            self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases[scope]));self.assertEqual(len(report['cases']),len(self.cases[scope]))
            for c in report['cases']:
                self.assertEqual(c['observed'],self.cases[scope][c['name']]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],main.BOUND)
                for row in c['observed']['rows']:self.assertEqual(row['data_sha256'],digest)
            self.assertEqual(len(evidence['byte_range_sha256']),len(main.ranges(scope)));self.assertEqual(len(evidence['data_range_sha256']),len(main.data_ranges(scope)))


if __name__=='__main__':unittest.main()
