import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import nand_object_lifetime as life


class NandObjectLifetimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={scope:{c['name']:c for c in life.native_vectors(scope)['cases']} for scope in ('open','consumer')}
    def case(self,name):return self.cases['consumer' if name.startswith('consumer_') else 'open'][name]
    def row(self,name):return self.case(name)['expected']['rows'][0]
    def actions(self,name):return self.case(name)['expected']['actions']
    def calls(self,name):return self.row(name)['lifetime_calls']
    def node(self,name,slot):return bytes.fromhex(self.row(name)['object_nodes_hex'][str(slot)])
    def results(self,name):return [c['returned'] for c in self.calls(name)]
    def geometry(self,active=1):
        b=bytearray(b'\xa5'*32);struct.pack_into('<I',b,0,0xbaef);struct.pack_into('<I',b,8,0x08000000);b[12]=active;return bytes(b)

    def test_first_open_calls_backend_once_and_repeated_open_increments_count(self):
        name='open_first_and_repeat';calls=self.calls(name)
        self.assertEqual([c['counts'][0] for c in calls],[1,2,2]);self.assertEqual(self.results(name),[0,0,0])
        self.assertEqual(sum(a.startswith('life_callback_open:') for a in self.actions(name)),1)
        self.assertIn('life_callback_open:0:4660:0',self.actions(name))

    def test_open_callback_error_preserves_zero_reference_count(self):
        name='open_callback_error';self.assertEqual(self.results(name),[0xfffffff7]);self.assertEqual(self.calls(name)[0]['counts'][0],0)
        self.assertFalse(any(a=='log:object_open_failed' for a in self.actions(name)))

    def test_missing_method_table_or_open_callback_returns_success_without_opening(self):
        for name in ('open_no_table','open_no_callback'):
            self.assertEqual(self.results(name),[0,0xfffffff2]);self.assertEqual(self.calls(name)[0]['counts'][0],0)
            self.assertFalse(any(a.startswith('life_callback_open:') for a in self.actions(name)))

    def test_positive_existing_count_skips_failing_backend(self):
        name='open_existing_count';self.assertEqual(self.calls(name)[0]['counts'][0],3);self.assertEqual(self.results(name),[0,0])
        self.assertFalse(any(a.startswith('life_callback_open:') for a in self.actions(name)))

    def test_negative_count_can_increment_to_zero_after_success(self):
        name='open_negative_count';self.assertEqual(self.results(name),[0,0xfffffff2])
        self.assertEqual(self.calls(name)[0]['counts'][0],0);self.assertIn('life_callback_open:0:4660:0',self.actions(name))

    def test_signed_overflow_blocks_ioctl_after_successful_open(self):
        name='open_signed_overflow';self.assertEqual(self.results(name),[0,0xfffffff2])
        self.assertEqual(self.calls(name)[0]['counts'][0],0x80000000)
        self.assertFalse(any(a.startswith('life_callback_open:') for a in self.actions(name)))

    def test_closed_ioctl_stops_before_callback(self):
        name='open_ioctl_closed';self.assertEqual(self.results(name),[0xfffffff2]);self.assertIn('log:object_not_open',self.actions(name))
        self.assertFalse(any(a.startswith('life_callback_ioctl:') for a in self.actions(name)))

    def test_missing_ioctl_callback_succeeds_without_modifying_output(self):
        name='open_ioctl_missing';self.assertEqual(self.results(name),[0,0])
        self.assertEqual(bytes.fromhex(self.row(name)['lifetime_output_hex']),b'\xa5'*32)

    def test_ioctl_forwards_arguments_and_retains_supplied_callback_effect_on_error(self):
        name='open_ioctl_error';self.assertEqual(self.results(name),[0,0xfffffff7])
        b=bytes.fromhex(self.row(name)['lifetime_output_hex']);self.assertEqual(struct.unpack_from('<I',b)[0],0x1001)
        self.assertEqual(b[4:],b'\xa5'*28);self.assertIn('life_callback_ioctl:0:4097:0:-9',self.actions(name))

    def test_ioctl_can_forward_null_output_to_supplied_callback(self):
        name='open_ioctl_null_output';self.assertEqual(self.results(name),[0,0])
        self.assertIn('life_callback_ioctl:0:4097:1:0',self.actions(name));self.assertEqual(bytes.fromhex(self.row(name)['lifetime_output_hex']),b'\xa5'*32)

    def test_null_object_open_and_ioctl_stop_at_their_original_assertions(self):
        for name,owner,line in (('open_null',0x80c3f5f4,297),('open_ioctl_null',0x80c3f5d4,491)):
            r=self.row(name);self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertEqual(self.results(name),[None]);self.assertEqual(r['object_head'],0)

    def test_register_open_publishes_object_before_open_callback(self):
        name='open_register_then_open';self.assertEqual(self.results(name),[0,0]);self.assertEqual(self.row(name)['object_head'],life.objects.NODES[0])
        self.assertEqual(self.calls(name)[0]['counts'][0],1);a=self.actions(name)
        self.assertLess(a.index('object_copy:0:31'),a.index('life_callback_open:0:4660:0'))

    def test_register_open_failure_leaves_registered_object_closed(self):
        name='open_registered_callback_error';self.assertEqual(self.results(name),[0xfffffff7,0xfffffff2])
        self.assertEqual(self.row(name)['object_head'],life.objects.NODES[0]);self.assertEqual(self.calls(name)[0]['counts'][0],0)
        self.assertIn('log:object_open_failed',self.actions(name))

    def test_register_open_maps_duplicate_rejection_to_minus_one(self):
        name='open_registered_duplicate';self.assertEqual(self.results(name),[0,0xffffffff,0])
        self.assertEqual([c['counts'][0] for c in self.calls(name)],[1,1,1])
        self.assertEqual(sum(a.startswith('life_callback_open:') for a in self.actions(name)),1)

    def test_register_open_without_callback_keeps_published_object_at_zero_count(self):
        name='open_registered_no_callback';self.assertEqual(self.results(name),[0,0xfffffff2])
        self.assertEqual(self.row(name)['object_head'],life.objects.NODES[0]);self.assertEqual(self.calls(name)[0]['counts'][0],0)

    def test_consumer_geometry_comes_from_four_original_queries_and_preserves_gaps(self):
        name='consumer_geometry';r=self.row(name);self.assertEqual(self.results(name),[0,0]);self.assertEqual(r['lifetime_root_return'],0)
        self.assertEqual(bytes.fromhex(r['lifetime_output_hex']),self.geometry())
        queries=[a for a in self.actions(name) if a.startswith('life_chip_ioctl:')]
        self.assertEqual(queries,['life_chip_ioctl:13','life_chip_ioctl:2','life_chip_ioctl:1','life_chip_ioctl:14'])

    def test_geometry_alias_has_identical_selected_output(self):
        self.assertEqual(bytes.fromhex(self.row('consumer_geometry_alias')['lifetime_output_hex']),self.geometry())

    def test_repeated_nand_open_skips_original_callback_and_retains_method_table(self):
        name='consumer_repeat_open';self.assertEqual([c['counts'][3] for c in self.calls(name)],[1,2,2])
        self.assertEqual(sum(a.startswith('life_nand_open:') for a in self.actions(name)),1)
        self.assertEqual(struct.unpack_from('<I',self.node(name,3),40)[0],life.objects.METHODS)

    def test_registered_nand_requires_positive_count_before_ioctl_dispatch(self):
        name='consumer_not_open';self.assertEqual(self.results(name),[0xfffffff2]);self.assertTrue(self.row(name)['root_heap_live'])
        self.assertFalse(any(a.startswith('life_nand_ioctl:') for a in self.actions(name)))

    def test_geometry_can_publish_capacity_with_inactive_bbt(self):
        name='consumer_no_bbt';self.assertEqual(bytes.fromhex(self.row(name)['lifetime_output_hex']),self.geometry(0))
        self.assertEqual(self.row(name)['bbt_resume_result'],1);self.assertEqual(self.results(name),[0,0])

    def test_noop_invalid_and_null_geometry_commands_do_not_write_output(self):
        for name,value in (('consumer_query_noop',0),('consumer_query_invalid',0xfffffff6),('consumer_null_geometry',0xfffffff6)):
            self.assertEqual(self.results(name),[0,value]);self.assertEqual(bytes.fromhex(self.row(name)['lifetime_output_hex']),b'\xa5'*32)
            self.assertFalse(any(a.startswith('life_chip_ioctl:') for a in self.actions(name)))

    def test_irq_and_scheduler_contexts_bypass_nand_mutex_services(self):
        self.assertEqual(self.actions('consumer_geometry').count('life_nand_acquire:0'),4)
        self.assertEqual(self.actions('consumer_geometry').count('life_nand_release:0'),4)
        for name in ('consumer_irq','consumer_scheduler'):
            self.assertFalse(any(a.startswith(('life_nand_acquire:','life_nand_release:')) for a in self.actions(name)))
            self.assertEqual(bytes.fromhex(self.row(name)['lifetime_output_hex']),self.geometry())

    def test_nand_lock_assertions_preserve_root_and_leave_geometry_unpublished(self):
        for name,line in (('consumer_acquire_error',36),('consumer_release_error',42)):
            r=self.row(name);self.assertIsNone(r['returned']);self.assertEqual(r['lifetime_root_return'],0)
            self.assertEqual(r['stopped']['line'],line);self.assertTrue(r['root_heap_live']);self.assertEqual(self.calls(name)[-1]['counts'][3],1)
            self.assertEqual(bytes.fromhex(r['lifetime_output_hex']),b'\xa5'*32)

    def test_original_nand_object_suspend_and_resume_return_zero_without_transfer(self):
        name='consumer_suspend_resume';self.assertEqual(self.results(name),[0,0,0]);self.assertEqual(self.row(name)['tx_hex'],'480018')
        self.assertEqual(bytes.fromhex(self.row(name)['lifetime_output_hex']),b'\xa5'*32)
        self.assertIn('life_nand_suspend:3',self.actions(name));self.assertIn('life_nand_resume:3',self.actions(name))
        self.assertEqual(self.row('consumer_uid_error')['uid_length'],17)
        self.assertEqual(bytes.fromhex(self.row('consumer_uid_error')['lifetime_output_hex']),self.geometry())
        r=self.row('consumer_root_alloc_error');self.assertEqual(r['lifetime_root_return'],0xfffffffa);self.assertEqual(r['lifetime_calls'],[])

    def test_contract_rejects_unbounded_counts_callbacks_and_foreign_consumer(self):
        base=self.case('open_first_and_repeat')
        for change in (dict(native_object_lifetime=False),dict(life_counts=[0]*3),dict(life_counts=[1<<32,0,0,0]),
                       dict(life_tables=['unknown']*4),dict(life_ops=[]),dict(life_ops=base['life_ops']*3),dict(life_open_status=101)):
            with self.subTest(change=change),self.assertRaises(ValueError):life.contract(base|change,'open')
        with self.assertRaises(ValueError):life.contract(self.case('consumer_geometry')|dict(life_ops=[base['life_ops'][0]]),'consumer')
        for fn in (life.ranges,life.data_ranges,life.native_vectors):
            with self.assertRaises(ValueError):fn('foreign')

    def test_native_reports_match_models_and_main_caller_buffer_stays_immutable(self):
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for scope,stem in (('open','nand-object-open'),('consumer','nand-object-consumer')):
            evidence=json.loads(Path('analysis',stem+'.json').read_bytes());report=evidence['native_validation']
            self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases[scope]))
            for c in report['cases']:
                self.assertEqual(c['observed'],self.cases[scope][c['name']]['expected']);self.assertEqual(c['observed']['rows'][0]['buffer_sha256'],expected)
                self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],report['bound_per_case'])
            self.assertEqual(len(evidence['byte_range_sha256']),len(life.ranges(scope)))
            self.assertEqual(len(evidence['data_range_sha256']),len(life.data_ranges(scope)))
            self.assertEqual(evidence['function_names']['80c3f5f4'],'dev_obj_open')
            if scope=='consumer':
                self.assertEqual(evidence['function_names']['80c3d1a0'],'dev_nand_suspend')
                self.assertEqual(evidence['function_names']['80c3d1c8'],'dev_nand_resume')


if __name__=='__main__':unittest.main()
