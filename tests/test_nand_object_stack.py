import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import nand_object_stack as objects


class NandObjectStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases={scope:{c['name']:c for c in objects.native_vectors(scope)['cases']} for scope in ('registry','root')}

    def case(self,name):return self.cases['root' if name.startswith('root_') else 'registry'][name]
    def row(self,name):return self.case(name)['expected']['rows'][0]
    def actions(self,name):return self.case(name)['expected']['actions']
    def node(self,name,index):return bytes.fromhex(self.row(name)['object_nodes_hex'][str(index)])
    def word(self,name,index,offset):return struct.unpack_from('<I',self.node(name,index),offset)[0]

    def test_empty_lookup_creates_registry_mutex_without_publishing_an_object(self):
        r=self.row('object_empty_lookup');self.assertEqual(r['object_results'],[0]);self.assertEqual(r['object_head'],0)
        self.assertEqual(r['object_mutex'],objects.MUTEX);self.assertEqual(r['probe_selected'],0)
        self.assertIn('object_mutex_create:'+str(objects.MUTEX),self.actions('object_empty_lookup'))

    def test_first_registration_sets_type_and_pointer_to_head_cell(self):
        name='object_first_insert';r=self.row(name);self.assertEqual(r['object_results'],[0,objects.NODES[0]])
        self.assertEqual(r['object_head'],objects.NODES[0]);self.assertEqual(self.node(name,0)[:32],b'dev_nand'+bytes(24))
        self.assertEqual(self.node(name,0)[36],23);self.assertEqual(self.word(name,0,48),0)
        self.assertEqual(self.word(name,0,52),0);self.assertEqual(self.word(name,0,56),objects.HEAD)
        self.assertEqual(self.word(name,0,40),0xa5a5a5a5)

    def test_three_appends_link_next_and_previous_pointer_cells(self):
        name='object_append_three'
        for i in range(3):
            self.assertEqual(self.word(name,i,52),objects.NODES[i+1] if i<2 else 0)
            self.assertEqual(self.word(name,i,56),objects.NODES[i-1]+52 if i else objects.HEAD)
        self.assertEqual(self.row(name)['object_results'],[0,0,0,objects.NODES[2]])

    def test_duplicate_name_rejects_distinct_object_without_mutating_it(self):
        name='object_duplicate_name';self.assertEqual(self.row(name)['object_results'],[0,0xfffffff5,objects.NODES[0]])
        self.assertEqual(self.node(name,1),b'\xa5'*60);self.assertEqual(self.word(name,0,52),0)

    def test_duplicate_pointer_with_new_name_keeps_original_name(self):
        name='object_duplicate_pointer';self.assertEqual(self.row(name)['object_results'],[0,0xfffffff5,0,objects.NODES[0]])
        self.assertEqual(self.node(name,0)[:9],b'dev_nand\0');self.assertEqual(self.word(name,0,52),0)

    def test_same_name_with_different_type_can_coexist(self):
        name='object_same_name_other_type';self.assertEqual(self.row(name)['object_results'],[0,0,objects.NODES[1],objects.NODES[0]])
        self.assertEqual((self.node(name,0)[36],self.node(name,1)[36]),(23,22))

    def test_seeded_list_retains_head_and_appends_to_original_tail(self):
        name='object_seeded_append';self.assertEqual(self.row(name)['object_head'],objects.NODES[1])
        self.assertEqual(self.word(name,1,52),objects.NODES[2]);self.assertEqual(self.word(name,2,52),objects.NODES[0])
        self.assertEqual(self.word(name,0,56),objects.NODES[2]+52)
        self.assertEqual(self.row('object_seeded_duplicate')['object_results'],[0xfffffff5,objects.NODES[1]])

    def test_existing_mutex_skips_creation(self):
        name='object_existing_mutex';self.assertFalse(any(a.startswith('object_mutex_create:') for a in self.actions(name)))
        self.assertEqual(self.row(name)['object_results'],[0,objects.NODES[0]])
        a=self.actions('root_existing_mutexes')
        self.assertFalse(any(v.startswith(('probe_mutex_create:','object_mutex_create:')) for v in a))
        self.assertEqual(self.row('root_existing_mutexes')['object_results'],[0,objects.NODES[3]])

    def test_supplied_lock_errors_and_null_mutex_do_not_stop_original_list_mutation(self):
        for name in ('object_mutex_retry','object_no_mutex','object_lock_errors'):
            r=self.row(name);self.assertIsNone(r['stopped']);self.assertEqual(r['object_results'],[0,objects.NODES[0]])
        self.assertEqual(self.row('object_no_mutex')['object_mutex'],0)
        self.assertEqual(self.actions('object_no_mutex').count('object_mutex_create:0'),4)
        self.assertIn('object_lock:0:-9',self.actions('object_no_mutex'))
        self.assertIn('object_unlock:'+str(objects.MUTEX)+':-9',self.actions('object_lock_errors'))

    def test_31_byte_name_remains_findable(self):
        name='object_name_31';self.assertEqual(self.row(name)['object_results'],[0,objects.NODES[0]])
        self.assertEqual(self.node(name,0)[:32],b'x'*31+b'\0')

    def test_32_byte_name_is_truncated_and_identical_long_names_can_be_inserted_twice(self):
        self.assertEqual(self.row('object_name_32')['object_results'],[0,0,objects.NODES[0]])
        name='object_long_duplicate';self.assertEqual(self.row(name)['object_results'],[0,0,objects.NODES[0]])
        self.assertEqual(self.node(name,0)[:32],self.node(name,1)[:32]);self.assertEqual(self.word(name,0,52),objects.NODES[1])

    def test_type_is_stored_as_byte_but_lookup_compares_full_argument(self):
        name='object_type_truncation';self.assertEqual(self.row(name)['object_results'],[0,0,objects.NODES[0],0])
        self.assertEqual(self.node(name,0)[36],23);self.assertEqual(self.node(name,1)[36],23)
        self.assertEqual(self.word(name,0,52),objects.NODES[1])

    def test_empty_name_is_allowed_but_null_name_and_pointer_stop_at_assertion(self):
        self.assertEqual(self.row('object_empty_name')['object_results'],[0,objects.NODES[0]])
        for name in ('object_null_name','object_null_pointer'):
            r=self.row(name);self.assertIsNone(r['returned']);self.assertEqual(r['object_results'],[])
            self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c3f614,line=125))
            self.assertEqual(r['object_head'],0);self.assertIn('object_invalid',self.actions(name))

    def test_root_publishes_original_method_table_after_real_probe_uid_and_bbt(self):
        name='root_ready';r=self.row(name)
        self.assertEqual((r['returned'],r['driver_root'],r['object_head']),(0,objects.PROPERTY,objects.NODES[3]))
        self.assertTrue(r['root_heap_live']);self.assertEqual(self.word(name,3,40),objects.METHODS)
        self.assertEqual(r['object_results'],[0,objects.NODES[3]]);self.assertEqual(r['uid_length'],16)
        self.assertEqual(r['bbt_resume_result'],0);self.assertEqual(self.node(name,3)[36],23)

    def test_root_orders_inner_probe_completion_before_object_allocation_and_registration(self):
        a=self.actions('root_ready')
        chain=['root_property:1','probe_uid_native','log:bbt_loaded','probe_mutex_create:1',
            'root_alloc:60:'+str(objects.NODES[3]),'object_zero:3:60','object_register_native:3:23']
        for left,right in zip(chain,chain[1:]):self.assertLess(a.index(left),a.index(right))

    def test_root_appends_to_seeded_list_and_allows_another_type(self):
        for name in ('root_append','root_other_type'):
            self.assertEqual(self.row(name)['object_head'],objects.NODES[0]);self.assertEqual(self.word(name,0,52),objects.NODES[3])
            self.assertEqual(self.word(name,3,56),objects.NODES[0]+52);self.assertEqual(self.word(name,3,40),objects.METHODS)
        self.assertEqual(self.row('root_other_type')['object_results'],[0,objects.NODES[3]])

    def test_root_duplicate_name_retains_allocated_unlinked_object_and_completed_inner_state(self):
        name='root_duplicate_name';r=self.row(name)
        self.assertEqual(r['returned'],0xfffffff5);self.assertTrue(r['root_heap_live'])
        expected=bytearray(60);struct.pack_into('<I',expected,40,objects.METHODS);self.assertEqual(self.node(name,3),bytes(expected))
        self.assertEqual(self.word(name,0,52),0);self.assertEqual(r['object_results'],[0xfffffff5,objects.NODES[0]])
        self.assertEqual((r['probe_guard_pages'],r['uid_length'],r['bbt_resume_result']),(512,16,0))

    def test_root_allocation_failure_preserves_published_probe_state(self):
        name='root_alloc_failure';r=self.row(name)
        self.assertEqual(r['returned'],0xfffffffa);self.assertFalse(r['root_heap_live']);self.assertEqual(r['driver_root'],objects.PROPERTY)
        self.assertEqual(r['probe_mutex'],objects.probe.inventory.MUTEX);self.assertEqual(r['probe_guard_pages'],512)
        self.assertEqual(self.node(name,3),b'\xa5'*60);self.assertEqual(r['object_results'],[0xfffffffa,0])

    def test_missing_property_asserts_before_probe_and_root_publication(self):
        name='root_property_missing';r=self.row(name)
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c3d208,line=49))
        self.assertEqual((r['driver_root'],r['probe_selected'],r['probe_regulator']),(0,0,0));self.assertFalse(r['root_heap_live'])
        self.assertFalse(any(a.startswith('probe_bus:') for a in self.actions(name)))

    def test_real_probe_feature_error_becomes_root_minus_six_and_retains_descriptor_and_uid(self):
        name='root_feature_error';r=self.row(name)
        self.assertEqual((r['returned'],r['driver_root'],r['probe_selected']),(0xfffffffa,objects.PROPERTY,objects.probe.CHIPS[0]['address']))
        self.assertEqual((r['uid_length'],r['probe_guard_pages'],r['probe_mutex']),(16,0,0));self.assertFalse(r['root_heap_live'])
        self.assertIsNone(r['bbt_resume_result']);self.assertFalse(any(a.startswith('root_alloc:') for a in self.actions(name)))

    def test_inner_assertions_stop_root_before_object_allocation(self):
        for name,line,guard in (('root_driver_mutex_failure',30,512),('root_bbt_assertion',172,0)):
            r=self.row(name);self.assertIsNone(r['returned']);self.assertEqual(r['stopped']['line'],line)
            self.assertFalse(r['root_heap_live']);self.assertEqual(r['object_results'],[]);self.assertEqual(r['probe_guard_pages'],guard)
            self.assertEqual(r['driver_root'],objects.PROPERTY)

    def test_stale_uid_export_is_possible_after_actual_root_registration(self):
        name='root_uid_error_export';r=self.row(name)
        self.assertEqual((r['returned'],r['uid_length'],r['aux_export_return']),(0,17,0));self.assertTrue(r['root_heap_live'])
        data=bytearray((i*3+1)&255 for i in range(512));data[0]=17;data[1:18]=b'\xa5'*17
        self.assertEqual(r['buffer_sha256'],hashlib.sha256(data).hexdigest())
        self.assertLess(self.actions(name).index('object_register_native:3:23'),self.actions(name).index('copy_uid:17'))

    def test_no_bbt_and_failed_repair_still_allow_actual_root_registration(self):
        for name,resume,magic in (('root_no_bbt',1,0),('root_repair_failure',0,objects.aux.joined.recovery.bbt.MAGIC)):
            r=self.row(name);self.assertEqual((r['returned'],r['object_head']),(0,objects.NODES[3]))
            self.assertEqual(r['bbt_resume_result'],resume);self.assertEqual(struct.unpack_from('<I',bytes.fromhex(r['bbt_state_hex']))[0],magic)
        self.assertIn('log:bbt_repair_failed',self.actions('root_repair_failure'))
        self.assertEqual(self.row('root_registry_mutex_failure')['object_mutex'],0)

    def test_contract_rejects_foreign_scope_and_unbounded_object_backing(self):
        base=self.case('object_first_insert')
        changes=[dict(native_object_registry=False),dict(native_nand_root=True),dict(registry_mutex_results=[]),
            dict(registry_mutex_results=[1]),dict(registry_lock_status=1),dict(registry_ops=base['registry_ops']*5),
            dict(registry_ops=[dict(kind='lookup',name='x'*65,type=23)]),
            dict(registry_ops=[dict(kind='lookup',name='a\0b',type=23)]),
            dict(registry_seed=[dict(slot=3,name='x',type=23)])]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):objects.contract(base|change,'registry')
        for fn in (objects.ranges,objects.data_ranges,objects.native_vectors):
            with self.assertRaises(ValueError):fn('foreign')
        with self.assertRaises(ValueError):objects.contract(self.case('root_ready')|dict(probe_entry='probe'),'root')

    def test_all_native_captures_match_models_and_caller_buffer_is_unchanged_without_export(self):
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for scope,stem in (('registry','nand-object-stack'),('root','nand-root-stack')):
            evidence=json.loads(Path('analysis',stem+'.json').read_bytes());report=evidence['native_validation']
            self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases[scope]))
            for c in report['cases']:
                case=self.cases[scope][c['name']];self.assertEqual(c['observed'],case['expected'])
                self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],report['bound_per_case'])
                if not case.get('aux_export_uid',False):self.assertEqual(c['observed']['rows'][0]['buffer_sha256'],expected)
            self.assertEqual(len(evidence['byte_range_sha256']),len(objects.ranges(scope)))
            self.assertEqual(len(evidence['data_range_sha256']),len(objects.data_ranges(scope)))


if __name__=='__main__':unittest.main()
