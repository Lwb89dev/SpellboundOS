import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_nand_stack as stack


class MainNandStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={s:{c['name']:c for c in stack.native_vectors(s)['cases']} for s in ('geometry','root')}
    def case(self,n):return self.cases['root' if n.startswith('main_root') else 'geometry'][n]
    def rows(self,n):return self.case(n)['expected']['rows']
    def actions(self,n):return self.case(n)['expected']['actions']
    def output(self,n):return bytes.fromhex(self.rows(n)[-1]['output_hex'])
    def geometry(self,identifier=0xbaef,capacity=0x08000000,active=1):
        b=bytearray(b'\xa5'*32);struct.pack_into('<I',b,0,identifier);struct.pack_into('<I',b,8,capacity);b[12]=active;return bytes(b)

    def test_geometry_traverses_original_context_chip_and_active_query(self):
        n='main_stack_geometry';self.assertEqual(self.output(n),self.geometry())
        self.assertEqual([a for a in self.actions(n) if a.startswith('main_chip_native:')],['main_chip_native:13','main_chip_native:2','main_chip_native:1','main_chip_native:14'])
        self.assertEqual(self.actions(n).count('main_acquire:0'),4);self.assertEqual(self.actions(n).count('main_release:0'),4)
        self.assertFalse(any(a.startswith('lower:') for a in self.actions(n)))

    def test_second_original_descriptor_produces_four_kib_geometry(self):
        n='main_stack_four_kib';self.assertEqual(self.output(n),self.geometry(0xb2ef,0x20000000))
        self.assertEqual(self.rows(n)[-1]['main_selected'],stack.CHIPS[1]['address'])

    def test_zero_and_wrong_magic_clear_only_active_byte(self):
        for n in ('main_stack_no_bbt','main_stack_bad_magic'):self.assertEqual(self.output(n),self.geometry(active=0))

    def test_absent_selected_descriptor_aborts_and_releases_mutex(self):
        n='main_stack_no_chip';self.assertEqual(self.rows(n)[1]['returned'],0xfffffffe);self.assertEqual(self.rows(n)[1]['lower_calls'],1)
        self.assertEqual(self.output(n),b'\xa5'*32);self.assertIn('log:main_chip_error',self.actions(n));self.assertIn('main_release:0',self.actions(n))

    def test_irq_and_scheduler_contexts_skip_driver_mutex(self):
        for n in ('main_stack_irq','main_stack_scheduler'):
            self.assertEqual(self.output(n),self.geometry());self.assertFalse(any(a.startswith(('main_acquire:','main_release:')) for a in self.actions(n)))
        self.assertFalse(any(a.startswith('main_scheduler:') for a in self.actions('main_stack_irq')))

    def test_absent_driver_mutex_keeps_queries_and_skips_lock_services(self):
        n='main_stack_no_mutex';self.assertEqual(self.output(n),self.geometry());self.assertEqual(self.rows(n)[-1]['main_mutex'],0)
        self.assertFalse(any(a.startswith(('main_acquire:','main_release:')) for a in self.actions(n)))

    def test_acquire_assertion_precedes_chip_and_output_writes(self):
        n='main_stack_acquire_error';r=self.rows(n)[-1]
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30f20,line=36));self.assertIsNone(r['returned'])
        self.assertEqual(self.output(n),b'\xa5'*32);self.assertFalse(any(a.startswith('main_chip_native:') for a in self.actions(n)))

    def test_release_assertion_follows_chip_query_without_geometry_publication(self):
        n='main_stack_release_error';r=self.rows(n)[-1]
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30f08,line=42));self.assertEqual(self.output(n),b'\xa5'*32)
        self.assertIn('main_chip_native:13',self.actions(n));self.assertEqual(r['lower_calls'],1)

    def test_geometry_alias_uses_original_lower_queries(self):
        self.assertEqual(self.output('main_stack_alias'),self.geometry());self.assertEqual(self.rows('main_stack_alias')[-1]['lower_calls'],4)

    def test_noop_and_null_output_do_not_enter_lower_driver(self):
        for n,value in (('main_stack_noop',0),('main_stack_null_output',0xfffffff6)):
            self.assertEqual(self.rows(n)[-1]['returned'],value);self.assertEqual(self.rows(n)[-1]['lower_calls'],0)
            self.assertEqual(self.output(n),b'\xa5'*32)

    def test_root_publishes_registry_object_cache_and_pm_binding(self):
        n='main_root_ready';r=self.rows(n)[0]
        self.assertEqual((r['returned'],r['main_root'],r['main_cache'],r['main_head']),(0,stack.base.PROPERTY,stack.base.OBJECT,stack.base.OBJECT))
        self.assertTrue(r['main_heap_live']);self.assertEqual(r['main_pm_calls'],1);self.assertEqual(self.output(n),self.geometry())
        self.assertEqual(struct.unpack_from('<I',bytes.fromhex(self.rows(n)[-1]['object_hex']),48)[0],0)
        self.assertEqual(self.rows(n)[-1]['main_cache'],stack.base.OBJECT)

    def test_root_orders_probe_wrapper_allocation_registration_cache_and_pm(self):
        a=self.actions('main_root_ready');chain=['main_property:1','main_probe:0','main_driver_mutex_create:'+str(stack.HANDLE),
            'main_alloc:'+str(stack.base.OBJECT),'main_zero:60','main_register_native','main_pm_property:1','main_pm_register:0','native:open']
        for x,y in zip(chain,chain[1:]):self.assertLess(a.index(x),a.index(y))

    def test_root_append_updates_actual_main_link_fields(self):
        r=self.rows('main_root_append')[0];seed=bytes.fromhex(r['main_seed_hex']);obj=bytes.fromhex(r['object_hex'])
        self.assertEqual(r['main_head'],stack.SEED);self.assertEqual(struct.unpack_from('<I',seed,52)[0],stack.base.OBJECT)
        self.assertEqual(struct.unpack_from('<I',obj,56)[0],stack.SEED+52)

    def test_duplicate_retains_allocation_but_skips_cache_and_pm_publication(self):
        n='main_root_duplicate';r=self.rows(n)[0];self.assertEqual(len(self.rows(n)),1);self.assertEqual(r['returned'],0xfffffff5)
        self.assertTrue(r['main_heap_live']);self.assertEqual((r['main_cache'],r['main_head'],r['main_pm_calls']),(0,stack.SEED,0))
        b=bytearray(60);struct.pack_into('<I',b,40,stack.base.METHODS);self.assertEqual(bytes.fromhex(r['object_hex']),bytes(b))
        self.assertNotIn('main_pm_property:1',self.actions(n))

    def test_probe_failure_becomes_outer_minus_six_before_allocation(self):
        n='main_root_probe_error';r=self.rows(n)[0];self.assertEqual(r['returned'],0xfffffffa)
        self.assertEqual(r['main_root'],stack.base.PROPERTY);self.assertEqual((r['main_selected'],r['main_cache'],r['main_mutex']),(0,0,0))
        self.assertFalse(r['main_heap_live']);self.assertFalse(any(a.startswith('main_alloc:') for a in self.actions(n)))

    def test_allocation_failure_retains_probe_and_mutex_state(self):
        r=self.rows('main_root_alloc_error')[0];self.assertEqual(r['returned'],0xfffffffa);self.assertFalse(r['main_heap_live'])
        self.assertEqual((r['main_selected'],r['main_mutex']),(stack.CHIPS[0]['address'],stack.HANDLE));self.assertEqual(bytes.fromhex(r['object_hex']),b'\xa5'*60)

    def test_missing_property_asserts_before_probe(self):
        n='main_root_no_property';r=self.rows(n)[0]
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30c88,line=49));self.assertEqual(r['main_root'],0)
        self.assertFalse(any(a.startswith('main_probe:') for a in self.actions(n)))

    def test_driver_mutex_failure_asserts_after_selected_descriptor(self):
        r=self.rows('main_root_mutex_error')[0];self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30ef0,line=30))
        self.assertEqual(r['main_selected'],stack.CHIPS[0]['address']);self.assertFalse(r['main_heap_live'])

    def test_missing_pm_property_asserts_after_object_cache_publication(self):
        r=self.rows('main_root_no_pm_property')[0];self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30c60,line=31))
        self.assertEqual((r['main_cache'],r['main_head']),(stack.base.OBJECT,stack.base.OBJECT));self.assertTrue(r['main_heap_live']);self.assertEqual(r['main_pm_calls'],0)

    def test_pm_registration_return_is_ignored_and_consumers_still_execute(self):
        n='main_root_pm_error_ignored';self.assertEqual(self.rows(n)[0]['returned'],0);self.assertEqual(self.rows(n)[0]['main_pm_calls'],1)
        self.assertIn('main_pm_register:-9',self.actions(n));self.assertEqual(self.output(n),self.geometry())

    def test_existing_mutexes_skip_creation_without_skipping_probe(self):
        n='main_root_existing_mutexes';self.assertIn('main_probe:0',self.actions(n))
        self.assertFalse(any(a.startswith(('main_driver_mutex_create:','main_reg_mutex_create:')) for a in self.actions(n)))

    def test_root_geometry_uses_selected_chip_and_authored_bbt_magic(self):
        self.assertEqual(self.output('main_root_no_bbt'),self.geometry(active=0))
        self.assertEqual(self.output('main_root_four_kib'),self.geometry(0xb2ef,0x20000000))

    def test_contract_rejects_foreign_scope_state_and_bad_root_sequence(self):
        c=self.case('main_stack_geometry')
        for change in (dict(native_main_lower=False),dict(native_main_root=True),dict(main_chip_index=2),dict(main_seed='bad'),dict(main_irq=2),dict(main_bbt_magic=1<<32)):
            with self.subTest(change=change),self.assertRaises(ValueError):stack.contract(c|change,'geometry')
        root=self.case('main_root_ready')
        for ops in ([],root['operations'][1:]):
            with self.assertRaises(ValueError):stack.contract(root|dict(operations=ops),'root')
        for fn in (stack.ranges,stack.data_ranges,stack.native_vectors):
            with self.assertRaises(ValueError):fn('foreign')

    def test_captured_native_reports_match_models_and_preserve_input_data(self):
        digest=hashlib.sha256(bytes((i*3+1)&255 for i in range(64))).hexdigest()
        for scope,stem in (('geometry','main-nand-query-stack'),('root','main-nand-root-stack')):
            evidence=json.loads(Path('analysis',stem+'.json').read_bytes());report=evidence['native_validation']
            self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases[scope]));self.assertEqual(len(report['cases']),len(self.cases[scope]))
            for c in report['cases']:
                self.assertEqual(c['observed'],self.cases[scope][c['name']]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],stack.base.BOUND)
                for row in c['observed']['rows']:self.assertEqual(row['data_sha256'],digest)
            self.assertEqual(len(evidence['byte_range_sha256']),len(stack.ranges(scope)));self.assertEqual(len(evidence['data_range_sha256']),len(stack.data_ranges(scope)))


if __name__=='__main__':unittest.main()
