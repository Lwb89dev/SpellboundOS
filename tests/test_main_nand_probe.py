import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_nand_probe as probe


class MainNandProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chips=probe.facts()['chips']
        cls.cases={s:{c['name']:c for c in probe.native_vectors(s)['cases']} for s in ('probe','root')}

    def case(self,n):return self.cases['root' if n.startswith('main_probe_root') else 'probe'][n]
    def rows(self,n):return self.case(n)['expected']['rows']
    def actions(self,n):return self.case(n)['expected']['actions']
    def output(self,n):return bytes.fromhex(self.rows(n)[-1]['output_hex'])

    def test_all_eleven_original_candidates_are_selected_without_descriptor_patching(self):
        self.assertEqual(len(self.chips),11)
        for i,chip in enumerate(self.chips):
            r=self.rows('main_probe_chip_'+str(i))[0]
            self.assertEqual((r['returned'],r['main_selected'],r['probe_id_reads'],r['probe_bus_calls']),(0,chip['address'],i+1,i+1))
            self.assertEqual((r['probe_guard_pages'],r['probe_guard_blocks']),(0x100000//chip['page_size'],0x100000//chip['page_size']//chip['pages_per_block']))

    def test_original_feature_order_and_values_drive_actual_probe_loop(self):
        for i,chip in enumerate(self.chips):
            n='main_probe_chip_'+str(i)
            self.assertEqual([a for a in self.actions(n) if a.startswith(('probe_set:','probe_get:'))],
                [a for reg,val in chip['features'] for a in (f'probe_set:{reg}:{val}:0',f'probe_get:{reg}:{val}:0')])
            self.assertEqual(self.rows(n)[0]['probe_features'],{str(reg):val for reg,val in chip['features']})

    def test_original_reset_delay_and_uid_flag_control_post_match_calls(self):
        flags=set()
        for i,chip in enumerate(self.chips):
            a=self.actions('main_probe_chip_'+str(i));flags.add(chip['uid'])
            self.assertIn(f'probe_reset:{chip["reset_opcode"]}:0',a)
            self.assertEqual([x for x in a if x.startswith('probe_delay:')],['probe_delay:20','probe_delay:20',f'probe_delay:{chip["reset_delay_us"]//1000+1}'])
            self.assertEqual(a.count('probe_uid:0'),int(chip['uid']))
        self.assertEqual(flags,{False,True})

    def test_retry_rounds_include_success_on_last_33rd_candidate(self):
        for n,calls,selected in (('main_probe_second_round',12,0),('main_probe_last_33rd',33,10)):
            r=self.rows(n)[0];self.assertEqual((r['returned'],r['probe_id_reads'],r['probe_bus_calls'],r['main_selected']),(0,calls,calls,self.chips[selected]['address']))
            self.assertEqual(sum(':ffffffffff:' in a for a in self.actions(n)),11*self.case(n)['probe_delayed_rounds'])

    def test_three_failed_rounds_return_minus_four_without_reset_or_features(self):
        n='main_probe_no_match';r=self.rows(n)[0]
        self.assertEqual((r['returned'],r['main_selected'],r['probe_id_reads'],r['probe_bus_calls']),(0xfffffffc,0,33,33))
        self.assertEqual(self.actions(n)[-2:],['log:probe_no_match','log:probe_error'])
        self.assertFalse(any(a.startswith(('probe_reset:','probe_set:','probe_bbt:')) for a in self.actions(n)))

    def test_bus_id_and_reset_faults_stop_at_actual_assertion_sites(self):
        for n,owner,line,reads,selected in (('main_probe_bus_assert',0x70a31738,99,0,0),
                ('main_probe_id_assert',0x70a30fa4,383,1,0),('main_probe_reset_assert',0x70a30f94,402,1,self.chips[0]['address'])):
            r=self.rows(n)[0];self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertEqual((r['probe_id_reads'],r['main_selected'],r['probe_guard_pages']),(reads,selected,0))
            self.assertNotIn('log:probe_error',self.actions(n))

    def test_feature_write_failure_returns_minus_five_without_read_or_bbt(self):
        n='main_probe_write_error';r=self.rows(n)[0]
        self.assertEqual((r['returned'],r['main_selected'],r['probe_features']),(0xfffffffb,self.chips[0]['address'],{}))
        self.assertFalse(any(a.startswith(('probe_get:','probe_bbt:')) for a in self.actions(n)))

    def test_feature_read_failure_returns_minus_six_after_feature_write(self):
        n='main_probe_read_error';r=self.rows(n)[0]
        self.assertEqual((r['returned'],r['probe_features'],r['probe_guard_pages']),(0xfffffffa,{'160':0},0))
        self.assertEqual(self.actions(n)[-2:],['log:probe_feature_read_error','log:probe_error'])

    def test_feature_mismatch_returns_minus_seven_and_retains_selected_chip(self):
        n='main_probe_feature_mismatch';r=self.rows(n)[0]
        self.assertEqual((r['returned'],r['main_selected'],r['probe_guard_blocks']),(0xfffffff9,self.chips[0]['address'],0))
        self.assertIn('probe_get:160:1:0',self.actions(n));self.assertNotIn('log:probe_guard',self.actions(n))

    def test_missing_regulator_continues_without_power_cycle(self):
        n='main_probe_missing_regulator';r=self.rows(n)[0]
        self.assertEqual((r['returned'],r['probe_regulator']),(0,0));self.assertIn('log:probe_regulator_missing',self.actions(n))
        self.assertFalse(any(a.startswith(('probe_enable:','probe_disable:')) for a in self.actions(n)))
        self.assertEqual(sum(a.startswith('probe_delay:') for a in self.actions(n)),1)

    def test_supplied_negative_power_status_does_not_prevent_probe(self):
        n='main_probe_power_error_ignored';r=self.rows(n)[0]
        self.assertEqual((r['returned'],r['probe_regulator']),(0,probe.POWER))
        a=self.actions(n);self.assertLess(a.index('probe_disable:-9'),a.index('probe_enable:-9'));self.assertIn('log:probe_guard',a)

    def test_auxiliary_return_register_values_are_ignored(self):
        n='main_probe_aux_returns_ignored';a=self.actions(n)
        self.assertEqual(self.rows(n)[0]['returned'],0)
        self.assertIn('probe_workaround:-9',a);self.assertIn('probe_uid:-9',a)
        self.assertTrue(any(x.startswith('probe_bbt:') and x.endswith(':-9') for x in a))
        self.assertEqual(a[-1],'log:probe_guard')

    def test_supplied_no_table_result_keeps_success_and_does_not_create_bbt_magic(self):
        r=self.rows('main_probe_supplied_no_bbt')[0]
        self.assertEqual((r['returned'],r['main_bbt_magic'],r['probe_guard_pages']),(0,0,512))

    def test_root_executes_probe_before_mutex_heap_registry_pm_and_consumers(self):
        n='main_probe_root_ready';a=self.actions(n);r=self.rows(n)[0]
        chain=['main_property:1','main_probe_native','log:probe_guard','main_driver_mutex_create:'+str(probe.stack.HANDLE),
            'main_alloc:'+str(probe.base.OBJECT),'main_register_native','main_pm_register:0','native:open']
        for x,y in zip(chain,chain[1:]):self.assertLess(a.index(x),a.index(y))
        self.assertEqual((r['returned'],r['main_cache'],r['main_head'],r['main_pm_calls']),(0,probe.base.OBJECT,probe.base.OBJECT,1))
        self.assertEqual(struct.unpack_from('<I',bytes.fromhex(self.rows(n)[-1]['object_hex']),48)[0],0)
        self.assertEqual(self.rows(n)[-1]['main_cache'],probe.base.OBJECT)

    def test_root_geometry_comes_from_actual_selected_two_and_four_kib_descriptors(self):
        for n,index in (('main_probe_root_ready',0),('main_probe_root_four_kib',3)):
            chip=self.chips[index];out=self.output(n)
            self.assertEqual(struct.unpack_from('<I',out,0)[0],chip['id'][0]|chip['id'][1]<<8)
            self.assertEqual(struct.unpack_from('<I',out,8)[0],chip['pages']*chip['page_size']);self.assertEqual(out[12],1)
            self.assertEqual(out[4:8]+out[13:],b'\xa5'*23)
            self.assertEqual(self.rows(n)[0]['main_selected'],chip['address'])

    def test_root_no_bbt_still_registers_but_actual_active_query_returns_zero(self):
        n='main_probe_root_no_bbt';r=self.rows(n)[0]
        self.assertEqual((r['returned'],r['main_cache'],r['main_bbt_magic']),(0,probe.base.OBJECT,0))
        self.assertEqual(self.output(n)[12],0);self.assertIn('main_chip_native:14',self.actions(n))

    def test_root_probe_errors_become_minus_six_before_allocation(self):
        for n,selected in (('main_probe_root_no_match',0),('main_probe_root_feature_error',self.chips[0]['address'])):
            r=self.rows(n)[0];self.assertEqual((r['returned'],r['main_selected'],r['main_cache'],r['main_mutex']),(0xfffffffa,selected,0,0))
            self.assertEqual(len(self.rows(n)),1);self.assertFalse(r['main_heap_live'])
            self.assertFalse(any(a.startswith('main_alloc:') for a in self.actions(n)))

    def test_root_duplicate_retains_successful_probe_and_unlinked_allocation(self):
        r=self.rows('main_probe_root_duplicate')[0]
        self.assertEqual((r['returned'],r['probe_guard_pages'],r['main_head'],r['main_cache'],r['main_pm_calls']),(0xfffffff5,512,probe.stack.SEED,0,0))
        self.assertTrue(r['main_heap_live']);self.assertEqual(bytes.fromhex(r['object_hex'])[52:],bytes(8))

    def test_root_append_preserves_head_and_links_allocated_object(self):
        r=self.rows('main_probe_root_append')[0]
        self.assertEqual(r['main_head'],probe.stack.SEED)
        self.assertEqual(struct.unpack_from('<I',bytes.fromhex(r['main_seed_hex']),52)[0],probe.base.OBJECT)
        self.assertEqual(struct.unpack_from('<I',bytes.fromhex(r['object_hex']),56)[0],probe.stack.SEED+52)

    def test_existing_mutexes_do_not_skip_actual_probe(self):
        a=self.actions('main_probe_root_existing_mutexes');self.assertIn('main_probe_native',a);self.assertIn('log:probe_guard',a)
        self.assertFalse(any(x.startswith(('main_driver_mutex_create:','main_reg_mutex_create:')) for x in a))

    def test_late_pm_assertion_and_heap_failure_retain_successful_probe_state(self):
        r=self.rows('main_probe_root_no_pm')[0]
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30c60,line=31))
        self.assertEqual((r['main_cache'],r['main_head'],r['probe_guard_pages']),(probe.base.OBJECT,probe.base.OBJECT,512))
        r=self.rows('main_probe_root_alloc_error')[0]
        self.assertEqual((r['returned'],r['main_selected'],r['probe_guard_pages'],r['main_cache']),(0xfffffffa,self.chips[0]['address'],512,0))
        self.assertFalse(r['main_heap_live'])

    def test_contract_rejects_unbounded_inputs_and_wrong_entry_sequence(self):
        c=self.case('main_probe_chip_0')
        for changes in (dict(probe_id=[1,2]),dict(probe_id=[256]*5),dict(probe_delayed_rounds=3),dict(probe_bus_fail_at=34),
                dict(probe_id_fail_at=-1),dict(probe_feature_write_fail_at=4),dict(probe_feature_read_fail_at=-1),
                dict(probe_feature_mismatch_at=4),dict(probe_power_status=101),dict(native_main_probe=False),dict(native_main_root=True),dict(operations=[])):
            with self.subTest(changes=changes),self.assertRaises(ValueError):probe.contract(c|changes,'probe')
        root=self.case('main_probe_root_ready')
        with self.assertRaises(ValueError):probe.contract(root|dict(operations=root['operations'][1:]),'root')
        for fn in (probe.ranges,probe.data_ranges,probe.native_vectors):
            with self.assertRaises(ValueError):fn('foreign')

    def test_captured_native_reports_match_models_and_preserve_authored_buffers(self):
        digest=hashlib.sha256(bytes((i*3+1)&255 for i in range(64))).hexdigest()
        for scope,stem in (('probe','main-nand-probe'),('root','main-nand-probe-root')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());report=e['native_validation']
            self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases[scope]))
            for c in report['cases']:
                self.assertEqual(c['observed'],self.cases[scope][c['name']]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],probe.base.BOUND)
                for row in c['observed']['rows']:self.assertEqual(row['data_sha256'],digest)
            self.assertEqual(e['native_steps'],sum(c['steps'] for c in report['cases']))

    def test_original_inventory_and_code_data_hashes_agree_with_native_guards(self):
        text=Path('analysis_scripts/ValidateMainObjects.java').read_text()
        config=json.loads(json.loads(re.search(r'CONFIG=(".*?");',text).group(1)))
        code={(g['address'],g['size']):g['sha256'] for key in ('guards','main_stack_guards','main_probe_guards') for g in config[key]}
        data={(g['address'],g['size']):g['sha256'] for g in config['main_probe_data_guards']}
        self.assertEqual(config['probe_chips'],[c['address'] for c in self.chips])
        self.assertEqual(data[(probe.TABLE,44)],probe.facts()['table_sha256'])
        for chip in self.chips:self.assertEqual(data[(chip['address'],184)],chip['sha256'])
        for scope,stem in (('probe','main-nand-probe'),('root','main-nand-probe-root')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes())
            self.assertEqual(e['inventory_sha256'],hashlib.sha256(probe.FACTS.read_bytes()).hexdigest())
            for label,spans,guards in (('byte_range_sha256',probe.ranges(scope),code),('data_range_sha256',probe.data_ranges(scope),data)):
                self.assertEqual(e[label],{f'{a:08x}_{n:x}':guards[(a,n)] for a,n in spans})


if __name__=='__main__':unittest.main()
