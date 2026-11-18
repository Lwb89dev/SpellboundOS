import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_nand_bus as bus
from analysis_scripts import main_nand_bus_probe as connected


class MainNandBusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.direct={c['name']:c for c in bus.native_vectors()['cases']}
        cls.linked={c['name']:c for c in connected.native_vectors()['cases']}

    def case(self,n):return self.linked['main_bus_probe_'+n] if 'main_bus_probe_'+n in self.linked else self.direct['main_bus_'+n]
    def direct_case(self,n):return self.direct['main_bus_'+n]
    def row(self,n):return self.case(n)['expected']['rows'][0]
    def actions(self,n):return self.case(n)['expected']['actions']
    def direct_actions(self,n):return self.direct_case(n)['expected']['actions']
    def direct_row(self,n):return self.direct_case(n)['expected']['rows'][0]

    def test_clock_word_boundary_and_ignored_initialization_status(self):
        for n,clock in (('init_low',2),('init_99',2),('init_100',1),('init_high',1)):
            self.assertEqual(self.direct_actions(n)[0],f'clock_select:{clock}');self.assertEqual(self.direct_row(n)['returned'],0)
        self.assertEqual(self.direct_row('init_status_ignored')['returned'],0)
        self.assertIn('controller_init:-9',self.direct_actions('init_status_ignored'))

    def test_platform_publishes_actual_main_dma_links_and_preserves_flags(self):
        r=self.direct_row('init_keeps_flags');b=bytes.fromhex(r['controller_hex'])
        self.assertEqual(struct.unpack_from('<I',b)[0],0x93240000)
        self.assertEqual(struct.unpack_from('<II',b,32),bus.DMA)
        self.assertEqual((r['reinit'],r['disabled']),(1,1));self.assertEqual(r['mmio'],[0x1000209,0x20000201])
        self.assertEqual(self.direct_actions('init_high').count('fence'),2)

    def test_disabled_transfer_returns_minus_one_before_reinit_or_revision_service(self):
        for n,reinit in (('disabled',0),('disabled_keeps_reinit',1)):
            r=self.direct_row(n);self.assertEqual((r['returned'],r['disabled'],r['reinit']),(0xffffffff,1,reinit))
            self.assertEqual(self.direct_actions(n),[]);self.assertEqual(bytes.fromhex(r['controller_hex']),b'\xa5'*64)

    def test_transfer_reinitializes_before_revision_and_command(self):
        a=self.direct_actions('reinitialize');r=self.direct_row('reinitialize')
        self.assertEqual(r['reinit'],0);self.assertLess(a.index('controller_init:0'),a.index('version_query'))
        self.assertLess(a.index('version_query'),next(i for i,x in enumerate(a) if x.startswith('command:')))

    def test_packet_conversion_normalizes_boolean_bytes_and_dummy_count(self):
        a=next(x for x in self.direct_actions('boolean_bytes') if x.startswith('command:'))
        self.assertEqual(list(map(int,a.split(':')[1:])),[2,0,3,1,1,0x1234,1,2,1,64,8,0])
        self.assertTrue(any(x.startswith('transmit_poll:64:') for x in self.direct_actions('boolean_bytes')))

    def test_bounce_requires_size_over_31_force_zero_and_unsigned_revision_over_one(self):
        for n,bounce in (('threshold_31',False),('threshold_32',True),('revision_0_poll',False),('revision_1_poll',False),('revision_unsigned_bounce',True),('poll_read',False)):
            a=self.direct_actions(n);self.assertEqual(any(x.startswith('receive_bounce:') for x in a),bounce)
            self.assertEqual(any(x.startswith('receive_poll:') for x in a),not bounce)

    def test_bounce_read_copies_to_caller_and_write_copies_before_command(self):
        read=self.direct_actions('bounce_read');self.assertLess(read.index('receive_bounce:64:0'),read.index('copy_from_bounce:64'))
        self.assertEqual(self.direct_row('bounce_read')['buffer_sha256'],self.direct_row('poll_read')['buffer_sha256'])
        write=self.direct_actions('bounce_write');self.assertEqual(write[1],'copy_to_bounce:64')
        self.assertTrue(write[2].startswith('command:'));self.assertTrue(write[3].startswith('transmit_bounce:64:'))

    def test_zero_length_still_issues_command_without_data_call(self):
        a=self.direct_actions('zero_length');self.assertEqual(len(a),2);self.assertEqual(a[0],'version_query')
        self.assertEqual(self.direct_row('zero_length')['returned'],0)

    def test_command_failures_stop_at_branch_specific_original_assertion(self):
        for n,owner,line in (('command_error',0x70a1bc8c,294),('positive_command_error',0x70a1bc8c,294),('bounce_command_error',0x70a1bca8,361)):
            r=self.direct_row(n);self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertEqual(self.direct_actions(n)[-2:],['log:command_error','diagnostic'])

    def test_receive_transmit_faults_stop_at_original_direct_and_bounce_assertions(self):
        for n,owner,line in (('read_error',0x70a1bc8c,305),('write_error',0x70a1bc8c,313),('bounce_read_error',0x70a1bca8,374),('bounce_write_error',0x70a1bca8,386)):
            self.assertEqual(self.direct_row(n)['stopped'],dict(kind='assertion',owner=owner,line=line))
        self.assertNotIn('copy_from_bounce:64',self.direct_actions('bounce_read_error'))

    def test_original_feature_packets_and_byte_truncation(self):
        for n,mode,opcode in (('feature_read',0,15),('feature_write',2,31)):
            command=next(x for x in self.direct_actions(n) if x.startswith('command:'))
            self.assertEqual(list(map(int,command.split(':')[1:])),[mode,0,opcode,1,1,176,1,1,1,1,0,0])
        self.assertEqual(self.direct_actions('feature_write'),self.direct_actions('feature_truncates'))
        self.assertIn(hashlib.sha256(b'\xa5').hexdigest(),self.direct_actions('feature_truncates')[-1])

    def test_disabled_features_assert_in_builder_while_hal_errors_assert_inside_bus(self):
        for n,owner,line in (('feature_read_disabled',0x70a3112c,55),('feature_write_disabled',0x70a31114,74),
                ('feature_read_bus_error',0x70a1bc8c,294),('feature_write_bus_error',0x70a1bc8c,313)):
            self.assertEqual(self.direct_row(n)['stopped'],dict(kind='assertion',owner=owner,line=line))
        self.assertEqual(self.direct_actions('feature_read_disabled'),[])

    def test_partial_supplied_receive_preserves_unwritten_caller_bytes(self):
        raw=bytearray((i*3+1)&255 for i in range(512));raw[:3]=bytes((0x5a,0x61,0x68))
        self.assertEqual(self.direct_row('partial_read')['buffer_sha256'],hashlib.sha256(raw).hexdigest())

    def test_all_eleven_candidates_use_original_bus_words_and_feature_packets(self):
        for i,chip in enumerate(bus.probe.facts()['chips']):
            n='chip_'+str(i);r=self.row(n);a=self.actions(n)
            self.assertEqual((r['returned'],r['main_selected'],r['probe_bus_calls'],r['probe_id_reads']),(0,chip['address'],i+1,i+1))
            self.assertEqual(r['bus_commands'],i+2+2*len(chip['features']))
            clocks=[x for x in a if x.startswith('clock_select:')]
            self.assertEqual(clocks,[f'clock_select:{2 if word<100 else 1}' for word in connected.BUS_WORDS[:i+1]])
            self.assertEqual([x for x in a if x.startswith(('probe_packet:31:','probe_packet:15:'))],
                [x for reg,val in chip['features'] for x in (f'probe_packet:31:{reg}:1:1',f'probe_packet:15:{reg}:1:0')])

    def test_all_selected_descriptors_drive_subsequent_geometry_and_close(self):
        for i,chip in enumerate(bus.probe.facts()['chips']):
            rows=self.case('chip_'+str(i))['expected']['rows'];last=rows[-1];out=bytes.fromhex(last['output_hex'])
            self.assertEqual(struct.unpack_from('<I',out,8)[0],chip['pages']*chip['page_size']);self.assertEqual(out[12],1)
            self.assertEqual(struct.unpack_from('<I',bytes.fromhex(last['object_hex']),48)[0],0)
            self.assertEqual(last['main_cache'],bus.base.OBJECT);self.assertEqual(len(rows),4)

    def test_probe_platform_ignores_supplied_negative_init_status(self):
        r=self.row('init_status_ignored');self.assertEqual(r['returned'],0);self.assertEqual(r['probe_guard_pages'],512)
        self.assertIn('controller_init:-9',self.actions('init_status_ignored'))
        self.assertEqual(r['bus_reinit'],0)

    def test_connected_disabled_id_stops_at_id_builder_before_first_hal_command(self):
        r=self.row('disabled');self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30fa4,line=383))
        self.assertEqual((r['bus_commands'],r['probe_id_reads'],r['main_selected']),(0,1,0));self.assertFalse(r['main_heap_live'])

    def test_connected_id_reset_and_feature_command_faults_stop_inside_transport(self):
        for n,selected in (('id_command_error',0),('reset_command_error',bus.probe.facts()['chips'][0]['address']),('feature_command_error',bus.probe.facts()['chips'][0]['address'])):
            r=self.row(n);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294))
            self.assertEqual(r['main_selected'],selected);self.assertIsNone(r['returned']);self.assertEqual(r['probe_guard_pages'],0)

    def test_connected_feature_data_faults_do_not_return_outer_probe_error(self):
        for n,line in (('id_receive_error',305),('feature_receive_error',305),('feature_transmit_error',313)):
            r=self.row(n);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=line));self.assertIsNone(r['returned'])
            self.assertEqual(r['main_cache'],0);self.assertFalse(r['main_heap_live'])

    def test_authored_disable_transitions_expose_real_feature_builder_assertions(self):
        for n,owner,line,features in (('feature_write_disabled',0x70a31114,74,{}),('feature_read_disabled',0x70a3112c,55,{'160':0})):
            r=self.row(n);self.assertEqual(r['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertEqual((r['bus_disabled'],r['probe_features'],r['probe_guard_pages']),(1,features,0))

    def test_real_feature_mismatch_propagates_minus_six_before_heap(self):
        r=self.row('feature_mismatch');self.assertEqual(r['returned'],0xfffffffa);self.assertIsNone(r['stopped'])
        self.assertEqual((r['probe_features'],r['probe_guard_pages'],r['main_cache']),({'160':0},0,0))
        self.assertFalse(r['main_heap_live']);self.assertIn('log:probe_feature_mismatch',self.actions('feature_mismatch'))

    def test_registered_device_can_have_inactive_authored_bbt_after_real_bus_probe(self):
        r=self.row('no_bbt');self.assertEqual((r['returned'],r['main_cache'],r['main_bbt_magic'],r['probe_guard_pages']),(0,bus.base.OBJECT,0,512))
        self.assertEqual(bytes.fromhex(self.case('no_bbt')['expected']['rows'][-1]['output_hex'])[12],0)

    def test_duplicate_and_late_pm_assertion_keep_successful_native_probe_state(self):
        r=self.row('duplicate');self.assertEqual((r['returned'],r['main_cache'],r['probe_guard_pages']),(0xfffffff5,0,512));self.assertTrue(r['main_heap_live'])
        r=self.row('no_pm');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30c60,line=31))
        self.assertEqual((r['main_cache'],r['main_head'],r['probe_guard_pages']),(bus.base.OBJECT,bus.base.OBJECT,512))

    def test_contracts_reject_unbounded_inputs_and_supplied_probe_fault_substitution(self):
        for changes in (dict(mode='busy'),dict(size=513),dict(responses=[]),dict(rom_revision=-1),dict(bus_word=1<<32),dict(command_lines=256),dict(copy_limit=513),dict(mmio=[]),dict(init_status=101)):
            with self.subTest(changes=changes),self.assertRaises(ValueError):bus.contract(self.direct_case('poll_read')|changes)
        for changes in (dict(native_main_bus=False),dict(native_main_root=False),dict(bus_command_fail_at=101),dict(bus_revision=-1),dict(probe_id_fail_at=1),dict(probe_feature_write_fail_at=1)):
            with self.subTest(changes=changes),self.assertRaises(ValueError):connected.contract(self.case('chip_0')|changes)

    def test_captured_reports_match_bounded_models_and_preserve_input_data(self):
        for stem,cases in (('main-nand-bus',self.direct),('main-nand-bus-probe',self.linked)):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());report=e['native_validation']
            self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(cases));self.assertEqual(len(report['cases']),len(cases))
            for c in report['cases']:
                self.assertEqual(c['observed'],cases[c['name']]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],bus.BOUND)
                if stem.endswith('-probe'):
                    for row in c['observed']['rows']:self.assertEqual(row['data_sha256'],hashlib.sha256(bytes((i*3+1)&255 for i in range(64))).hexdigest())
            self.assertEqual(e['native_steps'],sum(c['steps'] for c in report['cases']))

    def test_native_code_data_guards_match_both_evidence_files(self):
        def config(path,key):
            raw=re.search(key+r'=(".*?");',Path(path).read_text()).group(1);return json.loads(json.loads(raw))
        native=config('analysis_scripts/ValidateMainNandBus.java','CONFIG')
        self.assertEqual(native,config('analysis_scripts/ValidateMainNandBusProbe.java','BUS_CONFIG'))
        original=config('analysis_scripts/ValidateMainObjects.java','CONFIG')
        guards={(g['address'],g['size']):g['sha256'] for key in ('guards','main_stack_guards','main_probe_guards','main_probe_data_guards') for g in original[key]}
        guards.update({(g['address'],g['size']):g['sha256'] for g in native['guards']})
        for stem,code,data in (('main-nand-bus',bus.RANGES,bus.DATA_RANGES),('main-nand-bus-probe',connected.ranges(),connected.data_ranges())):
            e=json.loads(Path('analysis',stem+'.json').read_bytes())
            for key,spans in (('byte_range_sha256',code),('data_range_sha256',data)):
                self.assertEqual(e[key],{f'{a:08x}_{n:x}':guards[(a,n)] for a,n in spans})


if __name__=='__main__':unittest.main()
