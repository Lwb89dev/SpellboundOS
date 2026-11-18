import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_qspi_hal as hal
from analysis_scripts import main_qspi_bus as bus


class MainQspiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.direct={c['name'].removeprefix('main_hal_'):c for c in hal.native_vectors()['cases']}
        cls.linked={c['name'].removeprefix('main_qspi_bus_'):c for c in bus.native_vectors()['cases']}

    def case(self,n,linked=False):return (self.linked if linked else self.direct)[n]
    def row(self,n,linked=False):return self.case(n,linked)['expected']['rows'][0]
    def actions(self,n,linked=False):return self.case(n,linked)['expected']['actions']
    def count(self,n,linked=False):return struct.unpack_from('<I',bytes.fromhex(self.row(n,linked)['context_hex']),20)[0]
    def accesses(self,n,kind,linked=False):return [a for a in self.actions(n,linked) if a.startswith(kind+':256:')]

    def test_init_observes_reset_self_clear_and_sets_fifo_widths(self):
        a=self.actions('init_reset_then_ready');r=self.row('init_reset_then_ready')
        self.assertEqual(a[:3],['w:16:4:256','r:16:4:256','r:16:4:0']);self.assertEqual(r['mmio']['32'],0x3300)
        self.assertEqual(r['mmio']['52'],0x301);self.assertEqual(r['returned'],0)

    def test_mode_one_skips_flag_rewrite_and_other_bits_are_preserved(self):
        self.assertEqual(self.row('init_mode_one')['mmio']['16'],0)
        self.assertEqual(self.row('init_preserves_other_control_bits')['mmio']['16'],0x47)

    def test_pack_covers_command_address_and_data_line_combinations(self):
        values={'pack_1_1_1':0,'pack_1_1_2':0x20,'pack_1_1_3':0x40,'pack_1_2_1':0x60,'pack_1_3_1':0x80,'pack_2_1_1':0xa0,'pack_3_1_1':0xc0,'pack_0_1_1':0,'pack_1_0_1':0,'pack_1_1_4':0}
        for n,value in values.items():self.assertEqual(self.row(n)['returned'],value)

    def test_clock_masks_written_selector_and_refreshes_shadow_on_equal_branch(self):
        self.assertEqual(self.row('clock_11')['clock_word'],0xa5a5b5a5)
        self.assertEqual(self.actions('clock_11'),[f'clock_read:{0xa5a5b5a5}'])
        self.assertEqual(self.row('clock_11')['clock_shadow'],0xa5a5b5a5)
        self.assertEqual((self.row('clock_17')['clock_word']>>12)&15,1)

    def test_fifo_counts_scale_both_fields_at_all_four_width_shifts(self):
        for shift in range(4):
            self.assertEqual(self.row('rx_count_'+str(shift))['returned'],12>>(3-shift))
            self.assertEqual(self.row('tx_count_'+str(shift))['returned'],20>>(3-shift))

    def test_command_packs_special_direction_and_controller_base_bit(self):
        self.assertEqual(self.row('command_read')['mmio']['12'],0x6b000041)
        self.assertEqual(self.row('command_write')['mmio']['12'],0x6b000043)
        self.assertEqual(self.row('command_other_base')['mmio']['12'],0x6b000040)
        self.assertTrue(self.row('command_mode_seven')['mmio']['4']&0x10000000)
        self.assertEqual(self.count('command_read'),9)

    def test_null_command_inputs_return_one_without_register_access(self):
        for n in ('command_no_context','command_no_frame','command_no_base'):
            self.assertEqual(self.row(n)['returned'],1);self.assertEqual(self.actions(n),[])

    def test_empty_command_waits_and_acknowledges_completion(self):
        self.assertEqual(self.row('command_empty_ready')['returned'],0);self.assertIn('w:36:4:1',self.actions('command_empty_ready'))
        self.assertEqual(self.row('command_empty_ready')['mmio']['36'],0);self.assertEqual(self.row('command_empty_timeout')['returned'],3)

    def test_aligned_fifo_uses_words_and_unaligned_fifo_uses_bytes(self):
        for mode in ('receive','transmit'):
            kind='r' if mode=='receive' else 'w'
            aligned=self.accesses(mode+'_ready',kind);unaligned=self.accesses(mode+'_unaligned',kind)
            self.assertEqual([a.split(':')[2] for a in aligned],['4','4','1'])
            self.assertEqual(len(unaligned),9);self.assertTrue(all(a.split(':')[2]=='1' for a in unaligned))

    def test_receive_consumes_count_and_preserves_unwritten_buffer_tail(self):
        r=self.row('receive_ready');raw=bytearray((i*3+1)&255 for i in range(512));raw[:9]=bytes((0x5a+i*7)&255 for i in range(9))
        self.assertEqual(self.count('receive_ready'),0);self.assertEqual(r['rx_bytes'],9)
        self.assertEqual(r['buffer_sha256'],hashlib.sha256(raw).hexdigest())

    def test_data_timeout_and_late_completion_timeout_preserve_distinct_counts(self):
        for mode in ('receive','transmit'):
            self.assertEqual(self.row(mode+'_data_timeout')['returned'],3);self.assertEqual(self.count(mode+'_data_timeout'),9)
            self.assertEqual(self.row(mode+'_completion_timeout')['returned'],3);self.assertEqual(self.count(mode+'_completion_timeout'),0)

    def test_dma_setup_status_is_ignored_while_wait_status_propagates(self):
        for mode in ('receive_dma','transmit_dma'):
            self.assertEqual(self.row(mode+'_setup_error_ignored')['returned'],0)
            self.assertEqual(self.row(mode+'_wait_error')['returned'],0xfffffff7)
            self.assertEqual(self.count(mode+'_ready'),9)

    def test_dma_wrappers_clear_request_bit_even_if_it_was_already_set(self):
        for mode in ('receive_dma','transmit_dma'):
            self.assertEqual(self.row(mode+'_wait_error')['mmio']['32'],0x3300)
            self.assertEqual(self.row(mode+'_ready')['mmio']['32'],0x3300)

    def test_completion_rechecks_ready_and_accepts_exact_deadline(self):
        self.assertEqual(self.row('complete_ready_on_recheck')['returned'],0)
        self.assertEqual(self.row('complete_exact_deadline')['returned'],0)
        self.assertEqual(self.actions('complete_ready_on_recheck')[-2:],['r:36:4:1','w:36:4:1'])

    def test_completion_handles_low_word_and_full_counter_wrap(self):
        for n in ('complete_low_word_wrap','complete_full_counter_wrap'):
            self.assertEqual(self.row(n)['returned'],0);self.assertIn('w:36:4:1',self.actions(n))

    def test_timeout_high_word_sub_khz_and_multiplication_wrap_are_observed(self):
        for n in ('complete_high_word_elapsed','complete_sub_khz_frequency','complete_limit_multiply_wrap'):
            self.assertEqual(self.row(n)['returned'],3)

    def test_zero_fifo_stops_at_nonprogress_prefix_without_claiming_return(self):
        for mode in ('receive','transmit'):
            for suffix in ('_zero_fifo_prefix','_zero_fifo_advancing_prefix'):
                n=mode+suffix;r=self.row(n);self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='bounded_prefix',chunks=4))
                self.assertEqual(self.count(n),9);self.assertEqual((r['rx_bytes'],r['tx_hex']),(0,''))
                self.assertEqual(self.actions(n)[-1],'stop_no_progress:4')

    def test_actual_revision_body_requires_exact_recognized_string(self):
        for n,value in (('version_old',1),('version_new',2),('version_other',0),('version_no_prefix',0),('version_empty',0),('version_suffix',0)):
            self.assertEqual(self.row(n)['returned'],value)
        self.assertEqual(self.actions('version_no_prefix'),[]);self.assertEqual(len(self.actions('version_new')),2)

    def test_hal_contract_rejects_unbounded_time_payload_and_rom_inputs(self):
        c=self.case('command_read')
        for change in (dict(mode='foreign'),dict(mode='command_clock'),dict(count=65),dict(alignment=2),dict(frame=[0]),dict(ready=[]),dict(ticks=[-1]),dict(rom_version='v\x00tail'),dict(rom_version='é'),dict(timeout=1<<32),dict(stop_chunks=9)):
            with self.subTest(change=change),self.assertRaises(ValueError):hal.contract(c|change)

    def test_bus_conversion_drives_actual_registers_and_fifo(self):
        for n,write in (('read',False),('write',True)):
            r=self.row(n,True);self.assertEqual(r['returned'],0);self.assertEqual(self.count(n,True),0)
            self.assertEqual(len(bytes.fromhex(r['tx_hex'])) if write else r['rx_bytes'],64)
            self.assertEqual(r['mmio']['12'],0x03000003 if write else 0x03000001)
            self.assertFalse(any(a.startswith('command:') for a in self.actions(n,True)))

    def test_actual_revision_and_threshold_select_dma_or_direct_path(self):
        for n,dma in (('threshold_31',False),('threshold_32',True),('old_revision_direct',False),('unknown_revision_direct',False),('bounce_read',True)):
            a=self.actions(n,True);self.assertEqual(any(x.startswith('dma_setup:') for x in a),dma)
        self.assertEqual(self.actions('old_revision_direct',True)[0],'compare:v1.1.03:v1.1.03')

    def test_bounce_copies_and_dma_wrapper_preserve_original_count_field(self):
        a=self.actions('bounce_read',True);self.assertEqual(a[-1],'copy_from_bounce:64')
        self.assertEqual(self.row('bounce_read',True)['buffer_sha256'],self.row('read',True)['buffer_sha256'])
        self.assertEqual(self.count('bounce_read',True),64);self.assertIn('copy_to_bounce:64',self.actions('bounce_write',True))

    def test_connected_unaligned_receive_uses_byte_fifo_for_entire_payload(self):
        a=self.accesses('unaligned','r',True);self.assertEqual(len(a),64);self.assertTrue(all(x.split(':')[2]=='1' for x in a))

    def test_feature_builders_reach_fifo_and_truncate_write_byte(self):
        self.assertEqual(self.row('feature_read',True)['rx_bytes'],1)
        self.assertEqual(self.row('feature_write',True)['tx_hex'],'a5');self.assertEqual(self.row('feature_truncates',True)['tx_hex'],'a5')
        self.assertEqual(self.row('feature_write',True)['mmio']['12'],0x1f000003)

    def test_real_hal_timeout_reaches_original_bus_assertion_sites(self):
        for n,line in (('empty_timeout',294),('receive_timeout',305),('transmit_timeout',313),('feature_read_timeout',305),('feature_write_timeout',313),('receive_completion_timeout',305),('transmit_completion_timeout',313)):
            r=self.row(n,True);self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=line))

    def test_ignored_dma_setup_error_can_copy_unchanged_bounce_bytes(self):
        r=self.row('bounce_receive_setup_ignored',True);raw=bytearray((i*3+1)&255 for i in range(512));raw[:64]=b'\xa5'*64
        self.assertEqual(r['returned'],0);self.assertEqual(r['buffer_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.row('bounce_transmit_setup_ignored',True)['returned'],0)

    def test_dma_wait_error_reaches_bounce_assertion_and_skips_copyback(self):
        raw=bytes((i*3+1)&255 for i in range(512));r=self.row('bounce_receive_wait_error',True)
        self.assertEqual(r['buffer_sha256'],hashlib.sha256(raw).hexdigest());self.assertNotIn('copy_from_bounce:64',self.actions('bounce_receive_wait_error',True))
        for n,line in (('bounce_receive_wait_error',374),('bounce_transmit_wait_error',386)):
            self.assertEqual(self.row(n,True)['stopped'],dict(kind='assertion',owner=0x70a1bca8,line=line));self.assertEqual(self.row(n,True)['mmio']['32']&1,0)

    def test_native_reports_and_hash_guards_match_both_models(self):
        def config(path):return json.loads(json.loads(re.search(r'CONFIG=(".*?");',Path(path).read_text()).group(1)))
        guards={(g['address'],g['size']):g['sha256'] for path in ('analysis_scripts/ValidateMainQspiHal.java','analysis_scripts/ValidateMainNandBus.java') for g in config(path)['guards']}
        for stem,cases,code,data,prefix in (('main-qspi-hal',self.direct,hal.RANGES,hal.DATA_RANGES,'main_hal_'),('main-qspi-bus',self.linked,bus.ranges(),bus.data_ranges(),'main_qspi_bus_')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False);self.assertEqual(r['case_count'],len(cases));self.assertEqual(len(r['cases']),len(cases))
            for c in r['cases']:
                self.assertEqual(c['observed'],cases[c['name'].removeprefix(prefix)]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],hal.BOUND)
            for key,spans in (('byte_range_sha256',code),('data_range_sha256',data)):
                self.assertEqual(e[key],{f'{a:08x}_{n:x}':guards[(a,n)] for a,n in spans})
        c=self.case('read',True)
        for change in (dict(bus=c['bus']|dict(reinit=True)),dict(bus=c['bus']|dict(read_status=-9)),dict(context_present=False)):
            with self.assertRaises(ValueError):bus.contract(c|change)


if __name__=='__main__':unittest.main()
