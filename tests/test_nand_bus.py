import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_bus import BOUNCE,CTRL,DMA,contract,native_vectors


def initial_buffer():return bytes((i*3+1)&255 for i in range(512))


class NandBusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def command(self,name,index=0):
        return [int(v) for v in [a for a in self.result(name)['actions'] if a.startswith('command:')][index].split(':')[1:]]

    def test_init_descriptor_threshold_selects_one_or_two(self):
        self.assertEqual(self.result('init_high_word')['actions'][0],'clock_select:1')
        self.assertEqual(self.result('init_low_word')['actions'][0],'clock_select:2')
        self.assertEqual(self.result('init_boundary_99')['actions'][0],'clock_select:2')
        self.assertEqual(self.result('init_boundary_100')['actions'][0],'clock_select:1')

    def test_init_sets_selected_mmio_bits_and_preserves_other_bits(self):
        self.assertEqual(self.row('init_high_word')['mmio'],[0x01000209,0x20000201])
        self.assertEqual(self.result('init_high_word')['actions'].count('fence'),2)

    def test_init_publishes_controller_and_two_dma_descriptors(self):
        words=struct.unpack('<16I',bytes.fromhex(self.row('init_high_word')['controller_hex']))
        self.assertEqual((words[0],words[2],words[3]),(0x93240000,0,0))
        self.assertEqual(words[8:10],DMA)
        self.assertEqual(words[1],0xa5a5a5a5)
        for i,fields in enumerate(((12,2,0,2,0,0,6,1,0x93080000,5),(12,1,2,0,0,0,6,1,0x93080000,6))):
            data=struct.pack('<10I',*fields)+b'\xa5'*4+struct.pack('<I',CTRL)
            self.assertEqual(self.row('init_high_word')['dma_sha256'][i],hashlib.sha256(data).hexdigest())

    def test_init_does_not_propagate_supplied_callback_status(self):
        self.assertEqual(self.row('init_callback_status_ignored'),self.row('init_high_word'))

    def test_rom_version_query_recognizes_only_two_selected_strings(self):
        for label,value in (('v1_1_03',1),('v1_1_16',2),('v9_9_99',0),('unknown',0)):
            self.assertEqual(self.row('version_'+label)['returned'],value)

    def test_raw_packet_maps_to_complete_hal_frame(self):
        self.assertEqual(self.command('poll_read'),[0,0,3,1,1,0x1234,1,2,1,64,8,0])
        self.assertEqual(self.command('poll_write')[0],2)

    def test_boolean_direction_and_dummy_fields_are_normalized(self):
        frame=self.command('raw_boolean_fields')
        self.assertEqual((frame[0],frame[10]),(2,8))

    def test_bounce_policy_changes_at_thirty_two_bytes(self):
        self.assertIn('receive_poll:31:0',self.result('bounce_threshold_31')['actions'])
        self.assertIn('receive_bounce:32:0',self.result('bounce_threshold_32')['actions'])

    def test_old_and_unknown_rom_versions_force_direct_path(self):
        for name in ('old_rom_uses_poll','unknown_rom_uses_poll'):
            self.assertIn('receive_poll:64:0',self.result(name)['actions'])
            self.assertNotIn('receive_bounce:64:0',self.result(name)['actions'])

    def test_read_bounce_copies_supplied_data_back_to_caller(self):
        self.assertEqual(self.row('bounce_read')['buffer_sha256'],self.row('poll_read')['buffer_sha256'])
        expected=bytes((0x5a+i*7)&255 for i in range(64))+initial_buffer()[64:]
        self.assertEqual(self.row('bounce_read')['buffer_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.result('bounce_read')['actions'][-1],'copy_from_bounce:64')

    def test_write_bounce_copies_input_before_command(self):
        actions=self.result('bounce_write')['actions']
        copy_index=actions.index('copy_to_bounce:64')
        self.assertTrue(actions[copy_index+1].startswith('command:'))
        expected=initial_buffer()[:64]+b'\xa5'*448
        self.assertEqual(self.row('bounce_write')['bounce_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.row('bounce_write')['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())

    def test_reinitialization_flag_is_cleared_before_transfer(self):
        row=self.row('transfer_reinitializes')
        self.assertEqual(row['reinit'],0)
        self.assertEqual(row['controller_hex'],self.row('init_high_word')['controller_hex'])
        self.assertEqual(self.result('transfer_reinitializes')['actions'][0],'clock_select:1')

    def test_zero_length_only_sends_command(self):
        actions=self.result('zero_length_command')['actions']
        self.assertEqual(len(actions),2)
        self.assertFalse(any(a.startswith(('receive_','transmit_')) for a in actions))

    def test_command_errors_stop_before_data_phase(self):
        for name,owner,line in (('poll_command_error',0x80c37b7c,0x11f),('bounce_command_error',0x80c37b98,0x162)):
            self.assertIsNone(self.row(name)['returned'])
            self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertEqual(self.result(name)['actions'][-2:],['log:command_error','diagnostic'])

    def test_positive_hal_command_status_is_an_error(self):
        self.assertEqual(self.row('positive_command_error')['stopped'],self.row('poll_command_error')['stopped'])

    def test_direct_and_bounce_data_errors_have_distinct_assertions(self):
        for name,owner,line in (('poll_read_error',0x80c37b7c,0x12a),('poll_write_error',0x80c37b7c,0x132),
                                ('bounce_read_error',0x80c37b98,0x16f),('bounce_write_error',0x80c37b98,0x17b)):
            self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))
            self.assertIsNone(self.row(name)['returned'])

    def test_failed_bounce_receive_does_not_copy_to_caller(self):
        self.assertNotIn('copy_from_bounce:64',self.result('bounce_read_error')['actions'])
        self.assertEqual(self.row('bounce_read_error')['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())

    def test_feature_read_and_write_emit_descriptor_opcodes(self):
        read=self.command('read_feature');write=self.command('write_feature')
        self.assertEqual((read[0],read[2],read[5],read[7],read[9]),(0,0xf,0xb0,1,1))
        self.assertEqual((write[0],write[2],write[5],write[7],write[9]),(2,0x1f,0xb0,1,1))
        self.assertEqual(self.row('write_feature')['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())

    def test_feature_write_truncates_to_one_byte(self):
        self.assertEqual(self.result('write_feature_truncates'),self.result('write_feature'))
        expected=hashlib.sha256(b'\xa5').hexdigest()
        self.assertIn('transmit_poll:1:'+expected+':0',self.result('write_feature')['actions'])

    def test_supplied_partial_read_leaves_remaining_caller_bytes_intact(self):
        expected=bytes((0x5a+i*7)&255 for i in range(3))+initial_buffer()[3:]
        self.assertEqual(self.row('partial_supplied_read')['buffer_sha256'],hashlib.sha256(expected).hexdigest())

    def test_write_enable_cache_load_and_program_emit_no_data_phase(self):
        for name,opcode,address,addr_bytes in (('write_enable',6,0,0),('read_to_cache',0x13,0x1234,3),
                                             ('program_execute',0x10,0x1234,3)):
            frame=self.command(name)
            self.assertEqual((frame[2],frame[5],frame[7],frame[9]),(opcode,address,addr_bytes,0))

    def test_erase_builder_converts_block_to_page_address(self):
        frame=self.command('erase')
        self.assertEqual((frame[2],frame[5],frame[7],frame[9]),(0xd8,0x1234*64,3,0))

    def test_cache_read_builders_choose_single_and_quad_phase_codes(self):
        single=self.command('cache_read_x1');quad=self.command('cache_read_x4')
        self.assertEqual((single[2],single[8]),(3,1))
        self.assertEqual((quad[2],quad[8]),(0x6b,3))
        self.assertEqual((quad[7],quad[9],quad[10]),(2,64,8))

    def test_nonblocking_named_builders_select_bounce_path(self):
        self.assertIn('receive_bounce:64:0',self.result('cache_read_bounce')['actions'])
        self.assertTrue(any(a.startswith('transmit_bounce:64:') for a in self.result('cache_write_bounce')['actions']))

    def test_builder_error_stops_at_inner_platform_assertion(self):
        self.assertEqual(self.row('command_builder_hal_error')['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=0x11f))

    def test_busy_ready_status_preserves_non_busy_bits(self):
        expected=bytearray(initial_buffer());expected[0]=0x10
        self.assertEqual((self.row('busy_ready')['returned'],self.row('busy_ready')['buffer_sha256']),
                         (0,hashlib.sha256(expected).hexdigest()))

    def test_busy_second_read_follows_delay_and_feature_sequence(self):
        actions=self.result('busy_second_read')['actions']
        self.assertEqual(actions.count('wait_us:5'),2)
        self.assertEqual(actions.count('receive_poll:1:0'),2)
        self.assertNotIn('log:busy_timeout',actions)

    def test_zero_busy_timeout_checks_deadline_before_ready_status(self):
        row=self.row('busy_zero_timeout');expected=bytearray(initial_buffer());expected[0]=255
        self.assertEqual((row['returned'],row['buffer_sha256']),(0,hashlib.sha256(expected).hexdigest()))
        self.assertEqual(self.result('busy_zero_timeout')['actions'][-1],'log:busy_timeout')

    def test_busy_timeout_returns_zero_and_keeps_ff_output(self):
        actions=self.result('busy_timeout')['actions'];expected=bytearray(initial_buffer());expected[0]=255
        self.assertEqual(actions.count('receive_poll:1:0'),200)
        self.assertEqual((self.row('busy_timeout')['returned'],self.row('busy_timeout')['buffer_sha256']),
                         (0,hashlib.sha256(expected).hexdigest()))

    def test_ready_at_exact_busy_deadline_is_still_timeout(self):
        self.assertEqual(self.row('busy_ready_at_deadline'),self.row('busy_timeout'))
        self.assertEqual(self.result('busy_ready_at_deadline')['actions'][-1],'log:busy_timeout')

    def test_erase_busy_uses_tick_delay_and_same_deadline_order(self):
        self.assertEqual(self.result('erase_busy_second_ready')['actions'].count('sleep_tick:1'),2)
        self.assertNotIn('log:busy_timeout',self.result('erase_busy_second_ready')['actions'])
        self.assertIn('log:busy_timeout',self.result('erase_busy_first_deadline')['actions'])
        self.assertIn('log:busy_timeout',self.result('erase_busy_second_deadline')['actions'])

    def test_wait_and_deinit_return_zero_without_hardware_services(self):
        self.assertEqual(self.result('wait_passthrough')['actions'],['wait_us:5'])
        self.assertEqual(self.result('deinit_noop')['actions'],[])
        self.assertEqual(self.row('wait_passthrough')['returned'],0)
        self.assertEqual(self.row('deinit_noop')['returned'],0)

    def test_probe_bounds_reject_excessive_payload_or_rom_string(self):
        for changes in (dict(size=513),dict(responses=[]),dict(rom_version='v'*25)):
            with self.assertRaises(ValueError):contract(copy.deepcopy(self.cases['poll_read'])|changes)

    def test_public_native_observations_match_all_cases(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-bus.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(51,51))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['export_sha256']),len(report['byte_range_sha256'])),(18,18))


if __name__=='__main__':unittest.main()
