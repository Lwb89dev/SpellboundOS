import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.qspi_hal import contract,native_vectors


def initial_buffer():return bytes((i*3+1)&255 for i in range(512))


class QspiHalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def actions(self,name):return self.result(name)['actions']
    def mmio(self,name,at):return self.row(name)['mmio'][str(at)]
    def remaining(self,name):return struct.unpack_from('<I',bytes.fromhex(self.row(name)['context_hex']),20)[0]
    def fifo(self,name,write=False):return [a for a in self.actions(name) if a.startswith(('w:' if write else 'r:')+'256:')]

    def test_init_waits_for_reset_self_clear_then_configures_fifo(self):
        name='init_reset_then_ready'
        self.assertEqual(self.actions(name)[:3],['w:16:4:256','r:16:4:256','r:16:4:0'])
        self.assertEqual(self.mmio(name,32),0x3300)
        self.assertEqual(self.mmio(name,52),0x301)
        self.assertEqual(self.row(name)['returned'],0)

    def test_init_preserves_unselected_bits_and_honors_mode_one(self):
        self.assertEqual(self.mmio('init_preserves_other_control_bits',16),(0x44&0xffffffec)|3)
        self.assertEqual(self.actions('init_mode_one').count('w:16:4:256'),1)
        self.assertEqual(sum(a.startswith('w:16:') for a in self.actions('init_mode_one')),1)

    def test_clock_selection_updates_only_nibble_and_shadow(self):
        for value in (1,2,11,17):
            name='clock_'+str(value);expected=(0xa5a5b5a5&0xffff0fff)|((value&15)<<12)
            self.assertEqual((self.row(name)['clock_word'],self.row(name)['clock_shadow']),(expected,expected))
            self.assertEqual(self.actions(name)[0],'clock_read:2779100581')

    def test_same_clock_selector_avoids_mmio_write(self):
        self.assertEqual(len(self.actions('clock_11')),1)
        self.assertEqual(len(self.actions('clock_17')),2)

    def test_phase_packing_matrix(self):
        for suffix,value in (('1_1_1',0),('1_1_2',0x20),('1_1_3',0x40),('1_2_1',0x60),('1_3_1',0x80),('2_1_1',0xa0),('3_1_1',0xc0)):
            self.assertEqual(self.row('pack_'+suffix)['returned'],value)

    def test_unknown_phase_codes_fall_back_to_zero(self):
        for suffix in ('0_1_1','1_0_1','1_1_4'):self.assertEqual(self.row('pack_'+suffix)['returned'],0)

    def test_fifo_count_helpers_scale_units_from_control_fields(self):
        for shift,rx,tx in ((0,1,2),(1,3,5),(2,6,10),(3,12,20)):
            self.assertEqual(self.row('rx_count_'+str(shift))['returned'],rx)
            self.assertEqual(self.row('tx_count_'+str(shift))['returned'],tx)

    def test_command_writes_address_count_and_packed_request(self):
        name='command_read'
        self.assertEqual([self.mmio(name,at) for at in (0,4,8,12)],[0x1234,0x01080002,9,0x6b000041])
        self.assertEqual(self.remaining(name),9)
        self.assertFalse(any(a.startswith('tick:') for a in self.actions(name)))

    def test_command_direction_and_special_mode_seven(self):
        self.assertEqual(self.mmio('command_write',12),0x6b000043)
        self.assertEqual(self.mmio('command_mode_seven',12),0x6b6b0041)
        self.assertEqual(self.mmio('command_mode_seven',4),0x11080002)

    def test_primary_controller_adds_request_bit_zero(self):
        self.assertEqual(self.mmio('command_other_base',12),0x6b000040)

    def test_command_rejects_null_inputs_before_mmio(self):
        for name in ('command_no_context','command_no_frame','command_no_base'):
            self.assertEqual(self.row(name)['returned'],1)
            self.assertEqual(self.actions(name),[])

    def test_zero_count_command_waits_for_completion(self):
        self.assertEqual(self.row('command_empty_ready')['returned'],0)
        self.assertIn('w:36:4:1',self.actions('command_empty_ready'))
        self.assertEqual(self.row('command_empty_timeout')['returned'],3)

    def test_aligned_receive_uses_words_then_byte_tail(self):
        self.assertEqual([int(a.split(':')[2]) for a in self.fifo('receive_ready')],[4,4,1])
        expected=bytes((0x5a+i*7)&255 for i in range(9))+initial_buffer()[9:]
        self.assertEqual(self.row('receive_ready')['buffer_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertEqual((self.remaining('receive_ready'),self.row('receive_ready')['rx_bytes']),(0,9))

    def test_unaligned_receive_uses_only_byte_loads(self):
        self.assertEqual([int(a.split(':')[2]) for a in self.fifo('receive_unaligned')],[1]*9)
        expected=initial_buffer()[:1]+bytes((0x5a+i*7)&255 for i in range(9))+initial_buffer()[10:]
        self.assertEqual(self.row('receive_unaligned')['buffer_sha256'],hashlib.sha256(expected).hexdigest())

    def test_transmit_payload_and_alignment_widths(self):
        self.assertEqual(self.row('transmit_ready')['tx_hex'],initial_buffer()[:9].hex())
        self.assertEqual([int(a.split(':')[2]) for a in self.fifo('transmit_ready',True)],[4,4,1])
        self.assertEqual(self.row('transmit_unaligned')['tx_hex'],initial_buffer()[1:10].hex())
        self.assertEqual([int(a.split(':')[2]) for a in self.fifo('transmit_unaligned',True)],[1]*9)

    def test_selected_fifo_chunk_and_tail_counts(self):
        for n in (1,3,4,5,8):
            self.assertEqual(self.row('receive_count_'+str(n))['rx_bytes'],n)
            self.assertEqual(self.row('transmit_count_'+str(n))['tx_hex'],initial_buffer()[:n].hex())

    def test_zero_length_direct_paths_still_wait_for_completion(self):
        for mode in ('receive','transmit'):
            name=mode+'_empty'
            self.assertEqual(self.row(name)['returned'],0)
            self.assertEqual(self.fifo(name,mode=='transmit'),[])
            self.assertIn('w:36:4:1',self.actions(name))

    def test_fifo_ready_failure_precedes_payload_transfer(self):
        for mode in ('receive','transmit'):
            name=mode+'_data_timeout'
            self.assertEqual(self.row(name)['returned'],3)
            self.assertEqual(self.remaining(name),9)
            self.assertEqual(self.fifo(name,mode=='transmit'),[])

    def test_completion_failure_occurs_after_data_count_is_consumed(self):
        for mode in ('receive','transmit'):
            name=mode+'_completion_timeout'
            self.assertEqual(self.row(name)['returned'],3)
            self.assertEqual(self.remaining(name),0)
            self.assertEqual(len(self.fifo(name,mode=='transmit')),1)

    def test_zero_fifo_stops_at_observed_prefix_without_return_claim(self):
        for mode in ('receive','transmit'):
            name=mode+'_zero_fifo_prefix'
            self.assertIsNone(self.row(name)['returned'])
            self.assertEqual(self.row(name)['stopped'],dict(kind='bounded_prefix',chunks=4))
            self.assertEqual(self.remaining(name),9)
            self.assertEqual(self.fifo(name,mode=='transmit'),[])

    def test_ready_zero_fifo_keeps_restarting_wait_even_with_advancing_time(self):
        for mode in ('receive','transmit'):
            name=mode+'_zero_fifo_advancing_prefix'
            self.assertEqual([a for a in self.actions(name) if a.startswith('tick:')],['tick:0','tick:1001','tick:2002','tick:3003'])
            self.assertEqual(self.actions(name).count('frequency:1000'),4)
            self.assertEqual(self.remaining(name),9)
            self.assertEqual(self.row(name)['stopped'],dict(kind='bounded_prefix',chunks=4))

    def test_dma_receive_setup_precedes_enable_while_transmit_follows_enable(self):
        rx=self.actions('receive_dma_ready');tx=self.actions('transmit_dma_ready')
        self.assertTrue(rx[0].startswith('dma_setup:receive:9:13056:0:'))
        self.assertEqual(tx[:2],['r:32:4:13056','w:32:4:13057'])
        self.assertTrue(tx[2].startswith('dma_setup:transmit:9:13057:0:'))

    def test_dma_preserves_software_count_and_clears_enable(self):
        for mode in ('receive_dma','transmit_dma'):
            self.assertEqual(self.remaining(mode+'_ready'),9)
            self.assertEqual(self.mmio(mode+'_ready',32),0x3300)

    def test_dma_wait_failure_is_propagated_after_enable_clear(self):
        for mode in ('receive_dma','transmit_dma'):
            name=mode+'_wait_error'
            self.assertEqual(self.row(name)['returned'],0xfffffff7)
            self.assertEqual(self.mmio(name,32),0x3300)
            self.assertFalse(any(a.startswith('tick:') for a in self.actions(name)))

    def test_dma_setup_return_is_ignored_in_selected_wrappers(self):
        for mode in ('receive_dma','transmit_dma'):
            self.assertEqual(self.row(mode+'_setup_error_ignored')['returned'],0)
        self.assertEqual(self.row('receive_dma_setup_error_ignored')['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())

    def test_dma_timeout_after_successful_wait_maps_to_three(self):
        for mode in ('receive_dma','transmit_dma'):self.assertEqual(self.row(mode+'_completion_timeout')['returned'],3)

    def test_zero_length_dma_still_calls_setup_and_wait(self):
        for mode in ('receive_dma','transmit_dma'):
            name=mode+'_empty'
            self.assertTrue(any(a.startswith('dma_setup:') and ':0:' in a for a in self.actions(name)))
            self.assertTrue(any(a.startswith('dma_wait:') for a in self.actions(name)))
            self.assertEqual(self.row(name)['returned'],0)

    def test_successful_completion_ack_is_authored_w1c(self):
        self.assertEqual(self.actions('complete_ready')[-1],'w:36:4:1')
        self.assertEqual(self.mmio('complete_ready',36),0)
        self.assertEqual(self.row('complete_timeout')['returned'],3)

    def test_status_on_final_recheck_can_win_after_deadline(self):
        for name in ('complete_ready_on_recheck','wait_receive_ready_recheck','wait_transmit_ready_recheck'):
            self.assertEqual(self.row(name)['returned'],0)
            self.assertIn('tick:1001',self.actions(name))

    def test_exact_deadline_is_inclusive(self):
        self.assertEqual(self.row('complete_exact_deadline')['returned'],0)
        self.assertIn('tick:1000',self.actions('complete_exact_deadline'))

    def test_unsigned_low_and_full_counter_wrap(self):
        for name in ('complete_low_word_wrap','complete_full_counter_wrap'):self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(self.row('complete_high_word_elapsed')['returned'],3)

    def test_frequency_truncation_and_limit_multiplication_wrap(self):
        self.assertEqual(self.row('complete_sub_khz_frequency')['returned'],3)
        self.assertEqual(self.row('complete_limit_multiply_wrap')['returned'],3)

    def test_command_and_data_paths_execute_together(self):
        for mode in ('receive','transmit','receive_dma','transmit_dma'):
            self.assertEqual(self.row('command_'+mode)['returned'],0)
            self.assertTrue(self.actions('command_'+mode)[0].startswith('w:0:4:'))

    def test_actual_nand_builders_connect_through_bus_to_hal_fifo(self):
        for name in ('nand_feature_read','nand_feature_write','nand_cache_read','nand_cache_write'):
            self.assertEqual(self.row(name)['returned'],0)
            self.assertEqual(self.actions(name)[0],'version:2')
        self.assertEqual(self.mmio('nand_feature_read',0),0xb0)
        self.assertEqual(self.mmio('nand_feature_read',12),0x0f000001)
        self.assertEqual(self.row('nand_feature_read')['rx_bytes'],1)
        self.assertEqual(self.row('nand_feature_write')['tx_hex'],'a5')
        self.assertEqual(self.mmio('nand_cache_write',12),0x32000043)

    def test_hal_timeouts_reach_distinct_platform_assertions(self):
        for name,line,tag in (('nand_feature_read_timeout',0x12a,'receive_poll_error'),('nand_feature_write_timeout',0x132,'transmit_poll_error'),('nand_write_enable_timeout',0x11f,'command_error')):
            self.assertIsNone(self.row(name)['returned'])
            self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=line))
            self.assertEqual(self.actions(name)[-2:],['log:'+tag,'diagnostic'])

    def test_fixture_bounds(self):
        for changes in (dict(count=65),dict(alignment=2),dict(ready=[]),dict(ticks=[]),dict(fifo=0,mode='receive')):
            with self.assertRaises(ValueError):contract(self.cases['command_read']|changes)

    def test_public_native_observations_match_all_cases(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/qspi-hal.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(90,90))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['byte_range_sha256']),len(report['export_sha256'])),(19,19))


if __name__=='__main__':unittest.main()
