import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.qspi_dma import BOUNCE,contract,native_vectors
from analysis_scripts.qspi_hal import BUFFER,DMA


def initial_buffer():return bytes((i*3+1)&255 for i in range(512))


class QspiDmaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def actions(self,name):return self.result(name)['actions']
    def dma_reg(self,name,at):return self.row(name)['dma_mmio'][str(at)]
    def tracked(self,name,receive=True):return struct.unpack_from('<II',bytes.fromhex(self.row(name)['dma_contexts_hex'][int(receive)]),60)

    def test_both_dma_channels_are_actually_initialized_and_published(self):
        row=self.row('receive_dma_ready')
        self.assertEqual(row['dma_registry'][26:28],list(DMA))
        self.assertEqual(sum(v!=0 for v in row['dma_registry']),2)
        self.assertEqual(self.actions('receive_dma_ready').count('dma_w:36:1'),1)
        self.assertEqual(self.dma_reg('receive_dma_ready',5*32+0x104),0x3807)
        self.assertEqual(self.dma_reg('receive_dma_ready',6*32+0x104),0xe7)

    def test_receive_programs_fifo_source_and_caller_destination(self):
        name='receive_dma_ready'
        self.assertEqual(self.dma_reg(name,6*32+0x108),0x93240100)
        self.assertEqual(self.dma_reg(name,6*32+0x10c),BUFFER)
        self.assertEqual(self.dma_reg(name,6*32+0x114),13)
        self.assertEqual(self.row(name)['returned'],0)

    def test_transmit_programs_caller_source_and_fifo_destination(self):
        name='transmit_dma_ready'
        self.assertEqual(self.dma_reg(name,5*32+0x108),BUFFER)
        self.assertEqual(self.dma_reg(name,5*32+0x10c),0x93240100)
        self.assertEqual(self.dma_reg(name,5*32+0x114),13)
        self.assertEqual(self.row(name)['returned'],0)

    def test_real_backend_replaces_supplied_setup_wait_events(self):
        for name in ('receive_dma_ready','transmit_dma_ready'):
            self.assertFalse(any(a.startswith(('dma_setup:','dma_wait:')) for a in self.actions(name)))
            self.assertTrue(any(a.startswith('dma_cache_prepare:') for a in self.actions(name)))
            self.assertTrue(any(a.startswith('dma_tick:') for a in self.actions(name)))

    def test_receive_and_transmit_keep_distinct_enable_order(self):
        rx=self.actions('receive_dma_ready');tx=self.actions('transmit_dma_ready')
        self.assertLess(rx.index(f'dma_cache_prepare:{BUFFER}:13'),rx.index('w:32:4:13057'))
        self.assertLess(tx.index('w:32:4:13057'),tx.index(f'dma_cache_prepare:{BUFFER}:13'))

    def test_injected_status_does_not_manufacture_payload_movement(self):
        for name in ('receive_dma_ready','transmit_dma_ready'):
            self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())
            self.assertEqual((self.row(name)['tx_hex'],self.row(name)['rx_bytes']),('',0))

    def test_primary_receive_clears_tracking_before_controller_completion(self):
        name='receive_dma_ready';actions=self.actions(name)
        self.assertEqual(self.tracked(name),(0,0))
        self.assertLess(actions.index(f'dma_cache_finish:{BUFFER}:13'),actions.index('tick:0'))

    def test_alternate_receive_returns_zero_with_tracking_still_live(self):
        name='receive_dma_alternate'
        self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(self.tracked(name),(BUFFER,13))
        self.assertFalse(any(a.startswith('dma_cache_finish:') for a in self.actions(name)))

    def test_both_statuses_take_primary_cleanup_path(self):
        self.assertEqual(self.tracked('receive_dma_both'),(0,0))
        self.assertIn(f'dma_cache_finish:{BUFFER}:13',self.actions('receive_dma_both'))

    def test_dma_timeout_skips_controller_wait_and_disables_both_layers(self):
        for mode,ch in (('receive_dma',6),('transmit_dma',5)):
            name=mode+'_timeout'
            self.assertEqual(self.row(name)['returned'],3)
            self.assertEqual(self.row(name)['mmio']['32']&1,0)
            self.assertEqual(self.dma_reg(name,ch*32+0x100)&1,0)
            self.assertFalse(any(a.startswith('tick:') for a in self.actions(name)))
        self.assertEqual(self.tracked('receive_dma_timeout'),(BUFFER,13))

    def test_controller_timeout_is_independent_of_dma_success(self):
        for mode in ('receive_dma','transmit_dma'):
            name=mode+'_qspi_timeout'
            self.assertEqual(self.row(name)['returned'],3)
            self.assertIn('tick:1001',self.actions(name))
        self.assertEqual(self.tracked('receive_dma_qspi_timeout'),(0,0))

    def test_zero_count_and_unaligned_addresses_reach_actual_setup(self):
        for mode,ch in (('receive_dma',6),('transmit_dma',5)):
            self.assertEqual(self.row(mode+'_zero')['returned'],0)
            self.assertEqual(self.dma_reg(mode+'_zero',ch*32+0x114),0)
            at=0x10c if ch==6 else 0x108
            self.assertEqual(self.dma_reg(mode+'_unaligned',ch*32+at),BUFFER+1)

    def test_dma_full_counter_wrap_survives_connected_layers(self):
        for mode in ('receive_dma','transmit_dma'):
            name=mode+'_counter_wrap'
            self.assertEqual(self.row(name)['returned'],0)
            self.assertIn('dma_tick:18446744073709551614',self.actions(name))
            self.assertIn('dma_tick:1',self.actions(name))

    def test_dma_and_controller_waits_each_get_full_timeout_budget(self):
        for mode in ('receive_dma','transmit_dma'):
            name=mode+'_two_wait_budgets';actions=self.actions(name)
            self.assertEqual(self.row(name)['returned'],0)
            self.assertIn('dma_tick:1000',actions)
            self.assertIn('tick:1000',actions);self.assertIn('tick:2000',actions)
            self.assertLess(actions.index('dma_tick:1000'),actions.index('tick:1000'))

    def test_command_submission_connects_to_actual_dma_backend(self):
        for mode in ('receive_dma','transmit_dma'):
            name='command_'+mode
            self.assertEqual(self.row(name)['returned'],0)
            self.assertTrue(any(a.startswith('w:12:4:') for a in self.actions(name)))
            self.assertEqual(self.row(name)['mmio']['8'],13)

    def test_private_read_copies_back_only_after_controller_success(self):
        name='cache_read_bounce_ready';expected=b'\xa5'*64+initial_buffer()[64:]
        self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(self.actions(name)[-1],'copy_from_bounce:64')
        self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.dma_reg(name,6*32+0x10c),BOUNCE)
        self.assertEqual(self.tracked(name),(0,0))

    def test_private_write_copies_input_before_command_and_dma_setup(self):
        name='cache_write_bounce_ready';actions=self.actions(name)
        self.assertLess(actions.index('copy_to_bounce:64'),actions.index('w:0:4:4660'))
        self.assertEqual(self.dma_reg(name,5*32+0x108),BOUNCE)
        expected=initial_buffer()[:64]+b'\xa5'*448
        self.assertEqual(self.row(name)['bounce_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())

    def test_private_read_alternate_status_can_copy_with_tracking_preserved(self):
        name='cache_read_bounce_alternate'
        self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(self.tracked(name),(BOUNCE,64))
        self.assertEqual(self.actions(name)[-1],'copy_from_bounce:64')

    def test_private_timeout_errors_reach_actual_platform_assertion_boundaries(self):
        for mode,line,tag in (('cache_read_bounce',0x16f,'receive_bounce_error'),('cache_write_bounce',0x17b,'transmit_bounce_error')):
            for suffix in ('dma_timeout','qspi_timeout'):
                name=mode+'_'+suffix
                self.assertIsNone(self.row(name)['returned'])
                self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c37b98,line=line))
                self.assertEqual(self.actions(name)[-2:],['log:'+tag,'diagnostic'])
                self.assertNotIn('copy_from_bounce:64',self.actions(name))

    def test_private_dma_vs_controller_failure_leave_different_tracking(self):
        self.assertEqual(self.tracked('cache_read_bounce_dma_timeout'),(BOUNCE,64))
        self.assertEqual(self.tracked('cache_read_bounce_qspi_timeout'),(0,0))
        for name in ('cache_read_bounce_dma_timeout','cache_read_bounce_qspi_timeout'):
            self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())

    def test_fixture_bounds(self):
        c=self.cases['cache_read_bounce_ready']
        for changes in (dict(count=65),dict(count=31),dict(alignment=1),dict(done=[])):
            with self.assertRaises(ValueError):contract(c|changes)

    def test_public_native_observations_match_all_cases(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/qspi-dma.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(28,28))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['byte_range_sha256']),len(report['export_sha256'])),(24,24))


if __name__=='__main__':unittest.main()
