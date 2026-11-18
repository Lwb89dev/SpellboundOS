import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_dma_backend as dma
from analysis_scripts import main_qspi_dma as connected


class MainDmaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.direct={c['name'].removeprefix('main_dma_'):c for c in dma.native_vectors()['cases']}
        cls.linked={c['name'].removeprefix('main_qspi_dma_'):c for c in connected.native_vectors()['cases']}

    def case(self,n,linked=False):return (self.linked if linked else self.direct)[n]
    def row(self,n,linked=False):return self.case(n,linked)['expected']['rows'][0]
    def actions(self,n,linked=False):return self.case(n,linked)['expected']['actions']
    def tracking(self,n,linked=False,index=0):
        r=self.row(n,linked);return struct.unpack_from('<II',bytes.fromhex(r['dma_contexts_hex' if linked else 'contexts_hex'][index]),60)

    def test_initializer_registers_all_four_recognized_bank_offsets(self):
        for base,bank in dma.boot.BANKS.items():
            n='init_base_'+format(base,'x');c=self.case(n);r=self.row(n)
            self.assertEqual(r['returned'],0);self.assertEqual(len(r['registry']),35)
            self.assertEqual(r['registry'][bank+c['channel']],dma.boot.D);self.assertEqual(sum(bool(x) for x in r['registry']),1)

    def test_invalid_channels_return_one_before_any_mmio_or_tracking_change(self):
        for n in ('init_invalid_channel','init_restricted_channel'):
            self.assertEqual(self.row(n)['returned'],1);self.assertEqual(self.actions(n),[])
            self.assertEqual(self.tracking(n),(dma.boot.DEST,13))

    def test_unknown_base_publishes_fallback_slot_without_boot_fatal_path(self):
        n='init_unknown_base';r=self.row(n);c=self.case(n)
        self.assertEqual(r['returned'],0);self.assertIsNone(r['stopped'])
        self.assertEqual(r['registry'][28+c['channel']],dma.boot.D)
        self.assertEqual(r['registry'][:28],[0]*28);self.assertEqual(self.tracking(n),(0,0))

    def test_initialization_clears_tracking_and_programs_nand_tx_rx_channels(self):
        for n,ch in (('init_nand_tx',5),('init_nand_rx',6)):
            self.assertEqual(self.tracking(n),(0,0));r=self.row(n)
            self.assertEqual(r['mmio'][str(ch*32+0x110)],0)
            self.assertEqual(r['registry'][21+ch],dma.boot.D)
        self.assertNotIn('w:36:1',self.actions('init_already_enabled'))

    def test_setup_directions_have_distinct_cache_and_tracking_effects(self):
        for direction in range(4):
            n='setup_direction_'+str(direction);a=self.actions(n)
            self.assertEqual(sum(x.startswith('cache_prepare:') for x in a),{0:2,1:1,2:1,3:0}[direction])
            self.assertEqual(self.tracking(n),(0,0) if direction==2 else (dma.boot.DEST,13))

    def test_setup_irq_disables_both_interrupt_mask_bits_before_starting(self):
        for direction in range(4):
            n='setup_irq_direction_'+str(direction);r=self.row(n);at=self.case(n)['channel']*32
            self.assertEqual(r['mmio'][str(at+0x104)]&3,0);self.assertEqual(r['mmio'][str(at+0x100)]&1,1)
        self.assertEqual(self.row('setup_direction_1')['mmio'][str(5*32+0x104)],0xffff)

    def test_transfer_count_uses_full_shift_width_modulo_32(self):
        for width,count in ((0,13),(1,6),(2,3),(3,1),(32,13)):
            self.assertEqual(self.row('setup_width_'+str(width))['mmio'][str(5*32+0x114)],count)
        self.assertEqual(self.row('setup_zero_size')['mmio'][str(5*32+0x114)],0)

    def test_remaining_query_rejects_null_arguments_without_changing_output(self):
        self.assertEqual(self.row('remaining_count')['output'],0x44444444)
        for n in ('remaining_null_context','remaining_null_output'):
            self.assertEqual((self.row(n)['returned'],self.row(n)['output']),(1,0xa5a5a5a5));self.assertEqual(self.actions(n),[])

    def test_cancel_finishes_tracking_and_sets_cancel_while_clearing_start(self):
        n='cancel_tracking';self.assertEqual(self.tracking(n),(0,0))
        value=self.row(n)['mmio'][str(5*32+0x100)];self.assertTrue(value&0x8000);self.assertFalse(value&1)
        self.assertEqual(self.actions('cancel_empty_tracking')[0],'cache_finish:0:0')

    def test_native_wait_reads_both_status_registers_before_primary_branch(self):
        self.assertEqual(self.actions('wait_primary')[:3],['tick:0','r:20:32','r:24:0'])
        self.assertEqual(self.actions('wait_both')[:3],['tick:0','r:20:32','r:24:32'])

    def test_primary_clears_tracking_but_alternate_success_retains_it(self):
        self.assertEqual(self.tracking('wait_primary'),(0,0));self.assertEqual(self.tracking('wait_alternate'),(dma.boot.DEST,13))
        self.assertEqual(self.row('wait_alternate')['returned'],0)
        self.assertFalse(any(x.startswith('cache_finish:') for x in self.actions('wait_alternate')))

    def test_timeout_retains_tracking_but_acknowledges_status_and_stops_channel(self):
        n='wait_timeout';r=self.row(n);self.assertEqual(r['returned'],3);self.assertEqual(self.tracking(n),(dma.boot.DEST,13))
        self.assertEqual((r['mmio']['8'],r['mmio']['16']),(0x120,0x220));self.assertEqual(r['mmio'][str(5*32+0x100)]&1,0)

    def test_primary_and_alternate_recheck_results_take_their_own_cleanup_paths(self):
        self.assertEqual(self.row('wait_primary_on_recheck')['returned'],0);self.assertEqual(self.tracking('wait_primary_on_recheck'),(0,0))
        self.assertEqual(self.row('wait_alternate_on_recheck')['returned'],0);self.assertEqual(self.tracking('wait_alternate_on_recheck'),(dma.boot.DEST,13))

    def test_wait_deadline_and_counter_wrap_behave_at_original_boundaries(self):
        for n in ('wait_exact_limit','wait_low_wrap','wait_full_wrap'):self.assertEqual(self.row(n)['returned'],0)
        for n in ('wait_high_elapsed','wait_unrelated_bits'):self.assertEqual(self.row(n)['returned'],3)

    def test_init_setup_wait_combines_tracking_cleanup_and_registry_publication(self):
        for n,ch in (('connected_init_setup_wait_tx',5),('connected_init_setup_wait_rx',6)):
            self.assertEqual(self.row(n)['returned'],0);self.assertEqual(self.tracking(n),(0,0));self.assertEqual(self.row(n)['registry'][21+ch],dma.boot.D)
        self.assertEqual(self.row('connected_init_setup_wait_timeout')['returned'],3)

    def test_direct_contract_rejects_irq_and_unbounded_descriptor_or_time_inputs(self):
        c=self.case('wait_primary')
        for change in (dict(mode='irq'),dict(slots=[0,2]),dict(size=65),dict(base=0x93100000),dict(channel=7),dict(ticks=[]),dict(status_a=[-1]),dict(timeout=1<<32)):
            with self.subTest(change=change),self.assertRaises(ValueError):dma.contract(c|change)

    def test_connected_initializers_publish_both_authored_descriptor_bindings(self):
        r=self.row('receive_dma_ready',True)
        self.assertEqual(r['dma_registry'][26:28],list(connected.hal.boot.DMA))
        self.assertEqual(len(r['dma_registry']),35);self.assertEqual(sum(bool(x) for x in r['dma_registry']),2)

    def test_qspi_wrappers_call_real_backend_setup_and_wait(self):
        a=self.actions('receive_dma_ready',True)
        self.assertTrue(any(x.startswith('dma_w:456:') for x in a));self.assertIn('dma_tick:0',a)
        self.assertFalse(any(x.startswith(('dma_setup:','dma_wait:')) for x in a))

    def test_connected_success_does_not_simulate_peripheral_data_movement(self):
        original=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for n in ('receive_dma_ready','transmit_dma_ready'):
            r=self.row(n,True);self.assertEqual((r['returned'],r['buffer_sha256'],r['rx_bytes'],r['tx_hex']),(0,original,0,''))

    def test_connected_primary_and_alternate_preserve_different_receive_tracking(self):
        self.assertEqual(self.tracking('receive_dma_ready',True,1),(0,0))
        self.assertEqual(self.tracking('receive_dma_alternate',True,1),(connected.hal.boot.BUFFER,13))
        self.assertEqual(self.row('receive_dma_alternate',True)['returned'],0)

    def test_backend_timeout_propagates_and_clears_qspi_request_bit(self):
        for n in ('receive_dma_timeout','transmit_dma_timeout'):
            r=self.row(n,True);self.assertEqual(r['returned'],3);self.assertEqual(r['mmio']['32']&1,0)

    def test_qspi_timeout_after_backend_success_retains_backend_cleanup(self):
        for n,index in (('receive_dma_qspi_timeout',1),('transmit_dma_qspi_timeout',0)):
            self.assertEqual(self.row(n,True)['returned'],3);self.assertEqual(self.tracking(n,True,index),(0,0))

    def test_zero_unaligned_and_wrapping_backend_cases_return_without_copying(self):
        for mode in ('receive_dma','transmit_dma'):
            for suffix in ('_zero','_unaligned','_counter_wrap'):
                self.assertEqual(self.row(mode+suffix,True)['returned'],0)

    def test_separate_backend_and_qspi_wait_budgets_are_observed(self):
        for mode in ('receive_dma','transmit_dma'):
            n=mode+'_two_wait_budgets';a=self.actions(n,True)
            self.assertEqual(self.row(n,True)['returned'],0);self.assertIn('dma_tick:1000',a);self.assertIn('tick:2000',a)

    def test_successful_bounce_receive_copies_unchanged_sentinel_memory(self):
        r=self.row('cache_read_bounce_ready',True);raw=bytearray((i*3+1)&255 for i in range(512));raw[:64]=b'\xa5'*64
        self.assertEqual(r['returned'],0);self.assertEqual(r['buffer_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.actions('cache_read_bounce_ready',True)[-1],'copy_from_bounce:64')

    def test_bounce_timeout_stops_at_original_bus_assertions_and_skips_copyback(self):
        for prefix,line in (('cache_read_bounce',374),('cache_write_bounce',386)):
            for suffix in ('_dma_timeout','_qspi_timeout'):
                r=self.row(prefix+suffix,True);self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bca8,line=line))
        self.assertNotIn('copy_from_bounce:64',self.actions('cache_read_bounce_dma_timeout',True))

    def test_connected_contract_rejects_foreign_bindings_and_supplied_callback_results(self):
        c=self.case('receive_dma_ready',True)
        for change in (dict(mode='receive'),dict(dma_rx=c['dma_rx']|dict(channel=5)),dict(dma_tx=c['dma_tx']|dict(callback_a=True)),dict(dma_tx_hex='00')):
            with self.subTest(change=change),self.assertRaises(ValueError):connected.contract(c|change)

    def test_native_evidence_matches_models_and_fixed_instruction_guards(self):
        def cfg(path):return json.loads(json.loads(re.search(r'CONFIG=(".*?");',Path(path).read_text()).group(1)))
        guards={(g['address'],g['size']):g['sha256'] for path in ('analysis_scripts/ValidateMainDmaBackend.java','analysis_scripts/ValidateMainQspiHal.java','analysis_scripts/ValidateMainNandBus.java') for g in cfg(path)['guards']}
        for stem,cases,prefix,spans in (('main-dma-backend',self.direct,'main_dma_',dma.RANGES),('main-qspi-dma',self.linked,'main_qspi_dma_',connected.ranges())):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False);self.assertEqual(r['case_count'],len(cases));self.assertEqual(len(r['cases']),len(cases))
            for c in r['cases']:
                self.assertEqual(c['observed'],cases[c['name'].removeprefix(prefix)]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],dma.BOUND)
            self.assertEqual(e['byte_range_sha256'],{f'{a:08x}_{n:x}':guards[(a,n)] for a,n in spans})


if __name__=='__main__':unittest.main()
