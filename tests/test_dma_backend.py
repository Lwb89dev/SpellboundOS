import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.dma_backend import BANKS,D,DEST,SOURCE,contract,native_vectors


class DmaBackendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def actions(self,name):return self.result(name)['actions']
    def word(self,name,at,index=0):return struct.unpack_from('<I',bytes.fromhex(self.row(name)['contexts_hex'][index]),at)[0]
    def mmio(self,name,at):return self.row(name)['mmio'][str(at)]
    def tracked(self,name,index=0):return self.word(name,60,index),self.word(name,64,index)

    def test_initialization_publishes_each_controller_bank(self):
        for base,bank in BANKS.items():
            name='init_base_'+format(base,'x');channel=3 if base==0x92000000 else 6
            self.assertEqual(self.row(name)['returned'],0)
            self.assertEqual(self.row(name)['registry'][bank+channel],D)
            self.assertEqual(sum(v!=0 for v in self.row(name)['registry']),1)

    def test_nand_tx_and_rx_channel_configuration(self):
        self.assertEqual(self.mmio('init_nand_tx',5*32+0x100),0x460090)
        self.assertEqual(self.mmio('init_nand_tx',5*32+0x104),0x3807)
        self.assertEqual(self.mmio('init_nand_rx',6*32+0x100),0x4600c0)
        self.assertEqual(self.mmio('init_nand_rx',6*32+0x104),0xe7)

    def test_init_clears_tracking_and_channel_link_word(self):
        self.assertEqual(self.tracked('init_nand_tx'),(0,0))
        self.assertEqual(self.mmio('init_nand_tx',5*32+0x110),0)

    def test_init_rejects_invalid_channels_before_mmio(self):
        for name in ('init_invalid_channel','init_restricted_channel'):
            self.assertEqual(self.row(name)['returned'],1)
            self.assertEqual(self.actions(name),[])

    def test_unknown_base_stops_after_partial_register_changes(self):
        name='init_unknown_base'
        self.assertIsNone(self.row(name)['returned'])
        self.assertEqual(self.row(name)['stopped'],dict(kind='fatal_boundary',line=0x2a))
        self.assertEqual(self.tracked(name),(0,0))
        self.assertTrue(any(a.startswith('w:') for a in self.actions(name)))
        self.assertEqual(self.row(name)['registry'],[0]*28)

    def test_already_enabled_controller_is_not_rewritten(self):
        self.assertNotIn('w:36:1',self.actions('init_already_enabled'))
        self.assertEqual(self.mmio('init_already_enabled',36),0x101)

    def test_memory_direction_omits_peripheral_mode_bit(self):
        self.assertEqual(self.mmio('init_memory_mode',5*32+0x100)&0x80,0)
        self.assertEqual(self.mmio('init_memory_mode',5*32+0x104),7)

    def test_init_masks_numeric_fields_without_general_enum_rejection(self):
        self.assertEqual(self.row('init_other_direction')['returned'],0)
        name='init_field_masks'
        expected=(7<<11)|(6<<8)|(7<<16)|(3<<22)|(3<<5)|(2<<3)|0x80
        self.assertEqual(self.mmio(name,5*32+0x100),expected)
        self.assertEqual(self.mmio(name,5*32+0x104),7|(15<<9))

    def test_setup_direction_selects_cache_and_tracking(self):
        for direction in range(4):
            name='setup_direction_'+str(direction)
            cache=[a for a in self.actions(name) if a.startswith('cache_prepare:')]
            expected=[]
            if direction in (0,2):expected.append(f'cache_prepare:{SOURCE}:13')
            if direction in (0,1):expected.append(f'cache_prepare:{DEST}:13')
            self.assertEqual(cache,expected)
            self.assertEqual(self.tracked(name),(0,0) if direction==2 else (DEST,13))

    def test_setup_programs_source_destination_and_scaled_count(self):
        for width,count in ((0,13),(1,6),(2,3),(3,1),(32,13)):
            name='setup_width_'+str(width)
            self.assertEqual(self.mmio(name,5*32+0x108),SOURCE)
            self.assertEqual(self.mmio(name,5*32+0x10c),DEST)
            self.assertEqual(self.mmio(name,5*32+0x114),count)
            self.assertEqual(self.row(name)['returned'],0)

    def test_zero_size_still_programs_and_enables_channel(self):
        name='setup_zero_size'
        self.assertEqual(self.mmio(name,5*32+0x114),0)
        self.assertEqual(self.mmio(name,5*32+0x100)&1,1)
        self.assertEqual(self.tracked(name),(DEST,0))

    def test_setup_irq_variant_clears_two_configuration_bits(self):
        self.assertEqual(self.mmio('setup_irq_direction_1',5*32+0x104),0xfffc)
        self.assertEqual(self.mmio('setup_direction_1',5*32+0x104),0xffff)

    def test_remaining_query_and_null_arguments(self):
        self.assertEqual((self.row('remaining_count')['returned'],self.row('remaining_count')['output']),(0,0x44444444))
        for name in ('remaining_null_context','remaining_null_output'):
            self.assertEqual((self.row(name)['returned'],self.row(name)['output']),(1,0xa5a5a5a5))
            self.assertEqual(self.actions(name),[])

    def test_cancel_finishes_cache_then_clears_tracking_and_channel(self):
        name='cancel_tracking'
        self.assertEqual(self.actions(name)[0],f'cache_finish:{DEST}:13')
        self.assertEqual(self.tracked(name),(0,0))
        self.assertEqual(self.mmio(name,5*32+0x100)&0x8001,0x8000)
        self.assertEqual(self.row(name)['returned'],0)

    def test_cancel_calls_cache_boundary_even_for_empty_tracking(self):
        self.assertEqual(self.actions('cancel_empty_tracking')[0],'cache_finish:0:0')

    def test_wait_samples_both_status_words_before_primary_branch(self):
        self.assertEqual(self.actions('wait_primary')[:3],['tick:0','r:20:32','r:24:0'])

    def test_primary_wait_finishes_cache_and_clears_tracking(self):
        self.assertEqual(self.row('wait_primary')['returned'],0)
        self.assertEqual(self.tracked('wait_primary'),(0,0))
        self.assertIn(f'cache_finish:{DEST}:13',self.actions('wait_primary'))

    def test_alternate_wait_returns_zero_without_cache_or_tracking_clear(self):
        self.assertEqual(self.row('wait_alternate')['returned'],0)
        self.assertEqual(self.tracked('wait_alternate'),(DEST,13))
        self.assertFalse(any(a.startswith('cache_finish:') for a in self.actions('wait_alternate')))

    def test_primary_status_takes_precedence_when_both_are_set(self):
        self.assertEqual(self.row('wait_both')['returned'],0)
        self.assertEqual(self.tracked('wait_both'),(0,0))
        self.assertIn(f'cache_finish:{DEST}:13',self.actions('wait_both'))

    def test_wait_timeout_returns_three_and_preserves_tracking(self):
        for name in ('wait_timeout','wait_high_elapsed','wait_unrelated_bits'):
            self.assertEqual(self.row(name)['returned'],3)
            self.assertEqual(self.tracked(name),(DEST,13))

    def test_wait_always_requests_status_clears_and_disables_channel(self):
        for name in ('wait_primary','wait_alternate','wait_timeout'):
            self.assertEqual(self.mmio(name,8),0x120)
            self.assertEqual(self.mmio(name,16),0x220)
            self.assertEqual(self.mmio(name,5*32+0x100)&1,0)

    def test_final_status_recheck_can_win_after_timeout(self):
        self.assertEqual(self.row('wait_primary_on_recheck')['returned'],0)
        self.assertEqual(self.tracked('wait_primary_on_recheck'),(0,0))
        self.assertEqual(self.row('wait_alternate_on_recheck')['returned'],0)
        self.assertEqual(self.tracked('wait_alternate_on_recheck'),(DEST,13))

    def test_wait_deadline_and_unsigned_wrap(self):
        for name in ('wait_exact_limit','wait_low_wrap','wait_full_wrap'):
            self.assertEqual(self.row(name)['returned'],0)
            self.assertEqual(self.tracked(name),(0,0))

    def test_irq_uses_each_controller_registry_bank(self):
        for base in BANKS:
            name='irq_base_'+format(base,'x');channel=3 if base==0x92000000 else 6
            self.assertIsNone(self.row(name)['returned'])
            self.assertIsNone(self.row(name)['stopped'])
            self.assertIn(f'callback_a:{channel}:0:0',self.actions(name))

    def test_primary_irq_disables_unlinked_channel_and_cleans_before_callback(self):
        name='irq_primary';actions=self.actions(name)
        self.assertEqual(actions[:4],['r:4:32','r:12:0','w:8:32','w:16:0'])
        self.assertLess(actions.index(f'cache_finish:{DEST}:13'),actions.index('callback_a:5:0:0'))
        self.assertEqual(self.tracked(name),(0,0))
        self.assertEqual(self.mmio(name,5*32+0x100)&1,0)

    def test_linked_primary_irq_keeps_channel_enabled(self):
        self.assertEqual(self.mmio('irq_linked_primary',5*32+0x100)&1,1)
        self.assertEqual(self.tracked('irq_linked_primary'),(0,0))

    def test_alternate_irq_preserves_tracking_and_calls_distinct_callback(self):
        name='irq_alternate'
        self.assertIn(f'callback_b:5:{DEST}:13',self.actions(name))
        self.assertFalse(any(a.startswith('cache_finish:') for a in self.actions(name)))
        self.assertEqual(self.tracked(name),(DEST,13))
        self.assertEqual(self.mmio(name,5*32+0x100)&1,0)

    def test_both_irq_bits_call_both_callbacks_after_primary_cleanup(self):
        actions=self.actions('irq_both')
        self.assertLess(actions.index('callback_a:5:0:0'),actions.index('callback_b:5:0:0'))
        self.assertEqual(self.tracked('irq_both'),(0,0))

    def test_irq_optional_callbacks_and_empty_registry_without_pending_bits(self):
        self.assertFalse(any(a.startswith('callback_') for a in self.actions('irq_no_callbacks')))
        self.assertEqual(self.actions('irq_no_pending'),['r:4:0','r:12:0','w:8:0','w:16:0'])
        self.assertFalse(any(a.startswith('callback_') for a in self.actions('irq_high_bit_only')))

    def test_irq_dispatches_multiple_channels_in_order(self):
        events=[a for a in self.actions('irq_two_channels') if a.startswith('callback_')]
        self.assertEqual(events,['callback_a:0:0:0','callback_a:2:0:0','callback_b:2:0:0'])
        self.assertEqual(self.tracked('irq_two_channels',0),(0,0))
        self.assertEqual(self.tracked('irq_two_channels',1),(0,0))

    def test_irq_unknown_base_stops_before_acknowledgement(self):
        self.assertEqual(self.actions('irq_unknown_base'),['r:4:32','r:12:0'])
        self.assertEqual(self.row('irq_unknown_base')['stopped'],dict(kind='fatal_boundary',line=0x2a))

    def test_connected_init_setup_wait_variants(self):
        for name in ('connected_init_setup_wait_tx','connected_init_setup_wait_rx'):
            self.assertEqual(self.row(name)['returned'],0)
            self.assertEqual(self.tracked(name),(0,0))
            self.assertEqual(sum(v!=0 for v in self.row(name)['registry']),1)
        name='connected_init_setup_wait_timeout'
        self.assertEqual(self.row(name)['returned'],3)
        self.assertEqual(self.tracked(name),(DEST,13))

    def test_connected_init_setup_irq(self):
        self.assertIn('callback_a:5:0:0',self.actions('connected_init_setup_irq'))
        self.assertEqual(self.tracked('connected_init_setup_irq'),(0,0))

    def test_fixture_bounds(self):
        c=self.cases['wait_primary']
        for changes in (dict(size=65),dict(channel=8),dict(ticks=[]),dict(status_a=[]),dict(slots=[0,1,2])):
            with self.assertRaises(ValueError):contract(c|changes)

    def test_public_native_observations_match_all_cases(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/dma-backend.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(60,60))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['byte_range_sha256']),len(report['export_sha256'])),(7,7))


if __name__=='__main__':unittest.main()
