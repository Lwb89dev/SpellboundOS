import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_platform import DMA_ORIGINAL,PIN_FACTS,board_initial,contract,native_vectors
from analysis_scripts.qspi_hal import CTRL


def initial_buffer():return bytes((i*3+1)&255 for i in range(512))


class NandPlatformTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def actions(self,name):return self.result(name)['actions']
    def board(self,name,address):return self.row(name)['board_mmio'][str(address)]
    def dma_word(self,name,index,offset):return struct.unpack_from('<I',bytes.fromhex(self.row(name)['dma_contexts_hex'][index]),offset)[0]

    def test_pin_inventory_has_twenty_three_original_nibble_records(self):
        facts=json.loads(PIN_FACTS.read_bytes());rows=facts['records']
        self.assertIs(facts['hardware_execution'],False)
        self.assertEqual(len(rows),23)
        self.assertEqual([r['index'] for r in rows],list(range(23)))
        self.assertEqual(rows[0],dict(index=0,register=0x910000b4,shift=24))
        self.assertEqual(rows[12],dict(index=12,register=0x910000b8,shift=16))
        self.assertEqual(rows[-1],dict(index=22,register=0x910000bc,shift=28))

    def test_dma_descriptors_fall_inside_original_startup_zero_range(self):
        facts=json.loads(PIN_FACTS.read_bytes());region=facts['dma_startup_zero_region']
        self.assertEqual(region['kind'],'zero')
        self.assertLessEqual(region['destination'],DMA_ORIGINAL[1])
        self.assertGreaterEqual(region['destination']+region['size'],DMA_ORIGINAL[0]+68)
        self.assertEqual(DMA_ORIGINAL[0]-DMA_ORIGINAL[1],68)

    def test_each_function_selector_updates_its_original_table_field(self):
        records=json.loads(PIN_FACTS.read_bytes())['records'];initial=board_initial()
        for row in records:
            index=row['index'];name=('function_p0_'+str(index)) if index<12 else ('function_p1_'+str(index-12))
            old=initial[str(row['register'])];expected=(old&~(15<<row['shift']))|(1<<row['shift'])
            self.assertEqual(self.board(name,row['register']),expected)
            self.assertEqual(len(self.actions(name)),2)
            self.assertIsNone(self.row(name)['returned'])

    def test_combined_function_mask_keeps_selector_order(self):
        records=json.loads(PIN_FACTS.read_bytes())['records']
        writes=[a for a in self.actions('function_combined') if a.startswith('board_w:')]
        self.assertEqual(len(writes),23)
        self.assertEqual([int(a.split(':')[1]) for a in writes],[r['register'] for r in records])

    def test_function_p1_bit_eleven_is_accepted_but_has_no_effect(self):
        self.assertEqual(self.actions('function_p1_bit11'),[])
        self.assertEqual(self.row('function_p1_bit11')['board_mmio'],board_initial())

    def test_outside_function_mask_rejects_all_requested_changes(self):
        for name in ('function_rejects_p0_high','function_rejects_p1_high'):
            self.assertEqual(self.actions(name),[])
            self.assertEqual(self.row(name)['board_mmio'],board_initial())

    def test_function_zero_value_clears_only_selected_nibble(self):
        old=board_initial()[str(0x910000b8)]
        self.assertEqual(self.board('function_zero_mode',0x910000b8),old&~(15<<16))

    def test_function_value_is_not_masked_to_four_bits(self):
        old=board_initial()[str(0x910000b8)]
        self.assertEqual(self.board('function_mode_spill',0x910000b8),(old&~(15<<16))|(31<<16))
        self.assertEqual(self.board('function_mode_spill',0x910000b8)&(1<<20),1<<20)

    def test_pinmux_masks_input_value_to_six_bits(self):
        old=board_initial()[str(0x910001ac)]
        self.assertEqual(self.board('pinmux_p0_first',0x910001ac),(old&~63)|63)
        self.assertEqual(self.board('pinmux_p0_second',0x910001ac),(old&~(63<<8))|(63<<8))

    def test_pinmux_groups_multiple_selectors_into_single_fields(self):
        old=board_initial()[str(0x910001ac)]
        self.assertEqual(self.board('pinmux_p0_group',0x910001ac),(old&~(63<<16))|(63<<16))
        self.assertEqual(len(self.actions('pinmux_p0_group')),2)
        self.assertEqual(len(self.actions('pinmux_p0_upper')),6)

    def test_pinmux_high_groups_touch_separate_registers(self):
        for name,address in (('pinmux_p0_high',0x910001b8),('pinmux_p1_high',0x910001bc)):
            self.assertEqual(len(self.actions(name)),8)
            self.assertTrue(all(int(a.split(':')[1])==address for a in self.actions(name)))

    def test_pinmux_pair_is_two_distinct_read_modify_writes(self):
        for name in ('pinmux_p0_pair','pinmux_p1_pair'):
            actions=self.actions(name)
            self.assertEqual(len(actions),4)
            self.assertEqual([a.split(':')[0] for a in actions],['board_r','board_w','board_r','board_w'])
            self.assertTrue(all(int(a.split(':')[1])==0x910001c0 for a in actions))

    def test_complete_platform_initialization_returns_zero(self):
        for name in ('platform_original_clock','platform_low_clock_word','platform_boundary_99','platform_boundary_100','platform_preserves_other_fields'):
            self.assertEqual(self.row(name)['returned'],0)
            self.assertEqual(self.row(name)['reinit_flag'],0)
            self.assertEqual(self.actions(name).count('fence'),2)

    def test_original_clock_word_threshold_selects_register_field(self):
        for name,selector in (('platform_original_clock',1),('platform_low_clock_word',2),('platform_boundary_99',2),('platform_boundary_100',1)):
            self.assertEqual((self.row(name)['clock_word']>>12)&15,selector)

    def test_board_register_bit_is_actually_cleared_then_set(self):
        actions=self.actions('platform_original_clock');address=0x9a00000c;old=board_initial()[str(address)]
        events=[a for a in actions if a.startswith(('board_r:'+str(address)+':','board_w:'+str(address)+':'))]
        self.assertEqual(events,[f'board_r:{address}:{old}',f'board_w:{address}:{old&~0x200}',f'board_r:{address}:{old&~0x200}',f'board_w:{address}:{old|0x200}'])

    def test_platform_enables_controller_and_dma_without_clobbering_other_bits(self):
        old=board_initial()
        self.assertEqual(self.board('platform_original_clock',0x9a000004),old[str(0x9a000004)]|0x208)
        self.assertEqual(self.board('platform_original_clock',0x9a00000c),old[str(0x9a00000c)]|0x200)

    def test_platform_pin_requests_cover_selected_upper_seven_selectors(self):
        name='platform_original_clock';old=board_initial()
        self.assertEqual(self.board(name,0x910001b0),(old[str(0x910001b0)]&0xc0c0c0c0)|0x3f3f3f3f)
        self.assertEqual(self.board(name,0x910000b8),(old[str(0x910000b8)]&~(0xfff<<16))|(0x111<<16))
        self.assertEqual(self.board(name,0x910000bc),(old[str(0x910000bc)]&~0xffff)|0x1111)

    def test_full_initialization_links_original_adjacent_dma_contexts(self):
        row=self.row('platform_original_clock');words=struct.unpack('<16I',bytes.fromhex(row['context_hex']))
        self.assertEqual(words[0],0x93240000)
        self.assertEqual(words[8:10],DMA_ORIGINAL)
        self.assertEqual(row['dma_registry'][26:28],list(DMA_ORIGINAL))
        self.assertEqual([len(bytes.fromhex(b)) for b in row['dma_contexts_hex']],[68,68])
        for i in range(2):self.assertEqual(self.dma_word('platform_original_clock',i,44),CTRL)

    def test_actual_dma_initializers_clear_tracking_but_preserve_other_descriptor_words(self):
        name='platform_preserves_other_fields'
        for i in range(2):
            self.assertEqual(self.dma_word(name,i,40),0xa5a5a5a5)
            self.assertEqual(self.dma_word(name,i,48),0xa5a5a5a5)
            self.assertEqual(self.dma_word(name,i,60),0)
            self.assertEqual(self.dma_word(name,i,64),0)
        self.assertEqual(struct.unpack_from('<I',bytes.fromhex(self.row(name)['context_hex']),16)[0],1)

    def test_real_controller_initializer_configures_fifo(self):
        self.assertEqual(self.row('platform_original_clock')['mmio']['32'],0x3300)
        self.assertEqual(self.row('platform_original_clock')['mmio']['52'],0x301)
        self.assertEqual(self.row('platform_original_clock')['mmio']['16'],0)

    def test_clock_pins_controller_and_dma_initialization_order(self):
        actions=self.actions('platform_original_clock')
        clock=next(i for i,a in enumerate(actions) if a.startswith('clock_write:'))
        pins=next(i for i,a in enumerate(actions) if a.startswith('board_w:2432696752:'))
        reset=actions.index('w:16:4:256');dma=actions.index('dma_r:36:0')
        self.assertLess(clock,pins);self.assertLess(pins,reset);self.assertLess(reset,dma)

    def test_initialized_private_buffer_read_and_write_paths(self):
        for name in ('platform_read_bounce','platform_write_bounce'):
            self.assertEqual(self.row(name)['returned'],0)
            self.assertIn('version:2',self.actions(name))
            self.assertEqual(self.row(name)['dma_registry'][26:28],list(DMA_ORIGINAL))
        expected=b'\xa5'*64+initial_buffer()[64:]
        self.assertEqual(self.row('platform_read_bounce')['buffer_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.row('platform_write_bounce')['buffer_sha256'],hashlib.sha256(initial_buffer()).hexdigest())

    def test_bus_reinitialization_path_runs_actual_platform_before_transfer(self):
        name='platform_reinit_read_bounce';actions=self.actions(name)
        self.assertEqual(self.row(name)['returned'],0)
        self.assertEqual(self.row(name)['reinit_flag'],0)
        self.assertEqual((self.row(name)['clock_word']>>12)&15,2)
        self.assertLess(actions.index('dma_w:452:231'),actions.index('version:2'))
        self.assertEqual(actions[-1],'copy_from_bounce:64')

    def test_fixture_bounds(self):
        for changes in (dict(pin_value=-1),dict(mode='invalid')):
            with self.assertRaises(ValueError):contract(self.cases['function_p0_0']|changes)
        with self.assertRaises(ValueError):contract(self.cases['platform_read_bounce']|dict(count=31))

    def test_public_native_observations_match_all_cases(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-platform.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(47,47))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['byte_range_sha256']),len(report['export_sha256'])),(28,28))


if __name__=='__main__':unittest.main()
