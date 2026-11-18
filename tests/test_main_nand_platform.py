import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_nand_platform as platform


class MainNandPlatformTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={scope:{c['name'].removeprefix('main_platform_'):c for c in platform.native_vectors(scope)['cases']} for scope in ('init','transfer')}
    def case(self,n):return self.cases['init'][n] if n in self.cases['init'] else self.cases['transfer'][n]
    def row(self,n):return self.case(n)['expected']['rows'][0]
    def actions(self,n):return self.case(n)['expected']['actions']
    def descriptor(self,n,i=0):return bytes.fromhex(self.row(n)['dma_contexts_hex'][i])
    def tracking(self,n,i=1):return struct.unpack_from('<II',self.descriptor(n,i),60)

    def test_startup_facts_place_adjacent_68_byte_records_in_zero_region(self):
        facts=json.loads(platform.FACTS.read_bytes());region=facts['startup_zero_region']
        self.assertEqual(facts['dma_addresses'],list(platform.DMA));self.assertEqual(platform.DMA[1]+68,platform.DMA[0])
        self.assertEqual(facts['startup_sha256'],[hashlib.sha256(bytes(68)).hexdigest()]*2)
        self.assertLessEqual(region['destination'],platform.DMA[1]);self.assertGreaterEqual(region['destination']+region['size'],platform.DMA[0]+68)
        self.assertIs(facts['hardware_execution'],False)

    def test_native_platform_publishes_original_addresses_in_dma_registry(self):
        r=self.row('init');self.assertEqual(r['dma_registry'][26:28],list(platform.DMA));self.assertEqual(sum(bool(x) for x in r['dma_registry']),2)

    def test_controller_and_descriptors_have_reciprocal_original_links(self):
        context=bytes.fromhex(self.row('init')['context_hex']);self.assertEqual(struct.unpack_from('<II',context,32),platform.DMA)
        for i in range(2):self.assertEqual(struct.unpack_from('<I',self.descriptor('init',i),44)[0],platform.hal.CTRL)

    def test_actual_initializer_writes_original_ten_word_dma_profiles(self):
        expected=((12,2,0,2,0,0,6,1,0x93080000,5),(12,1,2,0,0,0,6,1,0x93080000,6))
        for i in range(2):self.assertEqual(struct.unpack_from('<10I',self.descriptor('init',i)),expected[i])

    def test_poisoned_private_fields_are_preserved_while_links_and_tracking_change(self):
        for i in range(2):
            b=self.descriptor('poisoned_private_fields',i);self.assertEqual(len(b),68)
            self.assertEqual(b[40:44]+b[48:60],b'\xa5'*16);self.assertEqual(b[60:68],bytes(8))
            self.assertEqual(struct.unpack_from('<I',b,44)[0],platform.hal.CTRL)

    def test_controller_mode_one_survives_platform_initialization(self):
        c=bytes.fromhex(self.row('controller_mode_one')['context_hex']);self.assertEqual(struct.unpack_from('<I',c,16)[0],1)
        self.assertEqual(self.row('controller_mode_one')['mmio']['32'],0x3300)

    def test_original_clock_word_threshold_and_boundary(self):
        for n,value in (('init',1),('clock_83',2),('clock_99',2),('clock_100',1)):
            self.assertEqual((self.row(n)['clock_word']>>12)&15,value)

    def test_board_bit_clear_and_set_are_separate_native_accesses(self):
        a=self.actions('init');p=platform.BOARD[1];old=self.case('init')['board_initial'][1]
        expected=[f'board_r:{p}:{old}',f'board_w:{p}:{old&~0x200}',f'board_r:{p}:{old&~0x200}',f'board_w:{p}:{old|0x200}']
        self.assertEqual([x for x in a if x.startswith((f'board_r:{p}:',f'board_w:{p}:'))],expected)
        self.assertEqual(self.row('init')['board_mmio'][str(platform.BOARD[0])],self.case('init')['board_initial'][0]|0x208)

    def test_supplied_negative_pin_results_are_ignored_by_actual_initializer(self):
        n='pin_status_ignored';self.assertEqual(self.row(n)['returned'],0)
        self.assertIn('platform_pinmux:-9',self.actions(n));self.assertIn('platform_gpio:-9',self.actions(n))

    def test_initialization_preserves_pending_and_disabled_flags(self):
        r=self.row('init_retains_flags');self.assertEqual((r['returned'],r['reinit_flag'],r['disabled_flag']),(0,1,1))
        self.assertEqual(r['dma_registry'][26:28],list(platform.DMA));self.assertEqual((r['rx_bytes'],r['tx_hex']),(0,''))

    def test_disabled_deferred_transfer_skips_initialization_and_keeps_pending_flag(self):
        n='disabled_keeps_reinit';r=self.row(n)
        self.assertEqual((r['returned'],r['reinit_flag'],r['disabled_flag']),(0xffffffff,1,1));self.assertEqual(self.actions(n),[])
        self.assertEqual(r['dma_registry'],[0]*35);self.assertEqual(bytes.fromhex(r['context_hex']),bytes(64))

    def test_connected_dma_setup_uses_original_records_and_nand_bounce_address(self):
        for n,index,offset in (('cache_read_bounce_ready',1,0x10c),('cache_write_bounce_ready',0,0x108)):
            r=self.row(n);self.assertEqual(r['dma_registry'][26:28],list(platform.DMA))
            self.assertEqual(r['dma_mmio'][str((5+index)*32+offset)],platform.integrated.bus.BOUNCE)
            self.assertFalse(any(x.startswith(('dma_setup:','dma_wait:')) for x in self.actions(n)))

    def test_successful_receive_copies_fixture_sentinels_without_fifo_payload_reads(self):
        r=self.row('cache_read_bounce_ready');raw=bytearray((i*3+1)&255 for i in range(512));raw[:64]=b'\xa5'*64
        self.assertEqual((r['returned'],r['rx_bytes']),(0,0));self.assertEqual(r['buffer_sha256'],hashlib.sha256(raw).hexdigest())

    def test_alternate_status_retains_receive_tracking_with_success(self):
        n='cache_read_bounce_alternate';self.assertEqual(self.row(n)['returned'],0)
        self.assertEqual(self.tracking(n),(platform.integrated.bus.BOUNCE,64));self.assertEqual(self.tracking('cache_read_bounce_ready'),(0,0))

    def test_backend_timeouts_reach_original_bus_assertions_after_initialization(self):
        for n,line in (('cache_read_bounce_dma_timeout',374),('cache_write_bounce_dma_timeout',386)):
            r=self.row(n);self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bca8,line=line))
            self.assertEqual(r['dma_registry'][26:28],list(platform.DMA));self.assertEqual(r['mmio']['32']&1,0)

    def test_late_qspi_timeout_preserves_primary_backend_cleanup(self):
        self.assertEqual(self.tracking('cache_read_bounce_qspi_timeout'),(0,0))
        self.assertEqual(self.tracking('cache_write_bounce_qspi_timeout',0),(0,0))
        self.assertNotIn('copy_from_bounce:64',self.actions('cache_read_bounce_qspi_timeout'))

    def test_pending_reinit_executes_platform_before_revision_and_data(self):
        n='deferred_reinit_read';a=self.actions(n);r=self.row(n)
        self.assertEqual((r['returned'],r['reinit_flag']),(0,0));self.assertEqual(a.count('fence'),2)
        self.assertEqual((r['clock_word']>>12)&15,2)
        self.assertLess(a.index('fence'),next(i for i,x in enumerate(a) if x.startswith('compare:')))

    def test_reinit_after_success_runs_actual_platform_twice(self):
        n='reinit_after_initialized';a=self.actions(n)
        self.assertEqual(self.row(n)['returned'],0);self.assertEqual(a.count('fence'),4)
        self.assertEqual(a.count('w:16:4:256'),2);self.assertEqual(sum(x.startswith('clock_read:') for x in a),2)
        self.assertEqual(sum(x.startswith('clock_write:') for x in a),1);self.assertEqual(self.row(n)['reinit_flag'],0)

    def test_repeated_init_preserves_original_private_fields(self):
        for i in range(2):
            b=self.descriptor('reinit_after_initialized',i);self.assertEqual(b[40:44]+b[48:60],b'\xa5'*16)
            self.assertEqual(len(b),68)

    def test_disabled_after_initialization_keeps_links_and_pending_state(self):
        n='disabled_after_initialized';r=self.row(n)
        self.assertEqual((r['returned'],r['reinit_flag'],r['disabled_flag']),(0xffffffff,1,1))
        self.assertEqual(r['dma_registry'][26:28],list(platform.DMA));self.assertEqual(self.actions(n).count('fence'),2)
        self.assertFalse(any(x.startswith('compare:') for x in self.actions(n)))

    def test_contract_rejects_foreign_scope_bindings_and_public_descriptor_changes(self):
        c=self.case('init')
        for change in (dict(mode='bus'),dict(platform_operation='transfer'),dict(initial_dma_byte=1),dict(board_initial=[]),dict(controller_mode=2),dict(dma_tx=c['dma_tx']|dict(request=13)),dict(dma_rx=c['dma_rx']|dict(descriptor_address=0))):
            with self.subTest(change=change),self.assertRaises(ValueError):platform.contract(c|change,'init')
        for scope in ('foreign',None):
            with self.assertRaises(ValueError):platform.native_vectors(scope)

    def test_native_reports_match_both_bounded_models(self):
        for scope,stem in (('init','main-nand-platform'),('transfer','main-nand-platform-transfer')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False)
            self.assertEqual(r['case_count'],len(self.cases[scope]));self.assertEqual(len(r['cases']),len(self.cases[scope]))
            for c in r['cases']:
                self.assertEqual(c['observed'],self.cases[scope][c['name'].removeprefix('main_platform_')]['expected']);self.assertGreater(c['steps'],0);self.assertLessEqual(c['steps'],platform.hal.BOUND)

    def test_instruction_data_and_startup_hashes_match_fixed_native_guards(self):
        def cfg(path):return json.loads(json.loads(re.search(r'CONFIG=(".*?");',Path(path).read_text()).group(1)))
        guards={(g['address'],g['size']):g['sha256'] for path in ('analysis_scripts/ValidateMainQspiHal.java','analysis_scripts/ValidateMainNandBus.java','analysis_scripts/ValidateMainDmaBackend.java') for g in cfg(path)['guards']}
        for stem in ('main-nand-platform','main-nand-platform-transfer'):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());self.assertEqual(e['startup_facts_sha256'],hashlib.sha256(platform.FACTS.read_bytes()).hexdigest())
            for key,spans in (('byte_range_sha256',platform.ranges()),('data_range_sha256',platform.data_ranges())):
                self.assertEqual(e[key],{f'{a:08x}_{n:x}':guards[(a,n)] for a,n in spans})

    def test_contract_does_not_mutate_fixture_or_descriptor_inputs(self):
        for scope in ('init','transfer'):
            c=next(iter(self.cases[scope].values()));before=copy.deepcopy(c);platform.contract(c,scope);self.assertEqual(c,before)


if __name__=='__main__':unittest.main()
