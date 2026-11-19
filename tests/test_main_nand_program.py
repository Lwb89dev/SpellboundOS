import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_nand_program as program


class MainNandProgramTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name'].removeprefix('main_program_'):c for c in program.native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][-1]
    def actions(self,name):
        a=self.cases[name]['expected']['actions'];i=next(i for i,v in enumerate(a) if v.startswith('app_program_native:'));return a[i:]
    def tx_context(self,name):return bytes.fromhex(self.row(name)['full_dma_contexts_hex'][0])

    def test_repair_and_publication_precede_application_program(self):
        c=self.cases['dma_ready'];a=c['expected']['actions'];self.assertLess(a.index('main_repair_program_return:0'),a.index('app_program_native:513:16:32'))
        first,last=c['expected']['rows'][0],self.row('dma_ready');self.assertEqual(first['app_calls'],0);self.assertEqual(last['app_page'],705)
        self.assertEqual(first['repair_tx_hex'],last['repair_tx_hex']);self.assertEqual(last['repair_program_calls'],1)

    def test_dma_stages_bytes_before_setup_and_does_not_fabricate_fifo_transmission(self):
        a=self.actions('dma_ready');self.assertLess(a.index('app_copy_to_bounce:32'),a.index(f'dma_cache_prepare:{program.BOUNCE}:32'))
        r=self.row('dma_ready');self.assertEqual((r['returned'],r['app_dma_calls'],r['app_tx_hex']),(0,1,''))
        self.assertEqual(r['app_bounce_sha256'],hashlib.sha256(program.source()[:32]+b'\x3c'*480).hexdigest())

    def test_31_and_32_byte_requests_use_distinct_paths(self):
        direct,dma=self.row('direct_31'),self.row('dma_ready');self.assertEqual((direct['app_dma_calls'],dma['app_dma_calls']),(0,1))
        self.assertEqual(bytes.fromhex(direct['app_tx_hex']),program.source()[:31]);self.assertEqual(dma['app_tx_hex'],'')

    def test_small_direct_payload_words_and_tail_are_exact(self):
        for name,n in (('direct_one',1),('direct_tail',13),('direct_31',31)):
            self.assertEqual(bytes.fromhex(self.row(name)['app_tx_hex']),program.source()[:n]);self.assertEqual(self.row(name)['returned'],0)
            self.assertEqual(self.row(name)['app_bounce_sha256'],hashlib.sha256(b'\x3c'*512).hexdigest())

    def test_64_byte_dma_staging_preserves_the_bounce_tail(self):
        r=self.row('dma_64');self.assertEqual(r['app_bounce_sha256'],hashlib.sha256(program.source()[:64]+b'\x3c'*448).hexdigest())
        self.assertEqual(r['app_dma_calls'],1);self.assertEqual(r['app_tx_hex'],'')

    def test_original_tx_binding_registry_link_and_mmio_addresses(self):
        r=self.row('dma_ready');self.assertEqual(r['full_dma_registry'][26],0x80c10df4)
        self.assertEqual(struct.unpack_from('<I',self.tx_context('dma_ready'),44)[0],0x80d94a60)
        regs=r['full_dma_mmio'];self.assertEqual((regs[str(0x1a8)],regs[str(0x1ac)],regs[str(0x1b4)]),(program.BOUNCE,0x93240100,32))

    def test_primary_tx_completion_calls_cache_finish_with_zero_tracking(self):
        a=self.actions('dma_ready');self.assertIn('dma_cache_finish:0:0',a)
        self.assertEqual(struct.unpack_from('<2I',self.tx_context('dma_ready'),60),(0,0))

    def test_alternate_tx_success_skips_cache_finish_and_still_executes_program(self):
        a=self.actions('dma_alternate');self.assertNotIn('dma_cache_finish:0:0',a);self.assertEqual(self.row('dma_alternate')['returned'],0)
        self.assertIn('probe_packet:16:705:0:1',a);self.assertEqual(struct.unpack_from('<2I',self.tx_context('dma_alternate'),60),(0,0))

    def test_dma_timeout_retains_staging_but_prevents_execute(self):
        r=self.row('dma_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bca8,line=386))
        self.assertEqual((r['app_page'],r['app_status_reads']),(0,0));self.assertIn('app_copy_to_bounce:32',self.actions('dma_timeout'))
        self.assertNotIn('probe_packet:16:705:0:1',self.actions('dma_timeout'));self.assertEqual(r['app_bounce_sha256'],self.row('dma_ready')['app_bounce_sha256'])

    def test_qspi_timeout_after_dma_also_prevents_execute(self):
        r=self.row('dma_qspi_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bca8,line=386))
        self.assertEqual((r['app_page'],r['app_status_reads']),(0,0));self.assertIn('dma_cache_finish:0:0',self.actions('dma_qspi_timeout'))
        self.assertNotIn('dma_cache_finish:0:0',self.actions('dma_timeout'))

    def test_old_rom_uses_direct_fifo_for_32_bytes(self):
        r=self.row('old_rom_direct');self.assertEqual((r['returned'],r['app_dma_calls']),(0,0));self.assertEqual(bytes.fromhex(r['app_tx_hex']),program.source()[:32])

    def test_guard_is_applied_after_recovered_mapping(self):
        r=self.row('guarded');a=self.actions('guarded');self.assertEqual((r['returned'],r['app_dma_calls']),((-250)&0xffffffff,0))
        self.assertIn('main_remap_page:256',a);self.assertIn('log:app_program_guard',a);self.assertNotIn('probe_packet:6:0:0:1',a)
        self.assertEqual(r['probe_guard_pages'],512)

    def test_mapped_guard_boundary_is_writable_in_original_software_policy(self):
        r=self.row('guard_boundary');self.assertEqual((r['returned'],r['app_page']),(0,512));self.assertIn('probe_packet:16:512:0:1',self.actions('guard_boundary'))

    def test_reserved_page_rejection_prevents_enable_and_dma(self):
        r=self.row('reserved');self.assertEqual((r['returned'],r['app_status_reads'],r['app_dma_calls']),((-150)&0xffffffff,0,0))
        self.assertNotIn('probe_packet:6:0:0:1',self.actions('reserved'))

    def test_null_and_zero_length_fail_before_enable(self):
        for name in ('null','zero_length'):
            self.assertEqual((self.row(name)['returned'],self.row(name)['app_dma_calls']),(0xffffffff,0));self.assertNotIn('probe_packet:6:0:0:1',self.actions(name))

    def test_exact_column_end_and_past_end_use_original_bounds(self):
        self.assertEqual(self.row('exact_end')['returned'],0);self.assertIn('probe_packet:50:2080:32:1',self.actions('exact_end'))
        self.assertEqual(self.row('past_end')['returned'],0xffffffff);self.assertNotIn('probe_packet:6:0:0:1',self.actions('past_end'))

    def test_unsigned_column_wrap_reaches_actual_command_and_fifo(self):
        r=self.row('wrapping_column');self.assertEqual((r['returned'],r['app_page']),(0,705))
        self.assertIn('probe_packet:50:4294967288:16:1',self.actions('wrapping_column'));self.assertEqual(bytes.fromhex(r['app_tx_hex']),program.source()[:16])

    def test_program_failure_and_other_status_bits_have_distinct_masks(self):
        self.assertEqual(self.row('failed')['returned'],(-102)&0xffffffff);self.assertEqual(self.row('other_bits')['returned'],0)
        self.assertIn('probe_packet:16:705:0:1',self.actions('failed'));self.assertTrue(self.row('failed')['main_heap_live'])

    def test_busy_then_ready_polls_twice_after_execute(self):
        r=self.row('busy_ready');a=self.actions('busy_ready');self.assertEqual((r['returned'],r['app_status_reads']),(0,2))
        self.assertLess(a.index('probe_packet:16:705:0:1'),a.index('probe_packet:15:192:1:0'))

    def test_enable_assertion_prevents_staging_and_dma(self):
        r=self.row('enable_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294))
        self.assertEqual((r['app_page'],r['app_dma_calls']),(0,0));self.assertNotIn('app_copy_to_bounce:32',self.actions('enable_timeout'))

    def test_direct_cache_readiness_timeout_emits_no_payload(self):
        r=self.row('direct_cache_ready_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=313))
        self.assertEqual((r['app_tx_hex'],r['app_page'],r['app_dma_calls']),('',0,0))

    def test_execute_timeout_follows_staging_but_precedes_status(self):
        r=self.row('execute_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294))
        self.assertEqual((r['app_dma_calls'],r['app_page'],r['app_status_reads']),(1,705,0));self.assertIn('app_copy_to_bounce:32',self.actions('execute_timeout'))

    def test_status_ready_and_done_assertions_retain_different_byte_counts(self):
        for name,n in (('status_ready_timeout',0),('status_done_timeout',1)):
            r=self.row(name);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=305));self.assertEqual(r['app_status_reads'],n)
            self.assertEqual((r['app_dma_calls'],r['app_page']),(1,705));self.assertTrue(r['main_heap_live']);self.assertEqual(r['main_cache'],program.base.OBJECT)

    def test_repeated_program_snapshots_and_source_bbt_uid_immutability(self):
        rows=self.cases['repeated_dma']['expected']['rows'];first,last=rows[-2:]
        self.assertEqual((first['app_dma_calls'],last['app_dma_calls']),(1,2));self.assertEqual((first['app_page'],last['app_page']),(705,833))
        self.assertEqual(first['app_bounce_sha256'],self.row('dma_ready')['app_bounce_sha256']);self.assertEqual(last['app_bounce_sha256'],self.row('dma_64')['app_bounce_sha256'])
        for c in self.cases.values():
            rows=c['expected']['rows']
            for key in ('bbt_state_hex','aux_uid_sha256','aux_uid_length'):self.assertEqual(rows[0][key],rows[-1][key])
            for row in rows:self.assertEqual(bytes.fromhex(row['app_buffer_hex']),program.source())
            self.assertNotIn('app_callback_invoked',c['expected']['actions'])

    def test_native_evidence_matches_all_models_and_original_hash_guards(self):
        e=json.loads(Path('analysis/main-nand-program.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False)
        self.assertEqual((r['case_count'],r['bound_per_case']),(26,program.BOUND))
        for row in r['cases']:
            self.assertEqual(row['observed'],self.cases[row['name'].removeprefix('main_program_')]['expected']);self.assertTrue(0<row['steps']<=program.BOUND)
        old=json.loads(Path('analysis/main-nand-bbt-program.json').read_bytes())
        for key in ('byte_range_sha256','data_range_sha256'):self.assertTrue(old[key].items()<=e[key].items())
        text=Path('analysis_scripts/ValidateMainNandProgram.java').read_text();cfg=json.loads(json.loads(re.search(r'PROGRAM_CONFIG=(".*?");',text).group(1)))
        for key,guards in (('byte_range_sha256',cfg['guards']),('data_range_sha256',cfg['data_guards'])):
            for g in guards:self.assertEqual(e[key][f'{g["address"]:08x}_{g["size"]:x}'],g['sha256'])
        self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(71,68))

    def test_contract_requires_bounded_tx_terminal_streams_and_keeps_input_immutable(self):
        c=self.cases['dma_ready'];before=copy.deepcopy(c);program.contract(c);self.assertEqual(c,before)
        for change in (dict(native_main_program=False),dict(app_statuses=[1]),dict(app_dma_a=[64]),dict(app_dma_a=[]),dict(app_dma_ticks=[-1]),dict(app_bounce_byte=256),dict(app_done_fail_at=33)):
            with self.subTest(change=change),self.assertRaises(ValueError):program.contract(c|change)
        bad=copy.deepcopy(c);bad['operations'][-1]['size']=65
        with self.assertRaises(ValueError):program.contract(bad)


if __name__=='__main__':unittest.main()
