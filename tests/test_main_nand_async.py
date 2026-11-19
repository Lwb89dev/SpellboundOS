import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_nand_async as app


class MainNandAsyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={s:{c['name'].removeprefix('main_async_'):c for c in app.native_vectors(s)['cases']} for s in ('read','erase')}
    def case(self,name):return self.cases['read'][name] if name in self.cases['read'] else self.cases['erase'][name]
    def row(self,name):return self.case(name)['expected']['rows'][-1]
    def actions(self,name):return self.case(name)['expected']['actions']
    def buffer(self,name):return bytes.fromhex(self.row(name)['app_buffer_hex'])
    def rx_context(self,name):return bytes.fromhex(self.row(name)['full_dma_contexts_hex'][1])
    def app_actions(self,name):
        a=self.actions(name);start=next(i for i,v in enumerate(a) if v.startswith(('app_read_native:','app_erase_native:')));return a[start:]

    def test_full_actual_bbt_repair_and_publication_precede_application_read(self):
        a=self.actions('dma_ready');self.assertLess(a.index('main_repair_program_return:0'),a.index('app_read_native:65:16:32'))
        rows=self.case('dma_ready')['expected']['rows'];self.assertEqual((rows[0]['repair_program_return'],rows[0]['app_calls']),(0,0))
        self.assertEqual(rows[0]['main_bbt_magic'],app.repair.read.recovery.policy.MAGIC)

    def test_31_byte_and_32_byte_reads_select_different_transport_paths(self):
        direct=self.row('direct_31');dma=self.row('dma_ready');self.assertEqual((direct['app_dma_calls'],dma['app_dma_calls']),(0,1))
        drows=self.case('direct_31')['expected']['rows'];mrows=self.case('dma_ready')['expected']['rows']
        self.assertEqual(direct['full_rx_bytes']-drows[0]['full_rx_bytes'],32)
        self.assertEqual(dma['full_rx_bytes']-mrows[0]['full_rx_bytes'],1)

    def test_dma_success_copies_authored_retained_bounce_bytes(self):
        self.assertEqual(self.buffer('dma_ready'),b'\x3c'*32+b'\xa5'*96)
        self.assertIn('app_copy_from_bounce:32',self.app_actions('dma_ready'))
        self.assertNotEqual(self.buffer('dma_ready')[:32],app.read.payload(129,16,32))

    def test_64_byte_dma_copy_preserves_output_tail(self):
        self.assertEqual(self.buffer('dma_64'),b'\x3c'*64+b'\xa5'*64);self.assertEqual(self.row('dma_64')['returned'],0)

    def test_small_reads_use_actual_fifo_payload_and_untouched_tail(self):
        for name,n in (('direct_one',1),('direct_tail',13),('direct_31',31)):
            self.assertEqual(self.buffer(name),app.read.payload(129,16,n)+b'\xa5'*(128-n))
            self.assertEqual(self.row(name)['app_dma_calls'],0)

    def test_old_rom_revision_uses_direct_fifo_for_same_32_byte_request(self):
        self.assertEqual((self.row('old_rom_direct')['returned'],self.row('old_rom_direct')['app_dma_calls']),(0,0))
        self.assertEqual(self.buffer('old_rom_direct')[:32],app.read.payload(129,16,32))

    def test_primary_dma_completion_finishes_cache_and_clears_tracking(self):
        a=self.app_actions('dma_ready');self.assertIn(f'dma_cache_prepare:{app.BOUNCE}:32',a);self.assertIn(f'dma_cache_finish:{app.BOUNCE}:32',a)
        self.assertEqual(struct.unpack_from('<2I',self.rx_context('dma_ready'),60),(0,0))

    def test_alternate_dma_completion_returns_success_with_tracking_retained(self):
        a=self.app_actions('dma_alternate');self.assertEqual(self.row('dma_alternate')['returned'],0)
        self.assertNotIn(f'dma_cache_finish:{app.BOUNCE}:32',a)
        self.assertEqual(struct.unpack_from('<2I',self.rx_context('dma_alternate'),60),(app.BOUNCE,32))
        self.assertEqual(self.buffer('dma_alternate'),self.buffer('dma_ready'))

    def test_dma_timeout_stops_before_copy_and_keeps_tracking(self):
        r=self.row('dma_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bca8,line=374))
        self.assertEqual(self.buffer('dma_timeout'),b'\xa5'*128);self.assertEqual(struct.unpack_from('<2I',self.rx_context('dma_timeout'),60),(app.BOUNCE,32))
        self.assertNotIn('app_copy_from_bounce:32',self.app_actions('dma_timeout'))

    def test_qspi_timeout_after_primary_dma_has_distinct_tracking_state(self):
        r=self.row('dma_qspi_timeout');self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bca8,line=374))
        self.assertEqual(struct.unpack_from('<2I',self.rx_context('dma_qspi_timeout'),60),(0,0))
        self.assertEqual(self.buffer('dma_qspi_timeout'),b'\xa5'*128)

    def test_stored_callback_is_not_invoked_by_selected_bus_path(self):
        for c in self.cases['read'].values():self.assertNotIn('app_callback_invoked',c['expected']['actions'])

    def test_ecc_rejection_can_follow_successful_dma_copy(self):
        r=self.row('ecc_after_dma');self.assertEqual((r['returned'],r['app_dma_calls']),((-101)&0xffffffff,1))
        self.assertEqual(self.buffer('ecc_after_dma'),self.buffer('dma_ready'));self.assertIn('app_page_retry:129',self.app_actions('ecc_after_dma'))

    def test_mapping_and_null_buffer_fail_before_dma_or_status(self):
        for name,status in (('reserved',-150),('null',-1)):
            r=self.row(name);self.assertEqual((r['returned'],r['app_status_reads'],r['app_dma_calls']),(status&0xffffffff,0,0))
            self.assertEqual(self.buffer(name),b'\xa5'*128);self.assertEqual(r['app_loaded'],0)

    def test_busy_then_ready_polls_fifo_twice_before_dma(self):
        r=self.row('busy_ready');self.assertEqual((r['returned'],r['app_status_reads'],r['app_dma_calls']),(0,2,1))
        rows=self.case('busy_ready')['expected']['rows'];self.assertEqual(r['aux_status_reads']-rows[0]['aux_status_reads'],2)

    def test_status_transport_timeout_prevents_dma_after_load(self):
        r=self.row('status_ready_timeout');self.assertEqual(r['stopped']['line'],305)
        self.assertEqual((r['app_loaded'],r['app_status_reads'],r['app_dma_calls']),(129,0,0))

    def test_direct_cache_timeout_keeps_output_and_dma_untouched(self):
        r=self.row('direct_cache_ready_timeout');self.assertEqual(r['stopped']['line'],305)
        self.assertEqual((r['app_status_reads'],r['app_dma_calls']),(1,0));self.assertEqual(self.buffer('direct_cache_ready_timeout'),b'\xa5'*128)

    def test_repeated_dma_reads_capture_each_intermediate_output(self):
        rows=self.case('repeated_dma')['expected']['rows'];first,last=rows[-2:]
        self.assertEqual(bytes.fromhex(first['app_buffer_hex']),b'\x3c'*32+b'\xa5'*96)
        self.assertEqual(bytes.fromhex(last['app_buffer_hex']),b'\x3c'*64+b'\xa5'*64)
        self.assertEqual((first['app_dma_calls'],last['app_dma_calls']),(1,2))
        self.assertEqual(first['app_loaded'],129);self.assertEqual(last['app_loaded'],321)

    def test_dma_setup_uses_original_root_rx_binding_and_private_buffer(self):
        r=self.row('dma_ready');self.assertEqual(r['full_dma_registry'][27],0x80c10db0)
        ctx=self.rx_context('dma_ready');self.assertEqual(struct.unpack_from('<I',ctx,44)[0],0x80d94a60)
        regs=r['full_dma_mmio'];self.assertEqual((regs[str(0x1c8)],regs[str(0x1cc)],regs[str(0x1d4)]),(0x93240100,app.BOUNCE,32))

    def test_mode_zero_erase_maps_block_and_requests_sleep_instead_of_delay(self):
        r=self.row('erase_ready');a=self.app_actions('erase_ready');self.assertEqual((r['returned'],r['app_sleep_calls'],r['app_status_reads']),(0,1,1))
        self.assertIn('main_remap_block:12',a);self.assertIn('probe_packet:216:960:0:1',a);self.assertIn('app_sleep:1',a);self.assertNotIn('delay:5',a)

    def test_sleep_poll_busy_then_ready_uses_two_requests(self):
        r=self.row('erase_busy_ready');self.assertEqual((r['returned'],r['app_sleep_calls'],r['app_status_reads']),(0,2,2))

    def test_sleep_poll_erase_failure_returns_minus_104_without_recovery_republication(self):
        r=self.row('erase_failed');self.assertEqual((r['returned'],r['bbt_resume_return']),((-104)&0xffffffff,0))
        self.assertIn('log:app_erase_result:-104',self.app_actions('erase_failed'));self.assertTrue(r['main_heap_live'])

    def test_sleep_poll_exhausts_at_twenty_and_discards_last_ready(self):
        for name in ('erase_exhausted','erase_ready_at_limit'):
            r=self.row(name);self.assertEqual((r['returned'],r['app_sleep_calls'],r['app_status_reads']),((-104)&0xffffffff,20,20))
            self.assertIn('log:busy_timeout',self.app_actions(name))
        last=lambda name:[v for v in self.app_actions(name) if v.startswith('r:256:1:')][-1]
        self.assertEqual(last('erase_exhausted'),'r:256:1:1');self.assertEqual(last('erase_ready_at_limit'),'r:256:1:0')

    def test_sleep_poll_penultimate_ready_is_published(self):
        r=self.row('erase_ready_before_limit');self.assertEqual((r['returned'],r['app_status_reads'],r['app_sleep_calls']),(0,19,19))
        self.assertNotIn('log:busy_timeout',self.app_actions('erase_ready_before_limit'))

    def test_recovered_mapping_is_applied_before_original_guard(self):
        r=self.row('erase_guarded');self.assertEqual((r['returned'],r['app_sleep_calls']),((-250)&0xffffffff,0))
        self.assertIn('log:app_erase_guard',self.app_actions('erase_guarded'))
        self.assertFalse(any(v.startswith('probe_packet:6:') for v in self.app_actions('erase_guarded')))
        r=self.row('erase_guard_boundary');self.assertEqual(r['returned'],0);self.assertIn('probe_packet:216:512:0:1',self.app_actions('erase_guard_boundary'))

    def test_reserved_block_rejection_prevents_sleep_or_erase_command(self):
        r=self.row('erase_reserved');self.assertEqual((r['returned'],r['app_sleep_calls']),((-151)&0xffffffff,0))
        self.assertNotIn('probe_packet:6:0:0:1',self.app_actions('erase_reserved'))

    def test_non_failure_status_bits_do_not_reject_erase(self):
        self.assertEqual(self.row('erase_other_bits')['returned'],0);self.assertEqual(self.row('erase_other_bits')['app_status_reads'],1)

    def test_erase_command_timeouts_stop_before_sleep(self):
        for name in ('erase_enable_timeout','erase_command_timeout'):
            r=self.row(name);self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a1bc8c,line=294));self.assertEqual(r['app_sleep_calls'],0)

    def test_erase_status_timeouts_distinguish_completed_status_read(self):
        ready=self.row('erase_status_ready_timeout');done=self.row('erase_status_done_timeout')
        self.assertEqual((ready['app_sleep_calls'],done['app_sleep_calls']),(1,1))
        self.assertEqual((ready['app_status_reads'],done['app_status_reads']),(0,1))
        self.assertEqual((ready['stopped']['line'],done['stopped']['line']),(305,305))

    def test_transport_assertions_after_publication_leave_registered_object(self):
        for name in ('dma_timeout','dma_qspi_timeout','status_ready_timeout','erase_command_timeout'):
            r=self.row(name);self.assertIsNone(r['returned']);self.assertTrue(r['main_heap_live']);self.assertEqual(r['main_cache'],app.base.OBJECT)
            self.assertEqual(r['main_bbt_magic'],app.repair.read.recovery.policy.MAGIC)

    def test_native_evidence_matches_models_and_fixed_new_guards(self):
        old=json.loads(Path('analysis/main-nand-bbt-program.json').read_bytes())
        text=Path('analysis_scripts/ValidateMainNandAsync.java').read_text();cfg=json.loads(json.loads(re.search(r'ASYNC_CONFIG=(".*?");',text).group(1)))
        for scope,stem in (('read','main-nand-async-read'),('erase','main-nand-async-erase')):
            e=json.loads(Path('analysis',stem+'.json').read_bytes());r=e['native_validation'];self.assertIs(r['hardware_execution'],False)
            self.assertEqual((r['case_count'],len(r['cases'])),(len(self.cases[scope]),len(self.cases[scope])));self.assertEqual(r['bound_per_case'],app.BOUND)
            for row in r['cases']:
                self.assertEqual(row['observed'],self.cases[scope][row['name'].removeprefix('main_async_')]['expected']);self.assertTrue(0<row['steps']<=app.BOUND)
            for key in ('byte_range_sha256','data_range_sha256'):self.assertTrue(old[key].items()<=e[key].items())
            for key,guards in (('byte_range_sha256',cfg['guards']),('data_range_sha256',cfg['data_guards'])):
                for g in guards:self.assertEqual(e[key][f'{g["address"]:08x}_{g["size"]:x}'],g['sha256'])
            self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(72,68))

    def test_original_guard_flag_is_readonly_and_published_guard_geometry_is_used(self):
        c=self.row('erase_guarded');self.assertEqual((c['probe_guard_blocks'],c['probe_guard_pages']),(8,512))
        e=json.loads(Path('analysis/main-nand-async-erase.json').read_bytes())
        self.assertEqual(e['data_range_sha256'][f'{app.GUARD:08x}_1'],hashlib.sha256(b'\x01').hexdigest())

    def test_contract_rejects_unbounded_dma_busy_and_out_of_backing_inputs(self):
        c=self.case('dma_ready')
        for change in (dict(native_main_async=False),dict(app_statuses=[1]),dict(app_bounce_byte=256),dict(app_dma_a=[]),dict(app_dma_a=[0],app_dma_b=[0],app_dma_ticks=[0]),dict(app_done_fail_at=33)):
            with self.subTest(change=change),self.assertRaises(ValueError):app.contract(c|change,'read')
        bad=copy.deepcopy(c);bad['operations'][-1]['size']=65
        with self.assertRaises(ValueError):app.contract(bad,'read')

    def test_contract_keeps_original_records_operations_and_dma_inputs_unchanged(self):
        c=self.case('dma_alternate');before=copy.deepcopy(c);app.contract(c,'read');self.assertEqual(c,before)
        c=self.case('erase_exhausted');before=copy.deepcopy(c);app.contract(c,'erase');self.assertEqual(c,before)

    def test_application_io_preserves_recovered_bbt_uid_and_authored_bounce_source(self):
        bounce=hashlib.sha256(b'\x3c'*512).hexdigest()
        for cases in self.cases.values():
            for c in cases.values():
                first,last=c['expected']['rows'][0],c['expected']['rows'][-1]
                for key in ('bbt_state_hex','aux_uid_sha256','aux_uid_length'):self.assertEqual(first[key],last[key])
                self.assertEqual(first['app_bounce_sha256'],bounce);self.assertEqual(last['app_bounce_sha256'],bounce)


if __name__=='__main__':unittest.main()
