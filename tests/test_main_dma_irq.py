import copy
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_dma_irq as irq
from analysis_scripts import main_nand_cache_guards as nand


def evidence(stem):return json.loads(Path('analysis',stem+'.json').read_bytes())
def calls(actions):return sum(a.startswith(('cache_prepare:','cache_finish:','dma_cache_prepare:','dma_cache_finish:')) for a in actions)


class MainDmaIrqTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={s:{c['name'].removeprefix('main_irq_'):c for c in irq.native_vectors(s)['cases']} for s in ('irq','cache-guards')}
    def row(self,name):return self.cases['irq'][name]['expected']['rows'][0]
    def actions(self,name):return self.cases['irq'][name]['expected']['actions']
    def tracking(self,name,index=0):return struct.unpack_from('<2I',bytes.fromhex(self.row(name)['contexts_hex'][index]),60)

    def test_four_original_banks_select_their_own_registry_offsets(self):
        for base,bank in irq.dma.boot.BANKS.items():
            name='irq_base_'+format(base,'x');c=self.cases['irq'][name];r=self.row(name)
            self.assertEqual(r['registry'][bank+c['channel']],irq.dma.boot.D);self.assertEqual(len(r['registry']),35)
            self.assertEqual(sum(bool(v) for v in r['registry']),1);self.assertEqual(self.tracking(name),(0,0))

    def test_fallback_irq_consumes_authored_slot_33_without_boot_fatal(self):
        r=self.row('irq_unknown_base');self.assertEqual(r['registry'][33],irq.dma.boot.D);self.assertEqual(r['registry'][:28],[0]*28)
        self.assertIsNone(r['stopped']);self.assertIn('callback_a:5:0:0',self.actions('irq_unknown_base'))

    def test_pending_masks_replace_acknowledgement_words_before_channel_actions(self):
        self.assertEqual(self.actions('irq_both')[:4],['r:4:32','r:12:32','w:8:32','w:16:32'])
        self.assertEqual((self.row('irq_both')['mmio']['8'],self.row('irq_both')['mmio']['16']),(32,32))

    def test_high_pending_bits_are_acknowledged_without_descriptor_dereference(self):
        name='unwalked_high_bits';self.assertEqual(self.actions(name),['r:4:2147483776','r:12:1073741824','w:8:2147483776','w:16:1073741824'])
        self.assertEqual(self.row(name)['registry'],[0]*35)

    def test_primary_finalizes_and_clears_tracking_before_callback(self):
        a=self.actions('irq_primary');self.assertLess(a.index(f'cache_finish:{irq.dma.boot.DEST}:13'),a.index('callback_a:5:0:0'))
        self.assertEqual(self.tracking('irq_primary'),(0,0));self.assertEqual(self.row('irq_primary')['mmio'][str(0x1a0)]&1,0)

    def test_alternate_retains_tracking_and_invokes_low_bit_tagged_callback(self):
        name='irq_alternate';self.assertEqual(self.tracking(name),(irq.dma.boot.DEST,13));self.assertIn(f'callback_b:5:{irq.dma.boot.DEST}:13',self.actions(name))
        self.assertFalse(any(a.startswith('cache_finish:') for a in self.actions(name)))
        ptr=struct.unpack_from('<I',bytes.fromhex(self.row(name)['contexts_hex'][0]),52)[0]
        self.assertEqual(ptr,irq.dma.boot.CONFIG['callback_b']|1)

    def test_both_pending_groups_invoke_primary_before_alternate_with_zero_tracking(self):
        a=self.actions('irq_both');self.assertLess(a.index('callback_a:5:0:0'),a.index('callback_b:5:0:0'));self.assertEqual(self.tracking('irq_both'),(0,0))

    def test_linked_primary_keeps_channel_running_but_clears_tracking(self):
        for name in ('irq_linked_primary','linked_nonboolean'):
            self.assertEqual(self.row(name)['mmio'][str(0x1a0)]&1,1);self.assertEqual(self.tracking(name),(0,0))
            self.assertIn('callback_a:5:0:0',self.actions(name))

    def test_alternate_stops_even_a_linked_channel(self):
        for name in ('linked_both','linked_alternate'):self.assertEqual(self.row(name)['mmio'][str(0x1a0)]&1,0)
        self.assertEqual(self.tracking('linked_alternate'),(irq.dma.boot.DEST,13));self.assertEqual(self.tracking('linked_both'),(0,0))

    def test_missing_primary_and_alternate_callbacks_do_not_skip_cleanup(self):
        a=self.actions('no_primary_callback');self.assertNotIn('callback_a:5:0:0',a);self.assertIn('callback_b:5:0:0',a)
        a=self.actions('no_alternate_callback');self.assertIn('callback_a:5:0:0',a);self.assertNotIn('callback_b:5:0:0',a)
        self.assertEqual(self.tracking('irq_no_callbacks'),(0,0))

    def test_channels_are_dispatched_in_bit_order_even_with_reverse_descriptor_order(self):
        a=[a for a in self.actions('reverse_descriptor_order') if a.startswith('callback_')]
        self.assertEqual(a,['callback_a:0:0:0','callback_b:0:0:0','callback_a:6:0:0'])
        self.assertEqual(self.tracking('reverse_descriptor_order',0),(0,0));self.assertEqual(self.tracking('reverse_descriptor_order',1),(0,0))

    def test_fallback_walk_handles_two_slots_at_indices_28_and_34(self):
        r=self.row('fallback_two');self.assertEqual((r['registry'][28],r['registry'][34]),(irq.dma.boot.D,irq.dma.boot.D+256))
        self.assertEqual([a for a in self.actions('fallback_two') if a.startswith('callback_')],['callback_a:0:0:0','callback_a:6:0:0','callback_b:6:0:0'])

    def test_irq_walk_covers_channel_six_in_the_initializer_restricted_bank(self):
        r=self.row('restricted_bank_channel_six');self.assertEqual(r['registry'][6],irq.dma.boot.D)
        self.assertIn('callback_a:6:0:0',self.actions('restricted_bank_channel_six'))
        old=next(c for c in irq.dma.native_vectors()['cases'] if c['name']=='main_dma_init_restricted_channel');self.assertEqual(old['expected']['rows'][0]['returned'],1)

    def test_empty_tracking_still_requests_cache_finish(self):
        self.assertIn('cache_finish:0:0',self.actions('zero_tracking'));self.assertIn('callback_a:5:0:0',self.actions('zero_tracking'))

    def test_init_setup_irq_connects_registration_mask_changes_and_cleanup(self):
        r=self.row('connected_init_setup_irq');a=self.actions('connected_init_setup_irq')
        self.assertEqual(r['registry'][26],irq.dma.boot.D);self.assertEqual(r['mmio'][str(0x1a4)]&3,0)
        self.assertLess(a.index(f'cache_prepare:{irq.dma.boot.DEST}:13'),a.index('r:4:32'));self.assertEqual(self.tracking('connected_init_setup_irq'),(0,0))

    def test_fallback_initializer_and_irq_consume_the_same_explicit_registry_slot(self):
        r=self.row('fallback_init_setup_irq');self.assertEqual(r['registry'][33],irq.dma.boot.D);self.assertEqual(self.tracking('fallback_init_setup_irq'),(0,0))
        self.assertIn('callback_a:5:0:0',self.actions('fallback_init_setup_irq'))

    def test_irq_cases_claim_no_return_value_and_empty_pending_preserves_tracking(self):
        for c in self.cases['irq'].values():self.assertIsNone(c['expected']['rows'][0]['returned']);self.assertIsNone(c['expected']['rows'][0]['stopped'])
        self.assertEqual(self.tracking('irq_no_pending'),(irq.dma.boot.DEST,13));self.assertEqual(len(self.actions('irq_no_pending')),4)

    def test_native_irq_and_cache_guard_reports_match_models_and_code_hashes(self):
        text=Path('analysis_scripts/ValidateMainDmaIrq.java').read_text();cfg=json.loads(json.loads(re.search(r'IRQ_CONFIG=(".*?");',text).group(1)))
        old=evidence('main-dma-backend')
        for scope,stem,n in (('irq','main-dma-irq',26),('cache-guards','main-dma-cache-guards',72)):
            e=evidence(stem);r=e['native_validation'];self.assertIs(r['hardware_execution'],False);self.assertEqual((r['case_count'],r['bound_per_case']),(n,irq.BOUND))
            for row in r['cases']:
                self.assertEqual(row['observed'],self.cases[scope][row['name'].removeprefix('main_irq_')]['expected']);self.assertTrue(0<row['steps']<=irq.BOUND)
            self.assertTrue(old['byte_range_sha256'].items()<=e['byte_range_sha256'].items());self.assertEqual(len(e['byte_range_sha256']),9)
            for g in cfg['guards']:self.assertEqual(e['byte_range_sha256'][f'{g["address"]:08x}_{g["size"]:x}'],g['sha256'])

    def test_actual_cache_guards_preserve_irq_observations_and_execute_two_extra_instructions_per_call(self):
        old={r['name']:r for r in evidence('main-dma-irq')['native_validation']['cases']}
        new={r['name']:r for r in evidence('main-dma-cache-guards')['native_validation']['cases']}
        for name,row in old.items():
            self.assertEqual(row['observed'],new[name]['observed']);self.assertEqual(new[name]['steps']-row['steps'],2*calls(row['observed']['actions']))

    def test_actual_cache_guards_preserve_all_46_earlier_backend_results(self):
        new={r['name']:r for r in evidence('main-dma-cache-guards')['native_validation']['cases']}
        for row in evidence('main-dma-backend')['native_validation']['cases']:
            actual=new['main_irq_guard_'+row['name'].removeprefix('main_dma_')]
            self.assertEqual(row['observed'],actual['observed']);self.assertEqual(actual['steps']-row['steps'],2*calls(row['observed']['actions']))

    def test_contract_rejects_unpopulated_active_slots_and_unreviewed_cache_addresses(self):
        c=self.cases['irq']['irq_primary']
        for change in (dict(registered=False),dict(irq_a=1),dict(slots=[5,5]),dict(channel=-1),dict(mode='missing'),dict(irq_a=-1),dict(tracked_address=0x1000),dict(native_cache_guards=True),dict(status_a=[])):
            with self.subTest(change=change),self.assertRaises(ValueError):irq.contract(c|change)
        bad=copy.deepcopy(c);bad['context_hex']=['00'*80]
        with self.assertRaises(ValueError):irq.contract(bad)

    def test_contract_keeps_registry_descriptor_and_status_inputs_immutable(self):
        for scope,name in (('irq','fallback_two'),('cache-guards','guard_connected_init_setup_wait_rx')):
            c=self.cases[scope][name];before=copy.deepcopy(c);irq.contract(c,scope);self.assertEqual(c,before)


class MainNandCacheGuardsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={s:{c['name']:c for c in nand.native_vectors(s)['cases']} for s in ('read','program')}
    def report(self,scope):return evidence('main-nand-cache-'+scope)
    def old(self,scope):return evidence('main-nand-async-read' if scope=='read' else 'main-nand-program')

    def test_connected_native_observations_match_models_with_original_hashes(self):
        for scope,n,code_count in (('read',16,74),('program',26,73)):
            e=self.report(scope);r=e['native_validation'];self.assertIs(r['hardware_execution'],False);self.assertEqual((r['case_count'],r['bound_per_case']),(n,nand.BOUND))
            for row in r['cases']:
                self.assertEqual(row['observed'],self.cases[scope][row['name']]['expected']);self.assertTrue(0<row['steps']<=nand.BOUND)
            old=self.old(scope)
            for key in ('byte_range_sha256','data_range_sha256'):self.assertTrue(old[key].items()<=e[key].items())
            self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(code_count,68))
            guards=evidence('main-dma-cache-guards')['byte_range_sha256']
            for a,n in nand.EXTRA:self.assertEqual(e['byte_range_sha256'][f'{a:08x}_{n:x}'],guards[f'{a:08x}_{n:x}'])

    def test_connected_actual_cache_bodies_keep_previous_complete_traces_and_outputs(self):
        for scope in ('read','program'):
            old={r['name']:r for r in self.old(scope)['native_validation']['cases']}
            for row in self.report(scope)['native_validation']['cases']:
                previous=old[row['name'].removeprefix('main_cache_'+scope+'_')];self.assertEqual(row['observed'],previous['observed'])
                self.assertEqual(row['steps']-previous['steps'],2*calls(row['observed']['actions']))

    def test_connected_cache_calls_only_use_signed_nonpositive_selected_arguments(self):
        for scope in ('read','program'):
            seen=[]
            for row in self.report(scope)['native_validation']['cases']:
                for action in row['observed']['actions']:
                    if action.startswith(('dma_cache_prepare:','dma_cache_finish:')):
                        _,address,n=action.split(':');address,n=int(address),int(n);seen.append((address,n))
                        self.assertTrue(address==0 or address>=0x80000000);self.assertLessEqual(n,64)
            self.assertIn((nand.read.BOUNCE,32),seen)
            if scope=='program':self.assertIn((0,0),seen)

    def test_read_alternate_completion_still_retains_tracking_without_finish(self):
        rows={r['name'].removeprefix('main_cache_read_main_async_'):r['observed'] for r in self.report('read')['native_validation']['cases']}
        primary,alternate=rows['dma_ready'],rows['dma_alternate'];p,a=primary['rows'][-1],alternate['rows'][-1]
        self.assertEqual((p['returned'],a['returned']),(0,0));self.assertEqual(p['app_buffer_hex'],a['app_buffer_hex'])
        self.assertEqual(struct.unpack_from('<2I',bytes.fromhex(a['full_dma_contexts_hex'][1]),60),(nand.read.BOUNCE,32))
        self.assertNotIn(f'dma_cache_finish:{nand.read.BOUNCE}:32',alternate['actions'])

    def test_tx_staging_precedes_actual_cache_guard_and_does_not_invent_fifo_dma_writes(self):
        row=next(r for r in self.report('program')['native_validation']['cases'] if r['name'].endswith('_dma_ready'))['observed'];a=row['actions'];last=row['rows'][-1]
        self.assertLess(a.index('app_copy_to_bounce:32'),a.index(f'dma_cache_prepare:{nand.read.BOUNCE}:32'));self.assertIn('dma_cache_finish:0:0',a)
        self.assertEqual(last['app_tx_hex'],'');self.assertEqual(last['full_dma_registry'][26],0x80c10df4)

    def test_guard_execution_preserves_timeout_specific_application_state(self):
        for scope in ('read','program'):
            rows=[r['observed']['rows'][-1] for r in self.report(scope)['native_validation']['cases'] if r['name'].endswith('_dma_timeout')]
            self.assertEqual(len(rows),1);r=rows[0];self.assertEqual(r['stopped']['line'],374 if scope=='read' else 386)
            self.assertTrue(r['main_heap_live']);self.assertEqual(r['main_cache'],nand.base.OBJECT)
            if scope=='read':self.assertEqual(bytes.fromhex(r['app_buffer_hex']),b'\xa5'*128)
            else:self.assertEqual((r['app_page'],r['app_status_reads']),(0,0))

    def test_connected_source_bbt_uid_and_original_binding_are_unchanged(self):
        for scope in ('read','program'):
            for row in self.report(scope)['native_validation']['cases']:
                first,last=row['observed']['rows'][0],row['observed']['rows'][-1]
                for key in ('bbt_state_hex','aux_uid_sha256','aux_uid_length'):self.assertEqual(first[key],last[key])
                self.assertEqual(last['full_dma_registry'][26:28],[0x80c10df4,0x80c10db0])
                if scope=='program':self.assertEqual(bytes.fromhex(last['app_buffer_hex']),nand.program.source())

    def test_connected_contract_requires_guard_scope_and_preserves_inputs(self):
        for scope in ('read','program'):
            c=next(iter(self.cases[scope].values()));before=copy.deepcopy(c);nand.contract(c,scope);self.assertEqual(c,before)
            with self.assertRaises(ValueError):nand.contract(c|dict(native_main_cache_guards=False),scope)
        with self.assertRaises(ValueError):nand.module('erase')


if __name__=='__main__':unittest.main()
