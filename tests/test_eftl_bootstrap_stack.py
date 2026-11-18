import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.eftl_bootstrap_stack import CONTEXT,PART,ROLES,contract,native_vectors


class EftlBootstrapStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def context(self,name):return bytes.fromhex(self.row(name)['eftl_context_hex'])
    def counters(self,name):return struct.unpack_from('<3H',self.context(name),56)
    def mapping(self,name):return struct.unpack('<8H',bytes.fromhex(self.row(name)['mapping_hex']))
    def flags(self,name):return bytes.fromhex(self.row(name)['write_flags_hex'])
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]

    def test_original_lookup_and_geometry_collect_chip_fields_and_partition_extent(self):
        name='bootstrap_connected';ctx=self.context(name);self.result(name,0)
        self.assertEqual(struct.unpack_from('<I',ctx)[0],PART)
        self.assertEqual(struct.unpack_from('<5I',ctx,8),(64,2048,8,512,512))
        self.assertEqual(struct.unpack_from('<7H',ctx,28),(64,16,4,4,20,36,52))
        queries=[int(a.split(':')[1]) for a in self.actions(name) if a.startswith('driver_ioctl:')]
        self.assertEqual(queries[:9],[2,1,3,2,3,18,19,20,21]);self.assertIn('init_strcmp:eftl:eftl',self.actions(name))

    def test_allocated_roles_have_exact_sizes_bindings_and_final_hashes(self):
        name='bootstrap_connected';r=self.row(name);ctx=self.context(name)
        self.assertEqual(r['init_allocation_attempts'],3);self.assertEqual(r['init_frees'],0)
        self.assertEqual(struct.unpack_from('<3I',ctx,44),tuple(p for p,n in ROLES))
        self.assertEqual([(h['pointer'],h['size'],h['active']) for h in r['init_heap']],[(p,n,True) for p,n in ROLES])
        for h,key in zip(r['init_heap'],('write_flags_hex','mapping_hex','scratch_sha256')):
            expected=r[key] if key.endswith('sha256') else hashlib.sha256(bytes.fromhex(r[key])).hexdigest()
            self.assertEqual(h['sha256'],expected)

    def test_full_initialization_resets_fast_mode_and_enables_readback(self):
        ctx=self.context('bootstrap_connected');self.assertEqual(ctx[4:7],bytes([165,1,0]))
        self.assertEqual(self.counters('bootstrap_connected'),(6,2,0));self.assertEqual(self.mapping('bootstrap_connected')[:2],(0,1))
        self.assertEqual(self.row('bootstrap_connected')['init_ready'],0)

    def test_successful_repeat_uses_context_marker_without_extra_effects(self):
        self.assertEqual(self.row('bootstrap_repeat'),self.row('bootstrap_connected'))
        self.assertEqual(self.actions('bootstrap_repeat'),self.actions('bootstrap_connected'))

    def test_marked_context_guard_preserves_old_live_allocations(self):
        name='bootstrap_marker_guard';r=self.row(name);self.result(name,0)
        self.assertEqual((r['init_allocation_attempts'],r['init_frees']),(0,0));self.assertEqual(len(r['init_heap']),3)
        self.assertTrue(all(h['active'] for h in r['init_heap']));self.assertNotIn('init_lookup:eftl',self.actions(name))
        self.assertFalse(any(a.startswith('init_fill:') for a in self.actions(name)))

    def test_force_cleanup_frees_old_generations_before_context_reset_and_reuse(self):
        name='bootstrap_force_cleanup';r=self.row(name);self.result(name,0)
        self.assertEqual((r['init_allocation_attempts'],r['init_frees']),(3,3));self.assertEqual(len(r['init_heap']),6)
        self.assertEqual([h['active'] for h in r['init_heap']],[False]*3+[True]*3)
        actions=self.actions(name);reset=actions.index(f'init_fill:{CONTEXT}:0:64')
        for p,n in ROLES:self.assertLess(actions.index('init_free:'+str(p)),reset)

    def test_each_allocation_failure_stops_at_null_fill_with_earlier_buffers_live(self):
        for i,(p,n) in enumerate(ROLES,1):
            name=f'bootstrap_alloc_{i}_failure';r=self.row(name);self.assertIsNone(r['returned'])
            self.assertEqual(r['stopped'],dict(kind='null_memset',size=n,fill=0 if i==1 else 255))
            self.assertEqual(r['init_allocation_attempts'],i);self.assertEqual(len(r['init_heap']),i-1)
            self.assertTrue(all(h['active'] for h in r['init_heap']));self.assertEqual(self.context(name)[4],0)
            self.assertEqual(struct.unpack_from('<I',self.context(name),44+(i-1)*4)[0],0)
            self.assertNotIn(0x13,self.opcodes(name))

    def test_oob_error_preserves_allocations_without_global_publication(self):
        self.result('bootstrap_oob_error',-1)
        for name in ('bootstrap_oob_error','bootstrap_lazy_oob_error'):
            r=self.row(name);self.assertEqual(r['init_ready'],0);self.assertEqual(r['init_capacity'],0x7fffffff)
            self.assertEqual(self.context(name)[4],0);self.assertEqual(len(r['init_heap']),3)
            self.assertTrue(all(h['active'] for h in r['init_heap']));self.assertNotIn('log:init_ready',self.actions(name))

    def test_forced_reinitialization_error_retains_preexisting_global_ready(self):
        name='bootstrap_force_oob_error_ready';r=self.row(name);self.result(name,-1)
        self.assertEqual(self.context(name)[4],0)
        self.assertEqual((r['init_ready'],r['init_capacity'],r['init_frees']),(1,0x7fffffff,3))
        self.assertEqual([h['active'] for h in r['init_heap']],[False]*3+[True]*3)
        self.assertNotIn('log:init_ready',self.actions(name))

    def test_lazy_wrapper_publishes_full_capacity_and_repeat_skips_initialization(self):
        name='bootstrap_lazy';r=self.row(name);self.assertIsNone(r['returned'])
        self.assertEqual((r['init_ready'],r['init_capacity'],r['init_block_size']),(1,1048576,131072))
        self.assertIn('log:init_ready',self.actions(name));self.assertEqual(self.row('bootstrap_lazy_repeat'),r)
        self.assertEqual(self.actions('bootstrap_lazy_repeat'),self.actions(name))

    def test_global_ready_guard_skips_context_validation_and_allocations(self):
        name='bootstrap_lazy_ready';r=self.row(name);self.assertEqual(self.context(name)[4],0)
        self.assertEqual((r['init_ready'],r['init_capacity'],r['init_allocation_attempts']),(1,0x7fffffff,0))
        self.assertNotIn('init_lookup:eftl',self.actions(name));self.assertEqual(self.opcodes(name),[])

    def test_reserved_blocks_reduce_published_capacity(self):
        name='bootstrap_lazy_reserved_capacity';r=self.row(name)
        self.assertEqual(self.counters(name),(6,1,1));self.assertEqual((r['init_ready'],r['init_capacity']),(1,917504))

    def test_positive_first_scan_resets_maps_flags_and_counters_before_repair(self):
        name='bootstrap_retry';self.result(name,0);self.assertEqual(self.counters(name),(8,0,0))
        self.assertEqual(self.mapping(name),(65535,)*8);self.assertEqual(self.flags(name),b'\xfe'*8)
        self.assertEqual([a for a in self.actions(name) if a.startswith('init_scan:')],['init_scan:0','init_scan:1'])
        self.assertEqual(self.actions(name).count(f'init_fill:{ROLES[0][0]}:0:8'),2)
        self.assertEqual(self.actions(name).count(f'init_fill:{ROLES[1][0]}:255:16'),2)

    def test_repair_success_with_all_blocks_reserved_can_publish_zero_capacity(self):
        name='bootstrap_retry_all_reserved';r=self.row(name);self.assertEqual(self.counters(name),(0,0,8))
        self.assertEqual(self.context(name)[4],165);self.assertEqual((r['init_ready'],r['init_capacity']),(1,0))
        self.assertEqual(self.mapping(name),(65535,)*8);self.assertEqual(self.flags(name),b'\xff'*8)

    def test_duplicate_and_stale_dma_remain_distinct_from_valid_media_evidence(self):
        name='bootstrap_duplicate';self.result(name,0);self.assertEqual(self.counters(name),(6,1,0))
        self.assertEqual(self.mapping(name)[0],0);self.assertEqual(self.flags(name)[1],254)
        name='bootstrap_generic_stale';self.result(name,0);self.assertEqual(self.counters(name),(8,0,0))
        self.assertEqual(self.actions(name).count('copy_from_bounce:64'),8)

    def test_original_format_executes_erases_and_ignores_selected_erase_errors(self):
        for name in ('bootstrap_force_format','bootstrap_force_erase_errors'):
            self.result(name,0);self.assertEqual(self.opcodes(name).count(0xd8),8)
            self.assertEqual(self.counters(name),(6,2,0));self.assertEqual(self.mapping(name)[:2],(0,1))
        self.assertEqual(self.actions('bootstrap_force_erase_errors').count('log:erase_result'),8)

    def test_geometry_handle_and_missing_registry_keep_precise_boundaries(self):
        name='bootstrap_geometry';self.result(name,0);self.assertEqual(self.row(name)['init_allocation_attempts'],0)
        self.assertIn('init_lookup:eftl',self.actions(name));self.assertNotIn('init_lookup:eftl',self.actions('bootstrap_geometry_handle'))
        self.assertEqual(self.context(name),self.context('bootstrap_geometry_handle'))
        r=self.row('bootstrap_registry_missing');self.assertIsNone(r['returned'])
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c34480,line=0x1a));self.assertEqual(r['init_allocation_attempts'],0)

    def test_contract_rejects_unsupported_slot_reuse_geometry_and_repeats(self):
        base=self.cases['bootstrap_connected']
        for change in (dict(partition_span=262144),dict(scan_count=2),dict(init_alloc_fail_at=4),dict(init_old_mask=7),dict(init_repeat=2,responses=[32]),dict(init_force=1,init_repeat=2)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_every_case_and_preserves_caller_buffer(self):
        report=json.loads(Path('analysis/eftl-bootstrap-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for row in report['cases']:
            self.assertEqual(row['observed'],self.cases[row['name']]['expected']);self.assertEqual(row['observed']['rows'][0]['buffer_sha256'],expected)


if __name__=='__main__':unittest.main()
