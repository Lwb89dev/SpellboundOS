import copy
import json
from pathlib import Path
import re
import unittest

from analysis_scripts import main_cache_control as cache


class MainCacheControlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={scope:{c['name'].removeprefix('main_cache_control_'):c for c in cache.native_vectors(scope)['cases']} for scope in ('range','critical')}
    def case(self,name,scope='range'):return self.cases[scope][name]
    def row(self,name,scope='range'):return self.case(name,scope)['expected']['rows'][-1]
    def actions(self,name,scope='range'):return self.case(name,scope)['expected']['actions']
    def csr(self,name,reg,scope='range'):return self.row(name,scope)['csrs'][str(reg)]
    def traces(self,name,scope='range'):return [a for a in self.actions(name,scope) if a.startswith('trace:')]

    def test_native_reports_match_every_independent_model_and_fixed_bounds(self):
        for scope,n in (('range',43),('critical',22)):
            e=json.loads(Path('analysis','main-cache-'+scope+'.json').read_bytes());r=e['native_validation']
            self.assertIs(r['hardware_execution'],False);self.assertEqual((r['case_count'],len(r['cases']),r['bound_per_case']),(n,n,cache.BOUND))
            for row in r['cases']:
                self.assertEqual(row['observed'],self.cases[scope][row['name'].removeprefix('main_cache_control_')]['expected']);self.assertTrue(0<row['steps']<=cache.BOUND)
            self.assertEqual(e['native_steps'],sum(row['steps'] for row in r['cases']))

    def test_original_code_hashes_match_harness_seed_and_prior_cache_bodies(self):
        def cfg(path):return json.loads(json.loads(re.search(r'CONFIG=(".*?");',Path(path).read_text()).group(1)))
        runner=cfg('analysis_scripts/ValidateMainCacheControl.java');seed=cfg('analysis_scripts/SeedMainCacheControl.java');self.assertEqual(runner,seed)
        hashes={f'{g["address"]:08x}_{g["size"]:x}':g['sha256'] for g in runner['guards']}
        old=json.loads(Path('analysis/main-dma-cache-guards.json').read_bytes())['byte_range_sha256']
        for scope in ('range','critical'):
            e=json.loads(Path('analysis','main-cache-'+scope+'.json').read_bytes());self.assertEqual(e['byte_range_sha256'],hashes);self.assertEqual(len(e['export_sha256']),10)
            for at in (cache.CONFIG['prepare'],cache.CONFIG['finish']):self.assertEqual(hashes[f'{at:08x}_64'],old[f'{at:08x}_64'])

    def test_three_range_routines_write_their_distinct_command_numbers(self):
        for kind,command in (('prepare',1),('finish',2),('invalidate',0)):
            r=self.row(kind+'_ready');self.assertEqual((r['returned'],r['commands'],r['readbacks']),(0,1,1))
            self.assertEqual(self.csr(kind+'_ready',0x7cc),command);self.assertEqual(self.csr(kind+'_ready',0x7cb),0x1060)

    def test_alignment_and_multi_readback_loop_use_supplied_feedback(self):
        for kind in ('prepare','finish','invalidate'):
            a=self.actions(kind+'_multi_readback');r=self.row(kind+'_multi_readback');self.assertEqual((r['commands'],r['readbacks']),(4,4))
            self.assertEqual([v for v in a if v.startswith('csr_r:1995:')],[f'csr_r:1995:{v}' for v in (0x1000,0x1020,0x1040,0x1060)])
            self.assertEqual([v for v in a if v.startswith('csr_w:1995:')],['csr_w:1995:4096'])

    def test_backward_feedback_is_accepted_until_unsigned_end_comparison_succeeds(self):
        for kind in ('prepare','finish','invalidate'):
            name=kind+'_backward_readback';self.assertEqual((self.row(name)['commands'],self.csr(name,0x7cb)),(3,0x1043))
            self.assertEqual([v for v in self.actions(name) if v.startswith('csr_r:1995:')],['csr_r:1995:4128','csr_r:1995:4096','csr_r:1995:4163'])

    def test_disabled_cache_requests_fence_without_address_or_command_access(self):
        for kind in ('prepare','finish','invalidate'):
            r=self.row(kind+'_disabled');a=self.actions(kind+'_disabled');self.assertEqual((r['commands'],r['readbacks'],r['fences']),(0,0,1));self.assertIn('fence',a)
            self.assertFalse(any(v.startswith(('csr_w:1995:','csr_r:1995:','csr_w:1996:')) for v in a))

    def test_only_control_bit_one_selects_the_command_loop(self):
        for kind in ('prepare','finish','invalidate'):
            self.assertEqual(self.row(kind+'_unrelated_control')['fences'],1);self.assertEqual(self.row(kind+'_all_control_bits')['commands'],1)
            self.assertEqual(self.csr(kind+'_all_control_bits',0x7ca),0xffffffff)

    def test_zero_length_aligned_range_still_issues_one_command(self):
        for kind in ('prepare','finish','invalidate'):
            r=self.row(kind+'_zero_aligned');self.assertEqual((r['commands'],r['readbacks']),(1,1))

    def test_zero_length_unaligned_range_can_require_multiple_feedback_reads(self):
        for kind in ('prepare','finish','invalidate'):
            r=self.row(kind+'_zero_unaligned');self.assertEqual((r['commands'],r['readbacks']),(2,2));self.assertEqual(self.csr(kind+'_zero_unaligned',0x7cb),0x1003)

    def test_wrapped_end_still_executes_one_command_before_comparing(self):
        for kind in ('prepare','finish','invalidate'):
            r=self.row(kind+'_wrapped_end');self.assertEqual((r['returned'],r['commands'],r['readbacks']),(0,1,1));self.assertEqual(self.csr(kind+'_wrapped_end',0x7cb),0x1000)

    def test_zero_and_high_half_addresses_skip_all_rtos_and_csr_work(self):
        for name in ('skip_zero','skip_high_half','skip_negative_one'):
            self.assertEqual(len(self.actions(name)),1);r=self.row(name);self.assertEqual((r['returned'],r['commands'],r['fences'],r['depth']),(0,0,0,0))
            self.assertEqual(r['trace_table'],[0xa5a5a5a5]*12)

    def test_last_positive_address_compares_readback_and_end_as_unsigned(self):
        r=self.row('last_positive');self.assertEqual((r['returned'],r['commands']),(0,1));self.assertEqual(self.csr('last_positive',0x7cb),0x80000000)
        self.assertIn('csr_w:1995:2147483616',self.actions('last_positive'))

    def test_whole_cache_command_is_unconditional_and_has_no_address_readback_loop(self):
        for name in ('all_enabled','all_disabled','all_context','all_runtime_off'):
            r=self.row(name);self.assertEqual((r['returned'],r['commands'],r['readbacks'],r['fences']),(0,1,0,0));self.assertEqual(self.csr(name,0x7cc),6)
            self.assertFalse(any(a.startswith(('csr_r:1994:','csr_r:1995:','csr_w:1995:')) for a in self.actions(name)))

    def test_context_bypass_preserves_mie_and_depth_while_cache_commands_execute(self):
        for kind in ('prepare','finish','invalidate'):
            name=kind+'_context_bypass';r=self.row(name);self.assertEqual((r['commands'],r['depth']),(1,0));self.assertEqual(self.csr(name,0x300),0xa5a50008)
            self.assertFalse(any(a.startswith(('csr_r:768:','csr_w:768:','trace:9:')) for a in self.actions(name)))

    def test_stalled_cache_stops_before_fifth_command_without_firmware_timeout_return(self):
        for kind in ('prepare','finish','invalidate'):
            r=self.row(kind+'_stalled');self.assertIsNone(r['returned']);self.assertEqual(r['stopped'],dict(kind='command_bound',limit=4))
            self.assertEqual((r['commands'],r['readbacks'],r['depth']),(4,4,1));self.assertEqual(r['csrs']['768']&8,0)
            self.assertNotIn('trace:9:2',self.actions(kind+'_stalled'))

    def test_source_writeback_call_disables_mie_before_command_and_enables_after(self):
        a=self.actions('prepare_ready');first=a.index('csr_w:768:2779054080');command=a.index('csr_w:1996:1');last=a.index('csr_w:768:2779054088')
        self.assertLess(first,command);self.assertLess(command,last)

    def test_repeated_prepare_and_finish_preserve_per_operation_state(self):
        rows=self.case('repeated_prepare_finish')['expected']['rows'];self.assertEqual([r['commands'] for r in rows],[1,2]);self.assertEqual([r['depth'] for r in rows],[0,0])
        self.assertEqual([r['trace_table'][7] for r in rows],[cache.RETURNS['prepare'],cache.RETURNS['finish']]);self.assertEqual([r['returned'] for r in rows],[0,0])

    def test_trace_table_records_original_cache_caller_pc_and_completed_transitions(self):
        for kind in ('prepare','finish','invalidate'):
            r=self.row(kind+'_ready');self.assertEqual((r['trace_table'][6],r['trace_table'][7],r['trace_table'][9]),(0,cache.RETURNS[kind],0))
            a=self.traces(kind+'_ready');self.assertEqual([v for v in a if v.startswith('trace:9:')],['trace:9:3','trace:9:1','trace:9:2','trace:9:0'])

    def test_nested_critical_pair_reenables_only_on_last_exit(self):
        rows=self.case('nested_pair','critical')['expected']['rows'];self.assertEqual([r['depth'] for r in rows],[1,2,1,0])
        self.assertEqual([r['csrs']['768']&8 for r in rows],[0,0,0,8]);self.assertEqual(self.traces('nested_pair','critical').count('trace:6:1'),1)

    def test_existing_depth_pair_keeps_mie_disabled_instead_of_restoring_initial_bit(self):
        rows=self.case('existing_depth_pair','critical')['expected']['rows'];self.assertEqual([r['depth'] for r in rows],[3,2]);self.assertEqual([r['csrs']['768']&8 for r in rows],[0,0])
        self.assertEqual(self.row('cache_existing_depth','critical')['depth'],2);self.assertEqual(self.csr('cache_existing_depth',0x300,'critical')&8,0)

    def test_runtime_off_entry_disables_mie_without_depth_tracking_or_exit_reenable(self):
        rows=self.case('runtime_off_pair','critical')['expected']['rows'];self.assertEqual([r['depth'] for r in rows],[0,0]);self.assertEqual([r['csrs']['768']&8 for r in rows],[0,0])
        self.assertNotIn('trace:6:1',self.actions('runtime_off_pair','critical'));self.assertEqual(self.csr('cache_runtime_off',0x300,'critical')&8,0)

    def test_disabled_initial_mie_can_be_enabled_when_depth_returns_to_zero(self):
        rows=self.case('disabled_mie_pair','critical')['expected']['rows'];self.assertEqual([r['csrs']['768']&8 for r in rows],[0,8])
        self.assertEqual(self.csr('cache_mie_disabled',0x300,'critical')&8,8)

    def test_normal_save_leaves_cookie_untouched_while_nonzero_context_writes_zero(self):
        normal=self.case('save_restore_normal','critical')['expected']['rows'];bypass=self.case('save_restore_context','critical')['expected']['rows']
        self.assertEqual([r['saved_word'] for r in normal],[0xa5a5a5a5]*2);self.assertEqual([r['saved_word'] for r in bypass],[0,0])
        self.assertEqual([r['depth'] for r in normal],[1,0]);self.assertEqual([r['depth'] for r in bypass],[0,0])

    def test_restore_argument_does_not_change_selected_wrapper_behavior(self):
        a=self.case('save_restore_normal','critical')['expected'];b=self.case('restore_argument_ignored','critical')['expected'];self.assertEqual(a,b)

    def test_depth_increment_wrap_can_leave_mie_disabled_after_following_empty_exit(self):
        rows=self.case('enter_depth_wrap','critical')['expected']['rows'];self.assertEqual([r['depth'] for r in rows],[0,0]);self.assertEqual([r['csrs']['768']&8 for r in rows],[0,0])
        self.assertNotIn('trace:6:1',self.actions('enter_depth_wrap','critical'));self.assertNotIn('trace:9:2',self.actions('enter_depth_wrap','critical'))

    def test_empty_exit_preserves_mie_while_one_to_zero_exit_enables_it(self):
        empty=self.row('empty_exit','critical');one=self.row('depth_one_exit','critical');two=self.row('depth_two_exit','critical')
        self.assertEqual((empty['depth'],empty['csrs']['768']&8),(0,0));self.assertEqual((one['depth'],one['csrs']['768']&8),(0,8));self.assertEqual((two['depth'],two['csrs']['768']&8),(1,8))
        self.assertFalse(any(v.startswith('csr_') for v in self.actions('empty_exit','critical')))

    def test_nonboolean_scheduler_context_and_diagnostic_flags_use_nonzero_policy(self):
        self.assertEqual(self.case('cache_runtime_nonboolean','critical')['expected']['rows'],self.case('prepare_ready')['expected']['rows'])
        self.assertEqual(self.case('save_restore_nonboolean_context','critical')['expected']['rows'],self.case('save_restore_context','critical')['expected']['rows'])
        self.assertEqual(self.row('cache_trace_nonboolean','critical')['trace_table'],self.row('prepare_ready')['trace_table'])

    def test_disabled_diagnostic_recording_keeps_calls_but_preserves_table(self):
        self.assertEqual(self.row('trace_disabled')['trace_table'],[0xa5a5a5a5]*12);self.assertTrue(self.traces('trace_disabled'))
        self.assertFalse(any(a.startswith('ram_w:'+str(cache.TRACE_TABLE+28)) for a in self.actions('trace_disabled')))
        for row in self.case('trace_disabled_pair','critical')['expected']['rows']:self.assertEqual(row['trace_table'],[0xa5a5a5a5]*12)

    def test_stalled_critical_and_context_paths_retain_distinct_interrupt_states(self):
        a=self.row('cache_stalled_critical','critical');b=self.row('cache_stalled_context','critical')
        self.assertEqual((a['commands'],b['commands']),(3,3));self.assertEqual((a['depth'],b['depth']),(1,0));self.assertEqual((a['csrs']['768']&8,b['csrs']['768']&8),(0,8))
        self.assertEqual(a['stopped'],b['stopped']);self.assertIsNone(a['returned']);self.assertIsNone(b['returned'])

    def test_unrelated_csr_bits_and_unaccessed_address_command_values_are_preserved(self):
        for scope,cases in self.cases.items():
            for c in cases.values():
                for row in c['expected']['rows']:
                    self.assertEqual(row['csrs']['768']&~8,c['mstatus']&~8);self.assertEqual(row['csrs']['1994'],c['control'])
        r=self.row('prepare_disabled');self.assertEqual((r['csrs']['1995'],r['csrs']['1996']),(0x88776655,0xcc))

    def test_contract_rejects_unbounded_feedback_words_and_operations(self):
        c=self.case('prepare_ready')
        for change in (dict(mstatus=-1),dict(depth=1<<32),dict(readbacks=[]),dict(readbacks=[-1]),dict(command_limit=0),dict(command_limit=17),dict(trace_enabled=256),dict(scope='missing'),dict(operations=[])):
            with self.subTest(change=change),self.assertRaises(ValueError):cache.contract(c|change)
        bad=copy.deepcopy(c);bad['operations'][0]['start']=-1
        with self.assertRaises(ValueError):cache.contract(bad)
        bad=copy.deepcopy(c);bad['operations']*=9
        with self.assertRaises(ValueError):cache.contract(bad)

    def test_contract_is_immutable_and_void_helper_rows_claim_no_return_abi(self):
        for scope,name in (('range','prepare_stalled'),('critical','nested_pair')):
            c=self.case(name,scope);before=copy.deepcopy(c);cache.contract(c,scope);self.assertEqual(c,before)
        for c in self.cases['critical'].values():
            for op,row in zip(c['operations'],c['expected']['rows']):
                if op['kind'] in ('enter','exit','save','restore'):self.assertIsNone(row['returned'])


if __name__=='__main__':unittest.main()
