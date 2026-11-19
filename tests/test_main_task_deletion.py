import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_task_deletion as deletion
from analysis_scripts import main_freertos_kernel as kernel


class MainTaskDeletionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = deletion.native_vectors()
        cls.cases = {c['name'].removeprefix('main_task_deletion_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-task-deletion.json').read_bytes())

    def row(self, name, index=-1):
        return self.cases[name]['expected']['rows'][index]

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def calls(self, name):
        return [a for a in self.actions(name) if a.startswith('call:')]

    def word_at(self, name, address, index=-1):
        for start, data in self.row(name, index)['snapshot'].items():
            start = int(start)
            if start <= address < start + len(data) // 2:
                return struct.unpack_from('<I', bytes.fromhex(data), address - start)[0]
        raise KeyError(hex(address))

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (12, 12, deletion.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_task_deletion_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= deletion.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_new_bodies_and_reuse_kernel_ranges(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in deletion.CODE + deletion.DATA}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        guards = deletion.REUSE + deletion.CODE + deletion.DATA
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])
        reused = {f'{a:#010x}' for a, _, _ in deletion.REUSE}
        self.assertEqual(set(self.evidence['reused_kernel_ranges']), reused)
        # Every reused range carries the same bytes as the kernel scope pinned.
        kernel_hashes = {a: h for a, _, h in kernel.CODE}
        for a, _, h in deletion.REUSE:
            self.assertEqual(kernel_hashes[a], h)

    def test_call_sites_tie_deletion_to_reused_lower_bodies(self):
        sites = {s['site']: s['target'] for s in self.evidence['call_sites']}
        self.assertEqual(sites['0x80d3a470'], f'{deletion.ENTER:#010x}')
        self.assertEqual(sites['0x80d3a4fa'], f'{deletion.DELETE_TCB:#010x}')
        self.assertEqual(sites['0x80d3a53a'], f'{deletion.YIELD:#010x}')
        self.assertEqual(sites['0x80d393c4'], f'{deletion.PORT_FREE:#010x}')
        self.assertEqual(len(sites), len(deletion.CALL_SITES))

    def test_delete_tcb_frees_by_allocation_mode(self):
        free = str(deletion.PORT_FREE)
        self.assertEqual([c for c in self.calls('delete_tcb_static') if free in c], [])
        dynamic = self.calls('delete_tcb_dynamic_stack_and_tcb')
        self.assertEqual(dynamic[0], f'call:{deletion.RECLAIM_REENT}:{deletion.TCBS[0] + 0x88}')
        self.assertEqual([c for c in dynamic if free in c],
                         [f'call:{deletion.PORT_FREE}:{deletion.STACKS[0]}',
                          f'call:{deletion.PORT_FREE}:{deletion.TCBS[0]}'])
        self.assertEqual([c for c in self.calls('delete_tcb_tcb_only') if free in c],
                         [f'call:{deletion.PORT_FREE}:{deletion.TCBS[0]}'])
        self.assertEqual(self.row('delete_tcb_bad_mode')['stopped'], 'assert')
        self.assertIn('call:%d:%d:%d:%d' % ((deletion.ASSERT,) + deletion.ASSERT_ALLOC),
                      self.actions('delete_tcb_bad_mode'))

    def test_delete_other_task_updates_lists_and_counts(self):
        b = deletion.TCBS[1]
        name = 'delete_other_last_in_priority_clears_bit'
        self.assertEqual(self.word_at(name, deletion.TOP_READY), 1 << 3)       # bit 5 cleared
        self.assertEqual(self.word_at(name, deletion.TASK_NUMBER), 8)
        self.assertEqual(self.word_at(name, deletion.NUM_TASKS), 3)
        self.assertEqual(self.word_at(name, deletion.NEXT_UNBLOCK), deletion.MASK)
        self.assertIn(f'call:{deletion.DELETE_TCB}'.split(':')[0], [c.split(':')[0] for c in self.calls(name)])
        shared = 'delete_other_keeps_shared_priority_bit'
        self.assertEqual(self.word_at(shared, deletion.TOP_READY), 1 << 3)     # bit kept, peer remains
        self.assertEqual(self.word_at(shared, deletion.NUM_TASKS), 3)
        event = 'delete_other_removes_event_list_item'
        self.assertEqual(self.word_at(event, b + 0x28), 0)  # event item container cleared
        self.assertEqual(self.word_at(event, 0x81800000), 0)                   # event list emptied

    def test_delete_self_moves_to_termination_and_yields(self):
        a = deletion.TCBS[0]
        for name in ('delete_self_moves_to_termination_and_yields', 'delete_null_handle_resolves_to_current'):
            self.assertEqual(self.row(name)['stopped'], 'yield')
            self.assertEqual(self.word_at(name, deletion.DELETED_WAITING), 1)
            self.assertEqual(self.word_at(name, deletion.TERMINATION), 1)
            self.assertEqual(self.calls(name)[-1], f'call:{deletion.YIELD}')
        full = 'delete_self_moves_to_termination_and_yields'
        self.assertNotIn(str(deletion.DELETE_TCB), ''.join(c.split(':')[1] for c in self.calls(full)))

    def test_delete_self_requires_unsuspended_scheduler(self):
        self.assertEqual(self.row('delete_self_while_suspended_asserts')['stopped'], 'assert')
        self.assertIn('call:%d:%d:%d:%d' % ((deletion.ASSERT,) + deletion.ASSERT_SUSPENDED),
                      self.actions('delete_self_while_suspended_asserts'))
        no_yield = 'delete_self_before_scheduler_start_no_yield'
        self.assertIsNone(self.row(no_yield)['stopped'])
        self.assertEqual(self.word_at(no_yield, deletion.DELETED_WAITING), 1)
        self.assertNotIn(f'call:{deletion.YIELD}', self.calls(no_yield))

    def test_delete_other_before_scheduler_start_does_not_yield(self):
        name = 'delete_other_before_scheduler_start'
        self.assertIsNone(self.row(name)['stopped'])
        self.assertEqual(self.word_at(name, deletion.NUM_TASKS), 3)
        self.assertNotIn(f'call:{deletion.YIELD}', self.calls(name))

    def test_contract_rejects_unknown_scope_or_unbounded(self):
        case = dict(self.cases['delete_tcb_static'])
        with self.assertRaises(ValueError):
            deletion.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            deletion.contract(dict(case, operations=[]))

    def test_evidence_records_allocation_modes_and_asserts(self):
        self.assertEqual(self.evidence['allocation_modes'],
                         {'static_no_free': 2, 'dynamic_stack_and_tcb': 0, 'tcb_only': 1})
        self.assertEqual(self.evidence['asserts']['suspended'][2], '0x516')
        self.assertEqual(self.evidence['termination_list'], f'{deletion.TERMINATION:#010x}')


if __name__ == '__main__':
    unittest.main()
