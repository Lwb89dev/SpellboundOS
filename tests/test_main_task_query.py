import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_task_query as query
from analysis_scripts import main_freertos_kernel as kernel


class MainTaskQueryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = query.native_vectors()
        cls.cases = {c['name'].removeprefix('main_task_query_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-task-query.json').read_bytes())

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
                         (19, 19, query.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_task_query_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= query.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_new_bodies_and_reuse_kernel_ranges(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in query.CODE + query.DATA}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        guards = query.REUSE + query.CODE + query.DATA
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])
        kernel_hashes = {a: h for a, _, h in kernel.CODE}
        for a, _, h in query.REUSE:
            self.assertEqual(kernel_hashes[a], h)

    def test_call_sites_tie_to_reused_lower_bodies(self):
        sites = {s['site']: s['target'] for s in self.evidence['call_sites']}
        self.assertEqual(sites['0x80d3a5fc'], f'{query.ENTER:#010x}')
        self.assertEqual(sites['0x80d3a70e'], f'{query.EXIT:#010x}')     # vTaskPrioritySet tail call
        self.assertEqual(sites['0x80d3a6c0'], f'{query.REMOVE:#010x}')
        self.assertEqual(sites['0x80d3a6fe'], f'{query.YIELD:#010x}')
        self.assertEqual(len(sites), len(query.CALL_SITES))

    def test_priority_get_enters_critical_and_returns_priority(self):
        self.assertEqual(self.row('priority_get_current')['a0'], 4)
        self.assertEqual(self.row('priority_get_other')['a0'], 7)
        enter = f'call:{query.DIAG}:9:3'      # first diagnostic call of vTaskEnterCritical
        self.assertIn(enter, self.actions('priority_get_current'))

    def test_get_state_maps_each_list_to_its_code(self):
        self.assertEqual(self.row('get_state_running')['a0'], query.E_RUNNING)
        self.assertEqual(self.row('get_state_ready')['a0'], query.E_READY)
        self.assertEqual(self.row('get_state_blocked_delayed')['a0'], query.E_BLOCKED)
        self.assertEqual(self.row('get_state_blocked_overflow')['a0'], query.E_BLOCKED)
        self.assertEqual(self.row('get_state_suspended')['a0'], query.E_SUSPENDED)
        self.assertEqual(self.row('get_state_suspended_waiting_notification')['a0'], query.E_BLOCKED)
        self.assertEqual(self.row('get_state_suspended_pending_event')['a0'], query.E_BLOCKED)
        self.assertEqual(self.row('get_state_deleted_termination')['a0'], query.E_DELETED)
        self.assertEqual(self.row('get_state_container_zero')['a0'], query.E_DELETED)

    def test_get_state_null_handle_asserts(self):
        self.assertEqual(self.row('get_state_null_asserts')['stopped'], 'assert')
        self.assertIn('call:%d:%d:%d:%d' % ((query.ASSERT,) + query.ASSERT_GETSTATE),
                      self.actions('get_state_null_asserts'))

    def test_priority_set_clamps_above_max_and_asserts(self):
        name = 'priority_set_above_max_clamps'
        self.assertEqual(self.row(name)['stopped'], 'assert')
        self.assertIn('call:%d:%d:%d:%d' % ((query.ASSERT,) + query.ASSERT_CLAMP), self.actions(name))

    def test_priority_set_same_priority_is_noop(self):
        name = 'priority_set_same_priority_noop'
        a = query.TCBS[0]
        self.assertIsNone(self.row(name)['stopped'])
        self.assertEqual(self.word_at(name, a + 0x2c), 3)
        self.assertNotIn(f'call:{query.YIELD}', self.calls(name))
        # Only the enter/exit critical diagnostics run, no list surgery.
        self.assertEqual([c for c in self.calls(name) if c.startswith(f'call:{query.DIAG}')][0], f'call:{query.DIAG}:9:3')

    def test_priority_set_lower_current_reorders_and_yields(self):
        name = 'priority_set_lower_current_reorders_and_yields'
        a = query.TCBS[0]
        self.assertEqual(self.word_at(name, a + 0x2c), 1)
        self.assertEqual(self.word_at(name, a + 0x5c), 1)
        self.assertEqual(self.word_at(name, a + 0x18), query.PRIORITIES - 1)
        self.assertEqual(self.word_at(name, query.TOP_READY), 1 << 1)       # bit 3 cleared, bit 1 set
        self.assertIn(f'call:{query.YIELD}', self.calls(name))

    def test_priority_set_raise_other_yields_only_when_reaching_current(self):
        b = query.TCBS[1]
        reach = 'priority_set_raise_other_to_current_yields'
        self.assertEqual(self.word_at(reach, b + 0x2c), 3)
        self.assertEqual(self.word_at(reach, query.TOP_READY), 1 << 3)      # both a and b at 3
        self.assertIn(f'call:{query.YIELD}', self.calls(reach))
        below = 'priority_set_raise_other_below_current_no_yield'
        self.assertEqual(self.word_at(below, b + 0x2c), 3)
        self.assertNotIn(f'call:{query.YIELD}', self.calls(below))

    def test_priority_set_keeps_inherited_active_priority(self):
        name = 'priority_set_inherited_active_not_touched'
        a = query.TCBS[0]
        self.assertEqual(self.word_at(name, a + 0x2c), 3)       # active priority unchanged (inherited > base)
        self.assertEqual(self.word_at(name, a + 0x5c), 4)       # base updated

    def test_priority_set_preserves_marked_event_list_value(self):
        name = 'priority_set_blocked_task_keeps_marked_event_value'
        b = query.TCBS[1]
        self.assertEqual(self.word_at(name, b + 0x5c), 2)
        self.assertEqual(self.word_at(name, b + 0x18), 0x80000006)      # high bit set, left untouched

    def test_contract_rejects_unknown_scope_or_unbounded(self):
        case = dict(self.cases['get_state_running'])
        with self.assertRaises(ValueError):
            query.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            query.contract(dict(case, operations=[]))

    def test_evidence_records_state_codes_and_priorities(self):
        self.assertEqual(self.evidence['state_codes'],
                         dict(running=0, ready=1, blocked=2, suspended=3, deleted=4))
        self.assertEqual(self.evidence['max_priorities'], query.PRIORITIES)
        self.assertEqual(self.evidence['asserts']['clamp'][2], '0x64e')


if __name__ == '__main__':
    unittest.main()
