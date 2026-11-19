import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_sched_resume as res
from analysis_scripts import main_freertos_kernel as kernel
from analysis_scripts import main_trap_irq as trap


class MainSchedResumeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = res.native_vectors()
        cls.cases = {c['name'].removeprefix('main_sched_resume_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-sched-resume.json').read_bytes())

    def row(self, name, index=-1):
        return self.cases[name]['expected']['rows'][index]

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def word_at(self, name, address):
        for start, data in self.row(name)['snapshot'].items():
            start = int(start)
            if start <= address < start + len(data) // 2:
                return struct.unpack_from('<I', bytes.fromhex(data), address - start)[0]
        raise KeyError(hex(address))

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (9, 9, res.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_sched_resume_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= res.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_reuse_the_whole_kernel_range_set(self):
        self.assertEqual(self.evidence['byte_range_sha256'],
                         {f'{a:08x}_{n:x}': h for a, n, h in res.CODE})
        self.assertEqual(self.evidence['reused_kernel_ranges'], len(kernel.CODE + kernel.DATA))
        guards = trap.CODE + trap.DATA + kernel.CODE + kernel.DATA + res.CODE
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])

    def test_decrement_only_above_one(self):
        name = 'decrement_only'
        self.assertEqual(self.word_at(name, kernel.SUSPENDED), 1)
        self.assertEqual(self.row(name)['a0'], 0)
        self.assertNotIn(f'call:{kernel.TICK}', self.actions(name))

    def test_unlock_with_no_work_returns_zero(self):
        self.assertEqual(self.word_at('unlock_no_work', kernel.SUSPENDED), 0)
        self.assertEqual(self.row('unlock_no_work')['a0'], 0)
        self.assertEqual(self.word_at('unlock_no_tasks', kernel.SUSPENDED), 0)
        self.assertEqual(self.row('unlock_no_tasks')['a0'], 0)

    def test_pending_ready_task_moved_to_ready_list(self):
        name = 'pending_lower_priority_moved'
        b = kernel.TCBS[1]
        # the state list item now points at the priority-1 ready list.
        self.assertEqual(self.word_at(name, b + 4 + 0x10), kernel.READY + 1 * 0x14)
        self.assertEqual(self.word_at(name, kernel.TOP_READY) & (1 << 1), 1 << 1)
        self.assertEqual(self.row(name)['a0'], 0)
        self.assertEqual(self.word_at(name, kernel.YIELD_PENDING), 0)

    def test_pending_higher_priority_requests_yield(self):
        name = 'pending_higher_priority_yields'
        self.assertEqual(self.word_at(name, kernel.YIELD_PENDING), 1)
        self.assertEqual(self.row(name)['a0'], 1)
        self.assertIn(f'call:{kernel.YIELD}', self.actions(name))

    def test_two_pending_tasks_served(self):
        name = 'two_pending_served'
        self.assertEqual(self.word_at(name, kernel.PENDING_READY), 0)
        bitmap = self.word_at(name, kernel.TOP_READY)
        self.assertEqual(bitmap & (1 << 2), 1 << 2)
        self.assertEqual(bitmap & (1 << 4), 1 << 4)

    def test_pended_ticks_caught_up(self):
        name = 'pended_ticks_caught_up'
        self.assertEqual(self.word_at(name, kernel.TICK_COUNT), 3)
        self.assertEqual(self.word_at(name, kernel.PENDED), 0)
        self.assertEqual(self.actions(name).count(f"call:{kernel.DIAG}:9:3"), 1)  # critical enter
        # equal-priority ready peer makes the catch-up request a yield.
        self.assertEqual(self.word_at(name, kernel.YIELD_PENDING), 1)

    def test_pended_ticks_waking_higher_priority_requests_yield(self):
        name = 'pended_ticks_wake_higher_priority'
        self.assertEqual(self.word_at(name, kernel.TICK_COUNT), 102)
        self.assertEqual(self.word_at(name, kernel.YIELD_PENDING), 1)
        self.assertEqual(self.row(name)['a0'], 1)

    def test_not_suspended_asserts(self):
        self.assertEqual(self.row('not_suspended_asserts')['stopped'], 'assert')
        self.assertIn('call:%d:%d:%d:%d' % ((kernel.ASSERT,) + res.ASSERT_RESUME),
                      self.actions('not_suspended_asserts'))

    def test_vectors_are_reproducible(self):
        again = res.native_vectors()
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.vectors, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
