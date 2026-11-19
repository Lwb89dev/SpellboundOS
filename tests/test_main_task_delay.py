import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_task_delay as delay
from analysis_scripts import main_sched_resume as resume
from analysis_scripts import main_freertos_kernel as kernel
from analysis_scripts import main_trap_irq as trap


class MainTaskDelayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = delay.native_vectors()
        cls.cases = {c['name'].removeprefix('main_task_delay_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-task-delay.json').read_bytes())

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
                         (8, 8, delay.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_task_delay_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= delay.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_reuse_the_kernel_and_resume_ranges(self):
        self.assertEqual(self.evidence['byte_range_sha256'],
                         {f'{a:08x}_{n:x}': h for a, n, h in delay.CODE})
        self.assertEqual(self.evidence['reused_lower_ranges'], len(kernel.CODE + kernel.DATA + resume.CODE))
        guards = trap.CODE + trap.DATA + kernel.CODE + kernel.DATA + resume.CODE + delay.CODE
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])

    def test_zero_ticks_yields_without_list_work(self):
        name = 'zero_ticks_yields'
        self.assertEqual(self.actions(name), ['op:delay', f'call:{kernel.YIELD}'])
        self.assertEqual(self.word_at(name, kernel.SUSPENDED), 0)
        self.assertIsNone(self.row(name)['stopped'])

    def test_delay_moves_current_task_to_delayed_list(self):
        name = 'delay_moves_to_delayed_list'
        a = kernel.TCBS[0]
        # the task's state list item now points at the delayed list and holds the wake time.
        self.assertEqual(self.word_at(name, a + 4), 110)                 # wake = tick 100 + 10
        self.assertEqual(self.word_at(name, a + 4 + 0x10), kernel.DELAYED1)
        self.assertEqual(self.word_at(name, kernel.NEXT_UNBLOCK), 110)
        self.assertEqual(self.word_at(name, kernel.SUSPENDED), 0)        # resume restored it
        self.assertIn(f'call:{kernel.YIELD}', self.actions(name))

    def test_ready_bit_cleared_when_last_task_at_priority(self):
        self.assertEqual(self.word_at('clears_ready_bit_when_last', kernel.TOP_READY), 0)
        # a peer at the same priority keeps the bit set.
        self.assertEqual(self.word_at('keeps_ready_bit_with_peer', kernel.TOP_READY) & (1 << 3), 1 << 3)

    def test_ordered_insertion_by_wake_time(self):
        # new wake 110 is earlier than the existing sleeper at 150 -> inserted before it (becomes head).
        before = 'ordered_before_later_sleeper'
        self.assertEqual(self.word_at(before, kernel.TCBS[0] + 4), 110)
        self.assertEqual(self.word_at(before, kernel.NEXT_UNBLOCK), 110)
        # new wake 140 is later than the existing sleeper at 105 -> inserted after it.
        after = 'ordered_after_sooner_sleeper'
        self.assertEqual(self.word_at(after, kernel.TCBS[0] + 4), 140)

    def test_wake_wrap_uses_overflow_list_without_unblock_update(self):
        name = 'overflow_list_on_wrap'
        a = kernel.TCBS[0]
        wake = (0xfffffff0 + 0x20) & 0xffffffff                         # wraps below the tick
        self.assertEqual(self.word_at(name, a + 4), wake)
        self.assertEqual(self.word_at(name, a + 4 + 0x10), kernel.DELAYED2)   # overflow list
        self.assertEqual(self.word_at(name, kernel.NEXT_UNBLOCK), 0xffffffff)  # not updated on overflow

    def test_suspended_at_entry_asserts(self):
        self.assertEqual(self.row('suspended_at_entry_asserts')['stopped'], 'assert')
        self.assertIn('call:%d:%d:%d:%d' % ((kernel.ASSERT,) + delay.ASSERT_DELAY),
                      self.actions('suspended_at_entry_asserts'))

    def test_vectors_are_reproducible(self):
        again = delay.native_vectors()
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.vectors, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
