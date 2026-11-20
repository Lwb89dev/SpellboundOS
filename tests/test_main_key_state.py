import json
from pathlib import Path
import unittest

from analysis_scripts import main_key_state as ks


class MainKeyStateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_key_state_'): c for c in ks.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-key-state.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (5, 5))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_key_state_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def _store_state(self, name):
        for a in self.cases[name]['expected']['actions']:
            if a.startswith('call:' + str(ks.STORE_STATE)):
                return int(a.split(':')[-1])
        return None

    def test_press_below_threshold_no_store(self):
        # Below threshold: counter increments, timer check runs, no state store.
        self.assertIsNone(self._store_state('press_below_threshold'))
        actions = self.cases['press_below_threshold']['expected']['actions']
        self.assertTrue(any(a.startswith('call:' + str(ks.TIMER_CHECK)) for a in actions))

    def test_threshold_stores_state_by_flag(self):
        # Config flag bit 4 selects state 1, else state 2.
        self.assertEqual(self._store_state('press_reaches_threshold_state2'), 2)
        self.assertEqual(self._store_state('press_reaches_threshold_state1'), 1)

    def test_release_runs_idle(self):
        actions = self.cases['release_clears_counter']['expected']['actions']
        self.assertTrue(any(a.startswith('call:' + str(ks.IDLE_HANDLER)) for a in actions))
        # The counter is cleared to 0.
        self.assertTrue(any(a.endswith(':4:0') for a in actions if a.startswith('w:')))

    def test_dispatch_contract(self):
        self.assertEqual(self.evidence['function'], '0x701e923e (gpio_key_state_machine)')
        self.assertIn('0x70f92b74', self.evidence['dispatch']['state_byte'])


if __name__ == '__main__':
    unittest.main()
