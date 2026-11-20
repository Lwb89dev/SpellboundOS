import json
from pathlib import Path
import unittest

from analysis_scripts import main_motor as motor


class MainMotorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_motor_'): c for c in motor.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-motor.json').read_bytes())

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (21, 21))
        for row in report['cases']:
            self.assertEqual(row['observed'], self.cases[row['name'].removeprefix('main_motor_')]['expected'])

    def test_switching(self):
        self.assertEqual(self.actions('on')[1:], [f'call:{motor.GPIO_WRITE}:95:1',
                                                  f'call:{motor.TRACE}:{motor.MOTOR}:{motor.SWITCH}:0:1:1'])
        self.assertIn(f'call:{motor.GPIO_WRITE}:95:0', self.actions('off'))
        self.assertEqual(self.actions('off_without_record'), ['op:motor'])

    def test_pulse_durations(self):
        expected = {0: 1000, 1: 25, 2: 25, 3: 50, 4: 50, 5: 80, 6: 130, 7: 25, 8: 25, 9: 1000}
        for level, ms in expected.items():
            self.assertIn(f'call:{motor.TIMER_START}:{motor.TIMER}:{ms}', self.actions(f'pulse_level_{level}'))
        self.assertNotIn(f'call:{motor.TIMER_START}', ' '.join(self.actions('pulse_mode_1_plain_on')))
        self.assertIn(f'w:{motor.PARAMS + 2}:2:130', self.actions('duration_level_6'))


if __name__ == '__main__':
    unittest.main()
