import json
from pathlib import Path
import unittest

from analysis_scripts import main_touch_open as topen


class MainTouchOpenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_touch_open_'): c for c in topen.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-touch-open.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (10, 10))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_touch_open_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_return_codes(self):
        codes = self.evidence['return_codes']
        self.assertEqual(codes['normal_mode'], 0)
        self.assertEqual(codes['bootloader_mode'], 0)
        self.assertEqual(codes['i2c_get_fails'], 3)
        self.assertEqual(codes['attach_irq_fails'], 0xA)
        self.assertEqual(codes['task_alloc_fails'], 0xFFFFFFFB)   # -5
        self.assertEqual(codes['timer_create_fails'], 0xFFFFFFFA)  # -6

    def test_check_mode_contract(self):
        cm = self.evidence['check_mode']
        self.assertIn('0x13', cm['function'])
        self.assertIn('normal mode', cm['normal'])
        self.assertIn('bootloader mode', cm['bootloader'])

    def test_bring_up_and_enable(self):
        self.assertEqual(self.evidence['function'], '0x701ebed8 (ztw622_open)')
        self.assertTrue(any('0x702bd834' in s for s in self.evidence['bring_up']))
        enable = ' '.join(self.evidence['enable'])
        self.assertIn('0xd4 = 0x3c', enable)
        self.assertIn('0xe3', enable)
        self.assertIn('+0x2b = +0x28 = 1', enable)

    def test_version_path_runs_in_bootloader_case(self):
        # The bootloader case must execute more bus traffic (the version block) than normal mode.
        normal = next(c for c in self.evidence['native_validation']['cases'] if c['name'].endswith('normal_mode'))
        boot = next(c for c in self.evidence['native_validation']['cases'] if c['name'].endswith('bootloader_mode'))
        self.assertGreater(boot['steps'], normal['steps'])


if __name__ == '__main__':
    unittest.main()
