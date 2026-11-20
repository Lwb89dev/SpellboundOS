import json
from pathlib import Path
import unittest

from analysis_scripts import main_key_init as ki


class MainKeyInitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_key_init_'): c for c in ki.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-key-init.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (3, 3))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_key_init_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_return_codes(self):
        codes = self.evidence['return_codes']
        self.assertEqual(codes['register_ok'], 0)
        self.assertEqual(codes['board_record_missing'], 1)
        self.assertEqual(codes['register_fails'], 0xFFFFFFF5)   # -11

    def test_thresholds(self):
        t = self.evidence['config']['thresholds']
        self.assertEqual(t['long_press_ms'], 500)
        self.assertEqual(t['double_window'], 800)
        self.assertEqual(t['debounce'], 0x7F)
        self.assertEqual(t['release'], 80)

    def test_driver_registration(self):
        drv = self.evidence['driver']
        self.assertEqual(drv['name'], 'keyboard')
        self.assertEqual(drv['ops_table'], '0x70f60e2c')
        self.assertEqual(drv['object'], '0x70f92bf4')

    def test_config_writes_present(self):
        # The register_ok trace must contain the per-key threshold stores plus the register call.
        actions = self.cases['register_ok']['expected']['actions']
        writes = [a for a in actions if a.startswith('w:')]
        self.assertEqual(len(writes), len(ki.WRITES))
        self.assertTrue(any(a.startswith('call:' + str(ki.REGISTER)) for a in actions))


if __name__ == '__main__':
    unittest.main()
