import json
from pathlib import Path
import unittest

from analysis_scripts import main_display_panel_ops as ops


class MainDisplayPanelOpsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_display_panel_ops_'): c for c in ops.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-display-panel-ops.json').read_bytes())

    def dcs(self, name):
        return [a.rsplit(':', 1)[1] for a in self.cases[name]['expected']['actions'] if a.startswith('bus:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (15, 15))
        for row in report['cases']:
            self.assertEqual(row['observed'],
                             self.cases[row['name'].removeprefix('main_display_panel_ops_')]['expected'])

    def test_unlocked_page0_commands(self):
        wrap = lambda cmd: ['fe80', 'f400', 'f500', 'fe00', 'fe00', cmd, 'fe80', 'f4ac', 'f5e1', 'fe00']
        self.assertEqual(self.dcs('dimming_off'), wrap('5320'))
        self.assertEqual(self.dcs('dimming_on'), wrap('5328'))
        self.assertEqual(self.dcs('hbm_on_default'), wrap('6602'))
        self.assertEqual(self.dcs('hbm_off_default'), wrap('6600'))
        self.assertIn('5180', self.dcs('brightness_80'))
        self.assertIn('51ff', self.dcs('brightness_ff'))

    def test_vendor_pages(self):
        self.assertIn('4e1f', self.dcs('sawtooth_on'))
        self.assertIn('4e00', self.dcs('sawtooth_off'))
        gamma = self.dcs('gamma_0x1234')
        self.assertEqual(gamma[gamma.index('fe50') + 1:gamma.index('fe50') + 3], ['3812', '3934'])
        self.assertEqual(self.dcs('hbm_on_variant_table'), ['6603', '29'])

    def test_register_access(self):
        read = self.cases['reg_read']['expected']['actions']
        self.assertIn(f'bus:{ops.READ}:12', read)
        self.assertIn(f'w:{ops.INFO + 4}:2:{0x5a}', read)
        self.assertIn('1277', self.dcs('reg_write'))
        self.assertIn('fe40', self.dcs('reg_write'))
        self.assertEqual(self.dcs('reg_unknown_op'), [])
        self.assertEqual(self.cases['reg_null']['expected']['rows'][0]['a0'], 1)


if __name__ == '__main__':
    unittest.main()
