import json
from pathlib import Path
import unittest

from analysis_scripts import main_display_init as di


class MainDisplayInitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = di.native_vectors()
        cls.cases = {c['name'].removeprefix('main_display_init_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-display-init.json').read_bytes())

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (2, 2))
        for row in report['cases']:
            name = row['name'].removeprefix('main_display_init_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= di.BOUND)

    def test_guard_and_call_sites(self):
        self.assertEqual(self.evidence['byte_range_sha256'],
                         {f'{a:08x}_{n:x}': h for a, n, h in di.CODE})
        sites = {s['site']: s['target'] for s in self.evidence['call_sites']}
        self.assertEqual(sites['0x702c8af4'], f'{di.RAIL_ON:#010x}')
        self.assertEqual(sites['0x702c8b1c'], f'{di.RESET_GPIO:#010x}')
        self.assertEqual(sites['0x702c833c'], f'{di.WRITE:#010x}')

    def test_bringup_sequences_rails_then_reset(self):
        acts = self.actions('power_reset_bringup')
        calls = [a for a in acts if a.startswith('call:')]
        self.assertEqual(calls, [
            f'call:{di.RAIL_ON}:{di.RAIL_1V8_HANDLE}',
            f'call:{di.DELAY}:5',
            f'call:{di.RAIL_ON}:{di.RAIL_3V3_HANDLE}',
            f'call:{di.BUS_CFG}',
            f'call:{di.RESET_GPIO}:{di.RESET_PIN}:0',
            f'call:{di.DELAY}:12',
            f'call:{di.RESET_GPIO}:{di.RESET_PIN}:1',
            f'call:{di.DELAY}:12',
        ])

    def test_real_init_table_issues_expected_dcs_commands(self):
        caps = [a[4:] for a in self.actions('real_icna3311_416_init') if a.startswith('cap:')]
        self.assertEqual(len(caps), 25)
        # Key MIPI DCS commands of the real ICNA3311 416x416 init.
        self.assertIn('3500', caps)       # set_tear_on
        self.assertIn('51ff', caps)       # write_display_brightness = max
        self.assertIn('3a55', caps)       # set_pixel_format RGB565
        self.assertIn('2a001201b1', caps) # set_column_address 0x0012..0x01b1 -> 416 wide
        self.assertIn('2b0000019f', caps) # set_page_address 0x0000..0x019f -> 416 tall
        self.assertIn('fe20', caps)       # ICNA3311 page select

    def test_all_nine_variant_geometries_decoded(self):
        geoms = [v['geometry'] for v in self.evidence['variants']]
        self.assertEqual(geoms, ['192x490', '192x490', None, '416x416',
                                 '390x450', '390x450', '390x450', '390x450', '390x450'])
        self.assertEqual(len(self.evidence['variants']), 9)
        self.assertEqual(self.evidence['variants'][3]['id'], '0x1b0909')

    def test_evidence_records_the_bringup_contract(self):
        self.assertEqual(self.evidence['panel'], 'ICNA3311')
        self.assertIn('rail 1.8V on', self.evidence['bringup_sequence'])
        self.assertIn('reset low', self.evidence['bringup_sequence'])

    def test_contract_rejects_unknown_scope(self):
        case = dict(self.cases['power_reset_bringup'])
        with self.assertRaises(ValueError):
            di.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            di.contract(dict(case, operations=case['operations'] * 2))


if __name__ == '__main__':
    unittest.main()
