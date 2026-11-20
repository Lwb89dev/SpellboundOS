import json
from pathlib import Path
import unittest

from analysis_scripts import main_charger_cw6305 as cw


class MainChargerCw6305Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = cw.native_vectors()
        cls.cases = {c['name'].removeprefix('main_charger_cw6305_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-charger-cw6305.json').read_bytes())

    def bus(self, name):
        return [a.split(':')[4:] for a in self.cases[name]['expected']['actions'] if a.startswith('bus:')]

    def writes(self, name):
        return [(int(b[0]), b[-1]) for b in self.bus(name) if b[-1]]

    def result(self, name):
        return self.cases[name]['expected']['rows'][0].get('a0')

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (38, 38))
        for row in report['cases']:
            name = row['name'].removeprefix('main_charger_cw6305_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_bus_framing(self):
        acts = self.cases['read_reg']['expected']['actions']
        self.assertEqual(acts[1], f'bus:{cw.BUS_READ}:{cw.HANDLE}:11:13:1:1:1000:')
        self.assertEqual(self.cases['read_reg']['expected']['rows'][0]['snapshot'][str(cw.OUT)], '42')
        self.assertEqual(self.writes('write_reg'), [(5, 'a5')])
        self.assertEqual(self.result('no_handle'), cw.word(-10))

    def test_power_off_and_charge_enable(self):
        self.assertEqual(self.writes('power_off'), [(8, '7f'), (8, 'bf'), (7, '80')])
        self.assertEqual(self.writes('power_off_first_read_fails'), [(8, '80'), (7, '81')])
        self.assertEqual(self.writes('chg_ctrl_1_from_00'), [(1, '40')])
        self.assertEqual(self.writes('chg_ctrl_0_from_ff'), [(1, 'bf')])
        self.assertEqual(self.writes('chg_ctrl_1_from_40'), [])
        self.assertEqual(self.writes('hibernate_enable_mode3'), [(1, '40')])
        self.assertEqual(self.writes('hibernate_disable_mode3'), [(1, '00')])
        self.assertEqual(self.bus('hibernate_other_mode'), [])

    def test_fast_charge_current(self):
        codes = {10: 0, 15: 4, 20: 8, 30: 12, 40: 16, 60: 20, 80: 24, 100: 26, 250: 41, 470: 63}
        for ma, code in codes.items():
            self.assertEqual(cw.current_code(ma), code)
            w = self.writes(f'current_{ma}ma')
            if code != 0x15:
                self.assertEqual(w, [(4, f'{0xc0 | code:02x}')])
        self.assertEqual(self.writes('current_unchanged_skips_write'), [])
        self.assertEqual(self.result('current_below_range'), cw.word(-1))
        self.assertEqual(self.result('current_above_range'), cw.word(-1))
        self.assertIsNone(cw.current_code(5))

    def test_other_controls(self):
        self.assertEqual(self.writes('safety_timer_2'), [(6, 'df')])
        self.assertEqual(self.writes('irq_clear'), [(0xb, '00')])
        self.assertEqual(self.result('irq_source_null'), cw.word(-10))
        self.assertEqual([b[0] for b in self.bus('status')], ['13'])
        self.assertEqual([b[0] for b in self.bus('status2')], ['14'])
        self.assertEqual(self.cases['id']['expected']['rows'][0]['snapshot'][str(cw.OUT)], '31')

    def test_init_table(self):
        self.assertEqual(self.writes('config_original_table'),
                         [(r, f'{v:02x}') for r, v in enumerate(cw.INIT_TABLE)])
        self.assertEqual(len(self.writes('config_retry_second_attempt')), 22)
        self.assertEqual(self.result('config_null_table'), cw.word(-10))


if __name__ == '__main__':
    unittest.main()
