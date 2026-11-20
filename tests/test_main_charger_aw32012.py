import json
from pathlib import Path
import unittest

from analysis_scripts import main_charger_aw32012 as aw


class MainChargerAw32012Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = aw.native_vectors()
        cls.cases = {c['name'].removeprefix('main_charger_aw32012_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-charger-aw32012.json').read_bytes())

    def writes(self, name):
        out = []
        for a in self.cases[name]['expected']['actions']:
            if a.startswith(f'bus:{aw.BUS_WRITE}:'):
                f = a.split(':')
                out.append((int(f[4]), f[-1]))
        return out

    def row(self, name):
        return self.cases[name]['expected']['rows'][0]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (47, 47))
        for row in report['cases']:
            name = row['name'].removeprefix('main_charger_aw32012_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_address_and_power_off(self):
        self.assertTrue(self.cases['read_reg']['expected']['actions'][1].startswith(
            f'bus:{aw.BUS_READ}:{aw.HANDLE}:73:8:'))
        self.assertEqual(self.writes('power_off'), [(6, '20')])
        self.assertEqual(self.row('no_handle')['a0'], aw.word(-10))

    def test_currents(self):
        self.assertEqual([aw.current_code(m) for m in (0, 4, 8, 16, 100, 519, 520)], [0xff, 0, 0, 1, 11, 63, 63])
        self.assertEqual(self.writes('current_100ma'), [(2, 'cb')])
        self.assertEqual(self.writes('current_0ma'), [(2, 'ff')])
        self.assertEqual(self.writes('current_unchanged'), [])
        self.assertEqual([aw.term_code(m) for m in (0, 1, 2, 10, 31, 32, 33)], [0, 0, 0, 4, 15, 15, 15])
        self.assertEqual(self.writes('term_set_10ma'), [(3, 'a4')])
        self.assertEqual(self.row('term_check_match')['snapshot'][str(aw.OUT)], '01')
        self.assertEqual(self.row('term_check_differs')['snapshot'][str(aw.OUT)], '00')

    def test_charge_control_is_active_high_disable(self):
        self.assertEqual(self.writes('chg_ctrl_1_from_08'), [(1, '00')])
        self.assertEqual(self.writes('chg_ctrl_0_from_00'), [(1, '08')])
        self.assertEqual(self.writes('chg_ctrl_1_from_00'), [])
        self.assertEqual(self.writes('hibernate_enable_mode3'), [(1, '00')])
        self.assertEqual(self.writes('hibernate_disable_mode3'), [(1, '08')])

    def test_status_and_tables(self):
        self.assertEqual(self.row('charge_state')['snapshot'][str(aw.OUT)], '03')
        self.assertEqual(self.row('id')['snapshot'][str(aw.OUT)], '49')
        self.assertEqual(self.writes('all_config_original_table'),
                         [(r, f'{v:02x}') for r, v in enumerate(aw.INIT_TABLE)])
        self.assertEqual(self.row('all_config_one_failure')['a0'], aw.word(-1))
        self.assertEqual(len(self.writes('chg_config_fourteen_registers')), 14)

    def test_vbus_reset_unlock_sequence(self):
        self.assertEqual(self.writes('vbus_reset_on'), [(0x69, 'c2'), (0x21, '7f'), (0x69, '00')])
        self.assertEqual(self.writes('vbus_reset_off'), [(0x69, 'c2'), (0x21, '81'), (0x69, '00')])
        self.assertEqual(self.writes('vbus_reset_unlock_fails'), [(0x69, 'c2'), (0x69, '00')])
        self.assertEqual(self.row('vbus_reset_relock_fails')['a0'], aw.word(-1))


if __name__ == '__main__':
    unittest.main()
