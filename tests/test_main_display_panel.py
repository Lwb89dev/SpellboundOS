import json
from pathlib import Path
import unittest

from analysis_scripts import main_display_panel as disp


class MainDisplayPanelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = disp.native_vectors()
        cls.cases = {c['name'].removeprefix('main_display_panel_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-display-panel.json').read_bytes())

    def row(self, name):
        return self.cases[name]['expected']['rows'][-1]

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def caps(self, name):
        return [a[4:] for a in self.actions(name) if a.startswith('cap:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (9, 9, disp.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_display_panel_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= disp.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guard_and_call_sites(self):
        self.assertEqual(self.evidence['byte_range_sha256'],
                         {f'{a:08x}_{n:x}': h for a, n, h in disp.CODE})
        sites = {s['site']: s['target'] for s in self.evidence['call_sites']}
        self.assertEqual(sites['0x702c825e'], f'{disp.READ_TRANSFER:#010x}')
        self.assertEqual(sites['0x702c82e4'], f'{disp.READ_ID:#010x}')
        self.assertEqual(sites['0x702c833c'], f'{disp.WRITE:#010x}')

    def test_read_id_issues_rdid_commands_and_accumulates_24_bit(self):
        name = 'read_id_accumulates_rdid'
        self.assertEqual(self.caps(name), ['da', 'db', 'dc'])      # MIPI DCS RDID1/2/3
        self.assertEqual(self.row(name)['a0'], 0x1b0909)
        self.assertEqual([int(c, 16) for c in self.caps(name)], list(disp.RDID))

    def test_read_id_transfer_error_stops_and_returns_zero(self):
        name = 'read_id_transfer_error_returns_zero'
        self.assertEqual(self.caps(name), ['da'])                  # fails on the first transfer
        self.assertEqual(self.row(name)['a0'], 0)
        self.assertIn(f'call:{disp.LOGGER}', self.actions(name))

    def test_probe_matches_a_real_icna3311_id(self):
        name = 'probe_matches_icna3311_variant'
        self.assertEqual(self.caps(name), ['da', 'db', 'dc'])
        # id 0x1b0909 is PANEL_IDS[3]; the descriptor sits at TABLE_BASE+0x100+3*0x10.
        self.assertEqual(self.row(name)['a0'], disp.TABLE_BASE + 0x100 + 3 * 0x10)
        self.assertEqual(disp.PANEL_IDS[3], 0x1b0909)

    def test_probe_returns_null_on_unknown_id_or_read_failure(self):
        self.assertEqual(self.row('probe_unknown_id_returns_null')['a0'], 0)
        self.assertEqual(self.row('probe_read_id_failure_returns_null')['a0'], 0)
        self.assertEqual(self.caps('probe_read_id_failure_returns_null'), ['da'])

    def test_command_table_player_writes_and_delays(self):
        name = 'interp_writes_and_delays'
        self.assertEqual(self.caps(name), ['1100', '29'])          # sleep-out(+arg), display-on
        self.assertIn(f'call:{disp.DELAY}:120', self.actions(name))   # the 0x78 ms delay
        self.assertEqual(self.row(name)['a0'], 0)
        bright = 'interp_brightness_then_on'
        self.assertEqual(self.caps(bright), ['51ff', '5320', '29'])  # DCS 0x51/0x53/0x29
        self.assertIn(f'call:{disp.DELAY}:10', self.actions(bright))

    def test_command_table_player_guards_null_and_zero_length(self):
        self.assertEqual(self.row('interp_null_table_errors')['a0'], disp.INTERP_ERROR)
        self.assertEqual(self.row('interp_zero_length_errors')['a0'], disp.INTERP_ERROR)
        self.assertEqual(self.caps('interp_zero_length_errors'), [])

    def test_evidence_records_the_panel_contract(self):
        self.assertEqual(self.evidence['panel'], 'ICNA3311')
        self.assertEqual(self.evidence['rdid_commands'], ['0xda', '0xdb', '0xdc'])
        self.assertEqual(len(self.evidence['panel_ids']), 9)
        self.assertIn('type 0 = DCS write', self.evidence['command_table_format'])

    def test_contract_rejects_unknown_scope(self):
        case = dict(self.cases['read_id_accumulates_rdid'])
        with self.assertRaises(ValueError):
            disp.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            disp.contract(dict(case, operations=case['operations'] * 2))


if __name__ == '__main__':
    unittest.main()
