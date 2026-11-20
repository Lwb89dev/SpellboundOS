import json
from pathlib import Path
import unittest

from analysis_scripts import main_display_dsi as dsi


class MainDisplayDsiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_display_dsi_'): c for c in dsi.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-display-dsi.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (6, 6))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_display_dsi_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_mipi_data_types(self):
        pc = self.evidence['per_case']
        self.assertEqual(pc['short_write_no_param']['data_type'], 0x05)
        self.assertEqual(pc['long_write_one_param']['data_type'], 0x15)
        self.assertEqual(pc['long_write_payload']['data_type'], 0x39)
        self.assertEqual(pc['short_packet_kind2']['data_type'], 2)

    def test_return_codes(self):
        pc = self.evidence['per_case']
        self.assertEqual(pc['short_write_no_param']['ret'], 0)
        self.assertEqual(pc['writer_failure']['ret'], 0xFFFFFFFF)   # -1
        self.assertEqual(pc['null_buffer']['ret'], 0xFFFFFFF6)      # -10

    def test_contract(self):
        self.assertEqual(self.evidence['function'], '0x701620f0 (mhs_dc_write_cmd)')
        self.assertIn('0x80c1220c', self.evidence['concurrency']['engine_active_flag'])


if __name__ == '__main__':
    unittest.main()
