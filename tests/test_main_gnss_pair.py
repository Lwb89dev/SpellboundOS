import json
from pathlib import Path
import unittest

from analysis_scripts import main_gnss_pair as gnss


class MainGnssPairTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_gnss_pair_'): c for c in gnss.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-gnss-pair.json').read_bytes())

    def test_native_checksum_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (8, 8))
        for row in report['cases']:
            self.assertEqual(row['observed'], self.cases[row['name'].removeprefix('main_gnss_pair_')]['expected'])
        self.assertEqual(self.cases['power_on']['expected']['rows'][0]['a0'], 0x38)
        self.assertEqual(self.cases['empty']['expected']['rows'][0]['a0'], 0)

    def test_frames(self):
        self.assertEqual(gnss.frame(b'002'), b'$PAIR002*38\r\n')
        self.assertEqual(gnss.frame(b'104,1'), b'$PAIR104,1*22\r\n')
        self.assertEqual(self.evidence['sample_frames']['066,1,1,1,1,0,0'], '$PAIR066,1,1,1,1,0,0*3A')

    def test_catalog_and_ack_table(self):
        self.assertEqual(len(self.evidence['call_catalog']), 49)
        self.assertEqual(len(self.evidence['acknowledgement_table']), 43)
        acks = {a['code']: a for a in self.evidence['acknowledgement_table']}
        self.assertEqual(acks['002']['event_bits'], '0x200000')
        self.assertEqual(acks['104']['result_chars'], '01')
        band = [c['code'] for c in self.evidence['call_catalog'] if c['function'] == 'set_gnss_band_mode']
        self.assertEqual(band, ['105', '003', '104', '002', '003', '104', '002'])
        self.assertEqual(self.evidence['codes_without_acknowledgement_entry'], ['113'])


if __name__ == '__main__':
    unittest.main()
