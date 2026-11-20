import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_als_stk31e60 as als


class MainAlsStk31e60Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = als.native_vectors()
        cls.cases = {c['name'].removeprefix('main_als_stk31e60_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-als-stk31e60.json').read_bytes())

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def writes(self, name):
        return [(int(a.split(':')[4]), a.rsplit(':', 1)[1]) for a in self.actions(name)
                if a.startswith(f'bus:{als.BUS_WRITE}:')]

    def row(self, name):
        return self.cases[name]['expected']['rows'][0]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (31, 31))
        for row in report['cases']:
            name = row['name'].removeprefix('main_als_stk31e60_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_retries(self):
        self.assertEqual(self.actions('read_retries_then_ok').count(f'call:{als.DELAY}:2'), 2)
        self.assertEqual(self.row('read_three_failures')['a0'], 5)

    def test_init_register_sequence(self):
        self.assertEqual(self.writes('init'), [(0xe5, '80'), (0x07, '03'), (0x08, 'e7'), (0x3d, '00'),
                                               (0x6a, 'ef'), (0x6b, '01'), (0x17, 'b0'), (0x6e, '00'), (0x6f, 'a6')])
        self.assertIn(f'w:{als.CTX + 0x69}:1:1', self.actions('init'))
        self.assertIn(f'w:{als.GAIN + 4}:8:{struct.unpack("<I", struct.pack("<f", 1.0))[0]}', self.actions('init'))
        self.assertEqual(self.row('init_0x07_fails')['a0'], als.word(-1))

    def test_integration_and_gain(self):
        self.assertEqual([als.integ_code(v) for v in (1.0, 16.6, 100.0)], [9, 166, 1009])
        self.assertEqual(self.writes('integration_100_0ms'), [(0x6e, '03'), (0x6f, 'f1')])
        self.assertEqual(self.row('integration_low_write_fails')['a0'], als.word(-1))
        ratio = struct.unpack('<I', struct.pack('<f', 256.0 / 4096.0))[0]
        self.assertIn(f'w:{als.GAIN + 4}:8:{ratio}', self.actions('gain_set_f0'))

    def test_chip_id_and_normalise(self):
        self.assertEqual(self.row('chip_id_ok')['a0'], 0)
        self.assertEqual(self.row('chip_id_wrong')['a0'], als.word(-1))
        self.assertEqual(self.writes('normalise'), [(0xe5, '80'), (0xec, '80')])

    def test_read_als(self):
        self.assertEqual(self.row('read_als')['snapshot'][str(als.OUT)], '3412')
        self.assertIn(f'call:{als.DELAY}:14', self.actions('read_als_waits_integration'))
        self.assertIn(f'call:{als.DELAY}:235', self.actions('read_als_mode_1'))
        self.assertIn(f'call:{als.DELAY}:19', self.actions('read_als_bad_mode'))
        self.assertEqual(self.row('read_als_data_error_uses_cache')['snapshot'][str(als.OUT)], '3412')
        self.assertEqual(self.row('read_als_data_error_uses_cache')['a0'], 0)
        self.assertEqual(self.row('read_als_not_ready')['a0'], als.word(-2))
        self.assertEqual(self.row('read_als_null')['a0'], als.word(-10))


if __name__ == '__main__':
    unittest.main()
