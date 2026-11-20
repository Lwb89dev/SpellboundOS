import json
from pathlib import Path
import unittest

from analysis_scripts import sensorhub_imu_read as rd


class SensorhubImuReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('sensorhub_imu_read_'): c for c in rd.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/sensorhub-imu-read.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (4, 4))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_read_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_empty_and_error_return_null(self):
        pc = self.evidence['per_case']
        for name in ('empty_flag_clear', 'empty_flag_set_rearms', 'drain_error', 'drain_error_flag_set'):
            self.assertEqual(pc[name]['ret'], 0)

    def test_rearm_on_dirty_flag(self):
        pc = self.evidence['per_case']
        self.assertTrue(pc['empty_flag_set_rearms']['rearmed'])
        self.assertTrue(pc['drain_error_flag_set']['rearmed'])
        self.assertFalse(pc['empty_flag_clear']['rearmed'])

    def test_contract(self):
        self.assertEqual(self.evidence['callback'], '0x80f714a0 (shared accelerometer/gyroscope FIFO read)')


if __name__ == '__main__':
    unittest.main()
