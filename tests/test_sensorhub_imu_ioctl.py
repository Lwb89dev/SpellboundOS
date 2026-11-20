import json
from pathlib import Path
import unittest

from analysis_scripts import sensorhub_imu_ioctl as io


class SensorhubImuIoctlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('sensorhub_imu_ioctl_'): c for c in io.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/sensorhub-imu-ioctl.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (8, 8))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_ioctl_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_acc_routing(self):
        r = self.evidence['executed_routing']
        self.assertEqual(r['acc_cmd_read'], '0x80f62f90')
        self.assertEqual(r['acc_cmd_b2'], '0x80f6300e')
        self.assertEqual(r['acc_cmd_unsupported'], '0x80f86d34')

    def test_gyro_rate(self):
        rates = self.evidence['gyroscope']['sample_rates']
        self.assertEqual(rates['gyro_cmd_rate'], 10000)       # 160000/16
        self.assertEqual(rates['gyro_cmd_rate_scaled'], 10000)  # 160000/(8*2)
        self.assertEqual(self.evidence['executed_routing']['gyro_cmd_unsupported'], '0x80f86d34')

    def test_command_map(self):
        m = self.evidence['accelerometer']['command_map']
        self.assertEqual(m['0x01'], '0x80f62f90')
        self.assertEqual(m['0xa0'], '0x80f71e2a')
        self.assertEqual(m['0x82'], 'unsupported')


if __name__ == '__main__':
    unittest.main()
