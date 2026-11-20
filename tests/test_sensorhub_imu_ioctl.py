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
        self.assertEqual((report['case_count'], len(report['cases'])), (4, 4))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_ioctl_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_routing(self):
        r = self.evidence['executed_routing']
        self.assertEqual(r['cmd_read'], '0x80f62f90')
        self.assertEqual(r['cmd_b2'], '0x80f6300e')
        self.assertEqual(r['cmd_unsupported'], '0x80f86d34')
        self.assertEqual(r['cmd_unsupported_high'], '0x80f86d34')

    def test_command_map(self):
        m = self.evidence['command_map']
        self.assertEqual(m['0x01'], '0x80f62f90')
        self.assertEqual(m['0xb2'], '0x80f6300e')
        self.assertEqual(m['0xa0'], '0x80f71e2a')     # read-id handler
        # the gap commands route to the unsupported logger
        self.assertEqual(m['0x82'], 'unsupported')
        self.assertEqual(m['0x9f'], 'unsupported')


if __name__ == '__main__':
    unittest.main()
