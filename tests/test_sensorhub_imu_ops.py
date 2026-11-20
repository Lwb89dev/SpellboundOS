import json
from pathlib import Path
import unittest

from analysis_scripts import sensorhub_imu_ops as ops


class SensorhubImuOpsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('sensorhub_imu_ops_'): c for c in ops.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/sensorhub-imu-ops.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (10, 10))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_ops_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_return_codes(self):
        rc = self.evidence['return_codes']
        self.assertEqual(rc['acc_enable_ok'], 0)
        self.assertEqual(rc['acc_enable_mode_fails'], 2)
        self.assertEqual(rc['gyro_enable_mode_fails'], 2)
        self.assertEqual(rc['acc_disable'], 0)
        self.assertEqual(rc['control_fifo_flush'], 0)
        self.assertEqual(rc['control_passthrough'], 7)

    def _actions(self, name):
        return self.cases[name]['expected']['actions']

    def test_enable_calls_mode_setter(self):
        self.assertTrue(any(a.startswith('call:' + str(ops.MODE_SET)) for a in self._actions('acc_enable_ok')))
        # Accelerometer running flag written.
        self.assertTrue(any(a.startswith('w:' + str(ops.GYRO_ODR) + ':4:1') for a in self._actions('acc_enable_ok')))

    def test_control_dispatch(self):
        self.assertTrue(any(a.startswith('call:' + str(ops.SELF_TEST)) for a in self._actions('control_self_test_pass')))
        self.assertTrue(any(a.startswith('call:' + str(ops.FIFO_DRAIN)) for a in self._actions('control_fifo_flush')))
        # Passthrough command touches neither.
        acts = self._actions('control_passthrough')
        self.assertFalse(any('call:' + str(ops.FIFO_DRAIN) in a for a in acts))

    def test_contract(self):
        cb = self.evidence['callbacks']
        self.assertEqual(cb['accelerometer']['enable'], '0x80f70f28')
        self.assertEqual(cb['gyroscope']['disable'], '0x80f71c24')


if __name__ == '__main__':
    unittest.main()
