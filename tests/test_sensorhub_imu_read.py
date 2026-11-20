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
        self.assertEqual((report['case_count'], len(report['cases'])), (16, 16))
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

    def test_accel_rate_cap_and_overlapping_compaction(self):
        name = 'accel_capped_and_compacted'
        row = self.evidence['per_case'][name]
        self.assertEqual((row['ret'], row['buffered_after']), (rd.PACKET, 34))
        self.assertEqual(row['streams'][0], dict(
            kind=2, sensitivity=4096, count=31, stride=186, hz=25,
            timestamp=rd.TS - 37 * 38, first_xyz=[110, -220, 4126]))
        native = next(c for c in self.evidence['native_validation']['cases']
                      if c['name'] == 'sensorhub_imu_read_' + name)
        actual = bytes.fromhex(native['observed']['rows'][0]['snapshot'][str(rd.CACHE)])
        before = dict(self.cases[name]['memory'])[rd.CACHE]
        self.assertEqual(actual[:34 * 7], bytes.fromhex(before)[31 * 7:])

    def test_gyro_packet_and_odd_word_handling(self):
        cases = self.evidence['per_case']
        streams = cases['gyro_delivery']['streams']
        self.assertEqual([s['kind'] for s in streams], [2, 4])
        self.assertEqual([s['count'] for s in streams], [2, 2])
        self.assertEqual([s['timestamp'] for s in streams], [rd.TS - 38] * 2)
        self.assertEqual(streams[1]['first_xyz'], [-340, 450, -560])
        self.assertEqual(cases['gyro_odd_unknown_tag_ignored']['buffered_after'], 0)
        self.assertEqual(cases['gyro_odd_extra_sample_rejected']['buffered_after'], 5)
        self.assertTrue(cases['gyro_odd_extra_sample_rejected']['error_event'])

    def test_failure_keeps_buffered_words(self):
        cases = self.evidence['per_case']
        for name, count in [('allocation_failed', 2), ('gyro_single_word_zero_stride', 1)]:
            with self.subTest(name=name):
                self.assertEqual((cases[name]['ret'], cases[name]['buffered_after']), (0, count))
                self.assertFalse(cases[name]['error_event'])
        for name, freed in [('missing_accel_releases_packet', True),
                            ('missing_gyro_retains_packet', False)]:
            with self.subTest(name=name):
                self.assertEqual((cases[name]['ret'], cases[name]['buffered_after']), (0, 2))
                self.assertTrue(cases[name]['error_event'])
                self.assertEqual(cases[name]['packet_freed'], freed)

    def test_original_drain_feeds_the_delivery_callback(self):
        cases = self.evidence['per_case']
        self.assertEqual([s['count'] for s in cases['connected_accel']['streams']], [3])
        gyro = cases['connected_gyro']
        self.assertEqual((gyro['buffered_after'], len(gyro['streams'])), (0, 2))
        self.assertEqual([s['count'] for s in gyro['streams']], [2, 2])
        error = cases['connected_spi_error']
        self.assertEqual((error['ret'], error['buffered_after']), (0, 0))
        for c in self.evidence['native_validation']['cases'][-3:]:
            self.assertTrue(any(action.startswith('spi:') for action in c['observed']['actions']))


if __name__ == '__main__':
    unittest.main()
