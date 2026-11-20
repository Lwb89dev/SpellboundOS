import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import sensorhub_imu_mode as mode
from analysis_scripts import sensorhub_imu_probe as probe


def spi(tx):
    return f'spi:{probe.SPI_HANDLE}:{len(tx) // 2}:{probe.SPI_TIMEOUT}:{tx}'


class SensorhubImuModeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = mode.native_vectors()
        cls.cases = {c['name'].removeprefix('sensorhub_imu_mode_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/sensorhub-imu-mode.json').read_bytes())

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def writes(self, name):
        """SPI register writes (reg, value) in order."""
        out = []
        for a in self.actions(name):
            if a.startswith('spi:'):
                tx = bytes.fromhex(a.rsplit(':', 1)[1])
                if not tx[0] & 0x80:
                    out.append((tx[0], tx[1]))
        return out

    def snapshot(self, name, address):
        return self.cases[name]['expected']['rows'][0]['snapshot'][str(address)]

    def event(self, name):
        caps = [a for a in self.actions(name) if a.startswith('cap:')]
        self.assertEqual(len(caps), 1)
        return struct.unpack('<II', bytes.fromhex(caps[0][4:]))

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual(report['bound_per_case'], mode.BOUND)
        self.assertEqual((report['case_count'], len(report['cases'])), (26, 26))
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_mode_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= mode.BOUND)

    def test_original_globals(self):
        g = self.evidence['original_globals']
        self.assertEqual((g['program'], g['gy_fs'], g['xl_fs'], g['rate'], g['accel_power']), (8, 6, 3, 26, 1))

    def test_gyro_enable_register_sequence(self):
        self.assertEqual(self.writes('gyro_enable_original_globals'), [
            (0x12, 0x05),                 # software reset
            (0x18, 0x00), (0x62, 0x00),   # i3c_disable_set(0)
            (0x14, 0x00), (0x15, 0x00),   # xl_power_mode_set(0): high performance
            (0x12, 0x40),                 # block_data_update_set(1)
            (0x10, 0x0c),                 # xl_full_scale_set(3)
            (0x15, 0x07),                 # gy_lp1_bandwidth_set(7)
            (0x13, 0x02),                 # gy_filter_lp1_set(1)
            (0x16, 0x00),                 # gy_power_mode_set(0)
            (0x11, 0x0c),                 # gy_full_scale_set(6)
            (0x09, 0x02), (0x10, 0x20),   # xl batch / ODR code 2 (26 Hz)
            (0x09, 0x20), (0x11, 0x20),   # gy batch / ODR code 2
            (0x0a, 0x06),                 # fifo_mode_set(6): continuous
        ])
        self.assertIn(f'w:{mode.PROGRAM_SEL}:1:0', self.actions('gyro_enable_original_globals'))
        self.assertEqual(self.event('gyro_enable_original_globals'), (0x103, 2604))
        self.assertEqual(self.snapshot('gyro_enable_original_globals', mode.STATE), '02')

    def test_rate_codes(self):
        for rate, code in ((52, 3), (104, 4), (208, 5), (417, 6), (833, 7), (26, 2), (100, 2)):
            w = self.writes(f'gyro_enable_rate_{rate}')
            self.assertEqual(w[-5:-1], [(0x09, code), (0x10, code << 4), (0x09, code << 4), (0x11, code << 4)])
            a = self.writes(f'accel_enable_rate_{rate}')
            self.assertEqual(a[-3:-1], [(0x09, code), (0x10, code << 4)])
            self.assertEqual(self.snapshot(f'accel_enable_rate_{rate}', mode.ACC_RATE), struct.pack('<H', rate).hex())

    def test_accel_power_selector(self):
        def pm(name):
            w = dict()
            for reg, val in self.writes(name):
                w.setdefault(reg, []).append(val)
            return w[0x14][0] >> 7 << 1 | w[0x15][0] >> 4 & 1
        self.assertEqual(pm('accel_enable_selector_0_ultra_low_power'), 2)
        self.assertEqual(pm('accel_enable_selector_1_low_normal_power'), 1)
        self.assertEqual(pm('accel_enable_selector_7_low_normal_power'), 1)
        self.assertEqual(pm('accel_enable_selector_2_high_performance'), 0)
        self.assertEqual(self.event('accel_enable_selector_2_high_performance'), (0x103, 2604))
        self.assertEqual(self.event('accel_enable_selector_1_low_normal_power'), (0x103, 0))

    def test_disable_and_dump(self):
        self.assertEqual(self.writes('disable_both'), [(0x10, 0x00), (0x11, 0x00)])
        self.assertEqual(self.writes('disable_with_gyro_flag_logs_error'), [])
        reads = [a for a in self.actions('disable_runs_pending_dump') if a.startswith('spi:')][4:]
        self.assertEqual(reads[0], spi('8000'))
        self.assertEqual(reads[-1], spi('ff00'))
        self.assertEqual(len(reads), 0x80)
        dump = self.snapshot('gyro_enable_dump_read_errors', mode.DUMP_BUFFER)
        self.assertEqual(dump[:4], 'ff5b')          # reg 0 failed -> 0xff; reg 1 -> 1 ^ 0x5a

    def test_fcvt_repair_is_recorded(self):
        fixes = [a for a in self.actions('gyro_enable_original_globals') if a.startswith('fix:')]
        self.assertEqual(fixes, [f'fix:{mode.FCVT_SITE}:2604'])

    def test_embedded_programs_are_described_not_executed(self):
        progs = self.evidence['embedded_programs']
        self.assertIs(progs['executed'], False)
        self.assertEqual([t['pairs'] for t in progs['tables']], [380, 380])
        self.assertEqual(progs['differing_pairs'], 15)
        case = dict(self.cases['gyro_enable_original_globals'])
        case['memory'] = [[mode.PROGRAM_SEL, '05'] if m[0] == mode.PROGRAM_SEL else m for m in case['memory']]
        with self.assertRaises(ValueError):
            mode.contract(case)


if __name__ == '__main__':
    unittest.main()
