import json
from pathlib import Path
import unittest

from analysis_scripts import sensorhub_imu_probe as imu


H = imu.SPI_HANDLE
T = imu.SPI_TIMEOUT


def spi(tx):
    return f'spi:{H}:{len(tx) // 2}:{T}:{tx}'


class SensorhubImuProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = imu.native_vectors()
        cls.cases = {c['name'].removeprefix('sensorhub_imu_probe_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/sensorhub-imu-probe.json').read_bytes())

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def result(self, name):
        return self.cases[name]['expected']['rows'][0].get('a0')

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (12, 12))
        for row in report['cases']:
            name = row['name'].removeprefix('sensorhub_imu_probe_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= imu.BOUND)

    def test_guards_and_call_sites(self):
        self.assertEqual(self.evidence['byte_range_sha256'],
                         {f'{a:08x}_{n:x}': h for a, n, h in imu.CODE + imu.DATA})
        sites = {s['site']: s['target'] for s in self.evidence['call_sites']}
        self.assertEqual(sites['0x80f6fb3e'], f'{imu.SPI_XFER:#010x}')
        self.assertEqual(sites['0x80f72bec'], f'{imu.CTX_WRITE:#010x}')
        self.assertEqual(sites['0x80f72bba'], f'{imu.CTX_READ:#010x}')
        ctx = self.evidence['context']
        self.assertEqual((ctx['write_reg'], ctx['read_reg']), ('0x80f6fb60', '0x80f6fafa'))

    def test_reset_framing_is_ctrl3_read_modify_write_then_poll(self):
        self.assertEqual(self.actions('reset_clears_immediately'), [
            'op:reset',
            spi('9200'), f'call:{imu.MEMCPY}',        # read CTRL3_C (0x12 | 0x80)
            spi('1205'),                              # write CTRL3_C = 0x04 | SW_RESET
            spi('9200'), f'call:{imu.MEMCPY}', f'call:{imu.DELAY}:1',
        ])
        self.assertIn(spi('1245'), self.actions('reset_preserves_other_ctrl3_bits'))

    def test_reset_polls_ten_times_then_logs_error(self):
        acts = self.actions('reset_times_out')
        self.assertEqual(acts.count(f'call:{imu.DELAY}:1'), imu.RESET_POLLS)
        self.assertEqual(acts.count(spi('9200')), 1 + imu.RESET_POLLS)
        self.assertEqual(acts[-1], f'call:{imu.LOGGER}:{imu.LOG_ERROR}')
        self.assertEqual(self.actions('reset_clears_on_third_poll').count(f'call:{imu.DELAY}:1'), 3)

    def test_reset_bus_errors(self):
        self.assertNotIn(spi('1205'), self.actions('reset_rmw_read_error_skips_write'))
        acts = self.actions('reset_write_error_still_polls')
        self.assertEqual(acts.count(spi('9200')), 2)

    def test_probe_accepts_only_0x6c(self):
        acts = self.actions('probe_identifies_lsm6dso')
        self.assertIn(spi('8f00'), acts)                       # WHO_AM_I 0x0f | 0x80
        self.assertIn(f'w:{imu.WHOAMI_CACHE}:1:{0x6c}', acts)
        self.assertEqual(self.result('probe_identifies_lsm6dso'), 0)
        self.assertEqual(self.result('probe_reset_timeout_then_id_ok'), 0)

    def test_probe_failures_retry_three_times(self):
        wrong = self.actions('probe_wrong_id_retries_three_times')
        self.assertEqual(wrong.count(f'call:{imu.DELAY}:10'), imu.INIT_ATTEMPTS)
        self.assertEqual(self.result('probe_wrong_id_retries_three_times'), 1)
        self.assertEqual(self.result('probe_read_error_retries_three_times'), 4)
        self.assertEqual(self.result('probe_recovers_on_second_attempt'), 0)

    def test_failed_whoami_read_keeps_previous_byte(self):
        cached = [a for a in self.actions('probe_read_error_keeps_stale_id')
                  if a.startswith(f'w:{imu.WHOAMI_CACHE}:')]
        self.assertEqual(cached, [f'w:{imu.WHOAMI_CACHE}:1:{v}' for v in (0x6a, 0x6a, 0x6c)])
        first = [a for a in self.actions('probe_read_error_retries_three_times')
                 if a.startswith(f'w:{imu.WHOAMI_CACHE}:')]
        self.assertEqual(first, [f'w:{imu.WHOAMI_CACHE}:1:0'] * 3)

    def test_model_rejects_unscripted_or_unsupported_inputs(self):
        case = dict(self.cases['reset_clears_immediately'])
        with self.assertRaises(ValueError):
            imu.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            imu.contract(dict(case, operations=case['operations'] * 2))
        with self.assertRaises(ValueError):
            imu.contract(dict(case, spi=case['spi'][:-1]))
        with self.assertRaises(ValueError):
            imu.contract(dict(case, spi=case['spi'] + [imu.write_ok()]))
        with self.assertRaises(ValueError):
            imu.contract(dict(case, spi=[imu.read_rx(4), imu.write_ok(), imu.fail(2)]))


if __name__ == '__main__':
    unittest.main()
