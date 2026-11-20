import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_touch_report as touch


class MainTouchReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = touch.native_vectors()
        cls.cases = {c['name'].removeprefix('main_touch_report_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-touch-report.json').read_bytes())

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def result(self, name):
        return self.cases[name]['expected']['rows'][0]['a0']

    def event(self, name):
        caps = [a for a in self.actions(name) if a.startswith('cap:')]
        self.assertEqual(len(caps), 1)
        return bytes.fromhex(caps[0][4:])

    def points(self, name):
        evt = self.event(name)
        out = []
        for i in range(evt[0x2c]):
            pt = 0xc + 0x10 * i
            down, = struct.unpack_from('<B', evt, pt)
            x, y = struct.unpack_from('<ii', evt, pt + 4)
            out.append((down, x, y, evt[pt + 0xc]))
        return out

    def writes(self, name):
        return [a.rsplit(':', 1)[1] for a in self.actions(name) if a.startswith(f'bus:{touch.BUS_WRITE}:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases'])), (29, 29))
        for row in report['cases']:
            name = row['name'].removeprefix('main_touch_report_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= touch.BOUND)

    def test_report_bus_sequence(self):
        acts = [a for a in self.actions('one_finger_down') if a.startswith('bus:')]
        self.assertEqual(acts, [
            f'bus:{touch.BUS_WRITE}:{touch.I2C_HANDLE}:32:2:10:8000',
            f'bus:{touch.BUS_READ}:{touch.I2C_HANDLE}:32:16:10:',
            f'bus:{touch.BUS_WRITE}:{touch.I2C_HANDLE}:32:2:10:0300',
        ])
        self.assertIn(f'call:{touch.TIMER_START}:{touch.TIMER}:5000', self.actions('one_finger_down'))

    def test_point_decode_and_rotation(self):
        self.assertEqual(self.points('one_finger_down'), [(1, 100, 50, 0)])
        self.assertEqual(self.points('two_fingers_rotation_90'), [(1, 50, 316, 0), (1, 400, 116, 1)])
        self.assertEqual(self.points('two_fingers_rotation_180'), [(1, 316, 366, 0), (1, 116, 16, 1)])
        self.assertEqual(self.points('two_fingers_rotation_270'), [(1, 366, 100, 0), (1, 16, 300, 1)])
        self.assertEqual(self.points('two_fingers_flip_180'), [(1, 316, 366, 0), (1, 116, 16, 1)])
        self.assertEqual(self.points('rotation_90_and_flip'), [(1, 366, 100, 0), (1, 16, 300, 1)])
        self.assertEqual(self.points('finger_up_bit'), [(0, 10, 20, 0)])
        self.assertEqual(self.points('empty_slot_skipped'), [(0, 0, 0, 0), (1, 7, 8, 1)])
        self.assertEqual(len(self.points('count_clamped_to_max_fingers')), 1)
        evt = self.event('one_finger_down')
        self.assertEqual(struct.unpack_from('<BxxxI', evt), (1, touch.TICK_VALUE))
        self.assertEqual(struct.unpack_from('<HH', evt, 0x30)[0], 416)

    def test_special_statuses(self):
        evt = self.event('large_object_reported')
        self.assertEqual((evt[0xc], evt[0x2c]), (2, 1))
        self.assertIn('26010000', self.writes('large_object_reported'))
        self.assertEqual(self.writes('large_object_ignored_when_disabled'), ['8000', '0300'])
        self.assertEqual(self.event('no_change_report')[0x2c], 0)
        self.assertEqual(self.writes('unknown_status_clears_interrupt'), ['8000', '0300'])
        self.assertEqual(self.writes('status_zero_clears_interrupt'), ['8000', '0300'])

    def test_states(self):
        self.assertEqual(self.writes('state_0_clears_interrupt'), ['0300'])
        self.assertEqual(self.result('state_6_busy'), touch.word(-10))
        self.assertEqual(self.result('state_out_of_range'), touch.word(-10))

    def test_gesture(self):
        evt = self.event('gesture_matches_mask')
        self.assertEqual((evt[0], evt[0xc], evt[0x2c]), (1, 3, 1))
        self.assertEqual(self.writes('gesture_matches_mask'), ['2601', '26010000', '0300'])
        self.assertFalse([a for a in self.actions('gesture_no_match_clears') if a.startswith('cap:')])
        local = [a for a in self.actions('gesture_null_event') if a.startswith(f'call:{touch.CALLBACK}:')]
        self.assertEqual(local, [f'call:{touch.CALLBACK}:{touch.DEV}:{touch.LOCAL_EVT}:{touch.USER_ARG}'])

    def test_errors(self):
        self.assertEqual(self.result('timer_handle_missing'), touch.word(-4))
        self.assertEqual(self.result('timer_start_fails'), touch.word(-14))
        self.assertEqual(self.result('read_fails_then_reset_retry_succeeds'), 0)
        self.assertIn(f'call:{touch.BUS_RESET}', self.actions('read_fails_then_reset_retry_succeeds'))
        self.assertEqual(self.result('read_fails_and_reset_fails'), 7)
        self.assertEqual(self.result('select_fails_twice'), 6)
        self.assertEqual(self.result('callback_missing'), touch.word(-4))
        self.assertEqual(self.result('callback_error_skips_clear'), 3)
        self.assertEqual(self.writes('callback_error_skips_clear'), ['8000'])
        self.assertEqual(self.result('clear_interrupt_fails_three_times'), 9)
        self.assertEqual(self.writes('clear_interrupt_fails_three_times'), ['8000', '0300', '0300', '0300'])

    def test_point_status_helper(self):
        raw = touch.point_status(0x0802, 1, [(1, 2, 3, 4)])
        self.assertEqual(raw.hex(), '0208015a01000200030400000000' + '0000')
        self.assertEqual(len(raw), 16)


if __name__ == '__main__':
    unittest.main()
