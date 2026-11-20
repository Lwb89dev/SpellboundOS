import json
from pathlib import Path
import unittest

from analysis_scripts import main_touch_dispatch as td


class MainTouchDispatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_touch_dispatch_'): c for c in td.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-touch-dispatch.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (7, 7))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_touch_dispatch_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_return_codes(self):
        codes = self.evidence['return_codes']
        self.assertEqual(codes['dispatch_event'], 0)
        self.assertEqual(codes['dispatch_callback_error'], 0xD)
        self.assertEqual(codes['dispatch_no_callback'], 0xFFFFFFFC)   # -4
        self.assertEqual(codes['dispatch_null_device'], 0xFFFFFFFC)   # -4
        self.assertEqual(codes['poll_notify_and_restart'], 0)
        self.assertEqual(codes['poll_notify_idle'], 0)
        self.assertEqual(codes['poll_timer_start_fails'], 0xFFFFFFF2)  # -14

    def test_event_layout(self):
        event = bytes.fromhex(self.evidence['dispatcher']['sample_event'])
        self.assertEqual(len(event), td.EVENT_SIZE)
        self.assertEqual(event[0], 1)
        self.assertEqual(event[8], 1)
        self.assertEqual(event[0xc], 5)              # mode
        self.assertEqual(event[0xe] | event[0xf] << 8, 0x00a0)   # value

    def test_poll_contract(self):
        poll = self.evidence['poll_timer']
        self.assertIn('0x70f8e100', poll['state_byte'])
        self.assertIn('0x80d3dedc', poll['notify'])
        self.assertIn('5000', poll['restart'])


if __name__ == '__main__':
    unittest.main()
