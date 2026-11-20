import json
from pathlib import Path
import unittest

from analysis_scripts import main_touch_upgrade as up


class MainTouchUpgradeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_touch_upgrade_'): c for c in up.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-touch-upgrade.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (4, 4))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_touch_upgrade_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def test_return_codes(self):
        codes = self.evidence['return_codes']
        self.assertEqual(codes['upgrade_one_chunk'], 0)
        self.assertEqual(codes['upgrade_two_chunks'], 0)
        self.assertEqual(codes['work_process_state2'], 0)
        self.assertEqual(codes['work_process_state2_reset_fails'], 3)

    def test_packet_framing(self):
        packets = self.evidence['upgrade']['sample_packets']
        self.assertEqual(len(packets), 8)                       # 0x40-byte chunk / 8 bytes
        for p in packets:
            self.assertTrue(p.startswith('d101'))               # 0x01d1 header, little-endian
            self.assertEqual(len(bytes.fromhex(p)), 0xa)        # 2 header + 8 data
        # The streamed payload is the source image bytes in order.
        payload = b''.join(bytes.fromhex(p)[2:] for p in packets)
        self.assertEqual(payload, bytes((0x11 + i) & 0xff for i in range(0x40)))

    def test_two_chunks_stream_more(self):
        one = next(c for c in self.evidence['native_validation']['cases'] if c['name'].endswith('one_chunk'))
        two = next(c for c in self.evidence['native_validation']['cases'] if c['name'].endswith('two_chunks'))
        self.assertGreater(two['steps'], one['steps'])

    def test_bootloader_sequence(self):
        up_ev = self.evidence['upgrade']
        self.assertIn('0xc000 = 1', up_ev['enter_bootloader'])
        self.assertIn('0xc003 = 0', up_ev['leave_bootloader'])
        self.assertIn('0x1d2', up_ev['verify'])


if __name__ == '__main__':
    unittest.main()
