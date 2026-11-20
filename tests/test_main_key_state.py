import json
from pathlib import Path
import unittest

from analysis_scripts import main_key_state as ks


class MainKeyStateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name'].removeprefix('main_key_state_'): c for c in ks.native_vectors()['cases']}
        cls.evidence = json.loads(Path('analysis/main-key-state.json').read_bytes())

    def test_native_matches_model(self):
        report = self.evidence['native_validation']
        self.assertEqual((report['case_count'], len(report['cases'])), (26, 26))
        self.assertFalse(report['hardware_execution'])
        for row in report['cases']:
            name = row['name'].removeprefix('main_key_state_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])

    def _pc(self, name):
        return self.evidence['per_case'][name]

    def test_state0(self):
        self.assertEqual(self._pc('s0_press_below'), dict(upload_bits=[], store_states=[]))
        self.assertEqual(self._pc('s0_press_store2')['store_states'], [2])
        self.assertEqual(self._pc('s0_press_store1')['store_states'], [1])

    def test_state2(self):
        self.assertEqual(self._pc('s2_press_store5'), dict(upload_bits=[2], store_states=[5]))
        self.assertEqual(self._pc('s2_press_store4'), dict(upload_bits=[2], store_states=[4]))
        self.assertEqual(self._pc('s2_release_hold'), dict(upload_bits=[8], store_states=[3]))
        self.assertEqual(self._pc('s2_release_end'), dict(upload_bits=[8, 1], store_states=[0]))

    def test_state3(self):
        self.assertEqual(self._pc('s3_press_store5'), dict(upload_bits=[0x10, 4], store_states=[5]))
        self.assertEqual(self._pc('s3_repeat_fires'), dict(upload_bits=[1], store_states=[0]))
        self.assertEqual(self._pc('s3_repeat_building'), dict(upload_bits=[], store_states=[]))

    def test_states_4_5_6(self):
        self.assertEqual(self._pc('s4_press_store6'), dict(upload_bits=[0x20], store_states=[6]))
        self.assertEqual(self._pc('s6_press_store5'), dict(upload_bits=[0x40], store_states=[5]))
        for name in ('s4_release', 's5_release_ends', 's6_release'):
            self.assertEqual(self._pc(name), dict(upload_bits=[8], store_states=[0]))
        self.assertEqual(self._pc('s5_press_counts'), dict(upload_bits=[], store_states=[]))

    def test_state1_combo(self):
        # Press within the combo window just debounces; past it or on release it uploads bit 0x10
        # and advances to state 2; a pending combo skips the upload.
        self.assertEqual(self._pc('s1_press_within_window'), dict(upload_bits=[], store_states=[]))
        self.assertEqual(self._pc('s1_press_past_window'), dict(upload_bits=[0x10], store_states=[2]))
        self.assertEqual(self._pc('s1_press_combo_pending'), dict(upload_bits=[], store_states=[2]))
        self.assertEqual(self._pc('s1_release_combo_clear'), dict(upload_bits=[0x10], store_states=[2]))
        self.assertEqual(self._pc('s1_release_combo_pending'), dict(upload_bits=[], store_states=[2]))

    def test_state1_combo_pairing(self):
        # Both keys active within the window -> combo event (bit 0x400); out of window -> bit 0x10.
        self.assertEqual(self._pc('s1_combo_detected'), dict(upload_bits=[0x400], store_states=[2]))
        self.assertEqual(self._pc('s1_combo_out_of_window'), dict(upload_bits=[0x10], store_states=[2]))

    def test_dispatch_contract(self):
        self.assertEqual(self.evidence['function'], '0x701e923e (gpio_key_state_machine)')
        self.assertIn('0x70f92b74', self.evidence['dispatch']['state_byte'])


if __name__ == '__main__':
    unittest.main()
