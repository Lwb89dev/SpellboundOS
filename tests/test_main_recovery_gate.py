import json
from pathlib import Path
import unittest

from analysis_scripts import main_recovery_gate as gate


class MainRecoveryGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = gate.native_vectors()
        cls.cases = {c['name'].removeprefix('main_recovery_gate_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-recovery-gate.json').read_bytes())

    def row(self, name):
        return self.cases[name]['expected']['rows'][-1]

    def enters_recovery(self, name):
        return self.row(name)['a0'] == 1

    def polls(self, name):
        return sum(1 for a in self.cases[name]['expected']['actions'] if a == f'call:{gate.POLL}')

    def calls(self, name, addr):
        return sum(1 for a in self.cases[name]['expected']['actions'] if a == f'call:{addr}')

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (8, 8, gate.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_recovery_gate_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= gate.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guard_and_call_sites(self):
        self.assertEqual(self.evidence['byte_range_sha256'],
                         {f'{a:08x}_{n:x}': h for a, n, h in gate.CODE})
        sites = {s['site']: s['target'] for s in self.evidence['call_sites']}
        self.assertEqual(sites['0x80c0031c'], f'{gate.REASON:#010x}')
        self.assertEqual(sites['0x80c0034a'], f'{gate.POWER:#010x}')
        self.assertEqual(sites['0x80c005e4'], f'{gate.BOOT_FIRMWARE:#010x}')
        self.assertEqual(sites['0x80c0068e'], f'{gate.RECOVERY_LAUNCH:#010x}')
        self.assertEqual(sites['0x80c006ac'], f'{gate.RECOVERY_LAUNCH:#010x}')

    def test_only_the_held_two_key_gesture_enters_recovery(self):
        self.assertTrue(self.enters_recovery('recovery_gesture_succeeds'))
        self.assertTrue(self.enters_recovery('second_key_late_then_held'))
        for name in ('reason_ota_skips', 'reason_reset_skips', 'no_external_power', 'power_check_error',
                     'keys_never_pressed_times_out', 'key_released_during_confirm_aborts'):
            self.assertFalse(self.enters_recovery(name))

    def test_skip_reasons_do_not_poll_power_or_keys(self):
        for name in ('reason_ota_skips', 'reason_reset_skips'):
            self.assertEqual(self.calls(name, gate.POWER), 0)
            self.assertEqual(self.polls(name), 0)
        self.assertEqual(self.evidence['skip_reasons'], [3, 6])

    def test_power_must_be_present_before_any_key_poll(self):
        for name in ('no_external_power', 'power_check_error'):
            self.assertEqual(self.calls(name, gate.POWER), 1)
            self.assertEqual(self.polls(name), 0)          # no key polling without power
            self.assertFalse(self.enters_recovery(name))

    def test_gesture_timeout_and_abort_do_not_enter_recovery(self):
        self.assertFalse(self.enters_recovery('keys_never_pressed_times_out'))
        # the wait-for-both-keys window is bounded, so polling is finite
        self.assertLessEqual(self.polls('keys_never_pressed_times_out'), 2 + 2 * gate.CONFIRM_WINDOW + 1)
        self.assertFalse(self.enters_recovery('key_released_during_confirm_aborts'))

    def test_evidence_documents_the_entry_conditions(self):
        self.assertEqual(self.evidence['confirm_window'], 20)
        self.assertEqual(self.evidence['poll_delay_ms'], 0x32)
        self.assertIn('external power present', self.evidence['requires'])
        self.assertEqual(self.evidence['boot_firmware'], f'{gate.BOOT_FIRMWARE:#010x}')
        self.assertIn('key pass', self.evidence['strings']['enter']['text'])

    def test_contract_rejects_unknown_scope(self):
        case = dict(self.cases['reason_ota_skips'])
        with self.assertRaises(ValueError):
            gate.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            gate.contract(dict(case, operations=case['operations'] * 2))


if __name__ == '__main__':
    unittest.main()
