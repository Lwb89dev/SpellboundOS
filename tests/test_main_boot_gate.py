import json
from pathlib import Path
import unittest

from analysis_scripts import main_boot_gate as gate


class MainBootGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = gate.native_vectors()
        cls.cases = {c['name'].removeprefix('main_boot_gate_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-boot-gate.json').read_bytes())

    def row(self, name):
        return self.cases[name]['expected']['rows'][-1]

    def calls(self, name):
        return [int(a.split(':')[1]) for a in self.cases[name]['expected']['actions'] if a.startswith('call:')]

    def hands_off(self, name):
        actions = self.cases[name]['expected']['actions']
        return self.row(name)['stopped'] == 'handoff' and \
            f'call:{gate.HANDOFF}:{gate.FIRMWARE_ENTRY}' in actions

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (16, 16, gate.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_boot_gate_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= gate.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_boot_bodies_and_call_sites(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in gate.CODE}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in gate.CODE])
        sites = {s['site']: s['target'] for s in self.evidence['call_sites']}
        self.assertEqual(sites['0x80c00962'], f'{gate.LOADER:#010x}')
        self.assertEqual(sites['0x80c00902'], f'{gate.VERIFY:#010x}')
        self.assertEqual(sites['0x80c0097a'], f'{gate.HANDOFF:#010x}')
        self.assertEqual(len(sites), len(gate.CALL_SITES))

    def test_handoff_happens_only_on_verified_firmware(self):
        self.assertTrue(self.hands_off('verified_firmware_hands_off'))
        self.assertTrue(self.hands_off('maximum_size_still_loads'))
        for name in ('verify_failure_no_handoff', 'oversize_firmware_rejected',
                     'open_failure_no_handoff', 'short_read_no_handoff'):
            self.assertFalse(self.hands_off(name))
            self.assertIsNone(self.row(name)['stopped'])
            self.assertNotIn(gate.HANDOFF, self.calls(name))

    def test_verified_path_verifies_before_handing_off(self):
        calls = self.calls('verified_firmware_hands_off')
        self.assertIn(gate.VERIFY, calls)
        self.assertLess(calls.index(gate.VERIFY), calls.index(gate.HANDOFF))
        self.assertEqual(calls[-1], gate.HANDOFF)

    def test_verify_failure_logs_and_returns_without_verify_pass_jump(self):
        calls = self.calls('verify_failure_no_handoff')
        self.assertIn(gate.VERIFY, calls)
        self.assertNotIn(gate.HANDOFF, calls)
        # loader logs the verify failure and boot logs the load failure (two LOG1 calls).
        self.assertEqual(calls.count(gate.LOG1), 2)

    def test_oversize_firmware_never_opens_or_verifies(self):
        calls = self.calls('oversize_firmware_rejected')
        self.assertNotIn(gate.LOADER, calls)
        self.assertNotIn(gate.OPEN, calls)
        self.assertNotIn(gate.VERIFY, calls)
        self.assertIn(gate.LOG2, calls)        # "firmware is too large"

    def test_open_and_short_read_failures_skip_verification(self):
        open_calls = self.calls('open_failure_no_handoff')
        self.assertIn(gate.OPEN, open_calls)
        self.assertNotIn(gate.READ, open_calls)
        self.assertNotIn(gate.VERIFY, open_calls)
        short = self.calls('short_read_no_handoff')
        self.assertIn(gate.READ, short)
        self.assertNotIn(gate.VERIFY, short)
        self.assertIn(gate.CLOSE, short)       # the handle is still closed

    def test_loader_return_value_tracks_verification(self):
        # The loader scope exercises the loader directly; success needs a nonzero verifier.
        for name in ('loader_verified_returns_success',):
            self.assertIn(gate.VERIFY, self.calls(name))
            self.assertIsNone(self.row(name)['stopped'])
        for name in ('loader_verify_failure_returns_error', 'loader_open_failure_returns_error',
                     'loader_short_read_returns_error'):
            self.assertNotIn(gate.HANDOFF, self.calls(name))

    def test_evidence_records_the_gate_structure(self):
        self.assertEqual(self.evidence['firmware_entry'], f'{gate.FIRMWARE_ENTRY:#010x}')
        self.assertEqual(self.evidence['signature_verifier'], f'{gate.VERIFY:#010x}')
        self.assertEqual(self.evidence['firmware_path'], '/mnt/system/firmware_sign.bin')
        self.assertEqual(self.evidence['size_limit'], f'{gate.SIZE_LIMIT:#x}')
        self.assertIn('secure verify failed', self.evidence['strings']['verify_failed']['text'])

    def test_contract_rejects_unknown_scope_or_multiple_operations(self):
        case = dict(self.cases['verified_firmware_hands_off'])
        with self.assertRaises(ValueError):
            gate.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            gate.contract(dict(case, operations=case['operations'] * 2))

    def test_original_main_verifier_chunks_only_payload_bytes(self):
        def chunk_sizes(name):
            actions = self.cases['original_verifier_' + name]['expected']['actions']
            return [int(a.rsplit(':', 1)[1]) for a in actions if a.startswith(f'call:{gate.SHA_UPDATE}:')]

        self.assertEqual(chunk_sizes('signature_only_rejected'), [])
        self.assertEqual(chunk_sizes('one_payload_byte'), [1])
        self.assertEqual(chunk_sizes('exact_chunk'), [gate.SHA_CHUNK])
        self.assertEqual(chunk_sizes('chunk_plus_one'), [gate.SHA_CHUNK, 1])
        chunks = chunk_sizes('ota_size_accepted')
        self.assertEqual(chunks, chunk_sizes('ota_size_rejected'))
        self.assertEqual(sum(chunks), gate.OTA_MAIN_SIZE - 64)
        self.assertTrue(self.hands_off('original_verifier_ota_size_accepted'))
        self.assertFalse(self.hands_off('original_verifier_ota_size_rejected'))


if __name__ == '__main__':
    unittest.main()
