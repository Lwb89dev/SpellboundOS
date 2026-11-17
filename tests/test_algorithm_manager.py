import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.algorithm_manager import (
    CB, HR, RECORDS, TABLE, apply_hr_control, contract, control_bytes,
    native_vectors, record_bytes, valid_id,
)


class AlgorithmManagerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def test_actual_hr_record_identifies_mask_and_four_adapters(self):
        fields = struct.unpack('<12I', record_bytes(dict(real=True)))
        self.assertEqual(fields[2:6], (0x100d, 0, 0x70313478, 0x70313470))
        self.assertEqual(fields[6:11], (0x82012, 0, 0, 0x7031345a, 0x70313446))
        self.assertEqual([1 << i for i in range(64) if fields[6] & (1 << i)],
                         [2, 0x10, 0x2000, 0x80000])

    def test_registration_returns_record_address_and_lookup_preserves_identity(self):
        c = dict(records=[dict(id=0x100d)], operations=[dict(op='base_reg'), dict(op='lookup')])
        result = contract(c)
        self.assertEqual([r['returned'] for r in result['rows']], [RECORDS, RECORDS])
        real = self.result('register_real_hr')
        self.assertEqual([r['returned'] for r in real['rows']], [None, HR, 0])
        table = bytearray(58 * 8)
        struct.pack_into('<I', table, 13 * 8, HR)
        self.assertEqual(real['rows'][0]['table_sha256'], hashlib.sha256(table).hexdigest())

    def test_registration_resets_refs_and_installs_default_lifecycle_callbacks(self):
        result = self.result('register_default_lifecycle')
        raw = record_bytes(dict(id=0x100d, init=False, exit=False))
        struct.pack_into('<H', raw, 12, 0)
        struct.pack_into('<II', raw, 16, 0x704c4a1e, 0x704c4a22)
        self.assertEqual(result['rows'][0]['record_sha256'], [hashlib.sha256(raw).hexdigest()])
        self.assertEqual(result['actions'], [])

    def test_duplicate_keeps_existing_slot_and_rejected_record_unmodified(self):
        result = self.result('register_duplicate_other')
        self.assertEqual(result['rows'][0]['table_sha256'], result['rows'][1]['table_sha256'])
        self.assertEqual(result['rows'][1]['returned'], 0)
        rejected = record_bytes(dict(id=0x100d, refs=456))
        self.assertEqual(result['rows'][1]['record_sha256'][1], hashlib.sha256(rejected).hexdigest())
        self.assertEqual(result['actions'], ['log:reg_duplicate'])
        self.assertEqual(self.result('register_duplicate_real')['actions'],
                         ['log:reg_duplicate', 'log:ops_reg_failed'])

    def test_ops_wrapper_checks_process_callback_but_base_registry_does_not(self):
        self.assertEqual(self.result('register_missing_process')['actions'], ['log:ops_invalid'])
        base = self.result('register_base_missing_process')
        self.assertEqual(base['actions'], [])
        self.assertEqual(base['rows'][0]['returned'], RECORDS)

    def test_null_and_invalid_registrations_do_not_populate_table(self):
        empty = hashlib.sha256(bytes(58 * 8)).hexdigest()
        null = self.result('register_null')
        self.assertEqual(null['actions'], ['log:ops_invalid'])
        self.assertEqual([r['returned'] for r in null['rows']], [None, 0])
        for identifier in (0, 0x1000, 0x103a, 0xffff):
            result = self.result('register_invalid_' + hex(identifier))
            self.assertEqual(result['actions'], ['log:reg_invalid', 'log:ops_reg_failed'])
            self.assertEqual(result['rows'][0]['table_sha256'], empty)

    def test_id_range_accepts_both_endpoints(self):
        for identifier in (0x1001, 0x1039):
            self.assertTrue(valid_id(identifier))
            result = self.result('register_edge_' + hex(identifier))
            self.assertEqual([r['returned'] for r in result['rows']], [RECORDS, RECORDS, 0, None])
        for identifier in (0x1000, 0x103a):
            self.assertFalse(valid_id(identifier))

    def test_two_owners_only_initialize_and_teardown_once(self):
        result = self.result('hr_lifetime_two_owners')
        self.assertEqual(result['actions'], ['backend:init', 'backend:exit'])
        counts = [0, 1, 2, 1, 0, 0]
        for row, count in zip(result['rows'], counts):
            raw = record_bytes(dict(real=True))
            struct.pack_into('<H', raw, 12, count)
            self.assertEqual(row['record_sha256'], [hashlib.sha256(raw).hexdigest()])

    def test_failed_init_keeps_reference_and_retries_until_success(self):
        result = self.result('hr_init_error_retries')
        self.assertEqual([r['returned'] for r in result['rows']], [None, 1, 1, 0, None, None, None])
        self.assertEqual(result['actions'], ['backend:init', 'log:enable_error', 'backend:init',
                         'log:enable_error', 'backend:init', 'backend:exit'])
        for row, count in zip(result['rows'], [0, 1, 2, 3, 2, 1, 0]):
            raw = record_bytes(dict(real=True))
            struct.pack_into('<H', raw, 12, count)
            self.assertEqual(row['record_sha256'], [hashlib.sha256(raw).hexdigest()])
        self.assertEqual(result['rows'][0]['table_sha256'], result['rows'][2]['table_sha256'])

    def test_hr_init_normalizes_error_while_generic_callback_preserves_it(self):
        self.assertEqual(self.result('hr_failed_init_then_disable')['rows'][1]['returned'], 1)
        self.assertEqual(self.result('generic_init_error_preserved')['rows'][1]['returned'], 7)
        self.assertNotIn('backend:exit', self.result('hr_failed_init_then_disable')['actions'][:2])

    def test_reference_wrap_does_not_disable_until_next_disable_call(self):
        result = self.result('lifetime_wrap')
        raw = record_bytes(dict(real=True))
        self.assertEqual(result['rows'][3]['record_sha256'], [hashlib.sha256(raw).hexdigest()])
        self.assertEqual(result['actions'], ['backend:init', 'supplied:seed', 'backend:exit'])
        self.assertNotEqual(result['rows'][3]['table_sha256'], result['rows'][4]['table_sha256'])

    def test_active_zero_ref_disable_and_exit_errors_clear_enable_flag(self):
        zero = self.result('lifetime_zero_refs_active')
        self.assertEqual(zero['actions'], ['supplied:seed', 'backend:exit'])
        error = self.result('hr_exit_status_ignored')
        self.assertEqual(error['actions'], ['backend:init', 'backend:exit'])
        self.assertEqual(error['rows'][0]['table_sha256'], error['rows'][-1]['table_sha256'])

    def test_disabled_dispatch_only_clears_ready_and_stores_tag(self):
        result = self.result('dispatch_disabled')
        output = bytearray(b'\xa5' * 0x520)
        output[0] = 0
        output[2:4] = bytes([0x0d, 0x10])
        self.assertEqual(result['actions'], [])
        self.assertEqual(result['rows'][1]['output_sha256'], hashlib.sha256(output).hexdigest())

    def test_dispatch_uses_real_mask_and_filters_previous_synthetic_type(self):
        for typ in (2, 0x10, 0x2000, 0x80000):
            self.assertIn('backend:process', self.result('dispatch_type_' + hex(typ))['actions'])
        for typ in (0x8000, 1):
            self.assertNotIn('backend:process', self.result('dispatch_type_' + hex(typ))['actions'])

    def test_actual_uninitialized_backend_guard_reports_error_without_ready_output(self):
        result = self.result('dispatch_real_uninitialized_guard')
        self.assertEqual(result['actions'], ['backend:init', 'backend:process',
                         'log:hr_uninitialized', 'log:dispatch_error', 'backend:exit'])
        self.assertEqual(result['rows'][2]['output_sha256'],
                         self.result('dispatch_disabled')['rows'][1]['output_sha256'])

    def test_null_output_logs_without_touching_output(self):
        result = self.result('dispatch_null_output')
        self.assertEqual(result['rows'][1]['output_sha256'], result['rows'][2]['output_sha256'])
        self.assertIn('log:dispatch_invalid', result['actions'])
        self.assertNotIn('backend:process', result['actions'])

    def test_mutable_64_bit_mask_and_null_descriptor_bypass(self):
        result = self.result('dispatch_mask_mutation')
        self.assertEqual(result['actions'].count('backend:process'), 1)
        raw = record_bytes(dict(real=True))
        struct.pack_into('<H', raw, 12, 1)
        struct.pack_into('<Q', raw, 24, 1 << 32)
        self.assertEqual(result['rows'][2]['record_sha256'], [hashlib.sha256(raw).hexdigest()])
        self.assertIn('backend:process', self.result('dispatch_null_descriptor')['actions'])

    def test_control_copies_exact_fields_and_preserves_other_backend_state(self):
        source = bytes.fromhex(control_bytes())
        state = bytearray(b'\x5a' * 160)
        state[0x9e] = 0
        apply_hr_control(state, source, 0)
        expected = bytearray(b'\x5a' * 160)
        expected[:56] = bytes(56)
        expected[0:6] = source[0:6]
        expected[7:17] = source[7:17]
        expected[17:27] = source[17:27]
        expected[27:38] = source[27:38]
        expected[156:159] = bytes([1, source[6], 0])
        self.assertEqual(state, expected)
        result = self.result('control_real_False_0')
        self.assertEqual(result['rows'][-1]['state_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertNotIn('backend:init', result['actions'])

    def test_control_moves_source_byte_six_and_zeroes_destination_byte_six(self):
        state = bytearray(160)
        source = bytearray.fromhex(control_bytes())
        source[6] = 255
        apply_hr_control(state, source, 0)
        self.assertEqual((state[6], state[157]), (0, 255))

    def test_control_extension_accepts_exact_one_and_adapter_discards_return(self):
        initial = bytearray(b'\x5a' * 160)
        initial[0x9e] = 0
        for status in (0, 1, 7):
            expected = bytearray(initial)
            apply_hr_control(expected, bytes.fromhex(control_bytes(True)), status)
            self.assertEqual(expected[156], int(status != 1))
            result = self.result('control_real_True_' + str(status))
            self.assertEqual(result['rows'][-1]['state_sha256'], hashlib.sha256(expected).hexdigest())
            self.assertNotIn('log:control_error', result['actions'])
        self.assertEqual(self.result('control_direct_success')['rows'][0]['returned'], 1)
        self.assertIn('log:control_error', self.result('control_generic_error')['actions'])

    def test_repeated_control_replaces_fields_and_extension_state(self):
        result = self.result('control_repeated')
        expected = bytearray(b'\x5a' * 160)
        expected[0x9e] = 0
        apply_hr_control(expected, bytes.fromhex(control_bytes(seed=99)), 0)
        self.assertEqual(result['rows'][-1]['state_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(result['actions'].count('backend:extension'), 1)
        self.assertNotEqual(result['rows'][1]['state_sha256'], result['rows'][2]['state_sha256'])

    def test_lookup_ids_outside_reviewed_width_are_rejected_by_host(self):
        with self.assertRaises(ValueError):
            contract(dict(records=[dict(real=True)], operations=[dict(op='lookup', id=0x1100d)]))
        with self.assertRaises(ValueError):
            record_bytes(dict(id=0x1100d))
        with self.assertRaises(ValueError):
            apply_hr_control(bytearray(160), bytes(47), 0)

    def test_public_native_observations_match_reviewed_model(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/algorithm-manager.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertFalse(native['hardware_execution'])
        self.assertEqual(native['case_count'], 48)
        self.assertEqual(len(native['cases']), len(self.cases))
        for row in native['cases']:
            self.assertEqual(row['observed'], self.result(row['name']))
            self.assertTrue(0 < row['steps'] <= 100000)
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))


if __name__ == '__main__':
    unittest.main()
