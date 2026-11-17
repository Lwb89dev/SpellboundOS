import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.boot_environment import (
    BACKUP, DATA, STOP, contract, native_vectors, upgrade_record,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class BootEnvironmentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def row(self, name):
        return self.result(name)['rows'][-1]

    def test_get_clips_copy_but_reports_original_size(self):
        row = self.row('get_truncated')
        self.assertEqual((row['returned'], row['length_output']), (12, 32))
        self.assertEqual(row['buffer_sha256'], sha(bytes(range(12)) + b'\xa5' * 1012))
        self.assertEqual(self.row('get_full')['returned'], 32)

    def test_get_missing_and_uninitialized_have_distinct_size_outputs(self):
        self.assertEqual(self.row('get_missing')['length_output'], 0)
        self.assertEqual(self.row('get_uninitialized')['length_output'], 0xa5a5a5a5)
        self.assertEqual(self.result('get_uninitialized')['actions'], ['env:uninitialized'])
        self.assertEqual(self.result('get_missing')['actions'], ['env:lock', 'env:find:0', 'env:unlock'])

    def test_get_null_destination_preserves_count_without_read(self):
        row = self.row('get_null_output')
        self.assertEqual((row['returned'], row['length_output']), (12, 32))
        self.assertEqual(row['buffer_sha256'], sha(b'\xa5' * 1024))
        self.assertFalse(any(a.startswith('env:read:') for a in self.result('get_null_output')['actions']))

    def test_get_optional_length_pointer_is_independent(self):
        for name in ('get_null_size', 'get_null_both'):
            self.assertEqual(self.row(name)['length_output'], 0xa5a5a5a5)
            self.assertEqual(self.row(name)['returned'], 12)

    def test_get_read_failure_status_is_ignored(self):
        row = self.row('get_read_failure')
        self.assertEqual((row['returned'], row['length_output']), (12, 32))
        self.assertEqual(row['buffer_sha256'], sha(b'\xa5' * 1024))
        self.assertIn('env:read:12:2', self.result('get_read_failure')['actions'])

    def test_zero_capacity_still_calls_read_and_reports_size(self):
        self.assertIn('env:read:0:0', self.result('get_zero_capacity')['actions'])
        self.assertEqual(self.row('get_zero_capacity')['length_output'], 32)
        self.assertEqual(self.row('get_empty_value')['length_output'], 0)

    def test_replace_orders_mark_append_and_final_remove(self):
        self.assertEqual(self.result('set_existing')['actions'], [
            'env:lock', 'env:reserve:51', 'env:find:1', 'env:remove:mark:0',
            'env:append:0', 'env:remove:final:0', 'env:unlock',
        ])
        descriptor = bytearray(56)
        struct.pack_into('<I', descriptor, 12, 32)
        struct.pack_into('<I', descriptor, 52, DATA)
        self.assertEqual(self.row('set_existing')['descriptor_sha256'], sha(descriptor))

    def test_new_key_does_not_remove(self):
        self.assertFalse(any(a.startswith('env:remove:') for a in self.result('set_new')['actions']))
        self.assertEqual(self.row('set_new')['appends'][0]['sha256'], sha(bytes(range(16))))

    def test_delete_bypasses_reservation_and_lookup(self):
        self.assertEqual(self.result('set_delete')['actions'], ['env:lock', 'env:remove:direct:0', 'env:unlock'])
        self.assertEqual(self.row('set_delete_failure')['returned'], 4)

    def test_null_and_nonnull_empty_value_are_distinct(self):
        result = self.result('set_nonnull_empty')
        self.assertIn('env:reserve:29', result['actions'])
        self.assertEqual(result['rows'][0]['appends'][0]['size'], 0)
        self.assertNotIn('env:remove:direct:0', result['actions'])

    def test_uninitialized_and_no_space_statuses(self):
        self.assertEqual(self.row('set_uninitialized')['returned'], 7)
        self.assertEqual(self.row('set_no_space')['returned'], 6)
        self.assertEqual(self.row('set_new')['returned'], 0)  # Reservation address zero is accepted.
        self.assertEqual(self.result('set_no_space')['actions'], ['env:lock', 'env:reserve:51', 'env:unlock'])

    def test_mutation_errors_propagate_and_skip_later_steps(self):
        for name, status in [('set_mark_failure', 4), ('set_new_append_failure', 5),
                             ('set_old_append_failure', 5), ('set_final_failure', 3)]:
            self.assertEqual(self.row(name)['returned'], status)
        self.assertEqual(self.row('set_mark_failure')['appends'], [])
        self.assertFalse(any(a.startswith('env:remove:final:') for a in self.result('set_old_append_failure')['actions']))

    def test_maintenance_status_does_not_override_saved_result(self):
        self.assertEqual(self.row('set_maintenance')['returned'], 0)
        self.assertEqual(self.row('set_maintenance')['maintenance_flag'], 0)
        self.assertEqual(self.row('set_mark_failure_maintenance')['returned'], 4)
        self.assertIn('env:maintenance', self.result('set_mark_failure_maintenance')['actions'])

    def test_early_delete_and_no_space_skip_maintenance(self):
        for name in ('set_delete_maintenance', 'set_no_space_maintenance'):
            self.assertEqual(self.row(name)['maintenance_flag'], 1)
            self.assertNotIn('env:maintenance', self.result(name)['actions'])

    def test_commit_returns_zero_without_backend_work(self):
        self.assertEqual(self.result('commit_only')['actions'], ['commit:no_op'])
        self.assertEqual(self.row('commit_only')['returned'], 0)
        rows = self.result('set_then_commit')['rows']
        self.assertEqual(rows[0]['appends'], rows[1]['appends'])

    def test_raw_reason_mapping_and_one_time_cache(self):
        for raw, mapped in ((0, 8), (1, 0), (2, 1), (3, 2), (99, 8)):
            result = self.result('reason_raw_' + str(raw))
            self.assertEqual([r['returned'] for r in result['rows']], [mapped, mapped])
            self.assertEqual(result['actions'], ['reason:raw', 'reason:retained'])

    def test_precached_reasons_skip_both_services(self):
        for value in (0, 6, 8, 0xfffffffe):
            result = self.result('reason_cached_' + str(value))
            self.assertEqual(result['actions'], [])
            self.assertEqual(result['rows'][0]['returned'], value)

    def test_retained_magic_overrides_raw_reason_and_sentinel_rereads(self):
        self.assertEqual(self.row('reason_retained_3')['returned'], 3)
        self.assertEqual(self.row('reason_retained_6')['returned'], 6)
        result = self.result('reason_retained_4294967295')
        self.assertEqual(result['actions'], ['reason:raw', 'reason:retained'] * 2)
        self.assertEqual(result['rows'][-1]['reason_cache'], 0xffffffff)

    def test_reason_and_power_guards_precede_polling(self):
        for name in ('key_reason_3', 'key_reason_6', 'key_power_error', 'key_no_power'):
            self.assertEqual(self.row(name)['returned'], 0)
            self.assertEqual(self.row(name)['polls_consumed'], 0)
        self.assertNotIn('power', self.result('key_reason_3')['actions'])

    def test_initial_release_and_last_press_attempt(self):
        self.assertEqual(self.row('key_release_wait')['returned'], 1)
        self.assertEqual(self.row('key_release_wait')['polls_consumed'], 45)
        self.assertEqual(self.row('key_press_last')['returned'], 1)
        self.assertEqual(self.row('key_press_last')['polls_consumed'], 81)
        self.assertEqual(self.row('key_press_timeout')['returned'], 0)
        self.assertEqual(self.result('key_press_timeout')['actions'].count('delay:50'), 20)

    def test_press_requires_exact_one_but_hold_accepts_nonzero(self):
        self.assertEqual(self.row('key_press_nonboolean')['returned'], 0)
        self.assertEqual(self.row('key_hold_nonboolean')['returned'], 1)
        self.assertEqual(self.result('key_success')['actions'].count('delay:50'), 20)
        for name in ('key_hold_last_release', 'key_hold_second_release'):
            self.assertEqual(self.row(name)['returned'], 0)
            self.assertNotIn('log:key_pass', self.result(name)['actions'])

    def test_driver_errors_stop_at_the_failing_sample(self):
        for index in range(5):
            row = self.row('key_driver_error_' + str(index))
            self.assertEqual((row['returned'], row['polls_consumed']), (0, index + 1))

    def test_record_bytes_match_independently_assembled_fixture(self):
        fixture = bytes.fromhex('a6cc07b02a0100000201') + bytes(32) + b'\x01'
        fixture += b'/mnt/backup/backup_fw_sign.zip'.ljust(254, b'\0') + b'\0'
        self.assertEqual(len(fixture), 298)
        self.assertEqual(upgrade_record(), fixture)
        row = self.row('prefix_backup')
        self.assertEqual(row['stopped']['record_sha256'], sha(fixture))
        self.assertEqual(row['appends'], [dict(key='upgrade', size=298, sha256=sha(fixture), status=0)])

    def test_prefix_stops_before_dispatch_with_live_frame(self):
        row = self.row('prefix_backup')
        self.assertIsNone(row['returned'])
        self.assertEqual(row['stopped']['pc'], STOP)
        self.assertEqual(row['stopped']['sp'], 0x81001000 - 0x150)
        self.assertEqual(row['stopped']['key_result'], 1)
        self.assertIn('env:reserve:333', self.result('prefix_backup')['actions'])

    def test_prefix_ignores_setter_error_without_proving_persistence(self):
        for name in ('prefix_env_uninitialized', 'prefix_reserve_failure', 'prefix_append_failure'):
            row = self.row(name)
            self.assertEqual(row['stopped'], self.row('prefix_backup')['stopped'])
            self.assertEqual(self.result(name)['actions'][-1], 'commit:no_op')
        self.assertEqual(self.row('prefix_env_uninitialized')['appends'], [])
        self.assertEqual(self.row('prefix_reserve_failure')['appends'], [])
        self.assertEqual(self.row('prefix_append_failure')['appends'][0]['status'], 5)

    def test_keyboard_failure_fallback_and_stale_handle(self):
        for name in ('prefix_register_failure', 'prefix_init_failure'):
            row = self.row(name)
            self.assertEqual(row['keyboard'], 0)
            self.assertEqual(row['stopped']['record_sha256'], sha(bytes(298)))
            self.assertIn('log:fallback_reason', self.result(name)['actions'])
        self.assertEqual(self.row('prefix_stale_handle')['keyboard'], 0x77)
        self.assertEqual(self.row('prefix_stale_handle')['stopped']['key_result'], 1)
        self.assertNotIn('keyboard:init', self.result('prefix_stale_handle')['actions'])
        self.assertEqual(self.row('prefix_key_rejected')['appends'], [])

    def test_fixture_bounds_and_terminal_prefix(self):
        for changes in (dict(capacity=1025), dict(key_name='a\0b'), dict(stored_hex='00' * 1025),
                        dict(payload_hex='00' * 513), dict(polls=[[2, 0, 0]]), dict(operations=['prefix', 'get'])):
            case = copy.deepcopy(self.cases['get_truncated']) | changes
            with self.assertRaises(ValueError):
                contract(case)

    def test_all_public_native_observations_match_model(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/boot-environment.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertIs(native['hardware_execution'], False)
        self.assertEqual(native['case_count'], 64)
        self.assertEqual(len(native['cases']), 64)
        for row, case in zip(native['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= native['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))
        self.assertEqual(len(report['export_sha256']), 8)


if __name__ == '__main__':
    unittest.main()
