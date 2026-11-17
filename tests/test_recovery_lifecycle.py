import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.recovery_lifecycle import (
    POINTERS, RAM, contract, entry_jump, native_vectors, raw_crc, signed,
)


class RecoveryLifecycleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def row(self, name):
        return self.result(name)['rows'][-1]

    def test_raw_getter_copies_header_and_balances_close(self):
        c = self.cases['get_1']
        row = c['expected']['rows'][0]
        expected = bytes.fromhex(c['files_hex'][1])[:72]
        self.assertEqual(row['header_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(row['returned'], 1)
        self.assertEqual(c['expected']['actions'], ['open:1:1', 'read:1:0:72:72', 'close:1'])
        self.assertEqual(row['open_handles'], [])

    def test_raw_setter_updates_source_crc_and_only_partition_header(self):
        c = self.cases['set_0']
        before = bytes.fromhex(c['files_hex'][0])
        source = bytearray.fromhex(c['source_header_hex'])
        struct.pack_into('<I', source, 68, raw_crc(source[:68]))
        row = c['expected']['rows'][0]
        self.assertIsNone(row['returned'])
        self.assertTrue(row['header_crc_valid'])
        self.assertEqual(row['header_sha256'], hashlib.sha256(source).hexdigest())
        self.assertEqual(row['partitions'][0]['sha256'], hashlib.sha256(source + before[72:]).hexdigest())

    def test_getter_error_status_does_not_leave_open_handle(self):
        for name in ('get_open_failure', 'get_short'):
            row = self.row(name)
            self.assertEqual(row['returned'], 0)
            self.assertEqual(row['open_handles'], [])
        self.assertEqual(self.result('get_short')['actions'][-2:], ['log:read_error', 'close:0'])

    def test_setter_failure_does_not_produce_status_and_short_write_is_not_retried(self):
        failed = self.row('set_open_failure')
        short = self.row('set_short')
        self.assertIsNone(failed['returned'])
        self.assertFalse(failed['header_crc_valid'])
        self.assertIsNone(short['returned'])
        self.assertTrue(short['header_crc_valid'])
        self.assertEqual(self.result('set_short')['actions'].count('write:0:72:71'), 1)
        self.assertIn('log:write_error', self.result('set_short')['actions'])

    def test_ota_is_first_priority_without_counter_reads(self):
        result = self.result('select_available_111')
        self.assertEqual(result['rows'][0]['returned'], POINTERS[2])
        self.assertEqual(result['actions'], ['validate:8:1'])

    def test_none_or_one_available_candidate(self):
        self.assertEqual(self.row('select_available_000')['returned'], 0)
        self.assertEqual(self.row('select_available_100')['returned'], POINTERS[0])
        self.assertEqual(self.row('select_available_010')['returned'], POINTERS[1])
        self.assertIn('log:error:379', self.result('select_available_000')['actions'])

    def test_retry_difference_threshold_is_nine_inclusive(self):
        self.assertEqual(self.row('select_delta_9_10')['returned'], POINTERS[0])
        self.assertEqual(self.row('select_delta_10_9')['returned'], POINTERS[1])
        self.assertEqual(self.row('select_delta_10_10')['returned'], 0)
        self.assertEqual(self.row('select_delta_11_0')['returned'], POINTERS[1])

    def test_zero_difference_ties_use_signed_generation_and_equal_generation_prefers_zero(self):
        self.assertEqual(self.row('select_generation_1_2')['returned'], POINTERS[1])
        self.assertEqual(self.row('select_generation_2_1')['returned'], POINTERS[0])
        self.assertEqual(self.row('select_generation_2_2')['returned'], POINTERS[0])
        self.assertEqual(self.row('select_generation_4294967295_0')['returned'], POINTERS[1])
        self.assertEqual(self.row('select_generation_0_2147483648')['returned'], POINTERS[0])

    def test_nonzero_equal_differences_prefer_one_and_negative_differences_are_eligible(self):
        self.assertEqual(self.row('select_delta_1_1')['returned'], POINTERS[1])
        self.assertEqual(self.row('select_delta_9_9')['returned'], POINTERS[1])
        self.assertEqual(self.row('select_delta_-1_0')['returned'], POINTERS[0])
        self.assertEqual(self.row('select_delta_0_-1')['returned'], POINTERS[1])
        self.assertEqual(signed(0xffffffff), -1)
        self.assertEqual(signed(0x80000000), -2147483648)

    def test_selector_ignores_raw_getter_failure_in_bounded_fixtures(self):
        short = self.result('select_get_short')
        failed = self.result('select_get_open_failure')
        self.assertIn('log:read_error', short['actions'])
        self.assertEqual(short['rows'][0]['returned'], POINTERS[0])
        self.assertIn('log:open_error', failed['actions'])
        self.assertEqual(failed['rows'][0]['returned'], POINTERS[1])

    def test_prepare_copies_image_returns_mapping_and_increments_boot_counter(self):
        c = self.cases['prepare_normal']
        row = c['expected']['rows'][0]
        expected = bytes.fromhex(c['files_hex'][0])[4096:] + b'\xa5' * (4096 - c['size'])
        self.assertEqual(row['ram_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(row['mapped'], 0x90101000)
        self.assertEqual((row['partitions'][0]['bootup'], row['partitions'][0]['complete']), (4, 3))
        self.assertEqual(row['returned'], 1)
        self.assertEqual(row['open_handles'], [])

    def test_mapping_only_still_updates_counters_and_no_outputs_does_nothing(self):
        c = self.cases['prepare_mapping_only']
        initial = bytearray(b'\xa5' * 4096)
        struct.pack_into('<I', initial, 0, 0x13)
        row = c['expected']['rows'][0]
        self.assertEqual(row['ram_sha256'], hashlib.sha256(initial).hexdigest())
        self.assertEqual(row['partitions'][0]['bootup'], 4)
        self.assertEqual(self.result('prepare_no_outputs')['actions'], [])
        self.assertEqual(self.row('prepare_no_outputs')['returned'], 0)
        self.assertEqual(self.row('prepare_ram_only')['mapped'], 0xa5a5a5a5)

    def test_successful_ota_prepare_clears_header_and_preserves_image(self):
        c = self.cases['prepare_ota']
        row = c['expected']['rows'][0]
        zero = bytearray(72)
        struct.pack_into('<I', zero, 68, raw_crc(zero[:68]))
        old = bytes.fromhex(c['files_hex'][2])
        self.assertEqual(row['partitions'][2]['sha256'], hashlib.sha256(zero + old[72:]).hexdigest())
        self.assertEqual(row['partitions'][2]['magic_hex'], '00000000')
        self.assertTrue(row['partitions'][2]['crc_valid'])
        self.assertEqual(row['returned'], 1)

    def test_prepare_short_header_or_image_returns_zero_with_handle_still_open(self):
        for name, error in (('prepare_header_short', 'log:error:3d8'), ('prepare_image_short', 'log:error:3e3')):
            row = self.row(name)
            self.assertEqual(row['returned'], 0)
            self.assertEqual([h['partition'] for h in row['open_handles']], ['recovery0'])
            self.assertIn(error, self.result(name)['actions'])
            self.assertFalse(any(a.startswith('write:') for a in self.result(name)['actions']))

    def test_counter_reread_open_failure_is_followed_by_zero_header_write(self):
        row = self.row('prepare_counter_open')
        self.assertEqual(row['returned'], 1)
        self.assertEqual(row['partitions'][0]['magic_hex'], '00000000')
        self.assertEqual(row['partitions'][0]['bootup'], 0)
        self.assertTrue(row['partitions'][0]['crc_valid'])
        self.assertIn('log:open_error', self.result('prepare_counter_open')['actions'])

    def test_short_counter_reread_skips_increment_but_prepare_returns_one(self):
        c = self.cases['prepare_counter_short']
        row = c['expected']['rows'][0]
        self.assertEqual(row['returned'], 1)
        self.assertEqual(row['partitions'][0]['bootup'], 3)
        self.assertEqual(row['partitions'][0]['sha256'], hashlib.sha256(bytes.fromhex(c['files_hex'][0])).hexdigest())
        self.assertIn('log:read_error', c['expected']['actions'])

    def test_write_failure_is_not_reflected_in_prepare_return(self):
        for name in ('prepare_write_open', 'prepare_write_short'):
            self.assertEqual(self.row(name)['returned'], 1)
        self.assertEqual(self.row('prepare_write_open')['partitions'][0]['bootup'], 3)
        short = self.row('prepare_write_short')['partitions'][0]
        self.assertEqual(short['bootup'], 4)
        self.assertFalse(short['crc_valid'])
        self.assertIn('log:write_error', self.result('prepare_write_short')['actions'])

    def test_counter_and_mapped_address_wrap_at_32_bits(self):
        wrapped = self.row('prepare_counter_wrap')['partitions'][0]
        self.assertEqual((wrapped['bootup'], wrapped['complete']), (0, 0xffffffff))
        self.assertTrue(wrapped['crc_valid'])
        self.assertEqual(self.row('prepare_mapping_wrap')['mapped'], 0x800)

    def test_finish_acknowledges_valid_normal_partitions_and_clears_ota(self):
        row = self.row('finish_all')
        self.assertEqual([(p['bootup'], p['complete']) for p in row['partitions'][:2]], [(5, 5), (7, 7)])
        self.assertEqual(row['partitions'][2]['magic_hex'], '00000000')
        self.assertTrue(all(p['crc_valid'] for p in row['partitions']))
        self.assertEqual(row['returned'], 1)
        self.assertEqual(self.result('finish_ota_only')['actions'], ['log:finish', 'open:2:1', 'write:2:72:72', 'close:2'])

    def test_finish_continues_after_ota_write_open_failure_and_skips_failed_normal_read(self):
        failed = self.result('finish_ota_open_failure')
        self.assertEqual(failed['rows'][0]['returned'], 1)
        self.assertIn('validate:0:1', failed['actions'])
        self.assertEqual(failed['rows'][0]['partitions'][2]['magic_hex'], '5245434f')
        short = self.result('finish_normal_short')
        self.assertFalse(any(a.startswith('write:0:') for a in short['actions']))
        self.assertIn('write:1:72:72', short['actions'])

    def test_counter_state_changes_selection_before_and_after_completion(self):
        rows = self.result('lifecycle_prepare_finish_select')['rows']
        self.assertEqual([r['returned'] for r in rows], [1, POINTERS[1], 1, POINTERS[0]])
        self.assertEqual((rows[0]['partitions'][0]['bootup'], rows[0]['partitions'][0]['complete']), (4, 3))
        self.assertEqual((rows[2]['partitions'][0]['bootup'], rows[2]['partitions'][0]['complete']), (4, 4))

    def test_handoff_clears_console_flag_and_emulated_interrupt_enable_bit(self):
        row = self.row('handoff_console')
        self.assertEqual((row['console'], row['mstatus']), (0, 0x1880))
        self.assertEqual(row['handoff'], dict(pc=RAM, sp=0x81001000, ra=0x70000000, first_word=0x13))
        self.assertIsNone(row['returned'])
        self.assertNotIn('boundary:console_close', self.result('handoff_console_off')['actions'])
        self.assertEqual(self.row('handoff_interrupts_already_off')['mstatus'], 0x1880)

    def test_actual_launch_reaches_entry_boundary_with_caller_frame_preserved(self):
        row = self.row('launch_normal')
        self.assertIsNone(row['returned'])
        self.assertEqual(row['handoff']['pc'], RAM)
        self.assertEqual((row['handoff']['sp'], row['handoff']['ra']), (0x81000ff0, 0x80c009d2))
        self.assertEqual(row['partitions'][0]['bootup'], 4)
        self.assertEqual(self.row('launch_ota')['partitions'][2]['magic_hex'], '00000000')

    def test_encoded_entry_trampoline_reaches_startup_without_linking_return_address(self):
        self.assertEqual(entry_jump(), 0x22c0006f)
        row = self.row('handoff_entry_trampoline')
        self.assertEqual(row['handoff'], dict(pc=RAM + 0x22c, sp=0x81001000,
                                            ra=0x70000000, first_word=entry_jump()))

    def test_failed_launch_does_not_run_handoff_cleanup(self):
        for name in ('launch_none', 'launch_image_short'):
            row = self.row(name)
            self.assertEqual(row['returned'], 0)
            self.assertIsNone(row['handoff'])
            self.assertEqual((row['console'], row['mstatus']), (1, 0x1888))
            self.assertEqual(self.result(name)['actions'][-2:], ['log:launch_error:164', 'log:launch_error:167'])

    def test_host_scope_is_bounded(self):
        c = self.cases['prepare_normal']
        for changes in ({'size': 4097}, {'target': 3}, {'available': []}, {'operations': ['unknown']},
                        {'operations': ['handoff', 'select']}, {'trampoline': True}, {'mstatus': 1 << 32}):
            with self.assertRaises(ValueError):
                contract(c | changes)

    def test_public_native_observations_match_host_model(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/recovery-lifecycle.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertFalse(native['hardware_execution'])
        self.assertEqual(native['case_count'], 64)
        self.assertEqual(len(native['cases']), len(self.cases))
        for row in native['cases']:
            self.assertEqual(row['observed'], self.result(row['name']))
            self.assertTrue(0 < row['steps'] <= 100000)
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))


if __name__ == '__main__':
    unittest.main()
