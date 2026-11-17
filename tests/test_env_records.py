import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest
import zlib

from analysis_scripts.boot_environment import upgrade_record
from analysis_scripts.env_records import (
    BASE, CURSOR, OLD, Model, contract, marker, native_vectors, record, state,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class EnvironmentRecordsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def row(self, name, index=-1):
        return self.result(name)['rows'][index]

    def writes(self, name):
        return [a.split(':') for a in self.result(name)['actions'] if a.startswith('write:')]

    def test_record_layout_and_crc_excludes_state_magic_and_total(self):
        value = record('upgrade', bytes(range(16)))
        self.assertEqual(value[:8], b'\x00\x00' + b'\xff' * 6)
        self.assertEqual(value[8:12], b'KV40')
        self.assertEqual(struct.unpack_from('<I', value, 12)[0], 51)
        self.assertEqual(value[20:28], b'\x07\xff\xff\xff\x10\x00\x00\x00')
        self.assertEqual(value[28:], b'upgrade' + bytes(range(16)))
        expected_crc = zlib.crc32(b'\x07\xff\xff\xff\x10\x00\x00\x00upgrade' + bytes(range(16)))
        self.assertEqual(struct.unpack_from('<I', value, 16)[0], expected_crc)

    def test_status_parser_uses_last_zero_among_count_minus_one_bytes(self):
        self.assertEqual([state(marker(i), 6) for i in range(6)], list(range(6)))
        self.assertEqual(state(b'\0\xff\0\xff\0', 6), 5)
        self.assertEqual(state(b'\0\0\xff', 4), 2)

    def test_append_orders_status_header_key_payload_and_final_status(self):
        writes = self.writes('append')
        self.assertEqual([(int(w[2]), int(w[3])) for w in writes], [
            (CURSOR, 1), (CURSOR + 8, 20), (CURSOR + 28, 7), (CURSOR + 35, 16), (CURSOR + 1, 1),
        ])
        self.assertEqual(writes[0][5], sha(b'\0'))
        self.assertEqual(writes[2][5], sha(b'upgrade'))

    def test_native_append_flash_hash_matches_complete_independent_record(self):
        model = Model(self.cases['append'])
        baseline = bytearray(model.flash)
        value = record('upgrade', bytes(range(16)))
        baseline[CURSOR - BASE:CURSOR - BASE + len(value)] = value
        self.assertEqual(self.row('append')['flash_sha256'], sha(baseline))

    def test_append_then_get_uses_native_cached_parser(self):
        row = self.row('append_get')
        self.assertEqual((row['returned'], row['length_output']), (16, 16))
        self.assertEqual(row['output_sha256'], sha(bytes(range(16)) + b'\xa5' * 4080))
        self.assertEqual(row['key_cache_record'], CURSOR)
        self.assertTrue(any(a.startswith(f'read:34:{CURSOR}:28:') for a in self.result('append_get')['actions']))
        self.assertNotIn('boundary:scan_miss', self.result('append_get')['actions'])

    def test_empty_value_is_stored_with_zero_length_payload_write(self):
        self.assertEqual(self.row('append_empty')['length_output'], 0)
        self.assertEqual(self.row('append_empty')['key_cache_record'], CURSOR)
        self.assertTrue(any(w[3] == '0' for w in self.writes('append_empty')))

    def test_key_length_32_is_accepted_and_33_rejected(self):
        self.assertEqual(self.row('append_key32')['returned'], 16)
        self.assertEqual(self.row('append_key33')['returned'], 4)
        self.assertEqual(self.result('append_key33')['actions'], ['warn:key_length'])

    def test_record_extent_4076_is_accepted_and_4077_rejected(self):
        row = self.row('append_record_max')
        self.assertEqual(row['length_output'], 4041)
        self.assertEqual(row['returned'], 64)
        self.assertEqual(self.row('append_record_large')['returned'], 6)
        self.assertEqual(self.result('append_record_large')['actions'], ['warn:record_length'])

    def test_sentinel_cursor_requests_reservation_before_writing(self):
        self.assertEqual(self.result('append_reserve')['actions'][0], 'boundary:reserve:51')
        self.assertEqual(self.row('append_reserve')['returned'], 0)
        self.assertEqual(self.result('append_no_space')['actions'], ['boundary:reserve:51'])
        self.assertEqual(self.row('append_no_space')['returned'], 6)

    def test_sector_status_and_dirty_status_have_separate_offsets(self):
        self.assertEqual(int(self.writes('append_sector_open')[0][2]), 0x7001)
        self.assertEqual(int(self.writes('append_sector_full')[0][2]), 0x7002)
        self.assertEqual(int(self.writes('remove_sector_update')[-1][2]), 0x6004)

    def test_free_space_threshold_and_unsigned_underflow(self):
        self.assertEqual(self.row('append_free_60')['maintenance_flag'], 0)
        self.assertEqual(self.row('append_free_59')['maintenance_flag'], 1)
        self.assertEqual(self.row('append_free_below_60')['maintenance_flag'], 1)
        self.assertEqual(self.row('append_free_underflow')['maintenance_flag'], 0)
        self.assertEqual(self.row('append_sector_full')['sector_cache_end'], 0xffffffff)
        self.assertEqual(self.row('append')['sector_cache_end'], CURSOR + 51)

    def test_each_append_write_error_stops_at_its_stage(self):
        for index in range(1, 6):
            name = 'append_error_' + str(index)
            self.assertEqual(self.row(name, 0)['returned'], 3)
            self.assertEqual(len(self.writes(name)), index)
        self.assertEqual(self.row('append_error_2')['key_cache_record'], 0xffffffff)
        self.assertEqual(self.row('append_error_3')['key_cache_record'], CURSOR)

    def test_key_cache_is_published_even_after_failed_key_write(self):
        row = self.row('append_error_3')
        self.assertEqual(row['returned'], 3)
        self.assertEqual(row['key_cache_record'], CURSOR)
        self.assertEqual(row['sector_cache_end'], CURSOR + 51)

    def test_final_status_failure_leaves_cache_readable(self):
        result = self.result('append_error_5')
        self.assertEqual([r['returned'] for r in result['rows']], [3, 16])
        self.assertEqual(result['rows'][0]['flash_sha256'], result['rows'][1]['flash_sha256'])
        model = Model(self.cases['append_error_5'])
        model.result()
        self.assertEqual(state(model.bytes(CURSOR, 5), 6), 1)

    def test_short_writes_return_success_and_continue(self):
        for index in (2, 3, 4, 5):
            name = 'append_short_' + str(index)
            self.assertEqual(self.row(name, 0)['returned'], 0)
            self.assertEqual(len(self.writes(name)), 5)
            self.assertEqual(self.writes(name)[index - 1][4], '0')
        self.assertEqual(self.row('append_short_5')['returned'], 16)

    def test_getter_clips_payload_and_reports_original_length(self):
        row = self.row('get_clip')
        self.assertEqual((row['returned'], row['length_output']), (3, 8))
        self.assertEqual(row['output_sha256'], sha(b'pre' + b'\xa5' * 4093))

    def test_decoder_descriptor_offsets_and_crc_failure(self):
        descriptor = bytearray(56)
        descriptor[:3] = bytes([2, 1, 7])
        struct.pack_into('<II', descriptor, 8, 43, 8)
        descriptor[16:23] = b'upgrade'
        struct.pack_into('<II', descriptor, 48, OLD, OLD + 35)
        self.assertEqual(self.row('decode')['descriptor_sha256'], sha(descriptor))
        descriptor[1] = 0
        descriptor[2] = 0
        descriptor[12:16] = bytes(4)
        descriptor[16:23] = bytes(7)
        descriptor[52:56] = bytes(4)
        self.assertEqual(self.row('decode_bad_crc')['descriptor_sha256'], sha(descriptor))

    def test_parser_does_not_check_magic_in_covered_cached_path(self):
        self.assertEqual(self.row('decode_bad_magic')['descriptor_sha256'], self.row('decode')['descriptor_sha256'])
        self.assertNotEqual(self.row('decode_bad_magic')['flash_sha256'], self.row('decode')['flash_sha256'])

    def test_connected_replace_keeps_new_cache_after_old_final_remove(self):
        row = self.row('set_get_replace')
        self.assertEqual(row['key_cache_record'], CURSOR)
        self.assertEqual(row['pending_replace'], 0)
        model = Model(self.cases['set_get_replace'])
        model.result()
        self.assertEqual(state(model.bytes(OLD, 5), 6), 4)
        self.assertEqual(state(model.bytes(CURSOR, 5), 6), 2)

    def test_replacement_errors_preserve_observed_cache_and_pending_flag(self):
        self.assertEqual([r['returned'] for r in self.result('replace_final_error')['rows']], [3, 16])
        self.assertEqual(self.row('replace_final_error')['pending_replace'], 0)
        self.assertEqual([r['returned'] for r in self.result('replace_mark_error')['rows']], [3, 8])
        self.assertEqual(self.row('replace_mark_error')['pending_replace'], 1)

    def test_delete_and_mark_have_distinct_cache_effects(self):
        self.assertEqual(self.row('remove_missing')['returned'], 4)
        self.assertEqual(self.row('remove')['key_cache_record'], 0xffffffff)
        self.assertEqual(self.row('remove')['returned'], 0)
        self.assertEqual(self.row('mark_then_get')['key_cache_record'], OLD)
        self.assertEqual(self.row('mark_then_get')['pending_replace'], 1)
        self.assertEqual(self.row('mark_then_get')['returned'], 8)
        self.assertEqual(self.row('remove_error')['returned'], 8)

    def test_dirty_sector_update_failure_occurs_after_cache_invalidation(self):
        row = self.row('remove_sector_error')
        self.assertEqual(row['returned'], 3)
        self.assertEqual(row['key_cache_record'], 0xffffffff)
        self.assertEqual(len(self.writes('remove_sector_error')), 2)

    def test_upgrade_payload_round_trips_through_native_backend(self):
        row = self.row('set_upgrade_record')
        self.assertEqual((row['returned'], row['length_output']), (298, 298))
        self.assertEqual(row['output_sha256'], sha(upgrade_record() + b'\xa5' * (4096 - 298)))
        self.assertIn('boundary:reserve:333', self.result('set_upgrade_record')['actions'])

    def test_read_write_routing_window_and_fallback(self):
        for op in ('read', 'write'):
            self.assertTrue(self.result(op + '_special')['actions'][0].startswith(op + ':17:256:'))
            self.assertTrue(self.result(op + '_fallback')['actions'][0].startswith(op + ':51:16640:'))
            self.assertTrue(self.result(op + '_special_end')['actions'][0].startswith(op + ':17:4095:'))
            self.assertTrue(self.result(op + '_general_boundary')['actions'][0].startswith(op + ':34:20480:'))
            self.assertTrue(self.result(op + '_zero_general')['actions'][0].startswith(op + ':0:'))

    def test_missing_special_handles_and_negative_status_mapping(self):
        for name, status in (('read_missing_special', 2), ('write_missing_special', 3),
                             ('read_error', 2), ('write_error', 3)):
            self.assertEqual(self.row(name)['returned'], status)
        self.assertEqual(self.result('read_missing_special')['actions'], ['log:read_error'])

    def test_short_positive_service_results_are_accepted(self):
        self.assertEqual(self.row('read_short')['returned'], 0)
        self.assertEqual(self.row('read_short')['output_sha256'], sha(b'\xff' * 3 + b'\xa5' * 4093))
        self.assertEqual(self.row('write_short')['returned'], 0)
        model = Model(self.cases['write_short'])
        model.result()
        self.assertEqual(model.bytes(0x5100, 5), b'\x00\x01\x02\xff\xff')

    def test_host_fixture_bounds(self):
        for changes in (dict(key='x' * 34), dict(key='a\0b'), dict(capacity=4097),
                        dict(payload_hex='00' * 4078), dict(operations=['decode'], read_result=1)):
            with self.assertRaises(ValueError):
                contract(copy.deepcopy(self.cases['append']) | changes)

    def test_all_public_native_observations_agree(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/env-records.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertIs(native['hardware_execution'], False)
        self.assertEqual((native['case_count'], len(native['cases'])), (57, 57))
        for row, case in zip(native['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= native['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))
        self.assertEqual(len(report['export_sha256']), 11)


if __name__ == '__main__':
    unittest.main()
