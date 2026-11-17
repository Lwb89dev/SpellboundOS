import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest
import zlib

from analysis_scripts.env_gc import Model, contract, native_vectors
from analysis_scripts.env_records import record, state


def sha(data):
    return hashlib.sha256(data).hexdigest()


EF40 = b'\x00\xff\xff\x00\xff\xff\xff\xffEF40' + b'\xff' * 8


class EnvironmentGCTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def row(self, name):
        return self.result(name)['rows'][-1]

    def executed(self, name):
        model = Model(copy.deepcopy(self.cases[name]))
        model.result()
        return model

    def test_formatter_erases_body_and_writes_independent_header(self):
        model = self.executed('format')
        self.assertEqual(model.flash[:4096], EF40 + b'\xff' * (4096 - 20))
        self.assertEqual(self.row('format')['returned'], 0)
        self.assertEqual(self.result('format')['actions'][0], 'erase:0:4096:0')

    def test_erase_failure_returns_one_without_changing_storage(self):
        model = Model(self.cases['format_erase_error'])
        self.assertEqual(self.row('format_erase_error')['flash_sha256'], sha(model.flash))
        self.assertEqual(self.row('format_erase_error')['returned'], 1)
        self.assertEqual(self.result('format_erase_error')['actions'], ['erase:0:4096:-1', 'log:erase_error'])

    def test_header_write_failure_leaves_erased_sector(self):
        model = self.executed('format_header_error')
        self.assertEqual(model.flash[:4096], b'\xff' * 4096)
        self.assertEqual(self.row('format_header_error')['returned'], 3)

    def test_short_header_write_can_return_success_with_invalid_header(self):
        model = self.executed('format_short_header')
        self.assertEqual(self.row('format_short_header')['returned'], 0)
        self.assertEqual(model.flash[:20], EF40[:3] + b'\xff' * 17)

    def test_formatter_invalidates_end_cache_and_retains_old_end_word(self):
        expected = struct.pack('<II', 0xffffffff, 62) + b'\xff' * 24
        self.assertEqual(self.row('format_warm_cache')['sector_cache_sha256'], sha(expected))

    def test_formatter_does_not_invalidate_key_cache_itself(self):
        initial = Model(self.cases['format'])
        self.assertEqual(self.row('format')['key_cache_sha256'], sha(initial.index))
        self.assertEqual(struct.unpack_from('<I', initial.index, 4)[0], 20)

    def test_relocation_copies_complete_body_and_finalizes_source(self):
        model = self.executed('move')
        self.assertEqual(model.flash[4116:4158], record('upgrade', b'payload'))
        self.assertEqual(state(model.flash[20:25], 6), 4)
        self.assertEqual(struct.unpack_from('<I', model.index, 4)[0], 4116)
        self.assertEqual(self.row('move')['pending_replace'], 0)
        self.assertEqual(self.row('move')['returned'], 0)

    def test_already_marked_record_can_leave_new_key_cache_invalid(self):
        model = self.executed('move_marked')
        self.assertEqual(model.flash[4116:4158], record('upgrade', b'payload'))
        self.assertEqual(struct.unpack_from('<I', model.index, 4)[0], 0xffffffff)

    def test_no_space_leaves_source_marked_and_pending(self):
        model = self.executed('move_no_space')
        self.assertEqual(self.row('move_no_space')['returned'], 6)
        self.assertEqual(state(model.flash[20:25], 6), 3)
        self.assertEqual(self.row('move_no_space')['pending_replace'], 1)
        self.assertFalse(any(a.startswith('erase:') for a in self.result('move_no_space')['actions']))

    def test_mark_prepare_and_initial_status_errors_do_not_stop_move(self):
        for ordinal in (1, 2, 3):
            name = 'move_write_error_' + str(ordinal)
            self.assertEqual(self.row(name)['returned'], 0)
            self.assertIn('diagnostic:5a4', self.result(name)['actions'])
            self.assertEqual(self.row(name)['pending_replace'], 0)

    def test_first_bulk_error_is_overwritten_by_later_copy_result(self):
        model = self.executed('move_write_error_4')
        self.assertEqual(self.row('move_write_error_4')['returned'], 0)
        self.assertEqual(model.flash[4124:4156], b'\xff' * 32)
        self.assertEqual(model.flash[4156:4158], b'ad')
        self.assertEqual(state(model.flash[20:25], 6), 4)

    def test_last_bulk_error_propagates_after_cache_and_source_updates(self):
        model = self.executed('move_write_error_5')
        self.assertEqual(self.row('move_write_error_5')['returned'], 3)
        self.assertEqual(model.flash[4156:4158], b'\xff\xff')
        self.assertEqual(struct.unpack_from('<I', model.index, 4)[0], 4116)
        self.assertEqual(state(model.flash[20:25], 6), 4)

    def test_destination_and_source_final_status_errors_are_ignored(self):
        destination_error = self.executed('move_write_error_6')
        source_error = self.executed('move_write_error_7')
        self.assertEqual(self.row('move_write_error_6')['returned'], 0)
        self.assertEqual(state(destination_error.flash[4116:4121], 6), 1)
        self.assertEqual(self.row('move_write_error_7')['returned'], 0)
        self.assertEqual(state(source_error.flash[20:25], 6), 3)

    def test_short_bulk_write_continues_with_incomplete_body(self):
        model = self.executed('move_short_copy')
        self.assertEqual(self.row('move_short_copy')['returned'], 0)
        self.assertEqual(model.flash[4124:4128], b'KV4\xff')
        self.assertEqual(state(model.flash[20:25], 6), 4)

    def test_duplicate_scan_can_skip_copy_but_finalize_source(self):
        absent = self.executed('move_duplicate_absent')
        present = self.executed('move_duplicate_present')
        self.assertEqual(absent.flash[4116:4158], record('upgrade', b'payload'))
        expected_existing = bytearray(record('upgrade', b'newer'))
        expected_existing[0] = 0xff  # Fixture starts with only the state-2 byte clear.
        self.assertEqual(present.flash[4116:4156], expected_existing)
        self.assertNotIn('diagnostic:5a4', self.result('move_duplicate_present')['actions'])
        self.assertEqual(state(present.flash[20:25], 6), 4)

    def test_collection_relocates_before_source_reformat(self):
        model = self.executed('collect')
        self.assertEqual(model.flash[:4096], EF40 + b'\xff' * 4076)
        self.assertEqual(model.flash[4116:4158], record('upgrade', b'payload'))
        actions = self.result('collect')['actions']
        self.assertLess(actions.index('diagnostic:5a4'), actions.index('erase:0:4096:0'))
        self.assertEqual(self.row('collect')['returned'], 0)

    def test_collection_moves_multiple_and_already_marked_records(self):
        two = self.executed('collect_two')
        self.assertEqual(two.flash[4116:4158], record('upgrade', b'payload'))
        self.assertEqual(two.flash[4158:4198], record('upgrade', b'other'))
        self.assertEqual(struct.unpack_from('<I', two.index, 4)[0], 4158)
        self.assertEqual(self.row('collect_marked')['returned'], 0)
        self.assertEqual(self.executed('collect_marked').flash[4116:4158], record('upgrade', b'payload'))

    def test_invalid_or_clean_sector_is_not_collected(self):
        for name in ('collect_invalid', 'collect_clean'):
            initial = Model(self.cases[name])
            self.assertEqual(self.result(name)['actions'], [])
            self.assertEqual(self.row(name)['flash_sha256'], sha(initial.flash))

    def test_deleted_and_crc_bad_records_are_skipped_before_reformat(self):
        for name in ('collect_deleted', 'collect_bad_crc'):
            model = self.executed(name)
            self.assertNotIn('diagnostic:5a4', self.result(name)['actions'])
            self.assertEqual(model.flash[:4096], EF40 + b'\xff' * 4076)
            self.assertEqual(model.flash[4116:4158], b'\xff' * 42)

    def test_no_space_collection_still_reformats_source(self):
        model = self.executed('collect_no_space')
        self.assertEqual(self.row('collect_no_space')['returned'], 0)
        self.assertIn('diagnostic:5e9', self.result('collect_no_space')['actions'])
        self.assertEqual(model.flash[:4096], EF40 + b'\xff' * 4076)
        self.assertEqual(self.row('collect_no_space')['pending_replace'], 1)

    def test_copy_error_does_not_prevent_collection_reformat(self):
        model = self.executed('collect_move_error')
        self.assertEqual(self.row('collect_move_error')['returned'], 0)
        self.assertIn('diagnostic:5e9', self.result('collect_move_error')['actions'])
        self.assertEqual(model.flash[:4096], EF40 + b'\xff' * 4076)

    def test_collection_ignores_formatter_erase_error(self):
        model = self.executed('collect_erase_error')
        self.assertEqual(self.row('collect_erase_error')['returned'], 0)
        self.assertIn('log:erase_error', self.result('collect_erase_error')['actions'])
        self.assertEqual(state(model.flash[20:25], 6), 4)
        self.assertEqual(model.flash[4116:4158], record('upgrade', b'payload'))

    def test_maintenance_executes_collection_and_clears_flag(self):
        self.assertIn('erase:0:4096:0', self.result('maintenance')['actions'])
        self.assertEqual(self.row('maintenance')['maintenance_flag'], 0)
        self.assertIsNone(self.row('maintenance')['returned'])
        self.assertFalse(any(a.startswith('erase:') for a in self.result('maintenance_enough_empty')['actions']))
        self.assertEqual(self.row('maintenance_enough_empty')['maintenance_flag'], 0)

    def test_defaults_restore_formats_four_sectors_then_appends(self):
        model = self.executed('defaults')
        erases = [a for a in self.result('defaults')['actions'] if a.startswith('erase:')]
        self.assertEqual(erases, [f'erase:{i * 4096}:4096:0' for i in range(4)])
        self.assertEqual(model.flash[20:58], record('upgrade', b'one'))
        self.assertEqual(model.flash[58:92], record('mode', b'tw'))
        self.assertEqual(self.row('defaults')['returned'], 0)

    def test_defaults_format_errors_stop_and_propagate(self):
        for name, status in (('defaults_erase_error', 1), ('defaults_header_error', 3)):
            self.assertEqual(self.row(name)['returned'], status)
            self.assertEqual(len([a for a in self.result(name)['actions'] if a.startswith('erase:')]), 2)
            self.assertEqual(self.executed(name).flash[20:58], b'\xff' * 38)

    def test_defaults_ignore_append_preparation_error(self):
        model = self.executed('defaults_prepare_error')
        self.assertEqual(self.row('defaults_prepare_error')['returned'], 0)
        self.assertIn('log:write_error', self.result('defaults_prepare_error')['actions'])
        self.assertEqual(model.flash[20:58], b'\xff' * 38)

    def test_defaults_ignore_failed_final_record_marker(self):
        model = self.executed('defaults_append_final_error')
        self.assertEqual(self.row('defaults_append_final_error')['returned'], 0)
        self.assertEqual(state(model.flash[20:25], 6), 1)
        self.assertEqual(model.flash[28:58], record('upgrade', b'one')[8:])

    def test_crc_and_index_tags_preserve_new_record_address(self):
        model = self.executed('move')
        tag, age, address = struct.unpack_from('<HHI', model.index)
        self.assertEqual((tag, age, address), (zlib.crc32(b'upgrade') >> 16, 0, 4116))
        self.assertEqual(self.row('move')['key_cache_sha256'], sha(model.index))

    def test_host_fixture_table_bounds(self):
        for changes in (dict(sectors=[]), dict(defaults=[]), dict(defaults=[dict(key='', value='x', length=0)]),
                        dict(defaults=[dict(key='x', value='y', length=2)])):
            with self.assertRaises(ValueError):
                contract(copy.deepcopy(self.cases['move']) | changes)

    def test_all_public_native_observations_match(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/env-gc.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertIs(native['hardware_execution'], False)
        self.assertEqual((native['case_count'], len(native['cases'])), (35, 35))
        for row, case in zip(native['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= native['bound_per_case'])
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))
        self.assertEqual(len(report['export_sha256']), 8)


if __name__ == '__main__':
    unittest.main()
