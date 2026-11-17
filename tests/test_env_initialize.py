import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.env_initialize import Model, TABLE, native_vectors
from analysis_scripts.env_records import record, state


def sha(data):
    return hashlib.sha256(data).hexdigest()


class EnvironmentInitializeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def row(self, name, index=-1):
        return self.result(name)['rows'][index]

    def executed(self, name):
        model = Model(copy.deepcopy(self.cases[name]))
        model.result()
        return model

    def test_binding_sets_table_and_ready_after_success(self):
        row = self.row('bind_clean')
        self.assertEqual((row['returned'], row['ready'], row['duplicate_guard']), (0, 1, 0))
        self.assertEqual((row['default_pointer'], row['default_count'], row['base']), (TABLE, 2, 0))
        self.assertEqual(self.result('bind_clean')['actions'][0], 'diagnostic:8fe')

    def test_direct_initializer_does_not_set_outer_ready_flag(self):
        row = self.row('initialize_clean')
        self.assertEqual((row['returned'], row['ready'], row['duplicate_guard']), (0, 0, 0))
        self.assertFalse(any(a.startswith('erase:') for a in self.result('initialize_clean')['actions']))

    def test_binding_clears_cache_addresses_but_keeps_other_bytes(self):
        ends = bytearray(b'\xa5' * 32)
        keys = bytearray(b'\xa5' * 128)
        for i in range(4):struct.pack_into('<I', ends, i * 8, 0xffffffff)
        for i in range(16):struct.pack_into('<I', keys, i * 8 + 4, 0xffffffff)
        row = self.row('bind_stale_cache')
        self.assertEqual(row['sector_cache_sha256'], sha(ends))
        self.assertEqual(row['key_cache_sha256'], sha(keys))
        self.assertEqual(row['ready'], 1)

    def test_already_ready_binding_skips_everything(self):
        row = self.row('bind_already_ready')
        self.assertEqual(self.result('bind_already_ready')['actions'], [])
        self.assertEqual((row['returned'], row['default_pointer'], row['default_count'], row['base']), (0, 0x81348888, 77, 4096))
        self.assertEqual(row['key_cache_sha256'], sha(b'\xa5' * 128))

    def test_live_record_is_preserved_without_populating_key_cache(self):
        initial = Model(self.cases['initialize_live'])
        row = self.row('initialize_live')
        self.assertEqual(row['flash_sha256'], sha(initial.flash))
        self.assertEqual(row['key_cache_sha256'], sha(b'\xff' * 128))

    def test_incomplete_record_is_marked_state_five(self):
        model = self.executed('initialize_incomplete')
        self.assertEqual(state(model.flash[20:25], 6), 5)
        self.assertEqual(self.row('initialize_incomplete')['returned'], 0)

    def test_marked_record_is_actually_relocated(self):
        model = self.executed('initialize_marked')
        self.assertEqual(model.flash[62:104], record('upgrade', b'payload'))
        self.assertEqual(state(model.flash[20:25], 6), 4)
        self.assertIn('diagnostic:86e', self.result('initialize_marked')['actions'])

    def test_existing_duplicate_skips_copy_and_finalizes_old_record(self):
        model = self.executed('initialize_duplicate')
        existing = bytearray(record('upgrade', b'newer'))
        existing[0] = 0xff
        self.assertEqual(model.flash[4116:4156], existing)
        self.assertEqual(state(model.flash[20:25], 6), 4)
        self.assertNotIn('diagnostic:5a4', self.result('initialize_duplicate')['actions'])

    def test_incomplete_callback_can_stop_before_later_marked_record(self):
        model = self.executed('initialize_incomplete_then_marked')
        self.assertEqual(state(model.flash[20:25], 6), 5)
        self.assertEqual(state(model.flash[62:67], 6), 3)
        self.assertEqual(self.row('initialize_incomplete_then_marked')['returned'], 0)

    def test_deleted_and_bad_crc_records_do_not_trigger_relocation(self):
        for name in ('initialize_deleted', 'initialize_bad_crc'):
            self.assertEqual(self.row(name)['flash_sha256'], sha(Model(self.cases[name]).flash))
            self.assertNotIn('diagnostic:5a4', self.result(name)['actions'])

    def test_unresolved_marked_record_can_coexist_with_initializer_success(self):
        model = self.executed('initialize_marked_no_space')
        self.assertEqual(self.row('initialize_marked_no_space')['returned'], 0)
        self.assertEqual(state(model.flash[20:25], 6), 3)
        self.assertIn('diagnostic:872', self.result('initialize_marked_no_space')['actions'])

    def test_dirty_three_callback_runs_maintenance_even_when_gc_is_skipped(self):
        row = self.row('initialize_dirty3_enough_empty')
        self.assertIn('diagnostic:603', self.result('initialize_dirty3_enough_empty')['actions'])
        self.assertFalse(any(a.startswith('erase:') for a in self.result('initialize_dirty3_enough_empty')['actions']))
        self.assertEqual(row['maintenance_flag'], 0)

    def test_dirty_three_callback_reaches_actual_collection(self):
        model = self.executed('initialize_dirty3_collect')
        self.assertEqual(model.flash[4116:4158], record('upgrade', b'payload'))
        self.assertEqual(model.flash[20:62], b'\xff' * 42)
        self.assertIn('erase:0:4096:0', self.result('initialize_dirty3_collect')['actions'])
        adjacent_reads = [a for a in self.result('initialize_dirty3_collect')['actions']
                          if a.startswith('read:') and int(a.split(':')[1]) + int(a.split(':')[2]) > 0x4000]
        self.assertTrue(adjacent_reads)
        self.assertTrue(all(int(a.split(':')[1]) + int(a.split(':')[2]) <= 0x4020 for a in adjacent_reads))

    def test_three_retry_path_dumps_then_copies_and_restarts(self):
        result = self.result('initialize_retry_three')
        self.assertEqual(result['actions'].count('diagnostic:872'), 3)
        self.assertEqual(result['actions'].count('diagnostic:506'), 3)
        self.assertEqual(result['actions'].count('dump:row'), 256)
        self.assertEqual(result['actions'].count('log:copy_complete'), 1)
        self.assertEqual(result['rows'][0]['flash_sha256'], result['rows'][0]['backup_sha256'])

    def test_invalid_sector_can_be_recovered_from_distinct_backup_bytes(self):
        result = self.result('initialize_backup_repair')
        model = self.executed('initialize_backup_repair')
        expected = bytearray(record('upgrade', b'backup'))
        expected[0] = 0xff
        self.assertEqual(model.flash[20:61], expected)
        self.assertEqual(result['rows'][0]['flash_sha256'], result['rows'][0]['backup_sha256'])
        self.assertNotIn('warn:restore_defaults', result['actions'])

    def test_missing_backup_leaves_defaults_but_no_ready_flag(self):
        model = self.executed('bind_backup_missing')
        self.assertEqual(model.flash[20:58], record('upgrade', b'one'))
        self.assertEqual(model.flash[58:92], record('mode', b'tw'))
        self.assertEqual((self.row('bind_backup_missing')['returned'], self.row('bind_backup_missing')['ready']), (7, 0))

    def test_binding_again_can_succeed_after_error_and_fallback(self):
        rows = self.result('bind_again_after_error')['rows']
        self.assertEqual([r['returned'] for r in rows], [7, 0])
        self.assertEqual([r['ready'] for r in rows], [0, 1])
        self.assertEqual(rows[0]['flash_sha256'], rows[1]['flash_sha256'])

    def test_backup_read_error_survives_successful_defaults_fallback(self):
        model = self.executed('initialize_backup_read_error')
        self.assertEqual(self.row('initialize_backup_read_error')['returned'], 2)
        self.assertEqual(model.flash[20:58], record('upgrade', b'one'))
        self.assertFalse(self.row('initialize_backup_read_error')['heap_active'])

    def test_backup_rewrite_error_survives_defaults_fallback(self):
        model = self.executed('initialize_backup_write_error')
        self.assertEqual(self.row('initialize_backup_write_error')['returned'], 3)
        self.assertEqual(model.flash[20:58], record('upgrade', b'one'))

    def test_still_invalid_backup_falls_back_without_second_copy(self):
        actions = self.result('initialize_backup_still_invalid')['actions']
        self.assertEqual(actions.count('log:copy_complete'), 1)
        self.assertIn('warn:restore_defaults', actions)
        self.assertEqual(self.row('initialize_backup_still_invalid')['returned'], 0)

    def test_initial_format_failure_can_be_repaired_by_backup(self):
        result = self.result('initialize_initial_erase_error')
        self.assertIn('log:erase_error', result['actions'])
        self.assertEqual(result['rows'][0]['returned'], 0)
        self.assertEqual(result['rows'][0]['flash_sha256'], result['rows'][0]['backup_sha256'])

    def test_defaults_formatter_error_does_not_replace_saved_copy_error(self):
        result = self.result('initialize_defaults_erase_error')
        self.assertEqual(result['rows'][0]['returned'], 7)
        self.assertIn('log:erase_error', result['actions'])
        self.assertEqual(self.executed('initialize_defaults_erase_error').flash[20:58], b'\xff' * 38)

    def test_copy_moves_four_distinct_blocks_and_frees_heap(self):
        case = self.cases['copy']
        initial = Model(case)
        self.assertNotEqual(sha(initial.flash), sha(initial.backup))
        row = self.row('copy')
        self.assertEqual(row['flash_sha256'], row['backup_sha256'])
        actions = self.result('copy')['actions']
        self.assertEqual([a.split(':')[1] for a in actions if a.startswith('rewrite:')], ['0', '4096', '8192', '12288'])
        self.assertEqual(actions.count('free:4096'), 1)

    def test_missing_handles_return_seven_without_allocation(self):
        for name in ('copy_missing_source', 'copy_missing_active', 'dump_missing_active'):
            self.assertEqual(self.row(name)['returned'], 7)
            self.assertEqual(self.result(name)['actions'], [])

    def test_heap_allocation_failure_has_no_free(self):
        for name in ('copy_alloc_error', 'dump_alloc_error'):
            self.assertEqual(self.row(name)['returned'], 7)
            self.assertEqual(self.result(name)['actions'], ['alloc:4096:0'])

    def test_copy_read_failure_stops_before_third_rewrite(self):
        actions = self.result('copy_read_error')['actions']
        self.assertEqual(self.row('copy_read_error')['returned'], 2)
        self.assertEqual(sum(a.startswith('rewrite:') for a in actions), 2)
        self.assertEqual(actions[-1], 'free:4096')

    def test_copy_rewrite_failure_stops_and_frees(self):
        actions = self.result('copy_write_error')['actions']
        self.assertEqual(self.row('copy_write_error')['returned'], 3)
        self.assertEqual(sum(a.startswith('backup_read:') for a in actions), 2)
        self.assertEqual(actions[-1], 'free:4096')

    def test_short_backup_read_still_rewrites_complete_heap_block(self):
        model = self.executed('copy_short_read')
        self.assertEqual(self.row('copy_short_read')['returned'], 0)
        self.assertEqual(model.flash[:64], model.backup[:64])
        self.assertEqual(model.flash[64:4096], b'\xa5' * (4096 - 64))

    def test_dump_rows_and_failure_cleanup(self):
        self.assertEqual(self.result('dump')['actions'].count('dump:row'), 256)
        self.assertEqual(self.row('dump')['returned'], 0)
        self.assertEqual(self.result('dump_read_error')['actions'].count('dump:row'), 128)
        self.assertEqual(self.row('dump_read_error')['returned'], 2)
        self.assertEqual(self.result('dump_read_error')['actions'][-1], 'free:4096')

    def test_public_native_observations_and_no_heap_leaks(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/env-initialize.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertIs(native['hardware_execution'], False)
        self.assertEqual((native['case_count'], len(native['cases'])), (34, 34))
        for row, case in zip(native['cases'], self.cases.values()):
            self.assertEqual(row['name'], case['name'])
            self.assertEqual(row['observed'], case['expected'])
            self.assertTrue(0 < row['steps'] <= native['bound_per_case'])
            self.assertTrue(all(not r['heap_active'] for r in row['observed']['rows']))
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))
        self.assertEqual(len(report['export_sha256']), 7)


if __name__ == '__main__':
    unittest.main()
