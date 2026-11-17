import hashlib
import json
from pathlib import Path
import struct
import unittest
import zlib

from analysis_scripts.nand_bbt import MAGIC,contract,native_vectors,record


class NandBbtTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def rows(self,name):return self.result(name)['rows']
    def row(self,name):return self.rows(name)[-1]
    def actions(self,name):return self.result(name)['actions']
    def state(self,name,index=-1):return bytes.fromhex(self.rows(name)[index]['state_hex'])
    def words(self,name,index=-1):return struct.unpack_from('<6I',self.state(name,index),140)

    def test_record_header_and_crc_cover_only_counted_entries(self):
        data=record(dict(bad=[1,3,7]))
        self.assertEqual(len(data),140)
        self.assertEqual(struct.unpack_from('<III',data),(MAGIC,3,zlib.crc32(b'\x01\0\x03\0\x07\0')))
        self.assertEqual(data[18:],b'\xff'*122)

    def test_inactive_mapping_passes_input_without_geometry_check(self):
        for name in ('inactive_block_passthrough','inactive_page_passthrough'):
            self.assertEqual((self.row(name)['returned'],self.row(name)['output']),(0,0xffffffff))

    def test_active_query_checks_magic(self):
        self.assertEqual(self.row('active_true')['returned'],1)
        self.assertEqual(self.row('active_false')['returned'],0)

    def test_sorted_bad_blocks_shift_addresses_at_each_threshold(self):
        for value,mapped in ((0,0),(1,2),(2,4),(3,5),(4,6),(5,8),(7,10),(8,11)):
            row=self.row('block_'+str(value))
            self.assertEqual((row['returned'],row['output']),(0,mapped))

    def test_backup_block_is_exclusive_mapped_limit(self):
        self.assertEqual(self.row('block_1018')['output'],1021)
        for value in (1019,1021,1022,1023):
            row=self.row('block_'+str(value))
            self.assertEqual((row['returned'],row['output']),(0xffffffff,0xa5a5a5a5))

    def test_empty_table_still_checks_limit(self):
        self.assertEqual((self.row('empty_table')['returned'],self.row('empty_table')['output']),(0,1021))

    def test_page_mapping_preserves_in_block_offset(self):
        for value,mapped in ((0,0),(63,63),(64,128),(65,129),(127,191),(128,256),(191,319),(511,703)):
            self.assertEqual((self.row('page_'+str(value))['returned'],self.row('page_'+str(value))['output']),(0,mapped))

    def test_page_mapping_uses_runtime_pages_per_block(self):
        self.assertEqual(self.row('page_different_ppb')['output'],257)

    def test_page_remap_failure_leaves_output_untouched(self):
        self.assertEqual((self.row('page_65216')['returned'],self.row('page_65216')['output']),(0xffffffff,0xa5a5a5a5))
        self.assertEqual(self.row('page_65215')['output'],65407)

    def test_wrapping_input_is_a_bounded_counterexample(self):
        self.assertEqual((self.row('block_wraps_to_zero')['returned'],self.row('block_wraps_to_zero')['output']),(0,0))

    def test_verifier_executes_crc_before_publication(self):
        actions=self.actions('verify_valid');payload=b'\x01\0\x03\0\x07\0'
        crc='crc:6:'+hashlib.sha256(payload).hexdigest()
        self.assertLess(actions.index(crc),actions.index('publish:140'))
        self.assertEqual(self.row('verify_valid')['returned'],1)
        self.assertEqual(self.state('verify_valid')[:140],record(dict(bad=[1,3,7])))

    def test_verified_empty_table_is_accepted(self):
        self.assertEqual(self.row('verify_empty')['returned'],1)
        self.assertIn('crc:0:'+hashlib.sha256(b'').hexdigest(),self.actions('verify_empty'))
        self.assertNotIn('log:entries',self.actions('verify_empty'))

    def test_magic_rejection_precedes_crc(self):
        self.assertEqual(self.row('verify_bad_magic')['returned'],0)
        self.assertIn('log:magic_error',self.actions('verify_bad_magic'))
        self.assertFalse(any(a.startswith('crc:') for a in self.actions('verify_bad_magic')))

    def test_count_limit_is_reserved_blocks_minus_two(self):
        self.assertEqual(self.row('verify_count_limit')['returned'],1)
        self.assertEqual(self.row('verify_count_exceeds')['returned'],0)
        self.assertIn('log:count_error',self.actions('verify_count_exceeds'))

    def test_crc_rejection_does_not_publish(self):
        self.assertEqual(self.row('verify_bad_crc')['returned'],0)
        self.assertIn('log:crc_error',self.actions('verify_bad_crc'))
        self.assertNotIn('publish:140',self.actions('verify_bad_crc'))
        self.assertEqual(self.state('verify_bad_crc').hex(),self.cases['verify_bad_crc']['initial_hex'])

    def test_read_error_does_not_log_a_record_or_publish(self):
        self.assertEqual(self.row('verify_read_error')['returned'],0)
        self.assertEqual(len(self.actions('verify_read_error')),1)

    def test_entry_logging_groups_twenty_values(self):
        self.assertEqual(self.actions('verify_two_log_groups').count('log:entries'),2)
        self.assertEqual(sum(a.startswith('format:') for a in self.actions('verify_two_log_groups')),21)
        self.assertEqual(self.actions('verify_max_reserved_count').count('log:entries'),4)

    def test_verification_and_mapping_share_published_ram_state(self):
        self.assertEqual([row['returned'] for row in self.rows('verify_then_map')],[1,0])
        self.assertEqual(self.row('verify_then_map')['output'],5)
        self.assertEqual(self.row('verify_then_page')['output'],321)

    def test_crc_valid_unsorted_entries_are_accepted_then_skip_incorrectly(self):
        self.assertEqual([row['returned'] for row in self.rows('verify_unsorted_then_map')],[1,0])
        self.assertEqual(self.row('verify_unsorted_then_map')['output'],1)

    def test_crc_valid_duplicates_shift_twice(self):
        self.assertEqual([row['returned'] for row in self.rows('verify_duplicate_then_map')],[1,0])
        self.assertEqual(self.row('verify_duplicate_then_map')['output'],3)

    def test_resume_derives_geometry_and_uses_last_two_good_reserved_blocks(self):
        self.assertEqual(self.words('resume_primary'),(1024,2048,64,16,1023,1022))
        self.assertEqual(self.actions('resume_primary')[:2],['bad_check:1023:1:0','bad_check:1022:1:0'])

    def test_primary_success_avoids_backup_read_and_repair(self):
        actions=self.actions('resume_primary')
        self.assertEqual(sum(a.startswith('read:') for a in actions),1)
        self.assertFalse(any(a.startswith(('erase:','write:')) for a in actions))
        self.assertEqual(self.row('resume_primary')['output'],5)

    def test_backup_success_restores_primary_with_mapping_disabled(self):
        actions=self.actions('resume_backup');write=next(a for a in actions if a.startswith('write:'))
        self.assertIn('read:65408:140:0:0',actions)
        self.assertIn('erase:1023:1:0:0',actions)
        self.assertTrue(write.startswith('write:65472:140:0:'))
        self.assertEqual(struct.unpack_from('<I',self.state('resume_backup'))[0],MAGIC)
        self.assertEqual(self.row('resume_backup')['output'],5)

    def test_reread_error_stops_repair_but_restores_ram_magic(self):
        actions=self.actions('resume_backup_reread_error')
        self.assertIn('log:repair_failed',actions)
        self.assertFalse(any(a.startswith(('erase:','write:')) for a in actions))
        self.assertEqual([r['returned'] for r in self.rows('resume_backup_reread_error')],[0,0])
        self.assertEqual(self.row('resume_backup_reread_error')['output'],5)

    def test_erase_error_stops_write_but_resume_returns_zero(self):
        actions=self.actions('resume_backup_erase_error')
        self.assertIn('erase:1023:1:0:-9',actions)
        self.assertFalse(any(a.startswith('write:') for a in actions))
        self.assertIn('log:repair_failed',actions)
        self.assertEqual([r['returned'] for r in self.rows('resume_backup_erase_error')],[0,0])

    def test_write_error_still_leaves_backup_table_active_in_ram(self):
        self.assertIn('log:repair_failed',self.actions('resume_backup_write_error'))
        self.assertEqual([r['returned'] for r in self.rows('resume_backup_write_error')],[0,0])
        self.assertEqual(self.row('resume_backup_write_error')['output'],5)

    def test_both_invalid_returns_one_and_leaves_mapping_inactive(self):
        self.assertEqual([r['returned'] for r in self.rows('resume_both_invalid')],[1,0])
        self.assertEqual(self.row('resume_both_invalid')['output'],3)
        self.assertEqual(struct.unpack_from('<I',self.state('resume_both_invalid'))[0],0)
        self.assertIn('log:no_bbt',self.actions('resume_both_invalid'))

    def test_primary_crc_failure_falls_back_to_backup(self):
        self.assertIn('log:crc_error',self.actions('resume_primary_crc_error'))
        self.assertEqual(self.row('resume_primary_crc_error')['returned'],0)
        self.assertTrue(any(a.startswith('write:') for a in self.actions('resume_primary_crc_error')))

    def test_scan_skips_bad_candidates_and_can_use_reserve_boundary(self):
        self.assertEqual(self.words('resume_skips_bad_tail')[-2:],(1022,1020))
        self.assertEqual(self.actions('resume_skips_bad_tail')[:2],['bad_check:1023:1:103']*2)
        self.assertEqual(self.words('resume_last_reserved_pair')[-2:],(1009,1008))

    def test_insufficient_good_blocks_stop_at_assertion(self):
        for name in ('resume_no_good','resume_only_one_good','resume_one_reserved_block'):
            self.assertIsNone(self.row(name)['returned'])
            self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c3d3b0,line=0xac))
            self.assertEqual(self.actions(name)[-1],'log:too_many_bad')

    def test_larger_geometry_updates_all_six_fields(self):
        self.assertEqual(self.words('resume_4096_blocks'),(4096,4096,64,64,4095,4094))
        self.assertEqual(self.row('resume_4096_blocks')['returned'],0)

    def test_fixture_bounds(self):
        for changes in (dict(blocks=0),dict(ppb=0),dict(bad=list(range(65))),dict(records={'0':dict(bad=[65536])})):
            with self.assertRaises(ValueError):contract(self.cases['active_true']|changes)

    def test_public_native_observations_match_all_fixtures(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-bbt.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(58,58))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['byte_range_sha256']),len(report['export_sha256'])),(6,6))


if __name__=='__main__':unittest.main()
