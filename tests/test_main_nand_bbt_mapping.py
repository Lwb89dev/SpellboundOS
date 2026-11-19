import copy
import json
from pathlib import Path
import re
import unittest

from analysis_scripts import main_nand_bbt_mapping as mapping


class MainNandBbtMappingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name'].removeprefix('main_bbt_map_'):c for c in mapping.native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][-1]
    def actions(self,name):return self.cases[name]['expected']['actions']

    def test_recovered_table_drives_block_skip_arithmetic(self):
        for name,wanted in (('block_0',0),('block_1',2),('block_3',5),('block_1018',1021)):
            self.assertEqual((self.row(name)['returned'],self.row(name)['map_output']),(0,wanted))

    def test_page_remapping_preserves_intra_block_offset(self):
        for name,wanted in (('page_0',0),('page_65',129),('page_193',321),('page_65215',65407)):
            self.assertEqual((self.row(name)['returned'],self.row(name)['map_output']),(0,wanted))

    def test_reserved_block_and_page_fail_without_output_write(self):
        for name in ('block_1019','page_65216'):
            self.assertEqual((self.row(name)['returned'],self.row(name)['map_output']),(0xffffffff,0xa5a5a5a5))

    def test_wrapping_block_input_can_map_to_zero(self):
        self.assertEqual((self.row('block_4294967295')['returned'],self.row('block_4294967295')['map_output']),(0,0))

    def test_large_page_input_fails_reserved_boundary(self):
        self.assertEqual(self.row('page_4294967295')['returned'],0xffffffff)
        self.assertEqual(self.row('page_4294967295')['map_output'],0xa5a5a5a5)

    def test_inactive_table_bypasses_remap_and_boundary_checks(self):
        for name in ('inactive_block','inactive_page'):
            r=self.row(name);self.assertEqual((r['returned'],r['map_output'],r['bbt_resume_return'],r['main_bbt_magic']),(0,0xffffffff,1,0))
        self.assertNotIn('main_remap_block:67108863',self.actions('inactive_page'))

    def test_empty_active_table_still_rejects_backup_boundary(self):
        self.assertEqual(self.row('empty_reserved')['returned'],0xffffffff)
        self.assertEqual(self.row('empty_reserved')['main_bbt_magic'],mapping.recovery.policy.MAGIC)

    def test_duplicate_entries_consume_two_slots(self):
        self.assertEqual(self.row('duplicate_entries')['map_output'],3)

    def test_unsorted_entries_can_stop_before_later_bad_block(self):
        self.assertEqual(self.row('unsorted_entries')['map_output'],1)
        self.assertEqual(self.row('unsorted_entries')['returned'],0)

    def test_repair_failure_leaves_active_mapping_usable(self):
        r=self.row('repair_error_active');self.assertEqual((r['bbt_resume_return'],r['returned'],r['map_output']),(0,0,5))
        self.assertIn('log:bbt_repair_failed',self.actions('repair_error_active'))

    def test_tail_pair_selection_changes_remapping_limit(self):
        self.assertEqual(self.row('last_pair_boundary')['returned'],0xffffffff)
        self.assertEqual(int.from_bytes(bytes.fromhex(self.row('last_pair_boundary')['bbt_state_hex'])[160:164],'little'),1008)

    def test_error_retains_last_successful_output_in_sequence(self):
        rows=self.cases['error_retains_previous_output']['expected']['rows'][-4:]
        self.assertEqual([r['map_output'] for r in rows],[5,5,129,129])
        self.assertEqual([r['returned'] for r in rows],[0,0xffffffff,0,0xffffffff])

    def test_mapping_preserves_recovered_record_and_uid_bytes(self):
        for case in self.cases.values():
            rows=case['expected']['rows'];self.assertTrue(all(r['bbt_state_hex']==rows[0]['bbt_state_hex'] for r in rows))
            self.assertTrue(all(r['aux_uid_sha256']==rows[0]['aux_uid_sha256'] for r in rows))

    def test_scope_rejects_null_output_and_non_word_input(self):
        c=self.cases['block_1']
        for field,value in (('output',False),('offset',-1),('offset',0x100000000)):
            bad=copy.deepcopy(c);bad['operations'][-1][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):mapping.contract(bad)

    def test_contract_does_not_mutate_recovered_state_or_configuration(self):
        c=self.cases['repair_error_active'];before=copy.deepcopy(c);mapping.contract(c);self.assertEqual(c,before)

    def test_native_evidence_matches_policy_and_fixed_main_guards(self):
        e=json.loads(Path('analysis/main-nand-bbt-mapping.json').read_bytes());r=e['native_validation']
        self.assertIs(r['hardware_execution'],False);self.assertEqual(r['case_count'],20);self.assertEqual(len(r['cases']),20)
        for row in r['cases']:
            self.assertEqual(row['observed'],self.cases[row['name'].removeprefix('main_bbt_map_')]['expected']);self.assertTrue(0<row['steps']<=mapping.recovery.uid.aux.joined.BOUND)
        previous=json.loads(Path('analysis/main-nand-bbt.json').read_bytes())
        self.assertTrue(previous['byte_range_sha256'].items()<=e['byte_range_sha256'].items());self.assertEqual(previous['data_range_sha256'],e['data_range_sha256'])
        text=Path('analysis_scripts/ValidateMainNandBbtMapping.java').read_text();cfg=json.loads(json.loads(re.search(r'MAP_CONFIG=(".*?");',text).group(1)))
        for g in cfg['guards']:self.assertEqual(e['byte_range_sha256'][f'{g["address"]:08x}_{g["size"]:x}'],g['sha256'])
        self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(59,67))


if __name__=='__main__':unittest.main()
