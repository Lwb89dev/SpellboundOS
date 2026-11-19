import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from analysis_scripts import main_nand_bbt as bbt


class MainNandBbtTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name'].removeprefix('main_bbt_'):c for c in bbt.native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][-1]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def state(self,name):return bytes.fromhex(self.row(name)['bbt_state_hex'])
    def word(self,name,offset):return struct.unpack_from('<I',self.state(name),offset)[0]

    def test_primary_record_is_published_with_original_geometry(self):
        r=self.row('primary');self.assertEqual((r['returned'],r['bbt_resume_return'],r['main_bbt_magic']),(0,0,bbt.policy.MAGIC))
        self.assertEqual(self.state('primary')[:140],bbt.policy.record(dict(bad=[1,3,7])))
        self.assertEqual(struct.unpack_from('<6I',self.state('primary'),140),(1024,2048,64,16,1023,1022))

    def test_crc_executes_over_only_declared_entry_bytes(self):
        payload=struct.pack('<3H',1,3,7);self.assertIn('bbt_crc:6:'+hashlib.sha256(payload).hexdigest(),self.actions('primary'))
        self.assertEqual(self.row('primary')['bbt_reads'],1)

    def test_empty_record_uses_zero_length_crc_and_remains_active(self):
        self.assertIn('bbt_crc:0:'+hashlib.sha256(b'').hexdigest(),self.actions('empty_table'))
        self.assertEqual(self.word('empty_table',4),0);self.assertEqual(self.word('empty_table',0),bbt.policy.MAGIC)

    def test_reserved_count_limit_is_fourteen_for_original_first_chip(self):
        self.assertEqual(self.word('count_limit',4),14);self.assertEqual(self.word('count_limit',0),bbt.policy.MAGIC)
        self.assertEqual(sum(a.startswith('bbt_format:') for a in self.actions('count_limit')),14)

    def test_excess_count_is_rejected_before_crc_or_publication(self):
        a=self.actions('count_exceeds');self.assertIn('log:bbt_count_error',a);self.assertFalse(any(x.startswith('bbt_crc:') for x in a))
        self.assertNotIn('bbt_publish:140',a);self.assertEqual(self.row('count_exceeds')['bbt_resume_return'],1)

    def test_bad_primary_crc_falls_back_to_backup_and_repair(self):
        a=self.actions('primary_bad_crc');self.assertIn('log:bbt_crc_error',a);self.assertIn('bbt_erase:1023:1:0:0',a)
        self.assertEqual((self.row('primary_bad_crc')['bbt_resume_return'],self.word('primary_bad_crc',0)),(0,bbt.policy.MAGIC))

    def test_primary_read_error_does_not_publish_failed_backing(self):
        a=self.actions('primary_read_error');self.assertIn('bbt_read:65472:140:0:-9',a)
        self.assertEqual(a.count('bbt_publish:140'),1);self.assertEqual(self.row('primary_read_error')['bbt_reads'],3)

    def test_backup_repair_temporarily_disables_ram_magic_during_io(self):
        a=self.actions('backup_repair');self.assertIn('bbt_read:65408:140:0:0',a);self.assertIn('bbt_erase:1023:1:0:0',a)
        write=next(x for x in a if x.startswith('bbt_write:'));self.assertTrue(write.startswith('bbt_write:65472:140:0:'))
        self.assertEqual(self.word('backup_repair',0),bbt.policy.MAGIC)

    def test_each_repair_error_restores_active_ram_table_and_returns_zero(self):
        for name in ('reread_error','erase_error','write_error'):
            r=self.row(name);self.assertEqual((r['returned'],r['bbt_resume_return'],r['main_bbt_magic']),(0,0,bbt.policy.MAGIC))
            self.assertIn('log:bbt_repair_failed',self.actions(name));self.assertEqual(self.state(name)[:140],bbt.policy.record(dict(bad=[1,3,7])))

    def test_reread_error_skips_erase_and_write_callbacks(self):
        a=self.actions('reread_error');self.assertFalse(any(x.startswith(('bbt_erase:','bbt_write:')) for x in a))
        self.assertEqual(self.row('reread_error')['bbt_reads'],3)

    def test_no_valid_record_return_one_is_ignored_by_outer_probe(self):
        r=self.row('both_invalid');self.assertEqual((r['returned'],r['bbt_resume_return'],r['main_bbt_magic']),(0,1,0))
        self.assertEqual(r['main_cache'],bbt.base.OBJECT);self.assertEqual(bytes.fromhex(r['output_hex'])[12],0)
        self.assertEqual(bytes.fromhex(r['export_hex'])[0],16);self.assertEqual(r['probe_guard_pages'],512)

    def test_unsorted_and_duplicate_entries_are_accepted_when_crc_matches(self):
        for name,bad in (('unsorted',[7,1]),('duplicates',[1,1])):
            self.assertEqual(self.state(name)[:140],bbt.policy.record(dict(bad=bad)));self.assertEqual(self.row(name)['bbt_resume_return'],0)

    def test_bad_tail_and_last_reserved_pair_select_authored_good_blocks(self):
        self.assertEqual(struct.unpack_from('<2I',self.state('skip_bad_tail'),156),(1022,1020))
        self.assertEqual(struct.unpack_from('<2I',self.state('last_reserved_pair'),156),(1009,1008))

    def test_no_good_block_assertion_stops_before_registration_and_export(self):
        r=self.row('no_good');self.assertIsNone(r['returned']);self.assertIsNone(r['bbt_resume_return'])
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x70a30e6c,line=196));self.assertEqual(r['export_calls'],0)
        self.assertFalse(r['main_heap_live']);self.assertTrue(r['aux_uid_completed'])

    def test_one_good_block_retains_primary_but_stops_before_normal_return(self):
        r=self.row('one_good');self.assertEqual(r['stopped']['line'],196);self.assertEqual(self.word('one_good',156),1023)
        self.assertEqual(r['bbt_reads'],0);self.assertEqual(r['probe_guard_pages'],0)

    def test_adjacent_bbt_and_uid_regions_keep_uid_source_intact(self):
        self.assertEqual(bbt.BBT+164,bbt.uid.aux.UID)
        expected=hashlib.sha256(bbt.uid.aux.policy.uid_bytes(0,True)+b'\xa5'*96).hexdigest()
        for name,c in self.cases.items():
            if name=='stale_uid':continue
            self.assertTrue(all(r['aux_uid_sha256']==expected for r in c['expected']['rows']))

    def test_valid_bbt_does_not_make_retained_uid_fresh(self):
        r=self.row('stale_uid');self.assertEqual((r['bbt_resume_return'],r['main_bbt_magic'],r['aux_uid_length']),(0,bbt.policy.MAGIC,17))
        self.assertEqual(bytes.fromhex(r['export_hex']),b'\x11'+b'\xa5'*128);self.assertEqual(r['returned'],0)

    def test_scope_rejects_supplied_bbt_status_and_out_of_range_records(self):
        c=self.cases['primary']
        for change in (dict(native_main_bbt=False),dict(probe_bbt_return=1),dict(bbt_good_blocks=[1007]),dict(bbt_write_status=-101),dict(bbt_record_hex={})):
            with self.subTest(change=change),self.assertRaises(ValueError):bbt.contract(c|change)
        bad=copy.deepcopy(c);bad['bbt_records']['1023']['bad']=list(range(65))
        with self.assertRaises(ValueError):bbt.contract(bad)

    def test_contract_does_not_mutate_initial_magic_or_records(self):
        for name in ('primary','both_invalid','no_good'):
            c=self.cases[name];before=copy.deepcopy(c);bbt.contract(c);self.assertEqual(c,before)

    def test_native_evidence_matches_models_and_original_main_crc_guards(self):
        e=json.loads(Path('analysis/main-nand-bbt.json').read_bytes());report=e['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:
            self.assertEqual(row['observed'],self.cases[row['name'].removeprefix('main_bbt_')]['expected']);self.assertTrue(0<row['steps']<=bbt.uid.aux.joined.BOUND)
        previous=json.loads(Path('analysis/main-nand-uid-export.json').read_bytes())
        for key in ('byte_range_sha256','data_range_sha256'):
            self.assertTrue(previous[key].items()<=e[key].items())
        text=Path('analysis_scripts/ValidateMainNandBbt.java').read_text();cfg=json.loads(json.loads(re.search(r'BBT_CONFIG=(".*?");',text).group(1)))
        for key,guards in (('byte_range_sha256',cfg['guards']),('data_range_sha256',cfg['data_guards'])):
            for g in guards:self.assertEqual(e[key][f'{g["address"]:08x}_{g["size"]:x}'],g['sha256'])
        self.assertEqual((len(e['byte_range_sha256']),len(e['data_range_sha256'])),(57,67))


if __name__=='__main__':unittest.main()
