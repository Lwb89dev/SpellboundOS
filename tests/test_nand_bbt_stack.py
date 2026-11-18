import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_bbt_stack import bbt,contract,native_vectors


class NandBbtStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def word(self,name,at):return struct.unpack_from('<I',bytes.fromhex(self.row(name)['bbt_state_hex']),at)[0]
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def commands(self,name):
        out=[];address=count=0
        for a in self.actions(name):
            if a.startswith('w:0:4:'):address=int(a.split(':')[-1])
            elif a.startswith('w:8:4:'):count=int(a.split(':')[-1])
            elif a.startswith('w:12:4:'):out.append((int(a.split(':')[-1])>>24,address,count))
        return out

    def test_primary_recovery_publishes_record_and_preserves_geometry(self):
        name='bbt_primary';self.result(name,0);self.assertEqual(self.word(name,0),bbt.MAGIC)
        self.assertEqual(self.word(name,4),3);self.assertEqual((self.word(name,156),self.word(name,160)),(1023,1022))
        self.assertEqual(self.row(name)['bbt_resume_result'],0)
        self.assertIn('bbt_crc:6:'+hashlib.sha256(struct.pack('<3H',1,3,7)).hexdigest(),self.actions(name))

    def test_recovered_table_drives_actual_followup_page_address_and_buffer(self):
        name='bbt_primary_then_read';self.result(name,0);self.assertEqual(self.row(name)['bbt_follow_return'],0)
        self.assertEqual([a for op,a,n in self.commands(name) if op==0x13][-1],792)
        expected=bytes(range(32))+bytes((i*3+1)&255 for i in range(32,512))
        self.assertEqual(self.row(name)['buffer_sha256'],hashlib.sha256(expected).hexdigest())

    def test_backup_repair_programs_exact_record_to_unmapped_primary(self):
        name='bbt_backup_repair';self.result(name,0);record=bbt.record(dict(bad=[1,3,7]))
        self.assertEqual(bytes.fromhex(self.row(name)['tx_hex']),record)
        self.assertIn((0xd8,1023*64,0),self.commands(name));self.assertIn((0x10,1023*64,0),self.commands(name))
        self.assertEqual(self.word(name,0),bbt.MAGIC);self.assertNotIn('log:bbt_repair_failed',self.actions(name))

    def test_backup_reread_error_skips_erase_but_restores_ram_mapping(self):
        name='bbt_backup_reread_error';self.result(name,0);self.assertEqual(self.word(name,0),bbt.MAGIC)
        self.assertEqual(self.row(name)['bbt_follow_return'],0);self.assertIn('log:bbt_repair_failed',self.actions(name))
        self.assertFalse(any(op==0xd8 for op,a,n in self.commands(name)))

    def test_erase_and_program_errors_return_zero_with_active_backup_table(self):
        for name in ('bbt_backup_erase_error','bbt_backup_program_error'):
            self.result(name,0);self.assertEqual(self.word(name,0),bbt.MAGIC)
            self.assertEqual(self.row(name)['bbt_follow_return'],0);self.assertIn('log:bbt_repair_failed',self.actions(name))
        self.assertEqual(self.row('bbt_backup_erase_error')['tx_hex'],'')
        self.assertEqual(len(bytes.fromhex(self.row('bbt_backup_program_error')['tx_hex'])),140)

    def test_no_valid_copy_returns_one_and_followup_read_uses_inactive_passthrough(self):
        name='bbt_both_invalid';self.result(name,1);self.assertEqual(self.word(name,0),0)
        self.assertEqual(self.row(name)['bbt_follow_return'],0)
        self.assertEqual([a for op,a,n in self.commands(name) if op==0x13][-1],600)
        self.assertIn('log:bbt_no_bbt',self.actions(name))

    def test_primary_crc_or_ecc_error_falls_back_to_backup(self):
        for name in ('bbt_primary_crc_bad','bbt_primary_ecc_bad'):
            self.result(name,0);self.assertEqual(self.word(name,4),3)
            self.assertEqual(bytes.fromhex(self.row(name)['bbt_state_hex'])[12:18],struct.pack('<3H',1,3,7))
        self.assertIn('log:bbt_crc_error',self.actions('bbt_primary_crc_bad'))
        self.assertIn('log:page_result',self.actions('bbt_primary_ecc_bad'))

    def test_bad_tail_selection_records_duplicate_initial_query(self):
        name='bbt_skip_bad_tail';self.result(name,0)
        self.assertEqual((self.word(name,156),self.word(name,160)),(1022,1020))
        self.assertEqual(self.actions(name).count('bbt_bad:1023'),2)

    def test_missing_primary_or_backup_stops_at_original_assertion(self):
        for name in ('bbt_no_good_blocks','bbt_only_one_good'):
            r=self.row(name);self.assertIsNone(r['returned']);self.assertIsNone(r['bbt_resume_result'])
            self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c3d3b0,line=0xac))
            self.assertEqual(self.word(name,0),0);self.assertEqual(self.word(name,152),16)

    def test_record_count_limit_is_checked_before_crc(self):
        self.result('bbt_count_limit',1);self.assertEqual(self.word('bbt_count_limit',4),14)
        name='bbt_count_exceeds';self.result(name,0);self.assertIn('log:bbt_count_error',self.actions(name))
        self.assertFalse(any(a.startswith('bbt_crc:') for a in self.actions(name)))

    def test_bad_crc_does_not_publish_record(self):
        name='bbt_verify_bad_crc';self.result(name,0);self.assertEqual(self.word(name,0),0)
        self.assertIn('log:bbt_crc_error',self.actions(name));self.assertNotIn('bbt_publish:140',self.actions(name))

    def test_unsorted_and_duplicate_records_feed_distinct_actual_mappings(self):
        for name,page in (('bbt_unsorted',64),('bbt_duplicates',192)):
            self.result(name,0);self.assertEqual(self.row(name)['bbt_follow_return'],0)
            self.assertEqual([a for op,a,n in self.commands(name) if op==0x13][-1],page)

    def test_direct_verification_with_active_mapping_can_fail_before_flash_read(self):
        name='bbt_verify_active_rejected';self.result(name,0)
        self.assertEqual(self.row(name)['bbt_state_hex'],self.cases[name]['bbt_hex'])
        self.assertFalse(any(op==0x13 for op,a,n in self.commands(name)))
        self.assertNotIn('log:bbt_record',self.actions(name))

    def test_followup_reserved_page_is_rejected_without_more_nand_commands(self):
        name='bbt_follow_reserved';self.result(name,0);self.assertEqual(self.row(name)['bbt_follow_return'],(-150)&0xffffffff)
        self.assertEqual(self.commands(name),self.commands('bbt_primary'))

    def test_contract_rejects_unsupported_geometry_tail_and_status_inputs(self):
        base=self.cases['bbt_primary']
        for change in (dict(bbt_good_blocks=[8]),dict(bbt_follow_page=65536),dict(responses=[1]),dict(bbt_verify_block=0),dict(bbt_hex='00'*164)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_every_regenerated_case(self):
        report=json.loads(Path('analysis/nand-bbt-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:self.assertEqual(row['observed'],self.cases[row['name']]['expected'])


if __name__=='__main__':unittest.main()
