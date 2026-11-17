import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.eftl_mutation_stack import contract,native_vectors


class EftlMutationStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def flags(self,name):return bytes.fromhex(self.row(name)['write_flags_hex'])
    def mapping(self,name):return struct.unpack('<8H',bytes.fromhex(self.row(name)['mapping_hex']))
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]
    def scratch(self,n=32,logical=0,erase=False):
        data=bytearray(b'\xff'*2112)
        if not erase:data[:n]=bytes((i*3+1)&255 for i in range(n))
        data[2068:2072]=struct.pack('<H',logical)+bytes([69,(logical%256+logical//256+69)&255])
        return data

    def test_partial_page_is_padded_and_original_oob_metadata_is_packed(self):
        name='program_existing';self.result(name,32)
        self.assertEqual(self.row(name)['scratch_sha256'],hashlib.sha256(self.scratch()).hexdigest())
        self.assertIn('write_fill:32:2016',self.actions(name));self.assertIn('write_fill:2048:64',self.actions(name))

    def test_normal_write_connects_full_2112_byte_private_dma(self):
        name='program_existing';self.assertIn('driver_program:705:0:2112',self.actions(name))
        self.assertIn('copy_to_bounce:2112',self.actions(name));self.assertEqual(self.row(name)['tx_hex'],'')
        self.assertEqual(self.row(name)['bounce_sha256'],self.row(name)['scratch_sha256'])
        self.assertEqual(self.opcodes(name),[6,0x32,0x10,15])

    def test_fast_and_irq_writes_capture_all_page_and_oob_bytes_in_fifo(self):
        for name in ('program_fast','program_irq'):
            self.result(name,32);self.assertEqual(bytes.fromhex(self.row(name)['tx_hex']),self.scratch())
            self.assertNotIn('copy_to_bounce:2112',self.actions(name))

    def test_envbak_and_recovery_logical_metadata_uses_the_original_record_offset(self):
        for name,logical in (('program_envbak',2),('program_recovery',4)):
            self.result(name,32);self.assertEqual(self.row(name)['scratch_sha256'],hashlib.sha256(self.scratch(logical=logical)).hexdigest())

    def test_64_byte_source_still_programs_one_complete_page(self):
        self.result('program_64',64);self.assertEqual(self.row('program_64')['scratch_sha256'],hashlib.sha256(self.scratch(n=64)).hexdigest())

    def test_program_alignment_is_checked_even_for_zero_length(self):
        self.result('program_zero',0);self.assertEqual(self.opcodes('program_zero'),[])
        for name in ('program_unaligned','program_zero_unaligned','program_end_clamp_unaligned'):
            self.result(name,-1);self.assertIn('log:eftl_write_alignment',self.actions(name));self.assertEqual(self.opcodes(name),[])

    def test_sequential_guard_runs_after_scratch_preparation_before_nand(self):
        name='program_sequence_error';self.result(name,-2);self.assertEqual(self.flags(name)[3],6)
        self.assertEqual(self.opcodes(name),[]);self.assertIn('log:eftl_sequence_error',self.actions(name))
        self.assertEqual(self.row(name)['scratch_sha256'],hashlib.sha256(self.scratch()).hexdigest())

    def test_first_page_erases_existing_mapped_block_before_programming(self):
        name='program_first_page';self.result(name,32)
        self.assertEqual(self.opcodes(name),[6,0xd8,15,6,0x32,0x10,15]);self.assertEqual(self.flags(name)[3],2)
        self.assertEqual(self.mapping(name)[0],3)

    def test_allocator_selects_free_block_and_publishes_mapping_after_program(self):
        name='program_allocate_free';self.result(name,32);self.assertEqual(self.mapping(name)[0],5)
        self.assertEqual(self.flags(name)[5],2);self.assertIn('w:0:4:1024',self.actions(name))
        self.assertEqual(self.opcodes(name),[6,0xd8,15,6,0x32,0x10,15])

    def test_no_free_block_returns_minus_two_without_mutating_mapping_or_nand(self):
        name='program_no_free';self.result(name,-2);self.assertEqual(self.mapping(name),(65535,)*8)
        self.assertEqual(self.flags(name),bytes([1]*8));self.assertEqual(self.opcodes(name),[])
        self.assertIn('log:eftl_map_full',self.actions(name));self.assertNotIn('write_fill:2048:64',self.actions(name))

    def test_logical_erase_erases_and_programs_ff_page_with_live_oob(self):
        name='erase_block';self.result(name,32)
        self.assertEqual(self.row(name)['scratch_sha256'],hashlib.sha256(self.scratch(erase=True)).hexdigest())
        self.assertEqual(self.opcodes(name),[6,0xd8,15,6,0x32,0x10,15])
        self.assertIn('erase_remainder:0:0',self.actions(name))

    def test_logical_erase_crosses_two_blocks_and_returns_requested_byte_count(self):
        name='erase_two_blocks';self.result(name,131104)
        self.assertEqual(self.opcodes(name).count(0xd8),2);self.assertEqual(self.opcodes(name).count(0x10),2)
        self.assertEqual(self.row(name)['scratch_sha256'],hashlib.sha256(self.scratch(logical=1,erase=True)).hexdigest())

    def test_erase_alignment_and_failure_translation(self):
        self.result('erase_zero',0)
        for name in ('erase_unaligned','erase_zero_unaligned'):self.result(name,-1)
        self.result('erase_no_free',-14);self.assertEqual(self.opcodes('erase_no_free'),[])
        self.assertEqual(self.actions('erase_no_free')[-1],'log:storage_erase_error')

    def test_rewrite_aliases_program_without_added_erase(self):
        self.result('rewrite_existing',32)
        self.assertEqual(self.row('rewrite_existing'),self.row('program_existing'))
        self.assertEqual(self.actions('rewrite_existing'),self.actions('program_existing'))
        self.assertNotIn(0xd8,self.opcodes('rewrite_existing'))

    def test_missing_rewrite_callback_does_not_enter_eftl(self):
        name='rewrite_missing';self.result(name,-1);self.assertEqual(self.row(name)['storage_backend_calls'],0)
        self.assertEqual(self.opcodes(name),[]);self.assertIn('log:storage_rewrite_missing',self.actions(name))

    def test_upper_input_assertions_keep_original_owner_and_line(self):
        cases=(('program_null',0x80c3c318,245),('erase_null',0x80c3c2f0,281),('rewrite_null',0x80c3c2c0,317),('program_null_input',0x80c3c318,246),('rewrite_null_input',0x80c3c2c0,318))
        for name,owner,line in cases:self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))

    def test_flags_advance_before_lock_or_hal_failure_without_mapping_publication(self):
        for name in ('program_acquire_assertion','program_release_assertion','program_fifo_assertion','program_dma_assertion'):
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.flags(name)[3],4);self.assertEqual(self.mapping(name)[0],3)
        self.assertEqual(self.opcodes('program_acquire_assertion'),[])
        self.assertEqual(self.row('program_dma_assertion')['stopped'],dict(kind='assertion',owner=0x80c37b98,line=0x17b))

    def test_caller_input_remains_unchanged_for_every_mutation_fixture(self):
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for name in self.cases:self.assertEqual(self.row(name)['buffer_sha256'],expected)

    def test_contract_excludes_unbounded_and_deferred_repair_paths(self):
        base=self.cases['program_existing']
        for change in (dict(storage_size=65),dict(responses=[8]),dict(driver_state='root_missing'),dict(write_flags=[]),dict(fifo_iteration_bound=0),dict(native_storage=False),dict(ecc_total=2)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_every_regenerated_fixture(self):
        report=json.loads(Path('analysis/eftl-mutation-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:self.assertEqual(row['observed'],self.cases[row['name']]['expected'])


if __name__=='__main__':unittest.main()
