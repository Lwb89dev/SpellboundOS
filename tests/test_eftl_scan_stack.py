import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.eftl_scan_stack import contract,native_vectors


class EftlScanStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def context(self,name):return bytes.fromhex(self.row(name)['eftl_context_hex'])
    def counters(self,name):return struct.unpack_from('<3H',self.context(name),56)
    def mapping(self,name):return struct.unpack('<8H',bytes.fromhex(self.row(name)['mapping_hex']))
    def flags(self,name):return bytes.fromhex(self.row(name)['write_flags_hex'])
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]

    def test_connected_scan_reconstructs_two_maps_from_full_oob_reads(self):
        name='scan_connected';self.result(name,0);self.assertEqual(self.mapping(name)[0],1);self.assertEqual(self.mapping(name)[2],0)
        self.assertEqual(self.counters(name),(0,2,0));self.assertEqual(self.flags(name)[:2],b'\x80\x80')
        self.assertEqual(self.opcodes(name).count(0x13),8);self.assertEqual(self.opcodes(name).count(0x6b),8)
        self.assertEqual(self.context(name)[4],165)

    def test_mixed_scan_classifies_free_used_and_reserved(self):
        name='scan_mixed';self.result(name,0);self.assertEqual(self.counters(name),(1,2,1))
        self.assertEqual(self.flags(name)[:4],bytes.fromhex('80fe80ff'));self.assertEqual(self.mapping(name)[0],2)

    def test_duplicate_keeps_first_copy_without_counting_second_as_free(self):
        name='scan_duplicate_old_first';self.result(name,0);self.assertEqual(self.mapping(name)[0],0)
        self.assertEqual(self.counters(name),(0,1,0));self.assertEqual(self.flags(name)[:2],b'\x80\xfe')

    def test_marked_old_block_is_skipped_but_scan_can_request_repair(self):
        name='scan_retired_old_skipped';self.result(name,1);self.assertEqual(self.mapping(name)[0],1)
        self.assertEqual(self.counters(name),(0,1,1));self.assertEqual(self.context(name)[4],0)
        self.assertNotIn(0xd8,self.opcodes(name))

    def test_marker_detection_stops_on_each_of_the_first_three_pages(self):
        for name,n in (('scan_retired_old_skipped',1),('scan_marker_second_page',2),('scan_marker_third_page',3)):
            self.assertIn('log:bad_mark_found',self.actions(name));self.assertEqual(self.flags(name)[0],255)
            if n>1:
                self.result(name,1);self.assertEqual(self.opcodes(name).count(0x13),n)
                self.assertEqual(self.row(name)['rx_bytes'],n*3)

    def test_second_marker_byte_alone_can_mark_the_block(self):
        name='scan_marker_second_byte';self.result(name,1);self.assertEqual(self.counters(name),(0,0,1))
        self.assertIn('r:256:1:255',self.actions(name));self.assertIn('r:256:1:254',self.actions(name))
        self.assertEqual(self.opcodes(name).count(0x13),1)

    def test_repair_mode_erases_positive_marker_result_before_oob(self):
        name='scan_repair_marked_block';self.result(name,0);self.assertEqual(self.mapping(name)[0],0)
        ops=self.opcodes(name);self.assertEqual(ops.count(0x6b),2);self.assertEqual(ops.count(0xd8),1)
        self.assertLess(ops.index(0xd8),len(ops)-1);self.assertEqual(self.counters(name),(0,1,0))

    def test_negative_marker_read_result_enters_erase_even_without_repair_mode(self):
        name='scan_marker_io_erased';self.result(name,0);self.assertEqual(self.mapping(name)[0],0)
        self.assertIn('log:bad_mark_error',self.actions(name));self.assertIn(0xd8,self.opcodes(name))
        self.assertNotIn('log:bad_mark_found',self.actions(name))

    def test_failed_erase_requests_first_scan_retry_but_repair_can_return_zero(self):
        for name,returned,marker in (('scan_marker_io_erase_failed',1,0),('scan_repair_erase_failed',0,165)):
            self.result(name,returned);self.assertEqual(self.context(name)[4],marker)
            self.assertEqual(self.counters(name),(0,0,1));self.assertEqual(self.flags(name)[0],255)
            self.assertEqual(self.mapping(name)[0],65535);self.assertIn('log:erase_result',self.actions(name))

    def test_oob_error_preserves_partial_mapping_and_pending_flag(self):
        self.result('scan_first_oob_io_error',-1);self.assertEqual(self.counters('scan_first_oob_io_error'),(0,0,0))
        name='scan_later_oob_io_error';self.result(name,-1);self.assertEqual(self.mapping(name)[2],0)
        self.assertEqual(self.counters(name),(0,1,0));self.assertEqual(self.flags(name)[:2],b'\x80\xfe')
        self.assertIn('log:scan_oob_error',self.actions(name))

    def test_wrong_tag_skips_checksum_while_bad_checksum_logs_and_counts_free(self):
        for name in ('scan_bad_tag','scan_bad_crc'):
            self.result(name,0);self.assertEqual(self.counters(name),(1,0,0))
        self.assertFalse(any(a.startswith('readback_checksum:') for a in self.actions('scan_bad_tag')))
        self.assertIn('log:checksum_error',self.actions('scan_bad_crc'))

    def test_generic_stale_dma_and_irq_direct_paths_have_distinct_evidence(self):
        name='scan_generic_stale';self.result(name,0);self.assertEqual(self.counters(name),(2,0,0))
        self.assertEqual(self.actions(name).count('copy_from_bounce:64'),2)
        name='scan_irq_direct';self.assertEqual(self.mapping(name),self.mapping('scan_connected'))
        self.assertEqual(self.counters(name),(0,2,0));self.assertNotIn('copy_from_bounce:64',self.actions(name))

    def test_segmented_oob_uses_original_copy_offsets_into_scan_stack_record(self):
        name='scan_segmented_oob';self.result(name,0);self.assertEqual(self.mapping(name)[2],0)
        self.assertIn('oob_copy:0:4:2',self.actions(name));self.assertIn('oob_copy:2:20:2',self.actions(name))

    def test_logical_index_beyond_declared_count_stays_within_explicit_backing(self):
        name='scan_logical_beyond_count';self.result(name,0)
        self.assertEqual(struct.unpack_from('<I',self.context(name),16)[0],1);self.assertEqual(self.mapping(name)[7],0)
        name='scan_existing_map';self.assertEqual(self.mapping(name)[0],7)
        self.assertEqual(self.counters(name),(0,0,0));self.assertEqual(self.flags(name)[0],254)

    def test_empty_scan_sets_marker_without_nand_access(self):
        name='scan_empty';self.result(name,0);self.assertEqual(self.context(name)[4],165)
        self.assertEqual(self.opcodes(name),[]);self.assertNotIn('chip_ioctl:10',self.actions(name))

    def test_oob_bus_assertion_stops_before_scan_error_cleanup(self):
        name='scan_oob_bus_assertion';r=self.row(name);self.assertIsNone(r['returned'])
        self.assertEqual(r['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=0x12a))
        self.assertEqual(self.flags(name)[0],254);self.assertNotIn('log:scan_oob_error',self.actions(name))

    def test_contract_rejects_unsupported_backing_geometry_and_statuses(self):
        base=self.cases['scan_connected']
        for change in (dict(scan_count=9),dict(scan_counters=[65536,0,0]),dict(cache_payloads=['00'*4]),dict(responses=[8]),dict(ecc_unit=0),dict(native_scan=False)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_all_cases_and_preserves_caller_buffer(self):
        report=json.loads(Path('analysis/eftl-scan-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        expected=hashlib.sha256(bytes((i*3+1)&255 for i in range(512))).hexdigest()
        for row in report['cases']:
            self.assertEqual(row['observed'],self.cases[row['name']]['expected']);self.assertEqual(row['observed']['rows'][0]['buffer_sha256'],expected)


if __name__=='__main__':unittest.main()
