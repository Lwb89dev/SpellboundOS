import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.eftl_readback_stack import contract,native_vectors
from analysis_scripts.eftl_mutation_stack import native_vectors as mutation_vectors


class EftlReadbackStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def mapping(self,name):return struct.unpack('<8H',bytes.fromhex(self.row(name)['mapping_hex']))

    def test_success_runs_original_program_load_cache_and_checksum(self):
        name='readback_fast';self.result(name,32)
        self.assertIn('readback_checksum:00004545',self.actions(name));self.assertEqual(self.row(name)['rx_bytes'],66)

    def test_wrong_logical_block_is_accepted_when_tag_and_checksum_match(self):
        name='readback_wrong_logical';self.result(name,32)
        self.assertIn('readback_checksum:0700454c',self.actions(name))
        self.assertEqual(self.mapping(name)[0],3)

    def test_bad_tag_short_circuits_checksum(self):
        name='readback_bad_tag';self.result(name,-2)
        self.assertFalse(any(a.startswith('readback_checksum:') for a in self.actions(name)))
        self.assertIn('log:eftl_readback_check_failed',self.actions(name))

    def test_bad_crc_executes_actual_checksum_and_returns_failure(self):
        name='readback_bad_crc';self.result(name,-2)
        self.assertIn('log:checksum_error',self.actions(name));self.assertEqual(self.actions(name)[-1],'log:storage_program_error')

    def test_private_dma_readback_exposes_stale_transmit_buffer_fixture(self):
        name='readback_private_stale';self.result(name,-2)
        self.assertIn('copy_to_bounce:2112',self.actions(name));self.assertIn('copy_from_bounce:64',self.actions(name))
        self.assertEqual(self.row(name)['rx_bytes'],2);self.assertEqual(self.row(name)['driver_calls'],2)

    def test_generic_irq_readback_uses_real_callbacks_and_direct_data(self):
        self.result('readback_irq',32);self.assertEqual(self.row('readback_irq')['driver_calls'],2)
        self.assertEqual(self.row('readback_irq')['rx_bytes'],66)

    def test_failed_check_leaves_new_block_unpublished_and_flag_advanced(self):
        name='readback_allocate_bad_crc';self.result(name,-2)
        self.assertEqual(self.mapping(name)[0],65535);self.assertEqual(bytes.fromhex(self.row(name)['write_flags_hex'])[5],2)
        self.assertEqual(self.mapping('readback_allocate')[0],5)

    def test_readback_disabled_reproduces_previous_program_capture(self):
        original=next(c for c in mutation_vectors()['cases'] if c['name']=='program_existing')['expected']
        self.assertEqual(self.cases['readback_disabled']['expected'],original)

    def test_rewrite_and_logical_erase_propagate_check_results(self):
        self.result('readback_rewrite',32);self.result('readback_erase',32);self.result('readback_erase_bad_crc',-14)
        self.assertEqual(self.actions('readback_erase_bad_crc')[-1],'log:storage_erase_error')

    def test_cache_assertion_stops_before_checksum(self):
        name='readback_cache_assertion';self.assertIsNone(self.row(name)['returned'])
        self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=0x80c37b7c,line=0x12a))
        self.assertFalse(any(a.startswith('readback_checksum:') for a in self.actions(name)))

    def test_contract_rejects_bad_readback_backing(self):
        base=self.cases['readback_fast']
        for change in (dict(cache_payloads=[]),dict(cache_payloads=['00']),dict(native_readback=False)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_all_regenerated_fixtures(self):
        report=json.loads(Path('analysis/eftl-readback-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases));self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:self.assertEqual(row['observed'],self.cases[row['name']]['expected'])


if __name__=='__main__':unittest.main()
