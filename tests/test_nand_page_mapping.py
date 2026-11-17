import hashlib
import json
from pathlib import Path
import unittest

from analysis_scripts.nand_page_mapping import contract,native_vectors


class NandPageMappingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def actions(self,name):return self.result(name)['actions']
    def status(self,name):
        value=self.row(name)['returned'];return value-(1<<32) if value&(1<<31) else value

    def test_all_operations_succeed_with_actual_remappers(self):
        for mode in ('read','write','copy_page','copy_oob','erase'):
            self.assertEqual(self.status(mode+'_mapped'),0)
            self.assertFalse(any(a.startswith('remap_page:') or a.startswith('remap_block:') for a in self.actions(mode+'_mapped')))

    def test_page_read_loads_mapped_physical_page(self):
        actions=self.actions('read_mapped')
        self.assertEqual(actions[:3],['native_remap_page:600','native_remap_block:9','load:792:0'])

    def test_program_uses_same_mapped_page(self):self.assertIn('program:792:0',self.actions('write_mapped'))

    def test_copy_maps_source_and_destination_separately(self):
        for mode in ('copy_page','copy_oob'):
            actions=self.actions(mode+'_mapped')
            self.assertEqual(actions[:4],['native_remap_page:600','native_remap_block:9','native_remap_page:700','native_remap_block:10'])
            self.assertIn('load:792:0',actions);self.assertIn('program:892:0',actions)

    def test_block_erase_uses_mapped_block(self):
        self.assertEqual(self.actions('erase_mapped')[0],'native_remap_block:12')
        self.assertIn('erase_command:15:0',self.actions('erase_mapped'))

    def test_inactive_bbt_preserves_caller_addresses(self):
        self.assertIn('load:600:0',self.actions('read_inactive'))
        self.assertIn('program:600:0',self.actions('write_inactive'))
        self.assertIn('program:700:0',self.actions('copy_page_inactive'))
        self.assertIn('erase_command:12:0',self.actions('erase_inactive'))
        self.assertNotIn('native_remap_block:9',self.actions('read_inactive'))

    def test_last_usable_mapped_page_can_be_loaded(self):
        self.assertEqual(self.status('read_last_usable'),0)
        self.assertIn('load:65407:0',self.actions('read_last_usable'))

    def test_read_reserved_boundary_returns_remap_error(self):
        self.assertEqual(self.status('read_reserved_limit'),-150)
        self.assertFalse(any(a.startswith('load:') for a in self.actions('read_reserved_limit')))

    def test_copy_rejects_reserved_destination_before_source_load(self):
        self.assertEqual(self.status('copy_dest_reserved_limit'),-150)
        self.assertFalse(any(a.startswith('load:') for a in self.actions('copy_dest_reserved_limit')))

    def test_write_guard_uses_mapped_first_mib_boundary(self):
        self.assertEqual(self.status('write_below_mapped_guard'),-250)
        self.assertEqual(self.status('write_at_mapped_guard'),0)
        self.assertIn('program:512:0',self.actions('write_at_mapped_guard'))

    def test_erase_guard_uses_mapped_block_boundary(self):
        self.assertEqual(self.status('erase_below_mapped_guard'),-250)
        self.assertEqual(self.status('erase_at_mapped_guard'),0)
        self.assertIn('erase_command:8:0',self.actions('erase_at_mapped_guard'))

    def test_reserved_block_erase_fails_before_write_enable(self):
        self.assertEqual(self.status('erase_reserved_limit'),-151)
        self.assertNotIn('enable:0',self.actions('erase_reserved_limit'))

    def test_unsorted_and_duplicate_tables_affect_actual_load_address(self):
        self.assertIn('load:64:0',self.actions('read_unsorted_table'))
        self.assertIn('load:192:0',self.actions('read_duplicate_table'))

    def test_connected_mapping_retains_busy_timeout_read_behavior(self):
        self.assertEqual(self.status('read_mapped_busy_timeout'),0)
        self.assertEqual(self.row('read_mapped_busy_timeout')['feature_reads'],2000)
        self.assertIn('load:792:0',self.actions('read_mapped_busy_timeout'))
        self.assertEqual(self.actions('read_mapped_busy_timeout')[-2:],['log:busy_timeout','cache_read_direct:16:64:0'])

    def test_connected_read_delivers_only_authored_cache_bytes(self):
        expected=bytes((0x5a+i*7)&255 for i in range(64))+bytes((i*3+1)&255 for i in range(64,512))
        self.assertEqual(self.row('read_mapped')['buffer_sha256'],hashlib.sha256(expected).hexdigest())

    def test_fixture_bounds(self):
        c=self.cases['read_mapped']
        with self.assertRaises(ValueError):contract(c|dict(bbt_hex='00'))
        with self.assertRaises(ValueError):contract(c|dict(size=513))

    def test_public_native_observations_match(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-page-mapping.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(21,21))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['byte_range_sha256']),len(report['export_sha256'])),(10,10))


if __name__=='__main__':unittest.main()
