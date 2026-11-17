import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_dispatch_stack import contract,native_vectors
from analysis_scripts.qspi_hal import BUFFER


class NandDispatchStackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def row(self,name):return self.cases[name]['expected']['rows'][0]
    def actions(self,name):return self.cases[name]['expected']['actions']
    def result(self,name,value):self.assertEqual(self.row(name)['returned'],value&0xffffffff)
    def opcodes(self,name):return [int(a.split(':')[-1])>>24 for a in self.actions(name) if a.startswith('w:12:4:')]
    def args(self,name):return struct.unpack('<4I',bytes.fromhex(self.row(name)['argument_hex'])[:16])

    def test_partition_rebases_before_original_bbt_mapping(self):
        actions=self.actions('partition_read_normal');self.assertIn('driver_read:519:16:64',actions)
        self.assertIn('native_remap_page:519',actions);self.assertIn('w:0:4:711',actions)

    def test_normal_context_locks_uses_private_dma_and_releases_after_transfer(self):
        name='partition_read_normal';actions=self.actions(name);self.result(name,0)
        self.assertLess(actions.index('mutex_acquire:0'),actions.index('native_remap_page:519'))
        self.assertLess(actions.index('copy_from_bounce:64'),actions.index('mutex_release:0'))
        self.assertEqual(self.row(name)['rx_bytes'],1)

    def test_irq_context_short_circuits_scheduler_and_skips_mutex(self):
        name='partition_read_irq';actions=self.actions(name);self.assertIn('irq_context:1',actions)
        self.assertFalse(any(a.startswith(('scheduler_context:','mutex_','copy_from_bounce:')) for a in actions))
        self.assertEqual(self.row(name)['rx_bytes'],65)

    def test_scheduler_context_uses_direct_transfer_without_mutex(self):
        actions=self.actions('partition_read_scheduler');self.assertIn('scheduler_context:1',actions)
        self.assertFalse(any(a.startswith(('mutex_','copy_from_bounce:')) for a in actions))

    def test_absent_mutex_retains_normal_private_transfer(self):
        actions=self.actions('partition_read_no_mutex');self.assertIn('copy_from_bounce:64',actions)
        self.assertFalse(any(a.startswith('mutex_') for a in actions))

    def test_tail_polling_and_dma_do_not_claim_identical_payload(self):
        original=bytearray((i*3+1)&255 for i in range(512));original[:13]=bytes((0x5a+i*7)&255 for i in range(13))
        self.assertEqual(self.row('partition_read_tail')['buffer_sha256'],hashlib.sha256(original).hexdigest())
        self.assertNotEqual(self.row('partition_read_normal')['buffer_sha256'],self.row('partition_read_irq')['buffer_sha256'])

    def test_partition_extent_does_not_bound_requested_page(self):
        self.result('partition_read_beyond_extent',0);self.assertIn('driver_read:10511:16:64',self.actions('partition_read_beyond_extent'))
        self.result('partition_read_derived_extent',0)

    def test_page_addition_wrap_reaches_lower_mapper(self):
        self.result('partition_read_wrapping_page',0);self.assertIn('native_remap_page:511',self.actions('partition_read_wrapping_page'))

    def test_invalid_partition_arguments_stop_before_context_services(self):
        for suffix in ('bad_base','bad_span','null_handle','null_output'):
            name='partition_read_'+suffix;self.result(name,-10);self.assertEqual(self.row(name)['driver_calls'],0)

    def test_all_missing_driver_states_return_minus_six(self):
        for state in ('root_missing','ops_missing','callback_missing'):
            name='partition_read_'+state;self.result(name,-6);self.assertEqual(self.opcodes(name),[])

    def test_mutex_failures_stop_at_actual_lock_or_unlock_assertion(self):
        for name,owner,line in (('partition_read_lock_assertion',0x80c3d464,0x24),('partition_read_unlock_assertion',0x80c3d44c,0x2a)):
            self.assertIsNone(self.row(name)['returned']);self.assertEqual(self.row(name)['stopped'],dict(kind='assertion',owner=owner,line=line))
        self.assertEqual(self.opcodes('partition_read_lock_assertion'),[])
        self.assertIn('copy_from_bounce:64',self.actions('partition_read_unlock_assertion'))

    def test_lower_read_error_still_releases_mutex(self):
        self.result('partition_read_ecc',-101);self.assertEqual(self.actions('partition_read_ecc')[-1],'mutex_release:0')
        self.result('partition_read_irq_ecc',-101);self.assertFalse(any(a.startswith('mutex_') for a in self.actions('partition_read_irq_ecc')))

    def test_direct_driver_read_skips_partition_rebase(self):
        self.assertIn('driver_read:600:16:64',self.actions('driver_read_normal'))
        self.result('driver_read_missing_chip',-2);self.assertEqual(self.actions('driver_read_missing_chip')[-1],'mutex_release:0')

    def test_geometry_queries_reach_original_ioctl_callback(self):
        for query,value in ((2,2048),(3,64),(18,64),(19,16),(20,4)):
            name='partition_query_'+str(query);self.assertEqual(self.args(name)[0],value)
            self.assertIn('driver_ioctl:'+str(query),self.actions(name));self.assertIn('chip_ioctl:'+str(query),self.actions(name))
        self.assertEqual(self.args('partition_query_21'),(4,20,36,52))
        self.assertEqual(self.args('partition_query_1')[0],5632);self.assertEqual(self.row('partition_query_1')['driver_calls'],0)

    def test_partition_erase_rebases_block_and_chooses_context_wait(self):
        self.assertIn('native_remap_block:13',self.actions('partition_erase'))
        self.assertIn('sleep:1',self.actions('partition_erase'));self.assertIn('delay:5',self.actions('partition_erase_irq'))
        self.result('partition_erase_sleep_timeout',-104);self.assertEqual(self.row('partition_erase_sleep_timeout')['feature_reads'],20)

    def test_format_ignores_real_mapped_guard_errors(self):
        name='partition_format_ignores_guard_errors';self.result(name,0)
        self.assertEqual(self.actions(name).count('log:block_guard'),2);self.assertEqual(self.row(name)['driver_calls'],2)
        self.assertEqual(self.opcodes(name),[])

    def test_copy_rebases_argument_in_place_even_when_driver_is_missing(self):
        for name in ('partition_copy_oob','partition_copy_oob_missing_driver'):
            self.assertEqual(self.args(name),(517,521,BUFFER,64))
        self.result('partition_copy_oob',0);self.result('partition_copy_oob_missing_driver',-6)
        self.assertIn(0x34,self.opcodes('partition_copy_oob'))

    def test_contract_rejects_unbounded_backing(self):
        base=self.cases['partition_read_normal']
        for change in (dict(count=65),dict(responses=[]),dict(bbt_hex='00'),dict(partition_base=-1),dict(query=8,partition_span=0)):
            with self.assertRaises(ValueError):contract(base|change)

    def test_native_capture_matches_regenerated_fixtures(self):
        report=json.loads(Path('analysis/nand-dispatch-stack.json').read_bytes())['native_validation']
        self.assertIs(report['hardware_execution'],False);self.assertEqual(report['case_count'],len(self.cases))
        self.assertEqual(len(report['cases']),len(self.cases))
        for row in report['cases']:self.assertEqual(row['observed'],self.cases[row['name']]['expected'])


if __name__=='__main__':unittest.main()
