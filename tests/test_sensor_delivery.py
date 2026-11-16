import hashlib
import struct
import unittest

from analysis_scripts.sensor_delivery import (
    P0,NODE,QUEUE,packet,summary,references_contract,listener_matches,fanout_contract,cache_contract,native_vectors,
)


class SensorDeliveryTest(unittest.TestCase):
    def test_last_release_clears_pointer_before_free(self):
        result=references_contract(1,['release'])
        self.assertEqual(result['actions'],['release:p0','free:p0'])
        self.assertEqual((result['packet']['refs'],result['packet']['descriptor']),(0,0))

    def test_retained_packet_survives_first_release(self):
        result=references_contract(1,['retain','release','release'])
        self.assertEqual([row['refs'] for row in result['operations']],[2,1,0])
        self.assertEqual(result['actions'].count('free:p0'),1)

    def test_reference_arithmetic_wraps_without_zero_saturation(self):
        result=references_contract(0,['release'])
        self.assertEqual(result['packet']['refs'],0xffffffff)
        self.assertNotIn('free:p0',result['actions'])
        result=references_contract(0xffffffff,['retain'])
        self.assertEqual(result['packet']['refs'],0)
        self.assertEqual(result['packet']['descriptor'],P0+24)

    def test_null_operations_do_not_enter_critical_section(self):
        result=references_contract(1,['retain','release'],context=0,mstatus=0x1880,null=True)
        self.assertEqual(result['actions'],[])
        self.assertEqual(result['mstatus'],0x1880)
        self.assertEqual(result['packet'],summary(packet(P0)))

    def test_critical_exit_does_not_restore_the_original_mie_bit(self):
        result=references_contract(1,['retain'],context=0,mstatus=0x1880)
        self.assertEqual(result['mstatus'],0x1888)
        self.assertEqual(result['depth'],0)
        result=references_contract(1,['retain'],context=0,started=False,mstatus=0x1888)
        self.assertEqual(result['mstatus'],0x1880)

    def test_nested_and_context_bypass_critical_paths(self):
        result=references_contract(1,['retain'],context=0,depth=2,mstatus=0x1888)
        self.assertEqual((result['depth'],result['mstatus']),(2,0x1880))
        result=references_contract(1,['retain'],context=1,depth=2,mstatus=0x1888)
        self.assertEqual((result['depth'],result['mstatus']),(2,0x1888))

    def test_normal_listener_group_membership_and_wildcard(self):
        self.assertTrue(listener_matches(6,0,5));self.assertTrue(listener_matches(6,0,15))
        self.assertFalse(listener_matches(6,0,16));self.assertTrue(listener_matches(6,0,36))
        self.assertTrue(listener_matches(1,0,2));self.assertTrue(listener_matches(1,0,257))
        self.assertFalse(listener_matches(0,0,36));self.assertFalse(listener_matches(36,0,36))

    def test_private_listener_uses_separate_wildcard_and_low_byte(self):
        self.assertTrue(listener_matches(6,1,6));self.assertFalse(listener_matches(6,1,36))
        self.assertTrue(listener_matches(6,257,1));self.assertFalse(listener_matches(6,256,6))
        self.assertFalse(listener_matches(6,6,6))

    def test_fanout_does_not_implicitly_retain_for_each_listener(self):
        result=fanout_contract(6,0,[[5,False],[6,False],[36,False]])
        self.assertEqual(result['actions'],['read','fusion','cache:p0','callback:0:p0','callback:1:p0',
                                             'callback:2:p0','release:p0','free:p0'])

    def test_synthetic_listener_retain_survives_owner_release(self):
        result=fanout_contract(6,0,[[6,True]])
        self.assertEqual(result['actions'],['read','fusion','cache:p0','callback:0:p0','retain:p0',
                                             'release:p0','release:p0','free:p0'])

    def test_empty_fusion_result_suppresses_source_fanout_but_releases_both(self):
        result=fanout_contract(6,0,[[6,True]],fusion='empty')
        self.assertEqual(result['actions'],['read','fusion','release:p1','free:p1','release:p0','free:p0'])

    def test_ready_fusion_result_replaces_source_in_delivery(self):
        result=fanout_contract(6,0,[[6,False]],fusion='ready')
        self.assertEqual(result['actions'][2:4],['cache:p1','callback:0:p1'])
        self.assertEqual(result['actions'][-4:],['release:p1','free:p1','release:p0','free:p0'])

    def test_cache_success_keeps_one_reference_when_not_drained(self):
        result=cache_contract(drain='none')
        self.assertEqual(result['packet']['refs'],1)
        self.assertEqual(result['queue'],dict(head=NODE,tail=NODE,count=1))
        fixture=struct.pack('<6I',QUEUE,QUEUE,0x80f655f8,8,68,P0)
        self.assertEqual(result['node_sha256'],hashlib.sha256(fixture).hexdigest())

    def test_successful_dequeue_and_short_buffer_have_distinct_cleanup_order(self):
        take=cache_contract();short=cache_contract(drain='short')
        self.assertEqual((take['get_result'],short['get_result']),(0,1))
        self.assertEqual(take['output_hex'],struct.pack('<II',68,P0).hex())
        self.assertEqual(short['output_hex'],'a5'*8)
        self.assertLess(take['actions'].index('free:node'),take['actions'].index('free:p0'))
        self.assertLess(short['actions'].index('free:p0'),short['actions'].index('free:node'))

    def test_enqueue_failure_balances_the_added_reference(self):
        for changes in (dict(allocated=False),dict(magic=False)):
            result=cache_contract(**changes)
            self.assertEqual(result['packet']['refs'],0)
            self.assertEqual(result['actions'].count('release:p0'),2)
            self.assertEqual(result['actions'].count('free:p0'),1)
            self.assertEqual(result['cached'],0)

    def test_cache_pressure_boundaries(self):
        self.assertNotIn('cache_flush',cache_contract(free_memory=102401)['actions'])
        self.assertIn('cache_flush',cache_contract(free_memory=102400)['actions'])
        self.assertNotIn('cache_flush',cache_contract(cached=0x4fff-68)['actions'])
        self.assertIn('cache_flush',cache_contract(cached=0x5000-68)['actions'])

    def test_vectors_are_bounded_and_unique(self):
        cases=native_vectors()['cases']
        self.assertEqual(len(cases),149);self.assertEqual(len({c['name'] for c in cases}),149)

    def test_invalid_host_inputs(self):
        with self.assertRaises(ValueError):references_contract(-1,['retain'])
        with self.assertRaises(ValueError):references_contract(1,['unknown'])
        with self.assertRaises(ValueError):cache_contract(drain='unknown')
        with self.assertRaises(ValueError):fanout_contract(6,0,[],fusion='unknown')


if __name__=='__main__':unittest.main()
