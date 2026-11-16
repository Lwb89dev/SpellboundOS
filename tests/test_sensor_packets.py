import hashlib
import struct
import unittest

from analysis_scripts.sensor_packets import (
    HEAP,RELOCATED,TICK,flush_contract,packet_contract,packet_size,consumer_contract,native_vectors,
)


class SensorPacketsTest(unittest.TestCase):
    def test_coordinated_callback_order_and_no_recursive_event(self):
        result=flush_contract(6,10)
        self.assertEqual(result['actions'],[
            'callback:1:129:0:0','callback:6:129:0:0','read:9','write:9:21',
            'read:13','write:13:18','write:13:16','callback:3:129:0:0','clock','clock'])
        self.assertEqual(result['optical'],dict(count=0,write=0,read=0,frame=3,last_tick=0))

    def test_uncoordinated_optical_flush_still_resets_driver(self):
        result=flush_contract(6,0)
        self.assertEqual(result['actions'][0],'callback:6:129:0:0')
        self.assertNotIn('clock',result['actions'])
        self.assertEqual(result['optical']['count'],0)

    def test_magnetic_group_alone_does_not_route_optical_through_fusion(self):
        self.assertEqual(flush_contract(6,2)['actions'],flush_contract(6,0)['actions'])
        self.assertEqual(flush_contract(3,2)['actions'],['callback:1:129:0:0','callback:3:129:0:0','clock'])

    def test_optical_active_group_flushes_imu_and_optical(self):
        actions=flush_contract(1,8)['actions']
        self.assertEqual(actions[:2],['callback:1:129:0:0','callback:6:129:0:0'])
        self.assertEqual(actions[-1],'clock')

    def test_irrelevant_flags_do_not_change_routing(self):
        for flags in range(64):
            for sensor in (1,3,4,6,31):
                a=flush_contract(sensor,flags);b=flush_contract(sensor,flags|0x80000001)
                self.assertEqual(a['actions'],b['actions'])
                self.assertEqual(a['optical'],b['optical'])

    def test_absent_handle_returns_two_and_missing_callback_returns_zero(self):
        absent=flush_contract(6,10,present=False)
        self.assertEqual((absent['returned'],absent['actions']),(2,[]))
        missing=flush_contract(6,10,callback=False)
        self.assertEqual(missing['returned'],0)
        self.assertEqual(missing['optical']['count'],4)
        self.assertEqual(missing['actions'],['callback:1:129:0:0','callback:3:129:0:0','clock','clock'])

    def test_disabled_optical_does_not_prevent_fusion_reset(self):
        result=flush_contract(6,10,enabled=False)
        self.assertIn('callback:6:129:0:0',result['actions'])
        self.assertEqual(result['actions'][-2:],['clock','clock'])
        self.assertEqual(result['optical']['count'],4)

    def test_lookup_tests_low_byte_but_uses_full_sensor_index(self):
        for sensor in (0,36,256):self.assertEqual(flush_contract(sensor,0)['returned'],2)
        self.assertEqual(flush_contract(257,0)['actions'],['callback:257:129:0:0'])

    def test_packet_layout_matches_an_independently_written_binary_fixture(self):
        # Header: two streams, four bytes each; descriptors at 24 and 64.
        fixture=bytearray(112)
        struct.pack_into('<HH',fixture,0,2,4)
        struct.pack_into('<II',fixture,16,1,HEAP+24)
        struct.pack_into('<Q',fixture,32,TICK);struct.pack_into('<I',fixture,56,HEAP+104)
        struct.pack_into('<Q',fixture,72,TICK);struct.pack_into('<I',fixture,96,HEAP+108)
        result=packet_contract(2,4,rebind=True)
        self.assertEqual(result['heap_sha256'],hashlib.sha256(fixture).hexdigest())
        struct.pack_into('<I',fixture,20,RELOCATED+24)
        struct.pack_into('<I',fixture,56,RELOCATED+104);struct.pack_into('<I',fixture,96,RELOCATED+108)
        self.assertEqual(result['relocated_sha256'],hashlib.sha256(fixture).hexdigest())

    def test_empty_and_failed_allocations_have_no_clock_or_memset(self):
        for count,stride in ((0,4),(1,0)):
            self.assertEqual(packet_contract(count,stride)['actions'],[])
        result=packet_contract(3,12,allocated=False)
        self.assertEqual(result['actions'],['alloc:4:180:4','allocation_log'])
        self.assertEqual(result['returned'],0)

    def test_native_allocation_size_wraps_at_32_bits(self):
        self.assertEqual(packet_size(1,0xffffffff),63)
        self.assertEqual(packet_size(0xffffffff,0xffffffff),0xfffffff1)
        self.assertEqual(packet_contract(65536,4,allocated=False)['actions'][0],'alloc:4:2883608:4')

    def test_rebind_uses_truncated_header_stride(self):
        result=packet_contract(2,65536,rebind=True)
        self.assertEqual(result['actions'],['alloc:4:131176:4','zero:131176','clock'])
        self.assertNotEqual(result['heap_sha256'],result['relocated_sha256'])

    def test_host_bounds_exclude_unreviewed_successful_malformed_allocations(self):
        for args in ((65536,4),(1,65537),(33,4)):
            with self.assertRaises(ValueError):packet_contract(*args)
        for args in ((-1,4),(1,True)):
            with self.assertRaises(ValueError):packet_size(*args)
        with self.assertRaises(ValueError):flush_contract(258,0)

    def test_vectors_are_unique_and_cover_all_six_low_flag_bits(self):
        cases=native_vectors()['cases']
        self.assertEqual(len(cases),557)
        self.assertEqual(len({c['name'] for c in cases}),557)
        flags={c['flags'] for c in cases if c['kind']=='flush' and c['sensor']==6}
        self.assertEqual(flags,set(range(64)))

    def test_consumer_packet_fixture_contains_two_streams_and_signed_samples(self):
        fixture=bytearray(120)
        struct.pack_into('<HH',fixture,0,2,8);struct.pack_into('<II',fixture,16,1,HEAP+24)
        struct.pack_into('<I',fixture,24,0x8000);struct.pack_into('<I',fixture,64,0x100000)
        for at,pointer in ((24,HEAP+104),(64,HEAP+112)):
            struct.pack_into('<Q',fixture,at+8,TICK)
            struct.pack_into('<HHH',fixture,at+20,2,10,20)
            struct.pack_into('<I',fixture,at+32,pointer)
        struct.pack_into('<ii',fixture,104,524287,-1);struct.pack_into('<ii',fixture,112,-524288,1)
        result=consumer_contract([0x2107ffff,0x22080000,0x210fffff,0x22000001],secondary=1)
        self.assertEqual(result['heap_sha256'],hashlib.sha256(fixture).hexdigest())
        self.assertEqual(result['state'],dict(count=0,read=4,auxiliary=7,counter=0))

    def test_consumer_ignores_tags_in_discarded_second_words(self):
        words=[0x21000001,0x23000002]
        self.assertNotIn('sample_tag_log',consumer_contract(words)['actions'])
        self.assertIn('sample_tag_log',consumer_contract(words,secondary=1)['actions'])

    def test_consumer_keeps_a_partial_frame_and_wraps_ring(self):
        result=consumer_contract([0x21000001,0x22000002,0x21000003],read=999)
        self.assertEqual(result['state'],dict(count=1,read=1,auxiliary=7,counter=0))

    def test_consumer_clamps_to_rate_and_keeps_unconsumed_words(self):
        result=consumer_contract([0x21000001,0x22000002]*20,secondary=1,rate=10)
        self.assertEqual(result['state']['count'],16)
        self.assertEqual(result['state']['read'],24)
        self.assertEqual(result['actions'][:2],['lock:4660','clamp_log'])

    def test_consumer_lock_and_allocation_failure_do_not_pop(self):
        words=[0x21000001,0x22000002]
        for options,actions in ((dict(enabled=False),[]),(dict(locked=False),['lock:4660']),
            (dict(allocated=False),['lock:4660','alloc:4:68:4','allocation_log','unlock:4660'])):
            result=consumer_contract(words,**options)
            self.assertEqual(result['actions'],actions)
            self.assertEqual(result['state'],dict(count=2,read=0,auxiliary=7,counter=5))

    def test_zero_rate_returns_no_packet_without_popping(self):
        result=consumer_contract([0x21000001,0x22000002],rate=0)
        self.assertEqual(result['actions'],['lock:4660','clamp_log','unlock:4660'])
        self.assertEqual(result['returned'],0)
        self.assertEqual(result['state']['count'],2)

    def test_consumer_host_bounds(self):
        for options in (dict(secondary=2),dict(read=1000),dict(rate=65536),dict(enabled=1)):
            with self.assertRaises(ValueError):consumer_contract([],**options)


if __name__=='__main__':unittest.main()
