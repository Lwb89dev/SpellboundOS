from dataclasses import replace
import struct
import unittest

from analysis_scripts.ppg_fifo_lifecycle import (
    State,fifo_read,pop_word,recovery,reset_metadata,response_words,sample_value,native_vectors,
)


class PpgFifoLifecycleTest(unittest.TestCase):
    def inputs(self,words=(0x21000009,0x2100000a)):
        ring=[0xdeadbeef]*1000;stage=bytearray(b'\xa5'*2052)
        for i,word in enumerate(words):struct.pack_into('>I',stage,2+4*i,word)
        return ring,bytes(stage)

    def read(self,state=None,**changes):
        args=dict(now=100,registers={3:0,4:2,9:5,13:16},response=response_words((0x21000001,0x21000002)))
        args.update(changes)
        return fifo_read(state or State(),*self.inputs(),**args)

    def test_cache_wrap_and_word_endianness(self):
        state,ring,stage,actions=self.read(State(count=10,write=999,read=989))
        self.assertEqual((state.count,state.write,state.read,state.frame_total),(12,1,989,10))
        self.assertEqual((ring[999],ring[0]),(0x21000001,0x21000002))
        self.assertEqual(actions,['read:3','read:4','bulk:10'])

    def test_spi_failure_keeps_stale_payload_in_the_cache(self):
        state,ring,_,actions=self.read(response=b'',bulk_result=0xfffffff2)
        self.assertEqual(ring[:2],[0x21000009,0x2100000a])
        self.assertEqual((state.count,state.frame_total),(2,10))
        self.assertEqual(actions,['read:3','read:4','bulk:10'])

    def test_partial_spi_failure_produces_a_mixed_word(self):
        response=response_words((0x2100aabb,))[:5]
        _,ring,stage,_=self.read(response=response,bulk_result=0xfffffff2)
        self.assertEqual(ring[:2],[0x2100aa09,0x2100000a])
        self.assertEqual(stage[:6],bytes.fromhex('aabb2100aa09'))

    def test_burst_result_is_ignored_even_with_complete_data(self):
        good=self.read();failed=self.read(bulk_result=0xfffffff2)
        self.assertEqual(good,failed)

    def test_status_failure_uses_zero_initialized_local_bytes(self):
        state,_,_,actions=self.read(registers={3:None,4:None},response=b'')
        self.assertEqual((state.count,state.last_tick),(0,100))
        self.assertEqual(actions,['read:3','read:4'])

    def test_cache_overflow_checks_available_before_frame_rounding(self):
        state,_,_,actions=self.read(State(count=998,write=998),registers={3:0,4:3,9:5,13:16},response=b'')
        self.assertEqual((state.count,state.write,state.last_tick),(0,0,0))
        self.assertNotIn('bulk:10',actions)
        self.assertIn('event:0206000000000000',actions)

    def test_failed_frame_preserves_prefix_bytes_and_auxiliary_count(self):
        state,ring,_,actions=self.read(State(frame=1),response=response_words((0x21000001,0x22000002)))
        self.assertEqual((state.count,state.write,state.auxiliary,state.frame_total),(0,0,1,11))
        self.assertEqual(ring[:2],[0x21000001,0xdeadbeef])
        self.assertEqual(actions[-1],'control:6:129:0:0')

    def test_inactive_recovery_leaves_committed_prefix_metadata(self):
        state,ring,_,actions=self.read(State(frame=1,enabled=False),response=response_words((0x21000001,0x22000002)))
        self.assertEqual((state.count,state.write,state.frame,state.auxiliary),(1,1,1,1))
        self.assertEqual(actions,['read:3','read:4','bulk:10'])

    def test_frame_check_is_only_at_starts_and_allows_channel_zero(self):
        for words in ((0x21000001,0x22000002),(0x02000001,0x02000002)):
            state,_,_,actions=self.read(response=response_words(words))
            self.assertEqual(state.count,2)
            self.assertNotIn('event:0206000000000000',actions)

    def test_kernel_tick_timeout_is_strict_and_wraps_at_32_bits(self):
        state,_,_,_=self.read(State(last_tick=50,limit=50))
        self.assertEqual(state.count,2)
        state,_,_,_=self.read(State(last_tick=0xfffffffe,limit=3),now=1)
        self.assertEqual(state.count,2)
        state,_,_,_=self.read(State(last_tick=0xfffffffe,limit=2),now=1,response=b'')
        self.assertEqual(state.last_tick,0)

    def test_zero_timestamp_skips_timeout_and_zero_frame_skips_burst(self):
        self.assertEqual(self.read(State(last_tick=0,limit=0))[0].count,2)
        state,_,_,actions=self.read(State(frame=0),response=b'')
        self.assertEqual(state.count,0)
        self.assertEqual(actions,['read:3','read:4'])

    def test_recovery_reuses_previous_register_byte_when_second_read_fails(self):
        state,actions=recovery(State(auxiliary=9),registers={9:5,13:None})
        self.assertEqual(actions[:5],['read:9','write:9:21','read:13','write:13:7','write:13:5'])
        self.assertEqual(state.auxiliary,9)

    def test_reset_fields_do_not_include_tick_or_auxiliary_without_outer_recovery(self):
        before=State(count=3,write=7,read=4,frame=4,base_frame=3,auxiliary=9,last_tick=12)
        self.assertEqual(reset_metadata(before),replace(before,count=0,write=0,read=0,frame=3))
        self.assertEqual(recovery(before,notify=False)[1][-1],'write:13:16')
        self.assertNotIn('control:6:129:0:0',recovery(before,registered=False)[1])

    def test_pop_flags_and_ring_wrap_without_erasing_payload(self):
        ring=[0]*1000;ring[999]=0x210fffff
        state,word,flags=pop_word(State(count=1,read=999,auxiliary=2),ring,0xa0)
        self.assertEqual((state.count,state.read,state.auxiliary,word,flags),(0,0,1,0x210fffff,0xa1))
        self.assertEqual(ring[999],0x210fffff)
        state,word,flags=pop_word(State(),ring,0xa0)
        self.assertEqual((word,flags),(0,0xa0))

    def test_mode_one_does_not_change_auxiliary_marker(self):
        state,_,_,_=self.read(State(mode=1,auxiliary=5))
        self.assertEqual(state.auxiliary,5)
        after,_,flags=pop_word(state,[0]*1000,0xa0)
        self.assertEqual((after.auxiliary,flags),(5,0xa0))

    def test_sign_extension_and_tag_diagnostic_are_separate(self):
        for raw,value in ((0x2107ffff,524287),(0x21080000,-524288),(0x210fffff,-1)):
            self.assertEqual(sample_value(0,raw),(value,False))
        self.assertEqual(sample_value(0,0x22000001),(1,True))
        for tag in (21,22):self.assertEqual(sample_value(0,tag<<24|1),(1,False))

    def test_synthetic_vectors_are_bounded_and_named_uniquely(self):
        cases=native_vectors()['cases']
        self.assertEqual(len(cases),45)
        self.assertEqual(len({c['name'] for c in cases}),45)
        self.assertEqual(max(c['expected']['state']['count'] for c in cases),1000)

    def test_invalid_host_state_and_buffers(self):
        for change in (dict(count=1001),dict(write=1000),dict(frame=33),dict(enabled=1)):
            with self.assertRaises(ValueError):State(**change)
        with self.assertRaises(ValueError):self.read(response=b'x'*11)
        with self.assertRaises(ValueError):sample_value(0,True)
        with self.assertRaises(ValueError):fifo_read(State(),[],b'',now=0,registers={})


if __name__=='__main__':unittest.main()
