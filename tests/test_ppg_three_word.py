import hashlib
import struct
import unittest

from analysis_scripts.ppg_three_word import contract,native_vectors,HEAP,TICK


class PpgThreeWordTest(unittest.TestCase):
    def test_three_stream_binary_fixture(self):
        fixture=bytearray(156);struct.pack_into('<HH',fixture,0,3,4);struct.pack_into('<II',fixture,16,1,HEAP+24)
        for at,kind,payload in ((24,0x10,144),(64,0x8000,148),(104,0x100000,152)):
            struct.pack_into('<I',fixture,at,kind);struct.pack_into('<Q',fixture,at+8,TICK)
            struct.pack_into('<HHH',fixture,at+20,1,10,20);struct.pack_into('<I',fixture,at+32,HEAP+payload)
        struct.pack_into('<H',fixture,52,1);struct.pack_into('<iii',fixture,144,3,1,2)
        result=contract([0x21000001,0x22000002,0x23000003],secondary=1)
        self.assertEqual(result['heap_sha256'],hashlib.sha256(fixture).hexdigest())
        self.assertEqual(result['state'],dict(count=0,read=3,auxiliary=4,counter=0))

    def test_discarded_second_word_and_unchecked_third_tag(self):
        self.assertNotIn('sample_tag_log',contract([0x21000001,0x23000002,0x2f000003])['actions'])
        self.assertIn('sample_tag_log',contract([0x21000001,0x23000002,0x2f000003],secondary=1)['actions'])

    def test_raw_clip_boundary(self):
        for raw,count in ((0x7fffe,0),(0x7ffff,1),(0x80000,1),(0x80001,1)):
            result=contract([0x21000001,0x22000002,0x23000000|raw],clip=1,rate=2,counter=0)
            self.assertEqual(result['state']['counter'],count)

    def test_value_threshold_is_strict(self):
        for raw,count in ((100,0),(101,1)):
            result=contract([0x21000001,0x22000002,0x23000000|raw],clip=1,minimum=-100,maximum=100,counter=0)
            self.assertEqual(result['state']['counter'],count)

    def test_only_all_bad_frames_accumulate_and_request_reset(self):
        words=[0x21000001,0x22000002,0x2307ffff]*2
        result=contract(words,clip=1,rate=2,counter=2)
        self.assertIn('postprocess_reset',result['actions']);self.assertEqual(result['state']['counter'],0)
        result=contract(words,clip=1,rate=2,counter=2,calibration=1)
        self.assertNotIn('postprocess_reset',result['actions']);self.assertEqual(result['state']['counter'],0)
        result=contract(words[:3]+[0x21000001,0x22000002,0x23000000],clip=1,counter=5)
        self.assertEqual(result['state']['counter'],0)

    def test_auxiliary_marks_are_consumed_for_every_popped_word(self):
        result=contract([0x21000001,0x22000002,0x23000003]*2,auxiliary=1)
        self.assertEqual(result['state']['auxiliary'],0)
        unmarked=contract([0x21000001,0x22000002,0x23000003]*2,auxiliary=0)
        self.assertNotEqual(result['heap_sha256'],unmarked['heap_sha256'])

    def test_frame_count_clamp_keeps_excess_words_and_wraps_read(self):
        result=contract([0x21000001,0x22000002,0x23000003]*20,rate=10,read=999)
        self.assertEqual(result['state']['count'],24);self.assertEqual(result['state']['read'],35)
        self.assertEqual(result['actions'][:2],['lock:4660','clamp_log'])

    def test_mode_three_uses_same_selected_packet_path(self):
        words=[0x21000001,0x22000002,0x23000003]
        self.assertEqual(contract(words,mode=2),contract(words,mode=3))

    def test_failed_allocation_preserves_ring_metadata(self):
        result=contract([0x21000001,0x22000002,0x23000003],allocated=False)
        self.assertEqual(result['state'],dict(count=3,read=0,auxiliary=7,counter=5))
        self.assertEqual(result['returned'],0)

    def test_unique_vectors_and_host_bounds(self):
        cases=native_vectors()['cases'];self.assertEqual(len(cases),29);self.assertEqual(len({c['name'] for c in cases}),29)
        for options in (dict(mode=1),dict(frame=2),dict(secondary=2),dict(clip=True),dict(minimum=1<<31)):
            with self.assertRaises(ValueError):contract([],**options)


if __name__=='__main__':unittest.main()
