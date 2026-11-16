import hashlib
import struct
import unittest

from analysis_scripts.cache_pipeline import (
    SOURCE,CLONE,BUFFER,MAGIC,TICK,packet,rebase,rebase_blob,parse_wire,native_vectors,
)


class CachePipelineTest(unittest.TestCase):
    def cases(self):return {c['name']:c for c in native_vectors()['cases']}

    def test_packet_fixture_has_independent_descriptor_and_payload_regions(self):
        data=packet(SOURCE,(0x10,0x8000),4)
        self.assertEqual(len(data),112)
        self.assertEqual(struct.unpack_from('<HHHHQII',data),(2,4,6,0,0x8010,1,SOURCE+24))
        self.assertEqual(struct.unpack_from('<QQ',data,24),(0x10,TICK))
        self.assertEqual(struct.unpack_from('<I',data,56),(SOURCE+104,))
        self.assertEqual(struct.unpack_from('<I',data,96),(SOURCE+108,))
        self.assertEqual(data[104:],bytes.fromhex('1112131422232425'))

    def test_rebase_rewrites_only_native_reference_and_pointer_fields(self):
        original=packet(SOURCE,(0x8000,),4);moved=rebase(original,BUFFER+20)
        self.assertEqual(struct.unpack_from('<II',moved,16),(1,BUFFER+44))
        self.assertEqual(struct.unpack_from('<I',moved,56),(BUFFER+84,))
        self.assertEqual(moved[60:],original[60:])
        self.assertEqual(moved[24:56],original[24:56])

    def test_partial_filter_copies_metadata_but_preserves_new_pointer_storage(self):
        c=self.cases()['filter_2'];source=bytes.fromhex(c['packets'][0]['hex'])
        expected=bytearray(72);struct.pack_into('<HHHHQII',expected,0,1,8,6,0,0x8000,0,0)
        expected[24:56]=source[64:96]
        struct.pack_into('<I',expected,56,CLONE+64)
        start=struct.unpack_from('<I',source,96)[0]-SOURCE;expected[64:]=source[start:start+8]
        self.assertEqual(expected[60:64],bytes(4))
        self.assertEqual(c['expected']['clone_sha256'],hashlib.sha256(expected).hexdigest())

    def test_high_type_word_participates_in_filtering(self):
        result=self.cases()['filter_7']['expected']
        self.assertIsNotNone(result['clone_sha256'])
        self.assertEqual(result['wires'][0]['length'],81)
        self.assertEqual(result['queue_count'],0)

    def test_no_matching_types_allocates_no_cache_buffer(self):
        result=self.cases()['filter_0']['expected']
        self.assertEqual(result['actions'],['free:p0'])
        self.assertEqual(result['buffers'],[])
        self.assertIsNone(result['clone_sha256'])

    def test_partial_allocation_and_enqueue_failure_free_owned_packets(self):
        cases=self.cases()
        failed=cases['filter_clone_allocated_failure']['expected']
        self.assertEqual(failed['actions'],['alloc_fail:clone:72','log:80fd4b4c','log:80fd5180','log:80fd51a4','free:p0'])
        failed=cases['filter_node_allocated_failure']['expected']
        self.assertEqual(failed['actions'][-3:],['log:80fd51c0','free:clone','free:p0'])
        self.assertEqual(failed['wires'],[])

    def test_flush_can_fit_one_record_exactly_in_capacity(self):
        result=self.cases()['flush_exact_fit']['expected']
        self.assertEqual(result['buffers'][0]['used'],4000)
        self.assertEqual(result['wires'][0]['length'],4005)
        self.assertEqual(result['queue_count'],0)

    def test_multiple_packets_pack_into_two_buffers(self):
        result=self.cases()['flush_multiple_buffers']['expected']
        self.assertEqual([b['used'] for b in result['buffers']],[3204,2136])
        self.assertEqual([w['length'] for w in result['wires']],[3209,2141])
        self.assertEqual(result['cached'],0)
        self.assertEqual(result['motion'],0)

    def test_oversized_head_makes_no_progress_under_selected_allocation_schedule(self):
        result=self.cases()['flush_oversized_no_progress']['expected']
        self.assertEqual(result['queue_count'],1)
        self.assertEqual(result['cached'],123)
        self.assertEqual(result['motion'],7)
        self.assertEqual([b['used'] for b in result['buffers']],[0,0])
        self.assertTrue(all(b['refs']==1 and b['magic']==MAGIC for b in result['buffers']))
        self.assertFalse(any(a.startswith('free:') for a in result['actions']))
        self.assertEqual(result['actions'][-3:],['alloc_fail:b2:4016','log:80fd5134','log:80fd515c'])

    def test_prefix_packet_is_consumed_before_oversized_head(self):
        result=self.cases()['flush_prefix_then_oversized']['expected']
        self.assertEqual([b['used'] for b in result['buffers']],[72,0])
        self.assertIn('free:p0',result['actions']);self.assertNotIn('free:p1',result['actions'])
        self.assertEqual(result['queue_count'],1)

    def test_send_failure_still_releases_event_buffer_reference(self):
        result=self.cases()['flush_send_error']['expected']
        self.assertEqual(result['actions'][-3:],['log:80fe18e0','log:80fe22dc','free:b0'])
        self.assertEqual(result['buffers'][0]['refs'],0)
        self.assertEqual(result['buffers'][0]['magic'],0)

    def test_wire_parser_checks_opcode_length_and_native_packet_shape(self):
        data=packet(SOURCE,(0x8000,),4);blob=struct.pack('<I',68)+data
        wire=b'\x15'+struct.pack('<I',72)+blob
        self.assertEqual(parse_wire(wire),[bytes(data)])
        for bad in (b'',b'\x16'+wire[1:],wire[:-1],wire+b'\0',wire[:5]+bytes(4)+wire[9:]):
            with self.assertRaises(ValueError):parse_wire(bad)

    def test_fixup_returns_without_changing_zero_or_overrun_records(self):
        original=struct.pack('<I',0)+packet(SOURCE,(0x8000,),4)
        self.assertEqual(rebase_blob(original,72,BUFFER+16),original)
        overrun=struct.pack('<I',80)+original[4:]
        self.assertEqual(rebase_blob(overrun,72,BUFFER+16),overrun)
        cases=self.cases()
        self.assertEqual(cases['buffer_zero_record']['expected']['statuses'],[1,1,1,1,1,0])
        self.assertEqual(cases['buffer_overrun_record']['expected']['statuses'],[1,1,1,1,1,0])

    def test_invalid_outer_buffer_prevents_retain_and_release(self):
        cases=self.cases()
        for name in ('buffer_zero_length','buffer_bad_magic','buffer_null_pointer'):
            result=cases[name]['expected'];self.assertEqual(result['statuses'],[0]*6)
            self.assertEqual(result['buffers'][0]['refs'],1)
            self.assertNotIn('free:b0',result['actions'])

    def test_zero_capacity_and_allocation_failure(self):
        cases=self.cases()
        self.assertEqual(cases['buffer_zero_capacity']['expected']['actions'],[])
        self.assertEqual(cases['buffer_allocation_failure']['expected']['returned'],0)
        self.assertEqual(cases['buffer_allocation_failure']['expected']['actions'],['alloc_fail:b0:144','log:80fd5134'])

    def test_native_vectors_are_named_uniquely(self):
        cases=native_vectors()['cases'];self.assertEqual(len(cases),29);self.assertEqual(len({c['name'] for c in cases}),29)

    def test_host_packet_and_parser_bounds(self):
        for args in ((SOURCE,(),4),(SOURCE,(0x8000,),0),(SOURCE,(0x8000,),4001)):
            with self.assertRaises(ValueError):packet(*args)
        with self.assertRaises(ValueError):parse_wire('not bytes')


if __name__=='__main__':unittest.main()
