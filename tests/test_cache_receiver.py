import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.cache_pipeline import parse_wire
from analysis_scripts.cache_receiver import (
    WIRE,HEAP,GUARD,MAGIC,decoder_contract,parse_contract,envelope,native_vectors,
)


class CacheReceiverTest(unittest.TestCase):
    def cases(self):return {c['name']:c for c in native_vectors()['cases']}

    def test_receiver_fixture_matches_prior_native_sender_wire(self):
        wire=bytes.fromhex(self.cases()['main_parse_one']['wire_hex'])
        prior=json.loads((Path(__file__).resolve().parents[1]/'analysis/cache-pipeline.json').read_text())
        sender=next(row for row in prior['native_validation']['cases'] if row['name']=='flush_one')
        self.assertEqual(hashlib.sha256(wire).hexdigest(),sender['observed']['wires'][0]['sha256'])

    def test_parser_returns_borrowed_payload_pointer(self):
        wire=bytes.fromhex(self.cases()['main_parse_one']['wire_hex']);parsed,status=parse_contract(wire)
        self.assertEqual(status,0);self.assertEqual(parsed,dict(opcode=21,length=72,pointer=WIRE+5))

    def test_native_parser_accepts_trailing_bytes_that_strict_host_parser_rejects(self):
        wire=bytes.fromhex(self.cases()['main_parse_trailing']['wire_hex'])
        self.assertEqual(parse_contract(wire)[1],0)
        self.assertEqual(parse_contract(wire)[0]['length'],72)
        with self.assertRaises(ValueError):parse_wire(wire)

    def test_zero_declared_length_is_a_null_slice_and_parser_failure(self):
        parsed,status=parse_contract(envelope(b''))
        self.assertEqual((parsed['length'],parsed['pointer'],status),(0,0,1))

    def test_oversized_declared_length_is_preserved_but_has_no_pointer(self):
        wire=bytes.fromhex(self.cases()['main_parse_huge']['wire_hex']);parsed,status=parse_contract(wire)
        self.assertEqual(parsed['length'],0xffffffff);self.assertEqual(parsed['pointer'],0);self.assertEqual(status,1)

    def test_short_length_field_does_not_form_a_partial_integer(self):
        for n in range(1,5):
            parsed,status=parse_contract(b'\x15\x48\x00\x00'[:n])
            self.assertEqual((parsed['length'],parsed['pointer'],status),(0,0,1))

    def test_parser_does_not_check_inner_record_shape(self):
        self.assertEqual(parse_contract(envelope(b'x'))[1],0)
        with self.assertRaises(ValueError):parse_wire(envelope(b'x'))

    def test_decoder_reads_little_endian_word(self):
        row=decoder_contract(bytes.fromhex('78563412'),['word'])[0]
        self.assertEqual((row['returned'],row['cursor'],row['error']),(0x12345678,WIRE+4,0))

    def test_failed_word_read_keeps_cursor_and_error_is_sticky(self):
        rows=decoder_contract(b'ab',['word','byte','data:1'])
        self.assertEqual([row['returned'] for row in rows],[0,97,WIRE+1])
        self.assertEqual([row['cursor'] for row in rows],[WIRE,WIRE+1,WIRE+2])
        self.assertEqual([row['error'] for row in rows],[2,2,2])

    def test_zero_slice_leaves_decoder_usable(self):
        rows=decoder_contract(b'ab',['data:0','byte'])
        self.assertEqual([row['returned'] for row in rows],[0,97])
        self.assertEqual([row['error'] for row in rows],[0,0])

    def test_empty_decoder_has_distinct_initial_error(self):
        rows=decoder_contract(b'',['byte','word','data:1'])
        self.assertTrue(all(row['base']==0 and row['cursor']==0 and row['error']==1 for row in rows))

    def test_receiver_uses_new_buffer_and_frees_it_after_unretained_callback(self):
        result=self.cases()['main_receive_one']['expected']
        self.assertEqual(result['actions'],['alloc:88','callback:0','free:buffer'])
        self.assertEqual((result['owner_after']['refs'],result['owner_after']['magic']),(0,0))
        self.assertEqual(result['ack'],0)
        self.assertEqual(result['parsed']['pointer'],WIRE+5)

    def test_retained_callbacks_survive_owner_release_and_cleanup_in_order(self):
        result=self.cases()['main_receive_two_listeners']['expected']
        self.assertEqual([row['refs'] for row in result['callbacks']],[1,2])
        self.assertEqual((result['owner_after']['refs'],result['owner_after']['magic']),(2,MAGIC))
        self.assertEqual(result['actions'][-3:],['drop:0','drop:1','free:buffer'])
        self.assertEqual(result['final_heap']['refs'],0)

    def test_missing_handler_does_not_allocate_or_dispatch(self):
        result=self.cases()['main_receive_no_handler']['expected']
        self.assertEqual(result['returned'],0);self.assertEqual(result['actions'],[])
        self.assertIsNone(result['final_heap'])

    def test_allocation_failure_returns_eight_without_callback(self):
        result=self.cases()['main_receive_allocation_failure']['expected']
        self.assertEqual(result['returned'],8)
        self.assertEqual(result['actions'],['alloc_fail:88','log:buffer_alloc','log:receive_alloc'])
        self.assertEqual(result['callbacks'],[])

    def test_parse_failure_prevents_allocation_and_handler(self):
        result=self.cases()['main_receive_bad_envelope']['expected']
        self.assertEqual(result['returned'],1)
        self.assertEqual(result['actions'],['log:parse_cache','log:receive_parse'])
        self.assertIsNone(result['owner_after'])

    def test_zero_and_overrun_record_prefixes_still_reach_listener(self):
        cases=self.cases()
        for name in ('main_receive_zero_prefix','main_receive_overrun_prefix'):
            result=cases[name]['expected'];self.assertEqual(result['returned'],0)
            self.assertEqual(result['actions'],['alloc:88','callback:0','free:buffer'])
            wire=bytes.fromhex(cases[name]['wire_hex'])
            self.assertEqual(result['callbacks'][0]['data_sha256'],hashlib.sha256(wire[5:]).hexdigest())

    def test_inner_count_fixture_records_write_outside_allocated_buffer(self):
        c=self.cases()['main_receive_inner_count_two'];result=c['expected']
        expected=bytearray(b'\xa5'*GUARD);struct.pack_into('<I',expected,28,HEAP+128)
        self.assertEqual(result['callbacks'][0]['guard_sha256'],hashlib.sha256(expected).hexdigest())
        self.assertNotEqual(result['callbacks'][0]['guard_sha256'],hashlib.sha256(b'\xa5'*GUARD).hexdigest())
        self.assertEqual(result['returned'],0)
        with self.assertRaises(ValueError):parse_wire(bytes.fromhex(c['wire_hex']))

    def test_valid_inputs_leave_guard_and_borrowed_input_unchanged(self):
        cases=self.cases()
        for name in ('main_receive_one','main_receive_multi','main_receive_retained'):
            c=cases[name];result=c['expected']
            self.assertEqual(result['final_heap']['guard_sha256'],hashlib.sha256(b'\xa5'*GUARD).hexdigest())
            self.assertEqual(result['input_sha256'],hashlib.sha256(bytes.fromhex(c['wire_hex'])).hexdigest())

    def test_vectors_cover_both_cores_and_are_named_uniquely(self):
        cases=native_vectors()['cases'];self.assertEqual(len(cases),66);self.assertEqual(len({c['name'] for c in cases}),66)
        self.assertEqual(sum(c['platform']=='main' for c in cases),33)

    def test_host_scope_and_operation_bounds(self):
        with self.assertRaises(ValueError):parse_contract(b'\x16')
        with self.assertRaises(ValueError):decoder_contract(b'ab',['data:-1'])
        with self.assertRaises(ValueError):decoder_contract(b'ab',['unknown'])


if __name__=='__main__':unittest.main()
