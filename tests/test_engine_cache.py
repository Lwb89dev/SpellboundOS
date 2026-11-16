import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.engine_cache import (
    CB, HEAP, MAGIC, NODES, contract, eligible, engine, hr_initial, hr_result,
    native_vectors, u32,
)


class EngineCacheTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def test_duplicate_registration_preserves_order_and_allocates_once(self):
        result = self.cases['registry_duplicate']['expected']
        self.assertEqual([r['returned'] for r in result['registry']], [1, 1, 1, None, 1, None, 1])
        self.assertEqual(result['registry'][1]['callbacks'], [CB])
        self.assertEqual(result['registry'][2]['callbacks'], [CB, CB + 4])
        self.assertEqual([a for a in result['actions'] if a.startswith('listener:')],
                         ['listener:0', 'listener:1', 'listener:1'])
        self.assertEqual([a for a in result['actions'] if a.startswith('node_alloc:')],
                         ['node_alloc:0', 'node_alloc:1'])

    def test_removed_nodes_are_self_linked_before_free(self):
        result = self.cases['registry_duplicate']['expected']
        for i, actual in enumerate(result['node_sha256']):
            node = NODES + 0x100 * i
            expected = struct.pack('<4I', node, node, 0, CB + 4 * i)
            self.assertEqual(actual, hashlib.sha256(expected).hexdigest())

    def test_missing_and_null_callbacks_do_not_allocate(self):
        missing = self.cases['registry_missing']['expected']
        self.assertEqual([r['returned'] for r in missing['registry']], [0, 1, 0, 1])
        self.assertEqual(missing['actions'].count('log:unreg_missing'), 1)
        null = self.cases['registry_null']['expected']
        self.assertEqual(null['actions'], [])
        self.assertEqual([r['returned'] for r in null['registry']], [0, 0])

    def test_failed_allocation_does_not_insert_a_callback(self):
        result = self.cases['registry_allocation_failure']['expected']
        self.assertEqual(result['registry'][0], dict(returned=0, callbacks=[]))
        self.assertEqual(result['registry'][1], dict(returned=1, callbacks=[CB + 4]))
        self.assertEqual(result['actions'],
                         ['node_alloc_fail:0', 'log:reg_alloc', 'node_alloc:1', 'listener:1'])

    def test_registration_after_removal_allocates_a_new_node(self):
        result = self.cases['registry_reinsert']['expected']
        self.assertEqual(result['actions'],
                         ['node_alloc:0', 'free:node0', 'node_alloc:1', 'listener:0', 'free:node1'])

    def test_engine_gate_requires_exact_state_but_nonzero_flags(self):
        for state in (0, 1, 3, 255):
            self.assertFalse(eligible(engine(7, state=state), 0x8000))
        self.assertTrue(eligible(engine(7, enabled=2, cache=255), 0x8000))
        for changes in ({'enabled': 0}, {'cache': 0}, {'callback': False}, {'handle': False}):
            self.assertFalse(eligible(engine(7, **changes), 0x8000))

    def test_slot_30_is_skipped_and_slot_39_is_outside_iteration(self):
        result = self.cases['gate_index_boundaries']['expected']
        self.assertEqual([d['engine'] for d in result['deliveries']], [0, 7, 38])
        self.assertEqual(result['event_returned'], 1)

    def test_64_bit_intersection_and_private_field_are_independent(self):
        self.assertTrue(eligible(engine(7, mask=1 << 32), 1 << 32))
        self.assertFalse(eligible(engine(7, mask=1 << 32), 0x8000))
        self.assertEqual(len(self.cases['gate_high_type']['expected']['deliveries']), 1)
        private = self.cases['gate_private_field']
        wire = bytes.fromhex(private['wire_hex'])
        self.assertEqual(int.from_bytes(wire[15:17], 'little'), 0x1234)
        self.assertEqual(private['expected']['algorithm_calls'],
                         self.cases['pipeline_hr']['expected']['algorithm_calls'])

    def test_event_retains_buffer_until_destructor(self):
        result = self.cases['pipeline_hr']['expected']
        self.assertEqual((result['registration'], result['unregistration']), (1, 1))
        self.assertEqual((result['owner_after']['refs'], result['owner_after']['magic']), (1, MAGIC))
        self.assertEqual((result['final_heap']['refs'], result['final_heap']['magic']), (0, 0))
        self.assertEqual(result['actions'], ['node_alloc:0', 'buffer_alloc:88', 'event_alloc',
                         'post:39', 'packet:20', 'engine:7:20', 'algorithm:44', 'free:buffer', 'free:node0'])
        self.assertEqual(result['owner_after']['guard_sha256'], result['final_heap']['guard_sha256'])

    def test_event_allocation_failure_never_retains_or_posts(self):
        result = self.cases['pipeline_event_allocation_failure']['expected']
        self.assertEqual(result['actions'], ['node_alloc:0', 'buffer_alloc:88',
                         'event_alloc_fail', 'log:event_alloc', 'free:buffer', 'free:node0'])
        self.assertEqual(result['owner_after']['refs'], 0)
        self.assertIsNone(result['event_returned'])

    def test_registration_failure_does_not_run_listener(self):
        result = self.cases['pipeline_registration_failure']['expected']
        self.assertEqual((result['registration'], result['unregistration']), (0, 0))
        self.assertEqual(result['actions'],
                         ['node_alloc_fail:0', 'log:reg_alloc', 'buffer_alloc:88', 'free:buffer'])

    def test_outer_validity_survives_zero_and_overrun_record_prefixes(self):
        for name in ('pipeline_zero_record', 'pipeline_overrun_record'):
            result = self.cases[name]['expected']
            self.assertEqual(result['event_returned'], 1)
            self.assertEqual(result['deliveries'], [])
            self.assertEqual(result['algorithm_calls'], [])
            self.assertEqual(result['final_heap']['refs'], 0)

    def test_default_hr_state_matches_complete_independent_byte_fixture(self):
        expected = bytearray(188)
        expected[0x75] = 1
        expected[0x69:0x6c] = bytes([72, 1, 4])
        struct.pack_into('<I', expected, 0x60, 10)
        struct.pack_into('<I', expected, 0x64, 0x00010048)
        struct.pack_into('<I', expected, 0x50, 1)
        expected[0x48:0x4b] = bytes([72, 4, 1])
        self.assertEqual(self.cases['pipeline_hr']['expected']['hr_sha256'],
                         hashlib.sha256(expected).hexdigest())

    def test_pulse_limits_are_inclusive_and_rejected_results_still_update_last(self):
        for pulse, accepted in ((29, False), (30, True), (220, True), (221, False)):
            c = self.cases['hr_pulse_' + str(pulse)]
            data = hr_initial(c)
            hr_result(data, c)
            self.assertEqual(list(data[0x69:0x6c]), [pulse, 1, 4])
            self.assertEqual(u32(data, 0x64), (0x10000 | pulse) if accepted else 0)
            self.assertEqual(data[0x4a], int(accepted))

    def test_quality_three_rejects_accumulation_and_seven_sets_success(self):
        rejected = self.cases['hr_quality_3']
        data = hr_initial(rejected)
        self.assertEqual(hr_result(data, rejected), [])
        self.assertEqual(list(data[0x69:0x6c]), [72, 1, 3])
        self.assertEqual(u32(data, 0x64), 0)
        success = self.cases['hr_quality_7']
        data = hr_initial(success)
        self.assertEqual(hr_result(data, success), ['log:period_success'])
        self.assertEqual(data[0x4a], 2)

    def test_manual_threshold_does_not_increment_counter(self):
        c = self.cases['hr_manual_threshold']
        for counter, status in ((9, 1), (10, 2), (11, 2)):
            variant = c | dict(counter=counter)
            data = hr_initial(variant)
            self.assertEqual(hr_result(data, variant), [])
            self.assertEqual(data[0x4a], status)
            self.assertEqual(u32(data, 0x5c), counter)
        success = self.cases['hr_manual_success']
        self.assertEqual(hr_result(hr_initial(success), success), ['log:manual_success'])

    def test_control_marker_requires_accepted_output_and_selected_bits(self):
        c = self.cases['pipeline_hr']
        for control, quality, marker in ((1, 4, 0), (2, 4, 1), (4, 4, 1), (2, 3, 0)):
            variant = c | dict(control=control, quality=quality)
            data = hr_initial(variant)
            hr_result(data, variant)
            self.assertEqual(data[0x76], marker)

    def test_sum_and_count_wrap_independently_with_full_temporary_count(self):
        c = self.cases['hr_aggregate_wrap']
        data = hr_initial(c)
        hr_result(data, c)
        self.assertEqual(u32(data, 0x64), 70)
        self.assertEqual(u32(data, 0x50), 65536)

    def test_disabled_missing_and_mask_mismatched_algorithms_leave_state_unchanged(self):
        for name in ('hr_disabled', 'algorithm_disabled', 'algorithm_missing', 'algorithm_mask_mismatch'):
            c = self.cases[name]
            self.assertEqual(c['expected']['algorithm_calls'], [])
            self.assertEqual(c['expected']['hr_sha256'], hashlib.sha256(hr_initial(c)).hexdigest())
        self.assertIn('log:algorithm_missing', self.cases['algorithm_missing']['expected']['actions'])

    def test_ready_flag_controls_processing_even_when_backend_reports_error(self):
        absent = self.cases['algorithm_result_absent']
        self.assertEqual(absent['expected']['hr_sha256'], hashlib.sha256(hr_initial(absent)).hexdigest())
        error = self.cases['algorithm_error_ready']['expected']
        self.assertIn('log:algorithm_error', error['actions'])
        self.assertEqual(error['hr_sha256'], self.cases['pipeline_hr']['expected']['hr_sha256'])
        self.assertEqual(error['algorithm_calls'],
                         [dict(descriptor=HEAP + 44, type=0x8000, payload=HEAP + 84, tag=0x100d)])

    def test_multi_packet_accumulates_once_per_matching_descriptor(self):
        c = self.cases['pipeline_multi']
        result = c['expected']
        self.assertEqual(len(result['algorithm_calls']), 4)
        expected = hr_initial(c)
        struct.pack_into('<I', expected, 0x64, (4 << 16) | (4 * 72))
        struct.pack_into('<I', expected, 0x50, 4)
        expected[0x48:0x4b] = bytes([72, 4, 1])
        expected[0x69:0x6c] = bytes([72, 1, 4])
        self.assertEqual(result['hr_sha256'], hashlib.sha256(expected).hexdigest())

    def test_public_native_observations_match_all_reviewed_fixtures(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/engine-cache.json'
        report = json.loads(path.read_text())
        observed = report['native_validation']
        self.assertFalse(observed['hardware_execution'])
        self.assertEqual(observed['case_count'], 40)
        self.assertEqual(len(observed['cases']), len(self.cases))
        for row in observed['cases']:
            self.assertEqual(row['observed'], self.cases[row['name']]['expected'])
            self.assertTrue(0 < row['steps'] <= 100000)
        self.assertEqual(report['native_steps'], sum(row['steps'] for row in observed['cases']))

    def test_host_model_rejects_out_of_scope_inputs(self):
        c = self.cases['pipeline_hr']
        with self.assertRaises(ValueError):
            contract(c | dict(pulse=256))
        with self.assertRaises(ValueError):
            contract(c | dict(kind='unknown'))
        with self.assertRaises(ValueError):
            contract(c | dict(wire_hex='1500000000'))


if __name__ == '__main__':
    unittest.main()
