import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.nand_partition import Model,contract,native_vectors


def output_hash(prefix):return hashlib.sha256(prefix+b'\xa5'*(512-len(prefix))).hexdigest()


class NandPartitionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={c['name']:c for c in native_vectors()['cases']}
    def result(self,name):return self.cases[name]['expected']
    def row(self,name):return self.result(name)['rows'][0]
    def words(self,name):return struct.unpack_from('<4I',bytes.fromhex(self.row(name)['argument_hex']))

    def test_registry_lookup_returns_original_row_and_refreshes_chip_dimensions(self):
        row=self.row('lookup_registry')
        self.assertEqual((row['returned'],row['dimensions']),(0x80c33a74,[2048,32768,64]))
        self.assertEqual([a for a in self.result('lookup_registry')['actions'] if a.startswith('chip_ioctl:')],['chip_ioctl:2','chip_ioctl:1','chip_ioctl:3'])

    def test_unready_registry_falls_back_to_original_board_table(self):
        row=self.row('lookup_board_fallback')
        self.assertEqual(row['returned'],0x80c336b4)
        self.assertIn('log:registry_unready',self.result('lookup_board_fallback')['actions'])
        self.assertIn('board:nand_partition:1',self.result('lookup_board_fallback')['actions'])

    def test_missing_board_or_name_returns_zero_without_driver_queries(self):
        for name in ('lookup_board_missing','lookup_missing_name'):
            self.assertEqual(self.row(name)['returned'],0)
            self.assertFalse(any(a.startswith('chip_ioctl:') for a in self.result(name)['actions']))

    def test_missing_chip_state_rejects_lookup(self):
        self.assertEqual(self.row('lookup_chip_absent')['returned'],0)
        self.assertEqual(self.result('lookup_chip_absent')['actions'][-1],'log:chip_error')

    def test_failed_lookup_can_leave_partially_refreshed_global_geometry(self):
        row=self.row('lookup_partial_refresh')
        self.assertEqual((row['returned'],row['dimensions']),(0,[1024,32768,64]))
        self.assertEqual(self.result('lookup_partial_refresh')['actions'][-1],'injected_ioctl_error:1')

    def test_three_missing_dispatch_layers_all_stop_before_chip_ioctl(self):
        for state in ('root_missing','ops_missing','callback_missing'):
            name='lookup_'+state
            self.assertEqual(self.row(name)['returned'],0)
            self.assertFalse(any(a.startswith('chip_ioctl:') for a in self.result(name)['actions']))

    def test_partition_page_count_is_derived_locally_from_span(self):
        self.assertEqual(self.words('ioctl_partition_pages')[0],5632)
        self.assertEqual(self.result('ioctl_partition_pages')['actions'],[])
        self.assertEqual(self.row('ioctl_partition_pages')['returned'],0)

    def test_zero_declared_span_uses_remaining_chip_capacity(self):
        self.assertEqual(self.words('ioctl_derived_pages')[0],32256)
        self.assertEqual(self.row('read_derived_span')['returned'],0)

    def test_chip_page_count_and_partition_page_count_have_distinct_meanings(self):
        self.assertEqual(self.words('chip_page_count')[0],32768)
        self.assertEqual(self.words('ioctl_partition_pages')[0],5632)

    def test_null_handle_and_local_page_output_are_rejected(self):
        for name in ('ioctl_null_handle','ioctl_null_page_output','read_null_output'):
            self.assertEqual(self.row(name)['returned'],0xfffffff6)
            self.assertEqual(self.result(name)['actions'],[])

    def test_page_and_block_alignment_checks_reject_without_dispatch(self):
        for name in ('ioctl_bad_base','ioctl_bad_span','ioctl_bad_block_alignment','ioctl_format_bad_alignment'):
            self.assertEqual(self.row(name)['returned'],0xfffffff6)
            self.assertEqual(self.result(name)['actions'],[])

    def test_driver_ecc_positions_are_expanded_to_four_words(self):
        self.assertEqual(self.words('ioctl_ecc_positions'),(2,8,16,24))
        self.assertEqual(self.row('ioctl_ecc_positions')['returned'],0)

    def test_chip_absence_and_unknown_command_return_distinct_errors(self):
        self.assertEqual(self.row('ioctl_chip_absent')['returned'],0xfffffffe)
        self.assertEqual(self.row('ioctl_unknown')['returned'],0xfffffff7)

    def test_bad_and_erase_commands_rebase_block_index_in_temporary_storage(self):
        self.assertIn('bad:13:-9',self.result('ioctl_bad_block_rebase')['actions'])
        self.assertIn('erase:13:0',self.result('ioctl_erase_rebase')['actions'])
        self.assertEqual(self.words('ioctl_bad_block_rebase')[0],5)
        self.assertEqual(self.words('ioctl_erase_rebase')[0],5)

    def test_range_command_rebases_both_caller_page_words(self):
        self.assertEqual(self.words('ioctl_range_rebase'),(517,521,0x11111111,0x22222222))
        self.assertIn('range:517:521:286331153:572662306:0',self.result('ioctl_range_rebase')['actions'])

    def test_range_mutation_survives_backend_error_or_missing_dispatch(self):
        self.assertEqual(self.row('ioctl_range_error')['returned'],0xfffffff7)
        self.assertEqual(self.row('ioctl_range_missing_driver')['returned'],0xfffffffa)
        for name in ('ioctl_range_error','ioctl_range_missing_driver'):
            self.assertEqual(self.words(name)[:2],(517,521))

    def test_partition_format_ignores_all_supplied_erase_errors(self):
        actions=self.result('ioctl_format_ignores_errors')['actions']
        self.assertEqual([a for a in actions if a.startswith('erase:')],['erase:8:-9','erase:9:-9'])
        self.assertEqual(self.row('ioctl_format_ignores_errors')['returned'],0)

    def test_mark_error_is_forwarded_and_logged(self):
        self.assertEqual(self.row('chip_mark_error')['returned'],0xfffffff7)
        self.assertEqual(self.result('chip_mark_error')['actions'][-1],'log:chip_error')

    def test_read_dispatch_adds_partition_base_in_pages(self):
        self.assertEqual(self.result('read_rebased')['actions'],['dispatch_read:nand:519:3:32','page:generic:519:3:32:0'])
        data=bytes((519*13+(3+i)*7)&255 for i in range(32))
        self.assertEqual(self.row('read_rebased')['buffer_sha256'],output_hash(data))

    def test_read_preserves_negative_and_positive_service_status(self):
        self.assertEqual(self.row('read_error')['returned'],0xfffffff7)
        self.assertEqual(self.row('read_positive_status')['returned'],7)
        self.assertEqual(self.row('read_positive_status')['buffer_sha256'],self.row('read_rebased')['buffer_sha256'])

    def test_missing_read_callback_returns_minus_six(self):
        self.assertEqual(self.row('read_missing_driver')['returned'],0xfffffffa)
        self.assertEqual(self.result('read_missing_driver')['actions'],['dispatch_read:nand:519:3:32'])

    def test_selected_read_wrapper_does_not_check_requested_page_against_span(self):
        self.assertEqual(self.row('read_beyond_span')['returned'],0)
        self.assertEqual(self.result('read_beyond_span')['actions'][0],'dispatch_read:nand:10511:3:32')

    def test_zero_length_read_still_reaches_page_service(self):
        self.assertEqual(self.result('read_zero')['actions'][-1],'page:generic:519:3:0:0')
        self.assertEqual(self.row('read_zero')['buffer_sha256'],output_hash(b''))

    def test_geometry_collector_runs_actual_lookup_partition_and_chip_queries(self):
        context=bytes.fromhex(self.row('geometry_connected')['context_hex'])
        self.assertEqual(struct.unpack_from('<I',context)[0],0x80c33a74)
        self.assertEqual(struct.unpack_from('<5I',context,8),(64,2048,88,5632,512))
        self.assertEqual(struct.unpack_from('<7H',context,28),(64,8,2,2,8,16,24))

    def test_geometry_fallback_changes_only_collected_partition_pointer(self):
        first=bytes.fromhex(self.row('geometry_connected')['context_hex'])
        fallback=bytes.fromhex(self.row('geometry_fallback')['context_hex'])
        self.assertEqual(struct.unpack_from('<I',fallback)[0],0x80c336b4)
        self.assertEqual(first[4:],fallback[4:])

    def test_oob_read_uses_spare_column_then_segmented_ecc_extraction(self):
        self.assertIn('page:generic:519:2048:64:0',self.result('oob_segmented')['actions'])
        self.assertEqual(self.row('oob_segmented')['buffer_sha256'],output_hash(bytes((105,112,147,154))))

    def test_contiguous_ecc_uses_second_position_word(self):
        self.assertEqual(self.row('extract_contiguous')['buffer_sha256'],output_hash(bytes((47,52,57,62))))
        self.assertFalse(any(a.startswith('copy:') for a in self.result('extract_contiguous')['actions']))

    def test_fast_oob_route_adds_base_page_and_matches_generic_bytes(self):
        self.assertIn('page:fast:519:2048:64:0',self.result('oob_fast')['actions'])
        self.assertEqual(self.row('oob_fast')['buffer_sha256'],self.row('oob_segmented')['buffer_sha256'])

    def test_nonzero_oob_service_status_skips_extraction(self):
        for name,status in (('oob_error',0xfffffff7),('oob_positive_status',7)):
            self.assertEqual(self.row(name)['returned'],status)
            self.assertEqual(self.row(name)['buffer_sha256'],output_hash(b''))
            self.assertFalse(any(a.startswith('copy:') for a in self.result(name)['actions']))

    def test_supplied_partial_spare_copy_can_leave_stale_extracted_bytes(self):
        self.assertEqual(self.row('oob_short_supplied_read')['returned'],0)
        self.assertEqual(self.row('oob_short_supplied_read')['buffer_sha256'],output_hash(bytes((105,22,47,52))))

    def test_segmented_extraction_reads_noncontiguous_positions(self):
        self.assertEqual(self.result('extract_segmented')['actions'],['copy:0:2050:2','copy:2:2056:2'])
        self.assertEqual(self.row('extract_segmented')['buffer_sha256'],output_hash(bytes((17,22,47,52))))

    def test_marker_zero_position_skips_first_two_bytes(self):
        self.assertEqual(self.result('extract_skip_marker')['actions'][0],'copy:0:2050:0')
        self.assertEqual(self.row('extract_skip_marker')['buffer_sha256'],output_hash(bytes((47,52,87,92))))

    def test_unit_one_with_zero_position_wraps_subtraction_before_clipping(self):
        self.assertEqual(self.result('extract_unit_one_zero_position')['actions'],['copy:0:2050:4'])
        self.assertEqual(self.row('extract_unit_one_zero_position')['buffer_sha256'],output_hash(bytes((17,22,27,32))))

    def test_zero_unit_returns_zero_after_four_empty_copies(self):
        self.assertEqual(len(self.result('extract_zero_unit')['actions']),4)
        self.assertEqual((self.row('extract_zero_unit')['returned'],self.row('extract_zero_unit')['buffer_sha256']),(0,output_hash(b'')))

    def test_insufficient_ecc_stops_before_assertion_body(self):
        row=self.row('extract_insufficient_ecc')
        self.assertIsNone(row['returned'])
        self.assertEqual(row['stopped'],dict(kind='assertion',line=0x48))

    def test_packing_clears_spare_and_places_four_input_bytes(self):
        model=Model(copy.deepcopy(self.cases['pack_segmented']));model.run()
        self.assertEqual(model.scratch[2050:2052],bytes((1,0)))
        self.assertEqual(model.scratch[2056:2058],bytes((0x45,0x46)))
        self.assertEqual(model.scratch[2048:2050],b'\xff'*2)
        self.assertEqual(model.scratch[2052:2056],b'\xff'*4)
        self.assertEqual(self.row('pack_segmented')['buffer_sha256'],output_hash(bytes((1,0,0x45,0x46))))

    def test_contiguous_packing_uses_same_second_position_as_reader(self):
        model=Model(copy.deepcopy(self.cases['pack_contiguous']));model.run()
        self.assertEqual(model.scratch[2056:2060],bytes((1,0,0x45,0x46)))
        self.assertFalse(any(a.startswith('pack_copy:') for a in self.result('pack_contiguous')['actions']))

    def test_packing_marker_skip_matches_extractor(self):
        model=Model(copy.deepcopy(self.cases['pack_skip_marker']));model.run()
        self.assertEqual(model.scratch[2056:2058],bytes((1,0)))
        self.assertEqual(model.scratch[2064:2066],bytes((0x45,0x46)))

    def test_zero_unit_packing_fills_spare_but_writes_no_record(self):
        model=Model(copy.deepcopy(self.cases['pack_zero_unit']));model.run()
        self.assertEqual(model.scratch[2048:2112],b'\xff'*64)
        self.assertEqual(self.row('pack_zero_unit')['returned'],0)

    def test_packing_assert_occurs_after_spare_fill(self):
        row=self.row('pack_insufficient_ecc')
        self.assertEqual(row['stopped'],dict(kind='assertion',line=0x70))
        self.assertEqual(self.result('pack_insufficient_ecc')['actions'],['spare_fill:2048:64'])

    def test_pack_extract_roundtrips_all_selected_layouts(self):
        for name in ('roundtrip_segmented','roundtrip_contiguous','roundtrip_marker_skip'):
            self.assertEqual((self.row(name)['returned'],self.row(name)['buffer_sha256']),(0,output_hash(bytes((1,0,0x45,0x46)))))

    def test_fixture_bounds_reject_unmapped_source_and_bad_input_length(self):
        for changes in (dict(positions=[63,8,16,24]),dict(size=513),dict(pack_data=[1,2])):
            with self.assertRaises(ValueError):contract(copy.deepcopy(self.cases['extract_segmented'])|changes)

    def test_public_native_observations_match_every_case(self):
        report=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-partition.json').read_bytes());execution=report['native_validation']
        self.assertIs(execution['hardware_execution'],False)
        self.assertEqual((execution['case_count'],len(execution['cases'])),(58,58))
        for row,case in zip(execution['cases'],self.cases.values()):
            self.assertEqual(row['name'],case['name']);self.assertEqual(row['observed'],case['expected'])
            self.assertTrue(0<row['steps']<=execution['bound_per_case'])
        self.assertEqual(report['native_steps'],sum(r['steps'] for r in execution['cases']))
        self.assertEqual((len(report['export_sha256']),len(report['byte_range_sha256'])),(11,11))


if __name__=='__main__':unittest.main()
