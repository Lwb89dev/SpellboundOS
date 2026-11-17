import hashlib
import json
from pathlib import Path
import struct
import unittest
import zlib

from analysis_scripts.recovery_validator import (
    KEY_HASH, Model, contract, crc, file_bytes, metadata_bytes, native_vectors, raw_crc, table,
)


class RecoveryValidatorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def test_standard_and_raw_crc_known_vectors(self):
        self.assertEqual(crc(b'123456789'), 0xcbf43926)
        self.assertEqual(raw_crc(b'123456789'), 0x340bc6d9)
        self.assertEqual(raw_crc(b''), 0xffffffff)
        self.assertEqual(crc(b''), 0)
        self.assertEqual(crc(bytes(range(256))), zlib.crc32(bytes(range(256))))

    def test_crc_seed_can_be_continued_across_chunks(self):
        data = bytes(range(256)) * 3
        first = raw_crc(data[:173], 0x12345678)
        self.assertEqual(raw_crc(data[173:], first), raw_crc(data, 0x12345678))
        first = crc(data[:173], 0x12345678)
        self.assertEqual(crc(data[173:], first), crc(data, 0x12345678))

    def test_table_and_recovery_header_use_raw_crc_without_final_inversion(self):
        values = struct.unpack('<256I', table())
        self.assertEqual(values[:4], (0, 0x77073096, 0xee0e612c, 0x990951ba))
        data = file_bytes(self.cases['partition_selector_0'])
        checksum = int.from_bytes(data[68:72], 'little')
        self.assertEqual(checksum, zlib.crc32(data[:68]) ^ 0xffffffff)
        self.assertNotEqual(checksum, zlib.crc32(data[:68]))

    def test_missing_ota_property_logs_but_does_not_abort_policy(self):
        result = self.result('metadata_no_ota')
        self.assertEqual(result['returned'], 1)
        self.assertEqual(result['actions'],
                         ['board:ota', 'log:ota_absent', 'board:hw', 'log:hw_unknown'])

    def test_hardware_major_matches_and_metadata_minor_must_be_at_least_board_minor(self):
        self.assertEqual(self.result('metadata_hw_33_33')['returned'], 1)
        self.assertEqual(self.result('metadata_hw_33_34')['returned'], 1)
        old = self.result('metadata_hw_34_33')
        other = self.result('metadata_hw_33_49')
        self.assertEqual((old['returned'], other['returned']), (0, 0))
        self.assertIn('log:error:ba', old['actions'])
        self.assertIn('log:error:b4', other['actions'])
        self.assertEqual(self.result('metadata_valid')['returned'], 1)
        self.assertIn('log:hw_unknown', self.result('metadata_valid')['actions'])

    def test_main_variant_is_checked_while_selected_recovery_variant_is_ignored(self):
        self.assertEqual(self.result('metadata_recovery_variant_ignored')['returned'], 1)
        self.assertEqual(self.result('metadata_main_valid')['returned'], 1)
        self.assertEqual(self.result('metadata_main_variant')['returned'], 0)
        self.assertIn('log:product', self.result('metadata_main_variant')['actions'])
        self.assertEqual(self.result('metadata_product')['returned'], 0)
        self.assertEqual(self.result('metadata_magic')['returned'], 0)

    def test_selected_policy_does_not_validate_metadata_size_or_body_size(self):
        c = self.cases['metadata_size_body_ignored']
        raw = metadata_bytes(c)
        self.assertEqual(int.from_bytes(raw[8:10], 'little'), 64)
        self.assertEqual(int.from_bytes(raw[10:14], 'little'), 0xffffffff)
        self.assertEqual(c['expected']['returned'], 1)
        self.assertEqual(self.result('image_size_field_ignored')['returned'], 1)

    def test_signature_size_guard_precedes_partition_reads(self):
        for n in (0, 64):
            result = self.result('signature_size_' + str(n))
            self.assertEqual(result['returned'], 0)
            self.assertEqual(result['actions'], ['log:signature_short'])
        result = self.result('signature_size_65')
        self.assertIn('sha:update:1', result['actions'])
        self.assertEqual(result['returned'], 1)

    def test_hash_chunk_boundaries_do_not_add_empty_final_chunks(self):
        for n, expected in ((4159, [4095]), (4160, [4096]), (4161, [4096, 1]), (8256, [4096, 4096])):
            actions = self.result('signature_size_' + str(n))['actions']
            sizes = [int(a.split(':')[2]) for a in actions if a.startswith('sha:update:')]
            self.assertEqual(sizes, expected)

    def test_hash_includes_metadata_and_excludes_exact_final_64_signature_bytes(self):
        c = self.cases['image_valid']
        data = bytes.fromhex(c['input_hex'])[4096:]
        crypto = c['expected']['crypto'][0]
        self.assertEqual(crypto['digest_hex'], hashlib.sha256(data[:-64]).hexdigest())
        self.assertEqual(crypto['signature_sha256'], hashlib.sha256(data[-64:]).hexdigest())
        self.assertNotEqual(crypto['digest_hex'], hashlib.sha256(data[:-112]).hexdigest())
        self.assertEqual((crypto['length'], crypto['curve']), (32, 0x80c3f378))

    def test_embedded_key_matches_prior_host_signature_evidence(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/ota-signatures.json'
        prior = json.loads(path.read_text())
        self.assertEqual(hashlib.sha256(bytes.fromhex(prior['public_key_xy_hex'])).hexdigest(), KEY_HASH)
        self.assertEqual(self.result('image_valid')['crypto'][0]['key_sha256'], KEY_HASH)

    def test_hash_read_buffer_is_released_before_ecdsa_bridge(self):
        actions = self.result('signature_size_4160')['actions']
        self.assertLess(actions.index('sha:final'), actions.index('free:4096'))
        self.assertLess(actions.index('free:4096'), actions.index('crypto'))
        failed = self.result('signature_alloc_failure')
        self.assertEqual(failed['returned'], 0)
        self.assertNotIn('sha:init', failed['actions'])
        self.assertNotIn('crypto', failed['actions'])

    def test_callback_reports_hashed_progress_against_size_including_signature(self):
        actions = self.result('signature_callback')['actions']
        self.assertEqual([a for a in actions if a.startswith('progress:')],
                         ['progress:4096:4161', 'progress:4097:4161'])

    def test_short_signature_read_still_reaches_verifier_with_partial_fixture(self):
        c = self.cases['signature_short_signature']
        expected = bytes.fromhex(c['input_hex'])[-64:-1] + b'\xa5'
        result = c['expected']
        self.assertEqual(result['returned'], 0)
        self.assertEqual(result['crypto'][0]['signature_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertIn('sha:final', result['actions'])
        self.assertIn('log:signature_rejected', result['actions'])

    def test_short_body_read_hashes_requested_count_with_unchanged_buffer_tail(self):
        c = self.cases['signature_short_body']
        source = bytes.fromhex(c['input_hex'])[4096:]
        expected = source[:4095] + b'\xa5' + source[:1]
        result = c['expected']
        self.assertEqual(result['crypto'][0]['digest_hex'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(result['returned'], 0)
        self.assertIn('sha:update:4096', result['actions'])
        self.assertIn('sha:update:1', result['actions'])

    def test_short_header_or_metadata_stops_before_hashing(self):
        for name, error in (('partition_header_short', 'log:error:2c2'),
                            ('image_metadata_short', 'log:error:24e')):
            result = self.result(name)
            self.assertEqual(result['returned'], 0)
            self.assertIn(error, result['actions'])
            self.assertEqual(result['crypto'], [])

    def test_partition_selector_names_and_invalid_selector_cleanup(self):
        for selector, name in ((0, 'recovery0'), (1, 'recovery1'), (8, 'recovery_ota')):
            result = self.result('partition_selector_' + str(selector))
            self.assertEqual(result['returned'], 1)
            self.assertIn('open:' + name, result['actions'])
            self.assertEqual(result['actions'][-2:], ['close', 'free:72'])
        bad = self.result('partition_selector_7')
        self.assertEqual(bad['actions'], ['alloc:72', 'log:error:2b1', 'free:72'])

    def test_partition_rejects_magic_crc_and_version_with_balanced_cleanup(self):
        for name, error in (('partition_magic', 'log:error:2c8'), ('partition_crc', 'log:error:2cf'),
                            ('partition_version_mismatch', 'log:error:2e9')):
            result = self.result(name)
            self.assertEqual(result['returned'], 0)
            self.assertIn(error, result['actions'])
            self.assertEqual(result['actions'][-2:], ['close', 'free:72'])
            self.assertTrue(all(a['freed'] for a in result['allocations']))
        self.assertEqual(self.result('partition_long_version')['returned'], 0)

    def test_image_version_copy_forces_terminator_and_can_be_omitted(self):
        expected = bytearray(b'\xa5' * 64)
        expected[:15] = b'2.3.1'.ljust(15, b'\0')
        self.assertEqual(self.result('image_valid')['output_sha256'], hashlib.sha256(expected).hexdigest())
        empty = hashlib.sha256(b'\xa5' * 64).hexdigest()
        self.assertEqual(self.result('image_no_output')['output_sha256'], empty)
        self.assertEqual(self.result('image_version_zero')['output_sha256'], empty)

    def test_outer_version_output_clamps_to_16_and_handles_capacity_one(self):
        one = bytearray(b'\xa5' * 64)
        one[0] = 0
        self.assertEqual(self.result('partition_output_1')['output_sha256'], hashlib.sha256(one).hexdigest())
        expected = bytearray(b'\xa5' * 64)
        expected[:16] = b'2.3.1'.ljust(16, b'\0')
        self.assertEqual(self.result('partition_output_20')['output_sha256'], hashlib.sha256(expected).hexdigest())

    def test_mandatory_wrapper_overrides_lower_level_verify_flag(self):
        low = self.result('partition_verify_disabled')
        wrapped = self.result('partition_wrapper_forces_verify')
        self.assertEqual((low['returned'], wrapped['returned']), (1, 0))
        self.assertEqual(low['crypto'], [])
        self.assertEqual(len(wrapped['crypto']), 1)
        self.assertIn('log:error:259', wrapped['actions'])
        self.assertIn('log:error:2e1', wrapped['actions'])
        self.assertEqual(self.result('partition_wrapper_valid')['returned'], 1)

    def test_nonzero_crypto_service_return_is_booleanized_by_actual_bridge(self):
        self.assertEqual(self.result('signature_nonzero_result')['returned'], 1)
        self.assertEqual(self.result('signature_rejected')['returned'], 0)
        self.assertEqual(self.result('partition_crypto_rejected')['returned'], 0)

    def test_host_scope_rejects_unbounded_output_or_image(self):
        c = self.cases['image_valid']
        for changes in ({'size': 16385}, {'output_len': 0}, {'version_len': 17}, {'magic': 'bad'}):
            with self.assertRaises(ValueError):
                contract(c | changes)

    def test_public_native_observations_match_reviewed_model(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/recovery-validator.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertFalse(native['hardware_execution'])
        self.assertEqual(native['case_count'], 62)
        self.assertEqual(len(native['cases']), len(self.cases))
        for row in native['cases']:
            self.assertEqual(row['observed'], self.result(row['name']))
            self.assertTrue(0 < row['steps'] <= 100000)
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))


if __name__ == '__main__':
    unittest.main()
