import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.hr_setup import (
    CLEAN_FIELDS, CONSTANTS, GLOBAL, HEAP, Model, clears, contract, native_vectors,
)


class HrSetupTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def test_clear_formulas_preserve_division_before_final_scaling(self):
        lengths = dict(clears(26))
        self.assertEqual(lengths[0], 2128)
        self.assertEqual(lengths[1], 248)
        self.assertEqual(lengths[12], 52)
        self.assertEqual(lengths[30], 208)
        self.assertEqual(lengths[34], 264)
        self.assertEqual(lengths[38], 1064)
        self.assertEqual(lengths[100], 31)
        self.assertEqual(len(lengths), 27)

    def test_rate_zero_still_issues_zero_length_clear_requests(self):
        case = self.cases['setup_rate_0']
        result = case['expected']
        self.assertTrue(all(n == 0 for _, n in clears(0)))
        self.assertTrue(all(a.endswith(':0') for a in result['actions'][:27]))
        self.assertEqual(result['allocation_sizes'][71:75], [0] * 4)
        self.assertEqual(result['allocation_sizes'][75:77], [0, 0])

    def test_standalone_fixtures_pad_buffers_and_clear_only_computed_prefix(self):
        c = self.cases['setup_rate_26']
        m = Model(c)
        m.fixture()
        m.setup()
        first = m.blocks[1]['data']
        self.assertEqual(first[:2128], bytes(2128))
        self.assertEqual(first[2128:], b'\xa5' * (4112 - 2128))
        self.assertEqual(len(first), 4112)

    def test_component_window_and_matrix_allocation_sizes(self):
        self.assertEqual(self.result('inner_rate_25')['allocation_sizes'][67:71], [76, 76, 76, 760])
        self.assertEqual(self.result('inner_rate_26')['allocation_sizes'][67:71], [76, 76, 76, 760])
        self.assertEqual(self.result('inner_rate_50')['allocation_sizes'][67:71], [148, 148, 148, 2812])

    def test_component_25_step_quantization_differs_from_linear_rate_scaling(self):
        self.assertEqual(self.result('inner_rate_24')['allocation_sizes'][71:75], [0, 0, 0, 0])
        self.assertEqual(self.result('inner_rate_26')['allocation_sizes'][71:75], [256, 256, 332, 332])
        self.assertEqual(self.result('inner_rate_50')['allocation_sizes'][71:75], [512, 512, 664, 664])

    def test_two_history_allocations_scale_to_rate(self):
        self.assertEqual(self.result('inner_rate_26')['allocation_sizes'][75:77], [624, 624])
        self.assertEqual(self.result('inner_rate_50')['allocation_sizes'][75:77], [1200, 1200])
        c = self.cases['inner_rate_26']
        m = Model(c)
        m.fixture()
        m.inner()
        self.assertEqual(m.blocks[0]['data'][0x3c4e], 78)

    def test_inner_initializer_sets_coefficients_and_exact_float_bits(self):
        m = Model(self.cases['inner_rate_25'])
        m.fixture()
        m.inner()
        root = m.blocks[0]['data']
        self.assertEqual(root[0xac:0xbc], struct.pack('<4f', 0.96, 0.8, 1.5, 0.95))
        self.assertEqual(root[0x138:0x13c], struct.pack('<f', -1.0))
        self.assertEqual(root[0x108:0x10c], struct.pack('<I', 0x41f2d07f))
        self.assertEqual(root[0x9c78:0x9c7c], struct.pack('<f', 0.0005))
        self.assertEqual(root[0x16e:0x173], bytes([1, 1, 1, 1, 1]))
        self.assertEqual(CONSTANTS[0x709c4e7c], struct.pack('<f', -1.0))

    def test_extra_workspace_clears_selected_windows_and_preserves_other_bytes(self):
        m = Model(self.cases['inner_rate_25'])
        m.fixture()
        m.inner()
        extra = m.blocks[77]['data']
        self.assertEqual(len(extra), 8188)
        expected = bytearray(b'\xa5' * 8188)
        for at, size in ((0, 4), (0x1580, 100), (0xfd4, 192), (0x1094, 440),
                         (0x1514, 96), (0x124c, 96), (0x12ac, 616), (0x1e7c, 384),
                         (0x15e4, 640), (0x1864, 520), (0x1a6c, 520), (0x1c74, 520),
                         (0x1574, 12)):
            expected[at:at + size] = bytes(size)
        self.assertEqual(extra, expected)
        self.assertEqual(self.result('inner_rate_25')['rows'][0]['allocation_sha256'][77],
                         hashlib.sha256(expected).hexdigest())

    def test_failed_extra_allocation_logs_and_owner_still_enables(self):
        failed = self.result('owner_extra_failure')
        normal = self.result('owner_cycle')
        self.assertIn('alloc_fail:8188', failed['actions'])
        self.assertIn('log:extra_alloc_failed', failed['actions'])
        self.assertEqual(failed['rows'][0]['returned'], 0)
        self.assertEqual(failed['rows'][0]['state_sha256'], normal['rows'][0]['state_sha256'])
        self.assertEqual(len(failed['allocation_sizes']), 88)
        self.assertEqual(failed['rows'][-1]['freed'], list(range(88)))

    def test_remaining_component_status_is_ignored(self):
        self.assertEqual(self.result('setup_component_status_ignored'), self.result('setup_rate_25'))

    def test_cleanup_null_calls_are_unconditional_for_four_slots(self):
        result = self.result('cleanup_mask_0')
        self.assertEqual(result['actions'], ['free:null'] * 4)
        self.assertEqual(result['rows'][0]['freed'], [])
        self.assertEqual(len(result['allocation_sizes']), 1)

    def test_cleanup_frees_each_seeded_slot_individually(self):
        for i in range(11):
            result = self.result('cleanup_mask_' + str(1 << i))
            self.assertEqual(result['rows'][0]['freed'], [1])
            self.assertEqual(result['actions'].count('free:1'), 1)
            self.assertEqual(result['actions'].count('free:null'), 3 if 6 <= i < 10 else 4)

    def test_cleanup_preserves_first_four_pointer_slots_and_clears_other_slots(self):
        root = bytearray(b'\x5a' * 0x9dc4)
        struct.pack_into('<H', root, 0x15a, 25)
        for i, at in enumerate(CLEAN_FIELDS):
            struct.pack_into('<I', root, at, HEAP + (i + 1) * 0x10000 if i < 4 else 0)
        result = self.result('cleanup_mask_2047')
        self.assertEqual(result['rows'][0]['allocation_sha256'][0], hashlib.sha256(root).hexdigest())
        self.assertEqual(result['rows'][0]['freed'], list(range(1, 12)))
        self.assertEqual(result['actions'], ['free:' + str(i) for i in range(1, 12)])

    def test_full_cycle_owns_89_allocations_and_frees_root_last(self):
        result = self.result('owner_cycle')
        self.assertEqual(len(result['allocation_sizes']), 89)
        self.assertEqual(sum(result['allocation_sizes']), 101108)
        self.assertEqual(result['rows'][-1]['freed'], list(range(89)))
        frees = [a for a in result['actions'] if a.startswith('free:')]
        self.assertEqual(len(frees), 89)
        self.assertEqual(frees[-1], 'free:0')
        self.assertEqual(result['rows'][-1]['aux'], 1)

    def test_nested_setup_explains_increment_over_previous_supplied_boundary(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/hr-workspace.json'
        old = json.loads(path.read_text())['native_validation']['cases']
        row = next(c for c in old if c['name'] == 'workspace_cycle')['observed']['rows'][0]
        self.assertEqual(sum(a['size'] for a in row['allocations']), 89556)
        self.assertEqual(sum(self.result('owner_cycle')['allocation_sizes']) - 89556, 11552)

    def test_repeated_calls_and_restart_keep_ownership_balanced(self):
        repeated = self.result('owner_repeated')
        self.assertEqual(repeated['rows'][0], repeated['rows'][1])
        self.assertEqual(repeated['rows'][2], repeated['rows'][3])
        restarted = self.result('owner_restart')
        self.assertEqual(len(restarted['allocation_sizes']), 178)
        self.assertEqual(restarted['rows'][-1]['freed'], list(range(178)))

    def test_mode_four_changes_limit_byte_after_shared_setup(self):
        normal = Model(self.cases['owner_cycle'])
        special = Model(self.cases['owner_mode4'])
        normal.owner_init()
        special.owner_init()
        a, b = normal.blocks[0]['data'], special.blocks[0]['data']
        self.assertEqual((a[0x75], a[0x76], b[0x75], b[0x76]), (1, 20, 1, 14))
        b[0x76] = 20
        self.assertEqual(a, b)

    def test_host_rate_scope_is_explicit(self):
        c = self.cases['setup_rate_25']
        with self.assertRaises(ValueError):
            contract(c | dict(rate=101))
        with self.assertRaises(ValueError):
            contract(c | dict(operations=['unknown']))

    def test_public_native_observations_match_model(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/hr-setup.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertFalse(native['hardware_execution'])
        self.assertEqual(native['case_count'], 37)
        self.assertEqual(len(native['cases']), len(self.cases))
        for row in native['cases']:
            self.assertEqual(row['observed'], self.result(row['name']))
            self.assertTrue(0 < row['steps'] <= 100000)
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))


if __name__ == '__main__':
    unittest.main()
