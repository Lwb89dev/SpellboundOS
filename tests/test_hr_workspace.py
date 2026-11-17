import hashlib
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts.hr_workspace import (
    CHILDREN, EXT_SIZE, HEAP, INPUT, ROOT_SIZE, SCRATCH, VIEWS, contract, native_vectors,
)


class HrWorkspaceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {c['name']: c for c in native_vectors()['cases']}

    def result(self, name):
        return self.cases[name]['expected']

    def test_workspace_allocation_inventory_and_sizes(self):
        result = self.result('workspace_init_only')
        allocated = result['rows'][0]['allocations']
        self.assertEqual(len(allocated), 78)
        self.assertEqual([a['size'] for a in allocated],
                         [ROOT_SIZE] + [size for _, size in CHILDREN] + [200] * 11)
        self.assertTrue(all(not a['freed'] for a in allocated))
        self.assertEqual([a['pointer'] for a in allocated], [HEAP + 0x10000 * i for i in range(78)])
        self.assertEqual(len(set(index for index, _ in CHILDREN)), 66)

    def test_root_links_all_children_and_sets_rate_and_mode_fields(self):
        root = bytearray(ROOT_SIZE)
        struct.pack_into('<H', root, 0x15a, 25)
        for i, (index, _) in enumerate(CHILDREN, start=1):
            struct.pack_into('<I', root, 4 * index, HEAP + 0x10000 * i)
        root[0x76] = 20
        self.assertEqual(self.result('workspace_init_only')['rows'][0]['allocations'][0]['sha256'],
                         hashlib.sha256(root).hexdigest())
        root[0x76] = 14
        self.assertEqual(self.result('workspace_mode4')['rows'][0]['allocations'][0]['sha256'],
                         hashlib.sha256(root).hexdigest())

    def test_exit_frees_every_allocation_exactly_once(self):
        result = self.result('workspace_cycle')
        frees = [int(a.split(':')[1]) for a in result['actions'] if a.startswith('free:')]
        self.assertEqual(len(frees), 78)
        self.assertEqual(sorted(frees), list(range(78)))
        self.assertEqual(frees[-1], 0)
        self.assertTrue(all(a['freed'] for a in result['rows'][-1]['allocations']))
        self.assertEqual(result['rows'][-1]['aux'], 1)
        self.assertEqual(result['actions'].count('boundary:setup'), 1)
        self.assertEqual(result['actions'].count('boundary:cleanup'), 1)

    def test_free_clears_root_pointers_and_preserves_nonpointer_fields(self):
        root = bytearray(ROOT_SIZE)
        struct.pack_into('<H', root, 0x15a, 25)
        root[0x76] = 20
        last = self.result('workspace_cycle')['rows'][-1]
        self.assertEqual(last['allocations'][0]['sha256'], hashlib.sha256(root).hexdigest())
        for a in last['allocations'][1:]:
            self.assertEqual(a['sha256'], hashlib.sha256(b'\xa5' * a['size']).hexdigest())

    def test_repeated_init_and_exit_are_noops(self):
        result = self.result('workspace_repeated')
        self.assertEqual(result['rows'][0], result['rows'][1])
        self.assertEqual(result['rows'][2], result['rows'][3])
        self.assertEqual(result['actions'].count('log:init'), 1)
        self.assertEqual(self.result('workspace_initialized_noop')['actions'], [])
        self.assertEqual(self.result('workspace_uninitialized_exit')['actions'], [])

    def test_restart_allocates_new_storage_and_frees_both_generations(self):
        result = self.result('workspace_restart')
        self.assertEqual(len(result['rows'][-1]['allocations']), 156)
        self.assertTrue(all(a['freed'] for a in result['rows'][-1]['allocations']))
        self.assertEqual(result['actions'].count('log:init'), 2)
        self.assertEqual(result['actions'].count('boundary:cleanup'), 2)
        self.assertEqual(result['rows'][2]['allocations'][78]['pointer'], HEAP + 78 * 0x10000)

    def test_primary_allocation_failure_does_not_run_setup_or_free(self):
        result = self.result('workspace_root_failure')
        self.assertEqual(result['actions'], ['log:init', 'alloc_fail:40388', 'log:backend_error'])
        self.assertEqual([r['returned'] for r in result['rows']], [1, 0])
        self.assertTrue(all(r['allocations'] == [] for r in result['rows']))

    def test_unsupported_types_clear_scratch_without_producing_output(self):
        for typ in (1, 0x8000, 1 << 32, 1 << 63):
            rows = self.result('unsupported_' + hex(typ))['rows']
            before, after = rows[:2]
            self.assertEqual(after['returned'], 0)
            self.assertEqual(before['output_sha256'], after['output_sha256'])
            self.assertEqual(after['allocations'][0], before['allocations'][0])
            for a in after['allocations'][-len(SCRATCH):]:
                self.assertEqual(a['sha256'], hashlib.sha256(bytes(200)).hexdigest())
            for a, b in zip(before['allocations'][1:67], after['allocations'][1:67]):
                self.assertEqual(a, b)

    def test_uninitialized_processing_returns_error_without_allocating(self):
        result = self.result('process_uninitialized')
        self.assertEqual(result['actions'], ['log:backend_error'])
        self.assertEqual(result['rows'][0]['returned'], 1)
        self.assertEqual(result['rows'][0]['allocations'], [])

    def test_extension_requires_exact_size_in_both_places(self):
        for case in self.cases.values():
            if len(case['operations']) != 1 or case['operations'][0]['op'] != 'extension':
                continue
            op = case['operations'][0]
            self.assertEqual(case['expected']['rows'][0]['returned'],
                             int(op['length'] == EXT_SIZE and op['header_size'] == EXT_SIZE))

    def test_extension_pointer_views_and_header_are_written_before_size_result(self):
        expected = bytearray(b'\x5a' * 104)
        expected[1:4] = bytes([11, 22, 33])
        struct.pack_into('<I', expected, 4, 0)
        for index, offset in enumerate(VIEWS):
            struct.pack_into('<I', expected, 8 + 4 * index, INPUT + offset)
        row = self.result('extension_0_0')['rows'][0]
        self.assertEqual(row['returned'], 0)
        self.assertEqual(row['extension_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(len(VIEWS), 24)
        self.assertEqual(VIEWS[-1], 0x17dd0)
        self.assertTrue(all(offset < EXT_SIZE for offset in VIEWS))

    def test_rejected_rebind_replaces_borrowed_pointer_metadata(self):
        result = self.result('extension_rebind')
        self.assertEqual([r['returned'] for r in result['rows']], [1, 0])
        self.assertNotEqual(result['rows'][0]['extension_sha256'], result['rows'][1]['extension_sha256'])
        self.assertEqual(result['actions'], ['log:extension', 'log:extension'])

    def test_host_scope_rejects_supported_signal_processing(self):
        c = self.cases['workspace_cycle'] | dict(operations=[dict(op='init'), dict(op='process', type=0x10)])
        with self.assertRaises(ValueError):
            contract(c)

    def test_public_native_observations_match_host_contract(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/hr-workspace.json'
        report = json.loads(path.read_text())
        native = report['native_validation']
        self.assertFalse(native['hardware_execution'])
        self.assertEqual(native['case_count'], 21)
        self.assertEqual(len(native['cases']), len(self.cases))
        for row in native['cases']:
            self.assertEqual(row['observed'], self.result(row['name']))
            self.assertTrue(0 < row['steps'] <= 100000)
        self.assertEqual(report['native_steps'], sum(r['steps'] for r in native['cases']))


if __name__ == '__main__':
    unittest.main()
