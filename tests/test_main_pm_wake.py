import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_pm_wake as pm
from analysis_scripts import main_trap_irq as trap


class SyntheticMemory:
    def __init__(self, base, data):
        self.base, self.blob = base, bytes(data)

    def read(self, address, size):
        offset = address - self.base
        if offset < 0 or offset + size > len(self.blob):
            raise struct.error('outside fixture')
        return self.blob[offset:offset + size]


class MainPmWakeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = pm.native_vectors()
        cls.cases = {c['name'].removeprefix('main_pm_wake_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-pm-wake.json').read_bytes())

    def row(self, name, index=-1):
        return self.cases[name]['expected']['rows'][index]

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def word_at(self, name, address):
        for start, data in self.row(name)['snapshot'].items():
            start = int(start)
            if start <= address < start + len(data) // 2:
                return struct.unpack_from('<I', bytes.fromhex(data), address - start)[0]
        raise KeyError(hex(address))

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (13, 13, pm.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_pm_wake_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= pm.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_pm_ranges_and_reuse_trap_plic(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in pm.CODE}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        guards = trap.CODE + trap.DATA + pm.CODE
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])
        for case in self.vectors['cases']:
            self.assertEqual(case['ranges'], [[a, a + n] for a, n, _ in pm.CODE + trap.CODE])

    def test_gate_reads_config_csr_field_bits_six_to_eight(self):
        self.assertEqual(self.row('gate_field_zero')['a0'], 1)
        self.assertEqual(self.row('gate_field_bit6')['a0'], 0)
        self.assertEqual(self.row('gate_field_bit8')['a0'], 0)
        self.assertEqual(self.row('gate_field_full')['a0'], 0)
        # only bits 6..8 matter: high bits set but the field clear still gates on.
        self.assertEqual(self.row('gate_field_high_bits_only')['a0'], 1)
        self.assertEqual(self.actions('gate_field_zero'),
                         ['op:gate', f'csr:{pm.CFG_CSR}:0:0'])
        self.assertEqual(self.evidence['config_csr'], '0xfc1')

    def test_reregistration_points_three_sources_at_ram_handlers_when_gated(self):
        for irq in (0xb, 0xc, 0xe):
            entry = pm.EXTERNAL_TABLE + 16 * irq
            self.assertEqual(self.word_at('rereg_gate_on', entry), pm.RAM_HANDLERS[irq])
            self.assertEqual(self.word_at('rereg_gate_on', entry + 8), 1)       # enabled word
            self.assertEqual(self.word_at('rereg_gate_on', pm.PLIC_PRIORITY + 4 * irq), 1)
        enable = struct.unpack('<3I', bytes.fromhex(self.row('rereg_gate_on')['snapshot'][str(pm.PLIC_ENABLE)]))
        self.assertEqual(enable[0], (1 << 0xb) | (1 << 0xc) | (1 << 0xe))
        # gate off: nothing is written at all.
        self.assertEqual(self.word_at('rereg_gate_off', pm.EXTERNAL_TABLE + 16 * 0xe), 0x80d41188)
        self.assertEqual([a for a in self.actions('rereg_gate_off') if a.startswith('w:')], [])

    def test_wake_body_pokes_and_restores_clock_and_pm_registers(self):
        name = 'wake_preserves_other_bits'
        writes = [a for a in self.actions(name) if a.startswith('w:')]
        control = f'w:{pm.PM_CONTROL}:4:'
        self.assertTrue(writes[0].startswith(control))
        # control is set to (orig & ~0x1f0)|0x70, then restored to its original value last.
        self.assertEqual(writes[0], f'w:{pm.PM_CONTROL}:4:{(0xffffffff & ~0x1f0) | 0x70}')
        self.assertEqual(writes[-1], f'w:{pm.PM_CONTROL}:4:{0xffffffff}')
        self.assertEqual(self.word_at(name, pm.PM_CONTROL), 0xffffffff)
        self.assertEqual(self.word_at(name, pm.PM_ENABLE), 0xffffffff & ~0x10)
        self.assertEqual(self.word_at(name, pm.CLOCK), 0xfffeffff)
        # the delay loop keeps the body bounded and touches no memory.
        self.assertTrue(0 < self.evidence['native_validation']['cases'][0]['steps'] <= pm.BOUND)
        self.assertEqual(self.evidence['wake_delay_iterations'], 10)
        self.assertEqual(self.word_at('wake_zero', pm.CLOCK), 0)

    def test_handler_runs_wake_only_when_status_bit_twelve_is_set(self):
        self.assertEqual(self.actions('handler_bit12_set_runs_wake')[1], f'r:{pm.PM_STATUS}:4:{1 << 12}')
        self.assertTrue(any(a.startswith(f'w:{pm.CLOCK}:') for a in self.actions('handler_bit12_set_runs_wake')))
        self.assertEqual([a for a in self.actions('handler_bit12_clear_returns') if a.startswith('w:')], [])
        self.assertEqual([a for a in self.actions('handler_other_bits_ignored') if a.startswith('w:')], [])
        self.assertEqual(self.row('handler_bit12_set_runs_wake')['a0'], 0)

    def test_evidence_records_deep_sleep_statically_only(self):
        sleep = self.evidence['deep_sleep']
        self.assertEqual((sleep['save'], sleep['restore']), ('0x80d34470', '0x80d343a0'))
        self.assertIn('wfi', sleep['note'])
        self.assertEqual(self.evidence['ram_handlers'],
                         {'0xb': '0x80d4202c', '0xc': '0x80d42018', '0xe': '0x80d42004'})

    def test_raw_decoder_confirms_handler_tail_jumps(self):
        # the three handlers each tail-jump to the wake body at offset +0xc.
        import zipfile
        from analysis_scripts.main_object_lifecycle import image_memory
        from analysis_scripts.main_freertos_kernel import direct_target
        memory = image_memory(zipfile.ZipFile('firmware/bip6-4.6.0.3.zip'))
        for handler in pm.HANDLERS:
            self.assertEqual(direct_target(memory, handler + 0xc), pm.WAKE)

    def test_contract_rejects_unknown_scope_and_unbounded_reads(self):
        case = dict(self.cases['gate_field_zero'])
        with self.assertRaises(ValueError):
            pm.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            pm.contract(dict(case, supplied={str(pm.PM_CONTROL): [0] * 25}))

    def test_vectors_are_reproducible(self):
        again = pm.native_vectors()
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.vectors, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
