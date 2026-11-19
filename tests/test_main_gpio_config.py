import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_gpio_config as cfg
from analysis_scripts import main_trap_irq as trap


class MainGpioConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = cfg.native_vectors()
        cls.cases = {c['name'].removeprefix('main_gpio_cfg_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-gpio-config.json').read_bytes())

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

    def writes(self, name):
        out = []
        for a in self.actions(name):
            if a.startswith('w:'):
                _, at, size, value = a.split(':')
                out.append((int(at), int(value)))
        return out

    def calls(self, name):
        return [a for a in self.actions(name) if a.startswith('call:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (13, 13, cfg.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_gpio_cfg_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= cfg.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_ranges_and_reuse_trap(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in cfg.CODE + cfg.DATA}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        guards = trap.CODE + trap.DATA + cfg.CODE + cfg.DATA
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])

    def test_pull_writer_sets_two_bit_field_four_pins_per_register(self):
        # bank0 pin0: value & 0x30 placed at bits 4-5 of slot 0; 0x77777777 keeps bits 4-5 set.
        self.assertEqual(self.word_at('padcfg_bank0_pin0', 0x91000100), 0x77777777)
        # bank1 pin2: slot 2 at shift 16, field 0x30 << 16.
        self.assertEqual(self.word_at('padcfg_bank1_pin2', 0x91000120),
                         (0x77777777 & ~(0x30 << 16)) | (0x30 << 16))
        # bank2 pin4 selects the second register (pin >> 2 == 1), slot 0.
        self.assertEqual(self.word_at('padcfg_bank2_pin4', 0x91000140 + 4),
                         (0x77777777 & ~0x30) | 0x30)
        # direct controller 0x9a00a000 uses bank 0x91000160.
        self.assertEqual(self.word_at('padcfg_direct_pin1', 0x91000160),
                         (0x77777777 & ~(0x30 << 8)) | (0x30 << 8))

    def test_pull_writer_bounds_mask_and_base_selection(self):
        self.assertEqual(self.writes('padcfg_direct_out_of_range'), [])
        self.assertEqual(self.word_at('padcfg_direct_out_of_range', 0x91000160), 0x11111111)
        self.assertEqual(self.writes('padcfg_unknown_base'), [])
        # only bits 4-5 of the value survive; pin 3 -> slot 3 at shift 24.
        self.assertEqual(self.word_at('padcfg_value_masked_to_bits_4_5', 0x91000100),
                         (0xff & 0x30) << 24)

    def test_enable_acknowledges_and_commits_registered_pin(self):
        self.assertEqual(self.writes('enable_no_registered_rows'), [])
        name = 'enable_one_row_state_zero'
        self.assertEqual(self.word_at(name, cfg.CTRL + 0x30), 1 << 5)
        # disable mask clears the pin bit; the enable register sets it.
        self.assertEqual(self.word_at(name, cfg.CTRL + 0x20), 0xffffffff & ~(1 << 5))
        self.assertEqual(self.word_at(name, cfg.CTRL + 0x2c), 1 << 5)
        # final handshake write returns the register to zero.
        self.assertEqual(self.word_at(name, cfg.HANDSHAKE), 0)
        # state zero: no critical save/restore wrappers are called.
        self.assertNotIn(f'call:{cfg.SAVE}:{cfg.SAVED_FLAG}', self.calls(name))
        # gate and state are the two supplied callees.
        self.assertIn(f'call:{cfg.GATE}', self.calls(name))
        self.assertIn(f'call:{cfg.STATE}', self.calls(name))

    def test_enable_handshake_value_follows_gate(self):
        # gate 0 -> handshake value 1; gate set -> handshake value 2.
        self.assertIn(f'w:{cfg.HANDSHAKE}:4:1', self.actions('enable_one_row_state_zero'))
        self.assertIn(f'w:{cfg.HANDSHAKE}:4:2', self.actions('enable_one_row_gate_set_handshake_two'))

    def test_enable_wraps_critical_when_state_nonzero(self):
        name = 'enable_one_row_state_nonzero_wraps_critical'
        self.assertIn(f'call:{cfg.SAVE}:{cfg.SAVED_FLAG}', self.calls(name))
        self.assertIn(f'call:{cfg.RESTORE}:0', self.calls(name))
        self.assertEqual(self.word_at(name, cfg.CTRL + 0x2c), 1 << 7)

    def test_enable_skips_unregistered_rows_and_serves_each_controller(self):
        self.assertEqual(self.word_at('enable_skips_unregistered_rows', cfg.CTRL + 0x2c), 1 << 3)
        two = 'enable_two_rows_distinct_controllers'
        other = 0x81400100
        self.assertEqual(self.word_at(two, cfg.CTRL + 0x2c), 1 << 1)
        self.assertEqual(self.word_at(two, other + 0x2c), 1 << 30)
        self.assertEqual(self.word_at(two, other + 0x20), 0xffffffff & ~(1 << 30))
        # the second row has state nonzero, so only its commit is wrapped.
        self.assertEqual(self.calls(two).count(f'call:{cfg.SAVE}:{cfg.SAVED_FLAG}'), 1)

    def test_evidence_records_layout_and_supplied_callees(self):
        self.assertEqual(self.evidence['controller_fields'],
                         {'acknowledge': '0x30', 'disable_mask': '0x20', 'enable': '0x2c'})
        self.assertEqual(self.evidence['handshake_register'], '0x900080b0')
        self.assertEqual(self.evidence['pull_banks']['0x91003000'], '0x91000100')
        self.assertEqual(self.evidence['supplied_callees']['critical_save'], '0x80d379ee')

    def test_contract_rejects_unknown_scope(self):
        case = dict(self.cases['enable_no_registered_rows'])
        with self.assertRaises(ValueError):
            cfg.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            cfg.contract(dict(case, operations=[]))

    def test_vectors_are_reproducible(self):
        again = cfg.native_vectors()
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.vectors, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
