import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_gpio_register as reg
from analysis_scripts import main_trap_irq as trap


class MainGpioRegisterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = reg.native_vectors()
        cls.cases = {c['name'].removeprefix('main_gpio_reg_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-gpio-register.json').read_bytes())

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
        return [a for a in self.actions(name) if a.startswith('w:')]

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (12, 12, reg.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_gpio_reg_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= reg.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_ranges_and_reuse_trap(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in reg.CODE + reg.DATA}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        guards = trap.CODE + trap.DATA + reg.CODE + reg.DATA
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])

    def test_fresh_row_written_with_full_layout(self):
        name = 'fresh_mode3'
        row = bytes.fromhex(self.row(name)['snapshot'][str(reg.CALLBACK_TABLE)])
        self.assertEqual(struct.unpack_from('<I', row, 0)[0], reg.CTRL)    # base
        self.assertEqual(struct.unpack_from('<I', row, 4)[0], 5)           # bit
        self.assertEqual(struct.unpack_from('<I', row, 8)[0], 0xa0a0)      # arg0
        self.assertEqual(row[0xc], 3)                                       # mode byte
        self.assertEqual(struct.unpack_from('<I', row, 0x10)[0], 0x70001000)  # handler
        self.assertEqual(struct.unpack_from('<I', row, 0x14)[0], 0xb0b0)   # arg1
        self.assertEqual(self.row(name)['a0'], 0)

    def test_ctz_maps_pin_mask_to_bit_index(self):
        row = bytes.fromhex(self.row('fresh_high_bit')['snapshot'][str(reg.CALLBACK_TABLE)])
        self.assertEqual(struct.unpack_from('<I', row, 4)[0], 30)
        self.assertEqual(self.evidence['ctz_helper'], '0x7094514c')

    def test_trigger_modes_program_three_controller_bits(self):
        bit = 1 << 5
        for mode, (b38, b34, b3c) in reg.MODES.items():
            name = 'fresh_mode%d' % mode
            if name not in self.cases:
                continue
            self.assertEqual(self.word_at(name, reg.CTRL + 0x38), bit if b38 else 0)
            self.assertEqual(self.word_at(name, reg.CTRL + 0x34), bit if b34 else 0)
            self.assertEqual(self.word_at(name, reg.CTRL + 0x3c), bit if b3c else 0)
        # every mode enables the pin and clears its disable-mask bit.
        self.assertEqual(self.word_at('fresh_mode1', reg.CTRL + 0x2c), bit)
        self.assertEqual(self.word_at('fresh_mode1', reg.CTRL + 0x20), 0)

    def test_handshake_value_follows_gate(self):
        self.assertIn(f'w:{reg.HANDSHAKE}:4:1', self.actions('fresh_mode1'))   # gate 0
        self.assertIn(f'w:{reg.HANDSHAKE}:4:2', self.actions('fresh_high_bit'))  # gate 1
        self.assertIn(f'w:{reg.HANDSHAKE}:4:0', self.actions('fresh_mode1'))   # release

    def test_existing_row_updated_not_duplicated(self):
        name = 'update_existing_handler'
        row0 = bytes.fromhex(self.row(name)['snapshot'][str(reg.CALLBACK_TABLE)])
        row1 = bytes.fromhex(self.row(name)['snapshot'][str(reg.CALLBACK_TABLE + reg.ROW)])
        self.assertEqual(struct.unpack_from('<I', row0, 0x10)[0], 0x70002000)   # handler updated in place
        self.assertEqual(struct.unpack_from('<I', row0, 0x14)[0], 0xcccc)       # arg1 updated
        self.assertEqual(row1, bytes(reg.ROW))                                  # second row untouched
        # same handler: no row field write at all, still reconfigures.
        same = 'existing_same_handler_reconfigures'
        self.assertFalse(any(a.startswith(f'w:{reg.CALLBACK_TABLE}:') for a in self.actions(same)))
        self.assertTrue(any(a.startswith(f'w:{reg.CTRL + 0x2c}:') for a in self.actions(same)))

    def test_first_free_row_after_occupied(self):
        row2 = bytes.fromhex(self.row('first_free_row_after_occupied')['snapshot'][str(reg.CALLBACK_TABLE + reg.ROW * 2)])
        self.assertEqual(struct.unpack_from('<I', row2, 0)[0], reg.CTRL)
        self.assertEqual(struct.unpack_from('<I', row2, 4)[0], 9)

    def test_state_nonzero_wraps_critical(self):
        name = 'state_nonzero_wraps_critical'
        self.assertIn(f'call:{reg.SAVE}:{reg.SAVED_FLAG}', self.actions(name))
        self.assertIn(f'call:{reg.RESTORE}:0', self.actions(name))

    def test_invalid_mode_and_full_table_error_without_controller_writes(self):
        self.assertEqual(self.row('invalid_mode_returns_error')['a0'], 1)
        self.assertEqual(self.word_at('invalid_mode_returns_error', reg.CTRL + 0x2c), 0)
        self.assertEqual(self.row('full_table_no_free_row_errors')['a0'], 1)
        self.assertEqual(self.writes('full_table_no_free_row_errors'), [])

    def test_vectors_are_reproducible(self):
        again = reg.native_vectors()
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.vectors, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
