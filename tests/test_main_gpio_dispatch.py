import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_gpio_dispatch as gpio
from analysis_scripts import main_trap_irq as trap


class MainGpioDispatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = gpio.native_vectors()
        cls.cases = {c['name'].removeprefix('main_gpio_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-gpio-dispatch.json').read_bytes())

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
                         (18, 18, gpio.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_gpio_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= gpio.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_ranges_and_reuse_trap(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in gpio.CODE + gpio.DATA}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        guards = trap.CODE + trap.DATA + gpio.CODE + gpio.DATA
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])

    def test_padmux_writes_one_nibble_in_selected_bank(self):
        # bank0 pin0: low nibble of 0x89abcdef -> 0xa.
        self.assertEqual(self.word_at('padmux_bank0_pin0', 0x91000080), 0x89abcdea)
        # bank1 pin5: nibble at (5&7)*4 = 20 bits -> clear 0xf<<20, set 0xa<<20.
        self.assertEqual(self.word_at('padmux_bank1_pin5', 0x91000090),
                         (0x89abcdef & ~(0xf << 20)) | (0xa << 20))
        # bank2 pin8 selects the second word of the bank (pin>>3 = 1).
        self.assertEqual(self.word_at('padmux_bank2_pin8', 0x910000a0 + 4), 0x89abcdea)
        # direct controller 0x9a00a000 uses bank 0x910000b0.
        self.assertEqual(self.word_at('padmux_direct_pin3', 0x910000b0),
                         (0x89abcdef & ~(0xf << 12)) | (0xa << 12))

    def test_padmux_bounds_and_base_selection(self):
        # the direct controller bounds the pin to <= 4: pin 5 writes nothing.
        self.assertEqual(self.writes('padmux_direct_pin_out_of_range'), [])
        self.assertEqual(self.word_at('padmux_direct_pin_out_of_range', 0x910000b0), 0x11111111)
        # an unknown controller base writes nothing.
        self.assertEqual(self.writes('padmux_unknown_base_ignored'), [])
        # a high pin index selects a higher word and leaves the first untouched.
        self.assertEqual(self.word_at('padmux_high_pin_selects_word', 0x91000080), 0)
        self.assertEqual(self.word_at('padmux_high_pin_selects_word', 0x91000080 + 4), 0x5 << 4)
        # only the addressed nibble changes.
        self.assertEqual(self.word_at('padmux_overwrites_only_nibble', 0x91000080),
                         (0xffffffff & ~(0xf << 4)) | (0x3 << 4))

    def test_dispatch_acknowledges_and_calls_registered_handler(self):
        self.assertEqual(self.writes('dispatch_no_pending'), [])
        self.assertEqual(self.calls('dispatch_no_pending'), [])
        name = 'dispatch_one_pending_registered'
        self.assertEqual(self.word_at(name, gpio.CTRL + 0x30), 1 << 5)
        self.assertEqual(self.calls(name), [f'call:{gpio.STUB}:{0xa0a0}:{0xb0b0}'])
        # an unregistered or handler-null pending bit is acknowledged-or-skipped without a call.
        self.assertEqual(self.calls('dispatch_pending_unregistered_bit'), [])
        self.assertEqual(self.calls('dispatch_registered_handler_null'), [])
        self.assertEqual(self.word_at('dispatch_registered_handler_null', gpio.CTRL + 0x30), 1 << 5)
        self.assertEqual(self.calls('dispatch_wrong_base_row_skipped'), [])

    def test_dispatch_traces_pending_and_bit_then_serves_bits_in_order(self):
        name = 'dispatch_one_pending_traced'
        self.assertEqual(self.word_at(name, gpio.TRACE_PENDING), 1 << 5)
        self.assertEqual(self.word_at(name, gpio.TRACE_BASE), gpio.CTRL)
        self.assertEqual(self.word_at(name, gpio.TRACE_BIT), 5)
        order = [a.split(':')[0] for a in self.actions(name) if a.startswith('w:')]
        trace_writes = [int(a.split(':')[1]) for a in self.actions(name) if a.startswith('w:')]
        self.assertEqual(trace_writes[0], gpio.TRACE_BASE)      # base is recorded before pending
        self.assertEqual(trace_writes[1], gpio.TRACE_PENDING)
        two = 'dispatch_two_pending_in_bit_order'
        self.assertEqual(self.calls(two), [f'call:{gpio.STUB}:{0x11}:{0x12}', f'call:{gpio.STUB}:{0x71}:{0x72}'])

    def test_shared_handler_wakes_then_dispatches(self):
        name = 'shared_wake_then_dispatch'
        # the wake poke restores the control register to its original value last.
        self.assertEqual(self.word_at(name, gpio.PM_CONTROL), 0xdeadbe00)
        self.assertEqual(self.word_at(name, gpio.PM_ENABLE), 0x00000001)
        self.assertEqual(self.word_at(name, gpio.CLOCK), 0x00000002)
        self.assertEqual(self.word_at(name, 0x91003000 + 0x30), 1 << 5)
        self.assertEqual(self.calls(name), [f'call:{gpio.STUB}:{0x1}:{0x2}'])
        # bit 12 clear: no wake writes, dispatch still runs.
        clear = 'shared_bit12_clear_dispatch_only'
        self.assertNotIn(f'w:{gpio.CLOCK}:4:65538', self.actions(clear))
        self.assertEqual(self.word_at(clear, 0x91004000 + 0x30), 1 << 5)
        # other base: never wakes even with bit 12 set, dispatch still runs.
        other = 'shared_other_base_dispatch_only'
        self.assertEqual(self.word_at(other, gpio.PM_CONTROL), 0xdeadbe00)
        self.assertEqual(self.word_at(other, 0x98005000 + 0x30), 1 << 5)

    def test_shared_handler_tail_calls_dispatcher_in_image(self):
        self.assertEqual(self.evidence['dispatcher'], '0x80d436b4')
        self.assertEqual(self.evidence['shared_handler'], '0x70293d50')
        self.assertEqual(self.evidence['callback_rows'], 16)
        self.assertEqual(self.evidence['callback_row_bytes'], '0x18')

    def test_contract_rejects_unknown_scope_and_unbounded(self):
        case = dict(self.cases['dispatch_no_pending'])
        with self.assertRaises(ValueError):
            gpio.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            gpio.contract(dict(case, operations=[]))

    def test_vectors_are_reproducible(self):
        again = gpio.native_vectors()
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.vectors, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
