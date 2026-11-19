import copy
import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_trap_irq as trap


def frame_words(row):
    data = bytes.fromhex(row['snapshot'][str(trap.TASK_A_STACK - trap.FRAME)])
    return data


class SyntheticMemory:
    def __init__(self, base, data):
        self.base, self.blob = base, bytes(data)

    def read(self, address, size):
        offset = address - self.base
        if offset < 0 or offset + size > len(self.blob):
            raise struct.error('outside fixture')
        return self.blob[offset:offset + size]


class MainTrapIrqTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = trap.native_vectors()
        cls.cases = {c['name'].removeprefix('main_trap_irq_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-trap-irq.json').read_bytes())

    def expected(self, name):
        return self.cases[name]['expected']

    def actions(self, name):
        return self.expected(name)['actions']

    def row(self, name, index=-1):
        return self.expected(name)['rows'][index]

    def writes(self, name):
        out = []
        for action in self.actions(name):
            if action.startswith('w:'):
                _, at, size, value = action.split(':')
                out.append((int(at), int(size), int(value)))
        return out

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']), (57, 57, trap.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_trap_irq_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= trap.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_every_original_code_and_data_range(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in trap.CODE + trap.DATA}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in trap.CODE + trap.DATA])
        ranges = [[a, a + n] for a, n, _ in trap.CODE]
        for case in self.vectors['cases']:
            self.assertEqual(case['ranges'], ranges)
        self.assertEqual(self.evidence['ram_code_copy'], {'destination': '0x80d32e00', 'size': '0x14d38', 'source': '0x70dce45c'})

    def test_original_vector_tables_route_software_timer_external_and_syscall(self):
        self.assertEqual(self.evidence['core_vectors'], {'3': '0x80d4118c', '7': '0x80d37f42', '11': '0x80d35b24'})
        vectors = self.evidence['exception_vectors']
        self.assertEqual(len(vectors), 12)
        self.assertEqual(vectors[11], '0x702a4088')
        self.assertEqual(self.evidence['isr_stack_top'], '0x80e00000')
        self.assertIn('core/freertos/tasks.c', ''.join(self.evidence['freertos_strings'].values()))

    def test_recovered_registrations_bind_four_dma_controllers_to_one_handler(self):
        sites = self.evidence['registration_sites']
        self.assertEqual(len(sites), 18)
        dma = {(s['irq'], s['argument']) for s in sites if s['handler'] == '0x702a041c'}
        self.assertEqual(dma, {('0x12', '0x92000000'), ('0x16', '0x93000000'), ('0x19', '0x93040000'), ('0x1c', '0x93080000')})
        shared = sorted(s['irq'] for s in sites if s['handler'] == '0x70293d50')
        self.assertEqual(shared, ['0x2a', '0x2b', '0x2c', '0x2d', '0x9', '0xa'])
        self.assertEqual(sum(s['irq'] is None for s in sites), 2)

    def test_direct_ram_registrations_reregister_shared_sources(self):
        direct = self.evidence['direct_registration_sites']
        self.assertEqual(len(direct), 5)
        self.assertEqual(direct[0], dict(site='0x80d37e58', irq='0xe', handler='0x80d37e08', argument='0x00000000'))
        self.assertEqual(sorted(d['irq'] for d in direct), ['0xb', '0xc', '0xe', '0xe', '0xe'])
        far = {s['irq'] for s in self.evidence['registration_sites']}
        self.assertTrue({'0xb', '0xc'} <= far)

    def test_trap_frame_layout_saves_every_register_and_csr(self):
        case = self.cases['external_dma']
        data = frame_words(self.row('external_dma'))
        frame = trap.TASK_A_STACK - trap.FRAME
        regs = case['registers']
        self.assertEqual(struct.unpack_from('<I', data, 0)[0], 0)
        self.assertEqual(struct.unpack_from('<I', data, 8)[0], frame)
        for index, name in enumerate(trap.X):
            if index > 2:
                self.assertEqual(struct.unpack_from('<I', data, 4 * index)[0], regs[name], name)
        self.assertEqual(struct.unpack_from('<IIII', data, 0x80), (0x1880, trap.CODE_AREA, 0x21, 0x81100000))
        for i, name in enumerate(trap.F):
            self.assertEqual('%016x' % struct.unpack_from('<Q', data, 0x90 + 8 * i)[0], case['fregisters'][name])
        self.assertEqual(struct.unpack_from('<II', data, 0x190), (0x41, 0xa5a5a5a5))

    def test_entry_publishes_frame_to_current_task_and_brackets_handler_with_trap_flag(self):
        frame = trap.TASK_A_STACK - trap.FRAME
        writes = self.writes('external_dma')
        self.assertEqual(writes[0], (trap.TCB_A, 4, frame))
        self.assertEqual(writes[1], (trap.IN_TRAP, 4, 1))
        self.assertEqual(writes[-1], (trap.IN_TRAP, 4, 0))
        self.assertIn(f'call:{0x702a041c}:{0x93000000}', self.actions('external_dma'))
        self.assertIn(f'call:{trap.OUT_OF_TABLE_HANDLER}:1', self.actions('external_claim_past_table'))

    def test_nested_trap_stays_on_task_stack_and_clears_outer_trap_flag(self):
        self.assertEqual(self.row('external_nested')['snapshot'][str(trap.IN_TRAP)], '00000000')
        self.assertEqual(self.writes('external_nested')[1], (trap.IN_TRAP, 4, 1))
        self.assertEqual(self.writes('external_nested')[-1], (trap.IN_TRAP, 4, 0))

    def test_switch_resumes_the_new_tasks_frame_and_leaves_mscratch_holding_hsp_value(self):
        for name in ('external_switch', 'timer_switch', 'yield_ecall_switch'):
            row = self.row(name)
            self.assertEqual(row['stopped'], 'mret')
            self.assertEqual(row['registers']['sp'], trap.TASK_B_FRAME + trap.FRAME)
            self.assertEqual(row['registers']['ra'], (0x6b000000 + 0x01010101) & trap.MASK)
            self.assertEqual(row['csrs']['833'], trap.CODE_AREA + 0x40)
            self.assertEqual((row['csrs']['832'], row['csrs']['1990']), (0x21, 0x21))
            self.assertEqual(row['fregisters']['ft0'], '6b0000003f800000')
        own = self.row('external_dma')
        self.assertEqual(own['registers']['sp'], trap.TASK_A_STACK)
        self.assertEqual(own['csrs']['832'], 0x21)
        self.assertNotEqual(own['csrs']['832'], self.cases['external_dma']['csrs']['832'])

    def test_unregistered_and_zero_claims_stop_in_default_handler_without_completion(self):
        for name in ('external_unregistered', 'external_claim_zero'):
            self.assertEqual(self.row(name)['stopped'], 'default_handler')
            self.assertFalse(any(at == trap.PLIC_CLAIM for at, _, _ in self.writes(name)))
        self.assertIn((trap.PLIC_CLAIM, 4, 0x53), self.writes('external_claim_past_table'))

    def test_timer_reprograms_compare_then_advances_by_one_thousand(self):
        writes = [w for w in self.writes('timer_no_switch') if w[0] in (trap.MTIMECMP, trap.MTIMECMP + 4, trap.NEXT_COMPARE, trap.NEXT_COMPARE + 4)]
        self.assertEqual(writes, [(trap.MTIMECMP, 4, 0), (trap.MTIMECMP + 4, 4, 7), (trap.MTIMECMP, 4, 0x1000),
                                  (trap.NEXT_COMPARE, 4, 0x1000 + 1000), (trap.NEXT_COMPARE + 4, 4, 7)])
        carry = [w for w in self.writes('timer_compare_carry') if w[0] in (trap.NEXT_COMPARE, trap.NEXT_COMPARE + 4)]
        self.assertEqual(carry, [(trap.NEXT_COMPARE, 4, (0xfffffe00 + 1000) & trap.MASK), (trap.NEXT_COMPARE + 4, 4, 8)])
        self.assertNotIn(f'call:{trap.SWITCH}', self.actions('timer_no_switch'))
        self.assertIn(f'call:{trap.SWITCH}', self.actions('timer_switch'))

    def test_yield_syscall_switches_and_advances_saved_pc_past_ecall(self):
        row = self.row('yield_ecall')
        self.assertIn(f'call:{trap.SWITCH}', self.actions('yield_ecall'))
        self.assertEqual((row['registers']['a0'], row['csrs']['833']), (0, trap.CODE_AREA + 4))
        other = self.row('ecall_other_number')
        self.assertNotIn(f'call:{trap.SWITCH}', self.actions('ecall_other_number'))
        self.assertEqual((other['registers']['a0'], other['csrs']['833']), (0, trap.CODE_AREA + 4))
        switched = frame_words(self.row('yield_ecall_switch'))
        self.assertEqual(struct.unpack_from('<I', switched, 0x84)[0], trap.CODE_AREA + 4)

    def test_every_exception_skips_the_faulting_instruction_by_its_length(self):
        for name, length in (('illegal_compressed', 2), ('illegal_standard', 4), ('breakpoint', 2), ('load_fault', 4)):
            self.assertEqual(self.row(name)['csrs']['833'], trap.CODE_AREA + length, name)
        self.assertIn(f'call:{trap.EXCEPTION_VECTORS[2]}:{trap.CODE_AREA}:{trap.TASK_A_STACK - trap.FRAME}', self.actions('illegal_standard'))
        for name in ('exception_past_table', 'local_unregistered', 'interrupt_code_zero'):
            self.assertEqual(self.row(name)['stopped'], 'null_vector')

    def test_registration_masks_only_bit_28_and_bounds_each_table(self):
        self.assertEqual(self.writes('register_external_last')[-1], (trap.PLIC_PRIORITY + 4 * 0x52, 4, 1))
        for name in ('register_external_out_of_range', 'register_external_high_bits', 'register_local_out_of_range',
                     'register_local_high_bits', 'register_local_large'):
            self.assertEqual(self.writes(name), [], name)
        self.assertEqual(self.writes('register_local_first'), [(trap.CORE_TABLE + 0x100, 4, 0x70aa0000), (trap.CORE_TABLE + 0x104, 4, 0x5aa50000)])
        self.assertEqual(self.writes('register_local_last')[0][0], trap.CORE_TABLE + 16 * 31)

    def test_local_enable_uses_mie_bit_sixteen_plus_and_wraps_at_sixteen(self):
        self.assertEqual(self.actions('enable_local_timer_bit')[1], f'csr:772:{0x888}:{0x888 | 1 << 19}')
        self.assertEqual(self.actions('enable_local_sixteen')[1], f'csr:772:{0x888}:{0x889}')
        self.assertEqual(self.actions('disable_local_sixteen')[1], f'csr:772:{0x888}:{0x888}')
        self.assertEqual(self.actions('enable_local_out_of_range'), ['op:enable'])
        self.assertEqual(self.writes('enable_external_word2'), [(trap.PLIC_ENABLE + 8, 4, 0x00060000), (trap.EXTERNAL_TABLE + 16 * 0x51 + 8, 4, 1)])

    def test_restore_reenables_only_marked_entries_with_their_stored_priorities(self):
        row = self.row('mask_restore')
        self.assertEqual(self.actions('mask_restore')[1:4], ['csr:772:2184:2184', f'w:{trap.SAVED_MIE}:4:2184', 'csr:772:2184:0'])
        enable = struct.unpack('<3I', bytes.fromhex(row['snapshot'][str(trap.PLIC_ENABLE)]))
        self.assertEqual(enable, (1 << 0x16, 1 << (0x2a - 32), 1 << (0x52 - 64)))
        self.assertEqual(row['snapshot'][str(trap.PLIC_PRIORITY + 0x100)], '00000000')
        self.assertEqual(row['snapshot'][str(trap.PLIC_PRIORITY + 0x148)], 'ffffffff')
        self.assertEqual(row['csrs']['772'], 0x888)

    def test_init_fills_default_handlers_then_enables_external_software_and_global(self):
        actions = self.actions('init')
        self.assertEqual(actions[1], 'csr:772:2184:0')
        self.assertIn(f'call:{trap.MEMSET}:{trap.PLIC_PRIORITY}:0:{0x150}', actions)
        fills = [w for w in self.writes('init') if trap.EXTERNAL_TABLE <= w[0] < trap.EXTERNAL_TABLE + 0x530]
        self.assertEqual(len(fills), 4 * trap.EXTERNAL_COUNT)
        self.assertEqual({w[2] for w in fills[::4]}, {trap.DEFAULT_HANDLER})
        self.assertEqual(actions[-3:], ['csr:772:0:2048', 'csr:772:2048:2056', 'csr:768:6152:6152'])
        self.assertEqual(self.actions('deinit')[1], 'csr:768:6152:6144')

    def test_first_task_start_installs_direct_vector_and_scheduler_asserts_mode_bits(self):
        row = self.row('start_first_task')
        self.assertEqual(self.actions('start_first_task')[1], f'csr:773:{0x80d35e00}:{trap.TRAP_ENTRY}')
        self.assertEqual(row['csrs']['3'], self.cases['start_first_task']['csrs']['3'])
        self.assertEqual(row['registers']['sp'], trap.TASK_B_FRAME + trap.FRAME)
        self.assertEqual(self.row('scheduler_direct_vector')['csrs']['772'], 0x888)
        for name in ('scheduler_vectored_vector', 'scheduler_mode_bits_two'):
            self.assertEqual(self.row(name)['stopped'], 'assert')
            self.assertIn(f'call:{trap.ASSERT}:{0x70a1d864}:{0x70a1d834}:{0x105}', self.actions(name))

    def test_contract_rejects_unbounded_or_unknown_inputs(self):
        case = copy.deepcopy(self.cases['init'])
        case['scope'] = 'other'
        with self.assertRaises(ValueError):
            trap.contract(case)
        case = copy.deepcopy(self.cases['init'])
        case['operations'] = case['operations'] * 13
        with self.assertRaises(ValueError):
            trap.contract(case)

    def test_raw_decoder_recovers_far_call_and_constant_arguments_from_synthetic_code(self):
        base = 0x70000000
        code = b''.join(struct.pack('<I', w) for w in (
            0x01600513,   # li a0, 0x16
            0x00000597,   # auipc a1, 0
            0x01c58593,   # addi a1, a1, 0x1c
            0x93000637,   # lui a2, 0x93000
            0x00000097,   # auipc ra, 0
            0x000080e7,   # jalr ra, 0(ra)
        ))
        memory = SyntheticMemory(base, code + b'\0' * 16)
        self.assertEqual(trap.call_target(memory, base + 16), base + 16)
        self.assertEqual(trap.arguments(memory, base + 16, window=16), (0x16, base + 4 + 0x1c, 0x93000000))
        self.assertIsNone(trap.call_target(memory, base))


if __name__ == '__main__':
    unittest.main()
