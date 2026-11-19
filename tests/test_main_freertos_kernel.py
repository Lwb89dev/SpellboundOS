import json
from pathlib import Path
import struct
import unittest

from analysis_scripts import main_freertos_kernel as kernel
from analysis_scripts import main_trap_irq as trap


class SyntheticMemory:
    def __init__(self, base, data):
        self.base, self.blob = base, bytes(data)

    def read(self, address, size):
        offset = address - self.base
        if offset < 0 or offset + size > len(self.blob):
            raise struct.error('outside fixture')
        return self.blob[offset:offset + size]


def words_of(hexdata):
    data = bytes.fromhex(hexdata)
    return struct.unpack('<%dI' % (len(data) // 4), data)


class MainFreertosKernelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = kernel.native_vectors()
        cls.cases = {c['name'].removeprefix('main_freertos_kernel_'): c for c in cls.vectors['cases']}
        cls.evidence = json.loads(Path('analysis/main-freertos-kernel.json').read_bytes())

    def row(self, name, index=-1):
        return self.cases[name]['expected']['rows'][index]

    def actions(self, name):
        return self.cases[name]['expected']['actions']

    def word_at(self, name, address, index=-1):
        snapshot = self.row(name, index)['snapshot']
        for start, data in snapshot.items():
            start = int(start)
            if start <= address < start + len(data) // 2:
                offset = address - start
                return struct.unpack_from('<I', bytes.fromhex(data), offset)[0]
        raise KeyError(hex(address))

    def test_native_report_matches_every_independent_model_case(self):
        report = self.evidence['native_validation']
        self.assertIs(report['hardware_execution'], False)
        self.assertEqual((report['case_count'], len(report['cases']), report['bound_per_case']),
                         (61, 61, kernel.BOUND))
        for row in report['cases']:
            name = row['name'].removeprefix('main_freertos_kernel_')
            self.assertEqual(row['observed'], self.cases[name]['expected'])
            self.assertTrue(0 < row['steps'] <= kernel.BOUND)
        self.assertEqual(self.evidence['native_steps'], sum(r['steps'] for r in report['cases']))

    def test_guards_pin_kernel_and_reused_trap_ranges(self):
        pinned = {f'{a:08x}_{n:x}': h for a, n, h in kernel.CODE + kernel.DATA}
        self.assertEqual(self.evidence['byte_range_sha256'], pinned)
        guards = trap.CODE + trap.DATA + kernel.CODE + kernel.DATA
        self.assertEqual(self.vectors['guards'], [dict(address=a, size=n, sha256=h) for a, n, h in guards])
        for case in self.vectors['cases']:
            self.assertEqual(case['ranges'], [[a, a + n] for a, n, _ in kernel.CODE + trap.CODE])
        self.assertEqual(self.evidence['reused_trap_ranges'], len(trap.CODE + trap.DATA))

    def test_call_sites_tie_scheduler_start_timer_tick_and_creation(self):
        sites = {s['site']: s['target'] for s in self.evidence['call_sites']}
        self.assertEqual(sites['0x80d37f78'], '0x80d3974e')
        self.assertEqual(sites['0x80d37f82'], '0x80d398d6')
        self.assertEqual(sites['0x80d39632'], '0x80d37e66')
        self.assertEqual(sites['0x80d3a386'], '0x80d37eca')
        self.assertEqual(len(sites), len(kernel.CALL_SITES))

    def test_raw_jump_decoder_on_synthetic_encodings(self):
        # jal ra, +0x10 at 0x1000; c.j -4 at 0x1004; c.jal +8 at 0x1006; addi at 0x1008.
        jal = (0x10 >> 1 & 0x3ff) << 21 | 1 << 7 | 0x6f
        cj = 0xa001 | 1 << 12 | 1 << 8 | 3 << 9 | 1 << 6 | 1 << 7 | 1 << 2 | 1 << 11 | 6 << 3
        cjal = 0x2001 | 4 << 3
        memory = SyntheticMemory(0x1000, struct.pack('<IHHI', jal, cj, cjal, 0x00000013))
        self.assertEqual(kernel.direct_target(memory, 0x1000), 0x1010)
        self.assertEqual(kernel.direct_target(memory, 0x1004), 0x1000)
        self.assertEqual(kernel.direct_target(memory, 0x1006), 0x100e)
        with self.assertRaises(ValueError):
            kernel.direct_target(memory, 0x1008)

    def synthetic_model(self, state, supplied=None):
        case = kernel.kernel_case('synthetic', 'tick', [kernel.op('tick')], state, supplied=supplied)
        return kernel.Model(case)

    def test_list_primitives_keep_circular_links_and_index(self):
        st = kernel.State()
        lst, items = 0x81800000, (0x81800100, 0x81800200, 0x81800300)
        for item in items:
            st.put(item, bytes(0x14))
        st.link(lst, [])
        model = self.synthetic_model(st)
        for item in items:
            model.insert_end(lst, item)
        self.assertEqual(model.read(lst), 3)
        self.assertEqual(model.read(lst + 0xc), items[0])
        self.assertEqual(model.read(lst + 0x10), items[2])
        model.write(lst + 4, 4, items[1])
        self.assertEqual(model.remove(items[1]), 2)
        self.assertEqual(model.read(lst + 4), items[0])
        self.assertEqual((model.read(items[0] + 4), model.read(items[2] + 8)), (items[2], items[0]))
        self.assertEqual(model.read(items[1] + 0x10), 0)

    def test_runtime_counter_subtracts_base_across_word_borrow(self):
        st = kernel.State()
        st.w64(kernel.RUN_BASE, 0x4_fffff000)
        model = self.synthetic_model(st, kernel.mtime((0x100, 5), retry=4))
        self.assertEqual(model.runtime_read(), (0x1100, 0))
        self.assertEqual([a.split(':')[1] for a in model.actions if a.startswith('r:')],
                         [str(kernel.MTIME_HI), str(kernel.MTIME_LO), str(kernel.MTIME_HI)] * 2)
        self.assertEqual(self.row('runtime_init_then_read', 1)['a0'], 0x1100)

    def test_timer_setup_programs_compare_next_period_and_source14(self):
        self.assertEqual(self.word_at('setup_timer_stable', kernel.MTIMECMP), 0x12345678 + 1000)
        self.assertEqual(self.word_at('setup_timer_stable', kernel.NEXT_COMPARE), 0x12345678 + 2000)
        self.assertEqual(self.word_at('setup_timer_both_compares_carry', kernel.MTIMECMP + 4), 0)
        self.assertEqual(self.word_at('setup_timer_next_compare_carry', kernel.MTIMECMP + 4), 7)
        self.assertEqual(self.word_at('setup_timer_next_compare_carry', kernel.NEXT_COMPARE + 4), 8)
        entry = trap.EXTERNAL_TABLE + 16 * 0xe
        self.assertEqual(self.word_at('setup_timer_stable', entry), kernel.SOURCE14)
        writes = [a for a in self.actions('setup_timer_stable') if a.startswith('w:')]
        self.assertEqual(writes[0], f'w:{kernel.MTIMECMP}:4:{0x12345678 + 1000}')
        self.assertEqual(writes[1], f'w:{kernel.MTIMECMP + 4}:4:7')
        self.assertEqual(self.actions('source14_original_object')[1], f'w:{kernel.ACK_REGISTER}:4:2')
        self.assertEqual(self.actions('source14_other_object')[1], f'w:{kernel.ACK_REGISTER}:4:4')

    def test_initial_frame_matches_port_contract(self):
        top = kernel.STACKS[0] + 0x3f8
        frame = words_of(self.row('init_stack_frame')['snapshot'][str(top - kernel.FRAME)])
        self.assertEqual(frame[1], kernel.TASK_EXIT)
        self.assertEqual(frame[10], 0x13572468)
        self.assertEqual(frame[0x80 // 4:0x90 // 4], (0x7880, 0x70aa1234, 0x21, kernel.STACKS[0] + kernel.FRAME))
        self.assertEqual(frame[2], 0)
        self.assertEqual(self.row('init_stack_frame')['a0'], top - kernel.FRAME)
        self.assertEqual(self.row('task_exit_deletes_self')['stopped'], 'task_delete')

    def test_created_task_starts_with_zero_gp_tp_and_stack_protection(self):
        regs = self.row('create_then_start_first_task')['registers']
        csrs = self.row('create_then_start_first_task')['csrs']
        top = kernel.STACKS[1] + 0x3f8
        self.assertEqual((regs['ra'], regs['a0'], regs['sp'], regs['gp'], regs['tp']),
                         (kernel.TASK_EXIT, 0x2468ace0, top, 0, 0))
        self.assertEqual((csrs['768'], csrs['833'], csrs['1990'], csrs['1991']),
                         (0x7880, 0x70bb0001, 0x21, kernel.STACKS[1] + kernel.FRAME))
        self.assertEqual(csrs['3'], 0x20)          # first-task start leaves fcsr untouched
        self.assertEqual(self.row('create_then_start_first_task', 0)['a0'], kernel.TCBS[5])

    def test_creation_clamps_priority_truncates_name_and_initializes_lists(self):
        tcb = kernel.TCBS[5]
        snap = bytes.fromhex(self.row('create_long_name_clamped_priority')['snapshot'][str(tcb)])
        self.assertEqual(snap[0x34:0x48], b'a-very-long-task-na\0')
        self.assertEqual(struct.unpack_from('<I', snap, 0x2c)[0], 9)
        self.assertEqual(struct.unpack_from('<I', snap, 0x18)[0], 1)
        self.assertEqual(struct.unpack_from('<II', snap, 0x138), (0xabcd330e, 0xe66d1234))
        first = 'create_first_task_initializes_lists'
        self.assertEqual(self.word_at(first, kernel.DELAYED_PTR), kernel.DELAYED1)
        self.assertEqual(self.word_at(first, kernel.OVERFLOW_PTR), kernel.DELAYED2)
        self.assertEqual(self.word_at(first, kernel.CURRENT), tcb)
        self.assertEqual(self.word_at(first, kernel.TOP_READY), 1 << 2)
        self.assertEqual(self.word_at(first, kernel.TASK_NUMBER), 8)
        self.assertEqual(sum(1 for a in self.actions(first) if a.startswith(f'w:{kernel.READY + 8}:4:')), 1)
        self.assertEqual(self.row('create_null_name')['snapshot'][str(tcb)][0x34 * 2:0x35 * 2], '00')
        self.assertEqual(self.row('create_null_stack_asserts')['stopped'], 'assert')

    def test_creation_selects_current_and_yields_only_when_running(self):
        a, b = kernel.TCBS[4], kernel.TCBS[5]
        self.assertEqual(self.word_at('create_before_start_higher', kernel.CURRENT), b)
        self.assertEqual(self.word_at('create_before_start_equal', kernel.CURRENT), b)
        self.assertEqual(self.word_at('create_before_start_lower', kernel.CURRENT), a)
        self.assertEqual(self.row('create_running_higher_yields')['stopped'], 'yield')
        self.assertIsNone(self.row('create_running_lower_no_yield')['stopped'])
        csr = [x for x in self.actions('create_running_lower_no_yield') if x.startswith('csr:768:')]
        self.assertEqual(csr, ['csr:768:6280:6272', 'csr:768:6272:6280'])
        before = [x for x in self.actions('create_before_start_lower') if x.startswith('csr:768:')]
        self.assertEqual(before, ['csr:768:6280:6272'])     # MIE stays clear before the scheduler runs
        self.assertEqual(self.word_at('create_running_lower_no_yield', a + 0x50), 0)

    def test_tick_wakes_by_deadline_and_reports_preemption(self):
        self.assertEqual([self.row('tick_wake_' + n)['a0'] for n in ('higher', 'lower', 'equal')], [1, 0, 1])
        self.assertEqual(self.row('tick_before_unblock_time')['a0'], 0)
        self.assertEqual(self.row('tick_time_slice_equal_ready')['a0'], 1)
        self.assertEqual(self.row('tick_yield_pending')['a0'], 1)
        self.assertEqual(self.word_at('tick_scheduler_suspended_pends', kernel.PENDED), 5)
        self.assertEqual(self.word_at('tick_wake_two_then_future_deadline', kernel.NEXT_UNBLOCK), 150)
        self.assertEqual(self.word_at('tick_deadline_reached_empty_list', kernel.NEXT_UNBLOCK), kernel.MASK)
        self.assertEqual(self.word_at('tick_unsigned_deadline_not_reached', kernel.NEXT_UNBLOCK), 0x80000000)
        waiter = kernel.TCBS[1]
        self.assertEqual(self.word_at('tick_wake_removes_event_item', waiter + 0x28), 0)
        self.assertEqual(self.word_at('tick_wake_moves_delayed_index', kernel.DELAYED1 + 4), kernel.DELAYED1 + 8)

    def test_tick_wrap_swaps_delayed_lists(self):
        name = 'tick_wrap_swaps_lists_nonempty_overflow'
        self.assertEqual(self.word_at(name, kernel.DELAYED_PTR), kernel.DELAYED2)
        self.assertEqual(self.word_at(name, kernel.OVERFLOW_PTR), kernel.DELAYED1)
        self.assertEqual(self.word_at(name, kernel.OVERFLOWS), 1)
        self.assertEqual(self.word_at(name, kernel.NEXT_UNBLOCK), 40)
        self.assertEqual(self.word_at('tick_wrap_swaps_lists_empty_overflow', kernel.NEXT_UNBLOCK), kernel.MASK)
        self.assertEqual(self.row('tick_wrap_with_pending_delayed_asserts')['stopped'], 'assert')
        self.assertIn('call:%d:%d:%d:%d' % ((kernel.ASSERT,) + kernel.ASSERTS['overflow']),
                      self.actions('tick_wrap_with_pending_delayed_asserts'))

    def test_switch_selection_runtime_and_stack_check(self):
        a, b = kernel.TCBS[:2]
        self.assertEqual(self.word_at('switch_round_robin_advances', kernel.CURRENT), b)
        self.assertEqual(self.word_at('switch_round_robin_wraps_end_marker', kernel.CURRENT), a)
        name = 'switch_highest_priority_runtime_errno_impure'
        self.assertEqual(self.word_at(name, kernel.CURRENT), b)
        self.assertEqual(self.word_at(name, kernel.ERRNO), 0x22)
        self.assertEqual(self.word_at(name, kernel.IMPURE), b + 0x88)
        self.assertEqual(self.word_at(name, a + 0x80), 0x40 + 0x1500 - 0x300)
        self.assertEqual(self.word_at('switch_runtime_equal_no_accumulate', a + 0x80), 0x40)
        self.assertEqual(self.word_at('switch_runtime_lower_high_word_no_accumulate', a + 0x80), 0x40)
        self.assertEqual(self.word_at('switch_scheduler_suspended_sets_yield_pending', kernel.YIELD_PENDING), 1)
        for i in range(4):
            self.assertIn(f'call:{kernel.OVERFLOW_HOOK}:{a}:{a + 0x34}', self.actions('switch_stack_overflow_word%d' % i))
        self.assertNotIn(f'call:{kernel.OVERFLOW_HOOK}:{a}:{a + 0x34}', self.actions('switch_round_robin_advances'))
        for bitmap in ('1', '100', '3ff'):
            self.assertEqual(self.word_at('switch_clz_bitmap_' + bitmap, kernel.CURRENT), b)
        self.assertEqual(self.row('switch_empty_selected_list_asserts')['stopped'], 'assert')
        self.assertEqual(kernel.word(kernel.READY + kernel.word(0x1f - kernel.Model.clz(0)) * 0x14), kernel.DELAYED1)
        self.assertEqual(self.row('switch_zero_bitmap_reads_list_below_ready_array')['stopped'], 'assert')

    def test_connected_trap_paths_resume_selected_task(self):
        for name, frame in (('trap_timer_round_robin_resumes_peer', trap.TASK_B_FRAME),
                            ('trap_timer_wakes_higher_priority', trap.TASK_B_FRAME),
                            ('trap_yield_selects_peer', trap.TASK_B_FRAME)):
            row = self.row(name)
            self.assertEqual(row['stopped'], 'mret')
            self.assertEqual(self.word_at(name, kernel.CURRENT), trap.TCB_B)
            self.assertEqual(row['csrs']['833'], trap.CODE_AREA + 0x40)
        self.assertEqual(self.word_at('trap_timer_no_switch_keeps_task', kernel.CURRENT), trap.TCB_A)
        self.assertEqual(self.word_at('trap_timer_wakes_higher_priority', kernel.TOP_READY), (1 << 3) | (1 << 6))
        self.assertEqual(self.word_at('trap_source14_acknowledges', kernel.ACK_REGISTER), 2)
        self.assertEqual(self.word_at('timer_handler_time_slice_switch', kernel.CURRENT), trap.TCB_B)
        self.assertEqual(self.word_at('timer_handler_tick_without_switch', kernel.CURRENT), trap.TCB_A)
        start = self.row('scheduler_start_actual_timer_setup')
        self.assertEqual(start['stopped'], 'mret')
        self.assertEqual(self.word_at('scheduler_start_actual_timer_setup', trap.PLIC_ENABLE), 1 << 0xe)

    def test_contract_rejects_unbounded_or_unknown_scope(self):
        case = dict(self.cases['tick_before_unblock_time'])
        with self.assertRaises(ValueError):
            kernel.contract(dict(case, scope='other'))
        with self.assertRaises(ValueError):
            kernel.contract(dict(case, operations=[]))
        with self.assertRaises(ValueError):
            kernel.contract(dict(case, supplied={str(kernel.MTIME_HI): [0] * 25}))

    def test_vectors_are_reproducible_and_json_stable(self):
        again = kernel.native_vectors()
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.vectors, sort_keys=True))
        self.assertEqual(self.evidence['kernel_layout']['max_priorities'], 10)
        self.assertEqual(self.evidence['kernel_layout']['tcb_size'], '0x4c0')


if __name__ == '__main__':
    unittest.main()
