#!/usr/bin/env python3
"""Main FreeRTOS task query and priority: eTaskGetState, uxTaskPriorityGet,
vTaskPrioritySet.

This scope executes the original ``eTaskGetState`` (``0x80d3a55e``),
``uxTaskPriorityGet`` (``0x80d3a5f4``) and ``vTaskPrioritySet``
(``0x80d3a61c``) end to end, reusing ``vTaskEnterCritical``,
``vTaskExitCritical``, ``uxListRemove`` and ``vListInsertEnd`` as guarded
original code already covered by
[MAIN_FREERTOS_KERNEL.md](MAIN_FREERTOS_KERNEL.md).  ``vTaskPrioritySet`` tail
calls the original ``vTaskExitCritical``.  Only ``configASSERT``, the
critical-section diagnostic body and ``vPortYield`` are supplied stubs; here
the yield returns, so the priority change completes.  Nothing executes vendor
code outside the hash-guarded original ranges.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import main_trap_irq as trap
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    import main_freertos_kernel as kernel
    import main_trap_irq as trap
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000

GET_STATE = 0x80d3a55e          # eTaskGetState
PRIORITY_GET = 0x80d3a5f4       # uxTaskPriorityGet
PRIORITY_SET = 0x80d3a61c       # vTaskPrioritySet
ENTER = kernel.ENTER
EXIT = kernel.EXIT
REMOVE = kernel.REMOVE
INSERT_END = kernel.INSERT_END
ASSERT = kernel.ASSERT
DIAG = kernel.DIAG
YIELD = kernel.YIELD            # 0x80d3965c, here supplied as a returning stub

CURRENT = kernel.CURRENT
RUNNING = kernel.RUNNING
TOP_READY = kernel.TOP_READY
READY = kernel.READY
DELAYED_PTR = kernel.DELAYED_PTR
OVERFLOW_PTR = kernel.OVERFLOW_PTR
SUSPENDED_LIST = kernel.SUSPENDED_LIST     # 0x80c07e70
TERMINATION = kernel.TERMINATION           # 0x80c07e88
PRIORITIES = kernel.PRIORITIES

TASKS_FILE = kernel.TASKS_FILE
ASSERT_GETSTATE = (0x70a1dde0, TASKS_FILE, 0x5ae)     # eTaskGetState: pxTCB != NULL
ASSERT_CLAMP = (0x70a1dff4, TASKS_FILE, 0x64e)        # vTaskPrioritySet: uxNewPriority < configMAX

CODE = (
    (GET_STATE, 0x96, '82a6388a3b27a6812993a06d964ba887ce65f468be4a50da692e2bdccef4e126'),
    (PRIORITY_GET, 0x28, 'd431ca5d4a04c40864ff64ad736277cb01511fb64d82b4082d098b85c7c6fc58'),
    (PRIORITY_SET, 0x104, '948a522a793b53b3f4a97a27cb5b27ea03cd903092ab70905c146a3b4dd88291'),
)
REUSE = tuple((a, n, h) for a, n, h in kernel.CODE if a in (ENTER, EXIT, REMOVE, INSERT_END))
DATA = ((TASKS_FILE, 0x1c, 'be652418b4c6707dc4fa0f11c837886cd457b93ba4cacfe811968208e3eebd2a'),)
CALL_SITES = (
    (0x80d3a5fc, ENTER), (0x80d3a60e, EXIT),            # uxTaskPriorityGet
    (0x80d3a652, ENTER), (0x80d3a6c0, REMOVE), (0x80d3a6f6, INSERT_END), (0x80d3a6fe, YIELD),
    (0x80d3a70e, EXIT),                                 # vTaskPrioritySet
)
CSRS = kernel.CSRS
X, F = kernel.X, kernel.F
HARNESS_STACK = kernel.HARNESS_STACK
QUIET = kernel.QUIET
TCBS = kernel.TCBS
STACKS = kernel.STACKS

# eTaskState codes as returned by this build.
E_RUNNING, E_READY, E_BLOCKED, E_SUSPENDED, E_DELETED = 0, 1, 2, 3, 4


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(kernel.Model):
    def call(self, address, *args):
        if address in self.stubs:
            return trap.Model.call(self, address, *args)
        raise ValueError(f'unmodelled callee {address:#x}')

    def priority_get(self, handle):
        self.enter_critical()
        tcb = handle or self.read(CURRENT)
        priority = self.read(tcb + 0x2c)
        self.exit_critical()
        return priority

    def get_state(self, handle):
        if handle == 0:
            self.call(ASSERT, *ASSERT_GETSTATE)
        if self.read(CURRENT) == handle:
            return E_RUNNING
        self.enter_critical()
        delayed, overflow = self.read(DELAYED_PTR), self.read(OVERFLOW_PTR)
        container = self.read(handle + 0x14)
        self.exit_critical()
        if container in (delayed, overflow):
            return E_BLOCKED
        if container == SUSPENDED_LIST:
            if self.read(handle + 0x28) == 0 and self.read(handle + 0x4b4, 1) != 1:
                return E_SUSPENDED
            return E_BLOCKED
        if container not in (TERMINATION, 0):
            return E_READY
        return E_DELETED

    def priority_set(self, handle, new_priority):
        if new_priority > PRIORITIES - 1:
            self.call(ASSERT, *ASSERT_CLAMP)
            new_priority = PRIORITIES - 1
        self.enter_critical()
        tcb = handle or self.read(CURRENT)
        base = self.read(tcb + 0x5c)
        if new_priority != base:
            current = self.read(CURRENT)
            if base < new_priority:
                do_yield = tcb != current and self.read(current + 0x2c) <= new_priority
            else:
                do_yield = current == tcb
            active = self.read(tcb + 0x2c)
            if base == active:
                self.write(tcb + 0x2c, 4, new_priority)
            self.write(tcb + 0x5c, 4, new_priority)
            if self.read(tcb + 0x18) < 0x80000000:
                self.write(tcb + 0x18, 4, PRIORITIES - new_priority)
            if self.read(tcb + 0x14) == word(READY + active * 0x14):
                if self.remove(tcb + 4) == 0:
                    self.write(TOP_READY, 4, self.read(TOP_READY) & ~(1 << (active & 31)))
                self.write(TOP_READY, 4, (1 << (self.read(tcb + 0x2c) & 31)) | self.read(TOP_READY))
                self.insert_end(word(READY + self.read(tcb + 0x2c) * 0x14), tcb + 4)
            if do_yield:
                self.call(YIELD)
        self.exit_critical()
        return None

    def operation(self, op):
        kind, args = op['name'].split('#')[0], op['args']
        handlers = dict(priority_get=self.priority_get, get_state=self.get_state, priority_set=self.priority_set)
        if kind not in handlers:
            raise ValueError('operation')
        return handlers[kind](*args)


def contract(case):
    if case['scope'] not in ('query', 'priority'):
        raise ValueError('query scope')
    if not 1 <= len(case['operations']) <= 4:
        raise ValueError('bounded operations')
    return Model(case).run()


def op(name, *args):
    kind = name.split('#')[0]
    entry = {'priority_get': PRIORITY_GET, 'get_state': GET_STATE, 'priority_set': PRIORITY_SET}[kind]
    return dict(name=name, entry=entry, call=True, args=list(args), registers=False,
                result=kind in ('priority_get', 'get_state'), result_high=False)


def stubs():
    return {str(ASSERT): dict(kind='stop', label='assert', args=3),
            str(DIAG): dict(kind='return', args=2),
            str(YIELD): dict(kind='return', args=0)}


def case(name, scope, operations, state, snapshot=(), running=1):
    state.w32(RUNNING, running)
    base_csrs = (0x20, 0x1888, 0x888, trap.TRAP_ENTRY, 0x51515151, trap.CODE_AREA, 0x8000000b, 0x21, 0x81100000)
    return dict(
        name='main_task_query_' + name, scope=scope, supplied={}, quiet=[list(q) for q in QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE + REUSE],
        csrs={str(n): v for n, v in zip(CSRS, base_csrs)}, registers={'sp': HARNESS_STACK},
        fregisters={}, stubs=stubs(), stops={}, snapshot=[list(s) for s in snapshot],
        operations=operations, memory=state.memory())


def make_tcb(st, tcb, priority, base=None, container=None, event_container=0, event_value=None,
             notify=0, stack=None):
    st.tcb(tcb, priority, stack or STACKS[0])
    st.w32(tcb + 0x5c, base if base is not None else priority)
    st.w32(tcb + 0x14, container if container is not None else word(READY + priority * 0x14))
    st.w32(tcb + 0x28, event_container)
    st.w32(tcb + 0x18, event_value if event_value is not None else (PRIORITIES - priority))
    st.put(tcb + 0x4b4, bytes([notify]))
    st.w32(tcb + 0x50, 0)
    return tcb


def base_state(current):
    st = kernel.State(current=current)
    return st


def native_vectors():
    cases = []
    a, b = TCBS[0], TCBS[1]

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    # uxTaskPriorityGet.
    st = base_state(a)
    make_tcb(st, a, 4)
    add(case('priority_get_current', 'priority', [op('priority_get', 0)], st, snapshot=[[CURRENT, 4]]))
    st = base_state(a)
    make_tcb(st, a, 4)
    make_tcb(st, b, 7, stack=STACKS[1])
    add(case('priority_get_other', 'priority', [op('priority_get', b)], st))

    # eTaskGetState.
    st = base_state(a)
    make_tcb(st, a, 3)
    add(case('get_state_null_asserts', 'query', [op('get_state', 0)], st))
    st = base_state(a)
    make_tcb(st, a, 3)
    add(case('get_state_running', 'query', [op('get_state', a)], st))
    for name, container, extra in (
            ('ready', word(READY + 4 * 0x14), {}),
            ('blocked_delayed', kernel.DELAYED1, {}),
            ('blocked_overflow', kernel.DELAYED2, {}),
            ('suspended', SUSPENDED_LIST, {}),
            ('suspended_waiting_notification', SUSPENDED_LIST, {'notify': 1}),
            ('suspended_pending_event', SUSPENDED_LIST, {'event_container': 0x81800000}),
            ('deleted_termination', TERMINATION, {}),
            ('container_zero', 0, {})):
        st = base_state(a)
        make_tcb(st, a, 3)
        make_tcb(st, b, 4, stack=STACKS[1], container=container, **extra)
        add(case('get_state_' + name, 'query', [op('get_state', b)], st))

    # vTaskPrioritySet.
    snap = [[TOP_READY, 4]]
    st = base_state(a)
    make_tcb(st, a, 3)
    st.ready(3, [a])
    st.w32(TOP_READY, 1 << 3)
    add(case('priority_set_above_max_clamps', 'priority', [op('priority_set', a, 15)], st,
             snapshot=snap + [[a + 0x2c, 4], [a + 0x5c, 4]]))

    st = base_state(a)
    make_tcb(st, a, 3)
    st.ready(3, [a])
    st.w32(TOP_READY, 1 << 3)
    add(case('priority_set_same_priority_noop', 'priority', [op('priority_set', a, 3)], st,
             snapshot=snap + [[a + 0x2c, 4]]))

    st = base_state(a)
    make_tcb(st, a, 3)
    st.ready(3, [a])
    st.w32(TOP_READY, 1 << 3)
    add(case('priority_set_lower_current_reorders_and_yields', 'priority', [op('priority_set', a, 1)], st,
             snapshot=snap + [[a + 0x2c, 4], [a + 0x5c, 4], [a + 0x18, 4], [READY + 3 * 0x14, 0x14],
                              [READY + 1 * 0x14, 0x14]]))

    st = base_state(a)
    make_tcb(st, a, 3)
    make_tcb(st, b, 2, stack=STACKS[1], container=word(READY + 2 * 0x14))
    st.ready(3, [a])
    st.ready(2, [b])
    st.w32(TOP_READY, (1 << 3) | (1 << 2))
    add(case('priority_set_raise_other_to_current_yields', 'priority', [op('priority_set', b, 3)], st,
             snapshot=snap + [[b + 0x2c, 4], [READY + 2 * 0x14, 0x14], [READY + 3 * 0x14, 0x14]]))

    st = base_state(a)
    make_tcb(st, a, 5)
    make_tcb(st, b, 1, stack=STACKS[1], container=word(READY + 1 * 0x14))
    st.ready(5, [a])
    st.ready(1, [b])
    st.w32(TOP_READY, (1 << 5) | (1 << 1))
    add(case('priority_set_raise_other_below_current_no_yield', 'priority', [op('priority_set', b, 3)], st,
             snapshot=snap + [[b + 0x2c, 4], [READY + 1 * 0x14, 0x14], [READY + 3 * 0x14, 0x14]]))

    st = base_state(a)
    make_tcb(st, a, 3, base=2, container=word(READY + 3 * 0x14))     # active 3, inherited above base 2
    st.ready(3, [a])
    st.w32(TOP_READY, 1 << 3)
    add(case('priority_set_inherited_active_not_touched', 'priority', [op('priority_set', a, 4)], st,
             snapshot=snap + [[a + 0x2c, 4], [a + 0x5c, 4], [READY + 3 * 0x14, 0x14]]))

    st = base_state(a)
    make_tcb(st, a, 3)
    make_tcb(st, b, 4, stack=STACKS[1], container=kernel.DELAYED1, event_value=0x80000006)
    st.ready(3, [a])
    st.delayed([(b, 500)])
    st.w32(TOP_READY, (1 << 3) | (1 << 4))
    add(case('priority_set_blocked_task_keeps_marked_event_value', 'priority', [op('priority_set', b, 2)], st,
             snapshot=snap + [[b + 0x2c, 4], [b + 0x5c, 4], [b + 0x18, 4]]))

    guards = REUSE + CODE + DATA
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in guards], cases=cases)


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in REUSE + CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for site, target in CALL_SITES:
        if kernel.direct_target(memory, site) != target:
            raise ValueError(f'call site {site:#x}')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
    return dict(
        main_sha256=MAIN_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        get_state=f'{GET_STATE:#010x}', priority_get=f'{PRIORITY_GET:#010x}',
        priority_set=f'{PRIORITY_SET:#010x}',
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        reused_kernel_ranges=[f'{a:#010x}' for a, _, _ in REUSE],
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        state_codes=dict(running=E_RUNNING, ready=E_READY, blocked=E_BLOCKED, suspended=E_SUSPENDED,
                         deleted=E_DELETED),
        max_priorities=PRIORITIES,
        asserts=dict(get_state=[f'{v:#x}' for v in ASSERT_GETSTATE],
                     clamp=[f'{v:#x}' for v in ASSERT_CLAMP]),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Original eTaskGetState, uxTaskPriorityGet and vTaskPrioritySet execute in an emulator over '
            'authored kernel state, TCBs and lists, reusing vTaskEnterCritical/ExitCritical, uxListRemove '
            'and vListInsertEnd as guarded original code; vTaskPrioritySet tail calls the original '
            'vTaskExitCritical and mret is not executed.',
            'configASSERT, the critical-section diagnostic body and vPortYield are supplied. The yield '
            'returns so the priority change completes; the resulting context switch is not modeled. '
            'Assert is a harness stop.',
            'Mutex priority inheritance/disinheritance, the pending-ready list state, notification-wait '
            'semantics and live rescheduling after a priority change remain unproved on hardware.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', nargs='?')
    parser.add_argument('--vectors-output', type=Path)
    parser.add_argument('--vectors', type=Path)
    parser.add_argument('--validation', type=Path)
    args = parser.parse_args()
    try:
        if args.vectors_output:
            args.vectors_output.write_text(json.dumps(native_vectors(), indent=2, sort_keys=True) + '\n')
            return
        if not all((args.archive, args.vectors, args.validation)):
            parser.error('need archive, --vectors and --validation')
        with zipfile.ZipFile(args.archive) as archive:
            result = evidence(archive, args.vectors, args.validation)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
        parser.exit(2, f'Cannot inspect main task query paths: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
