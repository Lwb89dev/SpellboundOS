#!/usr/bin/env python3
"""Main FreeRTOS task deletion: vTaskDelete and prvDeleteTCB.

This scope executes the original ``vTaskDelete`` (``0x80d3a45c``) and
``prvDeleteTCB`` (``0x80d3939c``) end to end, reusing every lower body as
guarded original code already covered by
[MAIN_FREERTOS_KERNEL.md](MAIN_FREERTOS_KERNEL.md): ``vTaskEnterCritical``,
``vTaskExitCritical``, ``uxListRemove``, ``vListInsertEnd`` and
``prvResetNextTaskUnblockTime``.  Only ``configASSERT``, the critical-section
diagnostic body, ``vPortYield``, newlib ``_reclaim_reent`` and ``vPortFree``
are supplied stubs.  Nothing here executes vendor code outside the
hash-guarded original ranges.
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

DELETE = 0x80d3a45c             # vTaskDelete
DELETE_TCB = 0x80d3939c         # prvDeleteTCB
# Lower bodies reused as guarded original code (same bytes as the kernel scope).
ENTER = kernel.ENTER
EXIT = kernel.EXIT
REMOVE = kernel.REMOVE
INSERT_END = kernel.INSERT_END
RESET_UNBLOCK = kernel.RESET_UNBLOCK
# Supplied callees.
ASSERT = kernel.ASSERT
DIAG = kernel.DIAG
YIELD = kernel.YIELD            # 0x80d3965c, stopped as 'yield'
RECLAIM_REENT = 0x709490b4
PORT_FREE = 0x80d3c14e

# Kernel globals (from the kernel scope).
CURRENT = kernel.CURRENT
RUNNING = kernel.RUNNING
SUSPENDED = kernel.SUSPENDED
TOP_READY = kernel.TOP_READY
READY = kernel.READY
TASK_NUMBER = kernel.TASK_NUMBER
NUM_TASKS = kernel.NUM_TASKS
NEXT_UNBLOCK = kernel.NEXT_UNBLOCK
DELAYED_PTR = kernel.DELAYED_PTR
TERMINATION = kernel.TERMINATION         # 0x80c07e88
DELETED_WAITING = 0x80c07e84             # uxDeletedTasksWaitingCleanUp

TASKS_FILE = kernel.TASKS_FILE
ASSERT_SUSPENDED = (0x70a1dfd8, TASKS_FILE, 0x516)     # "uxSchedulerSuspended == 0"
ASSERT_ALLOC = (0x70a1dd18, TASKS_FILE, 0x10b9)        # "pxTCB->ucStaticallyAllocated == ..."

CODE = (
    (DELETE, 0x102, '94b98cc7470bd008957d39a8505245309645cf8a4428a8f0b7a208bf24a2cbe3'),
    (DELETE_TCB, 0x5c, 'db4e73bc110e470cdc94340c923dc2b138d9907fc7923fce04ef52b848093d41'),
)
REUSE = tuple((a, n, h) for a, n, h in kernel.CODE
              if a in (ENTER, EXIT, REMOVE, INSERT_END, RESET_UNBLOCK))
DATA = ((TASKS_FILE, 0x1c, 'be652418b4c6707dc4fa0f11c837886cd457b93ba4cacfe811968208e3eebd2a'),)
# Direct call sites tying the deletion bodies to the reused lower bodies.
CALL_SITES = (
    (0x80d3a470, ENTER), (0x80d3a47e, REMOVE), (0x80d3a4ba, REMOVE), (0x80d3a4dc, INSERT_END),
    (0x80d3a4ee, EXIT), (0x80d3a4fa, DELETE_TCB), (0x80d3a53a, YIELD), (0x80d3a54c, RESET_UNBLOCK),
    (0x80d393b8, PORT_FREE), (0x80d393c4, PORT_FREE),
)
CSRS = kernel.CSRS
X, F = kernel.X, kernel.F
HARNESS_STACK = kernel.HARNESS_STACK
QUIET = kernel.QUIET
TCBS = kernel.TCBS
STACKS = kernel.STACKS


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(kernel.Model):
    """Reuses the kernel list/critical mirrors and adds the deletion bodies."""

    def call(self, address, *args):
        if address in self.stubs:
            return trap.Model.call(self, address, *args)
        raise ValueError(f'unmodelled callee {address:#x}')

    def delete_tcb(self, tcb):
        self.call(RECLAIM_REENT, tcb + 0x88)
        mode = self.read(tcb + 0x4b5, 1)
        if mode == 0:
            self.call(PORT_FREE, self.read(tcb + 0x30))
            self.call(PORT_FREE, tcb)
        elif mode == 1:
            self.call(PORT_FREE, tcb)
        elif mode == 2:
            return
        else:
            self.call(ASSERT, *ASSERT_ALLOC)

    def delete_task(self, handle):
        self.enter_critical()
        tcb = handle or self.read(CURRENT)
        removed = self.remove(tcb + 4)
        if removed == 0:
            priority = self.read(tcb + 0x2c)
            if self.read(word(READY + priority * 0x14)) == 0:
                self.write(TOP_READY, 4, self.read(TOP_READY) & ~(1 << (priority & 31)))
        if self.read(tcb + 0x28):
            self.remove(tcb + 0x18)
        self.write(TASK_NUMBER, 4, self.read(TASK_NUMBER) + 1)
        if self.read(CURRENT) == tcb:
            self.insert_end(TERMINATION, tcb + 4)
            self.write(DELETED_WAITING, 4, self.read(DELETED_WAITING) + 1)
        else:
            self.write(NUM_TASKS, 4, self.read(NUM_TASKS) - 1)
            self.reset_next_unblock()
        self.exit_critical()
        if self.read(CURRENT) != tcb:
            self.delete_tcb(tcb)
        if self.read(RUNNING) and self.read(CURRENT) == tcb:
            if self.read(SUSPENDED):
                self.call(ASSERT, *ASSERT_SUSPENDED)
            self.call(YIELD)

    def operation(self, op):
        kind, args = op['name'].split('#')[0], op['args']
        if kind == 'delete':
            self.delete_task(*args)
        elif kind == 'delete_tcb':
            self.delete_tcb(*args)
        else:
            raise ValueError('operation')
        return None


def contract(case):
    if case['scope'] not in ('delete', 'delete_tcb'):
        raise ValueError('deletion scope')
    if not 1 <= len(case['operations']) <= 4:
        raise ValueError('bounded operations')
    return Model(case).run()


def op(name, *args):
    return dict(name=name, entry=DELETE_TCB if name.split('#')[0] == 'delete_tcb' else DELETE,
                call=True, args=list(args), registers=False, result=False, result_high=False)


def stubs():
    return {str(ASSERT): dict(kind='stop', label='assert', args=3),
            str(DIAG): dict(kind='return', args=2),
            str(YIELD): dict(kind='stop', label='yield', args=0),
            str(RECLAIM_REENT): dict(kind='return', args=1),
            str(PORT_FREE): dict(kind='return', args=1)}


def case(name, scope, operations, state, snapshot=(), running=1, suspended=0):
    state.w32(RUNNING, running)
    state.w32(SUSPENDED, suspended)
    base_csrs = (0x20, 0x1888, 0x888, trap.TRAP_ENTRY, 0x51515151, trap.CODE_AREA, 0x8000000b, 0x21, 0x81100000)
    return dict(
        name='main_task_deletion_' + name, scope=scope, supplied={}, quiet=[list(q) for q in QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE + REUSE],
        csrs={str(n): v for n, v in zip(CSRS, base_csrs)}, registers={'sp': HARNESS_STACK},
        fregisters={}, stubs=stubs(), stops={}, snapshot=[list(s) for s in snapshot],
        operations=operations, memory=state.memory())


def tcb_state(current=0, running=1, suspended=0):
    st = kernel.State(current=current, running=running, suspended=suspended)
    st.w32(TASK_NUMBER, 7)
    st.w32(NUM_TASKS, 4)
    st.w32(DELETED_WAITING, 0)
    st.w32(NEXT_UNBLOCK, 200)
    return st


def ready_tcb(st, tcb, priority, stack, alloc=2, event=0):
    st.tcb(tcb, priority, stack)
    st.w32(tcb + 0x50, 0)
    st.put(tcb + 0x4b5, bytes([alloc]))
    st.w32(tcb + 0x28, event)
    return tcb


def native_vectors():
    cases = []
    a, b, c = TCBS[0], TCBS[1], TCBS[2]

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    # prvDeleteTCB allocation modes.
    for name, alloc in (('static', 2), ('dynamic_stack_and_tcb', 0), ('tcb_only', 1), ('bad_mode', 3)):
        st = kernel.State()
        ready_tcb(st, a, 3, STACKS[0], alloc=alloc)
        add(case('delete_tcb_' + name, 'delete_tcb', [op('delete_tcb', a)], st))

    # vTaskDelete of another task.
    st = tcb_state(current=a)
    ready_tcb(st, a, 3, STACKS[0], alloc=2)
    ready_tcb(st, b, 5, STACKS[1], alloc=0)
    st.ready(3, [a])
    st.ready(5, [b])
    st.w32(TOP_READY, (1 << 3) | (1 << 5))
    add(case('delete_other_last_in_priority_clears_bit', 'delete', [op('delete', b)], st, running=1,
             snapshot=[[TOP_READY, 4], [TASK_NUMBER, 4], [NUM_TASKS, 4], [NEXT_UNBLOCK, 4],
                       [READY + 5 * 0x14, 0x14]]))

    st = tcb_state(current=a)
    ready_tcb(st, a, 3, STACKS[0], alloc=2)
    ready_tcb(st, b, 3, STACKS[1], alloc=1)
    st.ready(3, [a, b])
    st.w32(TOP_READY, 1 << 3)
    add(case('delete_other_keeps_shared_priority_bit', 'delete', [op('delete', b)], st, running=1,
             snapshot=[[TOP_READY, 4], [NUM_TASKS, 4], [READY + 3 * 0x14, 0x14]]))

    st = tcb_state(current=a)
    ready_tcb(st, a, 3, STACKS[0], alloc=2)
    ready_tcb(st, b, 4, STACKS[1], alloc=0, event=0x81800000)
    st.ready(3, [a])
    st.ready(4, [b])
    st.event(b, 0x81800000)
    st.w32(TOP_READY, (1 << 3) | (1 << 4))
    add(case('delete_other_removes_event_list_item', 'delete', [op('delete', b)], st, running=1,
             snapshot=[[TOP_READY, 4], [b + 0x28, 4], [0x81800000, 4]]))

    st = tcb_state(current=a, running=0)
    ready_tcb(st, a, 3, STACKS[0], alloc=2)
    ready_tcb(st, b, 2, STACKS[1], alloc=0)
    st.ready(3, [a])
    st.ready(2, [b])
    st.w32(TOP_READY, (1 << 3) | (1 << 2))
    add(case('delete_other_before_scheduler_start', 'delete', [op('delete', b)], st, running=0,
             snapshot=[[TOP_READY, 4], [NUM_TASKS, 4]]))

    # vTaskDelete of the running task.
    st = tcb_state(current=a)
    ready_tcb(st, a, 3, STACKS[0], alloc=2)
    st.ready(3, [a])
    st.w32(TOP_READY, 1 << 3)
    add(case('delete_self_moves_to_termination_and_yields', 'delete', [op('delete', a)], st, running=1,
             snapshot=[[TOP_READY, 4], [TERMINATION, 4], [DELETED_WAITING, 4], [TERMINATION + 4, 8]]))

    st = tcb_state(current=a)
    ready_tcb(st, a, 3, STACKS[0], alloc=2)
    st.ready(3, [a])
    st.w32(TOP_READY, 1 << 3)
    add(case('delete_null_handle_resolves_to_current', 'delete', [op('delete', 0)], st, running=1,
             snapshot=[[TERMINATION, 4], [DELETED_WAITING, 4]]))

    st = tcb_state(current=a, suspended=1)
    ready_tcb(st, a, 3, STACKS[0], alloc=2)
    st.ready(3, [a])
    st.w32(TOP_READY, 1 << 3)
    add(case('delete_self_while_suspended_asserts', 'delete', [op('delete', a)], st, running=1, suspended=1))

    st = tcb_state(current=a, running=0)
    ready_tcb(st, a, 3, STACKS[0], alloc=2)
    st.ready(3, [a])
    st.w32(TOP_READY, 1 << 3)
    add(case('delete_self_before_scheduler_start_no_yield', 'delete', [op('delete', a)], st, running=0,
             snapshot=[[TERMINATION, 4], [DELETED_WAITING, 4]]))

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
        delete=f'{DELETE:#010x}', delete_tcb=f'{DELETE_TCB:#010x}',
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        reused_kernel_ranges=[f'{a:#010x}' for a, _, _ in REUSE],
        call_sites=[dict(site=f'{s:#010x}', target=f'{t:#010x}') for s, t in CALL_SITES],
        termination_list=f'{TERMINATION:#010x}', deleted_waiting=f'{DELETED_WAITING:#010x}',
        allocation_modes={'static_no_free': 2, 'dynamic_stack_and_tcb': 0, 'tcb_only': 1},
        asserts=dict(suspended=[f'{v:#x}' for v in ASSERT_SUSPENDED],
                     allocation=[f'{v:#x}' for v in ASSERT_ALLOC]),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'Original vTaskDelete and prvDeleteTCB execute in an emulator over authored kernel state, TCBs '
            'and lists, reusing vTaskEnterCritical/ExitCritical, uxListRemove, vListInsertEnd and '
            'prvResetNextTaskUnblockTime as guarded original code; mret is not executed.',
            'configASSERT, the critical-section diagnostic body, vPortYield, newlib _reclaim_reent and '
            'vPortFree are supplied. Assert and yield are harness stops; the deferred idle-task cleanup that '
            'actually frees a self-deleted task is not executed here.',
            'The heap free, reent reclamation, idle-task termination sweep (prvCheckTasksWaitingTermination) '
            'and live rescheduling after a yield remain unproved on hardware.'])


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
        parser.exit(2, f'Cannot inspect main task deletion paths: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
