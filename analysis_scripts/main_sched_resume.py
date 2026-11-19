#!/usr/bin/env python3
"""Main FreeRTOS xTaskResumeAll: scheduler unlock, pending-ready and tick catch-up.

This scope executes the original ``xTaskResumeAll`` at ``0x80d3a720`` over
authored kernel state, reusing every sub-body already covered by
[MAIN_FREERTOS_KERNEL.md](MAIN_FREERTOS_KERNEL.md): the task critical section
(``0x80d3a062``/``0x80d3a0ae``), the list primitives, ``xTaskIncrementTick``
and ``prvResetNextTaskUnblockTime`` all run as original code; only
``configASSERT``, the critical-section diagnostic body and ``vPortYield`` are
supplied stubs.  The independent model is the one from the kernel scope,
extended with the resume-all body.  Nothing here executes vendor code outside
the hash-guarded original ranges.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_trap_irq as trap
    from . import main_freertos_kernel as kernel
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    import main_trap_irq as trap
    import main_freertos_kernel as kernel
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000
RESUME = 0x80d3a720
PENDING_INDEX = kernel.PENDING_READY + 0xc     # pxPendingReadyList.pxIndex at 0x80c07ea8
ASSERT_RESUME = (0x70a1e020, kernel.TASKS_FILE, 0x902)

CODE = ((RESUME, 0x12c, 'de71fd48d15440851468257e9c0604b3b42e14215f319e7a87705349dc391d65'),)
CSRS = kernel.CSRS
X, F = kernel.X, kernel.F
HARNESS_STACK = kernel.HARNESS_STACK
TCBS = kernel.TCBS
QUIET = kernel.QUIET


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(kernel.Model):
    """The kernel model, extended with the xTaskResumeAll body."""

    def resume_all(self):
        if self.read(kernel.SUSPENDED) == 0:
            self.call(kernel.ASSERT, *ASSERT_RESUME)
        self.enter_critical()
        self.write(kernel.SUSPENDED, 4, word(self.read(kernel.SUSPENDED) - 1))
        result = 0
        if self.read(kernel.SUSPENDED) == 0 and self.read(kernel.NUM_TASKS) != 0:
            moved = 0
            while self.read(kernel.PENDING_READY):
                tcb = self.read(self.read(PENDING_INDEX) + 0xc)
                moved = tcb
                self.remove(tcb + 0x18)
                self.remove(tcb + 4)
                priority = self.read(tcb + 0x2c)
                self.write(kernel.TOP_READY, 4, (1 << (priority & 31)) | self.read(kernel.TOP_READY))
                self.insert_end(word(kernel.READY + priority * 0x14), tcb + 4)
                if self.read(self.read(kernel.CURRENT) + 0x2c) <= priority:
                    self.write(kernel.YIELD_PENDING, 4, 1)
            if moved:
                self.reset_next_unblock()
            pended = self.read(kernel.PENDED)
            if pended:
                for _ in range(pended):
                    if self.tick():
                        self.write(kernel.YIELD_PENDING, 4, 1)
                self.write(kernel.PENDED, 4, 0)
            if self.read(kernel.YIELD_PENDING):
                self.call(kernel.YIELD)
                result = 1
        self.exit_critical()
        return result

    def operation(self, op):
        if op['name'].split('#')[0] == 'resume':
            return self.resume_all()
        return super().operation(op)

    def run(self):
        rows = []
        for op in self.c['operations']:
            self.actions.append('op:' + op['name'])
            stopped, result = None, None
            try:
                result = self.operation(op)
            except trap.Stopped as stop:
                stopped = stop.label
            row = dict(stopped=stopped, csrs={str(n): self.csr[n] for n in CSRS})
            if stopped is None:
                row['a0'] = word(result)
            row['snapshot'] = {str(a): self.snapshot(a, n) for a, n in self.c['snapshot']}
            rows.append(row)
            if stopped:
                break
        return dict(actions=self.actions, rows=rows)


def contract(case):
    if case['scope'] != 'resume':
        raise ValueError('resume scope')
    if not 1 <= len(case['operations']) <= 4 or sum(len(v) for v in case['supplied'].values()) > 8:
        raise ValueError('bounded operations')
    return Model(case).run()


def words(*values):
    return kernel.words(*values)


def op(name):
    return dict(name=name, entry=RESUME, call=True, args=[], registers=False, result=True, result_high=False)


def base_case(name, state, snapshot=(), extra_stubs=None):
    base_csrs = (0x20, 0x1888, 0x888, trap.TRAP_ENTRY, 0x51515151, trap.CODE_AREA, 0x8000000b, 0x21, 0x81100000)
    stub = dict(kernel.stubs(extra_stubs or {}))
    # vPortYield (0x80d3965c) is a no-op return here: the context switch it would
    # trigger is not modeled, so resume-all completes and reports a pending yield.
    stub[str(kernel.YIELD)] = dict(kind='return', args=0)
    return dict(
        name='main_sched_resume_' + name, scope='resume', supplied={}, quiet=[list(q) for q in QUIET],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE + kernel.CODE + trap.CODE],
        csrs={str(n): v for n, v in zip(CSRS, base_csrs)}, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stub, stops={}, snapshot=[list(s) for s in snapshot],
        operations=[op('resume')], memory=state.memory())


def native_vectors():
    cases = []
    a, b, c = TCBS[:3]
    s = kernel.STACKS

    def add(case):
        case['expected'] = contract(case)
        cases.append(case)

    def base(suspended=1, tasks=2, current=a, cur_prio=3, pended=0, bitmap=1 << 3):
        st = kernel.State(current=current, priority_bitmap=bitmap, suspended=suspended)
        st.w32(kernel.NUM_TASKS, tasks)
        st.w32(kernel.PENDED, pended)
        st.tcb(a, cur_prio, s[0], name=b'current')
        st.ready(cur_prio, [a])
        return st

    snap = [[kernel.SUSPENDED, 4], [kernel.YIELD_PENDING, 4], [kernel.TOP_READY, 4], [kernel.PENDED, 4],
            [kernel.CURRENT, 4]]

    # Suspend count above 1: decrement only, nothing else runs.
    add(base_case('decrement_only', base(suspended=2), snapshot=snap))
    # Suspend count to zero, nothing pending, no pended ticks.
    add(base_case('unlock_no_work', base(suspended=1), snapshot=snap))
    # No tasks: the pending/tick work is skipped even at zero.
    add(base_case('unlock_no_tasks', base(suspended=1, tasks=0), snapshot=snap))

    # A pending-ready task of lower priority: moved, no yield.
    st = base()
    st.tcb(b, 1, s[1], name=b'woken')
    st.delayed([(b, 500)])                      # state item sits in a delayed list
    st.event(b, kernel.PENDING_READY)           # event item in the pending-ready list
    add(base_case('pending_lower_priority_moved', st,
                  snapshot=snap + [[b + 4 + 0x10, 4], [kernel.READY + 1 * 0x14, 0x14]]))

    # A pending-ready task of higher priority: moved and a yield requested.
    st = base()
    st.tcb(b, 6, s[1], name=b'urgent')
    st.delayed([(b, 500)])
    st.event(b, kernel.PENDING_READY)
    add(base_case('pending_higher_priority_yields', st, snapshot=snap))

    # Two pending-ready tasks served until the list empties.
    st = base()
    st.tcb(b, 2, s[1], name=b'first')
    st.tcb(c, 4, s[2], name=b'second')
    st.delayed([(b, 400), (c, 450)])
    st.link(kernel.PENDING_READY, [(b + 0x18, 0, b), (c + 0x18, 0, c)])
    add(base_case('two_pending_served', st, snapshot=snap + [[kernel.PENDING_READY, 4]]))

    # Pended ticks caught up through xTaskIncrementTick; equal-priority ready peer slices.
    st = base(pended=3)
    st.tcb(b, 3, s[1], name=b'peer')
    st.ready(3, [a, b])
    add(base_case('pended_ticks_caught_up', st, snapshot=snap + [[kernel.TICK_COUNT, 4]]))

    # Pended ticks that cross a wakeup deadline request a yield.
    st = base(pended=2)
    st.w32(kernel.TICK_COUNT, 100)
    st.w32(kernel.NEXT_UNBLOCK, 101)
    st.tcb(b, 6, s[1], name=b'sleeper')
    st.delayed([(b, 101)])
    add(base_case('pended_ticks_wake_higher_priority', st, snapshot=snap + [[kernel.TICK_COUNT, 4]]))

    # Not suspended at entry: the assertion fires.
    add(base_case('not_suspended_asserts', base(suspended=0), snapshot=snap))

    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h)
                        for a, n, h in trap.CODE + trap.DATA + kernel.CODE + kernel.DATA + CODE],
                cases=cases)


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in CODE:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    source = trap.COPY['source'] + RESUME - trap.COPY['destination']
    if memory.data[source - 0x70160000:source - 0x70160000 + 0x12c] != memory.read(RESUME, 0x12c):
        raise ValueError('copied code differs from its load image')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    for row, case in zip(report['cases'], vector_doc['cases']):
        if row['name'] != case['name'] or row['observed'] != case['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + case['name'])
    return dict(
        main_sha256=MAIN_HASH, vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE},
        reused_kernel_ranges=len(kernel.CODE + kernel.DATA),
        resume_routine=f'{RESUME:#010x}',
        globals=dict(suspended=f'{kernel.SUSPENDED:#010x}', pending_ready=f'{kernel.PENDING_READY:#010x}',
                     pending_index=f'{PENDING_INDEX:#010x}', pended_ticks=f'{kernel.PENDED:#010x}',
                     yield_pending=f'{kernel.YIELD_PENDING:#010x}'),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'xTaskResumeAll executes in an emulator over authored kernel state, reusing the original task '
            'critical section, list primitives, xTaskIncrementTick and prvResetNextTaskUnblockTime as '
            'guarded original code. No hardware timer or interrupt is delivered.',
            'configASSERT, the critical-section diagnostic body and vPortYield are supplied stubs. vPortYield '
            'is a no-op return, so the context switch it would trigger is not modeled; resume-all completes '
            'and reports the pending yield through its return value and xYieldPending.',
            'The pending-ready/delayed list contents are authored. Live concurrency, real preemption and the '
            'timer frequency remain unproved, as in the kernel scope.'])


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
        parser.exit(2, f'Cannot inspect xTaskResumeAll: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
