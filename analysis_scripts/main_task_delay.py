#!/usr/bin/env python3
"""Main FreeRTOS vTaskDelay: suspend, add to the delayed list, resume, yield.

This scope executes the original ``vTaskDelay`` (``0x80d3a84c``) end to end,
reusing every lower body as guarded original code: ``vTaskSuspendAll``
(``0x80d3969a``), ``prvAddCurrentTaskToDelayedList`` (``0x80d3927a``),
``vListInsert`` (``0x80d37db4``), ``uxListRemove``, ``vListInsertEnd`` and the
whole of ``xTaskResumeAll`` (``0x80d3a720``) covered in
[MAIN_SCHED_RESUME.md](MAIN_SCHED_RESUME.md).  Only ``configASSERT``, the
critical-section diagnostic body and ``vPortYield`` are supplied stubs; the
port yield is a no-op return, so the routine completes and the pending switch
is reported through the state it leaves behind.  Nothing here executes vendor
code outside the hash-guarded original ranges.
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
    from . import main_sched_resume as resume
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    import main_trap_irq as trap
    import main_freertos_kernel as kernel
    import main_sched_resume as resume
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000
VDELAY = 0x80d3a84c
SUSPEND_ALL = 0x80d3969a
ADD_DELAYED = 0x80d3927a
VLIST_INSERT = 0x80d37db4
ASSERT_DELAY = (0x70a1dfd8, kernel.TASKS_FILE, 0x582)

CODE = (
    (VDELAY, 0x52, 'daef5a6d226df143520084db96c9677031c9d652b3d0480ae120daa519d62d65'),
    (SUSPEND_ALL, 0x10, '1d6674239913b80938ccf567bfb2da76f1730d1fae21e12a17c44727f2318edc'),
    (ADD_DELAYED, 0xc0, '25c0af5932954522ad0c6cf248159d8f3ecc79ccd04576b592d2bc06c4cde4bc'),
    (VLIST_INSERT, 0x2e, '6219ab188e959de4ada935a6766757b661010d9985426ee47b0245d6da4b90d8'),
)
CSRS = kernel.CSRS
HARNESS_STACK = kernel.HARNESS_STACK
TCBS = kernel.TCBS
QUIET = kernel.QUIET


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(resume.Model):
    """The resume model, extended with suspend/add-to-delayed/delay."""

    def suspend_all(self):
        self.write(kernel.SUSPENDED, 4, word(self.read(kernel.SUSPENDED) + 1))

    def list_insert(self, lst, item):
        """vListInsert: ordered by value, with a tail insert for value 0xffffffff."""
        value = self.read(item)
        end = lst + 8
        if value == MASK:
            prev = self.read(lst + 0x10)        # xListEnd.pxPrevious
        else:
            prev = end
            nxt = self.read(prev + 4)
            while value >= self.read(nxt):
                prev = nxt
                nxt = self.read(prev + 4)
        after = self.read(prev + 4)
        self.write(item + 4, 4, after)
        self.write(after + 8, 4, item)
        self.write(item + 8, 4, prev)
        self.write(prev + 4, 4, item)
        self.write(item + 0x10, 4, lst)
        self.write(lst, 4, self.read(lst) + 1)

    def add_to_delayed(self, ticks, indefinite):
        tick = self.read(kernel.TICK_COUNT)
        current = self.read(kernel.CURRENT)
        if self.remove(current + 4) == 0:
            priority = self.read(current + 0x2c)
            self.write(kernel.TOP_READY, 4, ~(1 << (priority & 31)) & self.read(kernel.TOP_READY))
        if ticks == MASK and indefinite:
            self.insert_end(kernel.SUSPENDED_LIST, current + 4)
            return
        wake = word(ticks + tick)
        self.write(current + 4, 4, wake)
        if wake < tick:                      # the wake time wrapped: overflow list, no unblock update
            self.list_insert(self.read(kernel.OVERFLOW_PTR), current + 4)
        else:
            self.list_insert(self.read(kernel.DELAYED_PTR), current + 4)
            if wake < self.read(kernel.NEXT_UNBLOCK):
                self.write(kernel.NEXT_UNBLOCK, 4, wake)

    def delay(self, ticks):
        if ticks == 0:
            self.call(kernel.YIELD)
            return None
        if self.read(kernel.SUSPENDED) != 0:
            self.call(kernel.ASSERT, *ASSERT_DELAY)
        self.suspend_all()
        self.add_to_delayed(ticks, 0)
        if self.resume_all() == 0:
            self.call(kernel.YIELD)
        return None

    def operation(self, op):
        if op['name'].split('#')[0] == 'delay':
            return self.delay(op['args'][0])
        return super().operation(op)

    def run(self):
        rows = []
        for op in self.c['operations']:
            self.actions.append('op:' + op['name'])
            stopped = None
            try:
                self.operation(op)
            except trap.Stopped as stop:
                stopped = stop.label
            row = dict(stopped=stopped, csrs={str(n): self.csr[n] for n in CSRS})
            row['snapshot'] = {str(a): self.snapshot(a, n) for a, n in self.c['snapshot']}
            rows.append(row)
            if stopped:
                break
        return dict(actions=self.actions, rows=rows)


def contract(case):
    if case['scope'] != 'delay':
        raise ValueError('delay scope')
    if not 1 <= len(case['operations']) <= 4 or sum(len(v) for v in case['supplied'].values()) > 8:
        raise ValueError('bounded operations')
    return Model(case).run()


def words(*values):
    return kernel.words(*values)


def op(name, ticks):
    return dict(name=name, entry=VDELAY, call=True, args=[ticks], registers=False, result=False,
                result_high=False)


def base_case(name, ticks, state, snapshot=()):
    base_csrs = (0x20, 0x1888, 0x888, trap.TRAP_ENTRY, 0x51515151, trap.CODE_AREA, 0x8000000b, 0x21, 0x81100000)
    stub = dict(kernel.stubs())
    stub[str(kernel.YIELD)] = dict(kind='return', args=0)
    return dict(
        name='main_task_delay_' + name, scope='delay', supplied={}, quiet=[list(q) for q in QUIET],
        csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE + resume.CODE + kernel.CODE + trap.CODE],
        csrs={str(n): v for n, v in zip(CSRS, base_csrs)}, registers={'sp': HARNESS_STACK}, fregisters={},
        stubs=stub, stops={}, snapshot=[list(s) for s in snapshot],
        operations=[op('delay', ticks)], memory=state.memory())


def native_vectors():
    cases = []
    a, b = TCBS[:2]
    s = kernel.STACKS

    def add(case):
        case['expected'] = contract(case)
        cases.append(case)

    def base(tick=100, suspended=0, cur_prio=3, ready_peer=False):
        st = kernel.State(current=a, priority_bitmap=1 << cur_prio, tick=tick, suspended=suspended)
        st.w32(kernel.NUM_TASKS, 2)
        st.tcb(a, cur_prio, s[0], name=b'current')
        if ready_peer:
            st.tcb(b, cur_prio, s[1], name=b'peer')
            st.ready(cur_prio, [a, b], index=0)
            st.w32(kernel.TOP_READY, 1 << cur_prio)
        else:
            st.ready(cur_prio, [a])
        return st

    snap = [[kernel.SUSPENDED, 4], [kernel.TICK_COUNT, 4], [kernel.TOP_READY, 4], [a + 4, 4],
            [a + 4 + 0x10, 4], [kernel.NEXT_UNBLOCK, 4]]

    # ticks==0 yields immediately with no list work.
    add(base_case('zero_ticks_yields', 0, base(), snapshot=snap))

    # A plain delay: current task leaves the ready list and joins the delayed list.
    add(base_case('delay_moves_to_delayed_list', 10, base(), snapshot=snap + [[kernel.DELAYED1, 4]]))

    # Current task was the only one at its priority: its ready bit is cleared.
    st = base()
    add(base_case('clears_ready_bit_when_last', 25, st, snapshot=snap))

    # A ready peer at the same priority keeps the priority bit set.
    add(base_case('keeps_ready_bit_with_peer', 25, base(ready_peer=True), snapshot=snap))

    # Ordered insertion among existing sleepers in the delayed list.
    st = base(tick=100)
    st.tcb(b, 5, s[1], name=b'earlier')
    st.delayed([(b, 150)], lst=kernel.DELAYED1)
    add(base_case('ordered_before_later_sleeper', 10, st, snapshot=snap + [[kernel.DELAYED1 + 4, 4]]))
    st = base(tick=100)
    st.tcb(b, 5, s[1], name=b'sooner')
    st.delayed([(b, 105)], lst=kernel.DELAYED1)
    add(base_case('ordered_after_sooner_sleeper', 40, st, snapshot=snap + [[kernel.DELAYED1 + 4, 4]]))

    # Wake time wraps past the tick counter: the task joins the overflow list.
    add(base_case('overflow_list_on_wrap', 0x20, base(tick=0xfffffff0),
                  snapshot=snap + [[kernel.DELAYED2, 4]]))

    # Not called with the scheduler already suspended: the assertion fires.
    add(base_case('suspended_at_entry_asserts', 10, base(suspended=1), snapshot=snap))

    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h)
                        for a, n, h in trap.CODE + trap.DATA + kernel.CODE + kernel.DATA + resume.CODE + CODE],
                cases=cases)


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in CODE:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    for address, size, _ in CODE:
        source = trap.COPY['source'] + address - trap.COPY['destination']
        if memory.data[source - 0x70160000:source - 0x70160000 + size] != memory.read(address, size):
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
        reused_lower_ranges=len(kernel.CODE + kernel.DATA + resume.CODE),
        delay_routine=f'{VDELAY:#010x}', suspend_all=f'{SUSPEND_ALL:#010x}',
        add_to_delayed=f'{ADD_DELAYED:#010x}', vlist_insert=f'{VLIST_INSERT:#010x}',
        delayed_lists=[f'{kernel.DELAYED1:#010x}', f'{kernel.DELAYED2:#010x}'],
        suspended_list=f'{kernel.SUSPENDED_LIST:#010x}',
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'vTaskDelay executes in an emulator over authored kernel state, reusing vTaskSuspendAll, '
            'prvAddCurrentTaskToDelayedList, vListInsert, the list primitives and the whole of '
            'xTaskResumeAll as guarded original code. No hardware timer or interrupt is delivered.',
            'configASSERT, the critical-section diagnostic body and vPortYield are supplied stubs; vPortYield '
            'is a no-op return, so the context switch it would trigger is not modeled. The routine completes '
            'and the pending switch is visible only in the kernel state it leaves (the task moved off the '
            'ready lists onto a delayed list).',
            'The delayed/overflow/suspended list contents are authored. Indefinite blocking '
            '(ticks == 0xffffffff) is reachable only from other callers and is modeled but not exercised '
            'here; live preemption and the timer frequency remain unproved.'])


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
        parser.exit(2, f'Cannot inspect vTaskDelay: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
