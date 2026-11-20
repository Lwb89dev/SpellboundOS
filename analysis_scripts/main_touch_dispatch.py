#!/usr/bin/env python3
"""Main-image ZTW622 touch delivery: event dispatcher and poll-timer callback.

Executes in ``main-runtime`` the two small, self-contained delivery helpers that
sit above the [report handler](MAIN_TOUCH_REPORT.md) and are started by
[ztw622_open](MAIN_TOUCH_OPEN.md):

- the **event dispatcher** ``0x701eac38(dev, mode, value_ptr)``: builds a 0x38
  byte input event on the stack (``+0 = 1``, ``+8 = 1``, ``+0xc = mode``,
  ``+0xe = *value_ptr`` as a 16-bit field) and calls the device callback
  ``dev->callback(dev, &event, 0)`` (``dev+0x3c``); returns ``-4`` when the
  device or its callback is NULL, otherwise the callback's result.  This is how
  the firmware-upgrade worker reports stage/progress events to the UI;
- the **poll-timer callback** ``0x701eb154``: sets the input state byte at
  ``0x70f8e100`` to ``2`` (poll), notifies the input task (``0x80d3dedc`` on the
  task object at ``0x70f8e110``) and, when the notify returns non-zero, restarts
  the 5000 ms poll timer through ``0x701eb102`` (``0x80d36ba0(timer, 0x1388)``),
  returning ``-4``/``-14`` on a missing or failing timer.

Supplied (stubbed): memset, the device callback, the task-notify service, the
timer-start service and the logger.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
    from . import main_touch_report as rpt
else:
    import main_freertos_kernel as kernel
    import main_touch_report as rpt

BOUND = 20000
word = rpt.word

DISPATCH_BUILD = 0x701eac38
POLL_TIMER_CB = 0x701eb154
TIMER_START_WRAP = rpt.TIMER_START_WRAP     # 0x701eb102
NOTIFY = 0x80d3dedc
TIMER_START = rpt.TIMER_START               # 0x80d36ba0
MEMSET, LOGGER = rpt.MEMSET, rpt.LOGGER
EVENT_SIZE = rpt.EVENT_SIZE                  # 0x38
TIMER_MS = rpt.TIMER_MS                      # 5000

INPUT_OPEN_BYTE = 0x70f8e100
TIMER_HANDLE = 0x70f8e104
INPUT_TASK_SLOT = 0x70f8e110

DEV = 0x81005000
CALLBACK = 0x81006000
VALUE_PTR = 0x81007000
STACK = kernel.HARNESS_STACK                 # 0x81001000, within the quiet window
EVT = STACK - 0x48                           # dispatcher's event frame (sp-0x50+8)
THREAD_OBJ, TIMER_OBJ = 0x0d0d0001, 0x0e0e0001
LOG_ERROR = 3

CODE = (
    (DISPATCH_BUILD, 0x54, 'c079b5f354b67346877f6eaec7edbdd5ebbbb7dfc1887ed080eae7315178924e'),
    rpt.CODE[2],                             # TIMER_START_WRAP (0x701eb102, from the report scope)
    (POLL_TIMER_CB, 0x36, 'c6b14bd5f58f96e4454f89e273875ca29fb46b819beead659ac63f5b9db7d348'),
)
CSRS = kernel.CSRS


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(word(a)) for a in args]))

    def u8(self, a):
        return self.read(a, 1)

    def u16(self, a):
        return self.read(a, 2)

    def u32(self, a):
        return self.read(a, 4)

    def put(self, a, size, v):
        self.write(a, size, v & ((1 << (8 * size)) - 1))

    # 0x701eac38
    def dispatch_build(self, dev, mode, value_ptr):
        if dev == 0:
            return word(-4)
        self.leaf(MEMSET, EVT, 0, EVENT_SIZE)
        for i in range(EVENT_SIZE):
            self.put(EVT + i, 1, 0)                 # stack frame is quiet: not recorded
        self.put(EVT + 0, 1, 1)
        self.put(EVT + 8, 1, 1)
        self.put(EVT + 0xc, 1, mode)
        self.put(EVT + 0xe, 2, self.u16(value_ptr))
        callback = self.u32(dev + 0x3c)
        if callback == 0:
            return word(-4)
        self.leaf(callback, dev, EVT, 0)
        self.actions.append('cap:' + bytes(self.u8(EVT + i) for i in range(EVENT_SIZE)).hex())
        return word(self.svc['callback'])

    # 0x701eb102
    def timer_start_wrap(self, timer):
        if timer == 0:
            return word(-4)
        self.leaf(TIMER_START, timer, TIMER_MS)
        if self.svc['timer_start'] == 0:
            return 0
        self.leaf(LOGGER, LOG_ERROR)
        return word(-14)

    # 0x701eb154
    def poll(self):
        thread = self.u32(INPUT_TASK_SLOT)
        self.put(INPUT_OPEN_BYTE, 1, 2)
        self.leaf(NOTIFY, thread)
        if self.svc['notify'] == 0:
            return word(self.svc['notify'])
        return self.timer_start_wrap(self.u32(TIMER_HANDLE))

    def operation(self, op):
        if op['name'] == 'dispatch':
            return self.dispatch_build(*op['args'])
        if op['name'] == 'poll':
            return self.poll()
        raise ValueError('operation')


def contract(case):
    if case['scope'] != 'touch_dispatch' or len(case['operations']) != 1:
        raise ValueError('touch dispatch scope')
    return Model(case).run()


def case(name, op, args=(), cb_present=True, value=0x1234, **over):
    g = dict(callback=0, notify=1, timer_start=0)
    g.update(over)
    dev = bytearray(0x44)
    struct.pack_into('<I', dev, 0x3c, CALLBACK if cb_present else 0)
    bss = bytearray(0x14)                             # 0x70f8e100 .. 0x70f8e114
    struct.pack_into('<I', bss, 0x04, TIMER_OBJ)      # 0x70f8e104
    struct.pack_into('<I', bss, 0x10, THREAD_OBJ)     # 0x70f8e110
    value_mem = struct.pack('<I', value)
    stubs = {
        str(MEMSET): dict(kind='memset', args=3), str(LOGGER): dict(kind='return', args=1),
        str(CALLBACK): dict(kind='capture', ptr_arg=1, size=EVENT_SIZE, value=g['callback'], args=3),
        str(NOTIFY): dict(kind='return', args=1, value=g['notify']),
        str(TIMER_START): dict(kind='return', args=2, value=g['timer_start']),
    }
    entry = DISPATCH_BUILD if op == 'dispatch' else POLL_TIMER_CB
    memory = [[DEV, bytes(dev).hex()], [INPUT_OPEN_BYTE, bytes(bss).hex()], [VALUE_PTR, value_mem.hex()]]
    return dict(
        name='main_touch_dispatch_' + name, scope='touch_dispatch', supplied={},
        quiet=[[0x81000000, 0x81002000]], csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name=op, entry=entry, call=True, args=list(args), registers=False,
                                      result=True, result_high=False)],
        memory=memory, services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    add(case('dispatch_event', 'dispatch', (DEV, 5, VALUE_PTR), value=0x00a0, callback=0))
    add(case('dispatch_callback_error', 'dispatch', (DEV, 2, VALUE_PTR), value=0x0103, callback=0xd))
    add(case('dispatch_no_callback', 'dispatch', (DEV, 1, VALUE_PTR), cb_present=False))
    add(case('dispatch_null_device', 'dispatch', (0, 1, VALUE_PTR)))
    add(case('poll_notify_and_restart', 'poll', notify=1, timer_start=0))
    add(case('poll_notify_idle', 'poll', notify=0))
    add(case('poll_timer_start_fails', 'poll', notify=1, timer_start=0x55))
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in CODE], cases=cases)


def evidence(archive, vectors, validation):
    memory = kernel.image_memory(archive)
    for address, size, expected in CODE:
        if hashlib.sha256(memory.read(address, size)).hexdigest() != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    vector_doc = native_vectors()
    if json.loads(vectors.read_bytes()) != vector_doc:
        raise ValueError('vectors differ')
    report = json.loads(validation.read_bytes())
    if report['hardware_execution'] is not False or report['bound_per_case'] != BOUND or \
            report['case_count'] != len(vector_doc['cases']) or len(report['cases']) != len(vector_doc['cases']):
        raise ValueError('report bound/count')
    results = {}
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
        results[c['name'].removeprefix('main_touch_dispatch_')] = row['observed']['rows'][0]['a0']
    event = None
    for c in vector_doc['cases']:
        if c['name'].endswith('dispatch_event'):
            event = next(a[4:] for a in c['expected']['actions'] if a.startswith('cap:'))
    return dict(
        image='main firmware (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        dispatcher=dict(
            function=f'{DISPATCH_BUILD:#010x}(dev, mode, value_ptr)',
            event_layout='0x38 bytes: +0 = 1, +8 = 1, +0xc = mode, +0xe = *value_ptr (16-bit)',
            callback='dev->callback(dev, &event, 0) at dev+0x3c; returns -4 when dev or callback is NULL',
            sample_event=event),
        poll_timer=dict(
            callback=f'{POLL_TIMER_CB:#010x}',
            state_byte=f'{INPUT_OPEN_BYTE:#010x} set to 2 (poll)',
            notify=f'{NOTIFY:#010x} on the task object at {INPUT_TASK_SLOT:#010x}',
            restart=f'{TIMER_START_WRAP:#010x} -> {TIMER_START:#010x}(timer, {TIMER_MS}) when notify returns non-zero'),
        return_codes=results,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The device callback, the task-notify and timer-start services, memset and the logger are stubbed; '
            'the two helpers and the timer-start wrapper run as real code.',
            'The full input-task body (entry 0x701eca9c, the TP firmware-upgrade / ODR worker) is a separate, '
            'large routine and is not executed here.'])


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
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, IndexError, struct.error) as error:
        parser.exit(2, f'Cannot inspect touch dispatch: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
