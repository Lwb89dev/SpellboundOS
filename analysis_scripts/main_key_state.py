#!/usr/bin/env python3
"""Main-image gpio_key state machine (``gpio_key_state_machine`` ``0x701e923e``), state 0.

Executes in ``main-runtime`` the key event handler.  On each event it decodes the
GPIO level (``0x702bd6c8`` writes a press/release flag), then dispatches on the
per-key state byte (runtime context at ``0x70f92b74 + key*0x18``) through a
7-entry jump table.  This scope covers the dispatch and **state 0 (idle)**; the
configuration it reads is the one written by
[drv_key_init](MAIN_KEY_INIT.md) at object ``0x70f92bf4`` (per-key stride 0x30).

State 0:

- **press** (flag != 0): increment the press counter (runtime ``+4``); while it
  stays at or below the press threshold (config ``+0x58``) just run the timer
  check (``0x701e8afc``); once it exceeds the threshold, store the next state
  (``0x701e90be``; state 2 if config ``+0x50`` bit 4 is set, else state 1) and
  run the timer check;
- **release** (flag == 0): clear the press counter and run the idle handler
  (``0x701e8dba``).

Supplied (stubbed): the GPIO decode (writes the press/release flag), the
state store, the timer check, the idle handler and the event upload.  Later
blocks will cover states 1..6 (combo, long press, double click, repeat).
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_freertos_kernel as kernel
else:
    import main_freertos_kernel as kernel

BOUND = 20000
M32 = 0xffffffff

STATE_MACHINE = 0x701e923e
DECODE = 0x702bd6c8
STORE_STATE = 0x701e90be
TIMER_CHECK = 0x701e8afc
IDLE_HANDLER = 0x701e8dba
EVENT_UPLOAD = 0x701e8b40

RT_BASE = 0x70f92b74                 # runtime per-key context (stride 0x18)
OBJ = 0x70f92bf4                     # driver object / config base (per-key stride 0x30)
PRESS_THRESHOLD_OFF = 0x58           # config +0x58
FLAGS_OFF = 0x50                     # config +0x50 (bit 4 selects state 2 over state 1)

MSG = 0x81003000                     # message: [0]=event struct, [4]=config base
EVENT = 0x81003100                   # event struct: [0]=key index, [2]=event code
STACK = kernel.HARNESS_STACK         # 0x81001000
LOCAL_FLAG = STACK - 0x40 + 0xf      # the decode output on the handler's stack frame
EVENT_CODE = 0x0042
OBJ_SIZE = 0xb0                       # covers both per-key config blocks (stride 0x30)
CSRS = kernel.CSRS

CODE = ((STATE_MACHINE, 0x5b8, 'ddbbe73f3fcd87698a8817ec8c175569bc50aa5a8262b380663c2b2b94e4e338'),)


class Model(kernel.Model):
    def __init__(self, case):
        super().__init__(case)
        self.svc = case['services']

    def leaf(self, address, *args):
        self.actions.append(':'.join(['call', str(address)] + [str(a & M32) for a in args]))

    def u8(self, a):
        return self.read(a, 1)

    def u16(self, a):
        return self.read(a, 2)

    def u32(self, a):
        return self.read(a, 4)

    def put(self, a, size, v):
        self.write(a, size, v & ((1 << (8 * size)) - 1))

    def run_machine(self):
        event = self.u32(MSG)
        config = self.u32(MSG + 4)
        key = self.u8(event)
        self.leaf(DECODE, self.u16(event + 2), LOCAL_FLAG)
        flag = self.svc['decode']                    # written to the stack frame by the stub
        state = self.u8(RT_BASE + key * 0x18)
        if state > 6:
            return self.idle()
        if state == 0:
            return self.state0(event, config, key, flag)
        raise ValueError('only state 0 is modelled')

    def state0(self, event, config, key, flag):
        rt = RT_BASE + key * 0x18
        if flag != 0:
            # A non-zero decode flag is the release/idle edge: clear the counter and go idle.
            self.put(rt + 4, 4, 0)
            return self.idle()
        counter = self.u32(rt + 4) + 1
        self.put(rt + 4, 4, counter)
        cfg = config + key * 0x30
        if self.u32(cfg + PRESS_THRESHOLD_OFF) < counter:
            flags = self.u32(cfg + FLAGS_OFF)
            self.leaf(STORE_STATE, event, 1 if (flags >> 4) & 1 else 2)
        return self.done()

    def done(self):
        self.leaf(TIMER_CHECK, MSG)
        return word(self.svc['timer'])

    def idle(self):
        self.leaf(IDLE_HANDLER, MSG)
        return word(self.svc['idle'])

    def operation(self, op):
        if op['name'] != 'event':
            raise ValueError('operation')
        return self.run_machine()


def word(v):
    return v & M32


def contract(case):
    if case['scope'] != 'key_state' or len(case['operations']) != 1:
        raise ValueError('key state scope')
    return Model(case).run()


def case(name, key=0, state=0, press=1, counter=0, threshold=3, flags=0, **svc_over):
    g = dict(decode=press, timer=0, idle=0)
    g.update(svc_over)
    msg = struct.pack('<II', EVENT, OBJ)
    event = bytearray(0x10)
    event[0] = key
    struct.pack_into('<H', event, 2, EVENT_CODE)
    rt = bytearray((key + 1) * 0x18)
    rt[key * 0x18] = state
    struct.pack_into('<I', rt, key * 0x18 + 4, counter)
    obj = bytearray(OBJ_SIZE)
    struct.pack_into('<I', obj, key * 0x30 + PRESS_THRESHOLD_OFF, threshold)
    struct.pack_into('<I', obj, key * 0x30 + FLAGS_OFF, flags)
    stubs = {
        str(DECODE): dict(kind='store', out_arg=1, size=1, value=g['decode'], value_ret=0, args=2),
        str(STORE_STATE): dict(kind='return', args=2),
        str(TIMER_CHECK): dict(kind='return', args=1, value=g['timer']),
        str(IDLE_HANDLER): dict(kind='return', args=1, value=g['idle']),
        str(EVENT_UPLOAD): dict(kind='return', args=2),
    }
    return dict(
        name='main_key_state_' + name, scope='key_state', supplied={}, quiet=[[0x81000000, 0x81002000]],
        csr_allowed=list(CSRS), ranges=[[a, a + n] for a, n, _ in CODE],
        csrs={str(n): 0 for n in CSRS}, registers={'sp': STACK}, fregisters={}, stubs=stubs, stops={},
        snapshot=[], operations=[dict(name='event', entry=STATE_MACHINE, call=True, args=[MSG],
                                      registers=False, result=True, result_high=False)],
        memory=[[MSG, msg.hex()], [EVENT, bytes(event).hex()], [RT_BASE, bytes(rt).hex()],
                [OBJ, bytes(obj).hex()]], services=g)




def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    # A zero decode flag is the press/hold edge (counter builds); a non-zero flag is release.
    add(case('press_below_threshold', key=0, press=0, counter=0, threshold=3))
    add(case('press_reaches_threshold_state2', key=0, press=0, counter=3, threshold=3, flags=0))
    add(case('press_reaches_threshold_state1', key=0, press=0, counter=3, threshold=3, flags=0x10))
    add(case('release_clears_counter', key=0, press=1, counter=5))
    add(case('press_key1', key=1, press=0, counter=0, threshold=3))
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
        results[c['name'].removeprefix('main_key_state_')] = row['observed']['rows'][0]['a0']
    return dict(
        image='main firmware (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        function=f'{STATE_MACHINE:#010x} (gpio_key_state_machine)',
        dispatch=dict(
            decode=f'{DECODE:#010x} writes a press/release flag; must return 0',
            state_byte=f'runtime context {RT_BASE:#010x} + key*0x18, +0 (7-entry jump table)',
            config=f'driver object {OBJ:#010x} + key*0x30 (press threshold +0x58, flags +0x50)'),
        state0=dict(
            press='increment press counter (+4); below threshold -> timer check; above threshold -> '
                  'store next state (0x701e90be, state 2 if flags bit 4 else state 1) then timer check',
            release='clear the press counter and run the idle handler (0x701e8dba)',
            helpers=dict(timer_check=f'{TIMER_CHECK:#010x}', idle_handler=f'{IDLE_HANDLER:#010x}',
                         store_state=f'{STORE_STATE:#010x}', event_upload=f'{EVENT_UPLOAD:#010x}')),
        return_codes=results,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The GPIO decode, state store, timer check, idle handler and event upload are stubbed; the state '
            'machine runs as real code and the runtime counter writes are recorded.',
            'Only the dispatch and state 0 (idle) are covered. States 1..6 (combo, long press, double click, '
            'repeat) read both keys\' contexts and the combo globals and are mapped but not yet executed.'])


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
        parser.exit(2, f'Cannot inspect key state machine: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
