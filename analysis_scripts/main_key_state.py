#!/usr/bin/env python3
"""Main-image gpio_key state machine (``gpio_key_state_machine`` ``0x701e923e``).

Executes in ``main-runtime`` the key event handler.  On each event it decodes the
GPIO level (``0x702bd6c8`` writes a press/release flag), then dispatches on the
per-key state byte (runtime context at ``0x70f92b74 + key*0x18``) through a
7-entry jump table.  This scope covers the dispatch and **states 0 and 2..6**
(the single-key paths taken while the combo-pending global ``0x70f8e0dc`` is
clear); the configuration it reads is the one written by
[drv_key_init](MAIN_KEY_INIT.md) at object ``0x70f92bf4`` (per-key stride 0x30).

Per-key runtime context (``0x70f92b74 + key*0x18``): ``+0`` state byte, ``+4``
press counter, ``+8`` repeat counter, ``+0xc`` flag byte.  Config flags live at
``+0x50``; the states read thresholds at ``+0x58``/``+0x5c``/``+0x60``/``+0x64``
(press), ``+0x68`` (hold window), ``+0x6c`` (repeat max) and ``+0x70`` (release).

- **state 0** (idle): press builds the counter, storing state 1/2 at the
  threshold; release clears it.
- **state 2**: press stores state 4/5 and uploads bit 2; release uploads bit 8
  then, by the flags, either confirms a hold (store state 3) or ends (store 0).
- **state 3**: press uploads bits 0x10/0x4 and stores state 5; the repeat path
  uploads bit 1 and ends (store 0).
- **state 4**: press stores state 6 and uploads bit 0x20; release uploads bit 8
  and ends.
- **state 5**: press only counts; release ends (upload bit 8 by the flags).
- **state 6**: press uploads bit 0x40 and stores state 5; release ends.

Supplied (stubbed): the GPIO decode (writes the press/release flag), the state
store, the timer check, the idle handler and the event upload.  State 1 (combo,
two-key) and the combo sub-paths of states 2..6 are not covered here.
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

RT_BASE = 0x70f92b74
OBJ = 0x70f92bf4
COMBO_GLOBALS = 0x70f8e0d8           # combo-key-1 index (cleared when key 0 is active)
COMBO_PENDING = 0x70f8e0dc           # combo-pending flag
FLAGS = 0x50

MSG = 0x81003000
EVENT = 0x81003100
STACK = kernel.HARNESS_STACK
LOCAL_FLAG = STACK - 0x40 + 0xf
EVENT_CODE = 0x0042
OBJ_SIZE = 0xb0
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

    def u32(self, a):
        return self.read(a, 4)

    def u16(self, a):
        return self.read(a, 2)

    def put(self, a, v):
        self.write(a, 4, v & M32)

    def done(self):
        self.leaf(TIMER_CHECK, MSG)
        return self.svc['timer'] & M32

    def idle(self):
        self.leaf(IDLE_HANDLER, MSG)
        return self.svc['idle'] & M32

    def upload(self, bit):
        self.leaf(EVENT_UPLOAD, MSG, bit)

    def store(self, state):
        self.leaf(STORE_STATE, self.u32(MSG), state)

    def run_machine(self):
        event = self.u32(MSG)
        config = self.u32(MSG + 4)
        key = self.u8(event)
        self.leaf(DECODE, self.u16(event + 2), LOCAL_FLAG)
        flag = self.svc['decode']
        state = self.u8(RT_BASE + key * 0x18)
        if state > 6:
            return self.idle()
        rt = RT_BASE + key * 0x18

        def cfg(off):
            return self.u32(config + key * 0x30 + off)

        flags = cfg(FLAGS)

        def bit(n):
            return (flags >> n) & 1

        if state == 0:
            if flag != 0:
                self.put(rt + 4, 0)
                return self.idle()
            counter = self.u32(rt + 4) + 1
            self.put(rt + 4, counter)
            if cfg(0x58) < counter:
                self.store(1 if bit(4) else 2)
            return self.done()

        if state == 1:
            combo = self.u8(COMBO_PENDING)
            if flag != 0:                        # release
                if combo == 0:
                    self.upload(0x10)
                self.store(2)
                return self.done()
            counter = self.u32(rt + 4) + 1        # press
            self.put(rt + 4, counter)
            if combo != 0:
                self.store(2)
                return self.done()
            if cfg(0x58) + cfg(0x74) < counter:
                self.upload(0x10)
                self.store(2)
                return self.done()
            if self.u32(RT_BASE + 4) != 0:        # key 0 active -> clear the combo-key-1 index
                self.write(COMBO_GLOBALS, 1, 0)
            if self.u32(RT_BASE + 0x1c) == 0:     # key 1 idle -> no pairing
                return self.done()
            raise ValueError('two-key combo pairing is not modelled')

        if state == 2:
            if flag == 0:
                counter = self.u32(rt + 4) + 1
                self.put(rt + 4, counter)
                if not bit(1) or cfg(0x5c) >= counter:
                    return self.done()
                self.store(4 if bit(5) else 5)
                self.upload(2)
                return self.done()
            if not bit(3):
                return self.idle()
            self.upload(8)
            if bit(2) and cfg(0x68) >= self.u32(rt + 4) and self.u8(rt + 0xc) != 0:
                self.put(rt + 8, 0)
                self.store(3)
                self.put(rt + 4, 0)
                return self.done()
            if bit(0):
                self.upload(1)
            self.store(0)
            self.put(rt + 4, 0)
            return self.idle()

        if state == 3:
            if flag == 0:
                counter = self.u32(rt + 4) + 1
                self.put(rt + 4, counter)
                if cfg(0x58) >= counter:
                    return self.done()
                if bit(4):
                    self.upload(0x10)
                if bit(2) and self.u8(rt + 0xc) != 0:
                    self.upload(4)
                self.store(5)
                return self.done()
            repeat = self.u32(rt + 8) + 1
            self.put(rt + 8, repeat)
            if cfg(0x6c) >= repeat:
                return self.done()
            self.put(rt + 8, 0)
            self.put(rt + 4, 0)
            if bit(0):
                self.upload(1)
            self.store(0)
            return self.idle()

        if state == 4:
            if flag == 0:
                counter = self.u32(rt + 4) + 1
                self.put(rt + 4, counter)
                if not bit(5) or cfg(0x60) >= counter:
                    return self.done()
                self.store(6)
                self.upload(0x20)
                return self.done()
            self.put(rt + 4, 0)
            if bit(3):
                self.upload(8)
            self.store(0)
            return self.idle()

        if state == 5:
            counter = self.u32(rt + 4) + 1
            self.put(rt + 4, counter)
            if flag == 0:
                return self.done()
            if cfg(0x70) >= counter:
                return self.done()
            self.put(rt + 4, 0)
            if bit(3):
                self.upload(8)
            self.store(0)
            return self.idle()

        if state == 6:
            if flag == 0:
                counter = self.u32(rt + 4) + 1
                self.put(rt + 4, counter)
                if not bit(6) or cfg(0x64) >= counter:
                    return self.done()
                self.upload(0x40)
                self.store(5)
                return self.done()
            self.put(rt + 4, 0)
            if bit(3):
                self.upload(8)
            self.store(0)
            return self.idle()
        raise ValueError('state')

    def operation(self, op):
        if op['name'] != 'event':
            raise ValueError('operation')
        return self.run_machine()


def contract(case):
    if case['scope'] != 'key_state' or len(case['operations']) != 1:
        raise ValueError('key state scope')
    return Model(case).run()


# Config threshold fields (offset within the per-key 0x30 block -> value).
THRESHOLDS = {0x58: 3, 0x5c: 3, 0x60: 3, 0x64: 3, 0x68: 10, 0x6c: 3, 0x70: 3, 0x74: 0xa}


def case(name, key=0, state=0, press=0, counter=0, repeat=0, flagbyte=0, flags=0, combo=0):
    g = dict(decode=press, timer=0, idle=0)
    msg = struct.pack('<II', EVENT, OBJ)
    event = bytearray(0x10)
    event[0] = key
    struct.pack_into('<H', event, 2, EVENT_CODE)
    rt = bytearray(0x30)                # both keys' runtime contexts (state 1 reads both counters)
    base = key * 0x18
    rt[base] = state
    struct.pack_into('<I', rt, base + 4, counter)
    struct.pack_into('<I', rt, base + 8, repeat)
    rt[base + 0xc] = flagbyte
    obj = bytearray(OBJ_SIZE)
    struct.pack_into('<I', obj, key * 0x30 + FLAGS, flags)
    for off, value in THRESHOLDS.items():
        struct.pack_into('<I', obj, key * 0x30 + off, value)
    combo_block = bytearray(0x10)       # 0x70f8e0d8..; the pending flag at +4 gates the two-key paths
    combo_block[4] = combo
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
                [OBJ, bytes(obj).hex()], [COMBO_GLOBALS, bytes(combo_block).hex()]], services=g)


def native_vectors():
    cases = []

    def add(c_):
        c_['expected'] = contract(c_)
        cases.append(c_)

    # state 0
    add(case('s0_press_below', state=0, press=0, counter=0))
    add(case('s0_press_store2', state=0, press=0, counter=3, flags=0))
    add(case('s0_press_store1', state=0, press=0, counter=3, flags=0x10))
    add(case('s0_release', state=0, press=1, counter=5))
    add(case('s0_press_key1', key=1, state=0, press=0, counter=0))
    # state 1 (combo gate open; the two-key pairing needs the second key active)
    add(case('s1_press_within_window', state=1, press=0, counter=0, combo=0))
    add(case('s1_press_past_window', state=1, press=0, counter=20, combo=0))
    add(case('s1_press_combo_pending', state=1, press=0, counter=0, combo=1))
    add(case('s1_release_combo_clear', state=1, press=1, combo=0))
    add(case('s1_release_combo_pending', state=1, press=1, combo=1))
    # state 2
    add(case('s2_press_store5', state=2, press=0, counter=5, flags=0x02))
    add(case('s2_press_store4', state=2, press=0, counter=5, flags=0x22))
    add(case('s2_release_hold', state=2, press=1, counter=5, flagbyte=1, flags=0x0c))
    add(case('s2_release_end', state=2, press=1, counter=5, flags=0x09))
    add(case('s2_release_idle', state=2, press=1, counter=5, flags=0))
    # state 3
    add(case('s3_press_store5', state=3, press=0, counter=5, flagbyte=1, flags=0x14))
    add(case('s3_repeat_fires', state=3, press=1, repeat=5, flags=0x01))
    add(case('s3_repeat_building', state=3, press=1, repeat=0))
    # state 4
    add(case('s4_press_store6', state=4, press=0, counter=5, flags=0x20))
    add(case('s4_release', state=4, press=1, counter=5, flags=0x08))
    # state 5
    add(case('s5_press_counts', state=5, press=0, counter=0))
    add(case('s5_release_ends', state=5, press=1, counter=5, flags=0x08))
    # state 6
    add(case('s6_press_store5', state=6, press=0, counter=5, flags=0x40))
    add(case('s6_release', state=6, press=1, counter=5, flags=0x08))
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
    uploads = {}
    for row, c in zip(report['cases'], vector_doc['cases']):
        if row['name'] != c['name'] or row['observed'] != c['expected'] or not 0 < row['steps'] <= BOUND:
            raise ValueError('native mismatch ' + c['name'])
        bits = [int(a.split(':')[-1]) for a in c['expected']['actions'] if a.startswith('call:' + str(EVENT_UPLOAD))]
        stores = [int(a.split(':')[-1]) for a in c['expected']['actions'] if a.startswith('call:' + str(STORE_STATE))]
        uploads[c['name'].removeprefix('main_key_state_')] = dict(upload_bits=bits, store_states=stores)
    return dict(
        image='main firmware (OTA 4.6.0.3)',
        vectors_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(),
        validation_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        function=f'{STATE_MACHINE:#010x} (gpio_key_state_machine)',
        dispatch=dict(
            decode=f'{DECODE:#010x} writes a press/release flag; must return 0',
            state_byte=f'runtime context {RT_BASE:#010x} + key*0x18, +0 (7-entry jump table)',
            config=f'driver object {OBJ:#010x} + key*0x30 (flags +0x50)',
            combo_gated=f'the two-key combo paths are gated on the global {COMBO_GLOBALS + 4:#010x}'),
        states=dict(
            s0='press builds the counter, stores state 1/2 at the threshold; release clears it',
            s2='press stores state 4/5 and uploads bit 2; release uploads bit 8 then holds (state 3) or ends',
            s3='press uploads bits 0x10/0x4 and stores state 5; repeat uploads bit 1 and ends',
            s4='press stores state 6 and uploads bit 0x20; release uploads bit 8 and ends',
            s5='press only counts; release ends (upload bit 8)',
            s6='press uploads bit 0x40 and stores state 5; release ends'),
        per_case=uploads,
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The GPIO decode, state store, timer check, idle handler and event upload are stubbed; the state '
            'machine runs as real code and the runtime context writes are recorded.',
            'Only the single-key paths are covered (combo-pending global kept clear). State 1 (combo) and the '
            'two-key combo sub-paths of states 2..6 read both keys\' contexts and are not executed here.'])


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
