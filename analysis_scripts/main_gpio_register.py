#!/usr/bin/env python3
"""Main GPIO interrupt registration: callback-row insert/update and trigger mode.

This scope completes the GPIO interrupt chain begun in
[MAIN_GPIO_DISPATCH.md](MAIN_GPIO_DISPATCH.md) and
[MAIN_GPIO_CONFIG.md](MAIN_GPIO_CONFIG.md) by executing the original
registration routine ``0x80d43068``.  It converts a pin mask to a bit index
through libgcc ``__ctzsi2`` (``0x7094514c``), inserts or updates the pin's row
in the 16-row callback table at ``0x80c118c8``, and programs the controller's
trigger registers for one of five modes before enabling the pin, through the
same ``0x900080b0`` handshake the enable/commit routine uses.

Everything runs over authored controller structs, authored MMIO banks and the
authored callback table.  The configuration gate, the scheduler-state reader
and the critical save/restore wrappers are supplied return stubs.  Nothing here
executes vendor code outside the hash-guarded original ranges.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_trap_irq as trap
    from .main_object_lifecycle import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    import main_trap_irq as trap
    from main_object_lifecycle import image_memory
    from zrpc_packets import MAIN_HASH

MASK = 0xffffffff
BOUND = 5000
END = trap.END

REGISTER = 0x80d43068
CTZ = 0x7094514c
CTZ_TABLE = 0x709babf8
CALLBACK_TABLE = 0x80c118c8
STATE_WORD = 0x80c11730
SAVED_FLAG = 0x80c11734
HANDSHAKE = 0x900080b0
GATE = 0x80d341d8
STATE = 0x80d362b0
SAVE = 0x80d379ee
RESTORE = 0x80d37a1a
ROW = 0x18
ROWS = 16
# mode -> (bit 0x38, bit 0x34, bit 0x3c) controller trigger configuration.
MODES = {1: (0, 0, 0), 2: (0, 0, 1), 3: (1, 0, 0), 4: (0, 1, 1), 5: (0, 1, 0)}

CODE = (
    (REGISTER, 0x1d0, 'c79d6a0f8b0efc7955f3c469734c46b5a4d9c4e322852b9e1fc8fb60728245aa'),
    (CTZ, 0x76, 'ba83ffe48122376aec08d7243539dafe4a924aeafab510b32634ef6a668b3d7b'),
)
DATA = (
    (CTZ_TABLE, 0x100, '14a5d850c255623f9472e3c650abce0c78d32f0276b315b3a276a0462d97a1ac'),
)
CSRS = trap.CSRS
HARNESS_STACK = trap.HARNESS_STACK
QUIET = ((0x81000000, 0x81002000),)
CTRL = 0x81400000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return value & MASK


class Model(trap.Model):
    """Independent model of the GPIO interrupt registration routine."""

    def __init__(self, case):
        self.c = case
        self.mem = {}
        for address, data in case['memory']:
            for i, b in enumerate(bytes.fromhex(data)):
                self.mem[address + i] = b
        self.csr = {int(k): v for k, v in case['csrs'].items()}
        self.regs = dict(case['registers'])
        self.fregs = dict(case['fregisters'])
        self.actions = []
        self.supplied = {int(k): list(v) for k, v in case['supplied'].items()}
        self.stubs = {int(k): v for k, v in case['stubs'].items()}
        self.quiet = [tuple(q) for q in case['quiet']]
        self.returns = {int(k): list(v) for k, v in case.get('returns', {}).items()}

    def original_byte(self, at):
        if CTZ_TABLE <= at < CTZ_TABLE + 0x100:
            return (at - CTZ_TABLE).bit_length()
        raise ValueError(f'model read of unauthored byte {at:#x}')

    def write(self, address, size, value, record=True):
        value &= (1 << (8 * size)) - 1
        address = word(address)
        for i in range(size):
            self.mem[address + i] = (value >> (8 * i)) & 255
        if record and not any(lo <= address < hi for lo, hi in self.quiet):
            self.actions.append(f'w:{address}:{size}:{value}')

    def read(self, address, size=4):
        return super().read(word(address), size)

    def call(self, address, *args):
        parts = ['call', str(address)] + [str(word(a)) for a in args]
        self.actions.append(':'.join(parts))
        if address in self.returns:
            return self.returns[address].pop(0)
        return 0

    @staticmethod
    def ctz(mask):
        return (mask & -mask).bit_length() - 1

    def configure(self, base, bit, mode):
        if mode not in MODES:
            return 1
        b38, b34, b3c = MODES[mode]
        gate = self.call(GATE)
        state = self.call(STATE)
        self.write(STATE_WORD, 4, state)
        if state:
            self.call(SAVE, SAVED_FLAG)
            state = self.read(STATE_WORD)
        handshake = 2 if gate else 1
        while self.read(HANDSHAKE):
            pass
        self.write(HANDSHAKE, 4, handshake)
        while self.read(HANDSHAKE) != handshake:
            self.write(HANDSHAKE, 4, handshake)
        mask = word(1 << bit)
        self.write(base + 0x20, 4, ~mask & self.read(base + 0x20))
        self.write(base + 0x2c, 4, mask | self.read(base + 0x2c))
        self.write(base + 0x38, 4, (mask | self.read(base + 0x38)) if b38 else (~mask & self.read(base + 0x38)))
        self.write(base + 0x34, 4, (mask | self.read(base + 0x34)) if b34 else (~mask & self.read(base + 0x34)))
        self.write(base + 0x3c, 4, (mask | self.read(base + 0x3c)) if b3c else (~mask & self.read(base + 0x3c)))
        self.write(HANDSHAKE, 4, 0)
        if state:
            self.call(RESTORE, self.read(SAVED_FLAG))
        return 0

    def register(self, base, pin_mask, arg0, mode, handler, arg1):
        bit = self.ctz(pin_mask)
        free = -1
        for index in range(ROWS):
            row = CALLBACK_TABLE + ROW * index
            if self.read(row + 0x10) == 0 and free == -1:
                free = index
            if self.read(row) == base and self.read(row + 4) == bit:
                if handler != self.read(row + 0x10):
                    self.write(row + 0x14, 4, arg1)
                    self.write(row + 0x10, 4, handler)
                return self.configure(base, bit, mode)
        if free == -1:
            return 1
        row = CALLBACK_TABLE + ROW * free
        self.write(row + 8, 4, arg0)
        self.write(row + 4, 4, bit)
        self.write(row, 4, base)
        self.write(row + 0x14, 4, arg1)
        self.write(row + 0x10, 4, handler)
        self.write(row + 0xc, 1, mode & 0xff)
        return self.configure(base, bit, mode)

    def operation(self, op):
        if op['name'].split('#')[0] == 'register':
            return self.register(*op['args'])
        raise ValueError('operation')

    def run(self):
        rows = []
        for op in self.c['operations']:
            self.actions.append('op:' + op['name'])
            result = self.operation(op)
            row = dict(stopped=None, csrs={str(n): self.csr[n] for n in CSRS}, a0=word(result))
            row['snapshot'] = {str(a): self.snapshot(a, n) for a, n in self.c['snapshot']}
            rows.append(row)
        return dict(actions=self.actions, rows=rows)


def contract(case):
    if case['scope'] != 'register':
        raise ValueError('register scope')
    if not 1 <= len(case['operations']) <= 4 or sum(len(v) for v in case.get('returns', {}).values()) > 32:
        raise ValueError('bounded operations')
    return Model(case).run()


def words(*values):
    return trap.words(*values)


def op(name, *args):
    return dict(name=name, entry=REGISTER, call=True, args=list(args), result=True,
                registers=False, result_high=False)


def base_case(name, operations, memory, snapshot=(), returns=None):
    csrs = {str(n): v for n, v in zip(CSRS, (0x20, 0x1808, 0x888, 0, 0, 0, 0, 0, 0))}
    stub = {str(GATE): dict(kind='return', args=0), str(STATE): dict(kind='return', args=0),
            str(SAVE): dict(kind='return', args=1), str(RESTORE): dict(kind='return', args=1)}
    return dict(
        name='main_gpio_reg_' + name, scope='register', supplied={},
        returns={str(k): list(v) for k, v in (returns or {}).items()},
        quiet=[list(q) for q in QUIET], csr_allowed=list(CSRS),
        ranges=[[a, a + n] for a, n, _ in CODE + trap.CODE],
        csrs=csrs, registers={'sp': HARNESS_STACK}, fregisters={}, stubs=stub, stops={},
        snapshot=[list(s) for s in snapshot],
        operations=operations, memory=[[STATE_WORD, words(0, 0)], [HANDSHAKE, words(0)]] + [list(m) for m in memory])


def controller(base):
    data = bytearray(0x40)
    for off in (0x20, 0x2c, 0x34, 0x38, 0x3c):
        struct.pack_into('<I', data, off, 0)
    return [base, data.hex()]


def callbacks(entries):
    data = bytearray(ROW * ROWS)
    for index, (base, bit, handler) in entries.items():
        struct.pack_into('<II', data, ROW * index, base & MASK, bit)
        struct.pack_into('<I', data, ROW * index + 0x10, handler & MASK)
    return [CALLBACK_TABLE, data.hex()]


def native_vectors():
    cases = []

    def add(case):
        case['expected'] = contract(case)
        cases.append(case)

    row_snap = [[CALLBACK_TABLE, ROW], [CALLBACK_TABLE + ROW * 2, ROW]]
    ctrl_snap = [[CTRL + off, 4] for off in (0x20, 0x2c, 0x34, 0x38, 0x3c)]

    def reg_case(name, args, table, returns, snapshot):
        add(base_case(name, [op('register', *args)],
                      [callbacks(table), controller(CTRL)], snapshot=snapshot, returns=returns))

    # Fresh registration in the first free row, for each trigger mode.
    for mode in (1, 2, 3, 4, 5):
        reg_case('fresh_mode%d' % mode,
                 (CTRL, 1 << 5, 0xa0a0, mode, 0x70001000, 0xb0b0), {},
                 {GATE: [0], STATE: [0]},
                 row_snap + ctrl_snap + [[STATE_WORD, 4]])
    # ctz maps the pin mask to a bit index.
    reg_case('fresh_high_bit',
             (CTRL, 1 << 30, 0x1111, 4, 0x70001000, 0x2222), {},
             {GATE: [1], STATE: [0]}, row_snap + ctrl_snap)
    # Existing row with a different handler is updated in place, not duplicated.
    reg_case('update_existing_handler',
             (CTRL, 1 << 5, 0xa0a0, 1, 0x70002000, 0xcccc),
             {0: (CTRL, 5, 0x70001000)}, {GATE: [0], STATE: [0]},
             [[CALLBACK_TABLE, ROW], [CALLBACK_TABLE + ROW, ROW]] + ctrl_snap)
    # Existing row with the same handler: no row write, still reconfigures.
    reg_case('existing_same_handler_reconfigures',
             (CTRL, 1 << 5, 0xa0a0, 2, 0x70001000, 0xb0b0),
             {0: (CTRL, 5, 0x70001000)}, {GATE: [0], STATE: [0]},
             [[CALLBACK_TABLE, ROW]] + ctrl_snap)
    # First free row is chosen when earlier rows are occupied by other pins.
    reg_case('first_free_row_after_occupied',
             (CTRL, 1 << 9, 0x3333, 1, 0x70001000, 0x4444),
             {0: (0x81234000, 1, 0x70009000), 1: (0x81234000, 2, 0x70009000)},
             {GATE: [0], STATE: [0]},
             [[CALLBACK_TABLE + ROW * 2, ROW]] + ctrl_snap)
    # Scheduler state non-zero wraps the commit in the critical section.
    reg_case('state_nonzero_wraps_critical',
             (CTRL, 1 << 7, 0xa0a0, 3, 0x70001000, 0xb0b0), {},
             {GATE: [0], STATE: [2]}, ctrl_snap)
    # An invalid mode returns 1 without touching the controller.
    reg_case('invalid_mode_returns_error',
             (CTRL, 1 << 5, 0xa0a0, 6, 0x70001000, 0xb0b0), {},
             {}, ctrl_snap + row_snap)
    # A full table with no matching row returns 1.
    full = {i: (0x81234000, i, 0x70009000) for i in range(ROWS)}
    reg_case('full_table_no_free_row_errors',
             (CTRL, 1 << 5, 0xa0a0, 1, 0x70001000, 0xb0b0), full, {}, ctrl_snap)

    guards = trap.CODE + trap.DATA + CODE + DATA
    return dict(schema=1, bound_per_case=BOUND,
                guards=[dict(address=a, size=n, sha256=h) for a, n, h in guards], cases=cases)


def evidence(archive, vectors, validation):
    memory = image_memory(archive)
    for address, size, expected in trap.CODE + trap.DATA + CODE + DATA:
        if digest(memory.read(address, size)) != expected:
            raise ValueError(f'original bytes differ at {address:#x}')
    source = trap.COPY['source'] + REGISTER - trap.COPY['destination']
    if memory.data[source - 0x70160000:source - 0x70160000 + 0x1d0] != memory.read(REGISTER, 0x1d0):
        raise ValueError('copied code differs from its load image')
    table = memory.read(CTZ_TABLE, 0x100)
    if any(table[i] != i.bit_length() for i in range(0x100)):
        raise ValueError('ctz table is not a bit-length table')
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
        byte_range_sha256={f'{a:08x}_{n:x}': h for a, n, h in CODE + DATA},
        register_routine=f'{REGISTER:#010x}', ctz_helper=f'{CTZ:#010x}',
        callback_table=f'{CALLBACK_TABLE:#010x}', callback_rows=ROWS, callback_row_bytes=f'{ROW:#x}',
        row_layout=dict(base='0x00', bit='0x04', arg0='0x08', mode='0x0c', handler='0x10', arg1='0x14'),
        trigger_modes={str(mode): dict(reg38=bits[0], reg34=bits[1], reg3c=bits[2])
                       for mode, bits in MODES.items()},
        controller_fields=dict(disable_mask='0x20', enable='0x2c', trigger_a='0x34', level='0x38',
                               trigger_b='0x3c'),
        native_case_count=len(report['cases']), native_steps=sum(r['steps'] for r in report['cases']),
        native_validation=report,
        limitations=[
            'The GPIO interrupt registration routine and the libgcc __ctzsi2 helper execute in an emulator '
            'over authored controller structs, authored MMIO banks and an authored 16-row callback table. '
            'No hardware GPIO pin, interrupt or commit acknowledgement is delivered.',
            'The configuration gate 0x80d341d8, the scheduler-state reader 0x80d362b0 and the critical '
            'save/restore wrappers 0x80d379ee/0x80d37a1a are supplied return stubs, covered elsewhere. The '
            'commit handshake on 0x900080b0 reads authored memory, so no real acknowledgement latency is '
            'modeled.',
            'The five trigger modes map to three controller bits (0x34/0x38/0x3c); the edge/level/polarity '
            'meaning of each bit, the physical pin roles and the real interrupt delivery remain unproved.'])


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
        parser.exit(2, f'Cannot inspect main GPIO registration paths: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
